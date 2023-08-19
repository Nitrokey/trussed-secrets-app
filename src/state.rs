// Copyright (C) 2021-2022 The Trussed Developers
// Copyright (C) 2023 Nitrokey GmbH
//
// SPDX-License-Identifier: Apache-2.0 OR MIT

use core::convert::TryInto;
use core::time::Duration;

use iso7816::Status;
use serde::de::DeserializeOwned;
use serde::Serialize;

use crate::command::EncryptionKeyType;
use cbor_smol::cbor_deserialize;
use encrypted_container::EncryptedDataContainer;
use trussed::client::FilesystemClient;
use trussed::types::Message;
use trussed::{
    syscall, try_syscall,
    types::{KeyId, Location, PathBuf},
};

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct State {
    // at startup, trussed is not callable yet.
    // moreover, when worst comes to worst, filesystems are not available
    // persistent: Option<Persistent>,
    pub runtime: Runtime,
    location: Location,
    // temporary "state", to be removed again
    // pub hack: Hack,
    // trussed: RefCell<Trussed<S>>,
    // Count read-write access to the persistence storage. Development only.
    #[cfg(feature = "devel-counters")]
    counter_read_write: u32,
    // Count read-only access to the persistence storage. Development only.
    #[cfg(feature = "devel-counters")]
    counter_read_only: u32,
}

#[derive(Clone, Debug, Eq, PartialEq, serde::Deserialize, serde::Serialize)]
pub struct Persistent {
    pub salt: [u8; 8],
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct Runtime {
    pub previously: Option<CommandState>,
    /// This gets rotated regularly, so someone sniffing on the bus can't replay.
    /// There is a small window between a legitimate client authenticating,
    /// and its next command that needs such authentication.
    pub challenge: [u8; 8],
    /// Gets set after a successful VALIDATE call,
    /// good for use right after (e.g. to set/change/remove password),
    /// and cleared thereafter.
    pub client_authorized: bool,
    /// For book-keeping purposes, set client_authorized / prevents it from being cleared before
    /// returning control to caller of the app
    pub client_newly_authorized: bool,

    /// Timestamp of the last failed Reverse HOTP verification attempt, if any
    pub last_failed_request: Option<Duration>,

    /// Cache
    pub encryption_key: Option<KeyId>,
    pub encryption_key_hardware: Option<KeyId>,
}

impl Runtime {
    pub fn reset(&mut self) {
        *self = Self::default();
    }
}

impl Persistent {}

impl State {
    const FILENAME: &'static str = "state.bin";

    pub fn new(location: Location) -> Self {
        Self {
            location,
            runtime: Default::default(),
            #[cfg(feature = "devel-counters")]
            counter_read_write: Default::default(),
            #[cfg(feature = "devel-counters")]
            counter_read_only: Default::default(),
        }
    }

    pub fn try_write_file<T, O>(
        &mut self,
        trussed: &mut T,
        filename: PathBuf,
        obj: &O,
        encryption_key_type: Option<EncryptionKeyType>,
    ) -> crate::Result
    where
        T: trussed::Client + trussed::client::Chacha8Poly1305,
        O: Serialize,
    {
        let encryption_key = self
            .get_encryption_key_from_state(encryption_key_type)
            .map_err(|_| Status::SecurityStatusNotSatisfied)?;

        let data = EncryptedDataContainer::from_obj(trussed, obj, None, encryption_key).map_err(
            |_err| {
                error!("error encrypting object: {:?}", _err);
                Status::UnspecifiedPersistentExecutionError
            },
        )?;
        let data_serialized: Message = data.try_into().map_err(|_err| {
            error!("error serializing container: {:?}", _err);
            Status::UnspecifiedPersistentExecutionError
        })?;
        debug_now!("Container size: {}", data_serialized.len());
        try_syscall!(trussed.write_file(self.location, filename, data_serialized, None)).map_err(
            |e| {
                warn_now!("Failed to write the file: {:?}", e);
                Status::NotEnoughMemory
            },
        )?;
        Ok(())
    }

    fn get_encryption_key_from_state(
        &mut self,
        encryption_key_type: Option<EncryptionKeyType>,
    ) -> trussed::error::Result<KeyId> {
        // Try to read cached field (should not be empty if unlocked)
        let key = match encryption_key_type.unwrap_or(EncryptionKeyType::Hardware) {
            EncryptionKeyType::Hardware => self.runtime.encryption_key_hardware,
            EncryptionKeyType::PinBased => self.runtime.encryption_key,
        };
        if key.is_none() {
            warn_now!(
                "No encryption key set in the cache for type {:?}",
                encryption_key_type
            );
        }
        key.ok_or(trussed::Error::NoSuchKey)
    }

    pub fn decrypt_content<T, O>(
        &mut self,
        trussed: &mut T,
        ser_encrypted: Message,
    ) -> (encrypted_container::Result<O>, Option<EncryptionKeyType>)
    where
        T: trussed::Client + trussed::client::Chacha8Poly1305,
        O: DeserializeOwned,
    {
        // We do not know what key was used for encryption
        // If the value is not set, we should default to PIN based encryption key. Otherwise Hardware based one.
        // Order: PIN-based decryption (if PIN key is set), then hardware based key decryption

        for kt in &[EncryptionKeyType::PinBased, EncryptionKeyType::Hardware] {
            debug_now!("Trying decryption with {:?}", kt);
            let encryption_key = self.get_encryption_key_from_state(Some(*kt));

            match encryption_key {
                Err(_) => {
                    debug_now!("Key {:?} is not available", kt);
                    continue;
                }
                Ok(key) => {
                    let res =
                        EncryptedDataContainer::decrypt_from_bytes(trussed, &ser_encrypted, key);
                    debug_now!("Decryption result with {:?}: {:?}", kt, res.is_ok());
                    if res.is_ok() {
                        return (res, Some(kt.clone()));
                    }
                }
            }
        }
        (Err(encrypted_container::Error::FailedDecryption), None)
    }

    pub fn file_exists<T: FilesystemClient>(
        &mut self,
        trussed: &mut T,
        filename: PathBuf,
    ) -> crate::Result<bool> {
        Ok(
            try_syscall!(trussed.entry_metadata(self.location, filename))
                .map_err(|_| Status::UnspecifiedNonpersistentExecutionError)?
                .metadata
                .is_some(),
        )
    }

    pub fn try_read_file<T, O>(
        &mut self,
        trussed: &mut T,
        filename: PathBuf,
    ) -> trussed::error::Result<O>
    where
        T: trussed::Client + trussed::client::Chacha8Poly1305,
        O: DeserializeOwned,
    {
        let ser_encrypted = try_syscall!(trussed.read_file(self.location, filename))?.data;

        debug_now!("ser_encrypted {:?}", ser_encrypted);

        let (res, _) = self.decrypt_content(trussed, ser_encrypted);
        res.map_err(|e| e.into())
    }

    pub fn with_persistent<T, X>(
        &mut self,
        trussed: &mut T,
        f: impl FnOnce(&mut T, &Persistent) -> X,
    ) -> X
    where
        T: trussed::Client + trussed::client::Chacha8Poly1305,
    {
        let state = self.get_persistent_or_default(trussed);

        #[cfg(feature = "devel-counters")]
        {
            self.counter_read_only += 1;
            debug_now!("Getting the state RO {}", self.counter_read_only);
        }
        // 2. Let the app read the state

        f(trussed, &state)
    }

    fn get_persistent_or_default(&self, trussed: &mut impl trussed::Client) -> Persistent {
        // 1. If there is serialized, persistent state (i.e., the try_syscall! to `read_file` does
        //    not fail), then assume it is valid and deserialize it. If the reading fails, assume
        //    that this is the first run, and set defaults.
        //
        // NB: This is an attack vector. If the state can be corrupted, this clears the password.
        // Consider resetting the device in this situation
        // TODO DESIGN discuss, should failed deserialization be reacted on differently
        // TODO handle error from getting the random bytes
        try_syscall!(trussed.read_file(self.location, PathBuf::from(Self::FILENAME)))
            .ok()
            .and_then(|response| cbor_deserialize(&response.data).ok())
            .unwrap_or_else(|| {
                #[allow(clippy::unwrap_used)]
                let salt: [u8; 8] = syscall!(trussed.random_bytes(8))
                    .bytes
                    .as_ref()
                    .try_into()
                    .unwrap(); // OK, because random_bytes returns exact requested bytes count;
                Persistent { salt }
            })
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum CommandState {
    ListCredentials(usize, u8),
}
