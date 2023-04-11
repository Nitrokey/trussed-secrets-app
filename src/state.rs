use core::convert::TryInto;
use core::time::Duration;

use iso7816::Status;
use serde::de::DeserializeOwned;
use serde::Serialize;

use encrypted_container::EncryptedDataContainer;
use trussed::types::Message;
use trussed::{
    cbor_deserialize, syscall, try_syscall,
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
    /// This is the user's password, passed through PBKDF-HMAC-SHA1.
    /// It is used for authorization using challenge HMAC-SHA1'ing.
    #[cfg(feature = "challenge-response-auth")]
    pub authorization_key: Option<KeyId>,
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

    pub last_failed_request: Option<Duration>,

    /// Cache
    pub encryption_key: Option<KeyId>,
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
    ) -> crate::Result
    where
        T: trussed::Client + trussed::client::Chacha8Poly1305,
        O: Serialize,
    {
        let encryption_key = self
            .get_encryption_key_from_state()
            .map_err(|_| iso7816::Status::SecurityStatusNotSatisfied)?;
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
            |_| {
                debug_now!("Failed to write the file");
                iso7816::Status::NotEnoughMemory
            },
        )?;
        Ok(())
    }

    fn get_encryption_key_from_state(&mut self) -> trussed::error::Result<KeyId> {
        // Try to read cached field (should not be empty if unlocked)
        if self.runtime.encryption_key.is_none() {
            error_now!("No encryption key set in the cache");
        }
        self.runtime.encryption_key.ok_or(trussed::Error::NoSuchKey)
    }

    pub fn decrypt_content<T, O>(
        &mut self,
        trussed: &mut T,
        ser_encrypted: Message,
    ) -> encrypted_container::Result<O>
    where
        T: trussed::Client + trussed::client::Chacha8Poly1305,
        O: DeserializeOwned,
    {
        let encryption_key = self
            .get_encryption_key_from_state()
            .map_err(|_| encrypted_container::Error::FailedDecryption)?;

        EncryptedDataContainer::decrypt_from_bytes(trussed, ser_encrypted, encryption_key)
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

        self.decrypt_content(trussed, ser_encrypted)
            .map_err(|e| e.into())
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
                let salt: [u8; 8] = syscall!(trussed.random_bytes(8))
                    .bytes
                    .as_ref()
                    .try_into()
                    .unwrap();
                Persistent { salt }
            })
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum CommandState {
    ListCredentials(usize),
}
