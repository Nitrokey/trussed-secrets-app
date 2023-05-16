use core::convert::TryInto;

#[cfg(feature = "brute-force-delay")]
use core::time::Duration;

use flexiber::{Encodable, EncodableHeapless};
use heapless_bytes::Bytes;
use iso7816::Status::{
    NotFound, UnspecifiedNonpersistentExecutionError, UnspecifiedPersistentExecutionError,
};
use iso7816::{Data, Status};
use trussed::types::Location;
use trussed::types::{KeyId, Message};
use trussed::{client, syscall, try_syscall, types::PathBuf};

use crate::calculate::hmac_challenge;
use crate::command::CredentialData::HmacData;
use crate::command::{Credential, EncryptionKeyType, ListCredentials, VerifyCode, YKGetHMAC};
use crate::credential::CredentialFlat;
use crate::oath::Algorithm;
use crate::{
    command, ensure, oath,
    state::{CommandState, State},
    Command, ATTEMPT_COUNTER_DEFAULT_RETRIES, BACKEND_USER_PIN_ID, CTAPHID_MESSAGE_SIZE_LIMIT,
};

#[cfg(feature = "brute-force-delay")]
use crate::REQUIRED_DELAY_ON_FAILED_VERIFICATION;

/// The options for the authenticator app.
#[derive(Clone, Copy, Debug)]
#[non_exhaustive]
pub struct Options {
    /// The storage location for the application data (default: internal).
    pub location: Location,

    /// The custom status id to be set for the successful verification for the Reverse HOTP.
    /// By design this should be animated as: blink green LED for 10 seconds, highest priority.
    pub custom_status_reverse_hotp_success: u8,

    /// The custom status id to be set for the failed verification for the Reverse HOTP.
    /// By design this should be animated as: blink red LED infinite times, highest priority.
    pub custom_status_reverse_hotp_error: u8,

    /// A serial number to be returned in YK Challenge-Response and Status commands
    pub serial_number: [u8; 4],
}

impl Options {
    pub const fn new(
        location: Location,
        custom_status_reverse_hotp_success: u8,
        custom_status_reverse_hotp_error: u8,
        serial_number: [u8; 4],
    ) -> Self {
        Self {
            location,
            custom_status_reverse_hotp_success,
            custom_status_reverse_hotp_error,
            serial_number,
        }
    }
}

/// The TOTP authenticator Trussed® app.
pub struct Authenticator<T> {
    options: Options,
    state: State,
    trussed: T,
}

use crate::Result;

#[derive(Clone, Copy, Eq, PartialEq)]
struct OathVersion {
    major: u8,
    minor: u8,
    patch: u8,
}

impl Default for OathVersion {
    /// For ykman, 4.2.6 is the first version to support "touch" requirement
    fn default() -> Self {
        // TODO: set this up automatically during the build from the project version
        OathVersion {
            major: 4,
            minor: 11,
            patch: 0,
        }
    }
}

impl flexiber::Encodable for OathVersion {
    fn encoded_length(&self) -> flexiber::Result<flexiber::Length> {
        Ok(3u8.into())
    }
    fn encode(&self, encoder: &mut flexiber::Encoder) -> flexiber::Result<()> {
        let buf = [self.major, self.minor, self.patch];
        buf.as_ref().encode(encoder)
    }
}

// Mar 05 21:43:45 tensor pcscd[2238]: 00000588 APDU: 00 A4 04 00 07 A0 00 00 05 27 21 01
// Mar 05 21:43:45 tensor pcscd[2238]: 00008810 SW:
//      79 03 01 00 00
//      71 08 26 9F 14 54 3A 0E C7 AC
//      90 00

// 61 0F 79 03 01 00 00 71 08 01 02 03 04 01 02 03 04 90 00
#[derive(Clone, Copy, Encodable, Eq, PartialEq)]
struct AnswerToSelect {
    #[tlv(simple = "0x79")] // Tag::Version
    version: OathVersion,
    #[tlv(simple = "0x71")] // Tag::Name
    salt: [u8; 8],
    // the following is listed as "locked" and "FIPS mode"
    //
    // NB: Current BER-TLV derive macro has limitation that it
    // wants a tag. It should learn some kind of "suppress-tag-if-none".
    // As we would like to send "nothing" when challeng is None,
    // instead of '74 00', as with the tagged/Option derivation.
    // #[tlv(simple = "0x74")] // Tag::Challenge
    // challenge: Option<[u8; 8]>,
    #[tlv(simple = "0x8F")] // Tag::SerialNumber
    serial: SerialType,
}

#[derive(Clone, Copy, Eq, PartialEq)]
struct SerialType([u8; 4]);

impl flexiber::Encodable for SerialType {
    fn encoded_length(&self) -> flexiber::Result<flexiber::Length> {
        Ok(u8::try_from(self.0.len()).unwrap().into())
    }

    fn encode(&self, encoder: &mut flexiber::Encoder) -> flexiber::Result<()> {
        self.0.as_ref().encode(encoder)
    }
}

#[derive(Clone, Copy, Encodable, Eq, PartialEq)]
struct PINAnswerToSelect {
    #[tlv(simple = "0x79")] // Tag::Version
    version: OathVersion,

    #[tlv(simple = "0x82")] // Tag::PINCounter
    attempt_counter: Option<[u8; 1]>,

    #[tlv(simple = "0x8F")] // Tag::SerialNumber
    serial: SerialType,
}

#[derive(Clone, Copy, Encodable, Eq, PartialEq)]
struct ChallengingAnswerToSelect {
    #[tlv(simple = "0x79")] // Tag::Version
    version: OathVersion,
    #[tlv(simple = "0x71")] // Tag::Name
    salt: [u8; 8],

    // the following is listed as "locked" and "FIPS mode"
    //
    // NB: Current BER-TLV derive macro has limitation that it
    // wants a tag. It should learn some kind of "suppress-tag-if-none".
    // As we would like to send "nothing" when challeng is None,
    // instead of '74 00', as with the tagged/Option derivation.
    #[tlv(simple = "0x74")] // Tag::Challenge
    challenge: [u8; 8],

    #[tlv(simple = "0x7b")] // Tag::Algorithm
    // algorithm: oath::Algorithm,
    algorithm: [u8; 1],
}

impl AnswerToSelect {
    /// The salt is stable and used in modified form as "device ID" in ykman.
    /// It gets rotated on device reset.
    fn new(salt: [u8; 8], serial: SerialType) -> Self {
        Self {
            version: Default::default(),
            salt,
            serial,
        }
    }

    fn with_pin_attempt_counter(self, counter: Option<u8>) -> PINAnswerToSelect {
        let c = counter.map(u8::to_be_bytes);
        PINAnswerToSelect {
            version: self.version,
            attempt_counter: c,
            serial: self.serial,
        }
    }

    /// This challenge is only added when a password is set on the device.
    ///
    /// It is rotated each time SELECT is called.
    #[cfg(feature = "challenge-response-auth")]
    fn with_challenge(self, challenge: [u8; 8]) -> ChallengingAnswerToSelect {
        ChallengingAnswerToSelect {
            version: self.version,
            salt: self.salt,
            challenge,
            // algorithm: oath::Algorithm::Sha1  // TODO set proper algo
            algorithm: [0x01], // TODO set proper algo
        }
    }
}

impl<T> Authenticator<T>
where
    T: client::Client
        + client::HmacSha1
        + client::HmacSha256
        + client::Sha256
        + client::Chacha8Poly1305
        + trussed_auth::AuthClient,
{
    // const CREDENTIAL_DIRECTORY: &'static str = "cred";
    fn credential_directory() -> PathBuf {
        PathBuf::from("cred")
    }

    pub fn new(trussed: T, options: Options) -> Self {
        Self {
            state: State::new(options.location),
            trussed,
            options,
        }
    }

    pub fn init(&mut self) -> Result {
        if self.state.runtime.encryption_key_hardware.is_none() {
            self.state.runtime.encryption_key_hardware = Some(self._extension_get_hardware_key()?);
        }
        Ok(())
    }

    pub fn respond<const C: usize, const R: usize>(
        &mut self,
        command: &iso7816::Command<C>,
        reply: &mut Data<R>,
    ) -> Result {
        #[cfg(feature = "challenge-response-auth")]
        let no_authorization_needed_cha_resp = self
            .state
            .with_persistent(&mut self.trussed, |_, state| !state.password_set());

        // TODO: abstract out this idea to make it usable for all the PIV security indicators

        let client_authorized_before = self.state.runtime.client_authorized;
        self.state.runtime.client_newly_authorized = false;

        // debug_now!("inner respond, client_authorized {}", self.state.runtime.client_authorized);
        let result = self.inner_respond(command, reply);

        // we want to clear the authorization flag *except* if it wasn't set before,
        // but was set now.
        // if !(!client_authorized_before && self.state.runtime.client_newly_authorized) {
        // This is equivalent to the simpler formulation that stale authorization gets
        // removed, unless refreshed during this round
        if client_authorized_before || !self.state.runtime.client_newly_authorized {
            self.state.runtime.client_authorized = false;
        }
        if self.state.runtime.client_newly_authorized {
            self.state.runtime.client_authorized = true;
        }

        result
    }

    fn inner_respond<const C: usize, const R: usize>(
        &mut self,
        command: &iso7816::Command<C>,
        reply: &mut Data<R>,
    ) -> Result {
        let class = command.class();
        ensure(
            class.chain().last_or_only(),
            Status::CommandChainingNotSupported,
        )?;
        ensure(
            class.secure_messaging().none(),
            Status::SecureMessagingNotSupported,
        )?;
        ensure(class.channel() == Some(0), Status::ClassNotSupported)?;

        // parse Iso7816Command
        let command: Command = command.try_into()?;
        info_now!("{:?}", &command);

        // Make sure the "remaining" state is cleared if the new command is sent
        // It will clear itself with the final packet sent
        if !matches!(command, Command::SendRemaining) {
            self.state.runtime.previously = None;
        }

        // DESIGN Allow all commands to be called without PIN verification

        // Lazy init: make sure hardware key is initialized
        self.init()?;

        // Process the request
        let result = match command {
            Command::Select(select) => self.select(select, reply),
            Command::ListCredentials(version) => self.list_credentials(reply, None, version),
            Command::Register(register) => self.register(register),
            Command::Calculate(calculate) => self.calculate(calculate, reply),
            Command::GetCredential(get) => self.get_credential(get, reply),
            #[cfg(feature = "calculate-all")]
            Command::CalculateAll(calculate_all) => self.calculate_all(calculate_all, reply),
            Command::Delete(delete) => self.delete(delete),
            Command::Reset => self.reset(),
            #[cfg(feature = "challenge-response-auth")]
            Command::Validate(validate) => self.validate(validate, reply),
            #[cfg(feature = "challenge-response-auth")]
            Command::SetPassword(set_password) => self.set_password(set_password),
            #[cfg(feature = "challenge-response-auth")]
            Command::ClearPassword => self.clear_password(),
            Command::VerifyCode(verify_code) => self.verify_code(verify_code, reply),

            Command::VerifyPin(vpin) => self.verify_pin(vpin, reply),
            Command::SetPin(spin) => self.set_pin(spin, reply),
            Command::ChangePin(cpin) => self.change_pin(cpin, reply),

            Command::YKSerial => self.yk_serial(reply),
            Command::YKGetStatus => self.yk_status(reply),
            Command::YKGetHMAC(req) => self.yk_hmac(req, reply),

            Command::SendRemaining => self.send_remaining(reply),
            _ => Err(Status::ConditionsOfUseNotSatisfied),
        };

        // Call logout after processing, so the PIN-based KEK would not be kept in the memory
        // DESIGN -> Per-request authorization
        if self.state.runtime.encryption_key.is_some() {
            // Do not call automatic logout after these commands
            match command {
                // Always leave PIN KEK after verify PIN
                Command::VerifyPin(_) => {}
                _ => {
                    if self.state.runtime.previously.is_none() {
                        debug_now!("Calling logout");
                        self._extension_logout().ok();
                    }
                }
            }
        };

        result
    }

    fn select<const R: usize>(
        &mut self,
        _select: command::Select<'_>,
        reply: &mut Data<R>,
    ) -> Result {
        self.state.runtime.challenge = syscall!(self.trussed.random_bytes(8))
            .bytes
            .as_ref()
            .try_into()
            .unwrap();

        let state = self
            .state
            .with_persistent(&mut self.trussed, |_, state| state.clone());
        let answer_to_select =
            AnswerToSelect::new(state.salt, SerialType(self.options.serial_number));

        let data: heapless::Vec<u8, 128> = if self._extension_is_pin_set()? {
            answer_to_select
                .with_pin_attempt_counter(self._extension_attempt_counter())
                .to_heapless_vec()
        } else {
            answer_to_select.to_heapless_vec()
        }
        .unwrap();

        reply.extend_from_slice(&data).unwrap();
        Ok(())
    }

    fn load_credential(&mut self, label: &[u8]) -> Option<CredentialFlat> {
        let filename = self.filename_for_label(label);

        let mut credential: CredentialFlat =
            self.state.try_read_file(&mut self.trussed, filename).ok()?;
        // Set the default EncryptionKeyType as PinBased for backwards compatibility
        // All the new records should have it set as HardwareBased, if not overridden by user
        if credential.encryption_key_type.is_none() {
            credential.encryption_key_type =
                Some(EncryptionKeyType::default_for_loading_credential());
        }

        if label != credential.label.as_slice() {
            error_now!("Loaded credential label is different than expected. Aborting.");
            return None;
        }

        Some(credential)
    }

    fn reset(&mut self) -> Result {
        // DESIGN Reset: always confirm with touch button
        self.user_present()?;

        // Run any structured cleanup we have
        self._extension_pin_factory_reset()?;
        self.state.runtime.reset();

        // Remove potential missed remains for the extra care
        for loc in [Location::Volatile, self.options.location] {
            info_now!(":: reset - delete all keys and files in {:?}", loc);
            try_syscall!(self.trussed.delete_all(loc)).map_err(|_| Status::NotEnoughMemory)?;
            try_syscall!(self.trussed.remove_dir_all(loc, PathBuf::new()))
                .map_err(|_| Status::NotEnoughMemory)?;
        }

        debug_now!(":: reset over");
        Ok(())
    }

    fn delete(&mut self, delete: command::Delete<'_>) -> Result {
        debug_now!("{:?}", delete);
        // It seems tooling first lists all credentials, so the case of
        // delete being called on a non-existing label hardly occurs.

        // APDU: 00 A4 04 00 07 A0 00 00 05 27 21 01
        // SW: 79 03 01 00 00 71 08 26 9F 14 54 3A 0E C7 AC 90 00
        // APDU: 00 A1 00 00 00
        // SW: 72 13 21 74 6F 74 70 2E 64 61 6E 68 65 72 73 61 6D 2E 63 6F 6D 72 07 21 79 75 62 69 63 6F 90 00

        // APDU: 00 02 00 00 08 71 06 79 75 62 69 63 6F
        // SW: 90 00

        let label = &delete.label;
        if let Some(_credential) = self.load_credential(label) {
            let _filename = self.filename_for_label(label);
            let _deletion_result =
                try_syscall!(self.trussed.remove_file(self.options.location, _filename));
            debug_now!(
                "Delete credential with filename {}, result: {:?}",
                &self.filename_for_label(label),
                _deletion_result
            );
        } else {
            return Err(NotFound);
        }
        Ok(())
    }

    fn try_to_serialize_credential_for_list<const R: usize>(
        credential: &CredentialFlat,
        reply: &mut Data<R>,
        request_data: ListCredentials,
    ) -> core::result::Result<(), u8> {
        match request_data.version {
            1 => {
                reply.push(0x72)?;
                reply.push((credential.label.len() + 2) as u8)?;
                reply.push(oath::combine(credential.kind, credential.algorithm))?;
                reply.extend_from_slice(&credential.label).map_err(|_| 0)?;
                // Add metadata/properties byte
                reply.push(credential.get_properties_byte())?;
            }
            0 => {
                reply.push(0x72)?;
                reply.push((credential.label.len() + 1) as u8)?;
                reply.push(oath::combine(credential.kind, credential.algorithm))?;
                reply.extend_from_slice(&credential.label).map_err(|_| 0)?;
            }
            _ => {
                // Unhandled version requested
                return Err(1);
            }
        }

        if reply.len() > CTAPHID_MESSAGE_SIZE_LIMIT {
            // Finish early due to the usbd-ctaphid message size limit
            return Err(1);
        }
        Ok(())
    }

    /// The YK5 can store a Grande Totale of 32 OATH credentials.
    fn list_credentials<const R: usize>(
        &mut self,
        reply: &mut Data<R>,
        file_index: Option<usize>,
        request_data: ListCredentials,
    ) -> Result {
        // info_now!("recv ListCredentials");
        // return Ok(Default::default());
        // 72 13 21
        //          74 6F 74 70  2E 64 61 6E  68 65 72 73  61 6D 2E 63  6F 6D
        // 72 07 21
        //          79 75 62 69  63 6F
        // 90 00
        let file_index = file_index.unwrap_or(0);

        let mut maybe_credential = {
            // To avoid creating additional buffer for the unfit data
            // we will rewind the state and restart from there accordingly
            let first_file = try_syscall!(self.trussed.read_dir_files_first(
                self.options.location,
                Self::credential_directory(),
                None
            ))
            .map_err(|_| iso7816::Status::KeyReferenceNotFound)?
            .data;

            // Rewind if needed, otherwise return first file's content
            let file = {
                if file_index > 0 {
                    for _ in 0..file_index - 1 {
                        try_syscall!(self.trussed.read_dir_files_next())
                            .map_err(|_| iso7816::Status::KeyReferenceNotFound)?;
                    }
                    try_syscall!(self.trussed.read_dir_files_next())
                        .map_err(|_| iso7816::Status::KeyReferenceNotFound)?
                        .data
                } else {
                    first_file
                }
            };

            let maybe_credential: Option<CredentialFlat> = match file {
                None => None,
                Some(c) => self.state.decrypt_content(&mut self.trussed, c).ok(),
            };
            maybe_credential
        };

        let mut file_index = file_index;
        loop {
            if let Some(credential) = maybe_credential {
                // Try to serialize, abort if does not fit into the reply buffer
                let current_reply_bytes_count = reply.len();
                let res =
                    Self::try_to_serialize_credential_for_list(&credential, reply, request_data);
                if res.is_err() {
                    // Revert reply vector to the last good size, removing debris from the failed
                    // serialization
                    reply.truncate(current_reply_bytes_count);
                    return Err(Status::MoreAvailable(0xFF));
                }
            };

            // keep track, in case we need continuation
            file_index += 1;
            self.state.runtime.previously = Some(CommandState::ListCredentials(
                file_index,
                request_data.version,
            ));

            // check if there's more
            maybe_credential = match syscall!(self.trussed.read_dir_files_next()).data {
                // no more files, break the loop and return
                None => break,
                // we do not have the right key, continue
                Some(c) => self.state.decrypt_content(&mut self.trussed, c).ok(),
            };
        }

        // ran to completion
        // todo: pack this cleanup in a closure?
        self.state.runtime.previously = None;
        Ok(())
    }

    fn send_remaining<const R: usize>(&mut self, reply: &mut Data<{ R }>) -> Result {
        let file_index = if let Some(CommandState::ListCredentials(s_file_index, _)) =
            self.state.runtime.previously
        {
            s_file_index
        } else {
            0
        };

        match self.state.runtime.previously {
            None => Err(Status::ConditionsOfUseNotSatisfied),
            Some(CommandState::ListCredentials(_, v)) => {
                self.list_credentials(reply, Some(file_index), ListCredentials { version: v })
            }
        }
    }

    fn register(&mut self, register: command::Register<'_>) -> Result {
        // DESIGN Registration: require touch button if set on the credential, but not if the PIN was already checked
        if register.credential.touch_required
            && register.credential.encryption_key_type != EncryptionKeyType::PinBased
        {
            self.user_present()?;
        }

        // info_now!("recv {:?}", &register);

        // Allow to overwrite existing credentials by default
        // 0. ykman does not call delete before register, so we need to speculatively
        // delete the credential (the credential file would be replaced, but we need
        // to delete the secret key).
        self.delete(command::Delete {
            label: register.credential.label,
        })
        .ok();

        // 1. Replace secret in credential with handle
        let credential =
            CredentialFlat::try_from(&register.credential).map_err(|_| Status::NotEnoughMemory)?;

        // 2. Generate a filename for the credential
        let filename = self.filename_for_label(&credential.label);

        // 3. Serialize the credential (implicitly) and store it
        let write_res = self.state.try_write_file(
            &mut self.trussed,
            filename,
            &credential,
            credential.encryption_key_type,
        );

        if write_res.is_err() {
            warn_now!("Failed serialization of {:?}: {:?}", &credential.label, write_res);
            // 1. Try to delete the empty file, ignore errors
            let filename = self.filename_for_label(&credential.label);
            try_syscall!(self.trussed.remove_file(self.options.location, filename)).ok();
            // 2. Return the original error
            write_res?
        }

        Ok(())
    }

    fn filename_for_label(&mut self, label: &[u8]) -> trussed::types::PathBuf {
        let label_hash = syscall!(self.trussed.hash_sha256(label)).hash;

        // todo: maybe use a counter instead (put it in our persistent state).
        let mut hex_filename = [0u8; 16];
        const LOOKUP: &[u8; 16] = b"0123456789ABCDEF";
        for (i, &value) in label_hash.iter().take(8).enumerate() {
            hex_filename[2 * i] = LOOKUP[(value >> 4) as usize];
            hex_filename[2 * i + 1] = LOOKUP[(value & 0xF) as usize];
        }

        let filename = PathBuf::from(hex_filename.as_ref());
        let mut path = Self::credential_directory();
        path.push(&filename);
        info_now!("filename: {}", path.as_str_ref_with_trailing_nul());
        path
    }

    // 71 <- Tag::Name
    //    12
    //       74 6F 74 70 2E 64 61 6E 68 65 72 73 61 6D 2E 63 6F 6D
    // 76 <- Tag::TruncatedResponse
    //    05
    //       06 <- digits
    //       75 F9 2B 37 <- dynamically truncated HMAC
    // 71 <- Tag::Name
    //    06
    //       79 75 62 69 63 6F
    // 76 <- Tag::TruncatedResponse
    //    05
    //       06  <- digits
    //       5A D0 A7 CA <- dynamically truncated HMAC
    // 90 00
    #[cfg(feature = "calculate-all")]
    fn calculate_all<const R: usize>(
        &mut self,
        calculate_all: command::CalculateAll<'_>,
        reply: &mut Data<R>,
    ) -> Result {
        if !self.state.runtime.client_authorized {
            return Err(Status::ConditionsOfUseNotSatisfied);
        }

        let maybe_credential_enc = syscall!(self.trussed.read_dir_files_first(
            self.options.location,
            Self::credential_directory(),
            None
        ))
        .data;
        let mut maybe_credential: Option<CredentialFlat> = match maybe_credential_enc {
            None => None,
            Some(c) => self.state.decrypt_content(&mut self.trussed, c).ok(),
        };

        while let Some(credential) = maybe_credential {
            // add to response
            reply.push(0x71).unwrap();
            reply.push(credential.label.len() as u8).unwrap();
            reply.extend_from_slice(&credential.label).unwrap();

            // calculate the value
            if credential.kind == oath::Kind::Totp {
                let truncated_digest = crate::calculate::calculate(
                    &mut self.trussed,
                    credential.algorithm,
                    calculate_all.challenge,
                    &credential.secret,
                )?;
                reply.push(0x76).unwrap();
                reply.push(5).unwrap();
                reply.push(credential.digits).unwrap();
                reply.extend_from_slice(&truncated_digest).unwrap();
            } else {
                reply.push(0x77).unwrap();
                reply.push(0).unwrap();
            };

            // check if there's more
            maybe_credential = match syscall!(self.trussed.read_dir_files_next()).data {
                None => None,
                Some(c) => self.state.decrypt_content(&mut self.trussed, c).ok(),
            };
        }

        // ran to completion
        Ok(())
    }

    fn try_to_serialize_credential_for_get_credential<const R: usize>(
        credential: CredentialFlat,
        reply: &mut Data<R>,
    ) -> core::result::Result<(), u8> {
        reply.push(oath::Tag::Property as u8)?;
        reply.push(1)?;
        reply.push(oath::combine(credential.kind, credential.algorithm))?;

        for (tag, field) in &[
            (oath::Tag::Name, Some(credential.label)),
            (oath::Tag::PwsLogin, credential.login),
            (oath::Tag::PwsPassword, credential.password),
            (oath::Tag::PwsMetadata, credential.metadata),
        ] {
            if let Some(value) = field {
                reply.push(*tag as u8)?;
                reply.push((value.len()) as u8)?;
                reply.extend_from_slice(&value).map_err(|_| 0)?;
            }
            if reply.len() > CTAPHID_MESSAGE_SIZE_LIMIT {
                // Finish early due to the usbd-ctaphid message size limit
                return Err(1);
            }
        }
        Ok(())
    }

    fn get_credential<const R: usize>(
        &mut self,
        get_credential_req: command::GetCredential<'_>,
        reply: &mut Data<R>,
    ) -> Result {
        let credential = self
            .load_credential(get_credential_req.label)
            .ok_or(Status::NotFound)?;

        self.require_touch_if_needed(&credential)?;

        Self::try_to_serialize_credential_for_get_credential(credential, reply)
            .map_err(|_| UnspecifiedNonpersistentExecutionError)?;
        Ok(())
    }

    fn require_touch_if_needed(&mut self, credential: &CredentialFlat) -> Result<()> {
        // DESIGN Daily use: require touch button if set on the credential, but not if the PIN was already checked
        // Safety: encryption_key_type should be set for credential during loading in load_credential
        if credential.touch_required
            && credential.encryption_key_type.unwrap() != EncryptionKeyType::PinBased
        {
            self.user_present()?;
        }
        Ok(())
    }

    fn calculate<const R: usize>(
        &mut self,
        calculate: command::Calculate<'_>,
        reply: &mut Data<R>,
    ) -> Result {
        // info_now!("recv {:?}", &calculate);

        let credential = self
            .load_credential(calculate.label)
            .ok_or(Status::NotFound)?;

        self.require_touch_if_needed(&credential)?;

        let truncated_digest = match credential.kind {
            oath::Kind::Totp => crate::calculate::calculate(
                &mut self.trussed,
                credential.algorithm,
                calculate.challenge,
                &credential.secret,
            )?,
            oath::Kind::Hotp => {
                if let Some(counter) = credential.counter {
                    self.calculate_hotp_digest_and_bump_counter(&credential, counter)?
                } else {
                    error_now!("HOTP missing its counter");
                    return Err(Status::UnspecifiedPersistentExecutionError);
                }
            }
            _ => {
                // This credential kind should never be accessed through calculate()
                return Err(Status::ConditionsOfUseNotSatisfied);
            }
        };

        // SW: 71 0F 36 30 2F 73 6F 6C 6F 6B 65 79 73 37 5F 36 30 76 05 07 3D 8E 94 CF 90 00
        //
        // correct:
        // SW: 76 05 07 15 F9 B0 1F 90 00
        //
        // incorrect:
        // SW: 76 05 07 60 D2 F2 7C 90 00

        // response.push(0x71).unwrap();
        // response.push(credential.label.len() as u8).unwrap();
        // response.extend_from_slice(credential.label).unwrap();

        reply.push(0x76).unwrap();
        reply.push(5).unwrap();
        reply.push(credential.digits).unwrap();
        reply.extend_from_slice(&truncated_digest).unwrap();
        Ok(())
    }

    #[cfg(feature = "challenge-response-auth")]
    fn validate<const R: usize>(
        &mut self,
        validate: command::Validate<'_>,
        reply: &mut Data<R>,
    ) -> Result {
        let command::Validate {
            response,
            challenge,
        } = validate;

        if let Some(key) = self
            .state
            .with_persistent(&mut self.trussed, |_, state| state.authorization_key)
        {
            debug_now!("key set: {:?}", key);

            // 1. verify what the client sent (rotating challenge)
            let verification = try_syscall!(self
                .trussed
                .sign_hmacsha1(key, &self.state.runtime.challenge))
            .map_err(|_| Status::NotEnoughMemory)?
            .signature;

            self.state.runtime.challenge = try_syscall!(self.trussed.random_bytes(8))
                .map_err(|_| Status::NotEnoughMemory)?
                .bytes
                .as_ref()
                .try_into()
                .map_err(|_| Status::NotEnoughMemory)?;

            if verification != response {
                return Err(Status::IncorrectDataParameter);
            }

            self.state.runtime.client_newly_authorized = true;

            // 2. calculate our response to their challenge
            let response = try_syscall!(self.trussed.sign_hmacsha1(key, challenge))
                .map_err(|_| Status::NotEnoughMemory)?
                .signature;

            reply.push(0x75).ok();
            reply.push(20).ok();
            reply.extend_from_slice(&response).ok();
            debug_now!(
                "validated client! client_newly_authorized = {}",
                self.state.runtime.client_newly_authorized
            );
            Ok(())
        } else {
            Err(Status::ConditionsOfUseNotSatisfied)
        }

        // APDU: 00 A3 00 00 20 (AUTHENTICATE)
        //       75 14
        //             8C E0 33 83 E6 A9 0D 27 8B E7 D2 EF 9E 3B 1F DB F4 5E 91 35
        //       74 08
        //             AF C9 BA 64 22 6D F0 78
        // SW: 75 14
        //             87 BE EB AB 20 F4 C2 FA 24 EA 08 AB D3 4D C1 5B F0 51 DC 85
        //     90 00
        //

        //  response: &'l [u8; 20],
        //  challenge: &'l [u8; 8],
    }

    #[cfg(feature = "challenge-response-auth")]
    fn clear_password(&mut self) -> Result {
        self.user_present()?;

        if !self.state.runtime.client_authorized {
            return Err(Status::ConditionsOfUseNotSatisfied);
        }
        debug_now!("clearing password/key");
        if let Some(key) = self
            .state
            .try_with_persistent_mut(&mut self.trussed, |_, state| {
                let existing_key = state.authorization_key;
                state.authorization_key = None;
                Ok(existing_key)
            })
            .map_err(|_| Status::NotEnoughMemory)?
        {
            syscall!(self.trussed.delete(key));
        }
        Ok(())
    }

    #[cfg(feature = "challenge-response-auth")]
    fn set_password(&mut self, set_password: command::SetPassword<'_>) -> Result {
        self.user_present()?;

        // when there is no password set:
        // APDU: 00 A4 04 00 07 (SELECT)
        //                      A0 00 00 05 27 21 01
        // SW: 79 03
        //           01 00 00
        //     71 08
        //           26 9F 14 54 3A 0E C7 AC
        //     90 00
        //
        // APDU: 00 03 00 00 33 (SET PASSWORD)
        //       73 11
        //             21 83 93 58 A6 E1 A1 F6 AB 13 46 F6 5E 56 6F 26 8A
        //       74 08
        //             7D CB 79 D5 74 AA 68 6D
        //       75 14
        //             73 CA E7 96 6F 32 A8 49 9E B0 F9 D6 D0 3E AA 06 23 59 C6 F2
        // SW: 90 00

        // when there is a password previously set:
        //
        // APDU: 00 A4 04 00 07 (SELECT)
        //                      A0 00 00 05 27 21 01
        // SW: 79 03
        //           01 00 00
        //     71 08
        //           26 9F 14 54 3A 0E C7 AC
        //     74 08 (SALT, signals password is set)
        //           13 FB E9 67 DF 91 BB 89
        //     7B 01 (ALGORITHM, not sure what for)
        //           21
        //     90 00
        //
        // APDU: 00 A3 00 00 20 (AUTHENTICATE)
        //       75 14
        //             8C E0 33 83 E6 A9 0D 27 8B E7 D2 EF 9E 3B 1F DB F4 5E 91 35
        //       74 08
        //             AF C9 BA 64 22 6D F0 78
        // SW: 75 14
        //             87 BE EB AB 20 F4 C2 FA 24 EA 08 AB D3 4D C1 5B F0 51 DC 85
        //     90 00
        //
        // APDU: 00 03 00 00 33 (SET PASSWORD)
        //       73 11
        //             21 83 93 58 A6 E1 A1 F6 AB 13 46 F6 5E 56 6F 26 8A
        //       74 08
        //             08 7A 1C 76 17 12 C7 9D
        //       75 14
        //             4F B0 29 1A 0E FC 88 46 FA 30 FF A4 C7 1E 51 A5 50 79 9A B8
        // SW: 90 00

        info_now!("entering set password");
        if !self.state.runtime.client_authorized {
            return Err(Status::ConditionsOfUseNotSatisfied);
        }

        let command::SetPassword {
            kind,
            algorithm,
            key,
            challenge,
            response,
        } = set_password;

        info_now!("just checking");
        if kind != oath::Kind::Totp || algorithm != oath::Algorithm::Sha1 {
            return Err(Status::InstructionNotSupportedOrInvalid);
        }

        info_now!("injecting the key");
        let tmp_key = try_syscall!(self
            .trussed
            .unsafe_inject_shared_key(key, Location::Volatile,))
        .map_err(|_| Status::NotEnoughMemory)?
        .key;

        let verification = syscall!(self.trussed.sign_hmacsha1(tmp_key, challenge)).signature;
        syscall!(self.trussed.delete(tmp_key));

        // not really sure why this is all sent along, I guess some kind of fear of bitrot en-route?
        if verification != response {
            return Err(Status::IncorrectDataParameter);
        }

        // all-right, we have a new password to set
        let key = try_syscall!(self
            .trussed
            .unsafe_inject_shared_key(key, self.options.location))
        .map_err(|_| Status::NotEnoughMemory)?
        .key;

        debug_now!("storing password/key");
        self.state
            .try_with_persistent_mut(&mut self.trussed, |_, state| {
                state.authorization_key = Some(key);
                Ok(())
            })
            .map_err(|_| Status::NotEnoughMemory)?;

        //  struct SetPassword<'l> {
        //      kind: oath::Kind,
        //      algorithm: oath::Algorithm,
        //      key: &'l [u8],
        //      challenge: &'l [u8],
        //      response: &'l [u8],
        // }
        Ok(())
    }

    /// Verify the HOTP code coming from a PC host, and show visually to user,
    /// that the code is correct or not, with a green or red LED respectively.
    /// Does not need authorization by design.
    ///
    /// https://github.com/Nitrokey/nitrokey-hotp-verification#verifying-hotp-code
    /// Solution contains a mean to avoid desynchronization between the host's and device's counters. Device calculates up to 9 values ahead of its current counter to find the matching code (in total it calculates HOTP code for 10 subsequent counter positions). In case:
    ///
    /// - no code would match - the on-device counter will not be changed;
    /// - incoming code parsing would fail - the on-device counter will not be changed;
    /// - code would match, but with some counter's offset (up to 9) - the on-device counter will be set to matched code-generated HOTP counter and incremented by 1;
    /// - code would match, and the code matches counter without offset - the counter will be incremented by 1.
    ///
    /// Device will stop verifying the HOTP codes in case, when the difference between the host and on-device counters will be greater or equal to 10.
    fn verify_code<const R: usize>(&mut self, args: VerifyCode, reply: &mut Data<{ R }>) -> Result {
        const COUNTER_WINDOW_SIZE: u32 = 9;

        #[cfg(feature = "brute-force-delay")]
        {
            self.deny_if_too_soon_after_failure()?;
            self.mark_failed_verification_time()?;
        }

        let credential = self.load_credential(args.label).ok_or(Status::NotFound)?;

        self.require_touch_if_needed(&credential)?;

        let code_in = args.response;

        let current_counter = match credential.kind {
            oath::Kind::HotpReverse => {
                if let Some(counter) = credential.counter {
                    counter
                } else {
                    debug_now!("HOTP missing its counter");
                    return Err(Status::UnspecifiedPersistentExecutionError);
                }
            }
            _ => return Err(Status::ConditionsOfUseNotSatisfied),
        };
        let mut found = None;
        for offset in 0..=COUNTER_WINDOW_SIZE {
            // Do abort with error on the max value, so these could not be pregenerated,
            // and returned to user after overflow, or the same code used each time
            let counter = current_counter
                .checked_add(offset)
                .ok_or(Status::UnspecifiedPersistentExecutionError)?;
            let code = self
                .calculate_hotp_code_for_counter(&credential, counter)
                .map_err(|_| Status::UnspecifiedPersistentExecutionError)?;
            if code == code_in {
                found = Some(counter);
                break;
            }
        }

        let found = match found {
            None => {
                // Failed verification
                self.wink_bad();
                return Err(Status::VerificationFailed);
            }
            Some(val) => val,
        };

        self.bump_counter_for_cred(&credential, found)?;
        #[cfg(feature = "brute-force-delay")]
        self.clear_failed_verification_time();
        self.wink_good();

        // Verification passed
        // Return "No response". Communicate only through error codes.
        reply.push(0x77).unwrap();
        reply.push(0).unwrap();
        Ok(())
    }

    fn calculate_hotp_code_for_counter(
        &mut self,
        credential: &CredentialFlat,
        counter: u32,
    ) -> iso7816::Result<u32> {
        let truncated_digest = self.calculate_hotp_digest_for_counter(credential, counter)?;
        let truncated_code = u32::from_be_bytes(truncated_digest);
        let code = (truncated_code & 0x7FFFFFFF)
            % 10u32
                .checked_pow(credential.digits as _)
                .ok_or(Status::UnspecifiedPersistentExecutionError)?;
        debug_now!("Code for ({:?},{}): {}", credential.label, counter, code);
        Ok(code)
    }

    fn calculate_hotp_digest_and_bump_counter(
        &mut self,
        credential: &CredentialFlat,
        counter: u32,
    ) -> iso7816::Result<[u8; 4]> {
        let credential = self.bump_counter_for_cred(credential, counter)?;
        let res = self.calculate_hotp_digest_for_counter(&credential, counter)?;
        Ok(res)
    }

    fn bump_counter_for_cred(
        &mut self,
        credential: &CredentialFlat,
        counter: u32,
    ) -> Result<CredentialFlat> {
        // Do abort with error on the max value, so these could not be pregenerated,
        // and returned to user after overflow, or the same code used each time
        // load-bump counter
        let mut credential = credential.clone();
        credential.counter = Some(
            counter
                .checked_add(1)
                .ok_or(Status::UnspecifiedPersistentExecutionError)?,
        );
        // save credential back, with the updated counter
        let filename = self.filename_for_label(&credential.label);
        self.state.try_write_file(
            &mut self.trussed,
            filename,
            &credential,
            credential.encryption_key_type,
        )?;

        Ok(credential)
    }

    fn calculate_hotp_digest_for_counter(
        &mut self,
        credential: &CredentialFlat,
        counter: u32,
    ) -> Result<[u8; 4]> {
        let counter_long: u64 = counter.into();
        crate::calculate::calculate(
            &mut self.trussed,
            credential.algorithm,
            &counter_long.to_be_bytes(),
            &credential.secret,
        )
    }

    pub fn _extension_logout(&mut self) -> Result {
        if let Some(key) = self.state.runtime.encryption_key.take() {
            try_syscall!(self.trussed.delete(key))
                .map_err(|e| Self::_debug_trussed_backend_error(e, line!()))?;
        }
        Ok(())
    }

    fn _extension_pin_factory_reset(&mut self) -> Result {
        self._extension_logout()?;

        if let Some(key) = self.state.runtime.encryption_key_hardware.take() {
            try_syscall!(self.trussed.delete(key))
                .map_err(|e| Self::_debug_trussed_backend_error(e, line!()))?;
        }

        try_syscall!(self.trussed.delete_all_pins())
            .map_err(|e| Self::_debug_trussed_backend_error(e, line!()))?;

        Ok(())
    }

    fn _extension_check_pin(&mut self, password: &[u8]) -> Result {
        let reply = try_syscall!(self.trussed.check_pin(
            BACKEND_USER_PIN_ID,
            Bytes::from_slice(password).map_err(|_| iso7816::Status::IncorrectDataParameter)?
        ))
        .map_err(|_| iso7816::Status::SecurityStatusNotSatisfied)?;
        if !(reply.success) {
            Err(Status::SecurityStatusNotSatisfied)
        } else {
            Ok(())
        }
    }

    fn _extension_get_hardware_key(&mut self) -> Result<KeyId> {
        let reply = try_syscall!(self
            .trussed
            .get_application_key(Message::from_slice("default secrets key".as_ref()).unwrap()))
        .map_err(|e| Self::_debug_trussed_backend_error(e, line!()))?;
        Ok(reply.key)
    }

    fn _extension_set_pin(&mut self, password: &[u8]) -> Result {
        try_syscall!(self.trussed.set_pin(
            BACKEND_USER_PIN_ID,
            Bytes::from_slice(password).map_err(|_| iso7816::Status::IncorrectDataParameter)?,
            Some(ATTEMPT_COUNTER_DEFAULT_RETRIES),
            true
        ))
        .map_err(|e| Self::_debug_trussed_backend_error(e, line!()))?;
        Ok(())
    }

    fn _debug_trussed_backend_error(_e: trussed::Error, _l: u32) -> iso7816::Status {
        info_now!("Trussed backend error: {:?} (line {:?})", _e, _l);
        iso7816::Status::UnspecifiedNonpersistentExecutionError
    }

    fn _extension_change_pin(&mut self, password: &[u8], new_password: &[u8]) -> Result {
        let r = try_syscall!(self.trussed.change_pin(
            BACKEND_USER_PIN_ID,
            Bytes::from_slice(password).map_err(|_| iso7816::Status::IncorrectDataParameter)?,
            Bytes::from_slice(new_password).map_err(|_| iso7816::Status::IncorrectDataParameter)?,
        ))
        .map_err(|e| Self::_debug_trussed_backend_error(e, line!()))?;
        if !r.success {
            return Err(iso7816::Status::VerificationFailed);
        }
        Ok(())
    }

    fn _extension_attempt_counter(&mut self) -> Option<u8> {
        let reply = try_syscall!(self.trussed.pin_retries(BACKEND_USER_PIN_ID)).ok();
        reply?.retries
    }

    fn _extension_get_key_for_pin(&mut self, password: &[u8]) -> Result<KeyId> {
        let reply = try_syscall!(self.trussed.get_pin_key(
            BACKEND_USER_PIN_ID,
            Bytes::from_slice(password).map_err(|_| iso7816::Status::IncorrectDataParameter)?
        ))
        .map_err(|e| Self::_debug_trussed_backend_error(e, line!()))?;
        reply.result.ok_or(iso7816::Status::VerificationFailed)
    }

    fn _extension_is_pin_set(&mut self) -> Result<bool> {
        let r = try_syscall!(self.trussed.has_pin(BACKEND_USER_PIN_ID))
            .map_err(|e| Self::_debug_trussed_backend_error(e, line!()))?;
        Ok(r.has_pin)
    }

    fn verify_pin<const R: usize>(
        &mut self,
        verify_pin: command::VerifyPin<'_>,
        _reply: &mut Data<R>,
    ) -> Result {
        if !self._extension_is_pin_set()? {
            return Err(Status::SecurityStatusNotSatisfied);
        }

        self._extension_logout()?;

        // DESIGN Always ask for touch button confirmation before verifying PIN, to prevent
        // non-intentional attempt counter use up
        self.user_present()?;

        let command::VerifyPin { password } = verify_pin;
        // Returns error, if the PIN is not set, or incorrect. Otherwise returns the KeyId
        self.state.runtime.encryption_key = Some(self._extension_get_key_for_pin(password)?);

        self.state.runtime.client_newly_authorized = true;
        Ok(())
    }

    fn set_pin<const R: usize>(
        &mut self,
        set_pin: command::SetPin<'_>,
        _reply: &mut Data<R>,
    ) -> Result {
        if self._extension_is_pin_set()? {
            return Err(Status::SecurityStatusNotSatisfied);
        }
        // DESIGN Set PIN: always confirm with touch button
        self.user_present()?;

        let command::SetPin { password } = set_pin;
        self._extension_set_pin(password)
            .map_err(|_| Status::VerificationFailed)?;

        self.state.runtime.client_newly_authorized = true;
        Ok(())
    }

    fn change_pin<const R: usize>(
        &mut self,
        change_pin: command::ChangePin<'_>,
        _reply: &mut Data<R>,
    ) -> Result {
        if !self._extension_is_pin_set()? {
            return Err(Status::SecurityStatusNotSatisfied);
        }
        // DESIGN Change PIN: always confirm with touch button
        self.user_present()?;

        let command::ChangePin {
            password,
            new_password,
        } = change_pin;

        self._extension_change_pin(password, new_password)
            .map_err(|_| Status::VerificationFailed)?;
        Ok(())
    }

    fn user_present(&mut self) -> Result {
        use crate::UP_TIMEOUT_MILLISECONDS;
        let result = syscall!(self.trussed.confirm_user_present(UP_TIMEOUT_MILLISECONDS)).result;
        result.map_err(|err| match err {
            trussed::types::consent::Error::TimedOut => Status::SecurityStatusNotSatisfied,
            _ => Status::UnspecifiedPersistentExecutionError,
        })
    }

    /// Clear failed Reverse HOTP verification state. Should be called on successful verification.
    #[cfg(feature = "brute-force-delay")]
    fn clear_failed_verification_time(&mut self) {
        self.state.runtime.last_failed_request = None;
    }

    #[cfg(feature = "brute-force-delay")]
    fn mark_failed_verification_time(&mut self) -> Result {
        let uptime = self.get_uptime()?;
        self.state.runtime.last_failed_request = Some(uptime);
        Ok(())
    }

    #[cfg(feature = "brute-force-delay")]
    fn get_uptime(&mut self) -> Result<Duration> {
        let uptime = try_syscall!(self.trussed.uptime())
            .map_err(|_| iso7816::Status::SecurityStatusNotSatisfied)?
            .uptime;
        Ok(uptime)
    }

    fn wink_bad(&mut self) {
        // Blink red LED infinite times, highest priority
        warn!("Verification failed, calling critical error status");
        syscall!(self
            .trussed
            .set_custom_status(self.options.custom_status_reverse_hotp_error));
    }

    fn wink_good(&mut self) {
        // Blink green LED for 10 seconds, highest priority
        info!("Verification passed, calling success status");
        syscall!(self
            .trussed
            .set_custom_status(self.options.custom_status_reverse_hotp_success));
    }

    /// Deny request, if required time from the last one failed has not passed yet
    /// Make brute-force attack slower.
    #[cfg(feature = "brute-force-delay")]
    fn deny_if_too_soon_after_failure(&mut self) -> Result {
        if let Some(lft) = self.state.runtime.last_failed_request {
            let uptime = self.get_uptime()?;
            if uptime.saturating_sub(lft) < REQUIRED_DELAY_ON_FAILED_VERIFICATION {
                info!("Not enough time has passed since the last failed verification attempt. Rejecting request.");
                return Err(Status::SecurityStatusNotSatisfied);
            }
        }
        return Ok(());
    }

    fn yk_hmac<const R: usize>(&mut self, req: YKGetHMAC, reply: &mut Data<{ R }>) -> Result {
        // Get HMAC slot command
        let credential = self
            .load_credential(req.get_credential_label()?)
            .ok_or(Status::NotFound)?;
        let credential: Credential = credential.try_unpack_into_credential()?;
        if let Some(otpdata) = credential.otp {
            if let HmacData(x) = otpdata {
                let key: &[u8] = x.secret;
                let signature =
                    hmac_challenge(&mut self.trussed, Algorithm::Sha1, req.challenge, key)?;
                reply
                    .extend_from_slice(signature.as_slice())
                    .map_err(|_| UnspecifiedNonpersistentExecutionError)?;
                Ok(())
            } else {
                return Err(Status::IncorrectDataParameter);
            }
        } else {
            return Err(Status::IncorrectDataParameter);
        }
    }

    fn yk_status<const R: usize>(&self, reply: &mut Data<{ R }>) -> Result {
        // Get 6 bytes status; 3 bytes version, 3 bytes other data
        // TODO Discuss, should this be application or runner firmware version
        let v = OathVersion::default();
        let firmware_version = &[v.major, v.minor, v.patch];
        reply
            .extend_from_slice(firmware_version)
            .map_err(|_| UnspecifiedPersistentExecutionError)?;

        // Add filler to match the expected 6 bytes
        // TODO Check the actual data format for the YK request
        let other_data = &[0x42, 0x42, 0x42];
        reply
            .extend_from_slice(other_data)
            .map_err(|_| UnspecifiedPersistentExecutionError)?;
        Ok(())
    }

    fn yk_serial<const R: usize>(&self, reply: &mut Data<{ R }>) -> Result {
        // Get 4-byte serial
        reply
            .extend_from_slice(&self.options.serial_number)
            .map_err(|_| UnspecifiedPersistentExecutionError)?;
        Ok(())
    }
}

impl<T> iso7816::App for Authenticator<T> {
    fn aid(&self) -> iso7816::Aid {
        iso7816::Aid::new(crate::YUBICO_OATH_AID)
    }
}

#[cfg(feature = "apdu-dispatch")]
impl<T, const C: usize, const R: usize> apdu_dispatch::app::App<C, R> for Authenticator<T>
where
    T: client::Client
        + client::HmacSha1
        + client::HmacSha256
        + client::Sha256
        + client::Chacha8Poly1305
        + trussed_auth::AuthClient,
{
    fn select(&mut self, apdu: &iso7816::Command<C>, reply: &mut Data<R>) -> Result {
        self.respond(apdu, reply)
    }

    fn deselect(&mut self) { /*self.deselect()*/
    }

    fn call(
        &mut self,
        _: iso7816::Interface,
        apdu: &iso7816::Command<C>,
        reply: &mut Data<R>,
    ) -> Result {
        self.respond(apdu, reply)
    }
}
