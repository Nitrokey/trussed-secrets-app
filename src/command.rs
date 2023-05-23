use block_padding::{Pkcs7, RawPadding};
use core::convert::{TryFrom, TryInto};
use flexiber::{SimpleTag, TagLike};
use serde::{Deserialize, Serialize};

use iso7816::command::class::Class;
use iso7816::{Data, Instruction, Status};
use YkCommand::GetSerial;

use crate::oath::{Tag, YkCommand};
use crate::{ensure, oath};

const FAILED_PARSING_ERROR: Status = Status::IncorrectDataParameter;

/// Decoded command request, along with data
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Command<'l> {
    /// Select the application
    Select(Select<'l>),
    /// Calculate the authentication data for a credential given by label.
    Calculate(Calculate<'l>),
    /// Calculate the authentication data for all credentials.
    CalculateAll(CalculateAll<'l>),
    /// Clear the password.
    ClearPassword,
    /// Delete a credential.
    Delete(Delete<'l>),
    /// List all credentials.
    ListCredentials(ListCredentials),
    /// Register a new credential.
    Register(Register<'l>),
    /// Delete all credentials and rotate the salt.
    Reset,
    /// Set a password.
    SetPassword(SetPassword<'l>),
    /// Validate the password (both ways).
    Validate(Validate<'l>),
    /// Verify PIN through the backend
    VerifyPin(VerifyPin<'l>),
    /// Set PIN through the backend
    SetPin(SetPin<'l>),
    /// Change PIN through the backend
    ChangePin(ChangePin<'l>),
    /// Reverse HOTP validation
    VerifyCode(VerifyCode<'l>),
    /// Send remaining data in the buffer
    SendRemaining,
    /// Get Credential data
    GetCredential(GetCredential<'l>),
    /// Return serial number of the device. Yubikey-compatible command. Used in KeepassXC.
    YkSerial,
    /// Return application's status. Yubikey-compatible command. Used in KeepassXC.
    YkGetStatus,
    /// Get the HMAC response for a challenge. Yubikey-compatible command. Used in KeepassXC.
    YkGetHmac(YkGetHmac<'l>),
}

#[derive(Clone, Copy, Eq, PartialEq, Debug)]
pub struct YkGetHmac<'l> {
    /// challenge, padded with PKCS#7 to 64 bytes
    pub challenge: &'l [u8],
    /// The P1 parameter selecting the command, or the HMAC slot
    pub slot_cmd: Option<YkCommand>,
}

impl<'l, const C: usize> TryFrom<&'l Data<C>> for YkGetHmac<'l> {
    type Error = Status;
    fn try_from(data: &'l Data<C>) -> Result<Self, Self::Error> {
        Ok(Self {
            challenge: data,
            slot_cmd: None,
        })
    }
}

impl<'l> YkGetHmac<'l> {
    pub fn get_credential_label(&self) -> Result<&[u8], Status> {
        Ok(match self.slot_cmd.ok_or(Status::IncorrectDataParameter)? {
            YkCommand::HmacSlot1 => "HmacSlot1",
            YkCommand::HmacSlot2 => "HmacSlot2",
            _ => {
                return Err(Status::IncorrectDataParameter);
            }
        }
        .as_bytes())
    }
    fn with_slot(&self, slot: u8) -> Result<Self, Status> {
        let slot = YkCommand::try_from(slot)?;
        match slot {
            YkCommand::HmacSlot1 => {}
            YkCommand::HmacSlot2 => {}
            _ => return Err(Status::IncorrectDataParameter),
        };
        Ok(YkGetHmac {
            challenge: self.challenge,
            slot_cmd: Some(slot),
        })
    }
}

impl<'l> TryFrom<&'l [u8]> for YkGetHmac<'l> {
    type Error = Status;
    fn try_from(data: &'l [u8]) -> Result<Self, Self::Error> {
        // Input data should always be padded to 64 bytes
        ensure(data.len() == 64, Status::IncorrectDataParameter)?;
        // PKCS#7 padding; possibly incompatible with Yubikey's PKCS#7 version, as it expects
        // the last byte to always be the padding byte value. See KeepassXC implementation comments
        // for the details.
        // https://github.com/Nitrokey/keepassxc/blob/cf819e0a3f5664fb0e1705217dbebbdf704bdc34/src/keys/drivers/YubiKeyInterfacePCSC.cpp#L730
        // Everything works with the challenge length up to 63 bytes though, and YK implementation
        // would not handle more anyway, hence accepting this potential incompatibility.
        let challenge = Pkcs7::raw_unpad(data).map_err(|_| Status::IncorrectDataParameter)?;
        if challenge.is_empty() {
            // All sent is padding
            return Err(Status::IncorrectDataParameter);
        }

        Ok(Self {
            challenge,
            slot_cmd: None,
        })
    }
}

/// TODO: change into enum
#[derive(Clone, Copy, Eq, PartialEq)]
pub struct Select<'l> {
    pub aid: &'l [u8],
}

impl core::fmt::Debug for Select<'_> {
    fn fmt(&self, fmt: &mut core::fmt::Formatter<'_>) -> Result<(), core::fmt::Error> {
        fmt.debug_struct("Select")
            .field("aid", &hex_str!(&self.aid, 5))
            .finish()
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SetPassword<'l> {
    pub kind: oath::Kind,
    pub algorithm: oath::Algorithm,
    pub key: &'l [u8],
    pub challenge: &'l [u8],
    pub response: &'l [u8],
}

impl<'l, const C: usize> TryFrom<&'l Data<C>> for SetPassword<'l> {
    type Error = Status;
    fn try_from(data: &'l Data<C>) -> Result<Self, Self::Error> {
        // key = self.derive_key(password)
        // keydata = bytearray([OATH_TYPE.TOTP | ALGO.SHA1]) + key
        // challenge = os.urandom(8)
        // h = hmac.HMAC(key, hashes.SHA1(), default_backend())  # nosec
        // h.update(challenge)
        // response = h.finalize()
        // data = Tlv(TAG.KEY, keydata) + Tlv(TAG.CHALLENGE, challenge) + Tlv(
        //     TAG.RESPONSE, response)
        // self.send_apdu(INS.SET_CODE, 0, 0, data)
        // return key

        use flexiber::TaggedSlice;
        let mut decoder = flexiber::Decoder::new(data);
        let slice: TaggedSlice = decoder.decode().map_err(|_| FAILED_PARSING_ERROR)?;
        ensure(
            slice.tag() == (Tag::Key as u8).try_into().unwrap(),
            FAILED_PARSING_ERROR,
        )?;
        if slice.as_bytes().len() < 2 {
            return Err(FAILED_PARSING_ERROR);
        };
        let (key_header, key) = slice.as_bytes().split_at(1);

        let kind: oath::Kind = key_header[0].try_into()?;
        // assert!(kind == oath::Kind::Totp);
        let algorithm: oath::Algorithm = key_header[0].try_into()?;
        // assert!(algorithm == oath::Algorithm::Sha1);

        let slice: TaggedSlice = decoder.decode().map_err(|_| FAILED_PARSING_ERROR)?;
        ensure(
            slice.tag() == (Tag::Challenge as u8).try_into().unwrap(),
            FAILED_PARSING_ERROR,
        )?;
        let challenge = slice.as_bytes();
        // assert_eq!(challenge.len(), 8);

        let slice: TaggedSlice = decoder.decode().map_err(|_| FAILED_PARSING_ERROR)?;
        ensure(
            slice.tag() == (Tag::Response as u8).try_into().unwrap(),
            FAILED_PARSING_ERROR,
        )?;
        let response = slice.as_bytes();
        // assert_eq!(response.len(), 20);

        Ok(SetPassword {
            kind,
            algorithm,
            key,
            challenge,
            response,
        })
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Validate<'l> {
    pub response: &'l [u8],
    pub challenge: &'l [u8],
}

impl<'l, const C: usize> TryFrom<&'l Data<C>> for Validate<'l> {
    type Error = Status;
    fn try_from(data: &'l Data<C>) -> Result<Self, Self::Error> {
        use flexiber::TaggedSlice;
        let mut decoder = flexiber::Decoder::new(data);

        let slice: TaggedSlice = decoder.decode().map_err(|_| FAILED_PARSING_ERROR)?;
        ensure(
            slice.tag() == (Tag::Response as u8).try_into().unwrap(),
            FAILED_PARSING_ERROR,
        )?;
        let response = slice.as_bytes();

        let slice: TaggedSlice = decoder.decode().map_err(|_| FAILED_PARSING_ERROR)?;
        ensure(
            slice.tag() == (Tag::Challenge as u8).try_into().unwrap(),
            FAILED_PARSING_ERROR,
        )?;
        let challenge = slice.as_bytes();

        Ok(Validate {
            challenge,
            response,
        })
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct VerifyCode<'l> {
    pub label: &'l [u8],
    pub response: u32,
}

impl<'l, const C: usize> TryFrom<&'l Data<C>> for VerifyCode<'l> {
    type Error = Status;
    fn try_from(data: &'l Data<C>) -> Result<Self, Self::Error> {
        use flexiber::TaggedSlice;
        let mut decoder = flexiber::Decoder::new(data);

        let first: TaggedSlice = decoder.decode().map_err(|_| FAILED_PARSING_ERROR)?;
        ensure(
            first.tag() == (Tag::Name as u8).try_into().unwrap(),
            FAILED_PARSING_ERROR,
        )?;
        let label = first.as_bytes();

        let slice: TaggedSlice = decoder.decode().map_err(|_| FAILED_PARSING_ERROR)?;
        ensure(
            slice.tag() == (Tag::Response as u8).try_into().unwrap(),
            FAILED_PARSING_ERROR,
        )?;
        let response = u32::from_be_bytes(
            slice
                .as_bytes()
                .try_into()
                .map_err(|_| FAILED_PARSING_ERROR)?,
        );

        Ok(VerifyCode { label, response })
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SetPin<'l> {
    pub password: &'l [u8],
}

impl<'l, const C: usize> TryFrom<&'l Data<C>> for SetPin<'l> {
    type Error = Status;
    fn try_from(data: &'l Data<C>) -> Result<Self, Self::Error> {
        use flexiber::TaggedSlice;
        let mut decoder = flexiber::Decoder::new(data);

        let first: TaggedSlice = decoder.decode().map_err(|_| FAILED_PARSING_ERROR)?;
        ensure(
            first.tag() == (Tag::Password as u8).try_into().unwrap(),
            FAILED_PARSING_ERROR,
        )?;
        let password = first.as_bytes();

        Ok(SetPin { password })
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct GetCredential<'l> {
    pub label: &'l [u8],
}

impl<'l, const C: usize> TryFrom<&'l Data<C>> for GetCredential<'l> {
    type Error = Status;
    fn try_from(data: &'l Data<C>) -> Result<Self, Self::Error> {
        use flexiber::TaggedSlice;
        let mut decoder = flexiber::Decoder::new(data);

        let first: TaggedSlice = decoder.decode().map_err(|_| FAILED_PARSING_ERROR)?;
        ensure(
            first.tag() == (Tag::Name as u8).try_into().unwrap(),
            FAILED_PARSING_ERROR,
        )?;
        let label = first.as_bytes();

        Ok(GetCredential { label })
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ChangePin<'l> {
    pub password: &'l [u8],
    pub new_password: &'l [u8],
}

impl<'l, const C: usize> TryFrom<&'l Data<C>> for ChangePin<'l> {
    type Error = Status;
    fn try_from(data: &'l Data<C>) -> Result<Self, Self::Error> {
        use flexiber::TaggedSlice;
        let mut decoder = flexiber::Decoder::new(data);

        let first: TaggedSlice = decoder.decode().map_err(|_| FAILED_PARSING_ERROR)?;
        ensure(
            first.tag() == (Tag::Password as u8).try_into().unwrap(),
            FAILED_PARSING_ERROR,
        )?;
        let password = first.as_bytes();

        let second: TaggedSlice = decoder.decode().map_err(|_| FAILED_PARSING_ERROR)?;
        ensure(
            second.tag() == (Tag::NewPassword as u8).try_into().unwrap(),
            FAILED_PARSING_ERROR,
        )?;
        let new_password = second.as_bytes();

        Ok(ChangePin {
            password,
            new_password,
        })
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct VerifyPin<'l> {
    pub password: &'l [u8],
}

impl<'l, const C: usize> TryFrom<&'l Data<C>> for VerifyPin<'l> {
    type Error = Status;
    fn try_from(data: &'l Data<C>) -> Result<Self, Self::Error> {
        use flexiber::TaggedSlice;
        let mut decoder = flexiber::Decoder::new(data);

        let first: TaggedSlice = decoder.decode().map_err(|_| FAILED_PARSING_ERROR)?;
        ensure(
            first.tag() == (Tag::Password as u8).try_into().unwrap(),
            FAILED_PARSING_ERROR,
        )?;
        let password = first.as_bytes();

        Ok(VerifyPin { password })
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Calculate<'l> {
    pub label: &'l [u8],
    pub challenge: &'l [u8],
}

impl<'l, const C: usize> TryFrom<&'l Data<C>> for Calculate<'l> {
    type Error = Status;
    fn try_from(data: &'l Data<C>) -> Result<Self, Self::Error> {
        use flexiber::TaggedSlice;
        let mut decoder = flexiber::Decoder::new(data);

        let first: TaggedSlice = decoder.decode().map_err(|_| FAILED_PARSING_ERROR)?;
        ensure(
            first.tag() == (Tag::Name as u8).try_into().unwrap(),
            FAILED_PARSING_ERROR,
        )?;
        let label = first.as_bytes();

        let second: TaggedSlice = decoder.decode().map_err(|_| FAILED_PARSING_ERROR)?;
        ensure(
            second.tag() == (Tag::Challenge as u8).try_into().unwrap(),
            FAILED_PARSING_ERROR,
        )?;
        let challenge = second.as_bytes();

        Ok(Calculate { label, challenge })
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CalculateAll<'l> {
    pub challenge: &'l [u8],
}

impl<'l, const C: usize> TryFrom<&'l Data<C>> for CalculateAll<'l> {
    type Error = Status;
    fn try_from(data: &'l Data<C>) -> Result<Self, Self::Error> {
        use flexiber::TaggedSlice;
        let mut decoder = flexiber::Decoder::new(data);

        let first: TaggedSlice = decoder.decode().map_err(|_| FAILED_PARSING_ERROR)?;
        ensure(
            first.tag() == (Tag::Challenge as u8).try_into().unwrap(),
            FAILED_PARSING_ERROR,
        )?;
        let challenge = first.as_bytes();

        Ok(CalculateAll { challenge })
    }
}

#[derive(Clone, Copy, Eq, PartialEq)]
pub struct Delete<'l> {
    pub label: &'l [u8],
}

impl core::fmt::Debug for Delete<'_> {
    fn fmt(&self, fmt: &mut core::fmt::Formatter<'_>) -> Result<(), core::fmt::Error> {
        fmt.debug_struct("Credential")
            .field(
                "label",
                &core::str::from_utf8(self.label).unwrap_or("invalid UTF8 label"),
            )
            .finish()
    }
}

impl<'l, const C: usize> TryFrom<&'l Data<C>> for Delete<'l> {
    type Error = Status;
    fn try_from(data: &'l Data<C>) -> Result<Self, Self::Error> {
        use flexiber::TaggedSlice;
        let mut decoder = flexiber::Decoder::new(data);

        let first: TaggedSlice = decoder.decode().map_err(|_| FAILED_PARSING_ERROR)?;
        ensure(
            first.tag() == (Tag::Name as u8).try_into().unwrap(),
            FAILED_PARSING_ERROR,
        )?;
        let label = first.as_bytes();

        Ok(Delete { label })
    }
}

impl<'l, const C: usize> TryFrom<&'l Data<C>> for ListCredentials {
    type Error = Status;
    fn try_from(data: &'l Data<C>) -> Result<Self, Self::Error> {
        let v = if !data.is_empty() { data[0] } else { 0 };
        Ok(ListCredentials { version: v })
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ListCredentials {
    pub version: u8,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Register<'l> {
    pub credential: Credential<'l>,
}

#[derive(Clone, Copy, Eq, PartialEq, Debug)]
pub struct Credential<'l> {
    pub label: &'l [u8],
    pub touch_required: bool,
    pub encryption_key_type: EncryptionKeyType,
    pub otp: Option<CredentialData<'l>>,
    pub password_safe: Option<PasswordSafeData<'l>>,
}

#[derive(Clone, Copy, Eq, PartialEq, Debug)]
pub enum CredentialData<'l> {
    OtpData(OtpCredentialData<'l>),
    HmacData(HmacData<'l>),
}

#[derive(Clone, Copy, Eq, PartialEq, Debug)]
pub struct OtpCredentialData<'l> {
    pub kind: oath::Kind,
    pub algorithm: oath::Algorithm,
    pub digits: u8,
    pub secret: &'l [u8],
    pub counter: Option<u32>,
}

// non_exhaustive added to prevent construction without validation check
#[non_exhaustive]
#[derive(Clone, Copy, Eq, PartialEq, Debug)]
pub struct HmacData<'l> {
    pub algorithm: oath::Algorithm,
    pub secret: &'l [u8],
}

impl<'l> HmacData<'l> {
    pub fn try_from(algorithm: oath::Algorithm, secret: &'l [u8]) -> Result<Self, ()> {
        const SHA1_SECRET_EXPECTED_SIZE: usize = 20;
        // Currently only SHA1 is supported, hence the expected SECRET length
        if !(secret.len() == SHA1_SECRET_EXPECTED_SIZE && algorithm == oath::Algorithm::Sha1) {
            return Err(());
        }
        Ok(Self { algorithm, secret })
    }
}

#[derive(Clone, Copy, Eq, PartialEq, Debug)]
pub struct PasswordSafeData<'l> {
    pub login: &'l [u8],
    pub password: &'l [u8],
    pub metadata: &'l [u8],
}

impl<'l> PasswordSafeData<'l> {
    pub fn non_empty(&self) -> bool {
        !self.login.is_empty() || !self.password.is_empty() || !self.metadata.is_empty()
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct Properties(u8);

impl Properties {
    fn touch_required(&self) -> bool {
        self.0 & (oath::Properties::RequireTouch as u8) != 0
    }
    fn pin_encrypted(&self) -> bool {
        self.0 & (oath::Properties::PINEncrypt as u8) != 0
    }
}
impl<'a> flexiber::Decodable<'a> for Properties {
    fn decode(decoder: &mut flexiber::Decoder<'a>) -> flexiber::Result<Properties> {
        let two_bytes: [u8; 2] = decoder.decode()?;
        let [tag, properties] = two_bytes;
        use flexiber::Tagged;
        ensure(
            flexiber::Tag::try_from(tag).unwrap() == Self::tag(),
            flexiber::ErrorKind::Failed,
        )?;
        Ok(Properties(properties))
    }
}
impl flexiber::Tagged for Properties {
    fn tag() -> flexiber::Tag {
        flexiber::Tag::try_from(Tag::Property as u8).unwrap()
    }
}

#[repr(u8)]
#[derive(Clone, Copy, Eq, PartialEq, Debug, Deserialize, Serialize)]
pub enum EncryptionKeyType {
    Hardware,
    PinBased,
}

impl EncryptionKeyType {
    pub fn default_for_loading_credential() -> EncryptionKeyType {
        EncryptionKeyType::PinBased
    }
    pub fn default_for_command_registering_new_credential() -> EncryptionKeyType {
        EncryptionKeyType::Hardware
    }
}

impl TryFrom<Tag> for SimpleTag {
    type Error = Status;

    fn try_from(value: Tag) -> Result<Self, Self::Error> {
        SimpleTag::try_from(value as u8).map_err(|_| Status::UnspecifiedPersistentExecutionError)
    }
}

impl TryFrom<SimpleTag> for Tag {
    type Error = Status;

    fn try_from(value: SimpleTag) -> Result<Self, Self::Error> {
        Tag::try_from(value.embedding().number as u8)
            .map_err(|_| Status::UnspecifiedPersistentExecutionError)
    }
}

impl<'l, const C: usize> TryFrom<&'l Data<C>> for Register<'l> {
    type Error = Status;

    fn try_from(data: &'l Data<C>) -> Result<Self, Self::Error> {
        // All fields of the OTP Credential are obligatory
        // The PWS entries are optional
        use flexiber::Decodable;
        type TaggedSlice<'a> = flexiber::TaggedSlice<'a, SimpleTag>;
        let mut decoder = flexiber::Decoder::new(data);

        // first comes the label of the credential, with Tag::Name
        let first: TaggedSlice = decoder.decode().map_err(|_| FAILED_PARSING_ERROR)?;
        ensure(
            first.tag() == (Tag::Name as u8).try_into().unwrap(),
            FAILED_PARSING_ERROR,
        )?;
        let label = first.as_bytes();

        info_now!("parsed label {:?}", &label);

        // then come (kind,algorithm,digits) and the actual secret (somewhat massaged)
        let second: TaggedSlice = decoder.decode().map_err(|_| FAILED_PARSING_ERROR)?;
        second
            .tag()
            .assert_eq((Tag::Key as u8).try_into().unwrap())
            .map_err(|_| FAILED_PARSING_ERROR)?;

        if second.as_bytes().len() < 3 {
            return Err(FAILED_PARSING_ERROR);
        };
        let (secret_header, secret) = second.as_bytes().split_at(2);

        info_now!("parsed secret {:?}", &secret);

        let kind: oath::Kind = secret_header[0].try_into()?;
        let algorithm: oath::Algorithm = secret_header[0].try_into()?;
        let digits = secret_header[1];

        let maybe_properties: Option<Properties> =
            decoder.decode().map_err(|_| FAILED_PARSING_ERROR)?;

        let touch_required = maybe_properties
            .map(|properties| {
                info_now!("unraveling {:?}", &properties);
                properties.touch_required()
            })
            .unwrap_or(false);

        info_now!("parsed attributes");

        let encryption_key_type = match maybe_properties
            .map(|properties| properties.pin_encrypted())
            .unwrap_or(false)
        {
            true => EncryptionKeyType::PinBased,
            false => EncryptionKeyType::Hardware,
        };

        let mut counter = None;
        // kind::Hotp and valid u32 starting counter should be more tightly tied together on a
        // type level
        if matches!(kind, oath::Kind::Hotp | oath::Kind::HotpReverse) {
            // when the counter is not specified or set to zero, ykman does not send it
            counter = Some(0);
            if let Ok(last) = TaggedSlice::decode(&mut decoder) {
                if last.tag() == (Tag::InitialMovingFactor as u8).try_into().unwrap() {
                    let bytes = last.as_bytes();
                    if bytes.len() == 4 {
                        counter = Some(u32::from_be_bytes(bytes.try_into().unwrap()));
                    }
                }
            }
            debug_now!("counter set to {:?}", &counter);
        }

        let otp_data = match kind {
            oath::Kind::Hotp | oath::Kind::Totp | oath::Kind::HotpReverse => {
                Some(CredentialData::OtpData(OtpCredentialData {
                    kind,
                    algorithm,
                    digits,
                    secret,
                    counter,
                }))
            }
            oath::Kind::Hmac => Some(CredentialData::HmacData(
                HmacData::try_from(algorithm, secret).map_err(|_| FAILED_PARSING_ERROR)?,
            )),
            _ => None,
        };

        let pws_data = {
            let mut pws = PasswordSafeData {
                login: &[],
                password: &[],
                metadata: &[],
            };

            let mut next_decoded: Option<TaggedSlice> = decoder.decode().ok();
            while let Some(next) = next_decoded {
                let tag = next.tag().embedding().number as u8;
                let tag = Tag::try_from(tag).unwrap();
                let tag_data = next.as_bytes();

                // Following should be caught before this loop
                // Tag::Name => {},
                // Tag::Key => {}
                // Tag::Property => {}
                // Tag::InitialMovingFactor => {}
                // Tag::Algorithm => {}
                // Tag::Touch => {}

                match tag {
                    Tag::PwsLogin => {
                        pws.login = tag_data;
                    }
                    Tag::PwsPassword => {
                        pws.password = tag_data;
                    }
                    Tag::PwsMetadata => {
                        pws.metadata = tag_data;
                    }
                    _ => {
                        // Unmatched tags should return error
                        return Err(Status::IncorrectDataParameter);
                    }
                }
                next_decoded = decoder.decode().ok();
            }
            if pws.non_empty() {
                Some(pws)
            } else {
                None
            }
        };

        let credential = Credential {
            label,
            touch_required,
            encryption_key_type,
            otp: otp_data,
            password_safe: pws_data,
        };

        Ok(Register { credential })
    }
}

impl<'l> Command<'l> {
    /// Parse the Yubikey's Challenge-Response request
    fn try_parse_yk_req(
        class: Class,
        instruction: Instruction,
        p1: u8,
        p2: u8,
        data: &'l [u8],
    ) -> Result<Self, Status> {
        let instruction_byte: u8 = instruction.into();
        let yk_instruction: oath::YkInstruction = instruction_byte
            .try_into()
            .map_err(|_| Status::InstructionNotSupportedOrInvalid)?;
        match (class.into_inner(), yk_instruction, p1, p2) {
            // Get serial
            (0x00, oath::YkInstruction::ApiRequest, maybe_cmd_get_serial, 0x00)
                if maybe_cmd_get_serial == GetSerial.as_u8() =>
            {
                Ok(Self::YkSerial)
            }
            // Get HMAC slot command
            (0x00, oath::YkInstruction::ApiRequest, slot, 0x00) => Ok(Self::YkGetHmac({
                YkGetHmac::try_from(data)?.with_slot(slot)?
            })),
            // Get status
            (0x00, oath::YkInstruction::Status, 0x00, 0x00) => Ok(Self::YkGetStatus),
            _ => Err(Status::InstructionNotSupportedOrInvalid),
        }
    }
}
impl<'l, const C: usize> TryFrom<&'l iso7816::Command<C>> for Command<'l> {
    type Error = Status;
    /// The first layer of unraveling the iso7816::Command onion.
    ///
    /// The responsibility here is to check (cla, ins, p1, p2) are valid as defined
    /// in the "Command Syntax" boxes of NIST SP 800-73-4, and return early errors.
    ///
    /// The individual piv::Command TryFroms then further interpret these validated parameters.
    fn try_from(command: &'l iso7816::Command<C>) -> Result<Self, Self::Error> {
        let (class, instruction, p1, p2) = (
            command.class(),
            command.instruction(),
            command.p1,
            command.p2,
        );
        let data = command.data();

        if !class.secure_messaging().none() {
            return Err(Status::SecureMessagingNotSupported);
        }

        if class.channel() != Some(0) {
            return Err(Status::LogicalChannelNotSupported);
        }

        if let Ok(req) = Self::try_parse_yk_req(class, instruction, p1, p2, data) {
            Ok(req)
        } else if (0x00, Instruction::Select, 0x04, 0x00)
            == (class.into_inner(), instruction, p1, p2)
        {
            Ok(Self::Select(Select::try_from(data)?))
        } else {
            let instruction_byte: u8 = instruction.into();
            let instruction: oath::Instruction = instruction_byte.try_into()?;
            Ok(match (class.into_inner(), instruction, p1, p2) {
                // also 0xa4
                (0x00, oath::Instruction::Calculate, 0x00, 0x01) => {
                    Self::Calculate(Calculate::try_from(data)?)
                }
                #[cfg(feature = "calculate-all")]
                (0x00, oath::Instruction::CalculateAll, 0x00, 0x01) => {
                    Self::CalculateAll(CalculateAll::try_from(data)?)
                }
                (0x00, oath::Instruction::Delete, 0x00, 0x00) => {
                    Self::Delete(Delete::try_from(data)?)
                }
                (0x00, oath::Instruction::List, 0x00, 0x00) => {
                    Self::ListCredentials(ListCredentials::try_from(data)?)
                }
                (0x00, oath::Instruction::Put, 0x00, 0x00) => {
                    Self::Register(Register::try_from(data)?)
                }
                (0x00, oath::Instruction::Reset, 0xde, 0xad) => Self::Reset,
                #[cfg(feature = "challenge-response-auth")]
                (0x00, oath::Instruction::SetCode, 0x00, 0x00) => {
                    // should check this is a TLV(SetPassword, b'')
                    if data.len() == 2 {
                        Self::ClearPassword
                    } else {
                        Self::SetPassword(SetPassword::try_from(data)?)
                    }
                }
                #[cfg(feature = "challenge-response-auth")]
                (0x00, oath::Instruction::Validate, 0x00, 0x00) => {
                    Self::Validate(Validate::try_from(data)?)
                }
                (0x00, oath::Instruction::VerifyCode, 0x00, 0x00) => {
                    Self::VerifyCode(VerifyCode::try_from(data)?)
                }
                (0x00, oath::Instruction::VerifyPIN, 0x00, 0x00) => {
                    Self::VerifyPin(VerifyPin::try_from(data)?)
                }
                (0x00, oath::Instruction::ChangePIN, 0x00, 0x00) => {
                    Self::ChangePin(ChangePin::try_from(data)?)
                }
                (0x00, oath::Instruction::SetPIN, 0x00, 0x00) => {
                    Self::SetPin(SetPin::try_from(data)?)
                }
                (0x00, oath::Instruction::GetCredential, 0x00, 0x00) => {
                    Self::GetCredential(GetCredential::try_from(data)?)
                }
                (0x00, oath::Instruction::SendRemaining, 0x00, 0x00) => Self::SendRemaining,
                _ => return Err(Status::InstructionNotSupportedOrInvalid),
            })
        }
    }
}

impl<'l, const C: usize> TryFrom<&'l Data<C>> for Select<'l> {
    type Error = Status;
    fn try_from(data: &'l Data<C>) -> Result<Self, Self::Error> {
        // info_now!("comparing {} against {}", hex_str!(data.as_slice()), hex_str!(crate::YUBICO_OATH_AID));
        Ok(match data.as_slice() {
            crate::YUBICO_OATH_AID => Self { aid: data },
            _ => return Err(Status::NotFound),
        })
    }
}
