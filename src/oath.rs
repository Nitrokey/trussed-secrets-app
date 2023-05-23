use core::convert::TryFrom;

use serde::{Deserialize, Serialize};

#[allow(unused)]
#[repr(u8)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Tag {
    Name = 0x71,
    NameList = 0x72,
    Key = 0x73,
    Challenge = 0x74,
    Response = 0x75,
    /// Tag denotes what follows is (digits, dynamically truncated HMAC digest)
    ///
    /// The client then further processes u32::from_be_bytes(truncated-digest)/10**digits.
    TruncatedResponse = 0x76,
    Hotp = 0x77,
    Property = 0x78,
    Version = 0x79,
    InitialMovingFactor = 0x7a,
    Algorithm = 0x7b,
    Touch = 0x7c,
    // Extension starting from 0x80
    Password = 0x80,
    NewPassword = 0x81,
    PINCounter = 0x82,

    PwsLogin = 0x83,
    PwsPassword = 0x84,
    PwsMetadata = 0x85,

    SerialNumber = 0x8F,
    // Remember to update try_from below when adding new tags
}

impl TryFrom<u8> for Tag {
    type Error = iso7816::Status;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        Ok(match value {
            0x71 => Tag::Name,
            0x72 => Tag::NameList,
            0x73 => Tag::Key,
            0x74 => Tag::Challenge,
            0x75 => Tag::Response,

            0x77 => Tag::Hotp,
            0x78 => Tag::Property,
            0x79 => Tag::Version,
            0x7a => Tag::InitialMovingFactor,
            0x7b => Tag::Algorithm,
            0x7c => Tag::Touch,

            0x81 => Tag::NewPassword,
            0x82 => Tag::PINCounter,

            0x83 => Tag::PwsLogin,
            0x84 => Tag::PwsPassword,
            0x85 => Tag::PwsMetadata,
            0x8F => Tag::SerialNumber,
            _ => return Err(Self::Error::IncorrectDataParameter),
        })
    }
}

#[repr(u8)]
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub enum Algorithm {
    Sha1 = 0x01,
    Sha256 = 0x02,
    Sha512 = 0x03,
}

impl TryFrom<u8> for Algorithm {
    type Error = iso7816::Status;
    fn try_from(byte: u8) -> Result<Self, Self::Error> {
        use Algorithm::*;
        Ok(match byte & 0x0f {
            0x1 => Sha1,
            0x2 => Sha256,
            0x3 => Sha512,
            _ => return Err(Self::Error::IncorrectDataParameter),
        })
    }
}

#[repr(u8)]
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub enum Kind {
    Hotp = 0x10,
    Totp = 0x20,
    HotpReverse = 0x30,
    Hmac = 0x40,
    NotSet = 0xF0,
}

impl TryFrom<u8> for Kind {
    type Error = iso7816::Status;
    fn try_from(byte: u8) -> Result<Self, Self::Error> {
        Ok(match byte & 0xf0 {
            0x10 => Kind::Hotp,
            0x20 => Kind::Totp,
            0x30 => Kind::HotpReverse,
            0x40 => Kind::Hmac,
            0xF0 => Kind::NotSet,
            _ => return Err(Self::Error::IncorrectDataParameter),
        })
    }
}

pub fn combine(kind: Kind, algorithm: Algorithm) -> u8 {
    kind as u8 | algorithm as u8
}

#[repr(u8)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Properties {
    RequireTouch = 0x02,
    PINEncrypt = 0x04,
}

#[repr(u8)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum YkInstruction {
    ApiRequest = 0x01,
    Status = 0x03,
}

impl TryFrom<u8> for YkInstruction {
    type Error = iso7816::Status;
    fn try_from(byte: u8) -> Result<Self, Self::Error> {
        use YkInstruction::*;
        Ok(match byte {
            0x01 => ApiRequest,
            0x03 => Status,
            _ => return Err(Self::Error::InstructionNotSupportedOrInvalid),
        })
    }
}

#[repr(u8)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum YkCommand {
    GetSerial = 0x10,
    HmacSlot1 = 0x30,
    HmacSlot2 = 0x38,
}

impl TryFrom<u8> for YkCommand {
    type Error = iso7816::Status;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        use YkCommand::*;
        Ok(match value {
            0x10 => GetSerial,
            0x30 => HmacSlot1,
            0x38 => HmacSlot2,
            _ => return Err(Self::Error::IncorrectP1OrP2Parameter),
        })
    }
}

impl From<YkCommand> for u8 {
    fn from(val: YkCommand) -> Self {
        val.as_u8()
    }
}

impl YkCommand {
    pub fn as_u8(&self) -> u8 {
        *self as u8
    }
}

impl PartialEq<u8> for YkCommand {
    fn eq(&self, other: &u8) -> bool {
        *self as u8 == *other
    }
}

#[repr(u8)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Instruction {
    Put = 0x01,
    Delete = 0x02,
    SetCode = 0x03,
    Reset = 0x04,
    List = 0xa1,
    Calculate = 0xa2,
    Validate = 0xa3,
    CalculateAll = 0xa4,
    SendRemaining = 0xa5,
    // Place extending commands in 0xBx space
    VerifyCode = 0xb1,
    VerifyPIN = 0xb2,
    ChangePIN = 0xb3,
    SetPIN = 0xb4,
    GetCredential = 0xb5,
}

impl TryFrom<u8> for Instruction {
    type Error = iso7816::Status;
    fn try_from(byte: u8) -> Result<Self, Self::Error> {
        use Instruction::*;
        Ok(match byte {
            0x01 => Put,
            0x02 => Delete,
            0x03 => SetCode,
            0x04 => Reset,
            0xa1 => List,
            0xa2 => Calculate,
            0xa3 => Validate,
            0xa4 => CalculateAll,
            0xa5 => SendRemaining,
            0xb1 => VerifyCode,
            0xb2 => VerifyPIN,
            0xb3 => ChangePIN,
            0xb4 => SetPIN,
            0xb5 => GetCredential,
            _ => return Err(Self::Error::InstructionNotSupportedOrInvalid),
        })
    }
}

impl PartialEq<u8> for Instruction {
    fn eq(&self, other: &u8) -> bool {
        *self as u8 == *other
    }
}

// class MASK(IntEnum):
//     ALGO = 0x0f
//     TYPE = 0xf0
