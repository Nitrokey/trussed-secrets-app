use crate::command::EncryptionKeyType;
use crate::oath::{Algorithm, Kind};
use crate::{command, oath};
use serde::{Deserialize, Serialize};
use trussed::types::ShortData;

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct Credential {
    pub label: ShortData,
    #[serde(rename = "K")]
    pub kind: oath::Kind,
    #[serde(rename = "A")]
    pub algorithm: oath::Algorithm,
    #[serde(rename = "D")]
    pub digits: u8,
    /// What we get here (inspecting the client app) may not be the raw K, but K' in HMAC lingo,
    /// i.e., If secret.len() < block size (64B for Sha1/Sha256, 128B for Sha512),
    /// then it's the hash of the secret.  Otherwise, it's the secret, padded to length
    /// at least 14B with null bytes. This is of no concern to us, as is it does not
    /// change the MAC.
    ///
    /// The 14 is a bit strange: RFC 4226, section 4 says:
    /// "The algorithm MUST use a strong shared secret.  The length of the shared secret MUST be
    /// at least 128 bits.  This document RECOMMENDs a shared secret length of 160 bits."
    ///
    /// Meanwhile, the client app just pads up to 14B :)

    #[serde(rename = "S")]
    pub secret: ShortData,
    #[serde(rename = "T")]
    pub touch_required: bool,
    #[serde(rename = "C")]
    pub counter: Option<u32>,

    #[serde(rename = "E")]
    #[serde(skip_serializing_if = "Option::is_none")]
    // #[serde(default = "EncryptionKeyType::default_for_loading_credential")]
    pub encryption_key_type: Option<EncryptionKeyType>,

    // extract this one to a separate struct?
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(rename = "PL")]
    pub login: Option<ShortData>,

    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(rename = "PP")]
    pub password: Option<ShortData>,

    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(rename = "PM")]
    pub metadata: Option<ShortData>,
}

impl Default for Credential {
    fn default() -> Self {
        Credential {
            label: Default::default(),
            kind: Kind::NotSet,
            algorithm: Algorithm::Sha1,
            digits: 6,
            secret: Default::default(),
            touch_required: false,
            counter: None,
            encryption_key_type: None,
            login: None,
            password: None,
            metadata: None,
        }
    }
}

impl Credential {
    fn get_bytes_or_none_if_empty(x: &[u8]) -> Result<Option<ShortData>, ()> {
        Ok(
            if x.len() > 0 {
                Some(ShortData::from_slice(x)?)
            } else {
                None
            }
        )
    }

    pub fn try_from(credential: &command::Credential) -> Result<Self, ()> {
        let mut cred = Self {
            label: ShortData::from_slice(credential.label)?,
            touch_required: credential.touch_required,
            encryption_key_type: Some(credential.encryption_key_type),
            ..Default::default()
        };

        if let Some(otp) = credential.otp {
            cred.kind = otp.kind;
            cred.secret = ShortData::from_slice(otp.secret)?;
            cred.digits = otp.digits;
            cred.algorithm = otp.algorithm;
            cred.counter = otp.counter;
        }

        if let Some(pass) = credential.password_safe {
            cred.login = Self::get_bytes_or_none_if_empty(pass.login)?;
            cred.password = Self::get_bytes_or_none_if_empty(pass.password)?;
            cred.metadata = Self::get_bytes_or_none_if_empty(pass.metadata)?;
        }

        Ok(cred)
    }
}
