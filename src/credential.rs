use crate::{command, oath};
use iso7816::Status;
use serde::{Deserialize, Serialize};
use trussed::types::Location;
use trussed::types::{KeyId, ShortData};
use trussed::{client, try_syscall};

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct RawCredential {
    pub label: ShortData,
    #[serde(rename = "K")]
    pub kind: oath::Kind,
    #[serde(rename = "A")]
    pub algorithm: oath::Algorithm,
    #[serde(rename = "D")]
    pub digits: u8,
    #[serde(rename = "S")]
    pub secret_raw: ShortData,
    #[serde(rename = "T")]
    pub touch_required: bool,
    #[serde(rename = "C")]
    pub counter: Option<u32>,
}

impl RawCredential {
    pub fn try_from(credential: &command::Credential) -> Result<Self, ()> {
        Ok(Self {
            label: ShortData::from_slice(credential.label)?,
            kind: credential.kind,
            algorithm: credential.algorithm,
            digits: credential.digits,
            secret_raw: ShortData::from_slice(credential.secret)?,
            touch_required: credential.touch_required,
            counter: credential.counter,
        })
    }
}

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
    pub secret: KeyId,
    #[serde(rename = "T")]
    pub touch_required: bool,
    #[serde(rename = "C")]
    pub counter: Option<u32>,
}

impl Credential {
    pub fn try_from<T>(credential: &RawCredential, trussed: &mut T) -> crate::Result<Self>
    where
        T: client::Client,
    {
        Ok(Self {
            label: credential
                .label
                .try_convert_into()
                .map_err(|_| Status::NotEnoughMemory)?,
            kind: credential.kind,
            algorithm: credential.algorithm,
            digits: credential.digits,
            secret: {
                try_syscall!(trussed
                    .unsafe_inject_shared_key(credential.secret_raw.as_slice(), Location::Volatile))
                .map_err(|_| Status::NotEnoughMemory)?
                .key
            },
            touch_required: credential.touch_required,
            counter: credential.counter,
        })
    }
}
