// Copyright (C) 2021-2022 The Trussed Developers
// Copyright (C) 2023 Nitrokey GmbH
//
// SPDX-License-Identifier: Apache-2.0 OR MIT

use crate::command;
use crate::command::{
    CredentialData, EncryptionKeyType, HmacData, OtpCredentialData, PasswordSafeData,
    UpdateCredential,
};
use crate::oath::{Algorithm, Kind};
use iso7816::Status;
use serde::{Deserialize, Serialize};
use trussed::types::ShortData;

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct CredentialFlat {
    pub label: ShortData,
    #[serde(rename = "K")]
    pub kind: Kind,
    #[serde(rename = "A")]
    pub algorithm: Algorithm,
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

impl Default for CredentialFlat {
    fn default() -> Self {
        CredentialFlat {
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

use bitflags::bitflags;

bitflags! {
    #[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
    struct PropertiesByte: u8 {
        const touch_required =  1 << 0;
        const encrypted =  1 << 1;
        const pws_data_exist =  1 << 2;
    }
}

impl From<&CredentialFlat> for PropertiesByte {
    fn from(cred: &CredentialFlat) -> Self {
        let mut res: PropertiesByte = PropertiesByte::empty();
        if cred.touch_required {
            res |= PropertiesByte::touch_required;
        }
        if cred.encryption_key_type.is_none() {
            warn_now!("encryption_key_type is not set");
        }
        if cred
            .encryption_key_type
            .unwrap_or(EncryptionKeyType::PinBased)
            == EncryptionKeyType::PinBased
        {
            res |= PropertiesByte::encrypted;
        }
        if cred.login.is_some() || cred.password.is_some() {
            res |= PropertiesByte::pws_data_exist;
        }
        res
    }
}

impl CredentialFlat {
    pub fn get_properties_byte(&self) -> u8 {
        let res: PropertiesByte = self.into();
        res.bits()
    }

    fn get_bytes_if_not_empty_or_none(xo: Option<&[u8]>) -> Result<Option<ShortData>, ()> {
        if let Some(x) = xo {
            if !x.is_empty() {
                return Ok(Some(ShortData::from_slice(x)?));
            }
        }
        Ok(None)
    }

    fn get_ref_or_none(xo: &Option<ShortData>) -> Option<&[u8]> {
        if let Some(x) = xo {
            Some(x.as_slice())
        } else {
            None
        }
    }

    pub fn try_unpack_into_credential(&self) -> Result<command::Credential, Status> {
        let mut cred = command::Credential {
            label: &self.label,
            touch_required: self.touch_required,
            encryption_key_type: self
                .encryption_key_type
                .unwrap_or(EncryptionKeyType::Hardware),
            otp: None,
            password_safe: None,
        };

        cred.otp = match self.kind {
            Kind::Hotp | Kind::Totp | Kind::HotpReverse => {
                Some(CredentialData::OtpData(OtpCredentialData {
                    kind: self.kind,
                    algorithm: self.algorithm,
                    digits: self.digits,
                    secret: &self.secret,
                    counter: self.counter,
                }))
            }
            Kind::Hmac => Some(CredentialData::HmacData(
                HmacData::try_from(self.algorithm, &self.secret)
                    .map_err(|_| Status::IncorrectDataParameter)?,
            )),
            Kind::NotSet => None, // PWS only? do nothing
        };

        let p = PasswordSafeData {
            login: Self::get_ref_or_none(&self.login),
            password: Self::get_ref_or_none(&self.password),
            metadata: Self::get_ref_or_none(&self.metadata),
        };
        if p.non_empty() {
            cred.password_safe = Some(p);
        }

        Ok(cred)
    }

    pub fn try_from(credential: &command::Credential) -> Result<Self, ()> {
        // Assuming here all the data validation was done on the upstream struct construction.
        // Here we are simply passing it without checking.
        let mut cred = Self {
            label: ShortData::from_slice(credential.label)?,
            touch_required: credential.touch_required,
            encryption_key_type: Some(credential.encryption_key_type),
            ..Default::default()
        };

        if let Some(cd) = credential.otp {
            match cd {
                CredentialData::OtpData(otp) => {
                    cred.kind = otp.kind;
                    cred.secret = ShortData::from_slice(otp.secret)?;
                    cred.digits = otp.digits;
                    cred.algorithm = otp.algorithm;
                    cred.counter = otp.counter;
                }
                CredentialData::HmacData(data) => {
                    cred.kind = Kind::Hmac;
                    cred.secret = ShortData::from_slice(data.secret)?;
                    cred.algorithm = data.algorithm;
                }
            }
        }

        if let Some(pass) = credential.password_safe {
            cred.login = Self::get_bytes_if_not_empty_or_none(pass.login)?;
            cred.password = Self::get_bytes_if_not_empty_or_none(pass.password)?;
            cred.metadata = Self::get_bytes_if_not_empty_or_none(pass.metadata)?;
        }

        Ok(cred)
    }

    /// Update credential fields with new values, and save
    pub fn update_from(&mut self, update_req: UpdateCredential) -> Result<(), Status> {
        if let Some(new_label) = update_req.new_label {
            self.label = ShortData::from_slice(new_label).map_err(|_| Status::NotEnoughMemory)?;
        }
        if let Some(p) = update_req.properties {
            self.touch_required = p.touch_required();
        }
        if let Some(pws) = update_req.password_safe {
            self.login = Self::get_bytes_if_not_empty_or_none(pws.login)
                .map_err(|_| Status::UnspecifiedNonpersistentExecutionError)?;
            self.password = Self::get_bytes_if_not_empty_or_none(pws.password)
                .map_err(|_| Status::UnspecifiedNonpersistentExecutionError)?;
            self.metadata = Self::get_bytes_if_not_empty_or_none(pws.metadata)
                .map_err(|_| Status::UnspecifiedNonpersistentExecutionError)?;
        }
        Ok(())
    }
}
