// Copyright (C) 2023 Nitrokey GmbH
//
// SPDX-License-Identifier: Apache-2.0 OR MIT

#[derive(Copy, Clone, Eq, PartialEq, Debug)]
pub enum Error {
    DeserializationToContainerError,
    DeserializationToObjectError,
    ObjectSerializationError,
    ContainerSerializationError,
    SerializationBufferTooSmall,
    FailedEncryption,
    FailedContainerSerialization,
    EmptyContainerData,
    FailedDecryption,
    EmptyDecryptedData,
}

pub type Result<T = ()> = core::result::Result<T, Error>;

impl From<Error> for trussed_core::Error {
    fn from(e: Error) -> Self {
        match e {
            Error::DeserializationToContainerError => {
                trussed_core::Error::InvalidSerializationFormat
            }
            Error::DeserializationToObjectError => {
                trussed_core::Error::InvalidSerializationFormat
            }
            Error::ObjectSerializationError => trussed_core::Error::InvalidSerializationFormat,
            Error::ContainerSerializationError => trussed_core::Error::InvalidSerializationFormat,
            Error::SerializationBufferTooSmall => trussed_core::Error::InternalError,
            Error::FailedEncryption => trussed_core::Error::InternalError,
            Error::FailedContainerSerialization => {
                trussed_core::Error::InvalidSerializationFormat
            }
            Error::EmptyContainerData => trussed_core::Error::WrongMessageLength,
            Error::FailedDecryption => trussed_core::Error::InvalidSerializationFormat,
            Error::EmptyDecryptedData => trussed_core::Error::WrongMessageLength,
        }
    }
}
