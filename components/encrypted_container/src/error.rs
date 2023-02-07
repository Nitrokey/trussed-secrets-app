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

impl From<Error> for trussed::error::Error {
    fn from(e: Error) -> Self {
        match e {
            Error::DeserializationToContainerError => {
                trussed::error::Error::InvalidSerializationFormat
            }
            Error::DeserializationToObjectError => {
                trussed::error::Error::InvalidSerializationFormat
            }
            Error::ObjectSerializationError => trussed::error::Error::InvalidSerializationFormat,
            Error::ContainerSerializationError => trussed::error::Error::InvalidSerializationFormat,
            Error::SerializationBufferTooSmall => trussed::error::Error::InternalError,
            Error::FailedEncryption => trussed::error::Error::InternalError,
            Error::FailedContainerSerialization => {
                trussed::error::Error::InvalidSerializationFormat
            }
            Error::EmptyContainerData => trussed::error::Error::WrongMessageLength,
            Error::FailedDecryption => trussed::error::Error::InvalidSerializationFormat,
            Error::EmptyDecryptedData => trussed::error::Error::WrongMessageLength,
        }
    }
}
