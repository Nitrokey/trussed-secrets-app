use heapless_bytes::Bytes;
use serde::de::DeserializeOwned;
use serde::Serialize;
use trussed::types::{KeyId, Message};
use trussed::{cbor_deserialize, cbor_serialize, try_syscall};

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

/// Universal AEAD encrypted data container, using CBOR and Chacha8Poly1305
///
/// Encryption is realized by serializing the object using CBOR, then encrypting it using Chacha8Poly1305,
/// storing related crypto data, namely nonce and tag, and finally serializing the latter,
/// again using CBOR.
///
/// For the plaintext of size 48 bytes, the resulting container size is 87 bytes,
/// including the 28 bytes of cryptographic data overhead, and leaving 11 bytes
/// as the CBOR serialization overhead.
///
/// Decryption operation is done the same way as its counterpart, but backwards.
/// The serialized Encrypted Data Container in bytes is first deserialized, making a EDC instance,
/// and afterwards the decryption operation in Trussed is called, resulting in a original serialized
/// object, which is then deserialized to a proper instance.
///
/// CBOR was chosen as the serialization format due to its simplicity and extensibility.
/// If that is a requirement, more space efficient and faster would be postcard. Be advised however,
/// that it's format changes between major revisions (as expected with semver versioning).
///
/// This type has implemented bidirectional serialization to trussed Message object.
///
/// Showing the processing paths graphically:
///
/// T -> \[u8\]: object -> CBOR serialization -> EncryptedDataContainer encryption  -> CBOR serialization -> serialized EncryptedDataContainer
///
/// \[u8\] -> T: serialized EncryptedDataContainer -> CBOR deserialization -> EncryptedDataContainer decryption -> CBOR deserialization -> object
///
/// Note: to decrease the CBOR overhead it might be useful to rename the serialized object fields for
/// the serialization purposes. Use the `#[serde(rename = "A")]` attribute.
///
/// The minimum buffer size for the serialization operation of a single encrypted+serialized credential
/// should be about 256 bytes (the current maximum packet length) + CBOR overhead (field names and map encoding) + encryption overhead (12 bytes nonce + 16 bytes tag).
/// The extra bytes could be used in the future, when operating on the password-extended credentials.
///
/// Usage example:
/// ```
/// # use trussed::Client;
/// # use serde::Serialize;
/// # use trussed::client::Chacha8Poly1305;
/// # use trussed::types::{KeyId, Message};
/// # use oath_authenticator::encrypted_container::EncryptedDataContainer;
/// fn encrypt_unit<O: Serialize, T: Client + Chacha8Poly1305>(trussed: &mut T, obj: &O, ek: KeyId) -> Message {
///    let data = EncryptedDataContainer::from_obj(trussed, obj, None, ek).unwrap();
///    let data_serialized: Message = data.try_into().unwrap();
///    data_serialized
/// }
/// ```
/// Future work and extensions:
/// - Generalize over serialization method
/// - Generalize buffer size (currently buffer is based on the Message type)
/// - Investigate postcard structure extensibility, as a means for smaller overhead for serialization
#[derive(Debug, serde::Deserialize, serde::Serialize)]
pub struct EncryptedDataContainer {
    /// The ciphertext. 1024 bytes maximum. Reusing trussed::types::Message.
    #[serde(rename = "D")]
    data: trussed::types::Message,
    #[serde(rename = "T")]
    tag: ContainerTag,
    #[serde(rename = "N")]
    nonce: ContainerNonce,
}

type ContainerTag = Bytes<16>;
type ContainerNonce = Bytes<12>;

impl TryFrom<&[u8]> for EncryptedDataContainer {
    type Error = Error;

