// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

//! Type definitions for message header fields.

use super::serialize_functions::{read_bytes, read_u8, read_vec, write_bytes, write_u8};
use super::{Error, ser_err};
use crate::error::{Kind, err_with_cause};
use crate::shapes::{EncryptionContext, Source, Tee};
use crate::suites::algorithm_suite_from_bytes;
use aws_crypto_mpl::types::AlgorithmSuite;
use aws_crypto_mpl::types::EncryptedDataKey;
use vstd::prelude::*;

pub(crate) type MessageId = Vec<u8>;

verus! {

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub(crate) enum MessageFormatVersion {
    V1 = 1,
    V2 = 2,
}

/// The message format version encoded by `b`, or `None` if `b` is not a
/// supported version.
pub(crate) fn msg_format_version_from_u8(b: u8) -> (r: Option<MessageFormatVersion>)
    ensures
        (r == Some(MessageFormatVersion::V1)) <==> b == 1,
        (r == Some(MessageFormatVersion::V2)) <==> b == 2,
        (r is None) <==> (b != 1 && b != 2),
{
    //= spec/data-format/message-header.md#supported-versions
    //# The supported versions MUST be:
    match b {
        //= spec/data-format/message-header.md#supported-versions
        //# - Hex value `01` MUST be version 1.0
        1 => Some(MessageFormatVersion::V1),
        //= spec/data-format/message-header.md#supported-versions
        //# - Hex value `02` MUST be version 2.0
        2 => Some(MessageFormatVersion::V2),
        _ => None,
    }
}

/// How the decryptor treats a message's first (version) byte.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum VersionByte {
    /// A supported message format version.
    Supported(MessageFormatVersion),
    /// `0x41` (`A`): the first Base64 character of every supported message, so
    /// the input is probably Base64-encoded.
    Base64Hint,
    /// Any other unsupported byte.
    Unsupported,
}

/// Classify the version byte `b`: a supported version, the Base64 hint, or unsupported.
pub(crate) fn classify_version_byte(b: u8) -> (r: VersionByte)
    ensures
        (r == VersionByte::Supported(MessageFormatVersion::V1)) <==> b == 1,
        (r == VersionByte::Supported(MessageFormatVersion::V2)) <==> b == 2,
        (r is Base64Hint) <==> b == 0x41,
        (r is Unsupported) <==> (b != 1 && b != 2 && b != 0x41),
{
    match msg_format_version_from_u8(b) {
        Some(v) => VersionByte::Supported(v),
        None => if b == 0x41 {
            VersionByte::Base64Hint
        } else {
            VersionByte::Unsupported
        },
    }
}

//= spec/data-format/message-header.md#supported-types
//# The supported types MUST be:
#[derive(Clone, Copy, Debug, Default, Eq, Hash, PartialEq)]
pub(crate) enum MessageType {
    //= spec/data-format/message-header.md#supported-types
    //# - `80` MUST be Customer Authenticated Encrypted Data
    #[default]
    TypeCustomerAed = 0x80,
}

/// The message type encoded by `b`, or `None` if `b` is not a supported type.
pub(crate) fn msg_type_from_u8(b: u8) -> (r: Option<MessageType>)
    ensures
        (r == Some(MessageType::TypeCustomerAed)) <==> b == 0x80,
        (r is None) <==> b != 0x80,
{
    if b == 0x80 {
        Some(MessageType::TypeCustomerAed)
    } else {
        None
    }
}

//= spec/data-format/message-header.md#supported-content-types
//# The supported content types MUST be:
#[derive(Clone, Copy, Debug, Default, Eq, Hash, PartialEq)]
pub(crate) enum ContentType {
    NonFramed = 1,
    #[default]
    Framed = 2,
}

/// The content type encoded by `b`, or `None` if `b` is not a supported
/// content type.
pub(crate) fn content_type_from_u8(b: u8) -> (r: Option<ContentType>)
    ensures
        (r == Some(ContentType::NonFramed)) <==> b == 1,
        (r == Some(ContentType::Framed)) <==> b == 2,
        (r is None) <==> (b != 1 && b != 2),
{
    match b {
        1 => Some(ContentType::NonFramed),
        2 => Some(ContentType::Framed),
        _ => None,
    }
}

// Message ID lengths in bytes. Inside `verus!` so the key-derivation length
// specs (`key_derivation.rs`) can name `MESSAGE_ID_LEN_V2`.
pub(crate) const MESSAGE_ID_LEN_V1: usize = 16;
pub(crate) const MESSAGE_ID_LEN_V2: usize = 32;

} // verus!

pub(crate) fn write_msg_format_version(
    w: &mut Tee,
    data: MessageFormatVersion,
) -> Result<(), Error> {
    //= spec/data-format/message-header.md#version
    //# The length of the serialized version field MUST be 1 byte.
    write_u8(w, data as u8)
}

pub(crate) async fn read_msg_format_version(
    r: &mut dyn Source,
    raw: &mut Tee,
) -> Result<MessageFormatVersion, Error> {
    let version = read_u8(r, raw).await?;
    //= spec/client-apis/decrypt.md#parse-the-header
    //# The value MUST be a [supported version](../data-format/message-header.md#supported-versions).
    match classify_version_byte(version) {
        VersionByte::Supported(v) => Ok(v),
        //= spec/client-apis/decrypt.md#encrypted-message-format
        //# To make diagnosing this mistake easier, implementations SHOULD detect the first two bytes of the Base64 encoding of any supported message [versions](../data-format/message-header.md#version)
        //# and [types](../data-format/message-header.md#type)
        //# and fail with a more specific error message.
        VersionByte::Base64Hint => ser_err(
            "input appears to be Base64-encoded. The ESDK expects raw binary message format, not Base64",
        ),
        VersionByte::Unsupported => ser_err(&format!(
            "unsupported message format version: {version:#04x}"
        )),
    }
}

pub(crate) fn write_msg_type(w: &mut Tee, data: MessageType) -> Result<(), Error> {
    //= spec/data-format/message-header.md#type
    //# The length of the serialized type field MUST be 1 byte.
    write_u8(w, data as u8)
}

pub(crate) async fn read_msg_type(r: &mut dyn Source, raw: &mut Tee) -> Result<MessageType, Error> {
    //= spec/data-format/message-header.md#type
    //# The length of the serialized type field MUST be 1 byte.
    let msg_type = read_u8(r, raw).await?;

    //= spec/client-apis/decrypt.md#v1-header-deserialization
    //# The value MUST be a [supported type](../data-format/message-header.md#supported-types).
    match msg_type_from_u8(msg_type) {
        Some(t) => Ok(t),
        None => ser_err(&format!("unsupported message type: {msg_type:#04x}")),
    }
}

pub(crate) fn write_content_type(w: &mut Tee, data: ContentType) -> Result<(), Error> {
    //= spec/data-format/message-header.md#content-type
    //# The length of the serialized content type field MUST be 1 byte.
    write_u8(w, data as u8)
}

pub(crate) async fn read_content_type(
    r: &mut dyn Source,
    raw: &mut Tee,
) -> Result<ContentType, Error> {
    let content_type = read_u8(r, raw).await?;
    //= spec/data-format/message-header.md#content-type
    //# The length of the serialized content type field MUST be 1 byte.
    //
    //= spec/client-apis/decrypt.md#v1-header-deserialization
    //# The value MUST be a [supported content type](../data-format/message-header.md#supported-content-types).
    //
    //= spec/client-apis/decrypt.md#v2-header-deserialization
    //# The value MUST be a [supported content type](../data-format/message-header.md#supported-content-types).
    match content_type_from_u8(content_type) {
        Some(c) => Ok(c),
        None => ser_err(&format!("unsupported content type: {content_type:#04x}")),
    }
}

/// Header body fields for a version 1.0 message format.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct V1HeaderBody {
    pub(crate) message_type: MessageType,
    pub(crate) algorithm_suite: AlgorithmSuite,
    pub(crate) message_id: MessageId,
    pub(crate) encryption_context: EncryptionContext,
    pub(crate) encrypted_data_keys: Vec<EncryptedDataKey>,
    pub(crate) content_type: ContentType,
    pub(crate) header_iv_length: u8,
    pub(crate) frame_length: u32,
}

/// Header body fields for a version 2.0 message format.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct V2HeaderBody {
    pub(crate) algorithm_suite: AlgorithmSuite,
    pub(crate) message_id: MessageId,
    pub(crate) encryption_context: EncryptionContext,
    pub(crate) encrypted_data_keys: Vec<EncryptedDataKey>,
    pub(crate) content_type: ContentType,
    pub(crate) frame_length: u32,
    pub(crate) suite_data: Vec<u8>,
}

/// The body of a message header, parameterized by message format version.
#[expect(
    clippy::exhaustive_enums,
    reason = "closed set fixed by the ESDK message-format spec (V1/V2)"
)]
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum HeaderBody {
    /// A version 1.0 header body.
    V1Body(V1HeaderBody),
    /// A version 2.0 header body.
    V2Body(V2HeaderBody),
}

impl HeaderBody {
    pub(crate) const fn frame_length(&self) -> u32 {
        match self {
            Self::V1Body(body) => body.frame_length,
            Self::V2Body(body) => body.frame_length,
        }
    }
    pub(crate) const fn content_type(&self) -> ContentType {
        match self {
            Self::V1Body(body) => body.content_type,
            Self::V2Body(body) => body.content_type,
        }
    }
    /// Returns the message id bytes from the header body.
    #[must_use]
    pub const fn message_id(&self) -> &[u8] {
        match self {
            Self::V1Body(body) => body.message_id.as_slice(),
            Self::V2Body(body) => body.message_id.as_slice(),
        }
    }
    pub(crate) const fn encryption_context(&self) -> &EncryptionContext {
        match self {
            Self::V1Body(body) => &body.encryption_context,
            Self::V2Body(body) => &body.encryption_context,
        }
    }
    pub(crate) const fn encrypted_data_keys(&self) -> &[EncryptedDataKey] {
        match self {
            Self::V1Body(body) => body.encrypted_data_keys.as_slice(),
            Self::V2Body(body) => body.encrypted_data_keys.as_slice(),
        }
    }
    /// Returns the algorithm suite recorded in the header body.
    #[must_use]
    pub const fn algorithm_suite(&self) -> &AlgorithmSuite {
        match self {
            Self::V1Body(body) => &body.algorithm_suite,
            Self::V2Body(body) => &body.algorithm_suite,
        }
    }
    pub(crate) const fn suite_data(&self) -> &[u8] {
        match self {
            Self::V1Body(_) => &[],
            Self::V2Body(body) => body.suite_data.as_slice(),
        }
    }
}

/// Header authentication data carried in a message header.
#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum HeaderAuth {
    /// AES-GCM header authentication: an IV and the computed authentication tag.
    AESMac {
        /// The header initialization vector.
        header_iv: Vec<u8>,
        /// The header authentication tag.
        header_auth_tag: Vec<u8>,
    },
}

impl HeaderAuth {
    pub(crate) fn header_iv(&self) -> &[u8] {
        match self {
            Self::AESMac { header_iv, .. } => header_iv,
        }
    }
    pub(crate) fn header_auth_tag(&self) -> &[u8] {
        match self {
            Self::AESMac {
                header_auth_tag, ..
            } => header_auth_tag,
        }
    }
}

// --- Shared header read/write functions (suite ID, message ID) ---

pub(crate) async fn read_esdk_suite_id(
    r: &mut dyn Source,
    raw: &mut Tee,
) -> Result<AlgorithmSuite, Error> {
    //= spec/data-format/message-header.md#algorithm-suite-id
    //# The length of the serialized algorithm suite ID field MUST be 2 bytes.
    let mut esdk_suite_id_bytes = [0; 2];
    read_bytes(r, &mut esdk_suite_id_bytes, raw).await?;

    //= spec/data-format/message-header.md#algorithm-suite-id
    //# The value (hex) of this field MUST be a value that exists in the
    //# [Supported Algorithm Suites](../framework/algorithm-suites.md#supported-algorithm-suites) table.
    //
    //= spec/data-format/message-header.md#algorithm-suite-id
    //# This algorithm suite MUST be [supported for the ESDK](../framework/algorithm-suites.md#supported-algorithm-suites-enum).
    //
    //= spec/data-format/message.md#structure
    //= reason=This is the only place an algorithm suite ID is resolved from the wire; returning Err here aborts deserialization before any trailing bytes are read, so none can be treated as a footer
    //# If the [algorithm suite ID](message-header.md#algorithm-suite-id) is unrecognized or unsupported, or its [algorithm suite](../framework/algorithm-suites.md) definition cannot be used to determine whether a [signature algorithm](../framework/algorithm-suites.md#signature-algorithm) is required, the operation MUST raise an error and MUST NOT treat any trailing bytes as a valid [message footer](message-footer.md).
    let suite = algorithm_suite_from_bytes(esdk_suite_id_bytes).map_err(|e| {
        err_with_cause(
            Kind::Serialization,
            format!(
                "unrecognized or unsupported algorithm suite ID: 0x{:02X}{:02X}",
                esdk_suite_id_bytes[0], esdk_suite_id_bytes[1]
            ),
            e,
        )
    })?;
    Ok(suite)
}

pub(crate) fn write_esdk_suite_id(w: &mut Tee, suite: &AlgorithmSuite) -> Result<(), Error> {
    //= spec/data-format/message-header.md#algorithm-suite-id
    //# The length of the serialized algorithm suite ID field MUST be 2 bytes.
    write_bytes(w, &suite.id()[..])
}

pub(crate) async fn read_message_id_v1(
    r: &mut dyn Source,
    raw: &mut Tee,
) -> Result<MessageId, Error> {
    //= spec/data-format/message-header.md#message-id
    //# The length of the serialized message ID MUST be 16 bytes for [version 1.0](#header-body-version-10) headers.
    read_vec(r, MESSAGE_ID_LEN_V1, raw).await
}

pub(crate) async fn read_message_id_v2(
    r: &mut dyn Source,
    raw: &mut Tee,
) -> Result<MessageId, Error> {
    //= spec/data-format/message-header.md#message-id
    //# The length of the serialized message ID MUST be 32 bytes for [version 2.0](#header-body-version-20) headers.
    read_vec(r, MESSAGE_ID_LEN_V2, raw).await
}

pub(crate) fn write_message_id(w: &mut Tee, message_id: &MessageId) -> Result<(), Error> {
    write_bytes(w, message_id)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn from_u8_cores_accept_exactly_the_spec_bytes() {
        for b in 0..=u8::MAX {
            let version = match b {
                1 => Some(MessageFormatVersion::V1),
                2 => Some(MessageFormatVersion::V2),
                _ => None,
            };
            assert_eq!(msg_format_version_from_u8(b), version);
            let msg_type = (b == 0x80).then_some(MessageType::TypeCustomerAed);
            assert_eq!(msg_type_from_u8(b), msg_type);
            let content_type = match b {
                1 => Some(ContentType::NonFramed),
                2 => Some(ContentType::Framed),
                _ => None,
            };
            assert_eq!(content_type_from_u8(b), content_type);
        }
    }

    #[test]
    fn classify_version_byte_cases() {
        let v1 = VersionByte::Supported(MessageFormatVersion::V1);
        let v2 = VersionByte::Supported(MessageFormatVersion::V2);
        assert_eq!(classify_version_byte(1), v1);
        assert_eq!(classify_version_byte(2), v2);
        assert_eq!(classify_version_byte(0x41), VersionByte::Base64Hint);
        for b in [0, 3, 0x40, 0x42, 0xFF] {
            assert_eq!(
                classify_version_byte(b),
                VersionByte::Unsupported,
                "b={b:#x}"
            );
        }
    }

    #[test]
    fn from_u8_cores_round_trip_the_discriminants() {
        for v in [MessageFormatVersion::V1, MessageFormatVersion::V2] {
            assert_eq!(msg_format_version_from_u8(v as u8), Some(v));
        }
        let t = MessageType::TypeCustomerAed;
        assert_eq!(msg_type_from_u8(t as u8), Some(t));
        for c in [ContentType::NonFramed, ContentType::Framed] {
            assert_eq!(content_type_from_u8(c as u8), Some(c));
        }
    }
}
