// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

//! Top-level message header construction and parsing.

use super::header_types::{
    ContentType, HeaderAuth, HeaderBody, MESSAGE_ID_LEN_V1, MESSAGE_ID_LEN_V2,
    MessageFormatVersion, MessageId, read_msg_format_version,
};
use super::v1_header_body::{read_v1_header_body, write_v1_header_body};
use super::v2_header_body::{
    commit_key_length, has_commitment, read_v2_header_body, write_v2_header_body,
};
use super::{DigestWriter, Error, header_auth, ser_err, serialize_functions};
use crate::error::{Kind, err, val_err};
use crate::types::{EncryptionContext, Sink, Source, Tee};
use aws_crypto_mpl::structures::AlgorithmSuite;
use aws_lc_rs::constant_time;

pub(crate) const START_SEQUENCE_NUMBER: u32 = 1;

//= spec/data-format/message-body.md#sequence-number-end
//# The value MUST be encoded as the 4 bytes `FF FF FF FF` in hexadecimal notation.
pub(crate) const ENDFRAME_SEQUENCE_NUMBER: u32 = 0xFFFF_FFFF;
pub(crate) const NONFRAMED_SEQUENCE_NUMBER: u32 = 1;

//= spec/data-format/message-body.md#nonframed-data-encrypted-content-length
//# The value of this field MUST NOT be greater than `2^36 - 32`, or 64 gibibytes (64 GiB),
//# due to restrictions imposed by the [implemented algorithms](../framework/algorithm-suites.md).
pub(crate) const SAFE_MAX_ENCRYPT: u64 = 0x000F_FFFF_FFE0;

/// Parsed message header together with the raw header bytes, decrypted
/// encryption context, resolved algorithm suite, and header authentication.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct HeaderInfo {
    pub(crate) body: HeaderBody,
    pub(crate) raw_header: Vec<u8>,
    pub(crate) encryption_context: EncryptionContext,
    pub(crate) suite: AlgorithmSuite,
    pub(crate) header_auth: HeaderAuth,
}

pub(crate) fn write_header_body(w: &mut Tee, body: &HeaderBody) -> Result<(), Error> {
    // The body variant must agree with its embedded suite's message format version.
    // Construction sites in encrypt.rs pick V1Body/V2Body based on the suite, so this
    // is a dev-time guard against future drift; the invariant is enforced at the call site.
    debug_assert!(
        match body {
            HeaderBody::V1Body(b) => b.algorithm_suite.message_format_version() == 1,
            HeaderBody::V2Body(b) => b.algorithm_suite.message_format_version() == 2,
        },
        "header body variant does not match its embedded algorithm suite's message_version",
    );
    //= spec/data-format/message-header.md#structure
    //# The message header is a sequence of bytes that MUST be in big-endian format.
    match body {
        //= spec/client-apis/encrypt.md#v1-header
        //# If the message format version associated with the [algorithm suite](../framework/algorithm-suites.md#supported-algorithm-suites) is 1.0,
        //# the remaining header fields MUST be serialized according to the
        //# [Header Body Version 1.0](../data-format/message-header.md#header-body-version-10) specification:
        HeaderBody::V1Body(x) => write_v1_header_body(w, x),
        //= spec/client-apis/encrypt.md#v2-header
        //# If the message format version associated with the [algorithm suite](../framework/algorithm-suites.md#supported-algorithm-suites) is 2.0,
        //# the remaining header fields MUST be serialized according to the
        //# [Header Body Version 2.0](../data-format/message-header.md#header-body-version-20) specification:
        HeaderBody::V2Body(x) => write_v2_header_body(w, x),
    }
}

/// Deserializes a message header body from the ciphertext stream, writing the
/// consumed raw header bytes to `raw_header` for later authentication.
///
/// # Errors
///
/// Returns an error if the bytes are malformed, specify an unsupported message
/// format version or algorithm suite, or declare more encrypted data keys than
/// `max_edks` permits.
pub async fn read_header_body(
    ciphertext: &mut dyn Source,
    max_edks: Option<std::num::NonZeroUsize>,
    raw_header: &mut Tee,
) -> Result<HeaderBody, Error> {
    //= spec/client-apis/decrypt.md#parse-the-header
    //# This operation MUST attempt to deserialize all consumable encrypted message bytes until it has
    //# successfully deserialized a valid [message header](../data-format/message-header.md).
    //
    //= spec/client-apis/decrypt.md#parse-the-header
    //= reason=Every read method reads the next available bytes and does not jump out of sequence
    //# Given encrypted message bytes, this operation MUST process those bytes sequentially,
    //# deserializing those bytes according to the [message format](../data-format/message.md).

    //= spec/client-apis/decrypt.md#parse-the-header
    //= type=implication
    //= reason=read_msg_format_version reads the version from the cursor first; the match on its result dispatches the remaining field reads
    //# The [Version](../data-format/message-header.md#version) field MUST be deserialized first.
    let version = read_msg_format_version(ciphertext, raw_header).await?;

    //= spec/client-apis/decrypt.md#parse-the-header
    //# The header deserialization order MUST follow the [Header Body Version 1.0](../data-format/message-header.md#header-body-version-10)
    //# or [Header Body Version 2.0](../data-format/message-header.md#header-body-version-20) specification,
    //# depending on the [Version](../data-format/message-header.md#version) field in the message header.
    let result = match version {
        //= spec/client-apis/decrypt.md#v1-header-deserialization
        //# If the value of the deserialized version field is [1.0](../data-format/message-header.md#supported-versions),
        //# the remaining header fields MUST be deserialized according to the
        //# [Header Body Version 1.0](../data-format/message-header.md#header-body-version-10) specification:
        MessageFormatVersion::V1 => {
            let body = read_v1_header_body(ciphertext, max_edks, raw_header).await?;
            HeaderBody::V1Body(body)
        }

        //= spec/client-apis/decrypt.md#v2-header-deserialization
        //# If the value of the deserialized version field is [2.0](../data-format/message-header.md#supported-versions),
        //# the remaining header fields MUST be deserialized according to the
        //# [Header Body Version 2.0](../data-format/message-header.md#header-body-version-20) specification:
        MessageFormatVersion::V2 => {
            let body = read_v2_header_body(ciphertext, max_edks, raw_header).await?;
            HeaderBody::V2Body(body)
        }
    };

    match result.content_type() {
        ContentType::Framed => {
            if result.frame_length() == 0 {
                return ser_err("frame length must be positive if content is framed");
            }
        }
        ContentType::NonFramed => {
            if result.frame_length() != 0 {
                //= spec/data-format/message-header.md#frame-length
                //# When the [content type](#content-type) is nonframed, the value of this field MUST be 0.
                return ser_err("frame length must be zero if content is nonframed");
            }
        }
    }
    Ok(result)
}

pub(crate) const fn header_version_supports_commitment(
    suite: &AlgorithmSuite,
    body: &HeaderBody,
) -> bool {
    match body {
        HeaderBody::V2Body(body) => {
            has_commitment(suite) && body.suite_data.len() == commit_key_length(suite)
        }
        HeaderBody::V1Body(_) => true,
    }
}

pub(crate) fn validate_max_encrypted_data_keys(
    max_encrypted_data_keys: Option<std::num::NonZeroUsize>,
    edks: &[aws_crypto_mpl::structures::EncryptedDataKey],
) -> Result<(), Error> {
    if edks.is_empty() {
        //= spec/data-format/message-header.md#encrypted-data-key-count
        //# This value MUST be greater than 0.
        return Err(err(
            Kind::InvalidMaterials,
            "encrypted data key count must be greater than 0",
        ));
    }

    if let Some(max) = max_encrypted_data_keys
        && edks.len() > max.get()
    {
        return Err(val_err(format!(
            "encrypted data key count {} exceeds configured maximum {}",
            edks.len(),
            max.get(),
        )));
    }
    Ok(())
}

/// Generates a fresh message id of the size required by the algorithm suite's
/// message format version.
///
/// # Errors
///
/// Returns an error if the message format version is unsupported or if the
/// underlying source of randomness fails.
pub fn generate_message_id(suite: &AlgorithmSuite) -> Result<MessageId, Error> {
    // Defense-in-depth: in practice every supported suite has message_version 1 or 2
    // (suites are sourced from the static algorithm-suites table), but match explicitly
    // so a hypothetical future or malformed value fails loudly instead of silently
    // falling through to the V2 length.
    let length = match suite.message_format_version() {
        1 => MESSAGE_ID_LEN_V1,
        2 => MESSAGE_ID_LEN_V2,
        v => {
            return Err(err(
                Kind::Internal,
                format!("cannot generate message ID for unsupported message format version: {v}"),
            ));
        }
    };
    let mut rand_bytes: Vec<u8> = vec![0; length];

    //= spec/data-format/message-header.md#message-id
    //= reason=Uniqueness follows from drawing sufficient randomness; the same randomness call satisfies both sub-items.
    //# While implementations cannot guarantee complete uniqueness,
    //# implementations MUST use a good source of randomness when generating message IDs in order to make
    //# the chance of duplicate IDs negligible.
    aws_mpl_primitives::generate_random_bytes(&mut rand_bytes)?;
    Ok(rand_bytes)
}

pub(crate) fn validate_suite_data(
    suite: &AlgorithmSuite,
    header_body: &HeaderBody,
    expected_suite_data: &[u8],
) -> Result<(), Error> {
    //= spec/client-apis/key-derivation.md#hkdf-commit-key
    //= type=implication
    //= reason=aws_lc_rs::constant_time::verify_slices_are_equal performs a constant-time slice equality check by aws-lc-rs API contract
    //# Verification of the commitment key MUST be a constant time comparison.
    if constant_time::verify_slices_are_equal(header_body.suite_data(), expected_suite_data)
        .is_err()
    {
        return Err(err(
            Kind::Cryptographic,
            "the key commitment in the message header does not match the derived commit key",
        ));
    }

    //= spec/data-format/message-header.md#algorithm-suite-data
    //# The length of the suite data field MUST be equal to the [Algorithm Suite Data Length](../framework/algorithm-suites.md#algorithm-suite-data-length) value
    //# of the [algorithm suite](../framework/algorithm-suites.md) specified by the [Algorithm Suite ID](#algorithm-suite-id) field.
    if commit_key_length(suite) != expected_suite_data.len() {
        return Err(err(
            Kind::Internal,
            "algorithm suite data length does not match the algorithm suite's declared suite-data length",
        ));
    }
    Ok(())
}

/// Write the message header (body + auth tag) to the output stream.
///
/// Header bytes are streamed directly to both the ciphertext output and the
/// signature digest without buffering, so the serialized header is not
/// required to remain in memory for later signature construction.
pub(crate) async fn write_header(
    header: &HeaderInfo,
    ciphertext: &mut dyn Sink,
    sig_digest: &mut DigestWriter,
) -> Result<(), Error> {
    //= spec/data-format/message-header.md#structure
    //# The header MUST consist of, in order,
    //# Header Body,
    //# and Header Authentication.

    // Header Body

    //= spec/client-apis/encrypt.md#authentication-tag
    //= type=implication
    //= reason=header bytes are written to sig_digest during write_header, before any body bytes
    //# If the algorithm suite contains a signature algorithm and
    //# this operation is [streaming](streaming.md) the encrypted message output to the caller,
    //# this operation MUST input the serialized header to the signature algorithm as soon as it is serialized,
    //# such that the serialized header isn't required to remain in memory to [construct the signature](#construct-the-signature).
    serialize_functions::write_to_sink(ciphertext, &header.raw_header).await?;
    serialize_functions::write_bytes(sig_digest, &header.raw_header)?;

    // Header Authentication

    let mut auth_buf = Vec::new();
    header_auth::write_header_auth_tag(&mut auth_buf, &header.header_auth, &header.suite)?;
    serialize_functions::write_to_sink(ciphertext, &auth_buf).await?;
    serialize_functions::write_bytes(sig_digest, &auth_buf)?;
    Ok(())
}
