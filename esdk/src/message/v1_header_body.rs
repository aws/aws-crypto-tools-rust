// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

//! V1 message header body serialization and deserialization.

use super::encrypted_data_keys::{read_edks, write_edks};
use super::encryption_context::{read_encryption_context, write_aad_section};
use super::header_types::{
    MessageFormatVersion, V1HeaderBody, read_content_type, read_esdk_suite_id, read_message_id_v1,
    read_msg_type, write_content_type, write_esdk_suite_id, write_message_id,
    write_msg_format_version, write_msg_type,
};
use super::serializable_types::get_iv_length;
use super::serialize_functions::{read_bytes, read_u8, read_u32, write_bytes, write_u8, write_u32};
use super::{Error, ser_err};
use crate::error::{Kind, err};
use crate::shapes::{Source, Tee};
use aws_crypto_mpl::types::AlgorithmSuite;
use vstd::prelude::*;

verus! {

/// Whether the four V1 reserved bytes are all zero.
pub(crate) fn reserved_bytes_ok(b: [u8; 4]) -> (ok: bool)
    ensures
        ok <==> (b[0] == 0 && b[1] == 0 && b[2] == 0 && b[3] == 0),
{
    b[0] == 0 && b[1] == 0 && b[2] == 0 && b[3] == 0
}

/// Whether the header IV length equals the algorithm suite's IV length.
pub(crate) fn iv_len_matches(iv_len: u8, expected: usize) -> (ok: bool)
    ensures
        ok <==> iv_len as int == expected as int,
{
    usize::from(iv_len) == expected
}

} // verus!

//= spec/data-format/message-header.md#reserved
//# A reserved sequence of 4 bytes
//# that MUST have the value (hex) of `00 00 00 00`.
const RESERVED_BYTES: [u8; 4] = [0x00, 0x00, 0x00, 0x00];

pub(crate) fn write_v1_header_body(w: &mut Tee, body: &V1HeaderBody) -> Result<(), Error> {
    //= spec/data-format/message-header.md#header-body-version-1-0
    //# The V1 Header Body MUST consist of, in order,
    //# Version,
    //# Type,
    //# Algorithm Suite ID,
    //# Message ID,
    //# AAD,
    //# Encrypted Data Keys,
    //# Content Type,
    //# Reserved,
    //# IV Length,
    //# and Frame Length.
    //
    //= spec/client-apis/encrypt.md#v1-header
    //# The serialization order MUST follow the [Header Body Version 1.0](../data-format/message-header.md#header-body-version-10) specification.

    // Version

    //= spec/client-apis/encrypt.md#v1-header
    //# - MUST serialize the [Version](../data-format/message-header.md#version).
    //# The value MUST correspond to [1.0](../data-format/message-header.md#supported-versions).
    write_msg_format_version(
        w,
        //= spec/data-format/message-header.md#header-body-version-1-0
        //# The value of the `Version` field MUST be `01` in the Version 1.0 header body.
        MessageFormatVersion::V1,
    )?;

    // Type

    //= spec/client-apis/encrypt.md#v1-header
    //# - MUST serialize the [Type](../data-format/message-header.md#type).
    //# The value MUST correspond to [Customer Authenticated Encrypted Data](../data-format/message-header.md#supported-types).
    debug_assert_eq!(
        body.message_type,
        super::header_types::MessageType::TypeCustomerAed
    );
    write_msg_type(w, body.message_type)?;

    // Algorithm Suite ID

    //= spec/client-apis/encrypt.md#v1-header
    //# - MUST serialize the [Algorithm Suite ID](../data-format/message-header.md#algorithm-suite-id).
    //# The value MUST correspond to the [algorithm suite](../framework/algorithm-suites.md) used in this behavior.
    write_esdk_suite_id(w, &body.algorithm_suite)?;

    // Message ID

    //= spec/client-apis/encrypt.md#v1-header
    //# - MUST serialize the [Message ID](../data-format/message-header.md#message-id).
    //
    //= spec/client-apis/encrypt.md#v1-header
    //= reason=randomness is sourced via aws_mpl_primitives::generate_random_bytes
    //# The process used to generate this identifier MUST use a good source of randomness
    //# to make the chance of duplicate identifiers negligible.
    write_message_id(w, &body.message_id)?;

    // AAD

    //= spec/client-apis/encrypt.md#v1-header
    //# - MUST serialize the [AAD](../data-format/message-header.md#aad).
    //
    //= spec/client-apis/encrypt.md#v1-header
    //= reason=required EC keys are filtered out in shared code before the v1 header-specific code
    //# The value MUST be the serialization of the [encryption context](../framework/structures.md#encryption-context)
    //# in the [encryption materials](../framework/structures.md#encryption-materials),
    //# and this serialization MUST NOT contain any key value pairs listed in
    //# the [encryption material's](../framework/structures.md#encryption-materials)
    //# [required encryption context keys](../framework/structures.md#required-encryption-context-keys).
    write_aad_section(w, &body.encryption_context)?;

    // Encrypted Data Keys

    //= spec/client-apis/encrypt.md#v1-header
    //# - MUST serialize the [Encrypted Data Keys](../data-format/message-header.md#encrypted-data-keys).
    //# The value MUST be the serialization of the
    //# [encrypted data keys](../framework/structures.md#encrypted-data-keys) in the [encryption materials](../framework/structures.md#encryption-materials).
    write_edks(w, &body.encrypted_data_keys)?;

    // Content Type

    //= spec/client-apis/encrypt.md#v1-header
    //# - MUST serialize the [Content Type](../data-format/message-header.md#content-type).
    //# The value MUST be [02](../data-format/message-header.md#supported-content-types).
    debug_assert_eq!(body.content_type, super::header_types::ContentType::Framed);
    write_content_type(w, body.content_type)?;

    // Reserved

    //= spec/client-apis/encrypt.md#v1-header
    //# - MUST serialize the [Reserved](../data-format/message-header.md#reserved).
    //
    //= spec/data-format/message-header.md#reserved
    //# The length of the serialized reserved field MUST be 4 bytes.
    debug_assert_eq!(RESERVED_BYTES.len(), 4);
    write_bytes(w, &RESERVED_BYTES)?;

    // IV Length

    //= spec/client-apis/encrypt.md#v1-header
    //# The value MUST match the [IV length](../framework/algorithm-suites.md#iv-length)
    //# specified by the [algorithm suite](../framework/algorithm-suites.md).
    let iv_length_usize = get_iv_length(&body.algorithm_suite);
    let Ok(iv_length) = u8::try_from(iv_length_usize) else {
        return Err(err(
            Kind::Internal,
            format!("IV length {iv_length_usize} exceeds the UInt8 IV-length field"),
        ));
    };

    //= spec/client-apis/encrypt.md#v1-header
    //# - MUST serialize the [IV Length](../data-format/message-header.md#iv-length).
    //
    //= spec/data-format/message-header.md#iv-length
    //# This value MUST be equal to the [IV length](../framework/algorithm-suites.md#iv-length) value of the
    //# [algorithm suite](../framework/algorithm-suites.md) specified by the [Algorithm Suite ID](#algorithm-suite-id) field.
    //
    //= spec/data-format/message-header.md#iv-length
    //# The length of the serialized IV length field MUST be 1 byte.
    //
    //= spec/data-format/message-header.md#iv-length
    //# The IV length MUST be interpreted as a UInt8.
    write_u8(w, iv_length)?;

    // Frame Length

    //= spec/client-apis/encrypt.md#v1-header
    //# The value MUST be the value of the frame size determined above.
    let frame_len = body.frame_length;

    //= spec/client-apis/encrypt.md#v1-header
    //# - MUST serialize the [Frame Length](../data-format/message-header.md#frame-length).
    //
    //= spec/data-format/message-header.md#frame-length
    //# The length of the serialized frame length field MUST be 4 bytes.
    write_u32(w, frame_len)
}

pub(crate) async fn read_v1_reserved_bytes(r: &mut dyn Source, raw: &mut Tee) -> Result<(), Error> {
    let mut result = [0; RESERVED_BYTES.len()];
    read_bytes(r, &mut result, raw).await?;
    if reserved_bytes_ok(result) {
        Ok(())
    } else {
        ser_err("incorrect reserved bytes")
    }
}

pub(crate) async fn read_v1_header_iv_length(
    r: &mut dyn Source,
    suite: &AlgorithmSuite,
    raw: &mut Tee,
) -> Result<u8, Error> {
    let iv_len = read_u8(r, raw).await?;

    //= spec/data-format/message-header.md#iv-length
    //# This value MUST be equal to the [IV length](../framework/algorithm-suites.md#iv-length) value of the
    //# [algorithm suite](../framework/algorithm-suites.md) specified by the [Algorithm Suite ID](#algorithm-suite-id) field.
    if iv_len_matches(iv_len, get_iv_length(suite)) {
        Ok(iv_len)
    } else {
        ser_err("header IV length does not match algorithm suite")
    }
}

pub(crate) async fn read_v1_header_body(
    r: &mut dyn Source,
    max_edks: Option<std::num::NonZeroUsize>,
    raw: &mut Tee,
) -> Result<V1HeaderBody, Error> {
    //= spec/data-format/message-header.md#header-body-version-1-0
    //# The V1 Header Body MUST consist of, in order,
    //# Version,
    //# Type,
    //# Algorithm Suite ID,
    //# Message ID,
    //# AAD,
    //# Encrypted Data Keys,
    //# Content Type,
    //# Reserved,
    //# IV Length,
    //# and Frame Length.

    // Type

    //= spec/client-apis/decrypt.md#v1-header-deserialization
    //# - MUST deserialize the [Type](../data-format/message-header.md#type).
    let message_type = read_msg_type(r, raw).await?;

    // Algorithm Suite ID

    //= spec/client-apis/decrypt.md#v1-header-deserialization
    //# - MUST deserialize the [Algorithm Suite ID](../data-format/message-header.md#algorithm-suite-id).
    let algorithm_suite = read_esdk_suite_id(r, raw).await?;

    // Message ID

    //= spec/client-apis/decrypt.md#v1-header-deserialization
    //# - MUST deserialize the [Message ID](../data-format/message-header.md#message-id).
    let message_id = read_message_id_v1(r, raw).await?;

    // AAD

    //= spec/client-apis/decrypt.md#v1-header-deserialization
    //# - MUST deserialize the [AAD](../data-format/message-header.md#aad).
    let encryption_context = read_encryption_context(r, raw).await?;

    // Encrypted Data Keys

    //= spec/client-apis/decrypt.md#v1-header-deserialization
    //# - MUST deserialize the [Encrypted Data Keys](../data-format/message-header.md#encrypted-data-keys).
    let encrypted_data_keys = read_edks(r, max_edks, raw).await?;

    // Content Type

    //= spec/client-apis/decrypt.md#v1-header-deserialization
    //# - MUST deserialize the [Content Type](../data-format/message-header.md#content-type).
    let content_type = read_content_type(r, raw).await?;

    // Reserved

    //= spec/client-apis/decrypt.md#v1-header-deserialization
    //# - MUST deserialize the [Reserved](../data-format/message-header.md#reserved).
    read_v1_reserved_bytes(r, raw).await?;

    // IV Length

    //= spec/client-apis/decrypt.md#v1-header-deserialization
    //# - MUST deserialize the [IV Length](../data-format/message-header.md#iv-length).
    let header_iv_length = read_v1_header_iv_length(r, &algorithm_suite, raw).await?;

    // Frame Length

    //= spec/client-apis/decrypt.md#v1-header-deserialization
    //# - MUST deserialize the [Frame Length](../data-format/message-header.md#frame-length).
    let frame_length = read_u32(r, raw).await?;

    Ok(V1HeaderBody {
        message_type,
        algorithm_suite,
        message_id,
        encryption_context,
        encrypted_data_keys,
        content_type,
        header_iv_length,
        frame_length,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reserved_bytes_ok_only_for_all_zero() {
        assert!(reserved_bytes_ok(RESERVED_BYTES));
        for i in 0..4 {
            for v in 1..=u8::MAX {
                let mut b = RESERVED_BYTES;
                b[i] = v;
                assert!(!reserved_bytes_ok(b));
            }
        }
    }

    #[test]
    fn iv_len_matches_compares_values() {
        for iv_len in 0..=u8::MAX {
            assert!(iv_len_matches(iv_len, usize::from(iv_len)));
            assert!(!iv_len_matches(iv_len, usize::from(iv_len) + 1));
        }
        assert!(!iv_len_matches(12, 256 + 12));
    }
}
