// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

//! Header authentication tag serialization and deserialization.

use super::header_types::HeaderAuth;
use super::serializable_types::{get_iv_length, get_tag_length};
use super::serialize_functions::{read_vec, write_bytes};
use super::{Error, ser_err};
use crate::shapes::{Source, Tee};
use aws_crypto_mpl::types::AlgorithmSuite;

pub(crate) fn write_header_auth_tag(
    w: &mut Tee,
    header_auth: &HeaderAuth,
    suite: &AlgorithmSuite,
) -> Result<(), Error> {
    match suite.message_format_version() {
        //= spec/client-apis/encrypt.md#v1-authentication-tag
        //# With the authentication tag calculated,
        //# if the message format version associated with the [algorithm suite](../framework/algorithm-suites.md#supported-algorithm-suites) is 1.0
        //# this operation MUST serialize the [message header authentication](../data-format/message-header.md#header-authentication-version-1-0) with the following specifics:
        1 => write_header_auth_tag_v1(w, header_auth),
        //= spec/client-apis/encrypt.md#v2-authentication-tag
        //# With the authentication tag calculated,
        //# if the message format version associated with the [algorithm suite](../framework/algorithm-suites.md#supported-algorithm-suites) is 2.0,
        //# this operation MUST serialize the [message header authentication](../data-format/message-header.md#header-authentication-version-2-0) with the following specifics:
        2 => write_header_auth_tag_v2(w, header_auth),
        _ => ser_err("unexpected message version"),
    }
}

pub(crate) fn write_header_auth_tag_v1(w: &mut Tee, header_auth: &HeaderAuth) -> Result<(), Error> {
    match header_auth {
        HeaderAuth::AESMac {
            header_iv,
            header_auth_tag,
        } => {
            //= spec/data-format/message-header.md#header-authentication-version-1-0
            //# The V1 Header Authentication MUST consist of, in order,
            //# IV,
            //# and Authentication Tag.

            // IV

            //= spec/client-apis/encrypt.md#v1-authentication-tag
            //# - MUST serialize the [IV](../data-format/message-header.md#iv).
            //
            //= spec/client-apis/encrypt.md#v1-authentication-tag
            //# The value MUST be the IV used in the calculation above,
            //# padded to the [IV length](../data-format/message-header.md#iv-length) with 0.
            //
            //= spec/data-format/message-header.md#iv
            //# The length of the serialized IV MUST be equal to the [IV length](../framework/algorithm-suites.md#iv-length) value of the [algorithm suite](../framework/algorithm-suites.md) specified by the [Algorithm Suite ID](#algorithm-suite-id) field.
            //
            //= spec/data-format/message-header.md#iv
            //= type=implication
            //# The IV MUST be interpreted as bytes.
            write_bytes(w, header_iv)?;

            //= spec/client-apis/encrypt.md#v1-authentication-tag
            //# - MUST serialize the [Authentication Tag](../data-format/message-header.md#authentication-tag).
            //
            //= spec/client-apis/encrypt.md#v1-authentication-tag
            //# The value MUST be the authentication tag calculated above.
            //
            //= spec/data-format/message-header.md#authentication-tag
            //# The length of the serialized authentication tag MUST be equal to the [authentication tag length](../framework/algorithm-suites.md#authentication-tag-length) of the [algorithm suite](../framework/algorithm-suites.md) specified by the [Algorithm Suite ID](#algorithm-suite-id) field.
            //
            //= spec/data-format/message-header.md#authentication-tag
            //= type=implication
            //# The authentication tag MUST be interpreted as bytes.
            write_bytes(w, header_auth_tag)
        }
    }
}
pub(crate) fn write_header_auth_tag_v2(w: &mut Tee, header_auth: &HeaderAuth) -> Result<(), Error> {
    match header_auth {
        HeaderAuth::AESMac {
            header_auth_tag, ..
        } => {
            //= spec/data-format/message-header.md#header-authentication-version-2-0
            //# The V2 Header Authentication MUST consist of the Authentication Tag only.

            // Authentication Tag

            //= spec/client-apis/encrypt.md#v2-authentication-tag
            //# - The Encrypt operation MUST serialize the [Authentication Tag](../data-format/message-header.md#authentication-tag).
            //
            //= spec/client-apis/encrypt.md#v2-authentication-tag
            //# The value MUST be the authentication tag calculated above.
            write_bytes(w, header_auth_tag)
        }
    }
}

/// Deserializes the header authentication (IV and authentication tag) for the
/// header, dispatching on the algorithm suite's message format version.
///
/// # Errors
///
/// Returns an error if the message format version is unsupported or if the
/// stream ends before the IV and authentication tag are fully read.
pub async fn read_header_auth_tag(
    r: &mut dyn Source,
    suite: &AlgorithmSuite,
    raw: &mut Tee,
) -> Result<HeaderAuth, Error> {
    match suite.message_format_version() {
        //= spec/client-apis/decrypt.md#v1-header-deserialization
        //# The Decrypt operation MUST then deserialize the
        //# [Header Authentication Version 1.0](../data-format/message-header.md#header-authentication-version-10):
        1 => read_header_auth_tag_v1(r, suite, raw).await,
        //= spec/client-apis/decrypt.md#v2-header-deserialization
        //# The Decrypt operation MUST then deserialize the
        //# [Header Authentication Version 2.0](../data-format/message-header.md#header-authentication-version-20):
        2 => read_header_auth_tag_v2(r, suite, raw).await,
        _ => ser_err("unexpected message version"),
    }
}
pub(crate) async fn read_header_auth_tag_v1(
    r: &mut dyn Source,
    suite: &AlgorithmSuite,
    raw: &mut Tee,
) -> Result<HeaderAuth, Error> {
    //= spec/data-format/message-header.md#header-authentication-version-1-0
    //# The V1 Header Authentication MUST consist of, in order,
    //# IV,
    //# and Authentication Tag.

    // IV

    //= spec/data-format/message-header.md#iv
    //# The length of the serialized IV MUST be equal to the [IV length](../framework/algorithm-suites.md#iv-length) value of the [algorithm suite](../framework/algorithm-suites.md) specified by the [Algorithm Suite ID](#algorithm-suite-id) field.
    let iv_len = get_iv_length(suite);

    //= spec/client-apis/decrypt.md#v1-header-deserialization
    //# - MUST deserialize the [IV](../data-format/message-header.md#iv).
    //
    //= spec/data-format/message-header.md#iv
    //= type=implication
    //# The IV MUST be interpreted as bytes.
    let header_iv = read_vec(r, iv_len, raw).await?;

    // Authentication Tag

    //= spec/data-format/message-header.md#authentication-tag
    //# The length of the serialized authentication tag MUST be equal to the [authentication tag length](../framework/algorithm-suites.md#authentication-tag-length) of the [algorithm suite](../framework/algorithm-suites.md) specified by the [Algorithm Suite ID](#algorithm-suite-id) field.
    let tag_len = get_tag_length(suite);

    //= spec/data-format/message-header.md#authentication-tag
    //= type=implication
    //# The authentication tag MUST be interpreted as bytes.
    let header_auth_tag = read_vec(r, tag_len, raw).await?;
    Ok(HeaderAuth::AESMac {
        header_iv,
        header_auth_tag,
    })
}

pub(crate) async fn read_header_auth_tag_v2(
    r: &mut dyn Source,
    suite: &AlgorithmSuite,
    raw: &mut Tee,
) -> Result<HeaderAuth, Error> {
    //= spec/data-format/message-header.md#header-authentication-version-2-0
    //# The V2 Header Authentication MUST consist of the Authentication Tag only.

    // Authentication Tag

    let tag_len = get_tag_length(suite);

    let header_auth_tag = read_vec(r, tag_len, raw).await?;
    //= spec/client-apis/decrypt.md#verify-the-header
    //= type=implication
    //= reason=Cannot be tested externally because verifying the IV value requires the derived data key (not exposed by the public API). The literal `vec![0u8; ...]` here is the proof.
    //# For message format version [2.0](../data-format/message-header.md#supported-versions)
    //# the IV MUST be 0.
    let header_iv = vec![0u8; get_iv_length(suite)];
    Ok(HeaderAuth::AESMac {
        header_iv,
        header_auth_tag,
    })
}
