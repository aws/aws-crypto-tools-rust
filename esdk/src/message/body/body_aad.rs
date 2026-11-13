// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

//! Message body AAD (additional authenticated data) construction.

use crate::message::serialize_functions as sf;
use vstd::prelude::*;

verus! {

#[doc(hidden)]
#[expect(
    clippy::exhaustive_enums,
    reason = "closed set fixed by the ESDK message-body-AAD spec"
)]
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum BodyAADContent {
    /// Regular frame in framed data.
    RegularFrame,
    /// Final frame in framed data.
    FinalFrame,
    /// Whole-body nonframed data.
    SingleBlock,
}

//= spec/data-format/message-body-aad.md#body-aad-content
//# - The [regular frames](message-body.md#regular-frame) in [framed data](message-body.md#framed-data) MUST use the value `AWSKMSEncryptionClient Frame`.
#[expect(
    clippy::redundant_static_lifetimes,
    reason = "Verus rejects an elided lifetime in a const's type"
)]
const BODY_AAD_CONTENT_REGULAR_FRAME: &'static str = "AWSKMSEncryptionClient Frame";

//= spec/data-format/message-body-aad.md#body-aad-content
//# - The [final frame](message-body.md#final-frame) in [framed data](message-body.md#framed-data) MUST use the value `AWSKMSEncryptionClient Final Frame`.
#[expect(
    clippy::redundant_static_lifetimes,
    reason = "Verus rejects an elided lifetime in a const's type"
)]
const BODY_AAD_CONTENT_FINAL_FRAME: &'static str = "AWSKMSEncryptionClient Final Frame";

//= spec/data-format/message-body-aad.md#body-aad-content
//# - [Nonframed data](message-body.md#nonframed-data) MUST use the value `AWSKMSEncryptionClient Single Block`.
#[expect(
    clippy::redundant_static_lifetimes,
    reason = "Verus rejects an elided lifetime in a const's type"
)]
const BODY_AAD_CONTENT_SINGLE_BLOCK: &'static str = "AWSKMSEncryptionClient Single Block";

/// The UTF-8 bytes of `s`. (A plain `use` of the vstd trait would be an unused
/// import in the cargo build, where spec code is erased.)
spec fn str_bytes(s: &str) -> Seq<u8> {
    vstd::string::StringSliceAdditionalSpecFns::spec_bytes(s)
}

/// The UTF-8 bytes of the body AAD content string for `bc`.
spec fn spec_body_aad_content(bc: BodyAADContent) -> Seq<u8> {
    match bc {
        BodyAADContent::RegularFrame => str_bytes(BODY_AAD_CONTENT_REGULAR_FRAME),
        BodyAADContent::FinalFrame => str_bytes(BODY_AAD_CONTENT_FINAL_FRAME),
        BodyAADContent::SingleBlock => str_bytes(BODY_AAD_CONTENT_SINGLE_BLOCK),
    }
}

/// The body AAD content string for `bc`.
const fn body_aad_content_type_string(bc: BodyAADContent) -> (r: &'static str)
    ensures
        str_bytes(r) == spec_body_aad_content(bc),
{
    match bc {
        BodyAADContent::RegularFrame => BODY_AAD_CONTENT_REGULAR_FRAME,
        BodyAADContent::FinalFrame => BODY_AAD_CONTENT_FINAL_FRAME,
        BodyAADContent::SingleBlock => BODY_AAD_CONTENT_SINGLE_BLOCK,
    }
}

/// Overwrite the last 4 bytes of `result` with `sequence_number` big-endian,
/// leaving the bytes before them unchanged.
fn iv_seq_core(sequence_number: u32, result: &mut [u8])
    requires
        old(result).len() >= 4,
    ensures
        final(result)@ == old(result)@.subrange(0, old(result).len() - 4) + sf::spec_u32_to_be(
            sequence_number,
        ),
{
    let pivot = result.len() - 4;
    let b = sf::u32_to_be(sequence_number);
    result[pivot] = b[0];
    result[pivot + 1] = b[1];
    result[pivot + 2] = b[2];
    result[pivot + 3] = b[3];
    assert(result@ =~= old(result)@.subrange(0, old(result).len() - 4) + sf::spec_u32_to_be(
        sequence_number,
    ));
}

/// Replace `result` with the message body AAD:
/// message ID ‖ body AAD content ‖ sequence number (`UInt32`) ‖ content length (`UInt64`).
fn body_aad_core(
    message_id: &[u8],
    bc: BodyAADContent,
    sequence_number: u32,
    length: u64,
    result: &mut Vec<u8>,
)
    ensures
        final(result)@ == message_id@ + spec_body_aad_content(bc)
            + sf::spec_u32_to_be(sequence_number) + sf::spec_u64_to_be(length),
{
    result.clear();

    //= spec/data-format/message-body-aad.md#structure
    //# The message body AAD MUST consist of, in order,
    //# Message ID,
    //# Body AAD Content,
    //# Sequence Number,
    //# and Content Length.

    // Message ID

    //= spec/data-format/message-body-aad.md#message-id
    //# This MUST be the [message ID](message-header.md#message-id) stored in the header of the message.
    result.extend_from_slice(message_id);

    // Body AAD Content

    //= spec/data-format/message-body-aad.md#body-aad-content
    //= reason=Rust &str is guaranteed UTF-8; .as_bytes() produces the UTF-8 encoding
    //# The body AAD content value MUST be encoded as UTF-8 bytes.
    result.extend_from_slice(body_aad_content_type_string(bc).as_bytes());

    // Sequence Number

    //= spec/data-format/message-body-aad.md#sequence-number
    //= reason=u32_to_be (verified equal to u32::to_be_bytes()) produces exactly 4 bytes
    //# The length of the sequence number field MUST be 4 bytes.
    let seq_bytes = sf::u32_to_be(sequence_number);
    result.extend_from_slice(&seq_bytes);

    // Content Length

    //= spec/data-format/message-body-aad.md#content-length
    //= reason=u64_to_be (verified equal to u64::to_be_bytes()) produces exactly 8 bytes
    //# The length of the content length field MUST be 8 bytes.
    let len_bytes = sf::u64_to_be(length);
    result.extend_from_slice(&len_bytes);

    assert(result@ =~= message_id@ + spec_body_aad_content(bc)
        + sf::spec_u32_to_be(sequence_number) + sf::spec_u64_to_be(length));
}

} // verus!

/// Writes `sequence_number` as big-endian into the last 4 bytes of `result`.
pub(crate) fn iv_seq(sequence_number: u32, result: &mut [u8]) {
    debug_assert!(
        result.len() >= 4,
        "iv_seq: result must have at least 4 bytes of room for the sequence number, got {}",
        result.len()
    );
    iv_seq_core(sequence_number, result);
}

/// Serialize the Message Body AAD into `result`, per message-body-aad.md.
#[doc(hidden)]
pub fn body_aad(
    message_id: &[u8],
    bc: BodyAADContent,
    //= spec/data-format/message-body-aad.md#sequence-number
    //= reason=sequence_number parameter is u32, serialized big-endian by u32_to_be
    //# The sequence number field MUST be interpreted as a UInt32.
    sequence_number: u32,
    //= spec/data-format/message-body-aad.md#content-length
    //= reason=length parameter is u64, serialized big-endian by u64_to_be
    //# The content length field MUST be interpreted as a UInt64.
    length: u64,
    result: &mut Vec<u8>,
) {
    //= spec/data-format/message-body-aad.md#message-id
    //= reason=V1 message IDs are 16 bytes, V2 message IDs are 32 bytes; the debug_assert attempts to validate this
    //# The length of the Message ID field MUST be equal to the length of the [Message ID](message-header.md#message-id) defined by the message header version.
    debug_assert!(
        message_id.len() == 16 || message_id.len() == 32,
        "message ID must be 16 or 32 bytes, got {}",
        message_id.len()
    );

    body_aad_core(message_id, bc, sequence_number, length, result);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn iv_seq_writes_last_four_bytes() {
        for seq in [0, 1, 0x0102_0304, u32::MAX] {
            let mut iv: Vec<u8> = (0..12).collect();
            iv_seq(seq, &mut iv);
            assert_eq!(iv[..8], (0..8).collect::<Vec<u8>>()[..]);
            assert_eq!(iv[8..], seq.to_be_bytes());
        }
    }

    #[test]
    fn body_aad_layout_for_every_content_type() {
        let cases = [
            (BodyAADContent::RegularFrame, "AWSKMSEncryptionClient Frame"),
            (
                BodyAADContent::FinalFrame,
                "AWSKMSEncryptionClient Final Frame",
            ),
            (
                BodyAADContent::SingleBlock,
                "AWSKMSEncryptionClient Single Block",
            ),
        ];
        let message_id = [7u8; 32];
        for (bc, content) in cases {
            let mut result = vec![0xAA; 3];
            body_aad(
                &message_id,
                bc,
                0x0102_0304,
                0x0506_0708_090A_0B0C,
                &mut result,
            );
            let mut expected = message_id.to_vec();
            expected.extend_from_slice(content.as_bytes());
            expected.extend_from_slice(&0x0102_0304u32.to_be_bytes());
            expected.extend_from_slice(&0x0506_0708_090A_0B0Cu64.to_be_bytes());
            assert_eq!(result, expected);
        }
    }
}
