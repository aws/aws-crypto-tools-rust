// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
//! Verus proofs for the message-body-AAD / IV construction path.
//!
//! These are faithful, self-contained models of the pure functions in
//! `esdk/src/message/body/body_aad.rs`. See `verification/README.md` for why
//! the proofs live outside the `esdk` crate.
//!
//! Pipeline: `.kiro/agents/ai-verification-pipeline.md`
//! Targets:  `docs/verification-recommendations.md` (sequence→IV, body
//!           serialization panic-freedom; threats T2/T3, D2/D3).

use vstd::prelude::*;

verus! {

// ------------------------------------------------------------------
// SECTION 1: Big-endian encoding — spec source of truth
// ------------------------------------------------------------------

/// The four big-endian bytes of a u32, as a mathematical sequence.
/// This is the specification we prove the code against.
pub open spec fn spec_u32_be(x: u32) -> Seq<u8> {
    seq![
        ((x >> 24) & 0xff) as u8,
        ((x >> 16) & 0xff) as u8,
        ((x >> 8) & 0xff) as u8,
        (x & 0xff) as u8,
    ]
}

/// The eight big-endian bytes of a u64.
pub open spec fn spec_u64_be(x: u64) -> Seq<u8> {
    seq![
        ((x >> 56) & 0xff) as u8,
        ((x >> 48) & 0xff) as u8,
        ((x >> 40) & 0xff) as u8,
        ((x >> 32) & 0xff) as u8,
        ((x >> 24) & 0xff) as u8,
        ((x >> 16) & 0xff) as u8,
        ((x >> 8) & 0xff) as u8,
        (x & 0xff) as u8,
    ]
}

/// Executable big-endian u32 -> [u8; 4]. Equivalent to `u32::to_be_bytes`
/// (Rust std, documented big-endian order); we use explicit shifts because
/// vstd does not yet model `to_be_bytes`.
pub fn u32_be(x: u32) -> (r: [u8; 4])
    ensures
        r@ == spec_u32_be(x),
{
    [
        ((x >> 24) & 0xff) as u8,
        ((x >> 16) & 0xff) as u8,
        ((x >> 8) & 0xff) as u8,
        (x & 0xff) as u8,
    ]
}

/// Executable big-endian u64 -> [u8; 8]. Equivalent to `u64::to_be_bytes`.
pub fn u64_be(x: u64) -> (r: [u8; 8])
    ensures
        r@ == spec_u64_be(x),
{
    [
        ((x >> 56) & 0xff) as u8,
        ((x >> 48) & 0xff) as u8,
        ((x >> 40) & 0xff) as u8,
        ((x >> 32) & 0xff) as u8,
        ((x >> 24) & 0xff) as u8,
        ((x >> 16) & 0xff) as u8,
        ((x >> 8) & 0xff) as u8,
        (x & 0xff) as u8,
    ]
}

// ------------------------------------------------------------------
// SECTION 2: iv_seq — proof of panic-freedom + functional correctness
// ------------------------------------------------------------------

/// Faithful model of `iv_seq` from `esdk/src/message/body/body_aad.rs`.
///
/// Original:
/// ```ignore
/// pub(crate) fn iv_seq(sequence_number: u32, result: &mut [u8]) {
///     let pivot = result.len() - 4;
///     result[pivot..].copy_from_slice(&sequence_number.to_be_bytes());
/// }
/// ```
///
/// The `copy_from_slice(&seq.to_be_bytes())` is modeled as four indexed
/// writes of the big-endian bytes (`spec_u32_be`), which is exactly what
/// `to_be_bytes` produces.
///
/// Precondition `result.len() >= 4` is what every real caller satisfies:
/// callers pass an IV buffer sized to the algorithm suite's IV length, which
/// is 12 for every ESDK suite (`construct_frame` in `body_encrypt.rs`).
pub fn iv_seq(sequence_number: u32, result: &mut [u8])
    requires
        old(result).len() >= 4,
    ensures
        // No reallocation / length change.
        final(result).len() == old(result).len(),
        // Prefix bytes [0, len-4) are untouched.
        forall|i: int|
            0 <= i < final(result).len() - 4 ==> final(result)[i] == old(result)[i],
        // Last 4 bytes are the big-endian sequence number.
        final(result)@.subrange(final(result)@.len() - 4, final(result)@.len() as int)
            == spec_u32_be(sequence_number),
{
    let len = result.len();
    let pivot = len - 4;
    result[pivot] = ((sequence_number >> 24) & 0xff) as u8;
    result[pivot + 1] = ((sequence_number >> 16) & 0xff) as u8;
    result[pivot + 2] = ((sequence_number >> 8) & 0xff) as u8;
    result[pivot + 3] = (sequence_number & 0xff) as u8;
}

// ------------------------------------------------------------------
// SECTION 3: body_aad — proof of panic-freedom + byte layout
// ------------------------------------------------------------------

/// The body-AAD content strings, per `spec/data-format/message-body-aad.md`.
/// Modeled as an opaque `Seq<u8>` argument (`content`) because the real code
/// uses `&'static str` constants whose bytes Verus treats abstractly; the
/// layout proof does not depend on the specific string, only that its bytes
/// are appended in order.
///
/// Faithful model of `body_aad`:
/// ```ignore
/// result.clear();
/// result.extend_from_slice(message_id);
/// result.extend_from_slice(content_str.as_bytes());
/// result.extend_from_slice(&sequence_number.to_be_bytes());
/// result.extend_from_slice(&length.to_be_bytes());
/// ```
///
/// We prove the output is exactly `message_id ‖ content ‖ seq_be ‖ len_be`
/// and its length is `message_id.len() + content.len() + 12`, with no panic.
/// The real-caller invariant is `message_id.len() == 16 || == 32`, which we
/// carry as a `requires` and re-expose in the length `ensures`.
pub fn body_aad(
    message_id: &[u8],
    content: &[u8],
    sequence_number: u32,
    length: u64,
    result: &mut Vec<u8>,
)
    requires
        message_id@.len() == 16 || message_id@.len() == 32,
    ensures
        final(result)@ == message_id@ + content@ + spec_u32_be(sequence_number)
            + spec_u64_be(length),
        final(result)@.len() == message_id@.len() + content@.len() + 12,
{
    result.clear();
    result.extend_from_slice(message_id);
    result.extend_from_slice(content);

    let seq_bytes = u32_be(sequence_number);
    result.extend_from_slice(seq_bytes.as_slice());

    let len_bytes = u64_be(length);
    result.extend_from_slice(len_bytes.as_slice());
}

} // verus!

fn main() {}
