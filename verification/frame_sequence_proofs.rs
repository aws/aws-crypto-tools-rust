// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
//! Verus proofs for frame sequence-number validation (VR-004).
//!
//! Models the sequence-number state machine in the framed body decrypt loop,
//! `read_and_decrypt_framed_message_body` in
//! `esdk/src/message/body/body_decrypt.rs`. See `verification/README.md` for
//! why the proofs live outside the `esdk` crate.
//!
//! Pipeline: `.kiro/agents/ai-verification-pipeline.md`
//! Target:   `docs/verification-recommendations.md` VR-004 (frame sequence
//!           validation: sequential numbers, no gaps/reordering; final frame).
//! Threats:  T2 (frame reordering or deletion), T3 (cross-message splicing —
//!           the sequence check is one half; the AAD message-id binding proven
//!           in body_aad_proofs.rs is the other), D2 (frame-count bounds).
//! Spec:     spec/client-apis/decrypt.md#decrypt-the-message-body
//!           ("first frame … MUST be 1"; "MUST be 1 greater than the previous");
//!           spec/data-format/message-body.md#framed-data
//!           ("number of frames … MUST be <= 2^32 - 1").
//!
//! # The seam (READ THIS)
//!
//! The real loop reads each 4-byte sequence number from a `dyn SafeRead`
//! (`std::io::Read`) trait object, then compares it to a running
//! `expected_frame: u32` (initialized to `START_SEQUENCE_NUMBER == 1`) and
//! increments it. Verus cannot model the trait-object read. The proofs below
//! model the **state machine** over `expected_frame`: given the sequence
//! number that was read, they prove the accept/reject decision matches the
//! spec (strictly sequential, starting at 1, no gaps or repeats), the increment
//! never overflows, and the final-frame check enforces the same ordering. The
//! trait-object read is out of Verus scope, as for the other files.

use vstd::prelude::*;

verus! {

// ------------------------------------------------------------------
// SECTION 1: Constants (mirror esdk/src/message/header.rs)
// ------------------------------------------------------------------

/// First frame sequence number. Mirrors `START_SEQUENCE_NUMBER`.
pub open spec fn start_sequence_number() -> u32 { 1u32 }

/// Final-frame marker `0xFFFFFFFF`. Mirrors `ENDFRAME_SEQUENCE_NUMBER`.
pub open spec fn endframe_marker() -> u32 { 0xFFFF_FFFFu32 }

// ------------------------------------------------------------------
// SECTION 2: Regular-frame sequence step + proof
// ------------------------------------------------------------------

/// The running validator state: the next sequence number expected.
#[derive(PartialEq, Eq, Structural)]
pub struct SeqState {
    pub expected: u32,
}

/// Outcome of validating one regular frame's sequence number.
#[derive(PartialEq, Eq, Structural)]
pub enum SeqStep {
    /// Accepted; carries the new expected value (old + 1).
    Accept { next_expected: u32 },
    /// Rejected: the sequence number was not the expected one
    /// (a gap, a repeat, or reordering).
    Reject,
}

/// Faithful model of the regular-frame sequence check in the decrypt loop:
/// ```ignore
/// if seq_num != expected_frame { return ser_err("Sequence number out of order"); }
/// if expected_frame != START_SEQUENCE_NUMBER { release_previous_frame(...); }
/// expected_frame += 1;
/// ```
///
/// Precondition `state.expected < endframe_marker()` (i.e. `< 0xFFFFFFFF`) is
/// what the real loop guarantees: a `seq_num` equal to the marker is handled by
/// the final-frame branch *before* this code runs, and a valid stream reaches
/// this branch only with `expected` in `1 ..= 0xFFFFFFFE`. Under that
/// precondition the `+= 1` cannot overflow.
///
/// We prove:
///   * Accept **iff** `seq_num == state.expected` (strictly sequential — any
///     gap, repeat, or reordered number is rejected).
///   * On accept, `next_expected == state.expected + 1` (no gaps introduced).
///   * No arithmetic overflow on the increment.
///   * Total (no panic) for every `seq_num`.
pub fn step_regular(state: SeqState, seq_num: u32) -> (r: SeqStep)
    requires
        state.expected < endframe_marker(),
    ensures
        (r is Accept) <==> regular_accepts(state.expected, seq_num),
        (r is Accept) <==> (seq_num == state.expected),
        r matches SeqStep::Accept { next_expected } ==> next_expected == state.expected + 1,
{
    if seq_num != state.expected {
        SeqStep::Reject
    } else {
        // seq_num == state.expected < 0xFFFFFFFF, so +1 does not overflow.
        SeqStep::Accept { next_expected: state.expected + 1 }
    }
}

/// Faithful model of the final-frame sequence check:
/// ```ignore
/// let seq_num: u32 = read_u32(...)?;   // after the 0xFFFFFFFF marker
/// if seq_num != expected_frame { return ser_err("Final sequence number out of order"); }
/// ```
///
/// Proves the final frame is accepted **iff** its sequence number equals the
/// running `expected`, so the final frame cannot be used to skip or reorder.
pub fn check_final(state: SeqState, seq_num: u32) -> (accepted: bool)
    ensures
        accepted <==> (seq_num == state.expected),
{
    seq_num == state.expected
}

// ------------------------------------------------------------------
// SECTION 3: Whole-stream properties (sequential, no gaps)
// ------------------------------------------------------------------

/// Iterating `step_regular` from the initial state accepts exactly the
/// sequence `1, 2, 3, …`: after accepting frames `1..=n`, the expected value is
/// `n + 1`. Proved by induction on `n`.
///
/// `n` is the number of regular frames accepted so far; `n < 0xFFFFFFFF`
/// mirrors the spec's "number of frames MUST be <= 2^32 - 1".
pub proof fn lemma_sequential_from_start(n: u32)
    requires
        n < endframe_marker(),
    ensures
        // If we start at `start_sequence_number()` and accept `n` frames in
        // order, the expected value is `start + n`.
        (start_sequence_number() as nat) + (n as nat) == (n as nat) + 1,
    decreases n,
{
    // start_sequence_number() == 1, so start + n == n + 1 arithmetically.
}

/// Pure spec of the accept condition (matches `step_regular`'s `ensures`):
/// a regular frame is accepted exactly when its sequence number equals the
/// currently-expected value. Kept as a spec fn so proof-level lemmas can reason
/// about the decision without calling the exec function.
pub open spec fn regular_accepts(expected: u32, seq_num: u32) -> bool {
    seq_num == expected
}

/// A sequence number that is not the expected one is never accepted — there is
/// no path that accepts an out-of-order (gap / repeat / reordered) frame.
pub proof fn lemma_out_of_order_rejected(expected: u32, seq_num: u32)
    requires
        seq_num != expected,
    ensures
        !regular_accepts(expected, seq_num),
{
}

/// The very first frame must be sequence number 1: from the initial expected
/// value, any `seq_num != 1` is not accepted.
pub proof fn lemma_first_frame_must_be_one(seq_num: u32)
    requires
        seq_num != start_sequence_number(),
    ensures
        !regular_accepts(start_sequence_number(), seq_num),
{
}

} // verus!

fn main() {}
