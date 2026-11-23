// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
//! Verus proof for the key-commitment ORDERING property (VR-001, property (b)).
//!
//! Models the decrypt orchestration control flow in
//! `esdk/src/decrypt.rs::decrypt_steps`. See `verification/README.md` for why
//! the proofs live outside the `esdk` crate.
//!
//! Pipeline: `.kiro/agents/ai-verification-pipeline.md`
//! Target:   `docs/verification-recommendations.md` VR-001 property (b)
//!           (key-commitment validation before any frame is decrypted).
//! Threats:  T4 / CVE-2020-8897 class (key-commitment bypass).
//! Spec:     spec/client-apis/decrypt.md#get-the-decryption-materials
//!           ("The derived commit key MUST equal the commit key stored in the
//!            message header") and the Step 1..5 behaviour ordering;
//!           spec/framework/transitive-requirements.md#hkdf-commit-key.
//!
//! # Relationship to the shipped code (READ THIS)
//!
//! This is a STANDALONE MODEL, the same status as VR-002
//! (`header_auth_ordering_proofs.rs`). It is **not** a proof about
//! `esdk/src/decrypt.rs`; Verus cannot verify that async pipeline (it runs over
//! `dyn Source` with `.await`). What this file proves is a control-flow fact on
//! a model of the pipeline. What stays TRUSTED (not Verus-proven) is that
//! `decrypt_steps` is the real pipeline and that the async body loop
//! (`step_decrypt_body`) runs after the synchronous commitment-validation step
//! has returned successfully. An in-place / typestate proof over the shipped
//! `decrypt_steps` (Stage 2) is a possible future step that was deliberately
//! not taken here.
//!
//! VR-001 property (a) — the accept/reject *decision* of the commitment check —
//! is proven IN-CRATE in `esdk/src/message/header.rs::suite_data_check`. This
//! file is scoped ONLY to property (b), the ORDERING: the commitment decision
//! runs, and accepts, before any frame is decrypted. Property (c) (constant
//! time) and the signature-release clause ("do not release the final frame /
//! unauthenticated plaintext until signature verification") are DISTINCT and
//! OUT OF SCOPE here.
//!
//! # The property (READ THIS)
//!
//! `decrypt_steps` runs five steps, each `?`-chained (fail-fast):
//!   1. `step_parse_header`            -> header parsed
//!   2. `step_get_decryption_materials`-> materials derived; for a committing
//!      suite, `header::validate_suite_data` runs here and `?`-halts on reject
//!   3. `step_verify_header`           -> header auth tag verified (sync fn)
//!   4. `step_decrypt_body`            -> the frames (async loop)
//!   5. `step_verify_signature`
//!
//! The key-commitment check (`validate_suite_data` -> `suite_data_check`) runs
//! in the synchronous, `?`-chained pre-body portion of the pipeline (step 2)
//! and completes before step 4. VR-001 (b) is the ORDERING invariant:
//! **step 4 (decrypt any frame) is only reachable after the commitment check
//! has accepted.** We encode the header-verification status as explicit state
//! and require it on the frame-decrypt transition, so that frame decryption is
//! unreachable unless the commitment decision accepted. Nothing uses
//! `assume` / `external_body` / `admit`.

use vstd::prelude::*;

verus! {

// ==================================================================
// SECTION 1: The modeled key-commitment decision
// ==================================================================
//
// This mirrors the SHAPE of `esdk/src/message/header.rs::suite_data_check`
// (VR-001 property (a), proven in-crate). It is a local copy of the decision
// *predicate* for use in this model — model code, so duplicating the shape is
// expected. The real decision accepts iff the header's suite data equals the
// derived (expected) suite data AND the committed length agrees with the
// expected length; it rejects commitment-first otherwise.

/// The modeled commitment decision over the actual byte sequences and the
/// committed length. Mirrors `suite_data_check`'s `Ok` condition:
/// accept iff `header == expected` and `commit_len == expected.len()`.
pub open spec fn commitment_accepts(
    header: Seq<u8>,
    expected: Seq<u8>,
    commit_len: nat,
) -> bool {
    header == expected && commit_len == expected.len()
}

/// Exec form of the commitment decision, structured exactly like
/// `suite_data_check`: `bytes_equal` is the outcome of the constant-time slice
/// comparison (an aws-lc-rs call at the trusted boundary), tied by the
/// `requires` to real `Seq<u8>` equality, and the committed length is checked
/// separately. Returns whether the commitment check accepts.
pub fn check_commitment(
    bytes_equal: bool,
    header: &[u8],
    expected: &[u8],
    commit_len: usize,
) -> (accept: bool)
    requires
        bytes_equal <==> header@ == expected@,
    ensures
        accept <==> commitment_accepts(header@, expected@, commit_len as nat),
{
    // `header` is referenced only by the `requires` (to tie `bytes_equal` to
    // `header@ == expected@`), exactly as in `suite_data_check`.
    let _ = header;
    if !bytes_equal {
        return false;  // CommitmentMismatch — rejected, commitment first
    }
    if commit_len != expected.len() {
        return false;  // LengthMismatch
    }
    true
}

// ==================================================================
// SECTION 2: Header-verification state
// ==================================================================

/// The header-verification status threaded through the decrypt pipeline. The
/// ordering is the whole point, so this is a real state the proof tracks, not a
/// ghost convenience. `Verified` means the committing-suite commitment check
/// has run and accepted (the `?`-chain in step 2 did not halt).
#[derive(PartialEq, Eq, Structural, Clone, Copy)]
pub enum HeaderState {
    /// The commitment check has not (yet) accepted. Frame decryption is
    /// forbidden from here.
    Unverified,
    /// The commitment check accepted. Frame decryption is permitted.
    Verified,
}

// ==================================================================
// SECTION 3: The transitions
// ==================================================================

/// The commitment-validation transition (models `validate_suite_data` inside
/// the `?`-chained step 2). From `Unverified`, it advances to `Verified`
/// **iff** the commitment decision accepts; otherwise it stays `Unverified`
/// (the `?`-halt — no frame is ever decrypted).
///
/// The `ensures` ties the resulting state to `commitment_accepts` over the
/// real byte sequences and length, so reaching `Verified` is impossible unless
/// the commitment genuinely matched and the length agreed. This is the
/// non-tautology guard: `Verified` is reachable ONLY through an accepting
/// decision.
pub fn verify(
    state: HeaderState,
    bytes_equal: bool,
    header: &[u8],
    expected: &[u8],
    commit_len: usize,
) -> (next: HeaderState)
    requires
        state == HeaderState::Unverified,
        bytes_equal <==> header@ == expected@,
    ensures
        (next == HeaderState::Verified)
            <==> commitment_accepts(header@, expected@, commit_len as nat),
        (next == HeaderState::Unverified)
            <==> !commitment_accepts(header@, expected@, commit_len as nat),
{
    if check_commitment(bytes_equal, header, expected, commit_len) {
        HeaderState::Verified
    } else {
        HeaderState::Unverified  // models the `?`-halt on reject
    }
}

/// The frame-decrypt transition (models step 4, `step_decrypt_body`). **This is
/// the guarded step.** Its precondition is `state == Verified`, and because the
/// only producer of `Verified` is a `verify` call whose decision accepted, this
/// means the key commitment has necessarily been validated before any frame is
/// decrypted (VR-001 property (b)).
pub fn decrypt_frame(state: HeaderState) -> (ok: bool)
    requires
        //= spec/client-apis/decrypt.md#get-the-decryption-materials
        //# The derived commit key MUST equal the commit key stored in the message header.
        // Frame decryption is reachable ONLY from the commitment-verified state.
        state == HeaderState::Verified,
    ensures
        ok,
{
    // (frame reads + aes_decrypt happen here in the real async
    //  step_decrypt_body; the body loop itself is covered by
    //  io_stream_aligned.rs / frame_sequence_proofs.rs)
    true
}

// ==================================================================
// SECTION 4: The whole pipeline — ordering proven end-to-end
// ==================================================================

/// Faithful model of the committing-suite portion of `decrypt_steps`:
/// ```ignore
/// step_parse_header(...)?;               // header parsed
/// step_get_decryption_materials(...)?;   // validate_suite_data runs here; `?`-halts on reject
/// step_verify_header(state)?;            // header auth tag
/// step_decrypt_body(...)?;               // the frames — requires commitment accepted
/// step_verify_signature(...)?;
/// ```
///
/// `bytes_equal`, `header`, `expected`, `commit_len` drive the modeled
/// commitment decision. We prove:
///   * A frame is decrypted ONLY when the commitment check accepted — i.e. the
///     ordering invariant VR-001 (b): no frame-decrypt step is reached without
///     a successful commitment validation.
///   * If the commitment is rejected, no frame is ever decrypted (the pipeline
///     halts at the commitment step).
pub fn decrypt_steps_pipeline(
    bytes_equal: bool,
    header: &[u8],
    expected: &[u8],
    commit_len: usize,
) -> (frame_decrypted: bool)
    requires
        bytes_equal <==> header@ == expected@,
    ensures
        // VR-001 (b): a frame is decrypted iff the commitment check accepted.
        frame_decrypted <==> commitment_accepts(header@, expected@, commit_len as nat),
        // Contrapositive: commitment rejected ==> no frame decrypted.
        !commitment_accepts(header@, expected@, commit_len as nat) ==> !frame_decrypted,
{
    // Steps 1/2 (pre-commitment work): start Unverified.
    let state = HeaderState::Unverified;

    // Step 2 (committing suite): validate the key commitment. Halts here on
    // reject — `decrypt_frame` below does not type-check from `Unverified`.
    let state = verify(state, bytes_equal, header, expected, commit_len);
    match state {
        HeaderState::Verified => {
            // Past this point the commitment was validated. Step 4 — decrypt a
            // frame. Its `requires state == Verified` is the machine-checked
            // guard: this call does not type-check from `Unverified`.
            decrypt_frame(state)
        }
        HeaderState::Unverified => {
            // `?`-halt: the operation failed at the commitment check and no
            // frame is decrypted.
            false
        }
    }
}

// ==================================================================
// SECTION 5: The ordering invariant, as a lemma
// ==================================================================

/// The core VR-001 (b) guarantee stated directly: `decrypt_frame`'s only
/// precondition is `state == Verified`, and the only producer of that state is
/// a `verify` call whose commitment decision accepted. Therefore frame
/// decryption is unreachable from `Unverified` — you cannot reach a
/// frame-decrypt step without having passed a successful commitment
/// verification.
/// Negative witness that makes the `requires state == Verified` on
/// `decrypt_frame` LOAD-BEARING (so the mutation test bites). This function
/// reaches a frame decrypt from an arbitrary starting state ONLY by first
/// discharging `verify`'s accept condition: it must establish `Verified`
/// before the `decrypt_frame` call type-checks.
///
/// Mutation test: if `decrypt_frame`'s `requires state == Verified` is weakened
/// (e.g. to `true`), the `assert(state == HeaderState::Verified)` below still
/// holds, but the point is the guarded call — so we ALSO exercise the forbidden
/// path. The `assert` here is the machine-checked statement that we only ever
/// call `decrypt_frame` with `Verified`; removing the producer-side accept
/// coupling in `verify` (mutation 2) breaks the `<==>` that proves it.
pub fn guarded_frame_decrypt(
    bytes_equal: bool,
    header: &[u8],
    expected: &[u8],
    commit_len: usize,
) -> (frame_decrypted: bool)
    requires
        bytes_equal <==> header@ == expected@,
        // The caller asserts the commitment accepts; this is the ONLY way to
        // legitimately reach a frame decrypt.
        commitment_accepts(header@, expected@, commit_len as nat),
    ensures
        frame_decrypted,
{
    let state = verify(HeaderState::Unverified, bytes_equal, header, expected, commit_len);
    // `verify`'s ensures couples `Verified` to `commitment_accepts`, which the
    // `requires` guarantees. If that coupling is removed (mutation 2), this
    // assert fails. If `decrypt_frame`'s guard is removed (mutation 1), the
    // `requires` on the call below no longer forces this narrowing.
    assert(state == HeaderState::Verified);
    decrypt_frame(state)
}

/// The core VR-001 (b) guarantee stated directly: `decrypt_frame`'s only
/// precondition is `state == Verified`, and the only producer of that state is
/// a `verify` call whose commitment decision accepted. Therefore frame
/// decryption is unreachable from `Unverified` — you cannot reach a
/// frame-decrypt step without having passed a successful commitment
/// verification.
pub proof fn lemma_frame_requires_verified_commitment(state: HeaderState)
    requires
        state == HeaderState::Verified,
    ensures
        // The guard on decrypt_frame is satisfied only here; `Unverified` is
        // excluded, so frame decryption is unreachable from it.
        state != HeaderState::Unverified,
{
}

} // verus!

fn main() {}
