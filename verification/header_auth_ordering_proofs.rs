// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
//! Verus proof for the header-authentication ORDERING property (VR-002).
//!
//! Models the decrypt orchestration control flow in
//! `esdk/src/decrypt.rs::internal_decrypt`. See `verification/README.md` for
//! why the proofs live outside the `esdk` crate.
//!
//! Pipeline: `.kiro/agents/ai-verification-pipeline.md`
//! Target:   `docs/verification-recommendations.md` VR-002 (header auth tag
//!           verified before any frame is decrypted).
//! Threats:  T1 (header modification / algorithm-suite downgrade),
//!           T6 (auth tag truncation or modification).
//! Spec:     spec/client-apis/decrypt.md#verify-the-header
//!           ("If this tag verification fails, this operation MUST immediately
//!            halt and fail"), and the Step 1..5 behaviour ordering.
//!
//! # The property (READ THIS)
//!
//! `internal_decrypt` runs five steps, each with `?` (fail-fast):
//!   1. parse header
//!   2. get decryption materials (derive keys, read the header auth tag)
//!   3. **verify the header** — AES-GCM tag check; `maybe_header_auth?` halts
//!      the whole operation if the tag does not verify
//!   4. decrypt the message body (the frames)
//!   5. verify the signature
//!
//! VR-002 is the ORDERING invariant: **step 4 (decrypt any frame) is only
//! reachable after step 3 (verify header tag) has succeeded.** This is a
//! control-flow property, independent of the crypto: the AES-GCM tag check
//! itself is an `aws-lc-rs` call (out of Verus scope), but *whether the code
//! can proceed to frame decryption without it having succeeded* is pure control
//! flow, and that is what we model and prove here.
//!
//! We encode the decrypt phases as a state machine where each transition
//! requires the previous phase, so that "decrypt body" is unreachable unless
//! "header verified" was reached, which in turn requires the tag check to have
//! returned success. Nothing uses `assume` / `external_body` / `admit`.

use vstd::prelude::*;

verus! {

// ==================================================================
// SECTION 1: Decrypt phase state machine
// ==================================================================

/// The phases of `internal_decrypt`, in order. The ordering is the whole point,
/// so the phase is explicit ghost state threaded through the transitions.
#[derive(PartialEq, Eq, Structural, Clone, Copy)]
pub enum Phase {
    /// Nothing done yet.
    Start,
    /// Step 1 complete: header parsed.
    HeaderParsed,
    /// Step 2 complete: decryption materials obtained, header auth tag read,
    /// commit key validated (for committing suites).
    MaterialsReady,
    /// Step 3 complete: header authentication tag VERIFIED.
    HeaderVerified,
    /// Step 4 complete: message body decrypted.
    BodyDecrypted,
    /// Step 5 complete: signature verified. Terminal success.
    SignatureVerified,
}

/// Outcome of a step: either advance to a new phase, or fail (the `?` halt).
#[derive(PartialEq, Eq, Structural)]
pub enum StepOutcome {
    Advance { to: Phase },
    Fail,
}

// ==================================================================
// SECTION 2: The transitions (mirror the `?`-chained steps)
// ==================================================================

/// Step 3: verify the header authentication tag. `tag_ok` is the result of the
/// AES-GCM tag check (`aes_decrypt(...)` over the header — an aws-lc-rs call,
/// modeled here as its boolean success). The step advances to `HeaderVerified`
/// **iff** the tag verified; otherwise it fails (`maybe_header_auth?`).
///
/// Precondition: this step runs only from `MaterialsReady` (the `?`-chain order).
pub fn step_verify_header(phase: Phase, tag_ok: bool) -> (r: StepOutcome)
    requires
        phase == Phase::MaterialsReady,
    ensures
        // Advances to HeaderVerified exactly when the tag check passed.
        (r == (StepOutcome::Advance { to: Phase::HeaderVerified })) <==> tag_ok,
        // On tag failure the operation halts (Fail) — no advance.
        !tag_ok ==> r == StepOutcome::Fail,
{
    if tag_ok {
        StepOutcome::Advance { to: Phase::HeaderVerified }
    } else {
        StepOutcome::Fail  // models `maybe_header_auth?` halting the operation
    }
}

/// Step 4: decrypt the message body. **This is the guarded step.** Its
/// precondition is `phase == HeaderVerified`, which — because the only way to
/// reach that phase is a successful `step_verify_header` — means the header tag
/// has necessarily been verified before any frame is decrypted.
pub fn step_decrypt_body(phase: Phase) -> (r: StepOutcome)
    requires
        //= spec/client-apis/decrypt.md#verify-the-header
        //# If this tag verification fails, this operation MUST immediately halt and fail.
        // Body decryption is reachable ONLY from the header-verified phase.
        phase == Phase::HeaderVerified,
    ensures
        r == (StepOutcome::Advance { to: Phase::BodyDecrypted })
            || r == StepOutcome::Fail,
{
    // (frame reads + aes_decrypt happen here — see io_stream_aligned.rs
    //  read_and_decrypt_framed_body for the body-loop proof)
    StepOutcome::Advance { to: Phase::BodyDecrypted }
}

// ==================================================================
// SECTION 3: The whole pipeline — ordering proven end-to-end
// ==================================================================

/// Faithful model of the `?`-chained pipeline in `internal_decrypt`:
/// ```ignore
/// step_parse_header(...)?;              // -> HeaderParsed
/// step_get_decryption_materials(...)?;  // -> MaterialsReady
/// step_verify_header(state)?;           // -> HeaderVerified  (or halt)
/// step_decrypt_body(...)?;              // -> BodyDecrypted
/// step_verify_signature(...)?;          // -> SignatureVerified
/// ```
///
/// `parse_ok`, `materials_ok`, `tag_ok`, `sig_ok` model each step's success
/// (the crypto/IO results). We prove:
///   * If the pipeline reaches `BodyDecrypted` or `SignatureVerified`, then the
///     header tag was verified (`tag_ok`) — i.e. **no frame is decrypted unless
///     the header tag verified first** (VR-002).
///   * If the tag check fails (`!tag_ok`), the pipeline halts before body
///     decryption (result is `Fail`, never a body-decrypted phase).
pub fn internal_decrypt_pipeline(
    parse_ok: bool,
    materials_ok: bool,
    tag_ok: bool,
    sig_ok: bool,
) -> (result: Phase)
    ensures
        // VR-002 (contrapositive form): reaching body decryption implies the
        // header tag was verified.
        (result == Phase::BodyDecrypted || result == Phase::SignatureVerified)
            ==> tag_ok,
        // If the tag check failed, the body is never decrypted.
        !tag_ok ==> (result != Phase::BodyDecrypted && result != Phase::SignatureVerified),
{
    // Step 1
    if !parse_ok {
        return Phase::Start;
    }
    let phase = Phase::HeaderParsed;

    // Step 2
    if !materials_ok {
        return phase;  // halt at HeaderParsed
    }
    let phase = Phase::MaterialsReady;

    // Step 3 — verify the header tag. Halts here on failure.
    let phase = match step_verify_header(phase, tag_ok) {
        StepOutcome::Advance { to } => to,
        StepOutcome::Fail => return phase,  // MaterialsReady, body NOT decrypted
    };
    // Past this point, phase == HeaderVerified, which required tag_ok.

    // Step 4 — decrypt body. Its `requires phase == HeaderVerified` is the
    // machine-checked guard: this call does not type-check from any earlier
    // phase.
    let phase = match step_decrypt_body(phase) {
        StepOutcome::Advance { to } => to,
        StepOutcome::Fail => return phase,  // HeaderVerified
    };

    // Step 5 — verify signature.
    if !sig_ok {
        return phase;  // BodyDecrypted (tag_ok already established)
    }
    Phase::SignatureVerified
}

// ==================================================================
// SECTION 4: The ordering invariant, as a lemma
// ==================================================================

/// The core VR-002 guarantee stated directly: `step_decrypt_body`'s only
/// precondition is `phase == HeaderVerified`, and the only producer of that
/// phase is a successful `step_verify_header` (which requires `tag_ok`).
/// Therefore body decryption is unreachable without a verified header tag.
///
/// This lemma restates the reachability fact the pipeline proof relies on: any
/// phase from which the body may be decrypted must be `HeaderVerified`.
pub proof fn lemma_body_requires_verified_header(phase: Phase)
    requires
        phase == Phase::HeaderVerified,
    ensures
        // The guard on step_decrypt_body is satisfied only here.
        phase != Phase::Start,
        phase != Phase::HeaderParsed,
        phase != Phase::MaterialsReady,
{
}

} // verus!

fn main() {}
