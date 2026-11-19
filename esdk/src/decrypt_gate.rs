// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

//! Proof tokens for the decrypt order (VR-001 property (b) and VR-002).
//!
//! Decrypt must accept the key commitment and verify the header
//! authentication tag before it decrypts any frame. This module holds two
//! tokens that record those two facts:
//!
//! - [`CommitmentAccepted`]: the key commitment check passed, or the suite
//!   does not use key commitment.
//! - [`HeaderVerified`]: the header authentication tag verified. It can only
//!   be made by using up a `CommitmentAccepted`, so holding one means both
//!   checks passed.
//!
//! `step_decrypt_body` in `decrypt.rs` takes a `&HeaderVerified`, so the
//! code that decrypts frames cannot be called until both checks have passed.
//!
//! What is proven and what is trusted:
//! - Verus proves that each function here returns a token only when its check
//!   passed, and that every `CommitmentAccepted` for a committing suite
//!   records matching suite data and a matching length.
//! - The Rust compiler enforces the order. The token fields are private, so
//!   no code outside this module can build a token, and `step_decrypt_body`
//!   cannot be called without one. This does not depend on how the async
//!   runtime schedules the steps.
//! - Trusted, not proven: the callers in `decrypt.rs` and `header.rs` pass
//!   the real check results (the constant-time comparison result, the real
//!   suite, the real `secret::open` result); aws-lc-rs accepts only a valid
//!   tag; frames are decrypted only through `step_decrypt_body`; a token is
//!   not tied to one particular message.
//!
//! Both tokens are zero-sized at runtime and are neither `Clone` nor `Copy`.
//!
//! The module also holds back the final plaintext until the signature
//! verifies (VR-015). The spec says plaintext from a final frame or from a
//! non-framed body must not be released before the signature check passes.
//!
//! - [`SignaturePresence`]: the materials have a verification key exactly
//!   when the suite has a signature algorithm. `decrypt_steps` gets one from
//!   [`signature_presence_gate`], and the signature step needs it.
//! - [`SignatureRequired`]: the suite is signed and a key is present, so the
//!   signature must be checked. [`signature_gate`] needs one.
//! - [`SignatureVerified`]: the signature verified, or the suite is unsigned
//!   and there is no verification key, so there is nothing to check.
//! - [`HeldFinalPlaintext`]: the final plaintext. Its bytes can only be read
//!   through [`release`], which needs a `&SignatureVerified`.
//!
//! `step_decrypt_body` in `decrypt.rs` returns a `HeldFinalPlaintext`, and
//! `decrypt_steps` writes it to the caller only through `release`.
//!
//! What is proven and what is trusted for VR-015:
//! - Verus proves that a `SignaturePresence` is made only when "suite signed"
//!   equals "key present"; that a `SignatureVerified` is made only when the
//!   signature check returned `true` for a signed suite with a key, or when
//!   the suite is unsigned and there is no key; and that `release` returns
//!   exactly the held bytes.
//! - The Rust compiler enforces the order. Only this module can build these
//!   tokens or read a `HeldFinalPlaintext`, so the signature step cannot
//!   choose its path without the presence check, and the final plaintext
//!   cannot be written out before the signature step passes.
//! - Trusted, not proven: aws-lc-rs returns `true` only for a valid
//!   signature; the caller passes the real check result, the real suite
//!   flag and the real "verification key present" flag; the decryption
//!   materials do not change between the presence check and the signature
//!   step; the body readers return the final plaintext instead of writing it
//!   out themselves.
//!   Regular frames before the final one are released early on purpose, as
//!   the spec allows, and are not covered.

use crate::message::header::{SuiteDataError, suite_data_check};
use vstd::prelude::*;

verus! {

/// Proof that the key commitment check passed, or that the suite does not
/// use key commitment. Only this module can create one.
pub(crate) struct CommitmentAccepted {
    #[allow(dead_code, reason = "ghost field: read only by specs")]
    committing: Ghost<bool>,
    #[allow(dead_code, reason = "ghost field: read only by specs")]
    header: Ghost<Seq<u8>>,
    #[allow(dead_code, reason = "ghost field: read only by specs")]
    expected: Ghost<Seq<u8>>,
    #[allow(dead_code, reason = "ghost field: read only by specs")]
    commit_len: Ghost<nat>,
}

impl CommitmentAccepted {
    /// Whether the suite uses key commitment.
    pub(crate) closed spec fn committing(&self) -> bool {
        self.committing@
    }

    /// The suite data read from the header.
    pub(crate) closed spec fn header(&self) -> Seq<u8> {
        self.header@
    }

    /// The commit key derived from the data key.
    pub(crate) closed spec fn expected(&self) -> Seq<u8> {
        self.expected@
    }

    /// The suite's declared commit key length.
    pub(crate) closed spec fn commit_len(&self) -> nat {
        self.commit_len@
    }

    /// For a committing suite, the header's suite data equals the derived
    /// commit key, and the suite's commit length equals its length.
    #[verifier::type_invariant]
    spec fn inv(&self) -> bool {
        self.committing() ==> (self.header() == self.expected() && self.commit_len()
            == self.expected().len())
    }
}

/// Every `CommitmentAccepted` for a committing suite records a matching
/// commitment and length.
pub(crate) proof fn lemma_commitment_accepted(tracked t: &CommitmentAccepted)
    ensures
        t.committing() ==> (t.header() == t.expected() && t.commit_len() == t.expected().len()),
{
    use_type_invariant(t);
}

/// Proof that the header authentication tag verified, after the key
/// commitment was accepted. Only this module can create one, and only by
/// using up a `CommitmentAccepted`.
pub(crate) struct HeaderVerified {
    #[allow(dead_code, reason = "held so that a HeaderVerified implies a CommitmentAccepted")]
    _commitment: CommitmentAccepted,
}

impl HeaderVerified {
    /// The commitment token this header token was built from.
    pub(crate) closed spec fn commitment(&self) -> CommitmentAccepted {
        self._commitment
    }
}

/// For a suite without key commitment, returns a token saying no commitment
/// check is needed. For a committing suite, returns `None`, and the caller
/// must run the commitment check to get a token.
pub(crate) fn commitment_not_required(suite_commits: bool) -> (r: Option<CommitmentAccepted>)
    ensures
        (r is Some) <==> !suite_commits,
        r matches Some(t) ==> !t.committing(),
{
    if suite_commits {
        None
    } else {
        Some(
            CommitmentAccepted {
                committing: Ghost(false),
                header: Ghost(Seq::empty()),
                expected: Ghost(Seq::empty()),
                commit_len: Ghost(0),
            },
        )
    }
}

/// Runs the verified commitment decision `suite_data_check` and returns a
/// token only when it accepts. The errors are the same as
/// `suite_data_check`'s.
pub(crate) fn commitment_gate(
    bytes_equal: bool,
    header: &[u8],
    expected: &[u8],
    commit_len: usize,
) -> (r: Result<CommitmentAccepted, SuiteDataError>)
    requires
        bytes_equal <==> header@ == expected@,
    ensures
        (r is Ok) <==> (header@ == expected@ && commit_len == expected@.len()),
        (r matches Err(SuiteDataError::CommitmentMismatch)) <==> (header@ != expected@),
        (r matches Err(SuiteDataError::LengthMismatch)) <==> (header@ == expected@
            && commit_len != expected@.len()),
        r matches Ok(t) ==> (t.committing() && t.header() == header@ && t.expected() == expected@
            && t.commit_len() == commit_len),
{
    match suite_data_check(bytes_equal, header, expected, commit_len) {
        Ok(()) => Ok(
            CommitmentAccepted {
                committing: Ghost(true),
                header: Ghost(header@),
                expected: Ghost(expected@),
                commit_len: Ghost(commit_len as nat),
            },
        ),
        Err(e) => Err(e),
    }
}

/// Uses up the commitment token and returns a header token only when the
/// header tag check (`open_result`) succeeded. On failure it returns the same
/// error value unchanged.
pub(crate) fn header_auth_gate<E>(commitment: CommitmentAccepted, open_result: Result<(), E>) -> (r:
    Result<HeaderVerified, E>)
    ensures
        (r is Ok) <==> (open_result is Ok),
        r matches Ok(h) ==> h.commitment() == commitment,
        open_result matches Err(e) ==> (r matches Err(e2) && e2 == e),
{
    match open_result {
        Ok(()) => Ok(HeaderVerified { _commitment: commitment }),
        Err(e) => Err(e),
    }
}

// ---------------------------------------------------------------------------
// VR-015: the final plaintext is held until the signature verifies.
// ---------------------------------------------------------------------------
/// Proof that the message signature verified, or that the message has no
/// signature to check. Only this module can create one.
pub(crate) struct SignatureVerified {
    #[allow(dead_code, reason = "ghost field: read only by specs")]
    signed: Ghost<bool>,
}

impl SignatureVerified {
    /// Whether this token came from a real signature check (`true`) or from a
    /// message with no signature (`false`).
    pub(crate) closed spec fn signed(&self) -> bool {
        self.signed@
    }
}

/// Proof that the decryption materials have a verification key exactly when
/// the algorithm suite has a signature algorithm (VR-015 (b)). Only this
/// module can create one, and only through `signature_presence_gate`.
pub(crate) struct SignaturePresence {
    suite_signed: bool,
    #[allow(dead_code, reason = "ghost field: read only by specs")]
    has_key: Ghost<bool>,
}

impl SignaturePresence {
    /// Whether the algorithm suite has a signature algorithm.
    pub(crate) closed spec fn signed(&self) -> bool {
        self.suite_signed
    }

    /// Whether the decryption materials have a verification key.
    pub(crate) closed spec fn has_key(&self) -> bool {
        self.has_key@
    }

    /// The suite is signed exactly when there is a verification key.
    #[verifier::type_invariant]
    spec fn inv(&self) -> bool {
        self.signed() == self.has_key()
    }
}

/// Proof that the suite is signed and a verification key is present, so the
/// signature must be checked. Only this module can create one, and only by
/// using up a `SignaturePresence` for a signed suite.
pub(crate) struct SignatureRequired {
    #[allow(dead_code, reason = "held so that a SignatureRequired implies a SignaturePresence")]
    _presence: SignaturePresence,
}

impl SignatureRequired {
    /// The presence token this token was built from.
    pub(crate) closed spec fn presence(&self) -> SignaturePresence {
        self._presence
    }

    /// The suite is signed and a verification key is present.
    #[verifier::type_invariant]
    spec fn inv(&self) -> bool {
        self._presence.signed() && self._presence.has_key()
    }
}

/// Every `SignatureRequired` is for a signed suite with a verification key.
pub(crate) proof fn lemma_signature_required(tracked t: &SignatureRequired)
    ensures
        t.presence().signed() && t.presence().has_key(),
{
    use_type_invariant(t);
}

/// The presence check: returns a token only when the suite has a signature
/// algorithm exactly when the materials have a verification key. On a
/// mismatch it returns `None`, and the caller reports `InvalidMaterials`.
pub(crate) fn signature_presence_gate(suite_has_signature: bool, has_verification_key: bool) -> (r:
    Option<SignaturePresence>)
    ensures
        (r is Some) <==> (suite_has_signature == has_verification_key),
        r matches Some(p) ==> (p.signed() == suite_has_signature && p.has_key()
            == has_verification_key),
{
    if suite_has_signature == has_verification_key {
        Some(
            SignaturePresence {
                suite_signed: suite_has_signature,
                has_key: Ghost(has_verification_key),
            },
        )
    } else {
        None
    }
}

/// Uses up the presence token. For an unsigned suite with no verification
/// key, returns `Ok` with a token saying no signature check is needed. For a
/// signed suite with a verification key, returns `Err` with a
/// `SignatureRequired`, and the caller must check the signature to get a
/// token.
pub(crate) fn signature_not_required(presence: SignaturePresence) -> (r: Result<
    SignatureVerified,
    SignatureRequired,
>)
    ensures
        (r is Ok) <==> (!presence.signed() && !presence.has_key()),
        r matches Ok(t) ==> !t.signed(),
        r matches Err(q) ==> (q.presence() == presence && presence.signed() && presence.has_key()),
{
    proof {
        use_type_invariant(&presence);
    }
    if presence.suite_signed {
        Err(SignatureRequired { _presence: presence })
    } else {
        Ok(SignatureVerified { signed: Ghost(false) })
    }
}

/// Uses up the `SignatureRequired` token and returns a signature token only
/// when the signature check (`valid`) passed. When it failed, returns
/// `None`, and the caller reports the error.
pub(crate) fn signature_gate(_required: SignatureRequired, valid: bool) -> (r: Option<
    SignatureVerified,
>)
    ensures
        (r is Some) <==> valid,
        r matches Some(t) ==> (t.signed() && _required.presence().signed()
            && _required.presence().has_key()),
{
    proof {
        use_type_invariant(&_required);
    }
    if valid {
        Some(SignatureVerified { signed: Ghost(true) })
    } else {
        None
    }
}

/// The final plaintext of a message (the final frame, the last full frame
/// when the final frame is empty, or a non-framed body), held back until the
/// signature step passes. The bytes can only be read through `release`.
pub(crate) struct HeldFinalPlaintext {
    bytes: Vec<u8>,
}

impl HeldFinalPlaintext {
    /// The held bytes.
    pub(crate) closed spec fn bytes(&self) -> Seq<u8> {
        self.bytes@
    }
}

/// Holds the final plaintext so that it cannot be read without a
/// `SignatureVerified` token.
pub(crate) fn hold_final_plaintext(bytes: Vec<u8>) -> (r: HeldFinalPlaintext)
    ensures
        r.bytes() == bytes@,
{
    HeldFinalPlaintext { bytes }
}

/// Gives back the held final plaintext. It needs a `SignatureVerified` token,
/// so it cannot be called before the signature step passes. Returns exactly
/// the held bytes.
pub(crate) fn release<'a>(held: &'a HeldFinalPlaintext, _signature: &SignatureVerified) -> (r:
    &'a [u8])
    ensures
        r@ == held.bytes(),
{
    held.bytes.as_slice()
}

} // verus!

#[cfg(test)]
mod tests {
    use super::*;

    // Defense-in-depth test of esdk's own fallback check: the MPL rejects a
    // signing suite with no verification key, and an unsigned suite with one,
    // before the public API hands the materials to esdk.
    #[test]
    fn signature_presence_gate_rejects_mismatch() {
        assert!(signature_presence_gate(true, false).is_none());
        assert!(signature_presence_gate(false, true).is_none());
        assert!(signature_presence_gate(true, true).is_some());
        assert!(signature_presence_gate(false, false).is_some());
    }
}
