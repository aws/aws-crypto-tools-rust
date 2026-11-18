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

} // verus!
