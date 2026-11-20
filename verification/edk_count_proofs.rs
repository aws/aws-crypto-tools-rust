// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
//! Verus proof for the encrypted-data-key (EDK) count validation.
//!
//! Faithful, self-contained model of `validate_max_encrypted_data_keys` from
//! `esdk/src/message/header.rs`. See `verification/README.md` for why the
//! proofs live outside the `esdk` crate.
//!
//! Pipeline: `.kiro/agents/ai-verification-pipeline.md`
//! Target:   `docs/verification-recommendations.md` VR-007 (EDK count).
//! Threats:  D1 (excessive EDKs → KMS-call flood / DoS).
//! Spec:     spec/data-format/message-header.md#encrypted-data-key-count
//!           ("This value MUST be greater than 0.")
//!           spec/client-apis/decrypt.md (max encrypted data keys check).

use vstd::prelude::*;

verus! {

// ------------------------------------------------------------------
// SECTION 1: Specification — when EDK count is valid
// ------------------------------------------------------------------

/// The validity predicate the code must implement:
///   * the count MUST be > 0, and
///   * if a maximum is configured, the count MUST NOT exceed it.
///
/// `max` is modeled as `Option<usize>` with the caller obligation that a
/// present maximum is non-zero (the real signature uses `NonZeroUsize`, whose
/// invariant we re-establish in the exec model below).
pub open spec fn edk_count_valid(count: nat, max: Option<usize>) -> bool {
    &&& count > 0
    &&& match max {
        Some(m) => count <= m as nat,
        None => true,
    }
}

// ------------------------------------------------------------------
// SECTION 2: Faithful exec model + proof
// ------------------------------------------------------------------

/// Faithful model of `validate_max_encrypted_data_keys`.
///
/// Original:
/// ```ignore
/// pub(crate) fn validate_max_encrypted_data_keys(
///     max_encrypted_data_keys: Option<std::num::NonZeroUsize>,
///     edks: &[aws_mpl_legacy::EncryptedDataKey],
/// ) -> Result<(), Error> {
///     if edks.is_empty() {
///         return Err(val_err("Encrypted data key count must be greater than 0"));
///     }
///     if let Some(max) = max_encrypted_data_keys
///         && edks.len() > max.get()
///     {
///         return Err(val_err(format!(...)));
///     }
///     Ok(())
/// }
/// ```
///
/// Fidelity notes:
///   * `edks: &[T]` — the function only ever calls `edks.is_empty()` and
///     `edks.len()`, so the element type is irrelevant to the logic. We model
///     it with a generic slice `&[T]`; the count is `edks.len()`.
///   * `Error` is modeled as `()` in the `Err` arm — the proof is about
///     *which* branch is taken (Ok vs Err), not the error payload.
///   * The `if let Some && ...` let-chain is written as an explicit nested
///     `match`/`if`, which is semantically identical.
///
/// We prove: the result is `Ok(())` **iff** the count is valid per
/// `edk_count_valid` — i.e. the code accepts exactly the valid inputs and
/// rejects everything else, and never panics.
pub fn validate_max_encrypted_data_keys<T>(
    max_encrypted_data_keys: Option<core::num::NonZeroUsize>,
    edks: &[T],
) -> (result: Result<(), ()>)
    ensures
        result is Ok <==> edk_count_valid(
            edks@.len() as nat,
            match max_encrypted_data_keys {
                Some(m) => Some(m.get()),
                None => None,
            },
        ),
{
    if edks.is_empty() {
        //= spec/data-format/message-header.md#encrypted-data-key-count
        //# This value MUST be greater than 0.
        return Err(());
    }

    match max_encrypted_data_keys {
        Some(max) => {
            if edks.len() > max.get() {
                Err(())
            } else {
                Ok(())
            }
        }
        None => Ok(()),
    }
}

// ------------------------------------------------------------------
// SECTION 3: Sanity lemmas — the accept/reject boundary
// ------------------------------------------------------------------

/// Empty EDK list is always rejected, regardless of the configured maximum.
pub proof fn lemma_empty_rejected(max: Option<usize>)
    ensures
        !edk_count_valid(0, max),
{
}

/// With no configured maximum, any non-empty list is accepted.
pub proof fn lemma_no_max_accepts_nonempty(count: nat)
    requires
        count > 0,
    ensures
        edk_count_valid(count, None),
{
}

/// A count strictly above a configured maximum is rejected.
pub proof fn lemma_over_max_rejected(count: nat, m: usize)
    requires
        count > m as nat,
    ensures
        !edk_count_valid(count, Some(m)),
{
}

} // verus!

fn main() {}
