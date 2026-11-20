// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

//! Proof token for the encrypt signing step (VR-019, the encrypt-side
//! counterpart of VR-015 (b)).
//!
//! When the algorithm suite has a signature algorithm, encrypt must sign the
//! message with the signing key from the encryption materials. The signing
//! step in `encrypt.rs` (`step_construct_signature`) rejects a signing suite
//! whose materials have no signing key. This module holds that check and a
//! token that records it:
//!
//! - [`SigningKeyPresent`]: the suite has a signature algorithm and the
//!   materials have a signing key. It holds the key bytes, and the signing
//!   call reads the key only through [`signing_key`], which needs the token.
//!
//! What is proven and what is trusted:
//! - Verus proves that [`signing_key_gate`] returns a token exactly when the
//!   suite signs and a signing key is present, that every token is for a
//!   signing suite, and that [`signing_key`] returns exactly the key the
//!   token was made from.
//! - The Rust compiler enforces that no code outside this module can build a
//!   token (its fields are private), and that [`signing_key`] cannot be
//!   called without one.
//! - Trusted, not proven: the caller passes the real "suite signs" flag and
//!   the real signing key from the materials; `step_construct_signature`
//!   signs only with the key from [`signing_key`]; `encrypt_steps` runs the
//!   signing step for every signing suite and writes the footer.
//! - Not checked here (one direction only): esdk does not reject a
//!   non-signing suite whose materials have a signing key, and it rejects a
//!   signing suite without a key only in the signing step, after the header
//!   and body are written. Both the reverse direction and early rejection
//!   rely on the MPL (`GetEncryptionMaterials::send` /
//!   `check_encryption_materials` and `EncryptionMaterialsBuilder::build`),
//!   which is trusted code reading.
//!
//! The token is neither `Clone` nor `Copy`.

use vstd::prelude::*;

verus! {

/// Proof that the algorithm suite has a signature algorithm and the
/// encryption materials have a signing key. It holds the key bytes. Only
/// this module can create one, and only through `signing_key_gate`.
pub(crate) struct SigningKeyPresent<'a> {
    key: &'a [u8],
    #[allow(dead_code, reason = "ghost field: read only by specs")]
    suite_signs: Ghost<bool>,
}

#[allow(
    single_use_lifetimes,
    clippy::elidable_lifetime_names,
    reason = "Verus needs the named lifetime to match the struct for the type invariant"
)]
impl<'a> SigningKeyPresent<'a> {
    /// Whether the algorithm suite has a signature algorithm.
    pub(crate) closed spec fn signs(&self) -> bool {
        self.suite_signs@
    }

    /// The signing key bytes from the encryption materials.
    pub(crate) closed spec fn key(&self) -> Seq<u8> {
        self.key@
    }

    /// Every token is for a signing suite.
    #[verifier::type_invariant]
    spec fn inv(&self) -> bool {
        self.signs()
    }
}

/// Every `SigningKeyPresent` is for a signing suite.
pub(crate) proof fn lemma_signing_key_present(tracked t: &SigningKeyPresent<'_>)
    ensures
        t.signs(),
{
    use_type_invariant(t);
}

/// The signing-key check: returns a token holding the signing key only when
/// the suite has a signature algorithm and a signing key is present. When
/// either is missing it returns `None`, and the caller reports
/// `InvalidMaterials`.
pub(crate) fn signing_key_gate(suite_signs: bool, signing_key: Option<&[u8]>) -> (r: Option<
    SigningKeyPresent<'_>,
>)
    ensures
        (r is Some) <==> (suite_signs && signing_key is Some),
        r matches Some(t) ==> (t.signs() && (signing_key matches Some(k) && t.key() == k@)),
{
    if !suite_signs {
        return None;
    }
    let key = signing_key?;
    Some(SigningKeyPresent { key, suite_signs: Ghost(true) })
}

/// Gives back the signing key held by the token. Returns exactly the key the
/// token was made from.
pub(crate) fn signing_key<'a>(present: &SigningKeyPresent<'a>) -> (r: &'a [u8])
    ensures
        r@ == present.key(),
{
    present.key
}

} // verus!

#[cfg(test)]
mod tests {
    use super::*;

    // Defense-in-depth test of esdk's own fallback check: the MPL rejects a
    // signing suite with no signing key before the public API hands the
    // materials to esdk, and the only caller passes `suite_signs == true`.
    #[test]
    fn signing_key_gate_cases() {
        assert!(signing_key_gate(false, Some(b"k")).is_none());
        assert!(signing_key_gate(true, None).is_none());
        let Some(t) = signing_key_gate(true, Some(b"k")) else {
            panic!("a signing suite with a signing key must yield a token");
        };
        assert_eq!(signing_key(&t), b"k");
    }
}
