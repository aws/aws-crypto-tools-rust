// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
//! Verus proof for the secret-key zeroization loop.
//!
//! Models `PlaintextDataKey::zeroize` from
//! `mpl/src/structures/algorithm_suite.rs`. See `verification/README.md` for
//! why the proofs live outside the `esdk`/`mpl` crates.
//!
//! Pipeline: `.kiro/agents/ai-verification-pipeline.md`
//! Target:   `docs/verification-recommendations.md` VR-010 (zeroization).
//! Threats:  I1 (plaintext data key leaked from memory),
//!           I5 (key material persists after use).
//! Spec:     spec/framework/structures.md (Plaintext Data Key — zero after use).
//!
//! # Scope and honesty note (READ THIS)
//!
//! The original `zeroize` writes each byte through a raw pointer with
//! `core::ptr::write_volatile(ptr.add(i), 0)` inside an `unsafe` block. The
//! `volatile` write exists to stop the compiler eliminating the "dead" stores
//! (the Vec is about to be dropped), which is an *operational* guarantee about
//! codegen — NOT a functional or memory-safety property, and not something
//! Verus reasons about.
//!
//! Verus's raw-pointer model (`vstd::raw_ptr`) requires explicit `PointsTo<T>`
//! permission tokens that a normally-constructed `Vec<u8>` does not expose, so
//! faithfully verifying the `unsafe { write_volatile(ptr.add(i), 0) }` form is
//! not tractable here without reconstructing the whole allocation-permission
//! story. Rather than fake that with `assume`/`external_body` (forbidden by the
//! Verus skill invariants), this file proves the *computational* content of the
//! loop — what it writes and that every access is in bounds — via the
//! equivalent SAFE indexed-write form over the same `Vec<u8>`:
//!
//!   for i in 0..len { v[i] = 0; }   ==   for i in 0..len { write_volatile(ptr.add(i), 0); }
//!
//! The two loops write byte-for-byte identical results to the same buffer; they
//! differ only in whether the store is volatile. What remains argued informally
//! (not machine-checked) is exactly that one-line equivalence: the raw index
//! `ptr.add(i)` for `i in 0..len` is in bounds because `len == self.0.len()`,
//! which is the loop bound. See the accompanying README entry.

use vstd::prelude::*;

verus! {

// ------------------------------------------------------------------
// SECTION 1: Specification — "fully zeroed"
// ------------------------------------------------------------------

/// A buffer is fully zeroed when every byte is 0. This is the security
/// postcondition: no key material remains.
pub open spec fn all_zero(s: Seq<u8>) -> bool {
    forall|i: int| 0 <= i < s.len() ==> s[i] == 0u8
}

// ------------------------------------------------------------------
// SECTION 2: Safe indexed-write model of the zeroization loop + proof
// ------------------------------------------------------------------

/// Faithful model of the *computation* performed by
/// `PlaintextDataKey::zeroize`, using safe indexed writes over the same
/// `Vec<u8>`.
///
/// Original:
/// ```ignore
/// pub fn zeroize(&mut self) {
///     let ptr = self.0.as_mut_ptr();
///     let len = self.0.len();
///     for i in 0..len {
///         unsafe { core::ptr::write_volatile(ptr.add(i), 0u8); }
///     }
/// }
/// ```
///
/// We prove:
///   * No panic: every write index is in bounds for all iterations (the loop
///     invariant carries `idx <= len == v.len()`), and the length never
///     changes.
///   * Functional / security correctness: on return the buffer is fully zeroed
///     (`all_zero`), so no key bytes survive.
pub fn zeroize(v: &mut Vec<u8>)
    ensures
        final(v)@.len() == old(v)@.len(),
        all_zero(final(v)@),
{
    let len = v.len();
    let mut idx: usize = 0;
    while idx < len
        invariant
            len == v.len(),
            idx <= len,
            // Everything written so far is zero.
            forall|j: int| 0 <= j < idx ==> v@[j] == 0u8,
        decreases len - idx,
    {
        v[idx] = 0u8;
        idx += 1;
    }
}

// ------------------------------------------------------------------
// SECTION 3: Boundary lemmas
// ------------------------------------------------------------------

/// Zeroizing an empty buffer is vacuously fully-zeroed (no bytes, no panic).
pub proof fn lemma_empty_is_zeroed()
    ensures
        all_zero(Seq::<u8>::empty()),
{
}

/// `all_zero` is exactly "no non-zero byte remains" — i.e. there is no index
/// holding key material. Stated so downstream reasoning can use either form.
pub proof fn lemma_all_zero_iff_no_nonzero(s: Seq<u8>)
    ensures
        all_zero(s) <==> (forall|i: int| 0 <= i < s.len() ==> s[i] == 0u8),
{
}

} // verus!

fn main() {}
