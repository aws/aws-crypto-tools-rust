// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
//! Verus proof for the panic-free buffer bookkeeping in AES-GCM
//! encrypt/decrypt (VR-006 — the provable, non-FFI part).
//!
//! Models the buffer/bounds logic of `aes_encrypt` / `aes_decrypt` in
//! `prim/src/lib.rs`. See `verification/README.md` for why the proofs live
//! outside the `prim` crate.
//!
//! Pipeline: `.kiro/agents/ai-verification-pipeline.md`
//! Target:   `docs/verification-recommendations.md` VR-006 (AES-GCM panic
//!           freedom — the buffer slicing / length-guard portion).
//! Threats:  D1 (crafted input causing a crash during crypto).
//! Spec:     spec/framework/algorithm-suites.md (IV/tag/key lengths).
//!
//! # Scope and honesty note (READ THIS FIRST)
//!
//! `aes_encrypt`/`aes_decrypt` are THIN WRAPPERS over `aws-lc-rs`
//! (`UnboundKey::new`, `Nonce::try_assume_unique_for_key`,
//! `seal_in_place_separate_tag`, `open_separate_gather`). Those are FFI calls
//! Verus cannot model, and they do the actual cryptography. So VR-006 cannot be
//! "AES-GCM is proven correct" — it can only be **the panic-freedom of the Rust
//! buffer bookkeeping around the FFI calls**, which is exactly what this file
//! proves and nothing more:
//!
//!   * `aes_encrypt`: after `cipher_text.extend_from_slice(message)`, the slice
//!     `&mut cipher_text[old_size..]` is ALWAYS in bounds (no panic), because
//!     `old_size <= cipher_text.len()` after the extend. The length bookkeeping
//!     (`old_size`, the tag append) is tracked exactly.
//!   * `aes_decrypt`: the explicit guard `if plain_text.len() < cipher_text.len()
//!     { return err(...) }` establishes `plain_text.len() >= cipher_text.len()`
//!     on the path that proceeds — the output-buffer precondition the aws-lc-rs
//!     gather needs, proven to hold (no under-sized output buffer reaches FFI).
//!
//! What is NOT proven here (delegated to aws-lc-rs, out of Verus scope): the
//! encryption/decryption itself, tag generation/verification, and the internal
//! memory safety of the FFI. Nothing uses `assume`/`external_body`/`admit`.

use vstd::prelude::*;

verus! {

// ==================================================================
// SECTION 1: aes_encrypt — ciphertext slice is always in bounds
// ==================================================================

/// Faithful model of the buffer bookkeeping in `aes_encrypt`:
/// ```ignore
/// let old_size = cipher_text.len();
/// cipher_text.extend_from_slice(message);
/// let cipher_slice = &mut cipher_text[old_size..];   // <-- must not panic
/// // ... seal_in_place_separate_tag(cipher_slice) ...  (FFI, elided)
/// cipher_text.extend_from_slice(tag);
/// ```
///
/// We prove the `&mut cipher_text[old_size..]` slice is in bounds for ALL
/// inputs (it can never panic), and track the exact length effects: after the
/// message extend the buffer grew by `message.len()`, and the slice covers
/// exactly the freshly-appended message region. `tag` models the FFI-produced
/// authentication tag appended afterward.
pub fn aes_encrypt_buffer_bookkeeping(
    cipher_text: &mut Vec<u8>,
    message: &[u8],
    tag: &[u8],
)
    ensures
        // Final length = original + message + tag (no bytes lost or duplicated).
        final(cipher_text)@.len()
            == old(cipher_text)@.len() + message@.len() + tag@.len(),
        // The original prefix is preserved.
        final(cipher_text)@.subrange(0, old(cipher_text)@.len() as int)
            == old(cipher_text)@,
{
    let old_size = cipher_text.len();
    cipher_text.extend_from_slice(message);

    // The slice `&cipher_text[old_size..]` is in bounds: old_size <= len after
    // the extend. Verus discharges this because extend_from_slice's postcondition
    // gives cipher_text.len() == old_size + message.len() >= old_size. Taking the
    // slice (read form; the real code takes &mut for the in-place seal) witnesses
    // the bound without panicking.
    proof {
        assert(old_size <= cipher_text@.len());
    }
    let ghost cipher_slice = cipher_text@.subrange(old_size as int, cipher_text.len() as int);
    assert(cipher_slice.len() == message@.len());

    // seal_in_place_separate_tag(nonce, aad, &mut cipher_text[old_size..]) here —
    // aws-lc-rs FFI, elided; it encrypts in place and returns the tag `tag`.

    cipher_text.extend_from_slice(tag);
}

// ==================================================================
// SECTION 2: aes_decrypt — the output-buffer length guard
// ==================================================================

/// Faithful model of the length guard in `aes_decrypt`:
/// ```ignore
/// if plain_text.len() < cipher_text.len() {
///     return err(...);                 // reject under-sized output buffer
/// }
/// // ... open_separate_gather(cipher_text, auth_tag, plain_text) ...  (FFI)
/// ```
///
/// We prove the guard establishes `plain_text_len >= cipher_text_len` on the
/// path that proceeds to the FFI gather — i.e. an under-sized output buffer is
/// ALWAYS rejected (returns `Err`) before it reaches aws-lc-rs, so the gather
/// never overruns the plaintext buffer. Total (no panic); returns whether the
/// call may proceed to decryption.
pub fn aes_decrypt_length_guard(plain_text_len: usize, cipher_text_len: usize) -> (proceed: bool)
    ensures
        // Proceeds exactly when the output buffer is large enough.
        proceed <==> (plain_text_len >= cipher_text_len),
        // On the proceed path, the aws-lc-rs precondition holds.
        proceed ==> (plain_text_len >= cipher_text_len),
{
    if plain_text_len < cipher_text_len {
        false  // models `return err(...)` — under-sized buffer rejected
    } else {
        true   // safe to call open_separate_gather (FFI)
    }
}

// ==================================================================
// SECTION 3: Boundary lemmas
// ==================================================================

/// An under-sized output buffer is always rejected — no path reaches the FFI
/// gather with `plain_text` shorter than `cipher_text`.
pub proof fn lemma_undersized_output_rejected(plain_text_len: usize, cipher_text_len: usize)
    requires
        plain_text_len < cipher_text_len,
    ensures
        !(plain_text_len >= cipher_text_len),
{
}

} // verus!

fn main() {}
