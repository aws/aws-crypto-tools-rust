// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
//! Verus proof for the frame serialization layout in `construct_frame`.
//!
//! Models the `frame_buf` serialization performed by `construct_frame` in
//! `esdk/src/message/body/body_encrypt.rs`. See `verification/README.md` for
//! why the proofs live outside the `esdk` crate.
//!
//! Pipeline: `.kiro/agents/ai-verification-pipeline.md`
//! Target:   `docs/verification-recommendations.md` VR-005 (frame construction
//!           / body serialization), completing the earlier partial coverage
//!           (`iv_seq` + `body_aad` in `body_aad_proofs.rs`).
//! Threats:  T2 (frame reordering — sequence number field), T3 (cross-message
//!           splicing — bound via AAD, proved in body_aad_proofs.rs), D2
//!           (framing bounds / no panic during serialization).
//! Spec:     spec/data-format/message-body.md#regular-frame and #final-frame;
//!           spec/client-apis/encrypt.md#construct-a-frame.
//!
//! # The "Verus-buildable seam" (READ THIS)
//!
//! `construct_frame`'s real body is a sequence of `write_u32` / `write_bytes`
//! calls into a `frame_buf: &mut Vec<u8>` **and** a `dyn SafeWrite`
//! (`std::io::Write`) trait object, plus one `aes_encrypt` call (an `aws-lc-rs`
//! FFI). Verus cannot model `dyn SafeWrite`/`std::io::Write` or the FFI, so the
//! function cannot be verified as-written.
//!
//! The seam this file verifies is the part `construct_frame` actually controls:
//! **the byte layout it assembles into `frame_buf`** before that buffer is
//! released to the writer. Concretely:
//!   * `write_u32(frame_buf, x)` — a `Vec` extend of `x.to_be_bytes()`; modeled
//!     by `write_u32` here (same 4 big-endian bytes).
//!   * `write_bytes(frame_buf, iv)` — a `Vec` extend of `iv`; modeled by
//!     `write_bytes` here.
//!   * `aes_encrypt(..., frame_buf)` — appends `ciphertext ‖ tag`. By its
//!     documented contract (see `prim/src/lib.rs::aes_encrypt` and
//!     `body_aad_proofs`) the AES-GCM ciphertext is exactly `plaintext.len()`
//!     bytes and the tag is `tag_len` bytes. Verus cannot see the *values*
//!     (they come from the FFI), so we model only its **length effect**: it
//!     appends `plaintext_len + tag_len` unconstrained bytes. This is the
//!     honest boundary — we prove the frame *structure and field sizes*, not
//!     the ciphertext contents.
//!
//! What is proven: the serialized frame prefix has exactly the fields the spec
//! requires, in order, with the right sizes, for both regular and final frames,
//! and the serialization never panics. What is NOT proven here: the trait-object
//! release (`write_bytes(ciphertext, frame_buf)` / `sig_digest`) and the
//! ciphertext byte values (FFI). Those are documented as out of Verus scope.

use vstd::prelude::*;

verus! {

// ------------------------------------------------------------------
// SECTION 1: Big-endian spec (shared shape with body_aad_proofs.rs)
// ------------------------------------------------------------------

pub open spec fn spec_u32_be(x: u32) -> Seq<u8> {
    seq![
        ((x >> 24) & 0xff) as u8,
        ((x >> 16) & 0xff) as u8,
        ((x >> 8) & 0xff) as u8,
        (x & 0xff) as u8,
    ]
}

/// Sequence-number-end sentinel for a final frame: `FF FF FF FF`.
/// Mirrors `ENDFRAME_SEQUENCE_NUMBER` in `esdk/src/message/header.rs`.
pub open spec fn endframe_sentinel() -> u32 { 0xFFFF_FFFFu32 }

// ------------------------------------------------------------------
// SECTION 2: Verified serialization primitives (frame_buf = Vec<u8>)
// ------------------------------------------------------------------

/// Model of `write_u32(frame_buf, x)` when the writer is the `frame_buf`
/// `Vec<u8>`: appends the 4 big-endian bytes. (`serialize_functions::write_u32`
/// calls `write_bytes(w, &x.to_be_bytes())`.)
pub fn write_u32(buf: &mut Vec<u8>, x: u32)
    ensures
        final(buf)@ == old(buf)@ + spec_u32_be(x),
        final(buf)@.len() == old(buf)@.len() + 4,
{
    buf.push(((x >> 24) & 0xff) as u8);
    buf.push(((x >> 16) & 0xff) as u8);
    buf.push(((x >> 8) & 0xff) as u8);
    buf.push((x & 0xff) as u8);
}

/// Model of `write_bytes(frame_buf, data)` when the writer is `frame_buf`:
/// appends `data`. (`serialize_functions::write_bytes` calls `w.write_all`.)
pub fn write_bytes(buf: &mut Vec<u8>, data: &[u8])
    ensures
        final(buf)@ == old(buf)@ + data@,
        final(buf)@.len() == old(buf)@.len() + data@.len(),
{
    buf.extend_from_slice(data);
}

/// Model of the effect of `aes_encrypt(..., frame_buf)`: it appends the
/// AES-GCM output `ciphertext ‖ tag`. The concrete bytes come from the
/// `aws-lc-rs` FFI, which Verus cannot model, so the caller supplies them as a
/// real `cipher_and_tag: &[u8]` argument; the AES-GCM length contract
/// (`ciphertext.len() == plaintext.len()`, fixed `tag_len`) is expressed as the
/// `requires` on its length. This appends exactly those bytes — no
/// `external_body`, no ghost materialization.
pub fn aes_encrypt_append(buf: &mut Vec<u8>, plaintext: &[u8], tag_len: usize, cipher_and_tag: &[u8])
    requires
        cipher_and_tag@.len() == plaintext@.len() + tag_len,
    ensures
        final(buf)@ == old(buf)@ + cipher_and_tag@,
        final(buf)@.len() == old(buf)@.len() + plaintext@.len() + tag_len,
{
    buf.extend_from_slice(cipher_and_tag);
}

// ------------------------------------------------------------------
// SECTION 3: Frame layout spec + proof
// ------------------------------------------------------------------

/// The serialized frame layout, per the message-body spec, as a function of
/// its fields. `is_final` selects the final-frame shape (adds the
/// sequence-number-end sentinel prefix and the encrypted-content-length field).
///
///   regular: seq(4) ‖ iv ‖ ciphertext‖tag
///   final:   FFFFFFFF(4) ‖ seq(4) ‖ iv ‖ enc_content_len(4) ‖ ciphertext‖tag
pub open spec fn frame_layout(
    is_final: bool,
    seq: u32,
    iv: Seq<u8>,
    enc_content_len: u32,
    cipher_and_tag: Seq<u8>,
) -> Seq<u8> {
    if is_final {
        spec_u32_be(endframe_sentinel())
            + spec_u32_be(seq)
            + iv
            + spec_u32_be(enc_content_len)
            + cipher_and_tag
    } else {
        spec_u32_be(seq) + iv + cipher_and_tag
    }
}

/// Faithful model of the `frame_buf` assembly in `construct_frame`
/// (`body_encrypt.rs`), covering the field-serialization sequence:
/// ```ignore
/// frame_buf.clear();
/// // (AAD + iv_seq happen on separate buffers — see body_aad_proofs.rs)
/// if is_final { write_u32(frame_buf, ENDFRAME_SEQUENCE_NUMBER); }
/// write_u32(frame_buf, sequence_number);
/// write_bytes(frame_buf, iv);
/// if is_final { write_u32(frame_buf, enc_content_len); }
/// aes_encrypt(alg, iv, key, plaintext, aad, frame_buf); // appends ct ‖ tag
/// ```
///
/// We prove the assembled buffer equals `frame_layout(...)` exactly — correct
/// fields, correct order, correct sizes — and that the assembly never panics.
/// `iv.len()` and `tag_len` are the algorithm-suite IV/tag lengths (12 / 16 for
/// ESDK suites); we require them only to be consistent with `cipher_and_tag`.
pub fn build_frame_buf(
    frame_buf: &mut Vec<u8>,
    is_final: bool,
    sequence_number: u32,
    iv: &[u8],
    enc_content_len: u32,
    plaintext: &[u8],
    tag_len: usize,
    cipher_and_tag: &[u8],
)
    requires
        cipher_and_tag@.len() == plaintext@.len() + tag_len,
    ensures
        final(frame_buf)@ == frame_layout(
            is_final,
            sequence_number,
            iv@,
            enc_content_len,
            cipher_and_tag@,
        ),
{
    frame_buf.clear();

    if is_final {
        //= spec/data-format/message-body.md#sequence-number-end
        //# The value MUST be encoded as the 4 bytes `FF FF FF FF`.
        write_u32(frame_buf, 0xFFFF_FFFFu32);
    }

    // Sequence Number
    write_u32(frame_buf, sequence_number);

    // IV
    write_bytes(frame_buf, iv);

    if is_final {
        // Encrypted Content Length
        write_u32(frame_buf, enc_content_len);
    }

    // Encrypted Content ‖ Authentication Tag (from aes_encrypt / aws-lc-rs).
    aes_encrypt_append(frame_buf, plaintext, tag_len, cipher_and_tag);
}

// ------------------------------------------------------------------
// SECTION 4: Layout lemmas (field sizes / ordering)
// ------------------------------------------------------------------

/// A regular frame's serialized length is `4 (seq) + iv + ciphertext + tag`.
pub proof fn lemma_regular_frame_len(seq: u32, iv: Seq<u8>, ct: Seq<u8>)
    ensures
        frame_layout(false, seq, iv, 0, ct).len() == 4 + iv.len() + ct.len(),
{
}

/// A final frame's serialized length adds the 4-byte sentinel and the 4-byte
/// encrypted-content-length field: `4 + 4 (seq) + iv + 4 + ciphertext + tag`.
pub proof fn lemma_final_frame_len(seq: u32, iv: Seq<u8>, ecl: u32, ct: Seq<u8>)
    ensures
        frame_layout(true, seq, iv, ecl, ct).len() == 12 + iv.len() + ct.len(),
{
}

/// The first 4 bytes of a final frame are the `FF FF FF FF` sentinel, so a
/// final frame is distinguishable on the wire from a regular frame whose
/// sequence number is not the sentinel (this is what stops a decryptor from
/// mistaking one for the other — relevant to T2 frame-reordering defenses).
pub proof fn lemma_final_frame_starts_with_sentinel(seq: u32, iv: Seq<u8>, ecl: u32, ct: Seq<u8>)
    ensures
        frame_layout(true, seq, iv, ecl, ct).subrange(0, 4) == spec_u32_be(0xFFFF_FFFFu32),
{
    assert(frame_layout(true, seq, iv, ecl, ct).subrange(0, 4) =~= spec_u32_be(0xFFFF_FFFFu32));
}

} // verus!

fn main() {}
