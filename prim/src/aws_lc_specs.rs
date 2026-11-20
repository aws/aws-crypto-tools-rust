// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

//! Trusted computing base (TCB) for the VR-013 / VR-014 in-crate proofs
//! (pipeline target VR-2026-C03).
//!
//! Verus cannot see into `aws-lc-rs`, so every `aws-lc-rs` type and call the
//! verified cores use is named here. Each item is tagged with its id from the
//! TCB list in `docs/verus-proofs-report.md`:
//!
//! - **naming**: introduces a symbol and claims nothing about `aws-lc-rs`
//!   beyond the Rust signature (an uninterpreted function or an opaque type).
//! - **TRUSTED**: a real assumption about `aws-lc-rs` 1.18.1, not proven.
//!
//! None of the specifications below has a `requires`, so every listed call is
//! trusted not to panic. Allocation failure / OOM is out of scope.
//!
//! The VR-008 items (`ExSignature`, `Signature::as_ref`,
//! `<[T]>::copy_from_slice`) stay in `ecdsa.rs` and are reused, not restated.

use vstd::prelude::*;

verus! {

// ---------------------------------------------------------------------------
// digest (VR-013(a), VR-013(b))
// ---------------------------------------------------------------------------

// T-ty (naming): opaque `aws_lc_rs::digest::Algorithm`.
#[verifier::external_type_specification]
#[verifier::external_body]
#[doc(hidden)]
#[allow(missing_debug_implementations, missing_docs, dead_code, unreachable_pub)]
pub struct ExDigestAlgorithm(aws_lc_rs::digest::Algorithm);

// T-ty (naming): opaque `aws_lc_rs::digest::Digest`.
#[verifier::external_type_specification]
#[verifier::external_body]
#[doc(hidden)]
#[allow(missing_debug_implementations, missing_docs, dead_code, unreachable_pub)]
pub struct ExDigest(aws_lc_rs::digest::Digest);

// T-ty (naming): opaque `aws_lc_rs::digest::Context`.
#[verifier::external_type_specification]
#[verifier::external_body]
#[doc(hidden)]
#[allow(missing_debug_implementations, missing_docs, dead_code, unreachable_pub)]
pub struct ExDigestContext(aws_lc_rs::digest::Context);

// T-uf (naming): the output length of a digest algorithm.
#[doc(hidden)]
#[allow(unreachable_pub)]
pub uninterp spec fn spec_digest_output_len(a: &aws_lc_rs::digest::Algorithm) -> nat;

// T-uf (naming): the length of a computed digest value.
#[doc(hidden)]
#[allow(unreachable_pub)]
pub uninterp spec fn spec_digest_len(d: &aws_lc_rs::digest::Digest) -> nat;

// T-uf (naming): the output length of the algorithm a digest context runs.
#[doc(hidden)]
#[allow(unreachable_pub)]
pub uninterp spec fn spec_context_output_len(c: &aws_lc_rs::digest::Context) -> nat;

// A1 (naming): `digest::Algorithm::output_len` returns the algorithm's
// output length.
pub assume_specification[ aws_lc_rs::digest::Algorithm::output_len ](
    a: &aws_lc_rs::digest::Algorithm,
) -> (n: usize)
    ensures
        n == spec_digest_output_len(a),
;

// A2 (TRUSTED length): `digest::digest` returns a digest of exactly the
// algorithm's output length (aws-lc-rs 1.18.1 `digest.rs:194-201`,
// `len: algorithm.output_len`). Also trusted not to panic.
pub assume_specification[ aws_lc_rs::digest::digest ](
    algorithm: &'static aws_lc_rs::digest::Algorithm,
    data: &[u8],
) -> (d: aws_lc_rs::digest::Digest)
    ensures
        spec_digest_len(&d) == spec_digest_output_len(algorithm),
;

// A3 (naming): the byte view of a digest is `spec_digest_len` bytes
// (`digest.rs:251-255`).
pub assume_specification[ <aws_lc_rs::digest::Digest as AsRef<[u8]>>::as_ref ](
    d: &aws_lc_rs::digest::Digest,
) -> (s: &[u8])
    ensures
        s@.len() == spec_digest_len(d),
;

// A4 (naming): a context's algorithm has the context's output length.
pub assume_specification[ aws_lc_rs::digest::Context::algorithm ](
    c: &aws_lc_rs::digest::Context,
) -> (r: &'static aws_lc_rs::digest::Algorithm)
    ensures
        spec_digest_output_len(r) == spec_context_output_len(c),
;

// A5 (TRUSTED length + TRUSTED no-panic): `Context::finish` returns a digest
// of the context's output length. aws-lc-rs documents "Panics if the digest
// is unable to be finalized" (`digest.rs:131-137`,
// `expect("EVP_DigestFinal failed")`); that panic is trusted unreachable.
pub assume_specification[ aws_lc_rs::digest::Context::finish ](
    c: aws_lc_rs::digest::Context,
) -> (d: aws_lc_rs::digest::Digest)
    ensures
        spec_digest_len(&d) == spec_context_output_len(&c),
;

// ---------------------------------------------------------------------------
// hmac (VR-013(f))
// ---------------------------------------------------------------------------

// T-ty (naming): opaque `aws_lc_rs::hmac::Algorithm`.
#[verifier::external_type_specification]
#[verifier::external_body]
#[doc(hidden)]
#[allow(missing_debug_implementations, missing_docs, dead_code, unreachable_pub)]
pub struct ExHmacAlgorithm(aws_lc_rs::hmac::Algorithm);

// T-ty (naming): opaque `aws_lc_rs::hmac::Key`.
#[verifier::external_type_specification]
#[verifier::external_body]
#[doc(hidden)]
#[allow(missing_debug_implementations, missing_docs, dead_code, unreachable_pub)]
pub struct ExHmacKey(aws_lc_rs::hmac::Key);

// T-ty (naming): opaque `aws_lc_rs::hmac::Tag`.
#[verifier::external_type_specification]
#[verifier::external_body]
#[doc(hidden)]
#[allow(missing_debug_implementations, missing_docs, dead_code, unreachable_pub)]
pub struct ExHmacTag(aws_lc_rs::hmac::Tag);

// T-uf (naming): the tag length of an HMAC algorithm.
#[doc(hidden)]
#[allow(unreachable_pub)]
pub uninterp spec fn spec_hmac_tag_len(a: aws_lc_rs::hmac::Algorithm) -> nat;

// T-uf (naming): the algorithm an HMAC key was built for.
#[doc(hidden)]
#[allow(unreachable_pub)]
pub uninterp spec fn spec_hmac_key_alg(k: &aws_lc_rs::hmac::Key) -> aws_lc_rs::hmac::Algorithm;

// T-uf (naming): the length of a computed HMAC tag.
#[doc(hidden)]
#[allow(unreachable_pub)]
pub uninterp spec fn spec_hmac_tag_bytes_len(t: &aws_lc_rs::hmac::Tag) -> nat;

// A6 (naming): `hmac::Algorithm::tag_len` returns the algorithm's tag length.
pub assume_specification[ aws_lc_rs::hmac::Algorithm::tag_len ](
    a: &aws_lc_rs::hmac::Algorithm,
) -> (n: usize)
    ensures
        n == spec_hmac_tag_len(*a),
;

// A7 (naming): a key built by `hmac::Key::new(alg, ..)` is for `alg`.
pub assume_specification[ aws_lc_rs::hmac::Key::new ](
    algorithm: aws_lc_rs::hmac::Algorithm,
    key_value: &[u8],
) -> (k: aws_lc_rs::hmac::Key)
    ensures
        spec_hmac_key_alg(&k) == algorithm,
;

// A8 (TRUSTED length): `hmac::sign` returns a tag of exactly the key
// algorithm's tag length. Also trusted not to panic.
pub assume_specification[ aws_lc_rs::hmac::sign ](
    key: &aws_lc_rs::hmac::Key,
    data: &[u8],
) -> (t: aws_lc_rs::hmac::Tag)
    ensures
        spec_hmac_tag_bytes_len(&t) == spec_hmac_tag_len(spec_hmac_key_alg(key)),
;

// A9 (naming): the byte view of an HMAC tag is `spec_hmac_tag_bytes_len`
// bytes (`hmac.rs:166-170`).
pub assume_specification[ <aws_lc_rs::hmac::Tag as AsRef<[u8]>>::as_ref ](
    t: &aws_lc_rs::hmac::Tag,
) -> (s: &[u8])
    ensures
        s@.len() == spec_hmac_tag_bytes_len(t),
;

// ---------------------------------------------------------------------------
// Shared error type for the kbkdf / rand / constant_time / aead calls
// ---------------------------------------------------------------------------

// T-ty (naming): opaque `aws_lc_rs::error::Unspecified`.
#[verifier::external_type_specification]
#[verifier::external_body]
#[doc(hidden)]
#[allow(missing_debug_implementations, missing_docs, dead_code, unreachable_pub)]
pub struct ExUnspecified(aws_lc_rs::error::Unspecified);

// ---------------------------------------------------------------------------
// kbkdf (VR-013(c))
// ---------------------------------------------------------------------------

// T-ty (naming): opaque `aws_lc_rs::kdf::KbkdfCtrHmacAlgorithm`.
#[verifier::external_type_specification]
#[verifier::external_body]
#[doc(hidden)]
#[allow(missing_debug_implementations, missing_docs, dead_code, unreachable_pub)]
pub struct ExKbkdfCtrHmacAlgorithm(aws_lc_rs::kdf::KbkdfCtrHmacAlgorithm);

// T-ty (naming): opaque `aws_lc_rs::kdf::KbkdfCtrHmacAlgorithmId`. Opaque
// rather than a modeled enum: it is `#[non_exhaustive]`, and the
// `DigestAlg -> id` match stays in the unverified adapter.
#[verifier::external_type_specification]
#[verifier::external_body]
#[doc(hidden)]
#[allow(missing_debug_implementations, missing_docs, dead_code, unreachable_pub)]
pub struct ExKbkdfCtrHmacAlgorithmId(aws_lc_rs::kdf::KbkdfCtrHmacAlgorithmId);

// T-uf (naming): whether the linked aws-lc-rs provides the KBKDF algorithm.
#[doc(hidden)]
#[allow(unreachable_pub)]
pub uninterp spec fn spec_kbkdf_available(id: aws_lc_rs::kdf::KbkdfCtrHmacAlgorithmId) -> bool;

// A10 (naming): the lookup returns `Some` exactly when the algorithm is
// available. No claim that it is always `Some` (finding F3: in aws-lc-rs
// 1.18.1 it is, `kdf/kbkdf.rs:38-49`).
pub assume_specification[ aws_lc_rs::kdf::get_kbkdf_ctr_hmac_algorithm ](
    id: aws_lc_rs::kdf::KbkdfCtrHmacAlgorithmId,
) -> (r: Option<&'static aws_lc_rs::kdf::KbkdfCtrHmacAlgorithm>)
    ensures
        (r is Some) <==> spec_kbkdf_available(id),
;

// A11 (Rust type fact): the derivation writes into `output` in place and
// cannot change its length. Nothing about the bytes written.
pub assume_specification[ aws_lc_rs::kdf::kbkdf_ctr_hmac ](
    algorithm: &'static aws_lc_rs::kdf::KbkdfCtrHmacAlgorithm,
    secret: &[u8],
    info: &[u8],
    output: &mut [u8],
) -> (r: Result<(), aws_lc_rs::error::Unspecified>)
    ensures
        final(output)@.len() == old(output)@.len(),
;

// ---------------------------------------------------------------------------
// rand / constant_time (VR-013(d), VR-013(e))
// ---------------------------------------------------------------------------

// A12 (Rust type fact): `rand::fill` writes `dest` in place and cannot
// change its length. Nothing about the bytes written.
pub assume_specification[ aws_lc_rs::rand::fill ](dest: &mut [u8]) -> (r: Result<
    (),
    aws_lc_rs::error::Unspecified,
>)
    ensures
        final(dest)@.len() == old(dest)@.len(),
;

// T-uf (naming): the outcome of aws-lc-rs's slice comparison on two byte
// sequences. Deliberately uninterpreted: no claim that it means equality.
#[doc(hidden)]
#[allow(unreachable_pub)]
pub uninterp spec fn spec_slices_equal_ok(a: Seq<u8>, b: Seq<u8>) -> bool;

// A13 (TRUSTED determinism only): the comparison result is a function of
// the two byte sequences. No claim that `Ok` means equal, and nothing about
// timing.
pub assume_specification[ aws_lc_rs::constant_time::verify_slices_are_equal ](
    a: &[u8],
    b: &[u8],
) -> (r: Result<(), aws_lc_rs::error::Unspecified>)
    ensures
        (r is Ok) == spec_slices_equal_ok(a@, b@),
;

// ---------------------------------------------------------------------------
// AES-GCM (VR-014)
// ---------------------------------------------------------------------------

// T-ty (naming): opaque `aws_lc_rs::aead::Algorithm`.
#[verifier::external_type_specification]
#[verifier::external_body]
#[doc(hidden)]
#[allow(missing_debug_implementations, missing_docs, dead_code, unreachable_pub)]
pub struct ExAeadAlgorithm(aws_lc_rs::aead::Algorithm);

// T-ty (naming): opaque `aws_lc_rs::aead::UnboundKey`.
#[verifier::external_type_specification]
#[verifier::external_body]
#[doc(hidden)]
#[allow(missing_debug_implementations, missing_docs, dead_code, unreachable_pub)]
pub struct ExUnboundKey(aws_lc_rs::aead::UnboundKey);

// T-ty (naming): opaque `aws_lc_rs::aead::Nonce`.
#[verifier::external_type_specification]
#[verifier::external_body]
#[doc(hidden)]
#[allow(missing_debug_implementations, missing_docs, dead_code, unreachable_pub)]
pub struct ExNonce(aws_lc_rs::aead::Nonce);

// T-ty (naming): opaque `aws_lc_rs::aead::LessSafeKey`.
#[verifier::external_type_specification]
#[verifier::external_body]
#[doc(hidden)]
#[allow(missing_debug_implementations, missing_docs, dead_code, unreachable_pub)]
pub struct ExLessSafeKey(aws_lc_rs::aead::LessSafeKey);

// T-AsRef (naming, TCB): declares `core::convert::AsRef` to Verus. Why it
// exists: Verus cannot name `aws_lc_rs::aead::Aad<A: AsRef<[u8]>>` (needed
// for A17, A18, A20) unless the bound's trait is declared; without it Verus
// reports "cannot find trait `T34_AsRef`". Only the trait signature is
// declared; no method gets a specification. The proxy's `PointeeSized`
// bounds are unstable (`sized_hierarchy`), so, mirroring how vstd gates its
// `std_specs` module, it is compiled only under `verus_keep_ghost` (set by
// cargo-verus). It is ghost-only: no exec code is gated by this cfg.
#[cfg(verus_keep_ghost)]
#[verifier::external_trait_specification]
#[doc(hidden)]
#[allow(missing_docs, unreachable_pub)]
pub trait ExAsRef<T: core::marker::PointeeSized>: core::marker::PointeeSized {
    type ExternalTraitSpecificationFor: AsRef<T>;

    fn as_ref(&self) -> &T;
}

// T-ty (naming): opaque `aws_lc_rs::aead::Aad<A>`, the AAD wrapper the seal
// and open take. Needs the T-AsRef proxy above for its `A: AsRef<[u8]>`
// bound; like `ExSignature` it is erased by `verus!` in the cargo build.
#[verifier::external_type_specification]
#[verifier::external_body]
#[verifier::reject_recursive_types(A)]
#[doc(hidden)]
#[allow(missing_debug_implementations, missing_docs, dead_code, unreachable_pub)]
pub struct ExAad<A: AsRef<[u8]>>(aws_lc_rs::aead::Aad<A>);

// T-ty (naming): opaque `aws_lc_rs::aead::Tag`.
#[verifier::external_type_specification]
#[verifier::external_body]
#[doc(hidden)]
#[allow(missing_debug_implementations, missing_docs, dead_code, unreachable_pub)]
pub struct ExAeadTag(aws_lc_rs::aead::Tag);

// A14 (no-panic only): `UnboundKey::new`.
pub assume_specification[ aws_lc_rs::aead::UnboundKey::new ](
    algorithm: &'static aws_lc_rs::aead::Algorithm,
    key_bytes: &[u8],
) -> Result<aws_lc_rs::aead::UnboundKey, aws_lc_rs::error::Unspecified>;

// A15 (no-panic only): `Nonce::try_assume_unique_for_key`.
pub assume_specification[ aws_lc_rs::aead::Nonce::try_assume_unique_for_key ](
    value: &[u8],
) -> Result<aws_lc_rs::aead::Nonce, aws_lc_rs::error::Unspecified>;

// A16 (no-panic only): `LessSafeKey::new`.
pub assume_specification[ aws_lc_rs::aead::LessSafeKey::new ](
    key: aws_lc_rs::aead::UnboundKey,
) -> aws_lc_rs::aead::LessSafeKey;

// A17 (no-panic only): `Aad::<A>::from`.
pub assume_specification<A: AsRef<[u8]>>[ aws_lc_rs::aead::Aad::<A>::from ](
    aad: A,
) -> aws_lc_rs::aead::Aad<A>;

// A18 (Rust type fact): the seal encrypts `in_out` in place and cannot change
// its length. Nothing about the bytes written.
pub assume_specification<A: AsRef<[u8]>>[ aws_lc_rs::aead::LessSafeKey::seal_in_place_separate_tag::<A> ](
    key: &aws_lc_rs::aead::LessSafeKey,
    nonce: aws_lc_rs::aead::Nonce,
    aad: aws_lc_rs::aead::Aad<A>,
    in_out: &mut [u8],
) -> (r: Result<aws_lc_rs::aead::Tag, aws_lc_rs::error::Unspecified>)
    ensures
        final(in_out)@.len() == old(in_out)@.len(),
;

// A19 (TRUSTED length, AEAD-TAG-16): an AES-GCM tag is 16 bytes
// (aws-lc-rs 1.18.1 `aead.rs:1069-1074`). prim only uses AES-GCM algorithms.
pub assume_specification[ <aws_lc_rs::aead::Tag as AsRef<[u8]>>::as_ref ](
    t: &aws_lc_rs::aead::Tag,
) -> (s: &[u8])
    ensures
        s@.len() == 16,
;

// A20 (LABELED ASSUMPTION A-OPEN, not proven): aws-lc-rs 1.18.1 documents
// "The `out_plaintext` length must match the provided `in_ciphertext`"
// (`aead.rs:~806`), and `unbound_key.rs:136-139` returns `Err` when
// `in_ciphertext.len() != out_plaintext.len()`. Modeled as: `Ok` implies the
// two lengths are equal. The length of `out_plaintext` cannot change (Rust
// type fact). Nothing about the bytes written.
pub assume_specification<A: AsRef<[u8]>>[ aws_lc_rs::aead::LessSafeKey::open_separate_gather::<A> ](
    key: &aws_lc_rs::aead::LessSafeKey,
    nonce: aws_lc_rs::aead::Nonce,
    aad: aws_lc_rs::aead::Aad<A>,
    in_ciphertext: &[u8],
    in_tag: &[u8],
    out_plaintext: &mut [u8],
) -> (r: Result<(), aws_lc_rs::error::Unspecified>)
    ensures
        (r is Ok) ==> in_ciphertext@.len() == old(out_plaintext)@.len(),
        final(out_plaintext)@.len() == old(out_plaintext)@.len(),
;

} // verus!
