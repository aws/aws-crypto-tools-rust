// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

#![doc = include_str!("../README.md")]
#![cfg_attr(docsrs, feature(doc_cfg))]
// Verus builds only (cargo-verus sets `verus_keep_ghost`): the ghost-only
// `AsRef` trait proxy in `aws_lc_specs` needs `PointeeSized`, which Verus must
// see so it can name `aws_lc_rs::aead::Aad<A: AsRef<[u8]>>`. Mirrors how vstd
// gates its std specs. Stable `cargo build` never enables this feature.
#![cfg_attr(verus_keep_ghost, feature(sized_hierarchy))]
#![warn(
    absolute_paths_not_starting_with_crate,
    deprecated_in_future,
    explicit_outlives_requirements,
    keyword_idents,
    impl_trait_redundant_captures,
    keyword_idents_2024,
    let_underscore_drop,
    macro_use_extern_crate,
    missing_debug_implementations,
    missing_copy_implementations,
    missing_docs,
    non_ascii_idents,
    // non_exhaustive_omitted_patterns, unstable
    noop_method_call,
    redundant_imports,
    redundant_lifetimes,
    rust_2021_incompatible_closure_captures,
    rust_2021_incompatible_or_patterns,
    rust_2021_prefixes_incompatible_syntax,
    rust_2021_prelude_collisions,
    rust_2018_idioms,
    single_use_lifetimes,
    trivial_numeric_casts,
    trivial_casts,
    unit_bindings,
    unreachable_pub,
    unsafe_op_in_unsafe_fn,
    unused_crate_dependencies,
    unused_extern_crates,
    unused_lifetimes,
    unused_qualifications,

    clippy::style,
    clippy::pedantic,
    clippy::nursery,
    clippy::cargo,

    // clippy::restriction,
    clippy::create_dir,
    clippy::exhaustive_enums,
    clippy::exhaustive_structs,
    clippy::little_endian_bytes,
    clippy::missing_asserts_for_indexing,
    clippy::mixed_read_write_in_expression,
    clippy::panic,
    clippy::partial_pub_fields,
    clippy::redundant_type_annotations,
    clippy::renamed_function_params,
    clippy::rest_pat_in_fully_bound_structs,
    clippy::same_name_method,
    clippy::string_add,
    clippy::string_lit_chars_any,
    clippy::tests_outside_test_module,
)]
#![allow(clippy::missing_const_for_fn)] // a public const fn can't drop const later without breaking callers

pub mod error;

mod aws_lc_specs;
mod ecdsa;
pub use ecdsa::*;
mod hkdf;
pub use hkdf::*;

use aws_lc_rs::aead::{Aad, LessSafeKey, Nonce, UnboundKey};
use aws_lc_rs::rand;

use vstd::prelude::*;

/// Digest Algorithm. Default is Sha512
#[derive(Clone, Copy, Debug, Default, Eq, Hash, PartialEq)]
#[non_exhaustive]
#[allow(missing_docs)]
pub enum DigestAlg {
    Sha256,
    Sha384,
    #[default]
    Sha512,
}

impl DigestAlg {
    /// Returns the digest algorithm's output length in bytes: 32 for
    /// SHA-256, 48 for SHA-384, 64 for SHA-512.
    #[must_use]
    pub const fn output_len(self) -> usize {
        match self {
            Self::Sha256 => 32,
            Self::Sha384 => 48,
            Self::Sha512 => 64,
        }
    }
}

// Defined here rather than in `ecdsa` because `pub use ecdsa::*` would make a
// `pub` item there part of the public API, and `pub(crate)` inside a private
// module trips `clippy::redundant_pub_crate`. At the crate root a private
// `const fn` is reachable from `ecdsa` without exporting it.
const fn get_digest_alg(x: DigestAlg) -> &'static aws_lc_rs::digest::Algorithm {
    match x {
        DigestAlg::Sha256 => &aws_lc_rs::digest::SHA256,
        DigestAlg::Sha384 => &aws_lc_rs::digest::SHA384,
        DigestAlg::Sha512 => &aws_lc_rs::digest::SHA512,
    }
}

pub use error::Error;
use error::Kind;

#[track_caller]
fn serr(s: String) -> Error {
    Error::new(Kind::Cryptographic, s)
}

#[track_caller]
fn err<T>(s: String) -> Result<T, Error> {
    Err(serr(s))
}

/// Fill `bytes` with random data.
///
/// # Errors
///
/// Returns an [`Error`] if the system random number generator fails to
/// produce the requested number of bytes.
pub fn generate_random_bytes(bytes: &mut [u8]) -> Result<(), Error> {
    // Verified core (VR-013(d)): totality, `bytes` keeps its length.
    fill_random_core(bytes)
        .map_err(|_| serr(format!("could not generate {} random bytes", bytes.len())))?;
    Ok(())
}

/// AES GCM Algorithm. Default is `Aes256Gcm`
#[derive(Clone, Copy, Debug, Default, Eq, Hash, PartialEq)]
#[non_exhaustive]
#[allow(missing_docs)]
pub enum AesGcm {
    Aes128Gcm,
    Aes192Gcm,
    #[default]
    Aes256Gcm,
}

impl AesGcm {
    #[must_use]
    /// The key length, in bytes, for this algorithm.
    pub const fn key_length(&self) -> usize {
        match self {
            Self::Aes128Gcm => 16,
            Self::Aes192Gcm => 24,
            Self::Aes256Gcm => 32,
        }
    }
}

const fn get_aes_alg(alg: AesGcm) -> &'static aws_lc_rs::aead::Algorithm {
    match alg {
        AesGcm::Aes128Gcm => &aws_lc_rs::aead::AES_128_GCM,
        AesGcm::Aes192Gcm => &aws_lc_rs::aead::AES_192_GCM,
        AesGcm::Aes256Gcm => &aws_lc_rs::aead::AES_256_GCM,
    }
}

verus! {

/// Extend `cipher_text` with `message` and return the freshly appended tail
/// as a mutable slice of exactly `message.len()` bytes — the in-place target
/// the AES-GCM seal writes the ciphertext into.
///
/// This is the verified core of [`aes_encrypt`]'s buffer bookkeeping (VR-006,
/// part (b)). The slice obligation it discharges is the one that would panic
/// in the shipped code: `extend_from_slice` makes
/// `cipher_text.len() == old_size + message.len()`, so `old_size` is in range
/// for `split_at_mut` and the returned tail is exactly `message.len()` bytes.
/// Verus proves both facts; no index operation here can be out of bounds. The
/// AES-GCM crypto itself is not in scope — the returned slice is handed to the
/// `aws-lc-rs` seal in the [`aes_encrypt`] adapter, outside `verus!`.
///
/// VR-014 (BUG-07(a)) adds two conjuncts, labeled below: the returned tail
/// holds the plaintext, and the final buffer is the old buffer followed by
/// the final contents of the tail.
fn aes_encrypt_extend_core<'a>(cipher_text: &'a mut Vec<u8>, message: &[u8]) -> (slice: &'a mut [u8])
    ensures
        slice@.len() == message@.len(),
        // VR-014 (BUG-07(a)): the tail holds the plaintext.
        slice@ == message@,
        // VR-014 (BUG-07(a)): the old contents stay as the prefix, the tail follows.
        final(cipher_text)@ == old(cipher_text)@ + final(slice)@,
{
    let old_size = cipher_text.len();
    cipher_text.extend_from_slice(message);
    // `extend_from_slice` gives `cipher_text.len() == old_size + message.len()`,
    // so `old_size <= cipher_text.len()` and `split_at_mut(old_size)` cannot
    // panic. The tail runs from `old_size` to the end, i.e. `message.len()`
    // bytes — the ciphertext region the seal overwrites in place.
    let (_head, tail) = cipher_text.as_mut_slice().split_at_mut(old_size);
    tail
}

/// Why [`aes_decrypt_len_ok`] rejected its inputs, kept inside `verus!` so the
/// crate [`Error`] — which Verus does not model — never enters the verified
/// region (the same device T1 uses with `SignCoreError`).
enum AesDecryptLenError {
    /// The plaintext buffer is shorter than the ciphertext.
    PlainTooShort,
}

/// The verified decision core of [`aes_decrypt`] (VR-006, part (a)): accept
/// iff the plaintext buffer is at least as long as the ciphertext.
///
/// This is the guard that makes the downstream `aws-lc-rs`
/// `open_separate_gather` buffer-safe: the gather scatters `cipher_text.len()`
/// bytes into `plain_text`, so a plaintext buffer shorter than the ciphertext
/// must be rejected before the FFI call. The `ensures` ties the result to the
/// exact length relation on the real values, so the adapter cannot proceed to
/// the gather unless `plain_text.len() >= cipher_text.len()`.
fn aes_decrypt_len_ok(plain_text_len: usize, cipher_text_len: usize) -> (r: Result<(), AesDecryptLenError>)
    ensures
        (r is Ok) <==> plain_text_len >= cipher_text_len,
        (r is Err) <==> plain_text_len < cipher_text_len,
{
    if plain_text_len < cipher_text_len {
        Err(AesDecryptLenError::PlainTooShort)
    } else {
        Ok(())
    }
}

/// An output buffer did not have the exact length the guard required. Kept
/// inside `verus!` so the crate [`Error`] never enters the verified region;
/// `want_len` is the exact value the guard compared against, so the adapter
/// reports that value in its message. Shared by [`digest_core`],
/// `digest_finish_core` (in `ecdsa.rs`) and [`hmac_core`].
struct OutLenMismatch {
    /// The length the guard required.
    want_len: usize,
}

/// The verified core of [`digest`] (VR-013(a), pipeline target VR-2026-C03).
///
/// Returns `Err` unless `out.len()` equals the algorithm's output length, and
/// only then computes the digest and copies it. Verus proves the copy is in
/// bounds: the guard pins `out.len()` to `output_len()`, and the trusted
/// length fact A2 (see `aws_lc_specs`) pins the digest to the same length, so
/// vstd's `copy_from_slice` precondition holds. On `Err`, `out` is unchanged.
fn digest_core(
    digest_alg: &'static aws_lc_rs::digest::Algorithm,
    data: &[u8],
    out: &mut [u8],
) -> (r: Result<(), OutLenMismatch>)
    ensures
        (r is Ok) <==> old(out)@.len() == aws_lc_specs::spec_digest_output_len(digest_alg),
        r matches Err(e) ==> e.want_len == aws_lc_specs::spec_digest_output_len(digest_alg) && final(out)@
            == old(out)@,
        r is Ok ==> final(out)@.len() == old(out)@.len(),
{
    let want_len = digest_alg.output_len();
    if out.len() != want_len {
        return Err(OutLenMismatch { want_len });
    }
    let d = aws_lc_rs::digest::digest(digest_alg, data);
    out.copy_from_slice(d.as_ref());
    Ok(())
}

/// The verified core of [`hmac`] (VR-013(f), pipeline target VR-2026-C03).
///
/// Returns `Err` unless `out.len()` equals the tag length of `hmac_alg`, and
/// only then signs and copies. `want_len` comes from `hmac_alg.tag_len()`,
/// the tag length of the algorithm that signs, so the trusted length fact A8
/// (see `aws_lc_specs`) ties the tag to the guarded length and Verus proves
/// the copy in bounds. On `Err`, `out` is unchanged.
fn hmac_core(
    hmac_alg: aws_lc_rs::hmac::Algorithm,
    key: &[u8],
    msg: &[u8],
    out: &mut [u8],
) -> (r: Result<(), OutLenMismatch>)
    ensures
        (r is Ok) <==> old(out)@.len() == aws_lc_specs::spec_hmac_tag_len(hmac_alg),
        r matches Err(e) ==> e.want_len == aws_lc_specs::spec_hmac_tag_len(hmac_alg) && final(out)@
            == old(out)@,
        r is Ok ==> final(out)@.len() == old(out)@.len(),
{
    let want_len = hmac_alg.tag_len();
    if out.len() != want_len {
        return Err(OutLenMismatch { want_len });
    }
    let s_key = aws_lc_rs::hmac::Key::new(hmac_alg, key);
    let tag = aws_lc_rs::hmac::sign(&s_key, msg);
    out.copy_from_slice(tag.as_ref());
    Ok(())
}

/// Why [`kbkdf_core`] failed. Kept inside `verus!` so the crate [`Error`]
/// never enters the verified region.
enum KbkdfCoreError {
    /// The linked `aws-lc-rs` does not provide the algorithm.
    Unavailable,
    /// The `aws-lc-rs` derivation rejected the inputs.
    DerivationFailed,
}

/// The verified core of [`kbkdf_ctr_hmac`] (VR-013(c), pipeline target
/// VR-2026-C03): the wrapper's own logic. The algorithm lookup maps `None` to
/// `Unavailable` and nothing else does; a derivation failure maps to
/// `DerivationFailed`; there is no panic path in the wrapper. `okm` keeps its
/// length. The derivation itself is `aws-lc-rs` and is not verified.
fn kbkdf_core(
    alg_id: aws_lc_rs::kdf::KbkdfCtrHmacAlgorithmId,
    ikm: &[u8],
    info: &[u8],
    okm: &mut [u8],
) -> (r: Result<(), KbkdfCoreError>)
    ensures
        (r matches Err(KbkdfCoreError::Unavailable)) <==> !aws_lc_specs::spec_kbkdf_available(alg_id),
        r is Ok ==> aws_lc_specs::spec_kbkdf_available(alg_id),
        final(okm)@.len() == old(okm)@.len(),
{
    let Some(algorithm) = aws_lc_rs::kdf::get_kbkdf_ctr_hmac_algorithm(alg_id) else {
        return Err(KbkdfCoreError::Unavailable);
    };
    match aws_lc_rs::kdf::kbkdf_ctr_hmac(algorithm, ikm, info, okm) {
        Ok(()) => Ok(()),
        Err(_) => Err(KbkdfCoreError::DerivationFailed),
    }
}

/// Why [`fill_random_core`] failed. Kept inside `verus!` so the crate
/// [`Error`] never enters the verified region.
enum RandFillError {
    /// The system random number generator failed.
    Failed,
}

/// The verified core of [`generate_random_bytes`] (VR-013(d), pipeline
/// target VR-2026-C03). Totality only: no `requires`, so Verus's panic check
/// covers the wrapper for every input. No functional property (randomness)
/// is claimed.
fn fill_random_core(bytes: &mut [u8]) -> (r: Result<(), RandFillError>)
    ensures
        final(bytes)@.len() == old(bytes)@.len(),
{
    match rand::fill(bytes) {
        Ok(()) => Ok(()),
        Err(_) => Err(RandFillError::Failed),
    }
}

/// The verified core of [`constant_time_equal`] (VR-013(e), pipeline target
/// VR-2026-C03). Totality, and the result is exactly the `Ok`-ness of the
/// `aws-lc-rs` comparison (A13). Whether `Ok` means equal, and the timing
/// behavior, are third-party semantics and are not claimed.
fn ct_equal_core(a: &[u8], b: &[u8]) -> (r: bool)
    ensures
        r == aws_lc_specs::spec_slices_equal_ok(a@, b@),
{
    aws_lc_rs::constant_time::verify_slices_are_equal(a, b).is_ok()
}

/// Why [`aes_encrypt_core`] failed. Kept inside `verus!` so the crate
/// [`Error`] never enters the verified region.
enum AesEncryptCoreError {
    /// `UnboundKey::new` rejected the key.
    InvalidKey,
    /// `Nonce::try_assume_unique_for_key` rejected the IV.
    InvalidNonce,
    /// The seal failed.
    SealFailed,
}

/// The verified core of [`aes_encrypt`] (VR-014(a), pipeline target
/// VR-2026-C03, BUG-07(a)). The order of operations is the shipped order:
/// extend with the plaintext first, then key, nonce and seal, then append
/// the tag.
///
/// Proved buffer effects (`o` = old buffer, `m` = message):
///
/// - key or nonce rejected: the buffer is exactly `o ++ m`, i.e. the
///   plaintext stays appended (BUG-07(a));
/// - seal failed: length `|o| + |m|`, prefix `o` unchanged (the tail bytes
///   are whatever the seal left; A18 says nothing about them);
/// - `Ok`: length `|o| + |m| + 16`, prefix `o` unchanged, and the tag is
///   appended after the ciphertext (the `+ 16` rests on A19).
///
/// No crypto property is proven.
fn aes_encrypt_core(
    alg: &'static aws_lc_rs::aead::Algorithm,
    iv: &[u8],
    key: &[u8],
    message: &[u8],
    aad: &[u8],
    cipher_text: &mut Vec<u8>,
) -> (r: Result<(), AesEncryptCoreError>)
    ensures
        (r matches Err(AesEncryptCoreError::InvalidKey) || r matches Err(
            AesEncryptCoreError::InvalidNonce,
        )) ==> final(cipher_text)@ == old(cipher_text)@ + message@,
        r matches Err(AesEncryptCoreError::SealFailed) ==> final(cipher_text)@.len() == old(
            cipher_text,
        )@.len() + message@.len() && final(cipher_text)@.subrange(0, old(cipher_text)@.len() as int)
            == old(cipher_text)@,
        r is Ok ==> final(cipher_text)@.len() == old(cipher_text)@.len() + message@.len() + 16
            && final(cipher_text)@.subrange(0, old(cipher_text)@.len() as int) == old(
            cipher_text,
        )@,
{
    let ghost o = cipher_text@;
    // Verified core (VR-006 + VR-014): extend with `message` and hand back the
    // in-bounds tail slice of exactly `message.len()` bytes for the seal.
    let cipher_slice = aes_encrypt_extend_core(cipher_text, message);
    let Ok(key) = UnboundKey::new(alg, key) else {
        return Err(AesEncryptCoreError::InvalidKey);
    };
    let Ok(nonce) = Nonce::try_assume_unique_for_key(iv) else {
        return Err(AesEncryptCoreError::InvalidNonce);
    };
    let key = LessSafeKey::new(key);
    let aad = Aad::from(aad);
    let Ok(tag) = key.seal_in_place_separate_tag(nonce, aad, cipher_slice) else {
        return Err(AesEncryptCoreError::SealFailed);
    };
    let ghost ct = cipher_slice@;
    let tag_bytes: &[u8] = tag.as_ref();
    cipher_text.extend_from_slice(tag_bytes);
    // The tag is appended after the ciphertext.
    assert(cipher_text@ =~= o + ct + tag_bytes@);
    Ok(())
}

/// Why [`aes_decrypt_core`] failed. Kept inside `verus!` so the crate
/// [`Error`] never enters the verified region.
enum AesDecryptCoreError {
    /// `aes_decrypt_len_ok` (VR-006) rejected the buffer: shorter than the ciphertext.
    PlainTooShort,
    /// `UnboundKey::new` rejected the key.
    InvalidKey,
    /// `Nonce::try_assume_unique_for_key` rejected the IV.
    InvalidNonce,
    /// `open_separate_gather` failed.
    Open,
}

/// The verified core of [`aes_decrypt`] (VR-014(b), pipeline target
/// VR-2026-C03, BUG-07(b)). Calls the VR-006 guard `aes_decrypt_len_ok`
/// first, then the key, nonce and open, in the shipped order.
///
/// The first two `ensures` hold only under the LABELED ASSUMPTION A-OPEN
/// (A20 in `aws_lc_specs`): that `open_separate_gather` returns `Ok` only
/// when `out_plaintext` and `in_ciphertext` have equal lengths. The callee's
/// behavior is assumed, not proved. Relative to A-OPEN:
///
/// - `Ok` implies `|plain_text| == |cipher_text|`;
/// - BUG-07(b) observation: a buffer longer than the ciphertext passes the
///   prim guard (never `PlainTooShort`) and never yields `Ok`; it ends in a
///   callee-side `Err`, which the adapter reports as "authentication tag did
///   not match" when it is the open that fails.
///
/// `plain_text` keeps its length on every path.
fn aes_decrypt_core(
    alg: &'static aws_lc_rs::aead::Algorithm,
    key: &[u8],
    cipher_text: &[u8],
    auth_tag: &[u8],
    iv: &[u8],
    aad: &[u8],
    plain_text: &mut [u8],
) -> (r: Result<(), AesDecryptCoreError>)
    ensures
        r is Ok ==> old(plain_text)@.len() == cipher_text@.len(),
        old(plain_text)@.len() > cipher_text@.len() ==> (r is Err && !(r matches Err(
            AesDecryptCoreError::PlainTooShort,
        ))),
        final(plain_text)@.len() == old(plain_text)@.len(),
{
    if aes_decrypt_len_ok(plain_text.len(), cipher_text.len()).is_err() {
        return Err(AesDecryptCoreError::PlainTooShort);
    }
    let Ok(key) = UnboundKey::new(alg, key) else {
        return Err(AesDecryptCoreError::InvalidKey);
    };
    let Ok(nonce) = Nonce::try_assume_unique_for_key(iv) else {
        return Err(AesDecryptCoreError::InvalidNonce);
    };
    let key = LessSafeKey::new(key);
    let aad = Aad::from(aad);
    match key.open_separate_gather(nonce, aad, cipher_text, auth_tag, plain_text) {
        Ok(()) => Ok(()),
        Err(_) => Err(AesDecryptCoreError::Open),
    }
}

} // verus!

/// Encrypt message with AES GCM
///
/// On success, `cipher_text` is extended with the ciphertext followed by the
/// authentication tag.
///
/// The Rust-side buffer bookkeeping is proven panic-free by Verus (VR-006):
/// `aes_encrypt_extend_core` discharges the slice-bounds obligation so
/// `cipher_text[old_size..]` can never be out of bounds. The AES-GCM key
/// length and IV validity are *not* Verus-proven — they are enforced inside
/// `aws-lc-rs` (`UnboundKey::new` / `Nonce::try_assume_unique_for_key` return
/// `Err`), which is a trusted boundary. No crypto property is proven.
///
/// # Errors
///
/// Returns an [`Error`] if `key` is not the length required by `alg` (see
/// [`AesGcm::key_length`]), if `iv` is not a valid GCM nonce, or if the
/// underlying seal operation fails.
pub fn aes_encrypt(
    alg: AesGcm,
    iv: &[u8],
    key: &[u8],
    message: &[u8],
    aad: &[u8],
    cipher_text: &mut Vec<u8>,
) -> Result<(), Error> {
    // Verified core (VR-006 + VR-014(a)): the buffer effects on every path,
    // in the shipped order of operations.
    aes_encrypt_core(get_aes_alg(alg), iv, key, message, aad, cipher_text).map_err(|e| {
        serr(
            match e {
                AesEncryptCoreError::InvalidKey => "invalid AES-GCM key",
                AesEncryptCoreError::InvalidNonce => "invalid AES-GCM nonce",
                AesEncryptCoreError::SealFailed => "AES-GCM encryption failed",
            }
            .to_owned(),
        )
    })
}

/// Decrypt message with AES GCM
///
/// The plaintext-vs-ciphertext length precondition is proven panic-free by
/// Verus (VR-006): `aes_decrypt_len_ok` is the verified decision core that
/// rejects an under-sized `plain_text` buffer before the `aws-lc-rs` gather.
/// The AES-GCM key length, IV validity and tag verification are *not*
/// Verus-proven — they are enforced inside `aws-lc-rs`
/// (`UnboundKey::new` / `Nonce::try_assume_unique_for_key` /
/// `open_separate_gather` return `Err`), which is a trusted boundary. No
/// crypto property is proven.
///
/// # Errors
///
/// Returns an [`Error`] if `plain_text` is shorter than `cipher_text`, if
/// `key` is not the length required by `alg` (see [`AesGcm::key_length`]), if
/// `iv` is not a valid GCM nonce, or if `auth_tag` fails to verify.
pub fn aes_decrypt(
    alg: AesGcm,
    key: &[u8],
    cipher_text: &[u8],
    auth_tag: &[u8],
    iv: &[u8],
    aad: &[u8],
    plain_text: &mut [u8],
) -> Result<(), Error> {
    // Verified core (VR-006 guard first, then VR-014(b) under A-OPEN).
    match aes_decrypt_core(
        get_aes_alg(alg),
        key,
        cipher_text,
        auth_tag,
        iv,
        aad,
        plain_text,
    ) {
        Ok(()) => Ok(()),
        Err(AesDecryptCoreError::PlainTooShort) => err(format!(
            "plaintext buffer of {} bytes is shorter than the {} byte ciphertext",
            plain_text.len(),
            cipher_text.len()
        )),
        Err(AesDecryptCoreError::InvalidKey) => err("invalid AES-GCM key".to_owned()),
        Err(AesDecryptCoreError::InvalidNonce) => err("invalid AES-GCM nonce".to_owned()),
        Err(AesDecryptCoreError::Open) => err("authentication tag did not match".to_owned()),
    }
}

/// Calculate HMAC into `out`.
///
/// `out` must be exactly [`DigestAlg::output_len`] bytes for `alg`.
///
/// # Errors
///
/// Returns an [`Error`] if `out` is not exactly [`DigestAlg::output_len`]
/// bytes for `alg`.
pub fn hmac(alg: DigestAlg, key: &[u8], msg: &[u8], out: &mut [u8]) -> Result<(), Error> {
    use aws_lc_rs::hmac;
    let hmac_alg = match alg {
        DigestAlg::Sha256 => hmac::HMAC_SHA256,
        DigestAlg::Sha384 => hmac::HMAC_SHA384,
        DigestAlg::Sha512 => hmac::HMAC_SHA512,
    };
    // The verified `hmac_core` (VR-013(f)) takes the required length from
    // `hmac_alg.tag_len()`, the tag length of the algorithm that signs, so
    // the guard and the copy agree by construction: a disagreement surfaces
    // as an error, never a panic in copy_from_slice. In aws-lc-rs 1.18.1
    // `tag_len()` is the underlying digest's `output_len`, the value this
    // check used before, so the accepted lengths and messages are unchanged.
    if let Err(OutLenMismatch { want_len }) = hmac_core(hmac_alg, key, msg, out) {
        return err(format!(
            "output buffer of {} bytes does not match the {want_len} byte {alg:?} output",
            out.len()
        ));
    }
    Ok(())
}
/// Return a digest of `data` using the selected algorithm, written into
/// `out`.
///
/// `out` must be exactly [`DigestAlg::output_len`] bytes for `alg`.
///
/// # Errors
///
/// Returns an [`Error`] if `out` is not exactly [`DigestAlg::output_len`]
/// bytes for `alg`.
pub fn digest(alg: DigestAlg, data: &[u8], out: &mut [u8]) -> Result<(), Error> {
    // Length taken from the algorithm rather than DigestAlg::output_len so
    // the check is authoritative: a disagreement between the two surfaces
    // as an error here instead of a panic in copy_from_slice. The guard and
    // the copy live in the verified `digest_core` (VR-013(a)).
    if let Err(e) = digest_core(get_digest_alg(alg), data, out) {
        return err(format!(
            "output buffer of {} bytes does not match the {} byte {:?} output",
            out.len(),
            e.want_len,
            alg
        ));
    }
    Ok(())
}

/// Compare in constant time
#[must_use]
pub fn constant_time_equal(a: &[u8], b: &[u8]) -> bool {
    // Verified core (VR-013(e)): totality only; the comparison is aws-lc-rs.
    ct_equal_core(a, b)
}

/// KBKDF in counter mode with HMAC as the PRF (NIST SP 800-108 §4.1).
///
/// Derives `okm.len()` bytes into `okm` from the key-material `ikm` and
/// the caller-supplied `info` (typically `Label || 0x00 || Context || L_be32`
/// per NIST fixed-info construction). The HMAC digest is selected by `alg`:
///
/// - `DigestAlg::Sha256` -> HMAC-SHA-256 PRF
/// - `DigestAlg::Sha384` -> HMAC-SHA-384 PRF
/// - `DigestAlg::Sha512` -> HMAC-SHA-512 PRF
///
/// This is the same algorithm consumed by the AWS KMS Hierarchical
/// Keyring's branch-key derivation.
///
/// # Errors
///
/// Returns an [`Error`] if the selected HMAC PRF is unavailable in the
/// linked `aws-lc-rs` build, or if the underlying derivation rejects the
/// inputs — notably when `okm` is zero-length.
pub fn kbkdf_ctr_hmac(
    alg: DigestAlg,
    ikm: &[u8],
    info: &[u8],
    okm: &mut [u8],
) -> Result<(), Error> {
    let alg_id = match alg {
        DigestAlg::Sha256 => aws_lc_rs::kdf::KbkdfCtrHmacAlgorithmId::Sha256,
        DigestAlg::Sha384 => aws_lc_rs::kdf::KbkdfCtrHmacAlgorithmId::Sha384,
        DigestAlg::Sha512 => aws_lc_rs::kdf::KbkdfCtrHmacAlgorithmId::Sha512,
    };
    // Verified core (VR-013(c)): the lookup and error mapping, no panic path.
    kbkdf_core(alg_id, ikm, info, okm).map_err(|e| match e {
        KbkdfCoreError::Unavailable => {
            serr(format!("KBKDF-CTR-HMAC-{alg:?} algorithm is unavailable"))
        }
        KbkdfCoreError::DerivationFailed => serr("KBKDF-CTR-HMAC derivation failed".to_owned()),
    })
}
