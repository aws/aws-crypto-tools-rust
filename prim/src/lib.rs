#![doc = include_str!("../README.md")]
#![cfg_attr(docsrs, feature(doc_cfg))]
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

use std::sync::Arc;

mod ecdsa;
pub use ecdsa::*;
mod hkdf;
pub use hkdf::*;

use aws_lc_rs::aead::{Aad, LessSafeKey, Nonce, UnboundKey};
use aws_lc_rs::rand;
use std::backtrace::Backtrace;

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

/// Error type for this crate
#[derive(Clone, Debug)]
#[non_exhaustive]
pub struct Error {
    /// Text associated with the error
    pub message: String,
    /// Backtrace at time of creation
    pub backtrace: Arc<Backtrace>,
}

impl PartialEq for Error {
    fn eq(&self, other: &Self) -> bool {
        self.message == other.message
    }
}
impl Eq for Error {}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Crypto Error {}", self.message)
    }
}

impl std::error::Error for Error {}

#[track_caller]
fn serr(s: String) -> Error {
    Error {
        message: s,
        backtrace: Arc::new(Backtrace::capture()),
    }
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
    rand::fill(bytes)
        .map_err(|_| serr(format!("Failed to generate {} random bytes.", bytes.len())))?;
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
    /// Return key length associated with the algorithm
    pub const fn key_len(&self) -> u8 {
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

/// Encrypt message with AES GCM
///
/// On success, `cipher_text` is extended with the ciphertext followed by the
/// authentication tag.
///
/// # Errors
///
/// Returns an [`Error`] if `key` is not the length required by `alg` (see
/// [`AesGcm::key_len`]), if `iv` is not a valid GCM nonce, or if the
/// underlying seal operation fails.
pub fn aes_encrypt(
    alg: AesGcm,
    iv: &[u8],
    key: &[u8],
    message: &[u8],
    aad: &[u8],
    cipher_text: &mut Vec<u8>,
) -> Result<(), Error> {
    let alg = get_aes_alg(alg);
    let old_size = cipher_text.len();
    cipher_text.extend_from_slice(message);
    let cipher_slice = &mut cipher_text[old_size..];
    let key = UnboundKey::new(alg, key).map_err(|e| serr(format!("new {e:?}")))?;
    let nonce = Nonce::try_assume_unique_for_key(iv).map_err(|e| serr(format!("new {e:?}")))?;
    let key = LessSafeKey::new(key);
    let aad = Aad::from(aad);
    let tag = key
        .seal_in_place_separate_tag(nonce, aad, cipher_slice)
        .map_err(|e| serr(format!("Seal {e:?}")))?;
    cipher_text.extend_from_slice(tag.as_ref());
    Ok(())
}

/// Decrypt message with AES GCM
///
/// # Errors
///
/// Returns an [`Error`] if `plain_text` is shorter than `cipher_text`, if
/// `key` is not the length required by `alg` (see [`AesGcm::key_len`]), if
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
    if plain_text.len() < cipher_text.len() {
        return err(format!(
            "aes_decrypt : Plain text buffer length of {} is less than cipher text length of {}.",
            plain_text.len(),
            cipher_text.len()
        ));
    }
    let alg = get_aes_alg(alg);
    let key = UnboundKey::new(alg, key).map_err(|e| serr(format!("new {e:?}")))?;
    let nonce = Nonce::try_assume_unique_for_key(iv).map_err(|e| serr(format!("new {e:?}")))?;
    let key = LessSafeKey::new(key);
    let aad = Aad::from(aad);
    key.open_separate_gather(nonce, aad, cipher_text, auth_tag, plain_text)
        .map_err(|e| serr(format!("gather {e:?}")))?;
    Ok(())
}

#[must_use]
/// Calculate HMAC
// FIXME - pass in &mut[u8] instead of returning Vec
pub fn hmac(alg: DigestAlg, key: &[u8], msg: &[u8]) -> Vec<u8> {
    use aws_lc_rs::hmac;
    match alg {
        DigestAlg::Sha256 => {
            let s_key = hmac::Key::new(hmac::HMAC_SHA256, key);
            hmac::sign(&s_key, msg).as_ref().into()
        }
        DigestAlg::Sha384 => {
            let s_key = hmac::Key::new(hmac::HMAC_SHA384, key);
            hmac::sign(&s_key, msg).as_ref().into()
        }
        DigestAlg::Sha512 => {
            let s_key = hmac::Key::new(hmac::HMAC_SHA512, key);
            hmac::sign(&s_key, msg).as_ref().into()
        }
    }
}
#[must_use]
/// Return a digest of the data using the selected algorithm
pub fn digest(alg: DigestAlg, data: &[u8]) -> Vec<u8> {
    match alg {
        DigestAlg::Sha256 => aws_lc_rs::digest::digest(&aws_lc_rs::digest::SHA256, data)
            .as_ref()
            .to_vec(),
        DigestAlg::Sha384 => aws_lc_rs::digest::digest(&aws_lc_rs::digest::SHA384, data)
            .as_ref()
            .to_vec(),
        DigestAlg::Sha512 => aws_lc_rs::digest::digest(&aws_lc_rs::digest::SHA512, data)
            .as_ref()
            .to_vec(),
    }
}

/// Compare in constant time
#[must_use]
pub fn constant_time_equal(a: &[u8], b: &[u8]) -> bool {
    aws_lc_rs::constant_time::verify_slices_are_equal(a, b).is_ok()
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
    let algorithm = aws_lc_rs::kdf::get_kbkdf_ctr_hmac_algorithm(alg_id)
        .ok_or_else(|| serr(format!("KBKDF-CTR-HMAC-{alg:?} algorithm is unavailable")))?;
    aws_lc_rs::kdf::kbkdf_ctr_hmac(algorithm, ikm, info, okm)
        .map_err(|e| serr(format!("kbkdf_ctr_hmac {e:?}")))?;
    Ok(())
}
