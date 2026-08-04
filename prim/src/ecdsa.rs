use crate::DigestAlg;
use crate::Error;
use crate::err;
use crate::serr;

use aws_lc_rs::encoding::AsBigEndian;
use aws_lc_rs::rand::SystemRandom;
use aws_lc_rs::signature::EcdsaKeyPair;
use aws_lc_rs::signature::EcdsaSigningAlgorithm;
use aws_lc_rs::signature::EcdsaVerificationAlgorithm;
use aws_lc_rs::signature::KeyPair;
use aws_lc_rs::signature::UnparsedPublicKey;

/// Gathers Digest Data
#[derive(Clone)]
pub struct DigestContext {
    context: aws_lc_rs::digest::Context,
}

impl std::fmt::Debug for DigestContext {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "DigestContext {:?}", self.context.algorithm())
    }
}

impl DigestContext {
    /// Create new `DigestContext` from the given algorithm
    ///
    /// # Errors
    ///
    /// Every [`DigestAlg`] maps to a supported digest, so this currently
    /// always returns [`Ok`]. The fallible signature is retained so a future
    /// algorithm that requires runtime availability checks does not become a
    /// breaking change.
    pub fn new(alg: DigestAlg) -> Result<Self, Error> {
        let alg = get_digest_alg(alg);
        Ok(Self {
            context: aws_lc_rs::digest::Context::new(alg),
        })
    }

    /// Create new `DigestContext` from the digest paired with the given
    /// ECDSA signature algorithm
    ///
    /// # Errors
    ///
    /// Every [`EcdsaSignatureAlgorithm`] maps to a supported digest, so this
    /// currently always returns [`Ok`]. The fallible signature is retained
    /// for the same reason as [`DigestContext::new`].
    pub fn new_from_ecdsa(alg: EcdsaSignatureAlgorithm) -> Result<Self, Error> {
        let alg = get_digest_alg_from_ecdsa(alg);
        Ok(Self {
            context: aws_lc_rs::digest::Context::new(alg),
        })
    }

    /// Update with more bytes
    pub fn update(&mut self, data: &[u8]) {
        self.context.update(data);
    }

    /// finalize and return the signature
    #[must_use]
    pub fn finish(self) -> Vec<u8> {
        self.context.finish().as_ref().to_vec()
    }

    fn digest(self) -> aws_lc_rs::digest::Digest {
        self.context.finish()
    }
}

/// Which ECDSA Algorithm to use
#[derive(Clone, Copy, Debug, Default, Eq, Hash, PartialEq)]
#[non_exhaustive]
pub enum EcdsaSignatureAlgorithm {
    /// 384 bit ECDSA
    #[default]
    EcdsaP384,
    /// 256 bit ECDSA
    EcdsaP256,
}

const fn get_digest_alg(x: DigestAlg) -> &'static aws_lc_rs::digest::Algorithm {
    match x {
        DigestAlg::Sha256 => &aws_lc_rs::digest::SHA256,
        DigestAlg::Sha384 => &aws_lc_rs::digest::SHA384,
        DigestAlg::Sha512 => &aws_lc_rs::digest::SHA512,
    }
}

const fn get_digest_alg_from_ecdsa(
    x: EcdsaSignatureAlgorithm,
) -> &'static aws_lc_rs::digest::Algorithm {
    match x {
        EcdsaSignatureAlgorithm::EcdsaP256 => &aws_lc_rs::digest::SHA256,
        EcdsaSignatureAlgorithm::EcdsaP384 => &aws_lc_rs::digest::SHA384,
    }
}

const fn get_sign_alg(x: EcdsaSignatureAlgorithm) -> &'static EcdsaSigningAlgorithm {
    match x {
        EcdsaSignatureAlgorithm::EcdsaP256 => &aws_lc_rs::signature::ECDSA_P256_SHA256_ASN1_SIGNING,
        EcdsaSignatureAlgorithm::EcdsaP384 => &aws_lc_rs::signature::ECDSA_P384_SHA384_ASN1_SIGNING,
    }
}

const fn get_ver_alg(x: EcdsaSignatureAlgorithm) -> &'static EcdsaVerificationAlgorithm {
    match x {
        EcdsaSignatureAlgorithm::EcdsaP256 => &aws_lc_rs::signature::ECDSA_P256_SHA256_ASN1,
        EcdsaSignatureAlgorithm::EcdsaP384 => &aws_lc_rs::signature::ECDSA_P384_SHA384_ASN1,
    }
}

/// Maximum number of signing attempts made while looking for a DER
/// signature of the canonical length (see [`sign_fixed_len`]).
///
/// Each attempt succeeds with probability ~0.51, measured over 4000
/// signatures per curve, so 32 attempts leaves a spurious-failure
/// probability of ~1.3e-10.
const MAX_SIGN_ATTEMPTS: u32 = 32;

/// The DER-encoded signature length this crate emits for `alg`.
///
/// A `match` on the algorithm rather than a comparison against the
/// `aws-lc-rs` constants, so adding a curve to the `#[non_exhaustive]`
/// [`EcdsaSignatureAlgorithm`] is a compile error instead of a signing
/// operation that can never satisfy its length check.
const fn der_sig_len(alg: EcdsaSignatureAlgorithm) -> usize {
    match alg {
        EcdsaSignatureAlgorithm::EcdsaP256 => 71,
        EcdsaSignatureAlgorithm::EcdsaP384 => 103,
    }
}

/// Call `sign_once` until it produces a DER signature of exactly
/// `want_len` bytes, giving up after [`MAX_SIGN_ATTEMPTS`].
///
/// The DER encoding of an ECDSA signature varies in length because `r` and
/// `s` each need a leading `0x00` when their high bit is set, so a fresh
/// signature is simply retried until it lands on the canonical length.
/// This terminates only because ECDSA draws a random nonce per attempt,
/// making the attempts independent; a deterministic scheme (RFC 6979)
/// would produce the same length forever and always exhaust the retries.
///
/// # Errors
///
/// Returns an [`Error`] if `sign_once` fails, or if no signature of
/// `want_len` bytes is produced within [`MAX_SIGN_ATTEMPTS`].
fn sign_fixed_len(
    want_len: usize,
    mut sign_once: impl FnMut() -> Result<aws_lc_rs::signature::Signature, Error>,
) -> Result<Vec<u8>, Error> {
    for _ in 0..MAX_SIGN_ATTEMPTS {
        let signature = sign_once()?;
        if signature.as_ref().len() == want_len {
            return Ok(signature.as_ref().into());
        }
    }
    err(format!(
        "ecdsa_sign : no {want_len} byte DER signature produced in {MAX_SIGN_ATTEMPTS} attempts."
    ))
}

/// Sign the message with the key using the given algorithm
///
/// The key must be in DER format
///
/// # Errors
///
/// Returns an [`Error`] if `key` is not a valid DER-encoded private key for
/// `alg`, if the signing operation fails, or if no canonical-length
/// signature is produced within [`MAX_SIGN_ATTEMPTS`].
// FIXME - pass in &mut[u8] instead of returning Vec
pub fn ecdsa_sign(alg: EcdsaSignatureAlgorithm, key: &[u8], msg: &[u8]) -> Result<Vec<u8>, Error> {
    let want_len = der_sig_len(alg);
    let private_key: EcdsaKeyPair = EcdsaKeyPair::from_private_key_der(get_sign_alg(alg), key)
        .map_err(|e| serr(format!("{e:?}")))?;
    let rng = SystemRandom::new();
    sign_fixed_len(want_len, || {
        private_key
            .sign(&rng, msg)
            .map_err(|e| serr(format!("{e:?}")))
    })
}

/// Sign the accumulated digest with the key using the given algorithm
///
/// The key must be in DER format
///
/// # Errors
///
/// Returns an [`Error`] if `key` is not a valid DER-encoded private key for
/// `alg`, if the signing operation fails, or if no canonical-length
/// signature is produced within [`MAX_SIGN_ATTEMPTS`].
pub fn ecdsa_sign_digest(
    alg: EcdsaSignatureAlgorithm,
    key: &[u8],
    context: DigestContext,
) -> Result<Vec<u8>, Error> {
    let want_len = der_sig_len(alg);
    let private_key: EcdsaKeyPair = EcdsaKeyPair::from_private_key_der(get_sign_alg(alg), key)
        .map_err(|e| serr(format!("{e:?}")))?;
    let digest = context.digest();
    sign_fixed_len(want_len, || {
        private_key
            .sign_digest(&digest)
            .map_err(|e| serr(format!("{e:?}")))
    })
}

/// Verify the signature of the message using the key and algorithm
///
/// Returns `Ok(true)` when the signature verifies and `Ok(false)` when it
/// does not.
///
/// # Errors
///
/// A rejected signature, a malformed signature, and a malformed key are all
/// reported as `Ok(false)`, so this currently never returns an [`Error`].
/// The fallible signature is retained so verification can distinguish
/// operational failures from a genuine mismatch in future without a
/// breaking change.
pub fn ecdsa_verify(
    alg: EcdsaSignatureAlgorithm,
    key: &[u8],
    msg: &[u8],
    sig: &[u8],
) -> Result<bool, Error> {
    let public_key = UnparsedPublicKey::new(get_ver_alg(alg), key);
    match public_key.verify(msg, sig) {
        Ok(()) => Ok(true),
        Err(_) => Ok(false),
    }
}

/// Verify the signature of the accumulated digest using the key and
/// algorithm
///
/// Returns `Ok(true)` when the signature verifies and `Ok(false)` when it
/// does not.
///
/// # Errors
///
/// As with [`ecdsa_verify`], failures are reported as `Ok(false)`, so this
/// currently never returns an [`Error`].
pub fn ecdsa_verify_context(
    alg: EcdsaSignatureAlgorithm,
    key: &[u8],
    context: DigestContext,
    sig: &[u8],
) -> Result<bool, Error> {
    let public_key = UnparsedPublicKey::new(get_ver_alg(alg), key);
    let digest = context.digest();
    match public_key.verify_digest(&digest, sig) {
        Ok(()) => Ok(true),
        Err(_) => Ok(false),
    }
}

/// Generate a fresh ECDSA keypair for the given signature algorithm and
/// return `(private_key_be, public_key_sec1)`:
///
/// - `private_key_be`  — the raw private scalar in big-endian byte order.
///   32 bytes for P-256, 48 bytes for P-384.
/// - `public_key_sec1` — the public point in SEC1-uncompressed format
///   (`0x04 || X || Y`). 65 bytes for P-256, 97 bytes for P-384.
///
/// The scalar and uncompressed-point formats are what consumers of this
/// crate (e.g. `aws-crypto-mpl`'s default CMM) need to encode a signing
/// key into a `SigningKey` and to publish the verification key in the
/// encryption context.
///
/// # Errors
///
/// Returns an [`Error`] if key generation fails or if the generated private
/// key cannot be encoded to big-endian bytes.
pub fn ecdsa_generate_keypair(alg: EcdsaSignatureAlgorithm) -> Result<(Vec<u8>, Vec<u8>), Error> {
    let signing_alg = get_sign_alg(alg);
    let key_pair =
        EcdsaKeyPair::generate(signing_alg).map_err(|e| serr(format!("ECDSA keygen {e:?}")))?;

    let private_key_be: Vec<u8> = key_pair
        .private_key()
        .as_be_bytes()
        .map_err(|e| serr(format!("ECDSA private-key encoding {e:?}")))?
        .as_ref()
        .to_vec();

    let public_key_sec1: Vec<u8> = key_pair.public_key().as_ref().to_vec();

    Ok((private_key_be, public_key_sec1))
}
