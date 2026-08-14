use crate::DigestAlg;
use crate::Error;
use crate::err;
use crate::serr;

use aws_lc_rs::encoding::AsBigEndian;
use aws_lc_rs::encoding::AsDer;
use aws_lc_rs::encoding::EcPrivateKeyRfc5915Der;
use aws_lc_rs::encoding::EcPublicKeyCompressedBin;
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
        let alg = crate::get_digest_alg(alg);
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

    /// Length in bytes of the digest [`DigestContext::finish`] produces.
    #[must_use]
    pub fn output_len(&self) -> usize {
        self.context.algorithm().output_len()
    }

    /// Finalize and write the digest into `out`.
    ///
    /// `out` must be exactly [`DigestContext::output_len`] bytes.
    ///
    /// # Errors
    ///
    /// Returns an [`Error`] if `out` is not exactly
    /// [`DigestContext::output_len`] bytes.
    pub fn finish(self, out: &mut [u8]) -> Result<(), Error> {
        let want_len = self.output_len();
        if out.len() != want_len {
            return err(format!(
                "DigestContext::finish : output buffer length of {} does not match the {want_len} byte digest.",
                out.len()
            ));
        }
        out.copy_from_slice(self.context.finish().as_ref());
        Ok(())
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
/// Each attempt succeeds with probability 1/2, which follows from the
/// encoding rather than from measurement. `r` and `s` are each encoded as a
/// DER INTEGER, and each independently takes a leading `0x00` byte exactly
/// when its high bit is set — probability 1/2 apiece. So a signature runs
/// one byte long when both take the pad (1/4), one byte short when neither
/// does (1/4), and lands on the canonical length when exactly one does
/// (1/2). An `r` or `s` whose top byte is zero shortens it further, which
/// shifts the rate by about 1/256.
///
/// At p = 1/2, exhausting 128 attempts has probability 2^-128, negligible
/// against the other failure modes of signing. The expected number of
/// attempts is 2, so a bound this loose costs nothing in practice.
const MAX_SIGN_ATTEMPTS: u32 = 128;

/// The DER-encoded signature length [`ecdsa_sign`] emits for `alg`: 71
/// bytes for P-256, 103 for P-384.
///
/// A `match` on the algorithm rather than a comparison against the
/// `aws-lc-rs` constants, so adding a curve to the `#[non_exhaustive]`
/// [`EcdsaSignatureAlgorithm`] is a compile error instead of a signing
/// operation that can never satisfy its length check.
#[must_use]
pub const fn signature_len(alg: EcdsaSignatureAlgorithm) -> usize {
    match alg {
        EcdsaSignatureAlgorithm::EcdsaP256 => 71,
        EcdsaSignatureAlgorithm::EcdsaP384 => 103,
    }
}

/// Call `sign_once` until it produces a DER signature of exactly
/// `signature.len()` bytes, writing it into `signature` and giving up after
/// [`MAX_SIGN_ATTEMPTS`].
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
/// `signature.len()` bytes is produced within [`MAX_SIGN_ATTEMPTS`].
fn sign_fixed_len(
    signature: &mut [u8],
    mut sign_once: impl FnMut() -> Result<aws_lc_rs::signature::Signature, Error>,
) -> Result<(), Error> {
    let want_len = signature.len();
    for _ in 0..MAX_SIGN_ATTEMPTS {
        let candidate = sign_once()?;
        if candidate.as_ref().len() == want_len {
            signature.copy_from_slice(candidate.as_ref());
            return Ok(());
        }
    }
    err(format!(
        "ecdsa_sign : no {want_len} byte DER signature produced in {MAX_SIGN_ATTEMPTS} attempts."
    ))
}

/// Check that a caller-supplied signature buffer is the length `alg`
/// produces, so a wrong-sized buffer fails immediately rather than after
/// [`MAX_SIGN_ATTEMPTS`] signatures that can never match.
fn check_sig_len(alg: EcdsaSignatureAlgorithm, signature: &[u8]) -> Result<(), Error> {
    if signature.len() != signature_len(alg) {
        return err(format!(
            "ecdsa_sign : signature buffer length of {} does not match the {} byte {:?} DER signature.",
            signature.len(),
            signature_len(alg),
            alg
        ));
    }
    Ok(())
}

/// Sign the message with the key using the given algorithm, writing the
/// DER-encoded signature into `signature`.
///
/// The key must be in DER format. `signature` must be exactly
/// [`signature_len`] bytes for `alg`.
///
/// # Errors
///
/// Returns an [`Error`] if `signature` is not [`signature_len`] bytes for
/// `alg`, if `key` is not a valid DER-encoded private key for `alg`, if the
/// signing operation fails, or if no canonical-length signature is produced
/// within [`MAX_SIGN_ATTEMPTS`].
pub fn ecdsa_sign(
    alg: EcdsaSignatureAlgorithm,
    key: &[u8],
    msg: &[u8],
    signature: &mut [u8],
) -> Result<(), Error> {
    check_sig_len(alg, signature)?;
    let private_key: EcdsaKeyPair = EcdsaKeyPair::from_private_key_der(get_sign_alg(alg), key)
        .map_err(|e| serr(format!("{e:?}")))?;
    let rng = SystemRandom::new();
    sign_fixed_len(signature, || {
        private_key
            .sign(&rng, msg)
            .map_err(|e| serr(format!("{e:?}")))
    })
}

/// Sign the accumulated digest with the key using the given algorithm,
/// writing the DER-encoded signature into `signature`.
///
/// The key must be in DER format. `signature` must be exactly
/// [`signature_len`] bytes for `alg`.
///
/// # Errors
///
/// Returns an [`Error`] if `signature` is not [`signature_len`] bytes for
/// `alg`, if `key` is not a valid DER-encoded private key for `alg`, if the
/// signing operation fails, or if no canonical-length signature is produced
/// within [`MAX_SIGN_ATTEMPTS`].
pub fn ecdsa_sign_digest(
    alg: EcdsaSignatureAlgorithm,
    key: &[u8],
    context: DigestContext,
    signature: &mut [u8],
) -> Result<(), Error> {
    check_sig_len(alg, signature)?;
    let private_key: EcdsaKeyPair = EcdsaKeyPair::from_private_key_der(get_sign_alg(alg), key)
        .map_err(|e| serr(format!("{e:?}")))?;
    let digest = context.digest();
    sign_fixed_len(signature, || {
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

/// An ECDSA key pair, in the formats the Dafny MPL's `SignatureKeyPair`
/// uses (`AwsCryptographyPrimitives/src/Signature.dfy`).
///
/// `Debug` deliberately redacts [`Self::signing_key`] so private key
/// material cannot reach logs.
#[derive(Clone)]
#[non_exhaustive]
pub struct SignatureKeyPair {
    /// The public key, as an X9.62 compressed point (`0x02`/`0x03 || X`).
    /// Exactly [`field_size`] bytes: 33 for P-256, 49 for P-384.
    pub verification_key: Vec<u8>,
    /// The private key, DER-encoded per RFC 5915 — the form
    /// [`ecdsa_sign`] and [`ecdsa_sign_digest`] accept.
    pub signing_key: Vec<u8>,
}

impl std::fmt::Debug for SignatureKeyPair {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SignatureKeyPair")
            .field("verification_key", &self.verification_key)
            .field(
                "signing_key",
                &format_args!("[REDACTED; {} bytes]", self.signing_key.len()),
            )
            .finish()
    }
}

/// Length in bytes of a compressed verification key for `alg`.
///
/// Mirrors `FieldSize` in the Dafny MPL: `1 + ceil(bits / 8)`, i.e. one
/// X9.62 tag byte plus a single field element.
#[must_use]
pub const fn field_size(alg: EcdsaSignatureAlgorithm) -> usize {
    match alg {
        EcdsaSignatureAlgorithm::EcdsaP256 => 33,
        EcdsaSignatureAlgorithm::EcdsaP384 => 49,
    }
}

/// Generate a fresh ECDSA key pair for the given signature algorithm.
///
/// The returned formats match the Dafny MPL's `ExternKeyGen`: the
/// verification key is an X9.62 compressed point and the signing key is
/// DER-encoded, so the signing key composes directly with [`ecdsa_sign`]
/// and [`ecdsa_sign_digest`], and the verification key is already in the
/// form the ESDK publishes in the encryption context
/// (`spec/framework/transitive-requirements.md#ecdsa`, SEC 1 v2.0 §2.3.3).
///
/// # Errors
///
/// Returns an [`Error`] if key generation fails, if either key cannot be
/// encoded, or if the generated verification key is not [`field_size`]
/// bytes long.
pub fn ecdsa_generate_keypair(alg: EcdsaSignatureAlgorithm) -> Result<SignatureKeyPair, Error> {
    let key_pair = EcdsaKeyPair::generate(get_sign_alg(alg))
        .map_err(|e| serr(format!("ECDSA keygen {e:?}")))?;

    let compressed: EcPublicKeyCompressedBin<'static> = key_pair
        .public_key()
        .as_be_bytes()
        .map_err(|e| serr(format!("ECDSA public-key compression {e:?}")))?;
    let verification_key = compressed.as_ref().to_vec();

    let der: EcPrivateKeyRfc5915Der<'static> = key_pair
        .private_key()
        .as_der()
        .map_err(|e| serr(format!("ECDSA private-key DER encoding {e:?}")))?;
    let signing_key = der.as_ref().to_vec();

    // Mirrors the `KeyGen` postcondition in the Dafny MPL, which rejects a
    // verification key whose length is not `FieldSize`.
    if verification_key.len() != field_size(alg) {
        return err(format!(
            "ecdsa_generate_keypair : verification key is {} bytes, expected {}.",
            verification_key.len(),
            field_size(alg)
        ));
    }

    Ok(SignatureKeyPair {
        verification_key,
        signing_key,
    })
}
