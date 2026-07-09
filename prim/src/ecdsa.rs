use crate::DigestAlg;
use crate::Error;
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
    pub fn new(alg: DigestAlg) -> Result<Self, Error> {
        let alg = get_digest_alg(alg);
        Ok(Self {
            context: aws_lc_rs::digest::Context::new(alg),
        })
    }

    /// Create new `DigestContext` from the given algorithm
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

/// Sign the message with the key using the given algorithm
///
/// The key must be in DER format
// FIXME - pass in &mut[u8] instead of returning Vec
pub fn ecdsa_sign(alg: EcdsaSignatureAlgorithm, key: &[u8], msg: &[u8]) -> Result<Vec<u8>, Error> {
    // This loop can in theory run forever, but the chances of that are negligible.
    // We may want to consider failing, after some number of loops, if we can do so in a way consistent with other ESDKs.
    let alg = get_sign_alg(alg);
    let private_key: EcdsaKeyPair =
        EcdsaKeyPair::from_private_key_der(alg, key).map_err(|e| serr(format!("{e:?}")))?;
    let rng = SystemRandom::new();
    loop {
        let result: aws_lc_rs::signature::Signature = private_key
            .sign(&rng, msg)
            .map_err(|e| serr(format!("{e:?}")))?;

        if (alg == &aws_lc_rs::signature::ECDSA_P384_SHA384_ASN1_SIGNING
            && result.as_ref().len() == 103)
            || (alg == &aws_lc_rs::signature::ECDSA_P256_SHA256_ASN1_SIGNING
                && result.as_ref().len() == 71)
        {
            return Ok(result.as_ref().into());
        }
    }
}

/// Sign the message with the key using the given algorithm
///
/// The key must be in DER format
pub fn ecdsa_sign_digest(
    alg: EcdsaSignatureAlgorithm,
    key: &[u8],
    context: DigestContext,
) -> Result<Vec<u8>, Error> {
    let alg = get_sign_alg(alg);
    let digest = context.digest();
    let private_key: EcdsaKeyPair =
        EcdsaKeyPair::from_private_key_der(alg, key).map_err(|e| serr(format!("{e:?}")))?;

    // This loop can in theory run forever, but the chances of that are negligible.
    // We may want to consider failing, after some number of loops, if we can do so in a way consistent with other ESDKs.
    loop {
        let result: aws_lc_rs::signature::Signature = private_key
            .sign_digest(&digest)
            .map_err(|e| serr(format!("{e:?}")))?;

        if (alg == &aws_lc_rs::signature::ECDSA_P384_SHA384_ASN1_SIGNING
            && result.as_ref().len() == 103)
            || (alg == &aws_lc_rs::signature::ECDSA_P256_SHA256_ASN1_SIGNING
                && result.as_ref().len() == 71)
        {
            return Ok(result.as_ref().into());
        }
    }
}

/// Verify the signature of the message using the key and algorithm
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

/// Verify the signature of the message using the key and algorithm
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
