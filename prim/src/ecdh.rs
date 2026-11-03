// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

use crate::Error;
use crate::err;
use crate::serr;

use aws_lc_rs::agreement;
use aws_lc_rs::encoding::{AsDer, Pkcs8V1Der, PublicKeyX509Der};
use aws_lc_rs::signature;
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

/// An elliptic curve for ECDH key agreement.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
#[non_exhaustive]
pub enum EcdhCurveSpec {
    /// NIST P-256.
    EccNistP256,
    /// NIST P-384.
    EccNistP384,
    /// NIST P-521.
    EccNistP521,
}

impl EcdhCurveSpec {
    const fn agreement_alg(self) -> &'static agreement::Algorithm {
        match self {
            Self::EccNistP256 => &agreement::ECDH_P256,
            Self::EccNistP384 => &agreement::ECDH_P384,
            Self::EccNistP521 => &agreement::ECDH_P521,
        }
    }

    // Only parses and re-encodes public keys; the digest is never used.
    const fn point_alg(self) -> &'static signature::EcdsaVerificationAlgorithm {
        match self {
            Self::EccNistP256 => &signature::ECDSA_P256_SHA256_ASN1,
            Self::EccNistP384 => &signature::ECDSA_P384_SHA384_ASN1,
            Self::EccNistP521 => &signature::ECDSA_P521_SHA512_ASN1,
        }
    }

    /// The length of a DER-encoded X.509 `SubjectPublicKeyInfo` public key on this curve,
    /// with an uncompressed point: 91 bytes for P-256, 120 for P-384, 158 for P-521.
    #[must_use]
    pub const fn public_key_der_len(self) -> usize {
        match self {
            Self::EccNistP256 => 91,
            Self::EccNistP384 => 120,
            Self::EccNistP521 => 158,
        }
    }

    /// The length of a compressed X9.62 public key on this curve:
    /// 33 bytes for P-256, 49 for P-384, 67 for P-521.
    #[must_use]
    pub const fn compressed_public_key_len(self) -> usize {
        match self {
            Self::EccNistP256 => 33,
            Self::EccNistP384 => 49,
            Self::EccNistP521 => 67,
        }
    }

    /// The length of an uncompressed X9.62 point: `0x04 || X || Y`.
    const fn uncompressed_point_len(self) -> usize {
        2 * self.compressed_public_key_len() - 1
    }
}

/// An ECDH key pair.
///
/// `Debug` redacts the private key, and dropping the pair zeroizes it.
#[derive(Clone)]
#[non_exhaustive]
pub struct EcdhKeyPair {
    /// The private key, PEM-encoded PKCS #8 `PrivateKeyInfo`.
    pub private_key: Vec<u8>,
    /// The public key, DER-encoded X.509 `SubjectPublicKeyInfo`.
    pub public_key: Vec<u8>,
}

impl Drop for EcdhKeyPair {
    fn drop(&mut self) {
        self.private_key.zeroize();
    }
}

impl ZeroizeOnDrop for EcdhKeyPair {}

impl std::fmt::Debug for EcdhKeyPair {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("EcdhKeyPair")
            .field(
                "private_key",
                &format_args!("[REDACTED; {} bytes]", self.private_key.len()),
            )
            .field("public_key", &self.public_key)
            .finish()
    }
}

/// Parse a PEM-encoded PKCS #8 or RFC 5915 private key on `curve`.
fn private_key(
    curve: EcdhCurveSpec,
    private_key_pem: &[u8],
) -> Result<agreement::PrivateKey, Error> {
    let pem = pem::parse(private_key_pem)
        .map_err(|e| serr(format!("the ECC private key is not valid PEM: {e}")))?;
    let der = Zeroizing::new(pem.into_contents());
    agreement::PrivateKey::from_private_key_der(curve.agreement_alg(), &der).map_err(|_| {
        serr(format!(
            "the ECC private key is not a {curve:?} private key"
        ))
    })
}

/// Parse `public_key_der` as a public key on `curve`, accepting only X.509 `SubjectPublicKeyInfo`.
///
/// The parse rejects a point that is not on the curve, including the point at infinity.
fn parsed_public_key(
    curve: EcdhCurveSpec,
    public_key_der: &[u8],
) -> Result<agreement::ParsedPublicKey, Error> {
    let parsed = agreement::ParsedPublicKey::try_from(agreement::UnparsedPublicKey::new(
        curve.agreement_alg(),
        public_key_der,
    ))
    .map_err(|_| serr("Invalid X509 Public Key.".to_owned()))?;
    if parsed.format() != agreement::ParsedPublicKeyFormat::X509 {
        return err("Invalid X509 Public Key.".to_owned());
    }
    Ok(parsed)
}

/// Generate an ECDH key pair on `curve`.
///
/// # Errors
///
/// Returns an [`Error`] if key generation or encoding fails.
pub fn ecdh_generate_key_pair(curve: EcdhCurveSpec) -> Result<EcdhKeyPair, Error> {
    let key = agreement::PrivateKey::generate(curve.agreement_alg())
        .map_err(|_| serr("ECC key generation failed".to_owned()))?;
    let public_key: PublicKeyX509Der<'static> = key
        .compute_public_key()
        .and_then(|public_key| public_key.as_der())
        .map_err(|_| serr("ECC public key encoding failed".to_owned()))?;
    let private_der: Pkcs8V1Der<'static> = key
        .as_der()
        .map_err(|_| serr("ECC private key encoding failed".to_owned()))?;
    let private_key = pem::encode(&pem::Pem::new("PRIVATE KEY", private_der.as_ref())).into_bytes();
    Ok(EcdhKeyPair {
        private_key,
        public_key: public_key.as_ref().to_vec(),
    })
}

/// The DER-encoded X.509 `SubjectPublicKeyInfo` public key of a PEM-encoded private key on `curve`.
///
/// # Errors
///
/// Returns an [`Error`] if `private_key_pem` is not a PEM-encoded PKCS #8 or RFC 5915 private key on `curve`.
pub fn ecdh_public_key_from_private_key(
    curve: EcdhCurveSpec,
    private_key_pem: &[u8],
) -> Result<Vec<u8>, Error> {
    let public_key: PublicKeyX509Der<'static> = private_key(curve, private_key_pem)?
        .compute_public_key()
        .and_then(|public_key| public_key.as_der())
        .map_err(|_| serr("ECC public key encoding failed".to_owned()))?;
    Ok(public_key.as_ref().to_vec())
}

/// Check that `public_key_der` is a DER-encoded X.509 `SubjectPublicKeyInfo` public key on `curve`
/// whose point is on the curve and is not the point at infinity.
///
/// # Errors
///
/// Returns an [`Error`] if the key fails any of those checks.
pub fn ecdh_validate_public_key(curve: EcdhCurveSpec, public_key_der: &[u8]) -> Result<(), Error> {
    parsed_public_key(curve, public_key_der)?;
    Ok(())
}

/// The ECDH shared secret of a PEM-encoded private key and a DER-encoded public key, both on `curve`.
///
/// # Errors
///
/// Returns an [`Error`] if either key is not a valid key on `curve`, or if the key agreement fails.
pub fn ecdh_derive_shared_secret(
    curve: EcdhCurveSpec,
    private_key_pem: &[u8],
    public_key_der: &[u8],
) -> Result<Vec<u8>, Error> {
    let private_key = private_key(curve, private_key_pem)?;
    let public_key = parsed_public_key(curve, public_key_der)?;
    agreement::agree(
        &private_key,
        public_key,
        serr("ECDH key agreement failed".to_owned()),
        |secret| Ok(secret.to_vec()),
    )
}

/// Compress a DER-encoded X.509 `SubjectPublicKeyInfo` public key on `curve`
/// to its X9.62 compressed point.
///
/// # Errors
///
/// Returns an [`Error`] if `public_key_der` is not a valid public key on `curve`.
pub fn ecdh_compress_public_key(
    curve: EcdhCurveSpec,
    public_key_der: &[u8],
) -> Result<Vec<u8>, Error> {
    parsed_public_key(curve, public_key_der)?;
    // Re-encoding writes the point uncompressed at the end of the SubjectPublicKeyInfo.
    let der = uncompressed_der(curve, public_key_der)?;
    let point_len = curve.uncompressed_point_len();
    let Some(point_start) = der.len().checked_sub(point_len) else {
        return err(format!(
            "the {curve:?} public key encodes to {} bytes, shorter than a {point_len} byte point",
            der.len()
        ));
    };
    let point = &der[point_start..];
    let (Some(&0x04), Some(&y_last)) = (point.first(), point.last()) else {
        return err(format!(
            "the {curve:?} public key is not an uncompressed point"
        ));
    };
    let x_end = curve.compressed_public_key_len();
    let mut compressed = Vec::with_capacity(x_end);
    compressed.push(0x02 | (y_last & 1));
    compressed.extend_from_slice(&point[1..x_end]);
    Ok(compressed)
}

/// Decompress an X9.62 compressed point on `curve`
/// to a DER-encoded X.509 `SubjectPublicKeyInfo` public key.
///
/// # Errors
///
/// Returns an [`Error`] if `compressed_public_key` is not a compressed point on `curve`.
pub fn ecdh_decompress_public_key(
    curve: EcdhCurveSpec,
    compressed_public_key: &[u8],
) -> Result<Vec<u8>, Error> {
    if !matches!(compressed_public_key.first(), Some(0x02 | 0x03))
        || compressed_public_key.len() != curve.compressed_public_key_len()
    {
        return err(format!(
            "the public key is not a compressed {curve:?} point"
        ));
    }
    uncompressed_der(curve, compressed_public_key)
}

/// Re-encode a public key on `curve`, in any form the parser accepts,
/// as DER X.509 `SubjectPublicKeyInfo` with an uncompressed point.
fn uncompressed_der(curve: EcdhCurveSpec, public_key: &[u8]) -> Result<Vec<u8>, Error> {
    let parsed = signature::ParsedPublicKey::new(curve.point_alg(), public_key).map_err(|_| {
        serr(format!(
            "the public key is not a valid {curve:?} public key"
        ))
    })?;
    let der: PublicKeyX509Der<'static> = parsed
        .as_der()
        .map_err(|_| serr("ECC public key encoding failed".to_owned()))?;
    Ok(der.as_ref().to_vec())
}
