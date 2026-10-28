// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

//! HKDF tests ported from Dafny [`TestAwsCryptographyPrimitivesHKDF.dfy`]
//! and [`TestHKDF_Rfc5869TestVectors.dfy`].
//!
//! The Dafny tests use the RFC 5869 vectors with L = 42 or 82. This port
//! asks for L=32 and compares against the first 32 bytes of each RFC OKM.
//! HKDF-Expand output is prefix-stable, so the comparison is exact, not
//! approximate.
//!
//! [`TestAwsCryptographyPrimitivesHKDF.dfy`]: https://github.com/aws/aws-cryptographic-material-providers-library/blob/main/AwsCryptographyPrimitives/test/TestAwsCryptographyPrimitivesHKDF.dfy
//! [`TestHKDF_Rfc5869TestVectors.dfy`]: https://github.com/aws/aws-cryptographic-material-providers-library/blob/main/AwsCryptographyPrimitives/test/TestHKDF_Rfc5869TestVectors.dfy

use aws_mpl_primitives::{DigestAlg, Error, Prk, hkdf, hkdf_expand, hkdf_extract, hkdf_no_salt};

// A.1. Test Case 1 — basic SHA-256 test.
const A1_IKM: [u8; 22] = [
    11, 11, 11, 11, 11, 11, 11, 11, 11, 11, 11, 11, 11, 11, 11, 11, 11, 11, 11, 11, 11, 11,
];
const A1_SALT: [u8; 13] = [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12];
const A1_INFO: [u8; 10] = [240, 241, 242, 243, 244, 245, 246, 247, 248, 249];
/// First 32 bytes of A.1's 42-byte OKM from RFC 5869.
const A1_OKM32: [u8; 32] = [
    60, 178, 95, 37, 250, 172, 213, 122, 144, 67, 79, 100, 208, 54, 47, 42, 45, 45, 10, 144, 207,
    26, 90, 76, 93, 176, 45, 86, 236, 196, 197, 191,
];

// A.2. Test Case 2 — longer inputs/outputs with SHA-256.
const A2_IKM: [u8; 80] = [
    0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25,
    26, 27, 28, 29, 30, 31, 32, 33, 34, 35, 36, 37, 38, 39, 40, 41, 42, 43, 44, 45, 46, 47, 48, 49,
    50, 51, 52, 53, 54, 55, 56, 57, 58, 59, 60, 61, 62, 63, 64, 65, 66, 67, 68, 69, 70, 71, 72, 73,
    74, 75, 76, 77, 78, 79,
];
const A2_SALT: [u8; 80] = [
    96, 97, 98, 99, 100, 101, 102, 103, 104, 105, 106, 107, 108, 109, 110, 111, 112, 113, 114, 115,
    116, 117, 118, 119, 120, 121, 122, 123, 124, 125, 126, 127, 128, 129, 130, 131, 132, 133, 134,
    135, 136, 137, 138, 139, 140, 141, 142, 143, 144, 145, 146, 147, 148, 149, 150, 151, 152, 153,
    154, 155, 156, 157, 158, 159, 160, 161, 162, 163, 164, 165, 166, 167, 168, 169, 170, 171, 172,
    173, 174, 175,
];
const A2_INFO: [u8; 80] = [
    176, 177, 178, 179, 180, 181, 182, 183, 184, 185, 186, 187, 188, 189, 190, 191, 192, 193, 194,
    195, 196, 197, 198, 199, 200, 201, 202, 203, 204, 205, 206, 207, 208, 209, 210, 211, 212, 213,
    214, 215, 216, 217, 218, 219, 220, 221, 222, 223, 224, 225, 226, 227, 228, 229, 230, 231, 232,
    233, 234, 235, 236, 237, 238, 239, 240, 241, 242, 243, 244, 245, 246, 247, 248, 249, 250, 251,
    252, 253, 254, 255,
];
/// First 32 bytes of A.2's 82-byte OKM from RFC 5869.
const A2_OKM32: [u8; 32] = [
    177, 30, 57, 141, 200, 3, 39, 161, 200, 231, 247, 140, 89, 106, 73, 52, 79, 1, 46, 218, 45, 78,
    250, 216, 160, 80, 204, 76, 25, 175, 169, 124,
];

// A.3. Test Case 3 — SHA-256, zero-length salt and info.
const A3_IKM: [u8; 22] = A1_IKM;
/// First 32 bytes of A.3's 42-byte OKM from RFC 5869.
const A3_OKM32: [u8; 32] = [
    141, 164, 231, 117, 165, 99, 193, 143, 113, 95, 128, 42, 6, 60, 90, 49, 184, 161, 31, 92, 94,
    225, 135, 158, 195, 69, 78, 95, 60, 115, 141, 45,
];

// Full-hkdf tests (extract + expand collapsed into one call).

#[test]
fn test_hkdf_rfc5869_a1() -> Result<(), Error> {
    let mut okm = [0u8; 32];
    hkdf(DigestAlg::Sha256, &A1_SALT, &A1_IKM, &[&A1_INFO], &mut okm)?;
    assert_eq!(okm, A1_OKM32);
    Ok(())
}

#[test]
fn test_hkdf_rfc5869_a2() -> Result<(), Error> {
    let mut okm = [0u8; 32];
    hkdf(DigestAlg::Sha256, &A2_SALT, &A2_IKM, &[&A2_INFO], &mut okm)?;
    assert_eq!(okm, A2_OKM32);
    Ok(())
}

#[test]
fn test_hkdf_rfc5869_a3() -> Result<(), Error> {
    let mut okm = [0u8; 32];
    hkdf(DigestAlg::Sha256, &[], &A3_IKM, &[], &mut okm)?;
    assert_eq!(okm, A3_OKM32);
    Ok(())
}

// Extract + expand paired. aws-lc-rs's Prk is opaque, so we can't verify
// PRK bytes directly — instead we verify the final OKM matches, which
// implicitly checks that extract produced the RFC-correct PRK.

#[test]
fn test_hkdf_extract_then_expand_a1() -> Result<(), Error> {
    let prk: Prk = hkdf_extract(DigestAlg::Sha256, &A1_SALT, &A1_IKM);
    let mut okm = [0u8; 32];
    hkdf_expand(&prk, &[&A1_INFO], &mut okm)?;
    assert_eq!(okm, A1_OKM32);
    Ok(())
}

#[test]
fn test_hkdf_extract_then_expand_a2() -> Result<(), Error> {
    let prk = hkdf_extract(DigestAlg::Sha256, &A2_SALT, &A2_IKM);
    let mut okm = [0u8; 32];
    hkdf_expand(&prk, &[&A2_INFO], &mut okm)?;
    assert_eq!(okm, A2_OKM32);
    Ok(())
}

#[test]
fn test_hkdf_extract_then_expand_a3() -> Result<(), Error> {
    let prk = hkdf_extract(DigestAlg::Sha256, &[], &A3_IKM);
    let mut okm = [0u8; 32];
    hkdf_expand(&prk, &[], &mut okm)?;
    assert_eq!(okm, A3_OKM32);
    Ok(())
}

// hkdf_no_salt: RFC 5869 defines empty salt as HashLen zero bytes, which is
// exactly what prim's hkdf_no_salt supplies. A.3 has empty salt, so
// hkdf_no_salt should produce the same OKM as hkdf(&[], ...) for A.3.

#[test]
fn test_hkdf_no_salt_matches_a3() -> Result<(), Error> {
    let mut okm = [0u8; 32];
    hkdf_no_salt(DigestAlg::Sha256, &A3_IKM, &[], &mut okm)?;
    assert_eq!(okm, A3_OKM32);
    Ok(())
}

#[test]
fn test_hkdf_no_salt_sha384() -> Result<(), Error> {
    // Exercises default_salt_size's SHA-384 arm and the get_len(24) path.
    let mut okm = [0u8; 24];
    hkdf_no_salt(DigestAlg::Sha384, &A1_IKM, &[&A1_INFO], &mut okm)?;

    // There is no RFC vector for L=24 SHA-384, so instead assert that the
    // digest argument actually reaches the derivation: the same IKM and
    // info under SHA-256 must produce different key material. Both the PRF
    // and the default salt length follow from `alg`, so this does not
    // isolate `default_salt_size` on its own — it does show the SHA-384
    // arm is wired rather than silently falling back.
    let mut okm_sha256 = [0u8; 24];
    hkdf_no_salt(DigestAlg::Sha256, &A1_IKM, &[&A1_INFO], &mut okm_sha256)?;
    assert_ne!(okm, okm_sha256);
    Ok(())
}

#[test]
fn test_hkdf_no_salt_sha512() -> Result<(), Error> {
    // Exercises default_salt_size's SHA-512 arm. As above, compare against
    // SHA-256 over the same inputs rather than asserting a fixed length.
    let mut okm = [0u8; 16];
    hkdf_no_salt(DigestAlg::Sha512, &A1_IKM, &[&A1_INFO], &mut okm)?;

    let mut okm_sha256 = [0u8; 16];
    hkdf_no_salt(DigestAlg::Sha256, &A1_IKM, &[&A1_INFO], &mut okm_sha256)?;
    assert_ne!(okm, okm_sha256);
    Ok(())
}

// The full 42-byte OKM of RFC 5869 A.1: lengths other than 16/24/32 work.
#[test]
fn test_hkdf_rfc5869_a1_full_length() -> Result<(), Error> {
    let mut okm = [0u8; 42];
    hkdf(DigestAlg::Sha256, &A1_SALT, &A1_IKM, &[&A1_INFO], &mut okm)?;
    assert_eq!(okm[..32], A1_OKM32);
    assert_eq!(okm[32..], [52, 0, 114, 8, 213, 184, 135, 24, 88, 101]);
    Ok(())
}

// Error paths: HKDF output is at most 255 times the digest length.

#[test]
fn test_hkdf_bad_okm_length() {
    let mut okm = vec![0u8; 255 * 32 + 1];
    let err = hkdf(DigestAlg::Sha256, &A1_SALT, &A1_IKM, &[&A1_INFO], &mut okm).unwrap_err();
    assert!(err.is_cryptographic(), "{:?}", err);
}

#[test]
fn test_hkdf_expand_bad_okm_length() {
    let prk = hkdf_extract(DigestAlg::Sha256, &A1_SALT, &A1_IKM);
    let mut okm = vec![0u8; 255 * 32 + 1];
    let err = hkdf_expand(&prk, &[&A1_INFO], &mut okm).unwrap_err();
    assert!(err.is_cryptographic(), "{:?}", err);
}

// Prk derives Clone + Debug — exercise both for coverage.

#[test]
fn test_prk_clone_and_debug() -> Result<(), Error> {
    let prk = hkdf_extract(DigestAlg::Sha256, &A1_SALT, &A1_IKM);
    let cloned = prk.clone();
    // Same PRK → same OKM after expand.
    let mut okm1 = [0u8; 32];
    let mut okm2 = [0u8; 32];
    hkdf_expand(&prk, &[&A1_INFO], &mut okm1)?;
    hkdf_expand(&cloned, &[&A1_INFO], &mut okm2)?;
    assert_eq!(okm1, okm2);
    // Debug shouldn't panic and should produce something non-empty.
    let debug_str = format!("{prk:?}");
    assert!(!debug_str.is_empty());
    Ok(())
}
