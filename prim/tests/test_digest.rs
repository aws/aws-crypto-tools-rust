// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

//! Digest tests ported from Dafny [`TestDigest.dfy`]. Known-answer digests
//! for SHA-256, SHA-384, and SHA-512 of the message `"asdf"`.
//!
//! [`TestDigest.dfy`]: https://github.com/aws/aws-cryptographic-material-providers-library/blob/main/AwsCryptographyPrimitives/test/TestDigest.dfy

use aws_mpl_primitives::{DigestAlg, Error, digest};

const ASDF: [u8; 4] = [97, 115, 100, 102];

#[test]
fn test_digest_sha256_asdf() -> Result<(), Error> {
    let mut out = [0u8; 32];
    digest(DigestAlg::Sha256, &ASDF, &mut out)?;
    assert_eq!(
        out,
        [
            240, 228, 194, 247, 108, 88, 145, 110, 194, 88, 242, 70, 133, 27, 234, 9, 29, 20, 212,
            36, 122, 47, 195, 225, 134, 148, 70, 27, 24, 22, 225, 59
        ]
    );
    Ok(())
}

#[test]
fn test_digest_sha384_asdf() -> Result<(), Error> {
    let mut out = [0u8; 48];
    digest(DigestAlg::Sha384, &ASDF, &mut out)?;
    assert_eq!(
        out,
        [
            166, 158, 125, 243, 11, 36, 192, 66, 236, 84, 12, 203, 189, 191, 177, 86, 44, 133, 120,
            112, 56, 200, 133, 116, 156, 30, 64, 142, 45, 98, 250, 54, 100, 44, 208, 7, 95, 163,
            81, 232, 34, 226, 184, 165, 145, 57, 205, 157
        ]
    );
    Ok(())
}

#[test]
fn test_digest_sha512_asdf() -> Result<(), Error> {
    let mut out = [0u8; 64];
    digest(DigestAlg::Sha512, &ASDF, &mut out)?;
    assert_eq!(
        out,
        [
            64, 27, 9, 234, 179, 192, 19, 212, 202, 84, 146, 43, 184, 2, 190, 200, 253, 83, 24, 25,
            43, 10, 117, 242, 1, 216, 179, 114, 116, 41, 8, 15, 179, 55, 89, 26, 189, 62, 68, 69,
            59, 149, 69, 85, 183, 160, 129, 46, 16, 129, 195, 155, 116, 2, 147, 247, 101, 234, 231,
            49, 245, 166, 94, 209
        ]
    );
    Ok(())
}

#[test]
fn test_digest_alg_default_is_sha512() {
    // DigestAlg::Sha512 is the crate's declared default.
    assert_eq!(DigestAlg::default(), DigestAlg::Sha512);
}

#[test]
fn test_digest_alg_output_len() -> Result<(), Error> {
    assert_eq!(DigestAlg::Sha256.output_len(), 32);
    assert_eq!(DigestAlg::Sha384.output_len(), 48);
    assert_eq!(DigestAlg::Sha512.output_len(), 64);
    // Cross-check the table against the digest itself: `digest` sizes its
    // buffer check from the algorithm, so an output_len that disagreed with
    // the real digest length would fail here.
    for alg in [DigestAlg::Sha256, DigestAlg::Sha384, DigestAlg::Sha512] {
        let mut out = vec![0u8; alg.output_len()];
        digest(alg, b"asdf", &mut out)?;
    }
    Ok(())
}

#[test]
fn test_digest_rejects_wrong_length_output_buffer() {
    // 32 is the SHA-256 length, so this also covers passing the right buffer
    // for the wrong digest.
    let mut out = [0u8; 32];
    let err = digest(DigestAlg::Sha512, &ASDF, &mut out).unwrap_err();
    assert!(err.message.contains("output buffer length of 32"));
}
