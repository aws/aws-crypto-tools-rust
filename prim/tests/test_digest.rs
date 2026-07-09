// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

//! Digest tests ported from Dafny `TestDigest.dfy`. Known-answer digests
//! for SHA-256, SHA-384, and SHA-512 of the message `"asdf"`.

use aws_mpl_primitives::{DigestAlg, digest};

const ASDF: [u8; 4] = [97, 115, 100, 102];

#[test]
fn test_digest_sha256_asdf() {
    let out = digest(DigestAlg::Sha256, &ASDF);
    assert_eq!(
        out,
        vec![
            240, 228, 194, 247, 108, 88, 145, 110, 194, 88, 242, 70, 133, 27, 234, 9, 29, 20, 212,
            36, 122, 47, 195, 225, 134, 148, 70, 27, 24, 22, 225, 59
        ]
    );
    assert_eq!(out.len(), 32);
}

#[test]
fn test_digest_sha384_asdf() {
    let out = digest(DigestAlg::Sha384, &ASDF);
    assert_eq!(
        out,
        vec![
            166, 158, 125, 243, 11, 36, 192, 66, 236, 84, 12, 203, 189, 191, 177, 86, 44, 133, 120,
            112, 56, 200, 133, 116, 156, 30, 64, 142, 45, 98, 250, 54, 100, 44, 208, 7, 95, 163,
            81, 232, 34, 226, 184, 165, 145, 57, 205, 157
        ]
    );
    assert_eq!(out.len(), 48);
}

#[test]
fn test_digest_sha512_asdf() {
    let out = digest(DigestAlg::Sha512, &ASDF);
    assert_eq!(
        out,
        vec![
            64, 27, 9, 234, 179, 192, 19, 212, 202, 84, 146, 43, 184, 2, 190, 200, 253, 83, 24, 25,
            43, 10, 117, 242, 1, 216, 179, 114, 116, 41, 8, 15, 179, 55, 89, 26, 189, 62, 68, 69,
            59, 149, 69, 85, 183, 160, 129, 46, 16, 129, 195, 155, 116, 2, 147, 247, 101, 234, 231,
            49, 245, 166, 94, 209
        ]
    );
    assert_eq!(out.len(), 64);
}

#[test]
fn test_digest_alg_default_is_sha512() {
    // DigestAlg::Sha512 is the crate's declared default.
    assert_eq!(DigestAlg::default(), DigestAlg::Sha512);
}
