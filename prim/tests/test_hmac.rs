// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

//! HMAC tests ported from Dafny `TestHMAC.dfy` and
//! `TestAwsCryptographyPrimitivesHMAC.dfy`. Two key sets (`[1,2,3,4]` and
//! `[1,1,1,1]`), each with the message `"asdf"` and known-answer digests
//! for SHA-256, SHA-384, and SHA-512.

use aws_mpl_primitives::{DigestAlg, hmac};

const ASDF: [u8; 4] = [97, 115, 100, 102];

// Vectors from TestAwsCryptographyPrimitivesHMAC.dfy — key = [1,2,3,4]

#[test]
fn test_hmac_sha256_key_1234() {
    let out = hmac(DigestAlg::Sha256, &[1, 2, 3, 4], &ASDF);
    assert_eq!(
        out,
        vec![
            55, 107, 186, 241, 51, 255, 154, 169, 106, 133, 2, 248, 54, 230, 193, 147, 212, 179,
            154, 66, 43, 52, 108, 181, 144, 152, 19, 101, 117, 99, 204, 134
        ]
    );
    assert_eq!(out.len(), 32);
}

#[test]
fn test_hmac_sha384_key_1234() {
    let out = hmac(DigestAlg::Sha384, &[1, 2, 3, 4], &ASDF);
    assert_eq!(
        out,
        vec![
            90, 206, 234, 81, 173, 76, 235, 148, 203, 139, 195, 46, 251, 14, 97, 110, 146, 49, 147,
            24, 240, 1, 17, 231, 58, 104, 146, 53, 144, 167, 11, 112, 7, 39, 122, 15, 58, 53, 144,
            91, 16, 223, 51, 98, 30, 88, 23, 166
        ]
    );
    assert_eq!(out.len(), 48);
}

#[test]
fn test_hmac_sha512_key_1234() {
    let out = hmac(DigestAlg::Sha512, &[1, 2, 3, 4], &ASDF);
    assert_eq!(
        out,
        vec![
            100, 23, 173, 215, 39, 67, 51, 165, 149, 53, 87, 84, 145, 58, 221, 155, 239, 182, 249,
            134, 147, 191, 143, 224, 140, 165, 190, 221, 183, 15, 6, 102, 203, 77, 238, 64, 10,
            138, 61, 64, 219, 79, 248, 249, 90, 102, 217, 188, 13, 2, 101, 96, 217, 242, 73, 254,
            190, 217, 134, 33, 163, 137, 151, 183
        ]
    );
    assert_eq!(out.len(), 64);
}

// Vectors from TestHMAC.dfy — key = [1,1,1,1]

#[test]
fn test_hmac_sha256_key_1111() {
    let out = hmac(DigestAlg::Sha256, &[1, 1, 1, 1], &ASDF);
    assert_eq!(
        out,
        vec![
            93, 12, 86, 145, 123, 239, 169, 72, 195, 226, 204, 179, 103, 94, 195, 83, 134, 128,
            226, 185, 184, 203, 98, 100, 115, 32, 7, 44, 172, 11, 81, 16
        ]
    );
}

#[test]
fn test_hmac_sha384_key_1111() {
    let out = hmac(DigestAlg::Sha384, &[1, 1, 1, 1], &ASDF);
    assert_eq!(
        out,
        vec![
            219, 44, 51, 60, 217, 57, 186, 208, 8, 69, 115, 185, 190, 136, 136, 1, 69, 143, 151,
            148, 7, 66, 149, 193, 16, 225, 51, 85, 92, 176, 139, 249, 56, 93, 189, 11, 150, 21,
            135, 54, 153, 37, 76, 68, 70, 77, 154, 124
        ]
    );
}

#[test]
fn test_hmac_sha512_key_1111() {
    let out = hmac(DigestAlg::Sha512, &[1, 1, 1, 1], &ASDF);
    assert_eq!(
        out,
        vec![
            49, 213, 21, 219, 23, 169, 195, 39, 177, 1, 15, 162, 233, 182, 208, 84, 226, 3, 27,
            120, 75, 78, 85, 46, 220, 5, 166, 206, 79, 47, 25, 94, 88, 119, 211, 192, 148, 23, 252,
            155, 98, 218, 97, 225, 38, 93, 83, 113, 139, 95, 101, 222, 154, 98, 244, 206, 88, 229,
            6, 115, 226, 188, 152, 173
        ]
    );
}
