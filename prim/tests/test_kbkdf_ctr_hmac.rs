// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

//! KBKDF-CTR-HMAC test vectors ported from Dafny
//! [`TestKDF_TestVectors.dfy`].
//!
//! The scheme is NIST SP 800-108r1 §4.1: key derivation in counter mode
//! with HMAC as the PRF. Dafny implements it as `KdfCounterMode` in
//! [`KdfCtr.dfy`]. See `aws_mpl_primitives::kbkdf_ctr_hmac` for the
//! algorithm itself and the PRF-per-digest mapping.
//!
//! Vector fields use the KDF terminology from SP 800-108 / RFC 5869:
//! `ikm` is the *input keying material*, the secret fed into the KDF, and
//! `okm` is the *output keying material*, the derived bytes the KDF is
//! expected to produce for that input.
//!
//! Two vector families:
//!
//! * B.1–B.10 (`RAW_VECTORS`) — driven through the raw entry point, with
//!   `info` passed verbatim as the fixed-info input.
//! * C.1–C.5 (`PURPOSE_NONCE_VECTORS`) — the same derivation, with fixed
//!   info assembled the way the AWS KMS Hierarchical Keyring assembles it:
//!   `PURPOSE || 0x00 || nonce || L_be32` (see `build_fixed_info`). That
//!   is SP 800-108's fixed-info layout rather than an MPL invention:
//!   `PURPOSE` is the label, `0x00` the separation indicator, `nonce` the
//!   context, and `L_be32` is `[L]_2`, the derived length in bits.
//!
//! [`TestKDF_TestVectors.dfy`]: https://github.com/aws/aws-cryptographic-material-providers-library/blob/main/AwsCryptographyPrimitives/test/TestKDF_TestVectors.dfy
//! [`KdfCtr.dfy`]: https://github.com/aws/aws-cryptographic-material-providers-library/blob/main/AwsCryptographyPrimitives/src/KDF/KdfCtr.dfy

use aws_mpl_primitives::{DigestAlg, Error, kbkdf_ctr_hmac};

/// UTF-8 bytes of "aws-kms-hierarchy" — the purpose label used by the C
/// vectors.
const PURPOSE: &[u8] = b"aws-kms-hierarchy";

struct RawVector {
    name: &'static str,
    alg: DigestAlg,
    ikm: &'static [u8],
    info: &'static [u8],
    okm: &'static [u8],
}

/// B.1–B.10 from `TestKDF_TestVectors.dfy`. Info is passed verbatim.
const RAW_VECTORS: &[RawVector] = &[
    RawVector {
        name: "B.1",
        alg: DigestAlg::Sha256,
        ikm: &[
            226, 4, 214, 212, 102, 170, 213, 7, 255, 175, 109, 109, 171, 10, 91, 38, 21, 44, 158,
            33, 231, 100, 55, 4, 100, 227, 96, 200, 251, 199, 101, 198,
        ],
        info: &[
            123, 3, 185, 141, 159, 148, 184, 153, 229, 145, 243, 239, 38, 75, 113, 177, 147, 251,
            167, 4, 60, 126, 149, 60, 222, 35, 188, 83, 132, 188, 26, 98, 147, 88, 1, 21, 250, 227,
            73, 95, 216, 69, 218, 219, 208, 43, 214, 69, 92, 244, 141, 15, 98, 179, 62, 98, 54, 74,
            58, 128,
        ],
        okm: &[
            119, 13, 250, 182, 166, 164, 164, 190, 224, 37, 127, 243, 53, 33, 63, 120, 216, 40,
            123, 79, 213, 55, 213, 193, 255, 250, 149, 105, 16, 231, 199, 121,
        ],
    },
    RawVector {
        name: "B.2",
        alg: DigestAlg::Sha256,
        ikm: &[
            174, 238, 202, 96, 246, 137, 164, 65, 177, 59, 12, 188, 212, 65, 216, 45, 240, 207,
            135, 218, 194, 54, 41, 13, 236, 232, 147, 29, 248, 215, 3, 23,
        ],
        info: &[
            88, 142, 192, 65, 229, 115, 59, 112, 49, 33, 44, 85, 56, 239, 228, 246, 170, 250, 76,
            218, 139, 146, 93, 38, 31, 90, 38, 136, 240, 7, 179, 172, 36, 14, 225, 41, 145, 231,
            123, 140, 184, 83, 134, 120, 97, 89, 102, 22, 74, 129, 135, 43, 209, 207, 203, 251, 57,
            164, 244, 80,
        ],
        okm: &[
            62, 129, 214, 17, 60, 238, 60, 82, 158, 206, 223, 248, 154, 105, 153, 206, 37, 182, 24,
            193, 94, 225, 209, 157, 69, 203, 55, 106, 28, 142, 35, 116,
        ],
    },
    RawVector {
        name: "B.3",
        alg: DigestAlg::Sha256,
        ikm: &[
            149, 200, 247, 110, 17, 54, 126, 181, 85, 38, 162, 179, 147, 174, 144, 101, 131, 209,
            203, 221, 71, 150, 33, 70, 245, 6, 204, 124, 172, 18, 244, 100,
        ],
        info: &[
            202, 214, 14, 144, 75, 158, 156, 139, 254, 180, 168, 26, 127, 103, 211, 189, 220, 192,
            94, 100, 37, 88, 112, 64, 55, 112, 243, 83, 58, 230, 221, 99, 76, 234, 165, 108, 83,
            230, 136, 189, 19, 122, 230, 1, 137, 53, 243, 75, 159, 176, 132, 234, 72, 228, 198,
            136, 246, 187, 179, 136,
        ],
        okm: &[
            202, 250, 92, 160, 63, 95, 190, 42, 36, 32, 4, 171, 203, 211, 222, 16, 89, 199, 64,
            123, 30, 229, 121, 37, 81, 36, 175, 24, 155, 224, 181, 86,
        ],
    },
    RawVector {
        name: "B.4",
        alg: DigestAlg::Sha256,
        ikm: &[
            77, 5, 57, 31, 214, 251, 30, 41, 46, 120, 171, 150, 25, 177, 183, 42, 125, 99, 238, 89,
            215, 67, 93, 215, 24, 151, 185, 255, 126, 231, 174, 112,
        ],
        info: &[
            240, 120, 230, 249, 183, 248, 45, 100, 85, 79, 166, 182, 4, 200, 8, 241, 155, 31, 106,
            214, 114, 125, 183, 170, 111, 28, 134, 105, 78, 16, 75, 82, 86, 200, 180, 3, 153, 25,
            100, 100, 129, 215, 234, 36, 82, 199, 44, 23, 163, 232, 215, 211, 145, 98, 133, 70, 10,
            165, 235, 129,
        ],
        okm: &[
            107, 22, 232, 245, 59, 131, 26, 165, 232, 107, 249, 122, 92, 79, 163, 125, 8, 155, 193,
            114, 218, 90, 30, 127, 102, 45, 212, 165, 149, 51, 154, 183,
        ],
    },
    RawVector {
        name: "B.5",
        alg: DigestAlg::Sha256,
        ikm: &[
            15, 104, 168, 47, 241, 103, 22, 52, 204, 145, 54, 197, 100, 169, 224, 42, 118, 118, 33,
            221, 116, 161, 191, 92, 36, 18, 155, 128, 130, 20, 183, 82,
        ],
        info: &[
            100, 133, 153, 128, 156, 44, 78, 124, 106, 94, 108, 68, 159, 0, 49, 235, 245, 92, 54,
            97, 168, 149, 180, 77, 176, 87, 46, 232, 128, 131, 177, 244, 177, 38, 2, 170, 85, 252,
            29, 241, 80, 166, 90, 109, 110, 237, 160, 170, 121, 164, 52, 161, 3, 155, 145, 181,
            165, 143, 199, 241,
        ],
        okm: &[
            226, 151, 100, 15, 119, 104, 72, 93, 74, 110, 124, 254, 36, 95, 139, 250, 132, 112, 13,
            153, 118, 38, 146, 234, 26, 66, 92, 204, 2, 117, 232, 245,
        ],
    },
    RawVector {
        name: "B.6",
        alg: DigestAlg::Sha384,
        ikm: &[
            130, 44, 118, 74, 27, 17, 112, 133, 193, 15, 14, 104, 152, 20, 210, 191, 189, 155, 67,
            40, 127, 26, 140, 117, 215, 149, 169, 131, 26, 40, 97, 132, 200, 88, 111, 53, 119, 182,
            229, 187, 206, 22, 55, 146, 94, 4, 252, 71,
        ],
        info: &[
            175, 52, 97, 16, 185, 65, 177, 29, 33, 137, 49, 108, 159, 194, 185, 244, 33, 55, 117,
            165, 215, 54, 141, 53, 65, 38, 120, 162, 143, 205, 3, 176, 127, 5, 73, 102, 110, 253,
            243, 12, 128, 240, 171, 85, 99, 114, 10, 86, 239, 97, 106, 19, 187, 143, 119, 128, 3,
            111, 192, 142,
        ],
        okm: &[
            224, 174, 35, 92, 184, 35, 128, 82, 123, 231, 105, 52, 166, 150, 34, 57, 109, 144, 231,
            191, 167, 226, 210, 149, 228, 55, 91, 206, 224, 209, 177, 1,
        ],
    },
    RawVector {
        name: "B.7",
        alg: DigestAlg::Sha384,
        ikm: &[
            52, 14, 33, 45, 117, 142, 131, 204, 91, 137, 228, 181, 106, 134, 238, 140, 150, 49,
            174, 78, 75, 186, 236, 21, 172, 9, 94, 164, 64, 123, 199, 182, 52, 173, 99, 13, 208,
            190, 133, 169, 28, 8, 168, 199, 225, 225, 3, 11,
        ],
        info: &[
            60, 213, 86, 26, 209, 47, 173, 252, 228, 8, 224, 65, 128, 175, 206, 227, 139, 131, 21,
            107, 158, 75, 224, 119, 156, 79, 13, 185, 226, 107, 254, 92, 205, 67, 225, 89, 33, 151,
            124, 210, 107, 29, 184, 40, 139, 128, 8, 158, 183, 209, 187, 215, 245, 158, 16, 17,
            179, 225, 139, 81,
        ],
        okm: &[
            5, 250, 87, 123, 112, 129, 33, 14, 124, 157, 230, 157, 176, 61, 124, 32, 38, 207, 68,
            105, 169, 11, 250, 41, 241, 194, 193, 8, 24, 212, 99, 224,
        ],
    },
    RawVector {
        name: "B.8",
        alg: DigestAlg::Sha384,
        ikm: &[
            0, 161, 45, 60, 228, 255, 117, 166, 227, 15, 65, 243, 85, 124, 130, 106, 241, 50, 107,
            99, 2, 244, 206, 136, 123, 173, 61, 51, 23, 165, 72, 200, 192, 58, 5, 114, 132, 220,
            195, 141, 139, 198, 144, 189, 74, 86, 95, 71,
        ],
        info: &[
            36, 197, 192, 178, 200, 16, 223, 160, 142, 53, 215, 254, 235, 184, 199, 142, 12, 215,
            38, 201, 46, 205, 66, 217, 23, 16, 19, 115, 140, 162, 83, 26, 148, 127, 82, 60, 55,
            246, 76, 219, 4, 48, 91, 217, 105, 209, 214, 249, 236, 212, 100, 5, 210, 130, 128, 249,
            104, 80, 11, 167,
        ],
        okm: &[
            174, 243, 213, 124, 141, 167, 217, 88, 44, 93, 28, 98, 214, 182, 72, 150, 218, 155, 27,
            14, 64, 18, 164, 76, 220, 61, 207, 75, 112, 173, 108, 102,
        ],
    },
    RawVector {
        name: "B.9",
        alg: DigestAlg::Sha384,
        ikm: &[
            0, 0, 217, 183, 236, 111, 190, 253, 242, 86, 253, 104, 34, 11, 82, 5, 172, 101, 162, 0,
            17, 69, 17, 140, 80, 186, 107, 101, 112, 50, 25, 139, 139, 124, 227, 178, 247, 6, 138,
            120, 13, 193, 124, 34, 69, 154, 242, 183,
        ],
        info: &[
            216, 87, 84, 28, 98, 184, 87, 86, 220, 115, 222, 125, 194, 216, 111, 93, 94, 139, 40,
            51, 139, 176, 169, 69, 181, 196, 253, 124, 129, 247, 25, 97, 185, 112, 93, 61, 21, 59,
            25, 25, 93, 0, 59, 116, 33, 32, 104, 237, 16, 249, 108, 83, 67, 134, 83, 8, 122, 1, 82,
            207,
        ],
        okm: &[
            121, 62, 241, 19, 249, 99, 151, 171, 0, 49, 234, 160, 250, 167, 119, 193, 7, 231, 208,
            60,
        ],
    },
    RawVector {
        name: "B.10",
        alg: DigestAlg::Sha384,
        ikm: &[
            79, 61, 116, 77, 62, 68, 158, 6, 39, 191, 68, 152, 116, 56, 40, 248, 110, 99, 143, 96,
            98, 10, 126, 212, 167, 201, 181, 176, 115, 105, 28, 158, 201, 71, 40, 197, 136, 34,
            232, 39, 240, 246, 204, 248, 109, 188, 28, 174,
        ],
        info: &[
            48, 31, 238, 178, 94, 108, 168, 80, 62, 205, 130, 31, 29, 55, 135, 174, 191, 179, 208,
            236, 81, 139, 179, 17, 116, 245, 32, 155, 42, 193, 242, 142, 211, 230, 152, 115, 107,
            173, 16, 161, 142, 60, 189, 181, 220, 39, 187, 209, 45, 5, 139, 54, 219, 8, 146, 249,
            207, 208, 131, 0,
        ],
        okm: &[
            133, 239, 149, 5, 178, 48, 86, 94, 204, 242, 166, 74, 179, 222, 83, 229, 169, 28, 123,
            81,
        ],
    },
];

struct PurposeNonceVector {
    name: &'static str,
    ikm: &'static [u8],
    nonce: &'static [u8],
    okm: &'static [u8],
}

/// C.1–C.5 from `TestKDF_TestVectors.dfy`. All SHA-256, purpose is the
/// hierarchy label, L = 32.
const PURPOSE_NONCE_VECTORS: &[PurposeNonceVector] = &[
    PurposeNonceVector {
        name: "C.1",
        ikm: &[
            125, 201, 189, 252, 37, 52, 4, 124, 254, 99, 233, 235, 41, 123, 119, 82, 81, 73, 237,
            125, 74, 252, 233, 198, 68, 15, 53, 14, 97, 239, 62, 208,
        ],
        nonce: &[
            119, 218, 233, 62, 104, 155, 88, 29, 62, 6, 235, 1, 200, 211, 186, 2,
        ],
        okm: &[
            188, 232, 152, 114, 85, 137, 174, 192, 143, 152, 52, 179, 184, 15, 220, 63, 241, 115,
            144, 126, 85, 116, 231, 41, 253, 206, 18, 124, 247, 109, 183, 204,
        ],
    },
    PurposeNonceVector {
        name: "C.2",
        ikm: &[
            80, 22, 113, 23, 118, 68, 10, 32, 75, 169, 199, 192, 255, 220, 214, 60, 182, 1, 126,
            147, 171, 233, 110, 177, 35, 145, 217, 129, 30, 9, 80, 159,
        ],
        nonce: &[
            210, 241, 192, 158, 103, 66, 27, 35, 143, 66, 168, 189, 82, 171, 211, 252,
        ],
        okm: &[
            54, 206, 174, 72, 237, 133, 85, 156, 93, 53, 120, 152, 118, 82, 89, 33, 114, 98, 204,
            236, 138, 57, 162, 118, 85, 92, 199, 232, 240, 252, 92, 97,
        ],
    },
    PurposeNonceVector {
        name: "C.3",
        ikm: &[
            57, 90, 16, 46, 83, 54, 189, 241, 27, 242, 237, 236, 246, 66, 54, 226, 74, 112, 79,
            156, 208, 13, 148, 71, 117, 211, 139, 57, 73, 69, 122, 236,
        ],
        nonce: &[
            51, 15, 183, 124, 82, 229, 249, 86, 117, 148, 237, 162, 27, 243, 173, 108,
        ],
        okm: &[
            22, 55, 236, 141, 159, 163, 250, 236, 86, 47, 225, 103, 156, 225, 228, 146, 166, 45,
            244, 39, 136, 163, 205, 200, 116, 193, 20, 147, 112, 254, 210, 194,
        ],
    },
    PurposeNonceVector {
        name: "C.4",
        ikm: &[
            152, 192, 25, 223, 239, 154, 175, 67, 237, 250, 184, 146, 228, 243, 227, 1, 128, 247,
            228, 152, 142, 131, 149, 41, 60, 70, 244, 58, 166, 234, 86, 189,
        ],
        nonce: &[
            243, 160, 102, 127, 219, 137, 115, 38, 187, 216, 48, 80, 151, 168, 148, 71,
        ],
        okm: &[
            191, 112, 86, 234, 220, 233, 122, 154, 100, 188, 230, 238, 239, 155, 54, 32, 97, 35,
            51, 160, 121, 235, 42, 64, 145, 105, 15, 153, 162, 89, 9, 156,
        ],
    },
    PurposeNonceVector {
        name: "C.5",
        ikm: &[
            166, 236, 116, 51, 140, 189, 192, 175, 42, 154, 51, 26, 208, 149, 76, 159, 174, 162,
            207, 4, 108, 232, 196, 240, 12, 57, 228, 155, 97, 75, 42, 66,
        ],
        nonce: &[
            236, 169, 233, 45, 43, 25, 122, 243, 152, 191, 154, 55, 45, 134, 159, 220,
        ],
        okm: &[
            156, 11, 20, 251, 100, 227, 163, 161, 30, 45, 242, 2, 248, 246, 44, 11, 88, 132, 189,
            175, 95, 96, 61, 44, 98, 160, 212, 136, 140, 222, 57, 151,
        ],
    },
];

/// Build the NIST fixed-info: `Label || 0x00 || Context || L_be32` where
/// `L_be32` is the output length in **bits** as a big-endian u32.
fn build_fixed_info(label: &[u8], context: &[u8], okm_bytes: usize) -> Vec<u8> {
    let mut info = Vec::with_capacity(label.len() + 1 + context.len() + 4);
    info.extend_from_slice(label);
    info.push(0x00);
    info.extend_from_slice(context);
    let l_bits = u32::try_from(okm_bytes * 8).expect("L fits in u32");
    info.extend_from_slice(&l_bits.to_be_bytes());
    info
}

#[test]
fn test_kbkdf_ctr_hmac_raw_vectors() -> Result<(), Error> {
    for v in RAW_VECTORS {
        let mut okm = vec![0u8; v.okm.len()];
        kbkdf_ctr_hmac(v.alg, v.ikm, v.info, &mut okm)?;
        assert_eq!(okm, v.okm, "vector {}", v.name);
    }
    Ok(())
}

#[test]
fn test_kbkdf_ctr_hmac_purpose_nonce_vectors() -> Result<(), Error> {
    for v in PURPOSE_NONCE_VECTORS {
        let info = build_fixed_info(PURPOSE, v.nonce, v.okm.len());
        let mut okm = vec![0u8; v.okm.len()];
        kbkdf_ctr_hmac(DigestAlg::Sha256, v.ikm, &info, &mut okm)?;
        assert_eq!(okm, v.okm, "vector {}", v.name);
    }
    Ok(())
}

// Coverage extras — exercise the SHA-512 arm (not in Dafny) and the error
// path (`get_kbkdf_ctr_hmac_algorithm` return + `kbkdf_ctr_hmac` return).

#[test]
fn test_kbkdf_ctr_hmac_sha512_smoke() -> Result<(), Error> {
    // Verifies the DigestAlg -> KbkdfCtrHmacAlgorithmId mapping for the
    // SHA-512 arm, which the Dafny suite has no known-answer for.
    let ikm = [1u8; 32];
    let info = build_fixed_info(b"test", &[0u8; 8], 32);
    let mut okm = [0u8; 32];
    kbkdf_ctr_hmac(DigestAlg::Sha512, &ikm, &info, &mut okm)?;

    // No known-answer to compare against, so assert the property the API
    // does guarantee: the derivation is deterministic. Asserting the output
    // is non-zero would not be sound — nothing in the contract forbids an
    // all-zero derivation.
    let mut again = [0u8; 32];
    kbkdf_ctr_hmac(DigestAlg::Sha512, &ikm, &info, &mut again)?;
    assert_eq!(okm, again);
    Ok(())
}

#[test]
fn test_kbkdf_ctr_hmac_empty_okm() {
    // aws-lc-rs's kbkdf_ctr_hmac rejects a zero-length output. Exercise the
    // error branch.
    let ikm = [1u8; 32];
    let info = [0u8; 4];
    let mut okm: [u8; 0] = [];
    let err = kbkdf_ctr_hmac(DigestAlg::Sha256, &ikm, &info, &mut okm).unwrap_err();
    assert!(err.message.contains("kbkdf_ctr_hmac"));
}
