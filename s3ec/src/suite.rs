// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

//! Cryptographic parameters for the S3EC content-encryption algorithm suites.
//!
//! Each [`EncryptionAlgorithm`] carries a fixed set of cryptographic
//! parameters (key length, IV length, tag length, suite ID, and — for
//! committing suites — the key-commitment and message-ID lengths). These
//! values are interoperable with the other S3EC language implementations and
//! are sourced from the algorithm-suite definitions shared across the project.

use crate::config::EncryptionAlgorithm;

impl EncryptionAlgorithm {
    /// The two-byte algorithm suite identifier.
    ///
    /// `0x0070` for AES-CBC, `0x0072` for non-committing AES-GCM, and
    /// `0x0073` for the HKDF key-committing AES-GCM suite.
    pub fn suite_id(self) -> u16 {
        match self {
            Self::AlgAes256CbcIv16NoKdf => 0x0070,
            Self::AlgAes256GcmIv12Tag16NoKdf => 0x0072,
            Self::AlgAes256GcmHkdfSha512CommitKey => 0x0073,
        }
    }

    /// The content data-key length in bytes. All supported suites use a
    /// 256-bit (32-byte) AES key.
    pub fn data_key_length(self) -> usize {
        32
    }

    /// The IV / nonce length in bytes.
    ///
    /// GCM suites use a 12-byte IV; legacy CBC uses a 16-byte IV.
    pub fn iv_length(self) -> usize {
        match self {
            Self::AlgAes256CbcIv16NoKdf => 16,
            Self::AlgAes256GcmIv12Tag16NoKdf | Self::AlgAes256GcmHkdfSha512CommitKey => 12,
        }
    }

    /// The authentication-tag length in bytes for AEAD suites. CBC has no
    /// authentication tag and returns `0`.
    pub fn tag_length(self) -> usize {
        match self {
            Self::AlgAes256CbcIv16NoKdf => 0,
            Self::AlgAes256GcmIv12Tag16NoKdf | Self::AlgAes256GcmHkdfSha512CommitKey => 16,
        }
    }

    /// The key-commitment value length in bytes (committing suites only).
    pub fn commitment_length(self) -> usize {
        match self {
            Self::AlgAes256GcmHkdfSha512CommitKey => 28,
            _ => 0,
        }
    }

    /// The message-ID (HKDF salt) length in bytes (committing suites only).
    pub fn message_id_length(self) -> usize {
        match self {
            Self::AlgAes256GcmHkdfSha512CommitKey => 28,
            _ => 0,
        }
    }

    /// The algorithm suite ID as the big-endian bytes used as AAD and HKDF
    /// info for committing suites. Non-committing suites use no suite-ID AAD
    /// and return an empty slice.
    pub fn suite_id_bytes(self) -> Vec<u8> {
        match self {
            Self::AlgAes256GcmHkdfSha512CommitKey => self.suite_id().to_be_bytes().to_vec(),
            _ => Vec::new(),
        }
    }

    //= ../spec/s3-encryption/key-derivation.md#hkdf-operation
    //# This means that the IV for ALG_AES_256_GCM_HKDF_SHA512_COMMIT_KEY, which is 12 bytes long, would be `[0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01 ]`.
    /// The fixed all-`0x01` IV used for content encryption by the committing
    /// AES-GCM suite (in place of a generated IV).
    pub fn committing_iv(self) -> Vec<u8> {
        //= ../spec/s3-encryption/key-derivation.md#hkdf-operation
        //# When encrypting or decrypting with ALG_AES_256_GCM_HKDF_SHA512_COMMIT_KEY,
        //# the IV used in the AES-GCM content encryption/decryption MUST consist entirely of bytes with the value 0x01.
        //
        //= ../spec/s3-encryption/key-derivation.md#hkdf-operation
        //# The IV's total length MUST match the IV length defined by the algorithm suite.
        vec![0x01u8; self.iv_length()]
    }

    /// The `x-amz-cek-alg` (V2) / `x-amz-c` (V3) content-cipher metadata value
    /// for this suite.
    pub fn content_cipher_value(self) -> String {
        match self {
            Self::AlgAes256CbcIv16NoKdf => "AES/CBC/PKCS5Padding".to_string(),
            Self::AlgAes256GcmIv12Tag16NoKdf => "AES/GCM/NoPadding".to_string(),
            // The V3 content cipher value is the integer suite ID as a string.
            Self::AlgAes256GcmHkdfSha512CommitKey => self.suite_id().to_string(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn gcm_no_kdf_parameters() {
        let alg = EncryptionAlgorithm::AlgAes256GcmIv12Tag16NoKdf;
        assert_eq!(alg.suite_id(), 0x0072);
        assert_eq!(alg.iv_length(), 12);
        assert_eq!(alg.tag_length(), 16);
        assert_eq!(alg.data_key_length(), 32);
        assert!(!alg.is_committing());
        assert!(alg.suite_id_bytes().is_empty());
        assert_eq!(alg.content_cipher_value(), "AES/GCM/NoPadding");
    }

    #[test]
    fn committing_parameters() {
        let alg = EncryptionAlgorithm::AlgAes256GcmHkdfSha512CommitKey;
        assert_eq!(alg.suite_id(), 0x0073);
        assert_eq!(alg.iv_length(), 12);
        assert_eq!(alg.tag_length(), 16);
        assert_eq!(alg.commitment_length(), 28);
        assert_eq!(alg.message_id_length(), 28);
        assert!(alg.is_committing());
        assert_eq!(alg.suite_id_bytes(), vec![0x00, 0x73]);
        // The V3 content cipher value is the decimal suite ID "115" (0x0073).
        assert_eq!(alg.content_cipher_value(), "115");
    }

    #[test]
    fn committing_iv_is_all_ones() {
        let alg = EncryptionAlgorithm::AlgAes256GcmHkdfSha512CommitKey;

        //= ../spec/s3-encryption/key-derivation.md#hkdf-operation
        //= type=test
        //# This means that the IV for ALG_AES_256_GCM_HKDF_SHA512_COMMIT_KEY, which is 12 bytes long, would be `[0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01 ]`.
        //
        //= ../spec/s3-encryption/key-derivation.md#hkdf-operation
        //= type=test
        //# When encrypting or decrypting with ALG_AES_256_GCM_HKDF_SHA512_COMMIT_KEY,
        //# the IV used in the AES-GCM content encryption/decryption MUST consist entirely of bytes with the value 0x01.
        assert_eq!(alg.committing_iv(), vec![0x01u8; 12]);

        //= ../spec/s3-encryption/key-derivation.md#hkdf-operation
        //= type=test
        //# The IV's total length MUST match the IV length defined by the algorithm suite.
        assert_eq!(alg.committing_iv().len(), alg.iv_length());
    }
}
