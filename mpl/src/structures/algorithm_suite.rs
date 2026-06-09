// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

//! Algorithm suite identifiers, suite specifications, and associated key newtypes.

use std::fmt;

// ============================================================================
// Algorithm suite ID enum
// ============================================================================

//= ../spec/framework/algorithm-suites.md#overview
//= type=implication
//# The algorithm suite defines the behaviors [supported formats](#supported-formats) MUST follow for cryptographic operations.
//
//= ../spec/framework/algorithm-suites.md#supported-format-algorithm-suites-enum
//= type=implication
//# The Material Providers Library MUST provide
//# a set of algorithm suite ENUM for each [supported format](#supported-format).
//
//= ../spec/framework/algorithm-suites.md#supported-algorithm-suites-enum
//= type=implication
//# The Material Providers Library MUST provide
//# an ENUM that is the super set of all the [supported format algorithm suites enum](#supported-format-algorithm-suites-enum)
//# called the Algorithm Suite ENUM.
//
//= ../spec/framework/algorithm-suites.md#supported-algorithm-suites-enum
//= type=implication
//# This means that different formats MAY have duplicate Format Algorithm Suite ENUM.
//
//= ../spec/framework/algorithm-suites.md#cbc
//= type=exception
//= reason=Out of scope for this MPL implementation; only the ESDK format is supported. DBE and S3EC algorithm suites and the cryptographic constructs unique to them are not implemented.
//# If specified to use CBC, the S3 Encryption Client MUST use CBC with the following specifics:
//
//= ../spec/framework/algorithm-suites.md#cbc
//= type=exception
//= reason=Out of scope for this MPL implementation; only the ESDK format is supported. DBE and S3EC algorithm suites and the cryptographic constructs unique to them are not implemented.
//# - CBC MUST only be used to decrypt existing ciphertexts.
//
//= ../spec/framework/algorithm-suites.md#cbc
//= type=exception
//= reason=Out of scope for this MPL implementation; only the ESDK format is supported. DBE and S3EC algorithm suites and the cryptographic constructs unique to them are not implemented.
//# - CBC MUST NOT be used to encrypt new ciphertexts.
//
//= ../spec/framework/algorithm-suites.md#ctr
//= type=exception
//= reason=Out of scope for this MPL implementation; only the ESDK format is supported. DBE and S3EC algorithm suites and the cryptographic constructs unique to them are not implemented.
//# If specified to use CTR, the S3 Encryption Client MUST use CTR with the following specifics:
//
//= ../spec/framework/algorithm-suites.md#ctr
//= type=exception
//= reason=Out of scope for this MPL implementation; only the ESDK format is supported. DBE and S3EC algorithm suites and the cryptographic constructs unique to them are not implemented.
//# - CTR MUST only be used to decrypt existing ciphertexts.
//
//= ../spec/framework/algorithm-suites.md#ctr
//= type=exception
//= reason=Out of scope for this MPL implementation; only the ESDK format is supported. DBE and S3EC algorithm suites and the cryptographic constructs unique to them are not implemented.
//# - CTR MUST NOT be used to encrypt new ciphertexts.
//
//= ../spec/framework/algorithm-suites.md#algorithm-suites-signature-settings
//= type=exception
//= reason=Out of scope for this MPL implementation; only the ESDK format is supported. DBE and S3EC algorithm suites and the cryptographic constructs unique to them are not implemented.
//# An algorithm suite with a symmetric signature algorithm MUST use [intermediate key wrapping](#intermediate-key-wrapping).
//
//= ../spec/framework/algorithm-suites.md#intermediate-key-wrapping
//= type=exception
//= reason=Out of scope for this MPL implementation; only the ESDK format is supported. DBE and S3EC algorithm suites and the cryptographic constructs unique to them are not implemented.
//# - For each encrypted data key, a distinct `intermediate key` MUST be generated using cryptographically secure random bytes.
//
//= ../spec/framework/algorithm-suites.md#intermediate-key-wrapping
//= type=exception
//= reason=Out of scope for this MPL implementation; only the ESDK format is supported. DBE and S3EC algorithm suites and the cryptographic constructs unique to them are not implemented.
//# This intermediate key MUST have length equal to the encryption key length of the algorithm suite.
//
//= ../spec/framework/algorithm-suites.md#intermediate-key-wrapping
//= type=exception
//= reason=Out of scope for this MPL implementation; only the ESDK format is supported. DBE and S3EC algorithm suites and the cryptographic constructs unique to them are not implemented.
//# - For each encrypted data key, a [symmetric signing key](./structures.md#symmetric-signing-key) MUST be derived from the `intermediate key`
//# using the key derivation algorithm in the algorithm suite, with the following specifics:
//
//= ../spec/framework/algorithm-suites.md#intermediate-key-wrapping
//= type=exception
//= reason=Out of scope for this MPL implementation; only the ESDK format is supported. DBE and S3EC algorithm suites and the cryptographic constructs unique to them are not implemented.
//# - For each encrypted data key, a `key encryption key` MUST be derived from the `intermediate key`
//# using the key derivation algorithm in the algorithm suite, with the following specifics:
//
//= ../spec/framework/algorithm-suites.md#intermediate-key-wrapping
//= type=exception
//= reason=Out of scope for this MPL implementation; only the ESDK format is supported. DBE and S3EC algorithm suites and the cryptographic constructs unique to them are not implemented.
//# - The [EDK ciphertext](./structures.md#ciphertext) MUST be the following serialization:
//
//= ../spec/framework/algorithm-suites.md#wrapped-plaintext-data-key
//= type=exception
//= reason=Out of scope for this MPL implementation; only the ESDK format is supported. DBE and S3EC algorithm suites and the cryptographic constructs unique to them are not implemented.
//# The wrapped plaintext data key MUST be the result of the following AES GCM 256 Encrypt operation:
//
//= ../spec/framework/algorithm-suites.md#wrapped-plaintext-data-key
//= type=exception
//= reason=Out of scope for this MPL implementation; only the ESDK format is supported. DBE and S3EC algorithm suites and the cryptographic constructs unique to them are not implemented.
//# This value MUST be equal to the algorithm suite's encryption key length + 16.
//
//= ../spec/framework/algorithm-suites.md#symmetric-signature-algorithm
//= type=exception
//= reason=Out of scope for this MPL implementation; only the ESDK format is supported. DBE and S3EC algorithm suites and the cryptographic constructs unique to them are not implemented.
//# - Symmetric signatures MUST be generated using the specified symmetric signature algorithm.
//
//= ../spec/framework/algorithm-suites.md#symmetric-signature-algorithm
//= type=exception
//= reason=Out of scope for this MPL implementation; only the ESDK format is supported. DBE and S3EC algorithm suites and the cryptographic constructs unique to them are not implemented.
//# - Symmetric signatures MUST be verified using the specified symmetric signature algorithm.
//
//= ../spec/framework/algorithm-suites.md#symmetric-signature-algorithm
//= type=exception
//= reason=Out of scope for this MPL implementation; only the ESDK format is supported. DBE and S3EC algorithm suites and the cryptographic constructs unique to them are not implemented.
//# - The algorithm suite MUST also use [Intermediate Key Wrapping](#intermediate-key-wrapping).
/// Identifies an algorithm suite supported by this Material Providers Library.
///
/// This enum exposes only the ESDK supported formats; DBE and S3EC suites are
/// not implemented (see the `type=exception` annotations on this declaration).
/// Construct an `AlgorithmSuite` from a variant via [`Self::specification`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum AlgorithmSuiteId {
    /// 00 14 — ESDK.ALG_AES_128_GCM_IV12_TAG16_NO_KDF
    AlgAes128GcmIv12Tag16NoKdf,
    /// 00 46 — ESDK.ALG_AES_192_GCM_IV12_TAG16_NO_KDF
    AlgAes192GcmIv12Tag16NoKdf,
    /// 00 78 — ESDK.ALG_AES_256_GCM_IV12_TAG16_NO_KDF
    AlgAes256GcmIv12Tag16NoKdf,
    /// 01 14 — ESDK.ALG_AES_128_GCM_IV12_TAG16_HKDF_SHA256
    AlgAes128GcmIv12Tag16HkdfSha256,
    /// 01 46 — ESDK.ALG_AES_192_GCM_IV12_TAG16_HKDF_SHA256
    AlgAes192GcmIv12Tag16HkdfSha256,
    /// 01 78 — ESDK.ALG_AES_256_GCM_IV12_TAG16_HKDF_SHA256
    AlgAes256GcmIv12Tag16HkdfSha256,
    /// 02 14 — ESDK.ALG_AES_128_GCM_IV12_TAG16_HKDF_SHA256_ECDSA_P256
    AlgAes128GcmIv12Tag16HkdfSha256EcdsaP256,
    /// 03 46 — ESDK.ALG_AES_192_GCM_IV12_TAG16_HKDF_SHA384_ECDSA_P384
    AlgAes192GcmIv12Tag16HkdfSha384EcdsaP384,
    /// 03 78 — ESDK.ALG_AES_256_GCM_IV12_TAG16_HKDF_SHA384_ECDSA_P384
    AlgAes256GcmIv12Tag16HkdfSha384EcdsaP384,
    /// 04 78 — ESDK.ALG_AES_256_GCM_HKDF_SHA512_COMMIT_KEY
    AlgAes256GcmHkdfSha512CommitKey,
    /// 05 78 — ESDK.ALG_AES_256_GCM_HKDF_SHA512_COMMIT_KEY_ECDSA_P384
    AlgAes256GcmHkdfSha512CommitKeyEcdsaP384,
}

impl AlgorithmSuiteId {
    /// Materialize the [`AlgorithmSuite`] specification table for this suite ID.
    pub const fn specification(self) -> AlgorithmSuite {
        match self {
            Self::AlgAes128GcmIv12Tag16NoKdf => AlgorithmSuite {
                //= ../spec/framework/algorithm-suites.md#algorithm-suite-id
                //# A 2-byte hex value that MUST uniquely identify an algorithm suite.
                //
                //= ../spec/framework/algorithm-suites.md#algorithm-suite-id
                //# This 2-byte value SHOULD be used to bind algorithm suites to ciphertext.
                id: [0x00, 0x14],
                //= ../spec/framework/algorithm-suites.md#gcm
                //# If specified to use GCM, the AWS Encryption SDK MUST use GCM with the following specifics:
                encryption_algorithm: EncryptionAlgorithm::Aes,
                encryption_algorithm_mode: EncryptionAlgorithmMode::Gcm,
                //= ../spec/framework/algorithm-suites.md#encryption-algorithm
                //# The length of the input encryption key MUST equal the [encryption key length](#encryption-key-length) specified by the algorithm suite.
                encryption_key_length: 16,
                //= ../spec/framework/algorithm-suites.md#encryption-algorithm-mode
                //# The length of the input IV MUST equal the IV length specified by the algorithm suite.
                iv_length: 12,
                //= ../spec/framework/algorithm-suites.md#encryption-algorithm-mode
                //# The length of the authentication tag MUST equal the authentication tag length specified by the algorithm suite.
                authentication_tag_length: 16,
                //= ../spec/framework/algorithm-suites.md#identity-kdf
                //= type=implication
                //# The Identity KDF MUST take a byte sequence as input,
                //# and MUST return the input, unchanged, as output.
                //
                //= ../spec/framework/algorithm-suites.md#identity-kdf
                //= type=implication
                //# If included in the algorithm suite,
                //# the algorithm suite's encryption key length MUST equal the algorithm suite's [key derivation input length](#key-derivation-input-length).
                //
                //= ../spec/framework/algorithm-suites.md#encryption-key-derivation-algorithm
                //# The specified KDF algorithm MUST be used to generate the encryption algorithm encryption key input.
                encryption_kdf: KeyDerivationAlgorithm::IdentityKdf,
                commit_kdf: None,
                asymmetric_signature_algorithm: None,
                symmetric_signature_algorithm: None,
                //= ../spec/framework/algorithm-suites.md#message-format-version
                //# This MUST be used to branch any serialization/deserialization logic in [supported formats](#supported-formats).
                message_format_version: 0x01,
                //= ../spec/framework/algorithm-suites.md#algorithm-suite-data-length
                //# The field MAY be length 0.
                algorithm_suite_data_length: 0,
            },
            Self::AlgAes192GcmIv12Tag16NoKdf => AlgorithmSuite {
                id: [0x00, 0x46],
                encryption_algorithm: EncryptionAlgorithm::Aes,
                encryption_algorithm_mode: EncryptionAlgorithmMode::Gcm,
                encryption_key_length: 24,
                iv_length: 12,
                authentication_tag_length: 16,
                encryption_kdf: KeyDerivationAlgorithm::IdentityKdf,
                commit_kdf: None,
                asymmetric_signature_algorithm: None,
                symmetric_signature_algorithm: None,
                message_format_version: 0x01,
                algorithm_suite_data_length: 0,
            },
            Self::AlgAes256GcmIv12Tag16NoKdf => AlgorithmSuite {
                id: [0x00, 0x78],
                encryption_algorithm: EncryptionAlgorithm::Aes,
                encryption_algorithm_mode: EncryptionAlgorithmMode::Gcm,
                encryption_key_length: 32,
                iv_length: 12,
                authentication_tag_length: 16,
                encryption_kdf: KeyDerivationAlgorithm::IdentityKdf,
                commit_kdf: None,
                asymmetric_signature_algorithm: None,
                symmetric_signature_algorithm: None,
                message_format_version: 0x01,
                algorithm_suite_data_length: 0,
            },
            Self::AlgAes128GcmIv12Tag16HkdfSha256 => AlgorithmSuite {
                id: [0x01, 0x14],
                encryption_algorithm: EncryptionAlgorithm::Aes,
                encryption_algorithm_mode: EncryptionAlgorithmMode::Gcm,
                encryption_key_length: 16,
                iv_length: 12,
                authentication_tag_length: 16,
                encryption_kdf: KeyDerivationAlgorithm::HkdfSha256,
                commit_kdf: None,
                asymmetric_signature_algorithm: None,
                symmetric_signature_algorithm: None,
                message_format_version: 0x01,
                algorithm_suite_data_length: 0,
            },
            Self::AlgAes192GcmIv12Tag16HkdfSha256 => AlgorithmSuite {
                id: [0x01, 0x46],
                encryption_algorithm: EncryptionAlgorithm::Aes,
                encryption_algorithm_mode: EncryptionAlgorithmMode::Gcm,
                encryption_key_length: 24,
                iv_length: 12,
                authentication_tag_length: 16,
                encryption_kdf: KeyDerivationAlgorithm::HkdfSha256,
                commit_kdf: None,
                asymmetric_signature_algorithm: None,
                symmetric_signature_algorithm: None,
                message_format_version: 0x01,
                algorithm_suite_data_length: 0,
            },
            Self::AlgAes256GcmIv12Tag16HkdfSha256 => AlgorithmSuite {
                id: [0x01, 0x78],
                encryption_algorithm: EncryptionAlgorithm::Aes,
                encryption_algorithm_mode: EncryptionAlgorithmMode::Gcm,
                encryption_key_length: 32,
                iv_length: 12,
                authentication_tag_length: 16,
                encryption_kdf: KeyDerivationAlgorithm::HkdfSha256,
                commit_kdf: None,
                asymmetric_signature_algorithm: None,
                symmetric_signature_algorithm: None,
                message_format_version: 0x01,
                algorithm_suite_data_length: 0,
            },
            Self::AlgAes128GcmIv12Tag16HkdfSha256EcdsaP256 => AlgorithmSuite {
                id: [0x02, 0x14],
                encryption_algorithm: EncryptionAlgorithm::Aes,
                encryption_algorithm_mode: EncryptionAlgorithmMode::Gcm,
                encryption_key_length: 16,
                iv_length: 12,
                authentication_tag_length: 16,
                encryption_kdf: KeyDerivationAlgorithm::HkdfSha256,
                commit_kdf: None,
                //= ../spec/framework/algorithm-suites.md#asymmetric-signature-algorithm
                //# - Asymmetric signatures MUST be generated using the specified asymmetric signature algorithm.
                //
                //= ../spec/framework/algorithm-suites.md#asymmetric-signature-algorithm
                //# - Asymmetric signatures MUST be verified using the specified asymmetric signature algorithm.
                asymmetric_signature_algorithm: Some(AsymmetricSignatureAlgorithm::EcdsaP256),
                symmetric_signature_algorithm: None,
                message_format_version: 0x01,
                algorithm_suite_data_length: 0,
            },
            Self::AlgAes192GcmIv12Tag16HkdfSha384EcdsaP384 => AlgorithmSuite {
                id: [0x03, 0x46],
                encryption_algorithm: EncryptionAlgorithm::Aes,
                encryption_algorithm_mode: EncryptionAlgorithmMode::Gcm,
                encryption_key_length: 24,
                iv_length: 12,
                authentication_tag_length: 16,
                encryption_kdf: KeyDerivationAlgorithm::HkdfSha384,
                commit_kdf: None,
                asymmetric_signature_algorithm: Some(AsymmetricSignatureAlgorithm::EcdsaP384),
                symmetric_signature_algorithm: None,
                message_format_version: 0x01,
                algorithm_suite_data_length: 0,
            },
            Self::AlgAes256GcmIv12Tag16HkdfSha384EcdsaP384 => AlgorithmSuite {
                id: [0x03, 0x78],
                encryption_algorithm: EncryptionAlgorithm::Aes,
                encryption_algorithm_mode: EncryptionAlgorithmMode::Gcm,
                encryption_key_length: 32,
                iv_length: 12,
                authentication_tag_length: 16,
                encryption_kdf: KeyDerivationAlgorithm::HkdfSha384,
                commit_kdf: None,
                asymmetric_signature_algorithm: Some(AsymmetricSignatureAlgorithm::EcdsaP384),
                symmetric_signature_algorithm: None,
                message_format_version: 0x01,
                algorithm_suite_data_length: 0,
            },
            Self::AlgAes256GcmHkdfSha512CommitKey => AlgorithmSuite {
                id: [0x04, 0x78],
                encryption_algorithm: EncryptionAlgorithm::Aes,
                encryption_algorithm_mode: EncryptionAlgorithmMode::Gcm,
                encryption_key_length: 32,
                iv_length: 12,
                authentication_tag_length: 16,
                encryption_kdf: KeyDerivationAlgorithm::HkdfSha512,
                //= ../spec/framework/algorithm-suites.md#commit-key-derivation-algorithm
                //# The specified KDF algorithm MUST be used to generate the [commit key](#commit-key).
                commit_kdf: Some(KeyDerivationAlgorithm::HkdfSha512),
                asymmetric_signature_algorithm: None,
                symmetric_signature_algorithm: None,
                message_format_version: 0x02,
                //= ../spec/framework/algorithm-suites.md#supported-algorithm-suite-data
                //# - Algorithm Suite 04 78 MUST store the commit key in the suite data
                algorithm_suite_data_length: 32,
            },
            Self::AlgAes256GcmHkdfSha512CommitKeyEcdsaP384 => AlgorithmSuite {
                id: [0x05, 0x78],
                encryption_algorithm: EncryptionAlgorithm::Aes,
                encryption_algorithm_mode: EncryptionAlgorithmMode::Gcm,
                encryption_key_length: 32,
                iv_length: 12,
                authentication_tag_length: 16,
                encryption_kdf: KeyDerivationAlgorithm::HkdfSha512,
                commit_kdf: Some(KeyDerivationAlgorithm::HkdfSha512),
                asymmetric_signature_algorithm: Some(AsymmetricSignatureAlgorithm::EcdsaP384),
                symmetric_signature_algorithm: None,
                message_format_version: 0x02,
                //= ../spec/framework/algorithm-suites.md#supported-algorithm-suite-data
                //# - Algorithm Suite 05 78 MUST store the commit key in the suite data
                algorithm_suite_data_length: 32,
            },
        }
    }

    /// Returns the on-wire 2-byte algorithm suite identifier.
    ///
    /// The byte pair is unique across the supported-suites table. Reserved
    /// value `00 00` is never produced.
    //= ../spec/framework/algorithm-suites.md#supported-algorithm-suites
    //# The value `00 00` is reserved
    //# and MUST NOT be used
    //# as an Algorithm Suite ID in the future.
    //
    //= ../spec/framework/algorithm-suites.md#supported-algorithm-suites
    //# Algorithm Suite ID MUST be a unique hex value across all supported algorithm suites.
    pub const fn id_bytes(self) -> [u8; 2] {
        self.specification().id
    }

    /// Returns true when this suite has an asymmetric signature algorithm.
    pub const fn has_asymmetric_signing(self) -> bool {
        self.specification()
            .asymmetric_signature_algorithm
            .is_some()
    }

    /// Returns true when this suite has a symmetric signature algorithm.
    ///
    /// No ESDK suite includes a symmetric signature algorithm; this is always
    /// `false` for any constructible variant of `AlgorithmSuiteId`. The
    /// MUST-NOT-generate / MUST-NOT-verify clauses are enforced at the
    /// `EncryptionMaterials::new` / `DecryptionMaterials::new` boundary.
    pub const fn has_symmetric_signing(self) -> bool {
        self.specification().symmetric_signature_algorithm.is_some()
    }
}

// ============================================================================
// Algorithm suite specification table (opaque struct)
// ============================================================================

/// The set of cryptographic parameters defined by an [`AlgorithmSuiteId`].
///
/// This struct is opaque: there is no public constructor. Construct one by
/// calling [`AlgorithmSuiteId::specification`] on a chosen suite.
//= ../spec/framework/algorithm-suites.md#structure
//= type=implication
//# The fields described below are REQUIRED to be specified by algorithm suites, unless otherwise specified.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AlgorithmSuite {
    id: [u8; 2],
    encryption_algorithm: EncryptionAlgorithm,
    encryption_algorithm_mode: EncryptionAlgorithmMode,
    encryption_key_length: usize,
    iv_length: usize,
    authentication_tag_length: usize,
    encryption_kdf: KeyDerivationAlgorithm,
    commit_kdf: Option<KeyDerivationAlgorithm>,
    //= ../spec/framework/algorithm-suites.md#asymmetric-signature-algorithm
    //= type=implication
    //# This field is OPTIONAL.
    asymmetric_signature_algorithm: Option<AsymmetricSignatureAlgorithm>,
    //= ../spec/framework/algorithm-suites.md#symmetric-signature-algorithm
    //= type=implication
    //# This field is OPTIONAL.
    symmetric_signature_algorithm: Option<SymmetricSignatureAlgorithm>,
    message_format_version: u8,
    algorithm_suite_data_length: usize,
}

impl AlgorithmSuite {
    /// Returns the suite's 2-byte algorithm suite identifier.
    pub const fn id(&self) -> [u8; 2] {
        self.id
    }

    pub const fn encryption_algorithm(&self) -> EncryptionAlgorithm {
        self.encryption_algorithm
    }

    pub const fn encryption_algorithm_mode(&self) -> EncryptionAlgorithmMode {
        self.encryption_algorithm_mode
    }

    /// Returns the encryption key length, in bytes.
    pub const fn encryption_key_length(&self) -> usize {
        self.encryption_key_length
    }

    /// Returns the IV length, in bytes (12 for every ESDK suite).
    pub const fn iv_length(&self) -> usize {
        self.iv_length
    }

    /// Returns the authentication tag length, in bytes (16 for every ESDK suite).
    pub const fn authentication_tag_length(&self) -> usize {
        self.authentication_tag_length
    }

    pub const fn encryption_kdf(&self) -> KeyDerivationAlgorithm {
        self.encryption_kdf
    }

    pub const fn commit_kdf(&self) -> Option<KeyDerivationAlgorithm> {
        self.commit_kdf
    }

    /// Returns true when this suite has a commitment KDF (i.e. its
    /// [Key Commitment] value is True). Convenience predicate so callers can
    /// match the spec phrasing literally.
    ///
    /// [Key Commitment]: ../../../spec/framework/algorithm-suites.md#algorithm-suites-encryption-key-derivation-settings
    pub const fn key_commitment(&self) -> bool {
        self.commit_kdf.is_some()
    }

    pub const fn asymmetric_signature_algorithm(&self) -> Option<AsymmetricSignatureAlgorithm> {
        self.asymmetric_signature_algorithm
    }

    pub const fn symmetric_signature_algorithm(&self) -> Option<SymmetricSignatureAlgorithm> {
        self.symmetric_signature_algorithm
    }

    /// Returns the message format version byte (`0x01` for V1, `0x02` for V2).
    pub const fn message_format_version(&self) -> u8 {
        self.message_format_version
    }

    /// Returns the algorithm suite data field length, in bytes.
    pub const fn algorithm_suite_data_length(&self) -> usize {
        self.algorithm_suite_data_length
    }

    /// Required length of a private signing key (scalar) for this suite, in
    /// bytes. Returns `None` for non-signing suites.
    pub const fn signing_key_length(&self) -> Option<usize> {
        match self.asymmetric_signature_algorithm {
            Some(AsymmetricSignatureAlgorithm::EcdsaP256) => Some(SIGNING_KEY_LEN_P256),
            Some(AsymmetricSignatureAlgorithm::EcdsaP384) => Some(SIGNING_KEY_LEN_P384),
            None => None,
        }
    }

    /// Required length of a verification key (public point, SEC1 uncompressed
    /// `0x04 || X || Y`) for this suite, in bytes. Returns `None` for
    /// non-signing suites.
    pub const fn verification_key_length(&self) -> Option<usize> {
        match self.asymmetric_signature_algorithm {
            Some(AsymmetricSignatureAlgorithm::EcdsaP256) => Some(VERIFICATION_KEY_LEN_P256),
            Some(AsymmetricSignatureAlgorithm::EcdsaP384) => Some(VERIFICATION_KEY_LEN_P384),
            None => None,
        }
    }
}

// Private signing key (curve scalar) lengths
const SIGNING_KEY_LEN_P256: usize = 32;
const SIGNING_KEY_LEN_P384: usize = 48;

// SEC1-uncompressed public key lengths: 1 byte tag + 2 * coord_len
const VERIFICATION_KEY_LEN_P256: usize = 65;
const VERIFICATION_KEY_LEN_P384: usize = 97;

// ============================================================================
// Encryption / KDF / signature algorithm enums
// ============================================================================

/// Block cipher encryption algorithm. Always AES for every ESDK suite.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum EncryptionAlgorithm {
    Aes,
}

/// Block cipher mode of operation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum EncryptionAlgorithmMode {
    Gcm,
}

/// Key derivation algorithm.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum KeyDerivationAlgorithm {
    /// Identity KDF — input bytes are returned unchanged.
    IdentityKdf,
    HkdfSha256,
    HkdfSha384,
    HkdfSha512,
}

/// Asymmetric signature algorithm.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum AsymmetricSignatureAlgorithm {
    /// ECDSA with P-256 curve and SHA-256.
    EcdsaP256,
    /// ECDSA with P-384 curve and SHA-384.
    EcdsaP384,
}

/// Symmetric signature algorithm. No ESDK suite uses one; the variant exists so
/// `Option<SymmetricSignatureAlgorithm>` can express "OPTIONAL" per spec.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum SymmetricSignatureAlgorithm {
    HmacSha384,
}

// ============================================================================
// Cryptographic format identifier (ESDK only)
// ============================================================================

//= ../spec/framework/algorithm-suites.md#supported-formats
//= type=implication
//# Both short and long name MUST be unique.
/// Cryptographic format identifier. Only the ESDK format is implemented in this
/// MPL — uniqueness of short and long name is trivial (single variant).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Format {
    /// AWS Encryption SDK Message Format / "ESDK".
    Esdk,
}

impl Format {
    pub const fn long_name(self) -> &'static str {
        match self {
            Self::Esdk => "AWS Encryption SDK Message Format",
        }
    }

    pub const fn short_name(self) -> &'static str {
        match self {
            Self::Esdk => "ESDK",
        }
    }
}

// ============================================================================
// Key newtypes
// ============================================================================

/// Plaintext data key (secret).
#[derive(Clone, PartialEq, Eq)]
pub struct PlaintextDataKey(Vec<u8>);

impl PlaintextDataKey {
    pub fn new(bytes: Vec<u8>) -> Self {
        Self(bytes)
    }

    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }

    pub fn len(&self) -> usize {
        self.0.len()
    }

    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    /// Zero the plaintext data key material.
    //= ../spec/framework/structures.md#plaintext-data-key
    //# The plaintext data key SHOULD offer an interface to zero the plaintext data key.
    //
    //= ../spec/framework/structures.md#plaintext-data-key-1
    //# The plaintext data key SHOULD offer an interface to zero the plaintext data key.
    pub fn zeroize(&mut self) {
        let ptr = self.0.as_mut_ptr();
        let len = self.0.len();
        for i in 0..len {
            // SAFETY: we're within bounds of the allocated Vec
            unsafe {
                core::ptr::write_volatile(ptr.add(i), 0u8);
            }
        }
    }
}

impl fmt::Debug for PlaintextDataKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "PlaintextDataKey([REDACTED; {} bytes])", self.0.len())
    }
}

/// Signing key (secret).
#[derive(Clone, PartialEq, Eq)]
pub struct SigningKey(Vec<u8>);

impl SigningKey {
    pub fn new(bytes: Vec<u8>) -> Self {
        Self(bytes)
    }

    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }

    pub fn len(&self) -> usize {
        self.0.len()
    }

    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
}

impl fmt::Debug for SigningKey {
    //= ../spec/framework/structures.md#signing-key
    //# The value of this key MUST be kept secret.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "SigningKey([REDACTED; {} bytes])", self.0.len())
    }
}

/// Verification key (public, not secret).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerificationKey(Vec<u8>);

impl VerificationKey {
    pub fn new(bytes: Vec<u8>) -> Self {
        Self(bytes)
    }

    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }

    pub fn len(&self) -> usize {
        self.0.len()
    }

    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
}

/// Symmetric signing key (secret).
#[derive(Clone, PartialEq, Eq)]
pub struct SymmetricSigningKey(Vec<u8>);

impl SymmetricSigningKey {
    pub fn new(bytes: Vec<u8>) -> Self {
        Self(bytes)
    }

    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }

    pub fn len(&self) -> usize {
        self.0.len()
    }

    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
}

impl fmt::Debug for SymmetricSigningKey {
    //= ../spec/framework/structures.md#symmetric-signing-keys
    //# The value of keys in this list MUST be kept secret.
    //
    //= ../spec/framework/structures.md#symmetric-signing-key
    //# This value MUST be kept secret.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "SymmetricSigningKey([REDACTED; {} bytes])", self.0.len())
    }
}
