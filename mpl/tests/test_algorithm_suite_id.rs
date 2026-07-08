// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

//! Tests for `AlgorithmSuiteId`, the materialized `AlgorithmSuite` spec table,
//! and the `Format` enum. Each test asserts a property derived directly from
//! the algorithm-suites.md spec tables — hex IDs, encryption key lengths, IV
//! lengths, KDF / commit-KDF mappings, asymmetric-signature-algorithm
//! mappings, message format versions, and suite-data lengths.

use std::collections::HashSet;

use aws_crypto_mpl::structures::{
    AlgorithmSuiteId, AsymmetricSignatureAlgorithm, EncryptionAlgorithm, EncryptionAlgorithmMode,
    Format, KeyDerivationAlgorithm,
};

/// All 11 ESDK algorithm suite variants in the order their hex IDs appear in
/// the spec table (ascending).
const ALL_SUITES: [AlgorithmSuiteId; 11] = [
    AlgorithmSuiteId::AlgAes128GcmIv12Tag16NoKdf,
    AlgorithmSuiteId::AlgAes192GcmIv12Tag16NoKdf,
    AlgorithmSuiteId::AlgAes256GcmIv12Tag16NoKdf,
    AlgorithmSuiteId::AlgAes128GcmIv12Tag16HkdfSha256,
    AlgorithmSuiteId::AlgAes192GcmIv12Tag16HkdfSha256,
    AlgorithmSuiteId::AlgAes256GcmIv12Tag16HkdfSha256,
    AlgorithmSuiteId::AlgAes128GcmIv12Tag16HkdfSha256EcdsaP256,
    AlgorithmSuiteId::AlgAes192GcmIv12Tag16HkdfSha384EcdsaP384,
    AlgorithmSuiteId::AlgAes256GcmIv12Tag16HkdfSha384EcdsaP384,
    AlgorithmSuiteId::AlgAes256GcmHkdfSha512CommitKey,
    AlgorithmSuiteId::AlgAes256GcmHkdfSha512CommitKeyEcdsaP384,
];

// --- Hex IDs and uniqueness ---

#[test]
fn test_hex_ids_match_spec_table() {
    // Mapping is taken straight from the spec's Supported Algorithm Suites table.
    let expected: [(AlgorithmSuiteId, [u8; 2]); 11] = [
        (AlgorithmSuiteId::AlgAes128GcmIv12Tag16NoKdf, [0x00, 0x14]),
        (AlgorithmSuiteId::AlgAes192GcmIv12Tag16NoKdf, [0x00, 0x46]),
        (AlgorithmSuiteId::AlgAes256GcmIv12Tag16NoKdf, [0x00, 0x78]),
        (
            AlgorithmSuiteId::AlgAes128GcmIv12Tag16HkdfSha256,
            [0x01, 0x14],
        ),
        (
            AlgorithmSuiteId::AlgAes192GcmIv12Tag16HkdfSha256,
            [0x01, 0x46],
        ),
        (
            AlgorithmSuiteId::AlgAes256GcmIv12Tag16HkdfSha256,
            [0x01, 0x78],
        ),
        (
            AlgorithmSuiteId::AlgAes128GcmIv12Tag16HkdfSha256EcdsaP256,
            [0x02, 0x14],
        ),
        (
            AlgorithmSuiteId::AlgAes192GcmIv12Tag16HkdfSha384EcdsaP384,
            [0x03, 0x46],
        ),
        (
            AlgorithmSuiteId::AlgAes256GcmIv12Tag16HkdfSha384EcdsaP384,
            [0x03, 0x78],
        ),
        (
            AlgorithmSuiteId::AlgAes256GcmHkdfSha512CommitKey,
            [0x04, 0x78],
        ),
        (
            AlgorithmSuiteId::AlgAes256GcmHkdfSha512CommitKeyEcdsaP384,
            [0x05, 0x78],
        ),
    ];

    for (suite, bytes) in expected {
        assert_eq!(
            suite.id_bytes(),
            bytes,
            "id_bytes for {:?} must equal {:02X?}",
            suite,
            bytes
        );
    }
}

#[test]
fn test_hex_ids_are_unique_across_all_suites() {
    //
    let mut seen = HashSet::new();
    for suite in ALL_SUITES {
        let id = suite.id_bytes();
        assert!(
            seen.insert(id),
            "hex id {:02X?} appears more than once across the suite enum",
            id
        );
    }
    assert_eq!(seen.len(), 11, "expected 11 unique IDs across all variants");
}

#[test]
fn test_reserved_id_00_00_is_not_used() {
    for suite in ALL_SUITES {
        let id = suite.id_bytes();
        assert_ne!(
            id,
            [0x00, 0x00],
            "no constructible AlgorithmSuiteId variant may map to the reserved id 00 00"
        );
    }
}

// --- Format enum name pins ---

#[test]
fn test_format_short_and_long_names_are_the_spec_strings() {
    // Format::Esdk is the only variant this MPL ships; pin the spec-defined
    // short/long strings so a rename triggers a deliberate test failure.
    assert_eq!(Format::Esdk.short_name(), "ESDK");
    assert_eq!(
        Format::Esdk.long_name(),
        "AWS Encryption SDK Message Format"
    );
}

// --- GCM specifics (shared across every ESDK suite) ---

#[test]
fn test_gcm_specifics_for_every_esdk_suite() {
    for suite in ALL_SUITES {
        let spec = suite.specification();
        assert_eq!(
            spec.encryption_algorithm(),
            EncryptionAlgorithm::Aes,
            "{:?} encryption algorithm",
            suite
        );
        assert_eq!(
            spec.encryption_algorithm_mode(),
            EncryptionAlgorithmMode::Gcm,
            "{:?} encryption mode",
            suite
        );
    }
}

#[test]
fn test_key_commitment_matches_commit_kdf_presence() {
    // key_commitment() is a convenience predicate that MUST agree with
    // commit_kdf().is_some() for every suite in the table. This test both
    // pins that invariant and exercises the predicate — otherwise nothing
    // in the tree calls key_commitment(), leaving it uncovered.
    for suite in ALL_SUITES {
        let spec = suite.specification();
        assert_eq!(
            spec.key_commitment(),
            spec.commit_kdf().is_some(),
            "key_commitment() disagrees with commit_kdf().is_some() for {suite:?}",
        );
    }
}

// --- Encryption / IV / tag / KDF settings ---

#[test]
fn test_encryption_key_length_matches_spec_table() {
    // Per spec Encryption Settings table (bits → bytes):
    let cases: [(AlgorithmSuiteId, usize); 11] = [
        (AlgorithmSuiteId::AlgAes128GcmIv12Tag16NoKdf, 16),
        (AlgorithmSuiteId::AlgAes192GcmIv12Tag16NoKdf, 24),
        (AlgorithmSuiteId::AlgAes256GcmIv12Tag16NoKdf, 32),
        (AlgorithmSuiteId::AlgAes128GcmIv12Tag16HkdfSha256, 16),
        (AlgorithmSuiteId::AlgAes192GcmIv12Tag16HkdfSha256, 24),
        (AlgorithmSuiteId::AlgAes256GcmIv12Tag16HkdfSha256, 32),
        (
            AlgorithmSuiteId::AlgAes128GcmIv12Tag16HkdfSha256EcdsaP256,
            16,
        ),
        (
            AlgorithmSuiteId::AlgAes192GcmIv12Tag16HkdfSha384EcdsaP384,
            24,
        ),
        (
            AlgorithmSuiteId::AlgAes256GcmIv12Tag16HkdfSha384EcdsaP384,
            32,
        ),
        (AlgorithmSuiteId::AlgAes256GcmHkdfSha512CommitKey, 32),
        (
            AlgorithmSuiteId::AlgAes256GcmHkdfSha512CommitKeyEcdsaP384,
            32,
        ),
    ];
    for (suite, expected_bytes) in cases {
        assert_eq!(
            suite.specification().encryption_key_length(),
            expected_bytes,
            "{:?}",
            suite
        );
    }
}

#[test]
fn test_iv_length_is_twelve_for_every_esdk_suite() {
    for suite in ALL_SUITES {
        assert_eq!(suite.specification().iv_length(), 12, "{:?}", suite);
    }
}

#[test]
fn test_authentication_tag_length_is_sixteen_for_every_esdk_suite() {
    for suite in ALL_SUITES {
        assert_eq!(
            suite.specification().authentication_tag_length(),
            16,
            "{:?}",
            suite
        );
    }
}

#[test]
fn test_encryption_kdf_matches_spec_table() {
    let cases: [(AlgorithmSuiteId, KeyDerivationAlgorithm); 11] = [
        (
            AlgorithmSuiteId::AlgAes128GcmIv12Tag16NoKdf,
            KeyDerivationAlgorithm::IdentityKdf,
        ),
        (
            AlgorithmSuiteId::AlgAes192GcmIv12Tag16NoKdf,
            KeyDerivationAlgorithm::IdentityKdf,
        ),
        (
            AlgorithmSuiteId::AlgAes256GcmIv12Tag16NoKdf,
            KeyDerivationAlgorithm::IdentityKdf,
        ),
        (
            AlgorithmSuiteId::AlgAes128GcmIv12Tag16HkdfSha256,
            KeyDerivationAlgorithm::HkdfSha256,
        ),
        (
            AlgorithmSuiteId::AlgAes192GcmIv12Tag16HkdfSha256,
            KeyDerivationAlgorithm::HkdfSha256,
        ),
        (
            AlgorithmSuiteId::AlgAes256GcmIv12Tag16HkdfSha256,
            KeyDerivationAlgorithm::HkdfSha256,
        ),
        (
            AlgorithmSuiteId::AlgAes128GcmIv12Tag16HkdfSha256EcdsaP256,
            KeyDerivationAlgorithm::HkdfSha256,
        ),
        (
            AlgorithmSuiteId::AlgAes192GcmIv12Tag16HkdfSha384EcdsaP384,
            KeyDerivationAlgorithm::HkdfSha384,
        ),
        (
            AlgorithmSuiteId::AlgAes256GcmIv12Tag16HkdfSha384EcdsaP384,
            KeyDerivationAlgorithm::HkdfSha384,
        ),
        (
            AlgorithmSuiteId::AlgAes256GcmHkdfSha512CommitKey,
            KeyDerivationAlgorithm::HkdfSha512,
        ),
        (
            AlgorithmSuiteId::AlgAes256GcmHkdfSha512CommitKeyEcdsaP384,
            KeyDerivationAlgorithm::HkdfSha512,
        ),
    ];
    for (suite, expected_kdf) in cases {
        assert_eq!(
            suite.specification().encryption_kdf(),
            expected_kdf,
            "{:?}",
            suite
        );
    }
}

#[test]
fn test_identity_kdf_used_if_and_only_if_no_kdf_suite() {
    // The three NoKdf variants MUST have IdentityKdf; every other variant
    // MUST NOT. Proving BOTH directions here matches the spec's
    // "Identity KDF is used only for the NoKdf suites" language.
    for suite in ALL_SUITES {
        let is_no_kdf_suite = matches!(
            suite,
            AlgorithmSuiteId::AlgAes128GcmIv12Tag16NoKdf
                | AlgorithmSuiteId::AlgAes192GcmIv12Tag16NoKdf
                | AlgorithmSuiteId::AlgAes256GcmIv12Tag16NoKdf
        );
        let uses_identity_kdf =
            suite.specification().encryption_kdf() == KeyDerivationAlgorithm::IdentityKdf;
        assert_eq!(
            uses_identity_kdf, is_no_kdf_suite,
            "{:?}: IdentityKdf-iff-NoKdf-suite invariant violated",
            suite
        );
    }
}

#[test]
fn test_commit_kdf_present_only_for_commit_key_suites() {
    for suite in ALL_SUITES {
        let spec = suite.specification();
        let expected_commit = matches!(
            suite,
            AlgorithmSuiteId::AlgAes256GcmHkdfSha512CommitKey
                | AlgorithmSuiteId::AlgAes256GcmHkdfSha512CommitKeyEcdsaP384
        );
        if expected_commit {
            assert_eq!(
                spec.commit_kdf(),
                Some(KeyDerivationAlgorithm::HkdfSha512),
                "{:?} should use HKDF-SHA512 for commit key derivation",
                suite
            );
        } else {
            assert_eq!(
                spec.commit_kdf(),
                None,
                "{:?} must NOT have a commit-key KDF",
                suite
            );
        }
    }
}

// --- Asymmetric / symmetric signature algorithms ---

#[test]
fn test_asymmetric_signature_present_for_signing_suites() {
    // The actual signature generation/verification lives in downstream consumers;
    // this MPL layer exposes the required algorithm via
    // AlgorithmSuite::asymmetric_signature_algorithm(), and this test verifies
    // the suite-to-algorithm mapping consumers will read.
    //
    let cases: [(AlgorithmSuiteId, Option<AsymmetricSignatureAlgorithm>); 11] = [
        (AlgorithmSuiteId::AlgAes128GcmIv12Tag16NoKdf, None),
        (AlgorithmSuiteId::AlgAes192GcmIv12Tag16NoKdf, None),
        (AlgorithmSuiteId::AlgAes256GcmIv12Tag16NoKdf, None),
        (AlgorithmSuiteId::AlgAes128GcmIv12Tag16HkdfSha256, None),
        (AlgorithmSuiteId::AlgAes192GcmIv12Tag16HkdfSha256, None),
        (AlgorithmSuiteId::AlgAes256GcmIv12Tag16HkdfSha256, None),
        (
            AlgorithmSuiteId::AlgAes128GcmIv12Tag16HkdfSha256EcdsaP256,
            Some(AsymmetricSignatureAlgorithm::EcdsaP256),
        ),
        (
            AlgorithmSuiteId::AlgAes192GcmIv12Tag16HkdfSha384EcdsaP384,
            Some(AsymmetricSignatureAlgorithm::EcdsaP384),
        ),
        (
            AlgorithmSuiteId::AlgAes256GcmIv12Tag16HkdfSha384EcdsaP384,
            Some(AsymmetricSignatureAlgorithm::EcdsaP384),
        ),
        (AlgorithmSuiteId::AlgAes256GcmHkdfSha512CommitKey, None),
        (
            AlgorithmSuiteId::AlgAes256GcmHkdfSha512CommitKeyEcdsaP384,
            Some(AsymmetricSignatureAlgorithm::EcdsaP384),
        ),
    ];
    for (suite, expected) in cases {
        assert_eq!(
            suite.specification().asymmetric_signature_algorithm(),
            expected,
            "{:?}",
            suite
        );
    }
}

#[test]
fn test_no_asymmetric_signature_means_signing_disabled() {
    // The actual decision to skip signature generation/verification lives in
    // downstream consumers; this MPL layer exposes has_asymmetric_signing() =
    // false for non-signing suites, which is the suite-to-algorithm mapping
    // consumers will read.
    //
    // For each variant whose suite spec lacks an asymmetric signature algorithm,
    // `has_asymmetric_signing()` MUST return false. Materials construction with
    // a signing key on such a suite is rejected (covered by
    // tests/test_encryption_materials.rs::test_signing_key_rejected_without_asymmetric_signing).
    for suite in ALL_SUITES {
        let has_sig = suite
            .specification()
            .asymmetric_signature_algorithm()
            .is_some();
        assert_eq!(suite.has_asymmetric_signing(), has_sig, "{:?}", suite);
    }
}

#[test]
fn test_symmetric_signature_algorithm_is_none_for_every_esdk_suite() {
    // No ESDK suite uses a symmetric signature algorithm — the field is None
    // for every ESDK variant, so `has_symmetric_signing()` is uniformly false.
    // The `symmetric_signing_keys` fields on materials MUST NOT be present;
    // that None-side invariant is covered on the materials structs.
    for suite in ALL_SUITES {
        assert!(
            suite
                .specification()
                .symmetric_signature_algorithm()
                .is_none(),
            "{:?} must NOT have a symmetric signature algorithm (no ESDK suite does)",
            suite
        );
        assert!(!suite.has_symmetric_signing(), "{:?}", suite);
    }
}

// --- Message format version + suite data ---

#[test]
fn test_message_format_version_branches_v1_and_v2() {
    let cases: [(AlgorithmSuiteId, u8); 11] = [
        (AlgorithmSuiteId::AlgAes128GcmIv12Tag16NoKdf, 0x01),
        (AlgorithmSuiteId::AlgAes192GcmIv12Tag16NoKdf, 0x01),
        (AlgorithmSuiteId::AlgAes256GcmIv12Tag16NoKdf, 0x01),
        (AlgorithmSuiteId::AlgAes128GcmIv12Tag16HkdfSha256, 0x01),
        (AlgorithmSuiteId::AlgAes192GcmIv12Tag16HkdfSha256, 0x01),
        (AlgorithmSuiteId::AlgAes256GcmIv12Tag16HkdfSha256, 0x01),
        (
            AlgorithmSuiteId::AlgAes128GcmIv12Tag16HkdfSha256EcdsaP256,
            0x01,
        ),
        (
            AlgorithmSuiteId::AlgAes192GcmIv12Tag16HkdfSha384EcdsaP384,
            0x01,
        ),
        (
            AlgorithmSuiteId::AlgAes256GcmIv12Tag16HkdfSha384EcdsaP384,
            0x01,
        ),
        (AlgorithmSuiteId::AlgAes256GcmHkdfSha512CommitKey, 0x02),
        (
            AlgorithmSuiteId::AlgAes256GcmHkdfSha512CommitKeyEcdsaP384,
            0x02,
        ),
    ];
    for (suite, expected_version) in cases {
        assert_eq!(
            suite.specification().message_format_version(),
            expected_version,
            "{:?}",
            suite
        );
    }
}

#[test]
fn test_suite_04_78_stores_commit_key_in_suite_data() {
    let spec = AlgorithmSuiteId::AlgAes256GcmHkdfSha512CommitKey.specification();
    assert_eq!(spec.id(), [0x04, 0x78]);
    // Commit key for HKDF-SHA512 is 256 bits = 32 bytes; suite data field
    // stores the commit key, so its length is 32.
    assert_eq!(spec.algorithm_suite_data_length(), 32);
    assert!(spec.commit_kdf().is_some());
}

#[test]
fn test_suite_05_78_stores_commit_key_in_suite_data() {
    let spec = AlgorithmSuiteId::AlgAes256GcmHkdfSha512CommitKeyEcdsaP384.specification();
    assert_eq!(spec.id(), [0x05, 0x78]);
    assert_eq!(spec.algorithm_suite_data_length(), 32);
    assert!(spec.commit_kdf().is_some());
}

#[test]
fn test_algorithm_suite_data_length_may_be_zero() {
    // Every non-commit-key ESDK suite has algorithm_suite_data_length == 0.
    let zero_length_suites = [
        AlgorithmSuiteId::AlgAes128GcmIv12Tag16NoKdf,
        AlgorithmSuiteId::AlgAes192GcmIv12Tag16NoKdf,
        AlgorithmSuiteId::AlgAes256GcmIv12Tag16NoKdf,
        AlgorithmSuiteId::AlgAes128GcmIv12Tag16HkdfSha256,
        AlgorithmSuiteId::AlgAes192GcmIv12Tag16HkdfSha256,
        AlgorithmSuiteId::AlgAes256GcmIv12Tag16HkdfSha256,
        AlgorithmSuiteId::AlgAes128GcmIv12Tag16HkdfSha256EcdsaP256,
        AlgorithmSuiteId::AlgAes192GcmIv12Tag16HkdfSha384EcdsaP384,
        AlgorithmSuiteId::AlgAes256GcmIv12Tag16HkdfSha384EcdsaP384,
    ];
    for suite in zero_length_suites {
        assert_eq!(
            suite.specification().algorithm_suite_data_length(),
            0,
            "{:?}",
            suite
        );
    }
}

#[test]
fn test_signing_key_length_matches_spec_table() {
    // P-256 private scalar: 32 bytes. P-384: 48 bytes. Non-signing: None.
    let cases: [(AlgorithmSuiteId, Option<usize>); 11] = [
        (AlgorithmSuiteId::AlgAes128GcmIv12Tag16NoKdf, None),
        (AlgorithmSuiteId::AlgAes192GcmIv12Tag16NoKdf, None),
        (AlgorithmSuiteId::AlgAes256GcmIv12Tag16NoKdf, None),
        (AlgorithmSuiteId::AlgAes128GcmIv12Tag16HkdfSha256, None),
        (AlgorithmSuiteId::AlgAes192GcmIv12Tag16HkdfSha256, None),
        (AlgorithmSuiteId::AlgAes256GcmIv12Tag16HkdfSha256, None),
        (
            AlgorithmSuiteId::AlgAes128GcmIv12Tag16HkdfSha256EcdsaP256,
            Some(32),
        ),
        (
            AlgorithmSuiteId::AlgAes192GcmIv12Tag16HkdfSha384EcdsaP384,
            Some(48),
        ),
        (
            AlgorithmSuiteId::AlgAes256GcmIv12Tag16HkdfSha384EcdsaP384,
            Some(48),
        ),
        (AlgorithmSuiteId::AlgAes256GcmHkdfSha512CommitKey, None),
        (
            AlgorithmSuiteId::AlgAes256GcmHkdfSha512CommitKeyEcdsaP384,
            Some(48),
        ),
    ];
    for (suite, expected) in cases {
        assert_eq!(
            suite.specification().signing_key_length(),
            expected,
            "{:?}",
            suite
        );
    }
}

#[test]
fn test_verification_key_length_matches_spec_table() {
    // SEC1 uncompressed public key: 1 byte tag + 2 * coord_len.
    // P-256: 1 + 2*32 = 65 bytes. P-384: 1 + 2*48 = 97 bytes. Non-signing: None.
    let cases: [(AlgorithmSuiteId, Option<usize>); 11] = [
        (AlgorithmSuiteId::AlgAes128GcmIv12Tag16NoKdf, None),
        (AlgorithmSuiteId::AlgAes192GcmIv12Tag16NoKdf, None),
        (AlgorithmSuiteId::AlgAes256GcmIv12Tag16NoKdf, None),
        (AlgorithmSuiteId::AlgAes128GcmIv12Tag16HkdfSha256, None),
        (AlgorithmSuiteId::AlgAes192GcmIv12Tag16HkdfSha256, None),
        (AlgorithmSuiteId::AlgAes256GcmIv12Tag16HkdfSha256, None),
        (
            AlgorithmSuiteId::AlgAes128GcmIv12Tag16HkdfSha256EcdsaP256,
            Some(65),
        ),
        (
            AlgorithmSuiteId::AlgAes192GcmIv12Tag16HkdfSha384EcdsaP384,
            Some(97),
        ),
        (
            AlgorithmSuiteId::AlgAes256GcmIv12Tag16HkdfSha384EcdsaP384,
            Some(97),
        ),
        (AlgorithmSuiteId::AlgAes256GcmHkdfSha512CommitKey, None),
        (
            AlgorithmSuiteId::AlgAes256GcmHkdfSha512CommitKeyEcdsaP384,
            Some(97),
        ),
    ];
    for (suite, expected) in cases {
        assert_eq!(
            suite.specification().verification_key_length(),
            expected,
            "{:?}",
            suite
        );
    }
}
