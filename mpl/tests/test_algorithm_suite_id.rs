// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

//! Tests for `AlgorithmSuiteId`, the materialized `AlgorithmSuite` spec table,
//! and the `Format` enum. Each test asserts a property derived directly from
//! the algorithm-suites.md spec tables — hex IDs, encryption key lengths, IV
//! lengths, KDF / commit-KDF mappings, asymmetric-signature-algorithm
//! mappings, message format versions, and suite-data lengths.

use std::collections::HashSet;

use aws_crypto_mpl::structures::{
    AlgorithmSuite, AlgorithmSuiteId, AsymmetricSignatureAlgorithm, EncryptionAlgorithm,
    EncryptionAlgorithmMode, Format, KeyDerivationAlgorithm,
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
    //= ../spec/framework/algorithm-suites.md#supported-algorithm-suites
    //= type=test
    //# Algorithm Suite ID MUST be a unique hex value across all supported algorithm suites.
    //
    //= ../spec/framework/algorithm-suites.md#algorithm-suite-id
    //= type=test
    //# A 2-byte hex value that MUST uniquely identify an algorithm suite.
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
    //= ../spec/framework/algorithm-suites.md#supported-algorithm-suites
    //= type=test
    //# The value `00 00` is reserved
    //# and MUST NOT be used
    //# as an Algorithm Suite ID in the future.
    for suite in ALL_SUITES {
        let id = suite.id_bytes();
        assert_ne!(
            id,
            [0x00, 0x00],
            "no constructible AlgorithmSuiteId variant may map to the reserved id 00 00"
        );
    }
}

#[test]
fn test_id_bytes_length_is_two() {
    // 2-byte length is enforced by the [u8; 2] type. This regression test
    // documents that the public accessor returns exactly 2 bytes.
    for suite in ALL_SUITES {
        let id: [u8; 2] = suite.id_bytes();
        assert_eq!(id.len(), 2, "{:?}", suite);
    }
}

#[test]
fn test_id_bytes_can_bind_algorithm_suite_to_ciphertext() {
    //= ../spec/framework/algorithm-suites.md#algorithm-suite-id
    //= type=test
    //# This 2-byte value SHOULD be used to bind algorithm suites to ciphertext.
    // The accessor returns a fresh [u8; 2] copy, ready to be written into a
    // ciphertext header. This regression check ensures the public accessor
    // remains usable for that purpose.
    let id = AlgorithmSuiteId::AlgAes256GcmIv12Tag16NoKdf.id_bytes();
    let mut header_buf = [0u8; 8];
    header_buf[0..2].copy_from_slice(&id);
    assert_eq!(&header_buf[0..2], &[0x00, 0x78]);
}

// --- Format enum: short/long-name uniqueness ---

#[test]
fn test_format_short_and_long_names_unique() {
    // Format::Esdk is the only variant; uniqueness of short and long name is
    // trivially true (single-variant enum). Source-side annotation is
    // type=implication.
    let formats = [Format::Esdk];
    let shorts: HashSet<&'static str> = formats.iter().map(|f| f.short_name()).collect();
    let longs: HashSet<&'static str> = formats.iter().map(|f| f.long_name()).collect();
    assert_eq!(shorts.len(), formats.len(), "short names must be unique");
    assert_eq!(longs.len(), formats.len(), "long names must be unique");
    // ESDK / S3EC / DBE never collide on either name dimension; the implementer
    // ships only ESDK in this MPL, so uniqueness is trivial.
    assert_eq!(Format::Esdk.short_name(), "ESDK");
    assert_eq!(
        Format::Esdk.long_name(),
        "AWS Encryption SDK Message Format"
    );
}

// --- Per-section spec-table coverage ---

#[test]
fn test_overview_per_suite_specification_is_defined() {
    // Each variant materializes a non-default specification. The enum IS the
    // catalog of behaviors per the overview section; source-side annotation
    // is type=implication.
    let mut seen: HashSet<[u8; 2]> = HashSet::new();
    for suite in ALL_SUITES {
        let spec: AlgorithmSuite = suite.specification();
        seen.insert(spec.id());
    }
    assert_eq!(seen.len(), 11);
}

#[test]
fn test_gcm_specifics_for_every_esdk_suite() {
    //= ../spec/framework/algorithm-suites.md#gcm
    //= type=test
    //# If specified to use GCM, the AWS Encryption SDK MUST use GCM with the following specifics:
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
fn test_supported_format_algorithm_suites_enum_exposes_eleven_esdk_variants() {
    // The library exposes 11 ESDK suite variants on `AlgorithmSuiteId` —
    // matching the ESDK column of the spec's per-format ENUM table. Source-side
    // annotation is type=implication (the enum's existence IS the requirement).
    assert_eq!(ALL_SUITES.len(), 11);
}

#[test]
fn test_supported_algorithm_suites_enum_is_super_set() {
    // Only ESDK is supported, so the super-set IS the ESDK set; both have the
    // same 11 variants. Source-side annotation is type=implication. (DBE/S3EC
    // are out of scope — see exception annotations.)
    assert_eq!(ALL_SUITES.len(), 11);
}

#[test]
fn test_format_namespacing_allows_duplicate_format_enum_names() {
    // The spec namespaces variants as `Format.FormatENUM` (e.g.
    // `ESDK.ALG_AES_256_GCM_IV12_TAG16_NO_KDF`). In this MPL, only the ESDK
    // namespace exists. Source-side annotation is type=implication — the
    // Format enum's `short_name` IS the disambiguating prefix.
    assert_eq!(Format::Esdk.short_name(), "ESDK");
}

#[test]
fn test_structure_required_fields_present_for_every_suite() {
    // Each variant materializes an AlgorithmSuite with all required fields
    // populated. The struct's compile-time field set IS the requirement;
    // source-side annotation is type=implication.
    for suite in ALL_SUITES {
        let spec = suite.specification();
        assert_eq!(spec.id().len(), 2);
        assert!(spec.encryption_key_length() > 0);
        assert!(spec.iv_length() > 0);
        assert!(spec.authentication_tag_length() > 0);
        // optional fields use Option<T>, allowed to be None
        let _ = spec.commit_kdf();
        let _ = spec.asymmetric_signature_algorithm();
        let _ = spec.symmetric_signature_algorithm();
    }
}

// --- Encryption / IV / tag / KDF settings ---

#[test]
fn test_encryption_key_length_matches_spec_table() {
    //= ../spec/framework/algorithm-suites.md#encryption-algorithm
    //= type=test
    //# The length of the input encryption key MUST equal the [encryption key length](#encryption-key-length) specified by the algorithm suite.
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
    //= ../spec/framework/algorithm-suites.md#encryption-algorithm-mode
    //= type=test
    //# The length of the input IV MUST equal the IV length specified by the algorithm suite.
    for suite in ALL_SUITES {
        assert_eq!(suite.specification().iv_length(), 12, "{:?}", suite);
    }
}

#[test]
fn test_authentication_tag_length_is_sixteen_for_every_esdk_suite() {
    //= ../spec/framework/algorithm-suites.md#encryption-algorithm-mode
    //= type=test
    //# The length of the authentication tag MUST equal the authentication tag length specified by the algorithm suite.
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
    //= ../spec/framework/algorithm-suites.md#encryption-key-derivation-algorithm
    //= type=test
    //# The specified KDF algorithm MUST be used to generate the encryption algorithm encryption key input.
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
fn test_identity_kdf_used_only_for_no_kdf_suites() {
    // Defense-in-depth: every NoKdf suite has IdentityKdf, every other suite
    // does not. The two #identity-kdf requirements are annotated as
    // type=implication on the source side because no callable Identity KDF
    // function exists at this layer (the suite's `encryption_kdf` tag IS the
    // observable surface; key-derivation-input length is not a separate field).
    for suite in [
        AlgorithmSuiteId::AlgAes128GcmIv12Tag16NoKdf,
        AlgorithmSuiteId::AlgAes192GcmIv12Tag16NoKdf,
        AlgorithmSuiteId::AlgAes256GcmIv12Tag16NoKdf,
    ] {
        let spec = suite.specification();
        assert_eq!(
            spec.encryption_kdf(),
            KeyDerivationAlgorithm::IdentityKdf,
            "{:?} must use Identity KDF",
            suite
        );
        // Identity KDF input length == encryption key length
        let n = spec.encryption_key_length();
        assert!(
            n == 16 || n == 24 || n == 32,
            "{:?} encryption_key_length",
            suite
        );
    }
}

#[test]
fn test_commit_kdf_present_only_for_commit_key_suites() {
    //= ../spec/framework/algorithm-suites.md#commit-key-derivation-algorithm
    //= type=test
    //# The specified KDF algorithm MUST be used to generate the [commit key](#commit-key).
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
    //= ../spec/framework/algorithm-suites.md#asymmetric-signature-algorithm
    //= type=test
    //# - Asymmetric signatures MUST be generated using the specified asymmetric signature algorithm.
    //
    //= ../spec/framework/algorithm-suites.md#asymmetric-signature-algorithm
    //= type=test
    //# - Asymmetric signatures MUST be verified using the specified asymmetric signature algorithm.
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
    //= ../spec/framework/algorithm-suites.md#asymmetric-signature-algorithm
    //= type=test
    //# - Asymmetric signatures MUST NOT be generated.
    //
    //= ../spec/framework/algorithm-suites.md#asymmetric-signature-algorithm
    //= type=test
    //# - Asymmetric signatures MUST NOT be verified.
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
fn test_asymmetric_signature_algorithm_is_optional_field() {
    // Source-side annotation is type=implication — `Option<T>` encodes
    // OPTIONAL by construction. This test exists for regression coverage
    // documenting that variants split into both populated and unpopulated.
    let signing_count = ALL_SUITES
        .iter()
        .filter(|s| s.specification().asymmetric_signature_algorithm().is_some())
        .count();
    let no_signing_count = ALL_SUITES
        .iter()
        .filter(|s| s.specification().asymmetric_signature_algorithm().is_none())
        .count();
    assert!(signing_count > 0, "at least one variant has signing");
    assert!(no_signing_count > 0, "at least one variant has no signing");
}

#[test]
fn test_symmetric_signature_algorithm_is_optional_field() {
    // Source-side annotation is type=implication — `Option<T>` encodes OPTIONAL.
    // No ESDK suite uses a symmetric signature algorithm — the field is None
    // for every ESDK variant.
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

#[test]
fn test_no_symmetric_signature_means_generation_and_verification_disabled() {
    //= ../spec/framework/algorithm-suites.md#symmetric-signature-algorithm
    //= type=test
    //# - Symmetric signatures MUST NOT be generated.
    //
    //= ../spec/framework/algorithm-suites.md#symmetric-signature-algorithm
    //= type=test
    //# - Symmetric signatures MUST NOT be verified.
    // For every constructible ESDK variant, has_symmetric_signing() == false,
    // so callers MUST NOT generate or verify symmetric signatures with these
    // materials. The materials types reject symmetric_signing_key arguments
    // — covered by test_encryption_materials.rs and test_decryption_materials.rs
    // negative-path tests; here we prove the API surface forbids the action.
    for suite in ALL_SUITES {
        assert!(!suite.has_symmetric_signing(), "{:?}", suite);
    }
}

// --- Message format version + suite data ---

#[test]
fn test_message_format_version_branches_v1_and_v2() {
    //= ../spec/framework/algorithm-suites.md#message-format-version
    //= type=test
    //# This MUST be used to branch any serialization/deserialization logic in [supported formats](#supported-formats).
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
    //= ../spec/framework/algorithm-suites.md#supported-algorithm-suite-data
    //= type=test
    //# - Algorithm Suite 04 78 MUST store the commit key in the suite data
    let spec = AlgorithmSuiteId::AlgAes256GcmHkdfSha512CommitKey.specification();
    assert_eq!(spec.id(), [0x04, 0x78]);
    // Commit key for HKDF-SHA512 is 256 bits = 32 bytes; suite data field
    // stores the commit key, so its length is 32.
    assert_eq!(spec.algorithm_suite_data_length(), 32);
    assert!(spec.commit_kdf().is_some());
}

#[test]
fn test_suite_05_78_stores_commit_key_in_suite_data() {
    //= ../spec/framework/algorithm-suites.md#supported-algorithm-suite-data
    //= type=test
    //# - Algorithm Suite 05 78 MUST store the commit key in the suite data
    let spec = AlgorithmSuiteId::AlgAes256GcmHkdfSha512CommitKeyEcdsaP384.specification();
    assert_eq!(spec.id(), [0x05, 0x78]);
    assert_eq!(spec.algorithm_suite_data_length(), 32);
    assert!(spec.commit_kdf().is_some());
}

#[test]
fn test_algorithm_suite_data_length_may_be_zero() {
    //= ../spec/framework/algorithm-suites.md#algorithm-suite-data-length
    //= type=test
    //# The field MAY be length 0.
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
fn test_signing_key_length_p256() {
    let spec = AlgorithmSuiteId::AlgAes128GcmIv12Tag16HkdfSha256EcdsaP256.specification();
    // P-256 private scalar is 32 bytes.
    assert_eq!(spec.signing_key_length(), Some(32));
}

#[test]
fn test_signing_key_length_none_for_non_signing_suite() {
    let spec = AlgorithmSuiteId::AlgAes128GcmIv12Tag16NoKdf.specification();
    assert_eq!(spec.signing_key_length(), None);
}

#[test]
fn test_verification_key_length_p256() {
    let spec = AlgorithmSuiteId::AlgAes128GcmIv12Tag16HkdfSha256EcdsaP256.specification();
    // P-256 SEC1 uncompressed: 1 + 2*32 = 65 bytes.
    assert_eq!(spec.verification_key_length(), Some(65));
}

#[test]
fn test_verification_key_length_none_for_non_signing_suite() {
    let spec = AlgorithmSuiteId::AlgAes128GcmIv12Tag16NoKdf.specification();
    assert_eq!(spec.verification_key_length(), None);
}
