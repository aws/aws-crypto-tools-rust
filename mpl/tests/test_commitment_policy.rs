// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

//! Tests for `CommitmentPolicy` and its three per-policy methods.
//!
//! Covers the in-scope sections of `commitment-policy.md`:
//!
//! - `#supported-format-commitment-policy-enum` — distinct ESDK Format
//!   Commitment Policy ENUM.
//! - `#supported-commitment-policy-enum` — union ENUM.
//! - `#esdk-forbid-encrypt-allow-decrypt`
//! - `#esdk-require-encrypt-allow-decrypt`
//! - `#esdk-require-encrypt-require-decrypt`
//!
//! The DBE section is OUT OF SCOPE — covered by `type=exception` annotations
//! in `src/structures/commitment_policy.rs`.

use std::collections::HashSet;

use aws_crypto_mpl::structures::{AlgorithmSuiteId, CommitmentPolicy, Esdk};

/// A representative committing ESDK suite (Key Commitment value: True).
const COMMITTING: AlgorithmSuiteId = AlgorithmSuiteId::AlgAes256GcmHkdfSha512CommitKeyEcdsaP384;

/// The other committing ESDK suite, used to confirm the predicate is not
/// pinned to a single suite.
const COMMITTING_NO_SIG: AlgorithmSuiteId = AlgorithmSuiteId::AlgAes256GcmHkdfSha512CommitKey;

/// A representative non-committing ESDK suite (Key Commitment value: False).
const NON_COMMITTING: AlgorithmSuiteId = AlgorithmSuiteId::AlgAes256GcmIv12Tag16NoKdf;

/// A second non-committing ESDK suite (HKDF, no commitment) — proves the
/// predicate uses the spec's Key Commitment definition rather than naming a
/// specific suite.
const NON_COMMITTING_HKDF: AlgorithmSuiteId = AlgorithmSuiteId::AlgAes256GcmIv12Tag16HkdfSha256;

/// Every variant of `CommitmentPolicy`. Used to assert pairwise distinctness
/// and to enumerate the ESDK Format Commitment Policy ENUM rows.
const ALL_VARIANTS: [CommitmentPolicy; 3] = [
    CommitmentPolicy::Esdk(Esdk::ForbidEncryptAllowDecrypt),
    CommitmentPolicy::Esdk(Esdk::RequireEncryptAllowDecrypt),
    CommitmentPolicy::Esdk(Esdk::RequireEncryptRequireDecrypt),
];

#[test]
fn test_supported_format_commitment_policy_enum_is_distinct() {
    let mut seen = HashSet::new();
    for v in ALL_VARIANTS {
        assert!(
            seen.insert(v),
            "ESDK Format Commitment Policy ENUM variant {v:?} must be distinct"
        );
    }
    assert_eq!(seen.len(), 3, "expected 3 distinct ESDK ENUM variants");
}

#[test]
fn test_union_commitment_policy_enum_exposes_all_variants() {
    // Every value of the union ENUM (`CommitmentPolicy`) round-trips through
    // pattern matching against itself. With one format implemented (ESDK),
    // the union ENUM is exactly the three ESDK variants.
    for v in ALL_VARIANTS {
        let matched = match v {
            CommitmentPolicy::Esdk(Esdk::ForbidEncryptAllowDecrypt) => {
                "ESDK.FORBID_ENCRYPT_ALLOW_DECRYPT"
            }
            CommitmentPolicy::Esdk(Esdk::RequireEncryptAllowDecrypt) => {
                "ESDK.REQUIRE_ENCRYPT_ALLOW_DECRYPT"
            }
            CommitmentPolicy::Esdk(Esdk::RequireEncryptRequireDecrypt) => {
                "ESDK.REQUIRE_ENCRYPT_REQUIRE_DECRYPT"
            }
        };
        assert!(
            matched.starts_with("ESDK."),
            "every union ENUM variant must be an ESDK.* policy in this MPL: got {matched}"
        );
    }
}

#[test]
fn test_forbid_encrypt_allow_decrypt_default_is_alg_aes_256_gcm_iv12_tag16_no_kdf() {
    let default =
        CommitmentPolicy::Esdk(Esdk::ForbidEncryptAllowDecrypt).default_algorithm_suite_id();
    assert_eq!(default, AlgorithmSuiteId::AlgAes256GcmIv12Tag16NoKdf);
    // The spec also identifies this suite by raw bytes (`00 78`); cross-check.
    assert_eq!(default.specification().id(), [0x00, 0x78]);
}

#[test]
fn test_forbid_encrypt_allow_decrypt_encrypt_only_non_committing_suites() {
    let policy = CommitmentPolicy::Esdk(Esdk::ForbidEncryptAllowDecrypt);
    // Positive: a suite with Key Commitment value False is allowed.
    assert!(
        policy.allows_for_encrypt(NON_COMMITTING),
        "non-committing suite must be allowed under FORBID_ENCRYPT"
    );
    assert!(
        policy.allows_for_encrypt(NON_COMMITTING_HKDF),
        "non-committing HKDF suite must be allowed under FORBID_ENCRYPT"
    );
    // Negative: a suite with Key Commitment value True is forbidden.
    assert!(
        !policy.allows_for_encrypt(COMMITTING),
        "committing suite must be forbidden under FORBID_ENCRYPT"
    );
    assert!(
        !policy.allows_for_encrypt(COMMITTING_NO_SIG),
        "committing-no-sig suite must be forbidden under FORBID_ENCRYPT"
    );
}

#[test]
fn test_forbid_encrypt_allow_decrypt_decrypt_supports_all_suites() {
    let policy = CommitmentPolicy::Esdk(Esdk::ForbidEncryptAllowDecrypt);
    // Both committing and non-committing suites must be allowed for decrypt.
    assert!(policy.allows_for_decrypt(NON_COMMITTING));
    assert!(policy.allows_for_decrypt(NON_COMMITTING_HKDF));
    assert!(policy.allows_for_decrypt(COMMITTING));
    assert!(policy.allows_for_decrypt(COMMITTING_NO_SIG));
}

#[test]
fn test_require_encrypt_allow_decrypt_default_id_is_05_78() {
    let default =
        CommitmentPolicy::Esdk(Esdk::RequireEncryptAllowDecrypt).default_algorithm_suite_id();
    // Identity assertion (the variant whose id is 05 78).
    assert_eq!(
        default,
        AlgorithmSuiteId::AlgAes256GcmHkdfSha512CommitKeyEcdsaP384
    );
    // Raw byte assertion — the spec quote uses the byte id directly.
    assert_eq!(default.specification().id(), [0x05, 0x78]);
}

#[test]
fn test_require_encrypt_allow_decrypt_encrypt_only_committing_suites() {
    let policy = CommitmentPolicy::Esdk(Esdk::RequireEncryptAllowDecrypt);
    // Positive: committing suites are allowed.
    assert!(
        policy.allows_for_encrypt(COMMITTING),
        "committing suite must be allowed under REQUIRE_ENCRYPT"
    );
    assert!(
        policy.allows_for_encrypt(COMMITTING_NO_SIG),
        "committing-no-sig suite must be allowed under REQUIRE_ENCRYPT"
    );
    // Negative: non-committing suites are forbidden.
    assert!(
        !policy.allows_for_encrypt(NON_COMMITTING),
        "non-committing suite must be forbidden under REQUIRE_ENCRYPT"
    );
    assert!(
        !policy.allows_for_encrypt(NON_COMMITTING_HKDF),
        "non-committing HKDF suite must be forbidden under REQUIRE_ENCRYPT"
    );
}

#[test]
fn test_require_encrypt_allow_decrypt_decrypt_supports_all_suites() {
    let policy = CommitmentPolicy::Esdk(Esdk::RequireEncryptAllowDecrypt);
    assert!(policy.allows_for_decrypt(NON_COMMITTING));
    assert!(policy.allows_for_decrypt(NON_COMMITTING_HKDF));
    assert!(policy.allows_for_decrypt(COMMITTING));
    assert!(policy.allows_for_decrypt(COMMITTING_NO_SIG));
}

#[test]
fn test_require_encrypt_require_decrypt_default_id_is_05_78() {
    let default =
        CommitmentPolicy::Esdk(Esdk::RequireEncryptRequireDecrypt).default_algorithm_suite_id();
    assert_eq!(
        default,
        AlgorithmSuiteId::AlgAes256GcmHkdfSha512CommitKeyEcdsaP384
    );
    assert_eq!(default.specification().id(), [0x05, 0x78]);
}

#[test]
fn test_require_encrypt_require_decrypt_encrypt_only_committing_suites() {
    let policy = CommitmentPolicy::Esdk(Esdk::RequireEncryptRequireDecrypt);
    assert!(policy.allows_for_encrypt(COMMITTING));
    assert!(policy.allows_for_encrypt(COMMITTING_NO_SIG));
    assert!(!policy.allows_for_encrypt(NON_COMMITTING));
    assert!(!policy.allows_for_encrypt(NON_COMMITTING_HKDF));
}

#[test]
fn test_require_encrypt_require_decrypt_decrypt_only_committing_suites() {
    let policy = CommitmentPolicy::Esdk(Esdk::RequireEncryptRequireDecrypt);
    // Positive: committing suites are allowed.
    assert!(policy.allows_for_decrypt(COMMITTING));
    assert!(policy.allows_for_decrypt(COMMITTING_NO_SIG));
    // Negative: non-committing suites are forbidden.
    assert!(!policy.allows_for_decrypt(NON_COMMITTING));
    assert!(!policy.allows_for_decrypt(NON_COMMITTING_HKDF));
}
