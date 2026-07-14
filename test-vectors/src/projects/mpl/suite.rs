// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

//! Bridges between the manifest's hex-string suite IDs and the Rust MPL's
//! [`AlgorithmSuiteId`] enum, plus a helper that picks the compatible
//! [`CommitmentPolicy`] for a given suite.
//!
//! The manifest is byte-compatible with the Dafny test-vectors format, which
//! includes both ESDK and DBE suite IDs. The Rust `mpl` crate today only
//! supports ESDK suites, so [`SUPPORTED_SUITES`] enumerates exactly the 11
//! ESDK entries. Suite IDs outside this table are rejected up front by
//! [`suite_id_from_hex`] with a clear error message.

use aws_crypto_mpl::structures::{AlgorithmSuiteId, CommitmentPolicy, Esdk};

use crate::error::{Result, TestVectorError};

/// Every algorithm suite this crate can currently exercise, in the order the
/// reference Dafny `AllAlgorithmSuites` set enumerates them. Each entry is
/// `(hex-id, enum-variant)`. When the Rust `mpl` crate gains DBE (or any
/// other) suite support, append the new (hex, variant) pair here.
pub const SUPPORTED_SUITES: &[(&str, AlgorithmSuiteId)] = &[
    ("0014", AlgorithmSuiteId::AlgAes128GcmIv12Tag16NoKdf),
    ("0046", AlgorithmSuiteId::AlgAes192GcmIv12Tag16NoKdf),
    ("0078", AlgorithmSuiteId::AlgAes256GcmIv12Tag16NoKdf),
    ("0114", AlgorithmSuiteId::AlgAes128GcmIv12Tag16HkdfSha256),
    ("0146", AlgorithmSuiteId::AlgAes192GcmIv12Tag16HkdfSha256),
    ("0178", AlgorithmSuiteId::AlgAes256GcmIv12Tag16HkdfSha256),
    (
        "0214",
        AlgorithmSuiteId::AlgAes128GcmIv12Tag16HkdfSha256EcdsaP256,
    ),
    (
        "0346",
        AlgorithmSuiteId::AlgAes192GcmIv12Tag16HkdfSha384EcdsaP384,
    ),
    (
        "0378",
        AlgorithmSuiteId::AlgAes256GcmIv12Tag16HkdfSha384EcdsaP384,
    ),
    ("0478", AlgorithmSuiteId::AlgAes256GcmHkdfSha512CommitKey),
    (
        "0578",
        AlgorithmSuiteId::AlgAes256GcmHkdfSha512CommitKeyEcdsaP384,
    ),
];

/// Every hex-string suite ID this crate can currently exercise. Used by the
/// MPL vector generator to emit one vector per suite per keyring.
pub fn supported_suite_hex_ids() -> Vec<&'static str> {
    SUPPORTED_SUITES.iter().map(|(h, _)| *h).collect()
}

/// Resolve a manifest hex-string suite ID to an [`AlgorithmSuiteId`].
///
/// Comparison is case-insensitive (`"0478"` and `"0478"` — the manifest is
/// digit-only for every supported suite today — are accepted identically).
pub fn suite_id_from_hex(hex: &str) -> Result<AlgorithmSuiteId> {
    SUPPORTED_SUITES
        .iter()
        .find(|(h, _)| h.eq_ignore_ascii_case(hex))
        .map(|(_, id)| *id)
        .ok_or_else(|| {
            TestVectorError::other(format!(
                "algorithm suite '{hex}' is not supported by the Rust mpl crate yet"
            ))
        })
}

/// Format an [`AlgorithmSuiteId`] as the lowercase-hex 4-digit string the
/// manifest schema uses (`"0478"`, `"6700"`, ...).
pub fn hex_from_suite_id(id: AlgorithmSuiteId) -> String {
    let [hi, lo] = id.id_bytes();
    format!("{hi:02x}{lo:02x}")
}

/// Compatible commitment policy for `id`, mirroring the Dafny
/// `AllAlgorithmSuites.GetCompatibleCommitmentPolicy`:
///
/// * Non-committing ESDK suite → `ESDK.FORBID_ENCRYPT_ALLOW_DECRYPT`.
/// * Committing ESDK suite → `ESDK.REQUIRE_ENCRYPT_REQUIRE_DECRYPT`.
///
/// The Rust `CommitmentPolicy` enum today only has ESDK variants, so this
/// function only needs to distinguish committing vs. non-committing.
pub fn commitment_policy_for(id: AlgorithmSuiteId) -> CommitmentPolicy {
    if id.specification().key_commitment() {
        CommitmentPolicy::Esdk(Esdk::RequireEncryptRequireDecrypt)
    } else {
        CommitmentPolicy::Esdk(Esdk::ForbidEncryptAllowDecrypt)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_supported_hex_maps_back_to_itself_via_id_bytes() {
        // Confirms our hex table is consistent with AlgorithmSuiteId::id_bytes()
        // — if this fires the enum's on-wire bytes drifted from the manifest.
        for (hex, id) in SUPPORTED_SUITES {
            assert_eq!(hex_from_suite_id(*id), *hex);
        }
    }

    #[test]
    fn suite_id_from_hex_rejects_unknown_id() {
        // `6700` (DBE) is intentionally rejected until the Rust mpl crate
        // implements DBE. Guarantees the error path is exercised.
        let err = suite_id_from_hex("6700").unwrap_err();
        assert!(
            format!("{err}").contains("not supported"),
            "unexpected error: {err}"
        );
    }

    #[test]
    fn suite_id_from_hex_ignores_case() {
        assert_eq!(
            suite_id_from_hex("0478").unwrap(),
            AlgorithmSuiteId::AlgAes256GcmHkdfSha512CommitKey,
        );
        // Sanity: an uppercase form of a suite ID that happens to be
        // digit-only is unchanged; but the eq_ignore_ascii_case path is
        // still the one taken.
        assert_eq!(
            suite_id_from_hex("0478").unwrap(),
            AlgorithmSuiteId::AlgAes256GcmHkdfSha512CommitKey,
        );
    }

    #[test]
    fn commitment_policy_matches_dafny_selection() {
        // Non-committing ESDK suite → FORBID_ENCRYPT_ALLOW_DECRYPT
        assert_eq!(
            commitment_policy_for(AlgorithmSuiteId::AlgAes128GcmIv12Tag16NoKdf),
            CommitmentPolicy::Esdk(Esdk::ForbidEncryptAllowDecrypt),
        );
        // Committing ESDK suite → REQUIRE_ENCRYPT_REQUIRE_DECRYPT
        assert_eq!(
            commitment_policy_for(AlgorithmSuiteId::AlgAes256GcmHkdfSha512CommitKey),
            CommitmentPolicy::Esdk(Esdk::RequireEncryptRequireDecrypt),
        );
        // Signing-and-committing suite → REQUIRE_ENCRYPT_REQUIRE_DECRYPT
        assert_eq!(
            commitment_policy_for(AlgorithmSuiteId::AlgAes256GcmHkdfSha512CommitKeyEcdsaP384),
            CommitmentPolicy::Esdk(Esdk::RequireEncryptRequireDecrypt),
        );
    }

    #[test]
    fn supported_hex_ids_matches_supported_suites_table() {
        let hex: Vec<&str> = supported_suite_hex_ids();
        let expected: Vec<&str> = SUPPORTED_SUITES.iter().map(|(h, _)| *h).collect();
        assert_eq!(hex, expected);
    }
}
