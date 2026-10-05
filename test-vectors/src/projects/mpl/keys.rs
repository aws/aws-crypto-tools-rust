// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

//! Curated `keys.json` entries for the MPL vector suite.
//!
//! Every key entry that appears in the reference `keys.json` from the MPL
//! Dafny test-vectors project is available here, but the [`MplProject`] only
//! emits the subset needed by the keyrings implemented in the Rust `mpl`
//! crate today. Extending support for a new keyring is a two-step change:
//!
//! 1. Add its identifiers to the appropriate [`KeyGroup`] (or add a new
//!    variant if none of the existing ones fit).
//! 2. Register the group in `SUPPORTED_KEY_GROUPS` in `super::mod`.
//!
//! The full reference JSON is embedded via `include_str!` so
//! [`all_keys`] is the single source of truth for every entry's shape and
//! byte content — no hand-typed literals to drift out of sync.
//!
//! [`MplProject`]: super::MplProject

use std::sync::OnceLock;

use indexmap::IndexMap;

use crate::manifest::keys::KeyManifest;

/// Raw JSON copy of the reference `keys.json` used by the MPL Dafny
/// test-vectors project. Kept verbatim so the entries below match byte-for-byte
/// what other language implementations emit.
const REFERENCE_KEYS_JSON: &str = include_str!("reference_keys.json");

/// Named grouping of key IDs from the reference `keys.json`.
///
/// Groups correspond to the MPL keyring flavor that consumes them. Adding a
/// new keyring implementation should either extend an existing group or add
/// a new variant, then register it in `SUPPORTED_KEY_GROUPS`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum KeyGroup {
    /// `aws-kms-hierarchy` keyring keys.
    Hierarchy,
    /// `static-material` keyring keys (fixed plaintext/edk pairs).
    StaticMaterial,
    /// Raw AES keyring keys (`raw-aes`).
    RawAes,
    /// Raw RSA keyring keys (`raw-rsa`, public + private).
    RawRsa,
    /// Raw ECDH keyring keys (`raw-ecdh`).
    RawEcdh,
    /// AWS KMS keyring keys (regular and MRK variants).
    AwsKms,
    /// AWS KMS RSA keyring keys.
    AwsKmsRsa,
    /// AWS KMS ECDH keyring keys.
    AwsKmsEcdh,
}

impl KeyGroup {
    /// The key IDs — the top-level keys of the `keys` object in
    /// `keys.json` — that belong to this group.
    pub const fn key_ids(&self) -> &'static [&'static str] {
        match self {
            KeyGroup::Hierarchy => &["static-branch-key-1"],

            KeyGroup::StaticMaterial => &[
                "no-plaintext-data-key",
                "static-plaintext-data-key",
                "static-cashable-plaintext-data-key",
            ],

            KeyGroup::RawAes => &[
                "aes-128",
                "aes-192",
                "aes-256",
                "𝟁-nonascii-𐀂-aes-256-𝟁-with-\u{FFFD}",
            ],

            KeyGroup::RawRsa => &["rsa-4096-private", "rsa-4096-public"],

            KeyGroup::RawEcdh => &["ecc-256-private", "ecc-384-private", "ecc-521-private"],

            KeyGroup::AwsKms => &[
                "us-west-2-decryptable",
                "us-west-2-encrypt-only",
                "us-west-2-mrk",
                "us-east-1-mrk",
            ],

            KeyGroup::AwsKmsRsa => &["us-west-2-rsa-mrk"],

            KeyGroup::AwsKmsEcdh => &[
                "us-west-2-256-ecc",
                "us-west-2-384-ecc",
                "us-west-2-521-ecc",
            ],
        }
    }

    /// Every group defined in this enum. Handy for exhaustiveness tests that
    /// verify every declared key ID is resolvable in the reference registry.
    pub const fn all() -> &'static [KeyGroup] {
        &[
            KeyGroup::Hierarchy,
            KeyGroup::StaticMaterial,
            KeyGroup::RawAes,
            KeyGroup::RawRsa,
            KeyGroup::RawEcdh,
            KeyGroup::AwsKms,
            KeyGroup::AwsKmsRsa,
            KeyGroup::AwsKmsEcdh,
        ]
    }
}

/// Lazily-parsed reference registry mapping key ID -> raw JSON entry.
///
/// Panics on first access if the embedded `reference_keys.json` fails to
/// parse — that would indicate a corrupt file check-in and the tests would
/// catch it before it shipped.
fn reference() -> &'static KeyManifest {
    static CELL: OnceLock<KeyManifest> = OnceLock::new();
    CELL.get_or_init(|| {
        serde_json::from_str(REFERENCE_KEYS_JSON)
            .expect("embedded reference_keys.json failed to parse as KeyManifest")
    })
}

/// Every key entry known to the reference `keys.json`, keyed by ID. Insertion
/// order matches the source file thanks to `serde_json`'s `preserve_order`
/// feature and our own [`KeyManifest`] using [`IndexMap`].
pub fn all_keys() -> &'static IndexMap<String, serde_json::Value> {
    &reference().keys
}

/// Compose a [`KeyManifest`] containing exactly the entries for `groups`, in
/// the order they appear in the reference `keys.json`. Duplicates across
/// groups are ignored — each entry is emitted at most once.
///
/// # Errors
///
/// Returns [`ComposeError::UnknownKey`] if any declared group references an
/// ID that is not present in the reference `keys.json`. This can only happen
/// if the reference file drifts out of sync with [`KeyGroup::key_ids`] —
/// the [`test::every_declared_key_exists`] test guards against that at CI time.
pub fn compose(groups: &[KeyGroup]) -> Result<KeyManifest, ComposeError> {
    let all = all_keys();
    let mut manifest = KeyManifest::new();
    // Walk the reference registry in its original order so composed manifests
    // stay diff-stable regardless of the order `groups` is passed in.
    let wanted: std::collections::HashSet<&str> = groups
        .iter()
        .flat_map(|g| g.key_ids().iter().copied())
        .collect();

    // Sanity check: every declared ID must resolve.
    for id in &wanted {
        if !all.contains_key(*id) {
            return Err(ComposeError::UnknownKey((*id).to_string()));
        }
    }

    for (id, entry) in all {
        if wanted.contains(id.as_str()) {
            manifest.insert(id.clone(), entry.clone());
        }
    }
    Ok(manifest)
}

/// Errors returned by [`compose`].
#[derive(Debug, thiserror::Error)]
pub enum ComposeError {
    /// A key ID declared in one of the [`KeyGroup`] variants is missing from
    /// the embedded `reference_keys.json`.
    #[error(
        "reference keys.json is missing '{0}' — this indicates the reference \
         file has drifted from the KeyGroup definitions"
    )]
    UnknownKey(String),
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reference_json_parses_as_key_manifest() {
        // If this fires, the embedded reference_keys.json is malformed or the
        // KeyManifest schema drifted.
        let manifest = reference();
        assert_eq!(manifest.manifest.manifest_type, "keys");
        assert_eq!(manifest.manifest.version, 2);
        assert!(!manifest.keys.is_empty(), "reference keys map is empty");
    }

    #[test]
    fn every_declared_key_exists() {
        // Enforces that every ID referenced by a KeyGroup resolves to an
        // entry in the reference registry. This is the guard that keeps
        // `compose` from returning UnknownKey during normal operation.
        let all = all_keys();
        for group in KeyGroup::all() {
            for id in group.key_ids() {
                assert!(
                    all.contains_key(*id),
                    "KeyGroup::{:?} declares '{}' but it is not in reference_keys.json",
                    group,
                    id,
                );
            }
        }
    }

    #[test]
    fn compose_hierarchy_returns_expected_entries() {
        let manifest = compose(&[KeyGroup::Hierarchy]).unwrap();
        assert_eq!(manifest.manifest.manifest_type, "keys");
        assert_eq!(manifest.manifest.version, 2);
        assert_eq!(manifest.keys.len(), 1);
        assert!(manifest.get("static-branch-key-1").is_some());
    }

    #[test]
    fn compose_preserves_reference_order_across_groups() {
        // Passing groups in reversed declaration order still yields entries
        // in the reference file's original order.
        let manifest = compose(&[KeyGroup::AwsKms, KeyGroup::StaticMaterial]).unwrap();
        let emitted: Vec<&str> = manifest.keys.keys().map(String::as_str).collect();
        // StaticMaterial keys appear before AwsKms keys in reference_keys.json.
        assert_eq!(
            emitted,
            vec![
                "no-plaintext-data-key",
                "static-plaintext-data-key",
                "static-cashable-plaintext-data-key",
                "us-west-2-decryptable",
                "us-west-2-encrypt-only",
                "us-west-2-mrk",
                "us-east-1-mrk",
            ]
        );
    }

    #[test]
    fn compose_deduplicates_when_groups_overlap() {
        // Compose the same group twice — every entry should appear exactly once.
        let manifest = compose(&[KeyGroup::Hierarchy, KeyGroup::Hierarchy]).unwrap();
        assert_eq!(manifest.keys.len(), 1);
    }

    #[test]
    fn compose_of_all_groups_matches_reference_size() {
        // Composing every group should reproduce the full reference set.
        let manifest = compose(KeyGroup::all()).unwrap();
        assert_eq!(manifest.keys.len(), all_keys().len());
    }
}
