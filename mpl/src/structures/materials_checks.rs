// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

//! Checks that keyrings and CMMs return valid materials.
//! Ported from `Materials.dfy` in the Dafny MPL as the spec is weak here.

use crate::Error;

use super::{DecryptionMaterials, EncryptedDataKey, EncryptionMaterials};

/// The encryption context key that holds the verification key for a signing algorithm suite.
const PUBLIC_KEY_CONTEXT_KEY: &str = "aws-crypto-public-key";

/// Like Dafny `ValidEncryptionMaterials`.
/// Checks:
/// - a signing suite has a signing key
/// - the encryption context holds the verification key exactly when the suite signs
pub(crate) fn check_encryption_materials(materials: &EncryptionMaterials) -> Result<(), Error> {
    let signs = materials.algorithm_suite_id().has_asymmetric_signing();
    if signs && materials.signing_key().is_none() {
        return Err(Error::invalid_materials(
            "the encryption materials have a signing algorithm suite but no signing key",
        ));
    }
    check_public_key_context(
        signs,
        materials
            .encryption_context()
            .contains_key(PUBLIC_KEY_CONTEXT_KEY),
    )
}

/// Like Dafny `ValidDecryptionMaterials`.
/// Checks:
/// - a signing suite has a verification key
/// - the encryption context holds the verification key exactly when the suite signs
pub(crate) fn check_decryption_materials(materials: &DecryptionMaterials) -> Result<(), Error> {
    let signs = materials.algorithm_suite_id().has_asymmetric_signing();
    if signs && materials.verification_key().is_none() {
        return Err(Error::invalid_materials(
            "the decryption materials have a signing algorithm suite but no verification key",
        ));
    }
    check_public_key_context(
        signs,
        materials
            .encryption_context()
            .contains_key(PUBLIC_KEY_CONTEXT_KEY),
    )
}

fn check_public_key_context(signs: bool, has_public_key: bool) -> Result<(), Error> {
    match (signs, has_public_key) {
        (true, false) => Err(Error::invalid_materials(format!(
            "the materials have a signing algorithm suite but the encryption context has no '{PUBLIC_KEY_CONTEXT_KEY}'"
        ))),
        (false, true) => Err(Error::invalid_materials(format!(
            "the materials have a non-signing algorithm suite but the encryption context has '{PUBLIC_KEY_CONTEXT_KEY}'"
        ))),
        _ => Ok(()),
    }
}

/// Like Dafny `ValidEncryptionMaterialsTransition`.
/// Checks `new` against `old`:
/// - `new`: the materials that a keyring's `on_encrypt` returned
/// - `old`: the materials a keyring's `on_encrypt` was provided
///
/// The keyring may only:
/// - add a plaintext data key, if `old` has none
/// - add encrypted data keys
pub(crate) fn check_encryption_transition(
    old: &EncryptionMaterials,
    new: &EncryptionMaterials,
) -> Result<(), Error> {
    check_encryption_materials(old)?;
    check_encryption_materials(new)?;
    check_unchanged(
        new.algorithm_suite_id() == old.algorithm_suite_id(),
        "algorithm suite",
    )?;
    check_unchanged(
        new.encryption_context() == old.encryption_context(),
        "encryption context",
    )?;
    check_unchanged(
        new.required_encryption_context_keys() == old.required_encryption_context_keys(),
        "required encryption context keys",
    )?;
    check_unchanged(
        option_eq(old.signing_key(), new.signing_key(), |a, b| a.ct_eq(b)),
        "signing key",
    )?;
    let Some(new_key) = new.plaintext_data_key() else {
        return Err(Error::invalid_materials(
            "the keyring returned encryption materials without a plaintext data key",
        ));
    };
    if let Some(old_key) = old.plaintext_data_key() {
        check_unchanged(old_key.ct_eq(new_key), "plaintext data key")?;
    }
    if !contains_all(new.encrypted_data_keys(), old.encrypted_data_keys()) {
        return Err(Error::invalid_materials(
            "the keyring removed an encrypted data key from the encryption materials",
        ));
    }
    Ok(())
}

/// Like Dafny `DecryptionMaterialsTransitionIsValid`.
/// Checks `new` against `old`:
/// - `new`: the materials that a keyring's `on_decrypt` returned
/// - `old`: the materials a keyring's `on_decrypt` was provided
///
/// The keyring may only:
/// - add a plaintext data key, and `old` must have none
pub(crate) fn check_decryption_transition(
    old: &DecryptionMaterials,
    new: &DecryptionMaterials,
) -> Result<(), Error> {
    check_decryption_materials(old)?;
    check_decryption_materials(new)?;
    if old.plaintext_data_key().is_some() {
        return Err(Error::invalid_materials(
            "the decryption materials already have a plaintext data key",
        ));
    }
    check_unchanged(
        new.algorithm_suite_id() == old.algorithm_suite_id(),
        "algorithm suite",
    )?;
    check_unchanged(
        new.encryption_context() == old.encryption_context(),
        "encryption context",
    )?;
    check_unchanged(
        new.required_encryption_context_keys() == old.required_encryption_context_keys(),
        "required encryption context keys",
    )?;
    check_unchanged(
        new.verification_key() == old.verification_key(),
        "verification key",
    )?;
    if new.plaintext_data_key().is_none() {
        return Err(Error::invalid_materials(
            "the keyring returned decryption materials without a plaintext data key",
        ));
    }
    Ok(())
}

/// Like Dafny `EncryptionMaterialsHasPlaintextDataKey`.
/// Checks the materials that a CMM's `get_encryption_materials` returned:
/// - they have a plaintext data key
/// - they have at least one encrypted data key
/// - they pass `check_encryption_materials`
pub(crate) fn check_encryption_materials_complete(
    materials: &EncryptionMaterials,
) -> Result<(), Error> {
    if materials.plaintext_data_key().is_none() {
        return Err(Error::invalid_materials(
            "the encryption materials have no plaintext data key",
        ));
    }
    if materials.encrypted_data_keys().is_empty() {
        return Err(Error::invalid_materials(
            "the encryption materials have no encrypted data keys",
        ));
    }
    check_encryption_materials(materials)
}

/// Like Dafny `DecryptionMaterialsWithPlaintextDataKey`.
/// Checks the materials that a CMM's `decrypt_materials` returned:
/// - they have a plaintext data key
/// - they pass `check_decryption_materials`
pub(crate) fn check_decryption_materials_complete(
    materials: &DecryptionMaterials,
) -> Result<(), Error> {
    if materials.plaintext_data_key().is_none() {
        return Err(Error::invalid_materials(
            "the decryption materials have no plaintext data key",
        ));
    }
    check_decryption_materials(materials)
}

fn check_unchanged(unchanged: bool, field: &str) -> Result<(), Error> {
    if unchanged {
        Ok(())
    } else {
        Err(Error::invalid_materials(format!(
            "the keyring changed the materials' {field}"
        )))
    }
}

fn option_eq<T>(a: Option<&T>, b: Option<&T>, eq: impl Fn(&T, &T) -> bool) -> bool {
    match (a, b) {
        (None, None) => true,
        (Some(a), Some(b)) => eq(a, b),
        _ => false,
    }
}

/// Whether `haystack` holds every key in `needles`, counting repeats.
fn contains_all(haystack: &[EncryptedDataKey], needles: &[EncryptedDataKey]) -> bool {
    let mut used = vec![false; haystack.len()];
    needles.iter().all(|needle| {
        let found = haystack
            .iter()
            .zip(used.iter_mut())
            .find(|(key, used)| !**used && *key == needle);
        found.map(|(_, used)| *used = true).is_some()
    })
}
