//! Translate the modeled CMM/Keyring configuration into a vendored-MPL
//! `KeyringRef`. Constructing any keyring currently routes through the MPL's
//! `create_*_keyring` functions.
//!
//! Enforces the "exactly one variant member set" invariant that the Smithy
//! tagged-union-via-optional-members shapes cannot express in the type system.

use crate::error::ServerError;
use crate::model::{AesWrappingAlg, CryptographicMaterialsManager, Keyring, RawAesKeyringConfig};
use aws_mpl_legacy::keyring::{
    AesWrappingAlg as MplAesWrappingAlg, CreateRawAesKeyringInput, KeyringRef,
};

/// Resolve a CMM configuration to the keyring the ESDK client will use.
///
/// The ESDK for Rust accepts a keyring and wraps it in a default CMM, so a
/// `Default` CMM resolves to its inner keyring.
pub fn keyring_for_cmm(cmm: &CryptographicMaterialsManager) -> Result<KeyringRef, ServerError> {
    let set = [
        cmm.default_cmm.is_some(),
        cmm.required_encryption_context.is_some(),
        cmm.caching.is_some(),
    ]
    .iter()
    .filter(|present| **present)
    .count();
    if set != 1 {
        return Err(ServerError::generic(format!(
            "CryptographicMaterialsManager must set exactly one variant, found {set}"
        )));
    }

    if let Some(default_cmm) = &cmm.default_cmm {
        return build_keyring(&default_cmm.keyring);
    }
    Err(ServerError::generic(
        "only the Default CMM is wired in the Rust language server",
    ))
}

/// Build a `KeyringRef` from a modeled `Keyring`.
pub fn build_keyring(keyring: &Keyring) -> Result<KeyringRef, ServerError> {
    let set = [
        keyring.aws_kms.is_some(),
        keyring.aws_kms_mrk.is_some(),
        keyring.aws_kms_multi.is_some(),
        keyring.aws_kms_discovery.is_some(),
        keyring.aws_kms_rsa.is_some(),
        keyring.raw_aes.is_some(),
        keyring.raw_rsa.is_some(),
        keyring.multi.is_some(),
    ]
    .iter()
    .filter(|present| **present)
    .count();
    if set != 1 {
        return Err(ServerError::generic(format!(
            "Keyring must set exactly one variant, found {set}"
        )));
    }

    if let Some(raw_aes) = &keyring.raw_aes {
        return build_raw_aes(raw_aes);
    }
    Err(ServerError::generic(
        "only the RawAes keyring is wired in the Rust language server",
    ))
}

fn build_raw_aes(config: &RawAesKeyringConfig) -> Result<KeyringRef, ServerError> {
    let wrapping_alg = match config.wrapping_alg {
        AesWrappingAlg::Alg128 => MplAesWrappingAlg::AlgAes128GcmIv12Tag16,
        AesWrappingAlg::Alg192 => MplAesWrappingAlg::AlgAes192GcmIv12Tag16,
        AesWrappingAlg::Alg256 => MplAesWrappingAlg::AlgAes256GcmIv12Tag16,
    };
    CreateRawAesKeyringInput::new(
        config.key_namespace.clone(),
        config.key_name.clone(),
        config.wrapping_key.clone(),
        wrapping_alg,
    )
    .go()
    .map_err(ServerError::from_mpl)
}
