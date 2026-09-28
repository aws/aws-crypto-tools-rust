// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

//! Converting an existing `Shared*` handle reuses it instead of nesting it.

use aws_config::{BehaviorVersion, SdkConfig};
use aws_crypto_mpl::aws_kms::hierarchical_keyring::{GetBranchKeyIdInput, GetBranchKeyIdOutput};
use aws_crypto_mpl::structures::MaterialsError;
use aws_crypto_mpl::{
    AesGcm, BranchKeyStore, BranchKeySupplier, Cmc, Cmm, DefaultCmm, IntoShared, KeyStoreConfig,
    Keyring, Keystore, KmsConfiguration, LocalCmc, RawAesKeyring, SharedBranchKeySupplier,
    SharedCmc, SharedCmm, SharedKeyring, SharedKeystore,
};

fn keyring() -> RawAesKeyring {
    RawAesKeyring::new("namespace", "name", vec![0; 32], AesGcm::Aes256Gcm).unwrap()
}

fn keystore() -> BranchKeyStore {
    let cfg = SdkConfig::builder()
        .behavior_version(BehaviorVersion::latest())
        .build();
    BranchKeyStore::with_clients(KeyStoreConfig {
        ddb_table_name: "test-table".to_string(),
        kms_configuration: KmsConfiguration::KmsKeyArn(
            "arn:aws:kms:us-west-2:111122223333:key/1234abcd-12ab-34cd-56ef-1234567890ab"
                .to_string(),
        ),
        logical_keystore_name: "test-logical".to_string(),
        id: None,
        grant_tokens: None,
        ddb_client: Some(aws_sdk_dynamodb::Client::new(&cfg)),
        kms_client: Some(aws_sdk_kms::Client::new(&cfg)),
    })
    .unwrap()
}

fn cache() -> LocalCmc {
    LocalCmc::new(1, 1).unwrap()
}

struct Supplier;

impl BranchKeySupplier for Supplier {
    fn get_branch_key_id(
        &self,
        _input: GetBranchKeyIdInput,
    ) -> Result<GetBranchKeyIdOutput, MaterialsError> {
        Ok(GetBranchKeyIdOutput::new("branch-key-id".to_string()))
    }
}

/// Asserts that converting an existing handle reuses it instead of nesting it,
/// through both `new` and `into_shared`, where `impl Trait` is accepted.
macro_rules! assert_reuses_handle {
    ($handle:ident, $trait:ident, $make:expr) => {{
        fn into_handle(component: impl $trait + 'static) -> $handle {
            component.into_shared()
        }

        let original = $handle::new($make);
        assert!(
            $handle::ptr_eq(&original, &into_handle(original.clone())),
            "into_shared on a {} must reuse it",
            stringify!($handle),
        );
        assert!(
            $handle::ptr_eq(&original, &$handle::new(original.clone())),
            "{}::new on a {} must reuse it",
            stringify!($handle),
            stringify!($handle),
        );
        assert!(
            !$handle::ptr_eq(&original, &$handle::new($make)),
            "separately built components must not compare equal",
        );
    }};
}

#[test]
fn shared_keyring_reuses_handle() {
    assert_reuses_handle!(SharedKeyring, Keyring, keyring());
}

#[test]
fn shared_cmm_reuses_handle() {
    assert_reuses_handle!(SharedCmm, Cmm, DefaultCmm::new(keyring()));
}

#[test]
fn shared_keystore_reuses_handle() {
    assert_reuses_handle!(SharedKeystore, Keystore, keystore());
}

#[test]
fn shared_cmc_reuses_handle() {
    assert_reuses_handle!(SharedCmc, Cmc, cache());
}

#[test]
fn shared_branch_key_supplier_reuses_handle() {
    assert_reuses_handle!(SharedBranchKeySupplier, BranchKeySupplier, Supplier);
}
