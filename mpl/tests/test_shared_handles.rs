// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

//! Each `Shared*` handle wraps an `Arc` it is given without re-wrapping it.

use std::ptr::addr_eq;
use std::sync::Arc;

use aws_config::{BehaviorVersion, SdkConfig};
use aws_crypto_mpl::{
    AesGcm, BranchKeyStore, Cmc, Cmm, DefaultCmm, KeyStoreConfig, Keyring, Keystore,
    KmsConfiguration, LocalCmc, RawAesKeyring, SharedCmc, SharedCmm, SharedKeyring, SharedKeystore,
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

/// Asserts the three `Arc`-reusing conversions of one handle type:
/// - from `Arc<T>`
/// - from `Arc<dyn Trait>`
/// - from an existing handle, passed where `impl Into<Handle>` is accepted
macro_rules! assert_reuses_arc {
    ($handle:ident, $trait:ident, $make:expr) => {{
        fn into_handle(component: impl Into<$handle>) -> $handle {
            component.into()
        }

        let concrete = Arc::new($make);
        let from_concrete = into_handle(Arc::clone(&concrete));
        assert!(
            addr_eq(Arc::as_ptr(&concrete), &*from_concrete),
            "{} from Arc<T> must reuse the caller's Arc",
            stringify!($handle),
        );

        let erased: Arc<dyn $trait> = Arc::new($make);
        let from_erased = into_handle(Arc::clone(&erased));
        assert!(
            addr_eq(Arc::as_ptr(&erased), &*from_erased),
            "{} from Arc<dyn {}> must reuse the caller's Arc",
            stringify!($handle),
            stringify!($trait),
        );

        let from_handle = into_handle(from_concrete.clone());
        assert!(
            addr_eq(&*from_concrete, &*from_handle),
            "{} from an existing handle must not re-wrap it",
            stringify!($handle),
        );
    }};
}

#[test]
fn shared_keyring_reuses_arc() {
    assert_reuses_arc!(SharedKeyring, Keyring, keyring());
}

#[test]
fn shared_cmm_reuses_arc() {
    assert_reuses_arc!(SharedCmm, Cmm, DefaultCmm::new(keyring()));
}

#[test]
fn shared_keystore_reuses_arc() {
    assert_reuses_arc!(SharedKeystore, Keystore, keystore());
}

#[test]
fn shared_cmc_reuses_arc() {
    assert_reuses_arc!(SharedCmc, Cmc, cache());
}
