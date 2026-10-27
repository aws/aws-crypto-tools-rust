// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

//! Converting an existing `Shared*` handle with `into_shared` reuses it instead of nesting it,
//! and a handle's fluent builders reach the component it wraps.

use aws_crypto_mpl::Error;
use aws_crypto_mpl::async_trait;
use aws_crypto_mpl::cmc::{LocalCmc, SharedCmc};
use aws_crypto_mpl::cmm::{DefaultCmm, SharedCmm};
use aws_crypto_mpl::keyring::{
    BranchKeySupplier, RawAesKeyring, SharedBranchKeySupplier, SharedKeyring,
};
use aws_crypto_mpl::keyring::{GetBranchKeyIdInput, GetBranchKeyIdOutput};
use aws_crypto_mpl::shared::IntoShared;
use aws_crypto_mpl::types::AesWrappingAlg;
use aws_crypto_mpl::types::{
    AlgorithmSuiteId, EncryptionContext, EncryptionMaterials, EsdkAlgorithmSuiteId,
};
use aws_crypto_mpl::types::{CacheEntry, CachedMaterials};
use std::time::{Duration, SystemTime};

fn keyring() -> RawAesKeyring {
    RawAesKeyring::builder()
        .key_namespace("namespace")
        .key_name("name")
        .wrapping_key(vec![0; 32])
        .wrapping_alg(AesWrappingAlg::AlgAes256GcmIv12Tag16)
        .build()
        .unwrap()
}

fn cache() -> LocalCmc {
    LocalCmc::builder()
        .entry_capacity(1)
        .entry_pruning_tail_size(1)
        .build()
        .unwrap()
}

/// Returns the encryption context's `tenant` value as the branch key ID.
struct Supplier;

#[async_trait]
impl BranchKeySupplier for Supplier {
    async fn get_branch_key_id(
        &self,
        input: GetBranchKeyIdInput,
    ) -> Result<GetBranchKeyIdOutput, Error> {
        let tenant = input.encryption_context().get("tenant").unwrap_or_default();
        GetBranchKeyIdOutput::builder()
            .branch_key_id(tenant)
            .build()
    }
}

/// Asserts that `into_shared` reuses an existing handle instead of nesting it.
macro_rules! assert_reuses_handle {
    ($handle:ident, $make:expr) => {{
        fn into_handle(component: impl IntoShared<$handle>) -> $handle {
            component.into_shared()
        }

        let original = into_handle($make);
        assert!(
            $handle::ptr_eq(&original, &into_handle(original.clone())),
            "into_shared on a {} must reuse it",
            stringify!($handle),
        );
        assert!(
            !$handle::ptr_eq(&original, &into_handle($make)),
            "separately built components must not compare equal",
        );
    }};
}

#[test]
fn shared_keyring_reuses_handle() {
    assert_reuses_handle!(SharedKeyring, keyring());
}

#[test]
fn shared_cmm_reuses_handle() {
    assert_reuses_handle!(SharedCmm, DefaultCmm::new(keyring()));
}

#[test]
fn shared_cmc_reuses_handle() {
    assert_reuses_handle!(SharedCmc, cache());
}

#[test]
fn shared_branch_key_supplier_reuses_handle() {
    assert_reuses_handle!(SharedBranchKeySupplier, Supplier);
}

#[test]
fn a_handle_keeps_the_built_in_name() {
    let raw = keyring();
    let name = raw.name().into_owned();
    assert_eq!(SharedKeyring::new(raw).name(), name);

    let cmm = DefaultCmm::new(keyring());
    let name = cmm.name().into_owned();
    assert_eq!(SharedCmm::new(cmm).name(), name);
}

#[tokio::test]
async fn shared_cmc_fluent_builders_reach_the_cache() {
    let cache = SharedCmc::new(cache());
    let now = SystemTime::now();
    let materials = EncryptionMaterials::builder()
        .algorithm_suite_id(AlgorithmSuiteId::Esdk(
            EsdkAlgorithmSuiteId::AlgAes256GcmHkdfSha512CommitKey,
        ))
        .build()
        .unwrap();
    let entry = CacheEntry::builder()
        .materials(CachedMaterials::Encryption(materials))
        .creation_time(now)
        .expiry_time(now + Duration::from_secs(3600))
        .build()
        .unwrap();
    cache
        .put_cache_entry()
        .identifier(b"id")
        .entry(entry)
        .send()
        .await
        .unwrap();
    cache
        .update_usage_metadata()
        .identifier(b"id")
        .bytes_used(7)
        .send()
        .await
        .unwrap();

    let usage = cache
        .get_cache_entry()
        .identifier(b"id")
        .send()
        .await
        .unwrap()
        .into_entry()
        .expect("the entry put above")
        .usage_metadata();
    assert_eq!(usage.messages_used().get(), 1);
    assert_eq!(usage.bytes_used().get(), 7);

    cache
        .delete_cache_entry()
        .identifier(b"id")
        .send()
        .await
        .unwrap();
    let after_delete = cache
        .get_cache_entry()
        .identifier(b"id")
        .send()
        .await
        .unwrap();
    assert!(after_delete.entry().is_none());
}

#[tokio::test]
async fn shared_branch_key_supplier_fluent_builder_reaches_the_supplier() {
    let mut encryption_context = EncryptionContext::new();
    encryption_context.insert("tenant", "tenant-a");
    let output = SharedBranchKeySupplier::new(Supplier)
        .get_branch_key_id()
        .set_encryption_context(Some(encryption_context))
        .send()
        .await
        .unwrap();
    assert_eq!(output.branch_key_id(), "tenant-a");
}
