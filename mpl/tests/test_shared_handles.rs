// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

//! Converting an existing `Shared*` handle reuses it instead of nesting it.

use aws_crypto_mpl::Error;
use aws_crypto_mpl::aws_kms::hierarchical_keyring::{GetBranchKeyIdInput, GetBranchKeyIdOutput};
use aws_crypto_mpl::{
    AesGcm, BranchKeySupplier, Cmc, Cmm, DefaultCmm, IntoShared, Keyring, LocalCmc, RawAesKeyring,
    SharedBranchKeySupplier, SharedCmc, SharedCmm, SharedKeyring,
};

fn keyring() -> RawAesKeyring {
    RawAesKeyring::builder()
        .key_namespace("namespace")
        .key_name("name")
        .wrapping_key(vec![0; 32])
        .wrapping_alg(AesGcm::Aes256Gcm)
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

struct Supplier;

impl BranchKeySupplier for Supplier {
    fn get_branch_key_id(
        &self,
        _input: GetBranchKeyIdInput,
    ) -> Result<GetBranchKeyIdOutput, Error> {
        Ok(GetBranchKeyIdOutput::new("branch-key-id".to_string()))
    }
}

/// Asserts that `new` and `into_shared` reuse an existing handle instead of nesting it.
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
fn shared_cmc_reuses_handle() {
    assert_reuses_handle!(SharedCmc, Cmc, cache());
}

#[test]
fn shared_branch_key_supplier_reuses_handle() {
    assert_reuses_handle!(SharedBranchKeySupplier, BranchKeySupplier, Supplier);
}
