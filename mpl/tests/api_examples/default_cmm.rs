// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

use std::time::Duration;

use super::{dynamodb_key_store, raw_aes_keyring};
use aws_crypto_mpl::Error;
use aws_crypto_mpl::cmm::DefaultCmm;
use aws_crypto_mpl::keyring::HierarchicalKeyring;
use aws_crypto_mpl::types::{CommitmentPolicy, EncryptionContext, EsdkCommitmentPolicy};

#[tokio::test]
async fn new_with_raw_aes_keyring() -> Result<(), Error> {
    // api-example: api=default-cmm way=new takes=RawAesKeyring kind=pass have="a keyring"
    // snippet-start
    let raw_aes_keyring = raw_aes_keyring();
    let default_cmm = DefaultCmm::new(raw_aes_keyring);
    // snippet-end
    // The materials carry one encrypted data key, which the raw AES keyring wrapped.
    let materials = default_cmm
        .get_encryption_materials()
        .set_encryption_context(Some(EncryptionContext::new()))
        .commitment_policy(CommitmentPolicy::Esdk(
            EsdkCommitmentPolicy::RequireEncryptRequireDecrypt,
        ))
        .send()
        .await?
        .into_encryption_materials();
    assert_eq!(materials.encrypted_data_keys().len(), 1);
    assert_eq!(
        materials.encrypted_data_keys()[0].key_provider_id(),
        "my-key-namespace"
    );
    Ok(())
}

// Getting materials from a hierarchical keyring calls AWS, so the test only checks that the CMM builds.
#[allow(unused_variables)]
#[tokio::test]
async fn new_with_hierarchical_keyring() -> Result<(), Error> {
    let dynamodb_key_store = dynamodb_key_store().await;
    // api-example: api=default-cmm way=new takes=HierarchicalKeyring kind=pass have="a keyring"
    // snippet-start
    let hierarchical_keyring = HierarchicalKeyring::builder()
        .key_store(dynamodb_key_store)
        .branch_key_id("my-branch-key-id")
        .ttl(Duration::from_secs(600))
        .build()
        .await?;
    let default_cmm = DefaultCmm::new(hierarchical_keyring);
    // snippet-end
    Ok(())
}
