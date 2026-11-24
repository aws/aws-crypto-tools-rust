// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

use aws_esdk::types::CommitmentPolicy;
use aws_esdk::{Client, Config, Error};

#[test]
fn builder() -> Result<(), Error> {
    // api-example: api=client way=builder takes=none kind=pass
    // snippet-start
    let esdk_client = Client::builder()
        .commitment_policy(CommitmentPolicy::RequireEncryptRequireDecrypt)
        .max_encrypted_data_keys(3)
        .build()?;
    // snippet-end
    assert_eq!(
        esdk_client.config().commitment_policy(),
        CommitmentPolicy::RequireEncryptRequireDecrypt
    );
    assert_eq!(esdk_client.config().max_encrypted_data_keys(), Some(3));
    Ok(())
}

#[test]
fn from_conf() -> Result<(), Error> {
    // api-example: api=client way=from_conf takes=Config kind=pass
    // snippet-start
    let config = Config::builder().max_encrypted_data_keys(3).build()?;
    let esdk_client = Client::from_conf(config);
    // snippet-end
    let esdk_client_from_builder = Client::builder().max_encrypted_data_keys(3).build()?;
    assert_eq!(
        esdk_client.config().max_encrypted_data_keys(),
        esdk_client_from_builder.config().max_encrypted_data_keys()
    );
    assert_eq!(
        esdk_client.config().commitment_policy(),
        esdk_client_from_builder.config().commitment_policy()
    );
    Ok(())
}

#[test]
fn default() -> Result<(), Error> {
    // api-example: api=client way=default takes=none kind=pass
    // snippet-start
    let esdk_client = Client::default();
    // snippet-end
    let esdk_client_from_builder = Client::builder().build()?;
    assert_eq!(
        esdk_client.config().commitment_policy(),
        esdk_client_from_builder.config().commitment_policy()
    );
    assert_eq!(
        esdk_client.config().max_encrypted_data_keys(),
        esdk_client_from_builder.config().max_encrypted_data_keys()
    );
    Ok(())
}

#[test]
fn commitment_policy() -> Result<(), Error> {
    // api-example: api=client way=commitment_policy takes=CommitmentPolicy kind=pass
    // snippet-start
    let esdk_client = Client::builder()
        .commitment_policy(CommitmentPolicy::RequireEncryptAllowDecrypt)
        .build()?;
    // snippet-end
    assert_eq!(
        esdk_client.config().commitment_policy(),
        CommitmentPolicy::RequireEncryptAllowDecrypt
    );

    // api-example: api=client way=set_commitment_policy takes=Option<CommitmentPolicy> kind=pass
    // snippet-start
    let commitment_policy: Option<CommitmentPolicy> =
        Some(CommitmentPolicy::RequireEncryptAllowDecrypt);
    let mut client_builder = Client::builder();
    client_builder.set_commitment_policy(commitment_policy);
    let esdk_client_from_option = client_builder.build()?;
    // snippet-end
    assert_eq!(
        esdk_client_from_option.config().commitment_policy(),
        esdk_client.config().commitment_policy()
    );

    // api-example: api=client way=commitment_policy kind=omitted
    // snippet-start
    let esdk_client = Client::builder().build()?;
    // snippet-end
    assert_eq!(
        esdk_client.config().commitment_policy(),
        CommitmentPolicy::RequireEncryptRequireDecrypt
    );
    Ok(())
}

#[test]
fn max_encrypted_data_keys() -> Result<(), Error> {
    // api-example: api=client way=max_encrypted_data_keys takes=usize kind=pass
    // snippet-start
    let esdk_client = Client::builder().max_encrypted_data_keys(3).build()?;
    // snippet-end
    assert_eq!(esdk_client.config().max_encrypted_data_keys(), Some(3));

    // api-example: api=client way=set_max_encrypted_data_keys takes=Option<usize> kind=pass
    // snippet-start
    let max_encrypted_data_keys: Option<usize> = Some(3);
    let mut client_builder = Client::builder();
    client_builder.set_max_encrypted_data_keys(max_encrypted_data_keys);
    let esdk_client_from_option = client_builder.build()?;
    // snippet-end
    assert_eq!(
        esdk_client_from_option.config().max_encrypted_data_keys(),
        esdk_client.config().max_encrypted_data_keys()
    );

    // api-example: api=client way=max_encrypted_data_keys kind=omitted
    // snippet-start
    let esdk_client = Client::builder().build()?;
    // snippet-end
    assert_eq!(esdk_client.config().max_encrypted_data_keys(), None);

    // api-example: api=client way=max_encrypted_data_keys takes=usize kind=reject
    // snippet-start
    let result = Client::builder().max_encrypted_data_keys(0).build();
    // snippet-end
    assert!(result.is_err_and(|error| error.is_validation()));
    Ok(())
}
