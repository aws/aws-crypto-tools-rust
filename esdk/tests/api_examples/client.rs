// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

use super::support::*;

#[test]
fn builder() -> Result<(), Error> {
    // api-example: api=client frame way=builder
    let esdk_client = Client::builder()
        // api-example: tail
        .build()?;
    // api-example: end
    assert_eq!(
        esdk_client.config().commitment_policy(),
        Client::default().config().commitment_policy()
    );
    Ok(())
}

#[test]
fn from_conf() -> Result<(), Error> {
    // api-example: api=client way=from_conf have="a config" takes=Config
    let config = Config::builder().max_encrypted_data_keys(3).build()?;
    let esdk_client = Client::from_conf(config);
    // api-example: end
    assert_eq!(esdk_client.config().max_encrypted_data_keys(), Some(3));
    Ok(())
}

#[test]
fn default() -> Result<(), Error> {
    // api-example: api=client way=default have="nothing"
    let esdk_client = Client::default();
    // api-example: end
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
    // api-example: api=client way=commitment_policy have="one of the listed choices" takes=CommitmentPolicy
    let esdk_client = Client::builder()
        // api-example: setter
        .commitment_policy(CommitmentPolicy::RequireEncryptAllowDecrypt)
        .build()?;
    // api-example: end
    assert_eq!(
        esdk_client.config().commitment_policy(),
        CommitmentPolicy::RequireEncryptAllowDecrypt
    );

    // api-example: api=client way=set_commitment_policy have="one of the listed choices" takes=Option<CommitmentPolicy> alt
    let mut client_builder = Client::builder();
    // api-example: setter
    client_builder.set_commitment_policy(Some(CommitmentPolicy::RequireEncryptAllowDecrypt));
    let esdk_client = client_builder.build()?;
    // api-example: end
    assert_eq!(
        esdk_client.config().commitment_policy(),
        CommitmentPolicy::RequireEncryptAllowDecrypt
    );

    // api-example: api=client way=commitment_policy left-out
    let esdk_client = Client::builder().build()?;
    // api-example: end
    assert_eq!(
        esdk_client.config().commitment_policy(),
        CommitmentPolicy::RequireEncryptRequireDecrypt
    );
    Ok(())
}

#[test]
fn max_encrypted_data_keys() -> Result<(), Error> {
    // api-example: api=client way=max_encrypted_data_keys have="a number" takes=usize
    let esdk_client = Client::builder()
        // api-example: setter
        .max_encrypted_data_keys(3)
        .build()?;
    // api-example: end
    assert_eq!(esdk_client.config().max_encrypted_data_keys(), Some(3));

    // api-example: api=client way=set_max_encrypted_data_keys have="a number" takes=Option<usize> alt
    let mut client_builder = Client::builder();
    // api-example: setter
    client_builder.set_max_encrypted_data_keys(Some(3));
    let esdk_client = client_builder.build()?;
    // api-example: end
    assert_eq!(esdk_client.config().max_encrypted_data_keys(), Some(3));

    // api-example: api=client way=max_encrypted_data_keys have="zero" takes=usize fails=validation
    let result = Client::builder()
        // api-example: setter
        .max_encrypted_data_keys(0)
        .build();
    // api-example: end
    assert!(result.is_err_and(|error| error.is_validation()));

    // api-example: api=client way=max_encrypted_data_keys left-out
    let esdk_client = Client::builder().build()?;
    // api-example: end
    assert_eq!(esdk_client.config().max_encrypted_data_keys(), None);
    Ok(())
}
