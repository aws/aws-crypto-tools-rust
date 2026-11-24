// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

use super::{app_config, encrypted_message, raw_aes_keyring};
use aws_esdk::cmm::{DefaultCmm, SharedCmm};
use aws_esdk::mpl::shared::IntoShared;
use aws_esdk::types::EncryptionContext;
use aws_esdk::{Client, Error};

#[tokio::test]
async fn decrypt() -> Result<(), Error> {
    let esdk_client = Client::default();
    let raw_aes_keyring = raw_aes_keyring();
    let ciphertext = encrypted_message().await;
    // api-example: api=decrypt way=decrypt kind=pass have="an encrypted message and a keyring"
    // snippet-start
    let decrypt_output = esdk_client
        .decrypt()
        .ciphertext(&ciphertext)
        .keyring(raw_aes_keyring)
        .send()
        .await?;
    // snippet-end
    assert_eq!(decrypt_output.plaintext(), b"my secret data");
    Ok(())
}

#[tokio::test]
async fn ciphertext() -> Result<(), Error> {
    let esdk_client = Client::default();
    let raw_aes_keyring = raw_aes_keyring();
    let message = encrypted_message().await;
    // api-example: api=decrypt way=ciphertext takes=&[u8] kind=pass have="bytes in memory"
    // snippet-start
    let ciphertext: &[u8] = &message;
    let decrypt_output = esdk_client
        .decrypt()
        .ciphertext(ciphertext)
        .keyring(raw_aes_keyring.clone())
        .send()
        .await?;
    // snippet-end
    assert_eq!(decrypt_output.plaintext(), b"my secret data");

    // api-example: api=decrypt way=ciphertext takes=&Ciphertext kind=pass have="the output of encrypt"
    // snippet-start
    let encrypt_output = esdk_client
        .encrypt()
        .plaintext(b"my secret data")
        .keyring(raw_aes_keyring.clone())
        .send()
        .await?;
    let decrypt_output = esdk_client
        .decrypt()
        .ciphertext(encrypt_output.ciphertext())
        .keyring(raw_aes_keyring.clone())
        .send()
        .await?;
    // snippet-end
    assert_eq!(decrypt_output.plaintext(), b"my secret data");

    // api-example: api=decrypt way=set_ciphertext takes=Option<&[u8]> kind=pass have="a value that may be missing"
    // snippet-start
    let ciphertext: Option<&[u8]> = Some(&message);
    let decrypt_output = esdk_client
        .decrypt()
        .set_ciphertext(ciphertext)
        .keyring(raw_aes_keyring.clone())
        .send()
        .await?;
    // snippet-end
    assert_eq!(decrypt_output.plaintext(), b"my secret data");

    // api-example: api=decrypt way=ciphertext kind=missing
    // snippet-start
    let result = esdk_client.decrypt().keyring(raw_aes_keyring).send().await;
    // snippet-end
    assert!(result.is_err_and(|error| error.is_validation()));
    Ok(())
}

#[tokio::test]
async fn encryption_context() -> Result<(), Error> {
    let esdk_client = Client::default();
    let raw_aes_keyring = raw_aes_keyring();
    let ciphertext = encrypted_message().await;
    let app_config = app_config();
    // api-example: api=decrypt way=encryption_context takes=&str kind=pass have="a few pairs"
    // snippet-start
    let decrypt_output = esdk_client
        .decrypt()
        .ciphertext(&ciphertext)
        .encryption_context("tenant", "my-tenant")
        .keyring(raw_aes_keyring.clone())
        .send()
        .await?;
    // snippet-end
    assert_eq!(decrypt_output.plaintext(), b"my secret data");

    // api-example: api=decrypt way=encryption_context takes=String kind=pass have="a string from your config"
    // snippet-start
    let tenant: String = app_config.tenant;
    let decrypt_output = esdk_client
        .decrypt()
        .ciphertext(&ciphertext)
        .encryption_context("tenant", tenant)
        .keyring(raw_aes_keyring.clone())
        .send()
        .await?;
    // snippet-end
    assert_eq!(decrypt_output.plaintext(), b"my secret data");

    // api-example: api=decrypt way=set_encryption_context takes=Option<EncryptionContext> kind=pass have="a map"
    // snippet-start
    let encryption_context = EncryptionContext::from([("tenant", "my-tenant")]);
    let decrypt_output = esdk_client
        .decrypt()
        .ciphertext(&ciphertext)
        .set_encryption_context(Some(encryption_context))
        .keyring(raw_aes_keyring.clone())
        .send()
        .await?;
    // snippet-end
    assert_eq!(decrypt_output.plaintext(), b"my secret data");

    // api-example: api=decrypt way=encryption_context kind=omitted have="nothing"
    // snippet-start
    let decrypt_output = esdk_client
        .decrypt()
        .ciphertext(&ciphertext)
        .keyring(raw_aes_keyring.clone())
        .send()
        .await?;
    // snippet-end
    assert_eq!(
        decrypt_output.encryption_context().get("tenant"),
        Some("my-tenant")
    );

    // Decrypt fails when the message was encrypted with a different value.
    // api-example: api=decrypt way=encryption_context takes=&str kind=reject
    // snippet-start
    let result = esdk_client
        .decrypt()
        .ciphertext(&ciphertext)
        .encryption_context("tenant", "another-tenant")
        .keyring(raw_aes_keyring)
        .send()
        .await;
    // snippet-end
    assert!(result.is_err_and(|error| error.is_encryption_context_mismatch()));
    Ok(())
}

#[tokio::test]
async fn keyring() -> Result<(), Error> {
    let esdk_client = Client::default();
    let raw_aes_keyring = raw_aes_keyring();
    let ciphertext = encrypted_message().await;
    // api-example: api=decrypt way=keyring takes=RawAesKeyring kind=pass have="a keyring"
    // snippet-start
    let decrypt_output = esdk_client
        .decrypt()
        .ciphertext(&ciphertext)
        .keyring(raw_aes_keyring.clone())
        .send()
        .await?;
    // snippet-end
    assert_eq!(decrypt_output.plaintext(), b"my secret data");

    // api-example: api=decrypt way=set_keyring takes=Option<RawAesKeyring> kind=pass have="a keyring"
    // snippet-start
    let decrypt_output = esdk_client
        .decrypt()
        .ciphertext(&ciphertext)
        .set_keyring(Some(raw_aes_keyring.clone().into_shared()))
        .send()
        .await?;
    // snippet-end
    assert_eq!(decrypt_output.plaintext(), b"my secret data");

    // api-example: api=decrypt way=keyring kind=omitted have="nothing"
    // snippet-start
    let default_cmm = DefaultCmm::new(raw_aes_keyring.clone());
    let decrypt_output = esdk_client
        .decrypt()
        .ciphertext(&ciphertext)
        .cmm(default_cmm)
        .send()
        .await?;
    // snippet-end
    assert_eq!(decrypt_output.plaintext(), b"my secret data");
    Ok(())
}

#[tokio::test]
async fn cmm() -> Result<(), Error> {
    let esdk_client = Client::default();
    let raw_aes_keyring = raw_aes_keyring();
    let ciphertext = encrypted_message().await;
    // api-example: api=decrypt way=cmm takes=DefaultCmm kind=pass have="a CMM"
    // snippet-start
    let default_cmm = DefaultCmm::new(raw_aes_keyring.clone());
    let decrypt_output = esdk_client
        .decrypt()
        .ciphertext(&ciphertext)
        .cmm(default_cmm)
        .send()
        .await?;
    // snippet-end
    assert_eq!(decrypt_output.plaintext(), b"my secret data");

    // api-example: api=decrypt way=set_cmm takes=Option<SharedCmm> kind=pass have="a value that may be missing"
    // snippet-start
    let cmm: Option<SharedCmm> = Some(SharedCmm::new(DefaultCmm::new(raw_aes_keyring.clone())));
    let decrypt_output = esdk_client
        .decrypt()
        .ciphertext(&ciphertext)
        .set_cmm(cmm)
        .send()
        .await?;
    // snippet-end
    assert_eq!(decrypt_output.plaintext(), b"my secret data");

    // api-example: api=decrypt way=cmm kind=omitted have="nothing"
    // snippet-start
    let decrypt_output = esdk_client
        .decrypt()
        .ciphertext(&ciphertext)
        .keyring(raw_aes_keyring.clone())
        .send()
        .await?;
    // snippet-end
    assert_eq!(decrypt_output.plaintext(), b"my secret data");

    // Decrypt takes a keyring or a CMM, not both.
    // api-example: api=decrypt way=cmm takes=DefaultCmm kind=reject
    // snippet-start
    let default_cmm = DefaultCmm::new(raw_aes_keyring.clone());
    let result = esdk_client
        .decrypt()
        .ciphertext(&ciphertext)
        .keyring(raw_aes_keyring.clone())
        .cmm(default_cmm)
        .send()
        .await;
    // snippet-end
    assert!(result.is_err_and(|error| error.is_validation()));
    Ok(())
}
