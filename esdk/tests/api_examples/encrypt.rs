// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

use super::{app_config, decrypt, raw_aes_keyring};
use aws_esdk::cmm::{DefaultCmm, SharedCmm};
use aws_esdk::mpl::shared::IntoShared;
use aws_esdk::types::{AlgorithmSuiteId, EncryptionContext};
use aws_esdk::{Client, Error};

#[tokio::test]
async fn encrypt() -> Result<(), Error> {
    let esdk_client = Client::default();
    let raw_aes_keyring = raw_aes_keyring();
    // api-example: api=encrypt way=encrypt takes=none kind=pass
    // snippet-start
    let plaintext = b"my secret data";
    let encrypt_output = esdk_client
        .encrypt()
        .plaintext(plaintext)
        .keyring(raw_aes_keyring)
        .send()
        .await?;
    // snippet-end
    assert_eq!(decrypt(encrypt_output.ciphertext()).await?, plaintext);
    Ok(())
}

#[tokio::test]
async fn plaintext() -> Result<(), Error> {
    let esdk_client = Client::default();
    let raw_aes_keyring = raw_aes_keyring();
    // api-example: api=encrypt way=plaintext takes=&[u8] kind=pass
    // snippet-start
    let plaintext: &[u8] = b"my secret data";
    let encrypt_output = esdk_client
        .encrypt()
        .plaintext(plaintext)
        .keyring(raw_aes_keyring.clone())
        .send()
        .await?;
    // snippet-end
    assert_eq!(decrypt(encrypt_output.ciphertext()).await?, plaintext);

    // api-example: api=encrypt way=set_plaintext takes=Option<&[u8]> kind=pass
    // snippet-start
    let plaintext: Option<&[u8]> = Some(b"my secret data");
    let encrypt_output = esdk_client
        .encrypt()
        .set_plaintext(plaintext)
        .keyring(raw_aes_keyring.clone())
        .send()
        .await?;
    // snippet-end
    assert_eq!(
        decrypt(encrypt_output.ciphertext()).await?,
        b"my secret data"
    );

    // api-example: api=encrypt way=plaintext kind=missing
    // snippet-start
    let result = esdk_client.encrypt().keyring(raw_aes_keyring).send().await;
    // snippet-end
    assert!(result.is_err_and(|error| error.is_validation()));
    Ok(())
}

#[tokio::test]
async fn encryption_context() -> Result<(), Error> {
    let esdk_client = Client::default();
    let raw_aes_keyring = raw_aes_keyring();
    let app_config = app_config();
    // api-example: api=encrypt way=encryption_context takes=&str kind=pass
    // snippet-start
    let encrypt_output = esdk_client
        .encrypt()
        .plaintext(b"my secret data")
        .encryption_context("tenant", "my-tenant")
        .keyring(raw_aes_keyring.clone())
        .send()
        .await?;
    // snippet-end
    assert_eq!(
        encrypt_output.encryption_context().get("tenant"),
        Some("my-tenant")
    );

    // api-example: api=encrypt way=encryption_context takes=String kind=pass
    // snippet-start
    let tenant: String = app_config.tenant;
    let encrypt_output_from_string = esdk_client
        .encrypt()
        .plaintext(b"my secret data")
        .encryption_context("tenant", tenant)
        .keyring(raw_aes_keyring.clone())
        .send()
        .await?;
    // snippet-end
    assert_eq!(
        encrypt_output_from_string
            .encryption_context()
            .get("tenant"),
        encrypt_output.encryption_context().get("tenant")
    );

    // api-example: api=encrypt way=set_encryption_context takes=Option<EncryptionContext> kind=pass
    // snippet-start
    let encryption_context = EncryptionContext::from([("tenant", "my-tenant")]);
    let encrypt_output_from_option = esdk_client
        .encrypt()
        .plaintext(b"my secret data")
        .set_encryption_context(Some(encryption_context))
        .keyring(raw_aes_keyring.clone())
        .send()
        .await?;
    // snippet-end
    assert_eq!(
        encrypt_output_from_option
            .encryption_context()
            .get("tenant"),
        encrypt_output.encryption_context().get("tenant")
    );

    // api-example: api=encrypt way=encryption_context kind=omitted
    // snippet-start
    let encrypt_output = esdk_client
        .encrypt()
        .plaintext(b"my secret data")
        .keyring(raw_aes_keyring)
        .send()
        .await?;
    // snippet-end
    assert_eq!(encrypt_output.encryption_context().get("tenant"), None);
    Ok(())
}

#[tokio::test]
async fn algorithm_suite_id() -> Result<(), Error> {
    let esdk_client = Client::default();
    let raw_aes_keyring = raw_aes_keyring();
    // api-example: api=encrypt way=algorithm_suite_id takes=AlgorithmSuiteId kind=pass
    // snippet-start
    let encrypt_output = esdk_client
        .encrypt()
        .plaintext(b"my secret data")
        .algorithm_suite_id(AlgorithmSuiteId::AlgAes256GcmHkdfSha512CommitKey)
        .keyring(raw_aes_keyring.clone())
        .send()
        .await?;
    // snippet-end
    assert_eq!(
        encrypt_output.algorithm_suite_id(),
        AlgorithmSuiteId::AlgAes256GcmHkdfSha512CommitKey
    );

    // api-example: api=encrypt way=set_algorithm_suite_id takes=Option<AlgorithmSuiteId> kind=pass
    // snippet-start
    let algorithm_suite_id: Option<AlgorithmSuiteId> =
        Some(AlgorithmSuiteId::AlgAes256GcmHkdfSha512CommitKey);
    let encrypt_output_from_option = esdk_client
        .encrypt()
        .plaintext(b"my secret data")
        .set_algorithm_suite_id(algorithm_suite_id)
        .keyring(raw_aes_keyring.clone())
        .send()
        .await?;
    // snippet-end
    assert_eq!(
        encrypt_output_from_option.algorithm_suite_id(),
        encrypt_output.algorithm_suite_id()
    );

    // The default suite for the default commitment policy signs the message.
    // api-example: api=encrypt way=algorithm_suite_id kind=omitted
    // snippet-start
    let encrypt_output = esdk_client
        .encrypt()
        .plaintext(b"my secret data")
        .keyring(raw_aes_keyring.clone())
        .send()
        .await?;
    // snippet-end
    assert_eq!(
        encrypt_output.algorithm_suite_id(),
        AlgorithmSuiteId::AlgAes256GcmHkdfSha512CommitKeyEcdsaP384
    );

    // The default commitment policy rejects a suite without key commitment.
    // api-example: api=encrypt way=algorithm_suite_id takes=AlgorithmSuiteId kind=reject
    // snippet-start
    let result = esdk_client
        .encrypt()
        .plaintext(b"my secret data")
        .algorithm_suite_id(AlgorithmSuiteId::AlgAes256GcmIv12Tag16HkdfSha256)
        .keyring(raw_aes_keyring)
        .send()
        .await;
    // snippet-end
    assert!(result.is_err_and(|error| error.is_validation()));
    Ok(())
}

#[tokio::test]
async fn frame_length() -> Result<(), Error> {
    let esdk_client = Client::default();
    let raw_aes_keyring = raw_aes_keyring();
    let plaintext = vec![0x42; 10_000];
    // api-example: api=encrypt way=frame_length takes=u32 kind=pass
    // snippet-start
    let encrypt_output = esdk_client
        .encrypt()
        .plaintext(&plaintext)
        .frame_length(1024)
        .keyring(raw_aes_keyring.clone())
        .send()
        .await?;
    // snippet-end
    assert_eq!(decrypt(encrypt_output.ciphertext()).await?, plaintext);

    // api-example: api=encrypt way=set_frame_length takes=Option<u32> kind=pass
    // snippet-start
    let frame_length: Option<u32> = Some(1024);
    let encrypt_output_from_option = esdk_client
        .encrypt()
        .plaintext(&plaintext)
        .set_frame_length(frame_length)
        .keyring(raw_aes_keyring.clone())
        .send()
        .await?;
    // snippet-end
    // Same frame length, so the same number of frames and the same message size.
    assert_eq!(
        encrypt_output_from_option.ciphertext().len(),
        encrypt_output.ciphertext().len()
    );

    // api-example: api=encrypt way=frame_length kind=omitted
    // snippet-start
    let encrypt_output_default_frames = esdk_client
        .encrypt()
        .plaintext(&plaintext)
        .keyring(raw_aes_keyring.clone())
        .send()
        .await?;
    // snippet-end
    // The default frame length is 4096, so the message has fewer frames than with 1024.
    assert!(encrypt_output_default_frames.ciphertext().len() < encrypt_output.ciphertext().len());

    // api-example: api=encrypt way=frame_length takes=u32 kind=reject
    // snippet-start
    let result = esdk_client
        .encrypt()
        .plaintext(&plaintext)
        .frame_length(0)
        .keyring(raw_aes_keyring)
        .send()
        .await;
    // snippet-end
    assert!(result.is_err_and(|error| error.is_validation()));
    Ok(())
}

#[tokio::test]
async fn keyring() -> Result<(), Error> {
    let esdk_client = Client::default();
    let raw_aes_keyring = raw_aes_keyring();
    // api-example: api=encrypt way=keyring takes=RawAesKeyring kind=pass
    // snippet-start
    let encrypt_output = esdk_client
        .encrypt()
        .plaintext(b"my secret data")
        .keyring(raw_aes_keyring.clone())
        .send()
        .await?;
    // snippet-end
    assert_eq!(
        decrypt(encrypt_output.ciphertext()).await?,
        b"my secret data"
    );

    // api-example: api=encrypt way=set_keyring takes=Option<RawAesKeyring> kind=pass
    // snippet-start
    let encrypt_output = esdk_client
        .encrypt()
        .plaintext(b"my secret data")
        .set_keyring(Some(raw_aes_keyring.clone().into_shared()))
        .send()
        .await?;
    // snippet-end
    assert_eq!(
        decrypt(encrypt_output.ciphertext()).await?,
        b"my secret data"
    );

    // api-example: api=encrypt way=keyring kind=omitted
    // snippet-start
    let default_cmm = DefaultCmm::new(raw_aes_keyring.clone());
    let encrypt_output = esdk_client
        .encrypt()
        .plaintext(b"my secret data")
        .cmm(default_cmm)
        .send()
        .await?;
    // snippet-end
    assert_eq!(
        decrypt(encrypt_output.ciphertext()).await?,
        b"my secret data"
    );

    // api-example: api=encrypt way=keyring takes=RawAesKeyring kind=reject
    // snippet-start
    let default_cmm = DefaultCmm::new(raw_aes_keyring.clone());
    let result = esdk_client
        .encrypt()
        .plaintext(b"my secret data")
        .keyring(raw_aes_keyring.clone())
        .cmm(default_cmm)
        .send()
        .await;
    // snippet-end
    assert!(result.is_err_and(|error| error.is_validation()));
    Ok(())
}

#[tokio::test]
async fn cmm() -> Result<(), Error> {
    let esdk_client = Client::default();
    let raw_aes_keyring = raw_aes_keyring();
    // api-example: api=encrypt way=cmm takes=DefaultCmm kind=pass
    // snippet-start
    let default_cmm = DefaultCmm::new(raw_aes_keyring.clone());
    let encrypt_output = esdk_client
        .encrypt()
        .plaintext(b"my secret data")
        .cmm(default_cmm)
        .send()
        .await?;
    // snippet-end
    assert_eq!(
        decrypt(encrypt_output.ciphertext()).await?,
        b"my secret data"
    );

    // api-example: api=encrypt way=set_cmm takes=Option<SharedCmm> kind=pass
    // snippet-start
    let cmm: Option<SharedCmm> = Some(SharedCmm::new(DefaultCmm::new(raw_aes_keyring.clone())));
    let encrypt_output = esdk_client
        .encrypt()
        .plaintext(b"my secret data")
        .set_cmm(cmm)
        .send()
        .await?;
    // snippet-end
    assert_eq!(
        decrypt(encrypt_output.ciphertext()).await?,
        b"my secret data"
    );

    // api-example: api=encrypt way=cmm kind=omitted
    // snippet-start
    let encrypt_output = esdk_client
        .encrypt()
        .plaintext(b"my secret data")
        .keyring(raw_aes_keyring.clone())
        .send()
        .await?;
    // snippet-end
    assert_eq!(
        decrypt(encrypt_output.ciphertext()).await?,
        b"my secret data"
    );
    Ok(())
}
