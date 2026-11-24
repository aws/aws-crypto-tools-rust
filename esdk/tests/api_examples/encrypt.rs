// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

use super::support::*;

#[tokio::test]
async fn encrypt() -> Result<(), Error> {
    // api-example: api=encrypt frame way=encrypt one-of=keyring,cmm
    let esdk_client = Client::default();
    // api-example: call
    let encrypt_output = esdk_client
        .encrypt()
        // api-example: options
        .plaintext(b"my secret data")
        .keyring(make_raw_aes_keyring())
        // api-example: tail
        .send()
        .await?;
    // api-example: end
    assert_eq!(
        decrypt(encrypt_output.ciphertext()).await?,
        b"my secret data"
    );
    Ok(())
}

#[tokio::test]
async fn plaintext() -> Result<(), Error> {
    let esdk_client = Client::default();
    // api-example: api=encrypt way=plaintext have="bytes in memory" takes=&[u8] default
    let plaintext: &[u8] = b"my secret data";
    // api-example: call
    let encrypt_output = esdk_client
        .encrypt()
        // api-example: setter
        .plaintext(plaintext)
        .keyring(make_raw_aes_keyring())
        .send()
        .await?;
    // api-example: end
    assert_eq!(decrypt(encrypt_output.ciphertext()).await?, plaintext);

    // api-example: api=encrypt way=set_plaintext have="bytes in memory" takes=Option<&[u8]> alt
    let plaintext: Option<&[u8]> = Some(b"my secret data");
    // api-example: call
    let encrypt_output = esdk_client
        .encrypt()
        // api-example: setter
        .set_plaintext(plaintext)
        .keyring(make_raw_aes_keyring())
        .send()
        .await?;
    // api-example: end
    assert_eq!(
        decrypt(encrypt_output.ciphertext()).await?,
        b"my secret data"
    );

    // api-example: api=encrypt way=plaintext left-out fails=validation
    let result = esdk_client
        .encrypt()
        .keyring(make_raw_aes_keyring())
        .send()
        .await;
    // api-example: end
    assert!(result.is_err_and(|error| error.is_validation()));
    Ok(())
}

#[tokio::test]
async fn encryption_context() -> Result<(), Error> {
    let esdk_client = Client::default();
    // api-example: api=encrypt way=encryption_context have="a few pairs" takes=&str
    let encrypt_output = esdk_client
        .encrypt()
        .plaintext(b"my secret data")
        // api-example: setter
        .encryption_context("tenant", "my-tenant")
        .keyring(make_raw_aes_keyring())
        .send()
        .await?;
    // api-example: end
    assert_eq!(
        encrypt_output.encryption_context().get("tenant"),
        Some("my-tenant")
    );

    // api-example: api=encrypt way=encryption_context have="a string from your config" takes=String
    let tenant: String = app_config().tenant;
    // api-example: call
    let encrypt_output = esdk_client
        .encrypt()
        .plaintext(b"my secret data")
        // api-example: setter
        .encryption_context("tenant", tenant)
        .keyring(make_raw_aes_keyring())
        .send()
        .await?;
    // api-example: end
    assert_eq!(
        encrypt_output.encryption_context().get("tenant"),
        Some("my-tenant")
    );

    // set_encryption_context is the only way to pass a whole map, so it is its own choice.
    // api-example: api=encrypt way=set_encryption_context have="a map" takes=Option<EncryptionContext>
    let encryption_context = EncryptionContext::from([("tenant", "my-tenant")]);
    // api-example: call
    let encrypt_output = esdk_client
        .encrypt()
        .plaintext(b"my secret data")
        // api-example: setter
        .set_encryption_context(Some(encryption_context))
        .keyring(make_raw_aes_keyring())
        .send()
        .await?;
    // api-example: end
    assert_eq!(
        encrypt_output.encryption_context().get("tenant"),
        Some("my-tenant")
    );

    // api-example: api=encrypt way=encryption_context left-out
    let encrypt_output = esdk_client
        .encrypt()
        .plaintext(b"my secret data")
        .keyring(make_raw_aes_keyring())
        .send()
        .await?;
    // api-example: end
    assert_eq!(encrypt_output.encryption_context().get("tenant"), None);
    Ok(())
}

#[tokio::test]
async fn algorithm_suite_id() -> Result<(), Error> {
    let esdk_client = Client::default();
    // api-example: api=encrypt way=algorithm_suite_id have="one of the listed choices" takes=AlgorithmSuiteId
    let encrypt_output = esdk_client
        .encrypt()
        .plaintext(b"my secret data")
        // api-example: setter
        .algorithm_suite_id(AlgorithmSuiteId::AlgAes256GcmHkdfSha512CommitKey)
        .keyring(make_raw_aes_keyring())
        .send()
        .await?;
    // api-example: end
    assert_eq!(
        encrypt_output.algorithm_suite_id(),
        AlgorithmSuiteId::AlgAes256GcmHkdfSha512CommitKey
    );

    // api-example: api=encrypt way=set_algorithm_suite_id have="one of the listed choices" takes=Option<AlgorithmSuiteId> alt
    let encrypt_output = esdk_client
        .encrypt()
        .plaintext(b"my secret data")
        // api-example: setter
        .set_algorithm_suite_id(Some(AlgorithmSuiteId::AlgAes256GcmHkdfSha512CommitKey))
        .keyring(make_raw_aes_keyring())
        .send()
        .await?;
    // api-example: end
    assert_eq!(
        encrypt_output.algorithm_suite_id(),
        AlgorithmSuiteId::AlgAes256GcmHkdfSha512CommitKey
    );

    // The default commitment policy rejects a suite without key commitment.
    // api-example: api=encrypt way=algorithm_suite_id have="a suite without key commitment" takes=AlgorithmSuiteId fails=validation
    let result = esdk_client
        .encrypt()
        .plaintext(b"my secret data")
        // api-example: setter
        .algorithm_suite_id(AlgorithmSuiteId::AlgAes256GcmIv12Tag16HkdfSha256)
        .keyring(make_raw_aes_keyring())
        .send()
        .await;
    // api-example: end
    assert!(result.is_err_and(|error| error.is_validation()));

    // The default suite for the default commitment policy signs the message.
    // api-example: api=encrypt way=algorithm_suite_id left-out
    let encrypt_output = esdk_client
        .encrypt()
        .plaintext(b"my secret data")
        .keyring(make_raw_aes_keyring())
        .send()
        .await?;
    // api-example: end
    assert_eq!(
        encrypt_output.algorithm_suite_id(),
        AlgorithmSuiteId::AlgAes256GcmHkdfSha512CommitKeyEcdsaP384
    );
    Ok(())
}

#[tokio::test]
async fn frame_length() -> Result<(), Error> {
    let esdk_client = Client::default();
    let plaintext = vec![0x42; 10_000];
    // api-example: api=encrypt way=frame_length have="a number" takes=u32
    let encrypt_output = esdk_client
        .encrypt()
        .plaintext(&plaintext)
        // api-example: setter
        .frame_length(1024)
        .keyring(make_raw_aes_keyring())
        .send()
        .await?;
    // api-example: end
    assert_eq!(decrypt(encrypt_output.ciphertext()).await?, plaintext);

    // api-example: api=encrypt way=set_frame_length have="a number" takes=Option<u32> alt
    let encrypt_output_from_option = esdk_client
        .encrypt()
        .plaintext(&plaintext)
        // api-example: setter
        .set_frame_length(Some(1024))
        .keyring(make_raw_aes_keyring())
        .send()
        .await?;
    // api-example: end
    // Same frame length, so the same number of frames and the same message size.
    assert_eq!(
        encrypt_output_from_option.ciphertext().len(),
        encrypt_output.ciphertext().len()
    );

    // api-example: api=encrypt way=frame_length have="zero" takes=u32 fails=validation
    let result = esdk_client
        .encrypt()
        .plaintext(&plaintext)
        // api-example: setter
        .frame_length(0)
        .keyring(make_raw_aes_keyring())
        .send()
        .await;
    // api-example: end
    assert!(result.is_err_and(|error| error.is_validation()));

    // api-example: api=encrypt way=frame_length left-out
    let encrypt_output_default_frames = esdk_client
        .encrypt()
        .plaintext(&plaintext)
        .keyring(make_raw_aes_keyring())
        .send()
        .await?;
    // api-example: end
    // The default frame length is 4096, so the message has fewer frames than with 1024.
    assert!(encrypt_output_default_frames.ciphertext().len() < encrypt_output.ciphertext().len());
    Ok(())
}

#[tokio::test]
async fn keyring() -> Result<(), Error> {
    let esdk_client = Client::default();
    // api-example: api=encrypt way=keyring have="a keyring" takes=RawAesKeyring default
    let raw_aes_keyring = make_raw_aes_keyring();
    // api-example: call
    let encrypt_output = esdk_client
        .encrypt()
        .plaintext(b"my secret data")
        // api-example: setter
        .keyring(raw_aes_keyring)
        .send()
        .await?;
    // api-example: end
    assert_eq!(
        decrypt(encrypt_output.ciphertext()).await?,
        b"my secret data"
    );

    // api-example: api=encrypt way=set_keyring have="a keyring" takes=Option<SharedKeyring> alt
    let raw_aes_keyring = make_raw_aes_keyring();
    // api-example: call
    let encrypt_output = esdk_client
        .encrypt()
        .plaintext(b"my secret data")
        // api-example: setter
        .set_keyring(Some(raw_aes_keyring.into_shared()))
        .send()
        .await?;
    // api-example: end
    assert_eq!(
        decrypt(encrypt_output.ciphertext()).await?,
        b"my secret data"
    );

    // Encrypt needs a keyring or a CMM, and this call has the CMM.
    // api-example: api=encrypt way=keyring left-out
    let encrypt_output = esdk_client
        .encrypt()
        .plaintext(b"my secret data")
        .cmm(DefaultCmm::new(make_raw_aes_keyring()))
        .send()
        .await?;
    // api-example: end
    assert_eq!(
        decrypt(encrypt_output.ciphertext()).await?,
        b"my secret data"
    );
    Ok(())
}

#[tokio::test]
async fn cmm() -> Result<(), Error> {
    let esdk_client = Client::default();
    // api-example: api=encrypt way=cmm have="a CMM" takes=DefaultCmm
    let default_cmm = DefaultCmm::new(make_raw_aes_keyring());
    // api-example: call
    let encrypt_output = esdk_client
        .encrypt()
        .plaintext(b"my secret data")
        // api-example: setter
        .cmm(default_cmm)
        .send()
        .await?;
    // api-example: end
    assert_eq!(
        decrypt(encrypt_output.ciphertext()).await?,
        b"my secret data"
    );

    // api-example: api=encrypt way=set_cmm have="a CMM" takes=Option<SharedCmm> alt
    let cmm: Option<SharedCmm> = Some(SharedCmm::new(DefaultCmm::new(make_raw_aes_keyring())));
    // api-example: call
    let encrypt_output = esdk_client
        .encrypt()
        .plaintext(b"my secret data")
        // api-example: setter
        .set_cmm(cmm)
        .send()
        .await?;
    // api-example: end
    assert_eq!(
        decrypt(encrypt_output.ciphertext()).await?,
        b"my secret data"
    );

    // api-example: api=encrypt way=cmm left-out
    let encrypt_output = esdk_client
        .encrypt()
        .plaintext(b"my secret data")
        .keyring(make_raw_aes_keyring())
        .send()
        .await?;
    // api-example: end
    assert_eq!(
        decrypt(encrypt_output.ciphertext()).await?,
        b"my secret data"
    );
    Ok(())
}

#[tokio::test]
async fn keyring_or_cmm() -> Result<(), Error> {
    let esdk_client = Client::default();
    // api-example: api=encrypt way=keyring,cmm left-out fails=validation
    let result = esdk_client
        .encrypt()
        .plaintext(b"my secret data")
        .send()
        .await;
    // api-example: end
    assert!(result.is_err_and(|error| error.is_validation()));

    // api-example: api=encrypt way=keyring,cmm together fails=validation
    let result = esdk_client
        .encrypt()
        .plaintext(b"my secret data")
        .keyring(make_raw_aes_keyring())
        .cmm(DefaultCmm::new(make_raw_aes_keyring()))
        .send()
        .await;
    // api-example: end
    assert!(result.is_err_and(|error| error.is_validation()));
    Ok(())
}
