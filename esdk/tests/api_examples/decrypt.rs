// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

use super::support::*;

#[tokio::test]
async fn decrypt() -> Result<(), Error> {
    let ciphertext = make_encrypted_message().await;
    // api-example: api=decrypt frame way=decrypt one-of=keyring,cmm
    let esdk_client = Client::default();
    // api-example: call
    let decrypt_output = esdk_client
        .decrypt()
        // api-example: options
        .ciphertext(&ciphertext)
        .keyring(make_raw_aes_keyring())
        // api-example: tail
        .send()
        .await?;
    // api-example: end
    assert_eq!(decrypt_output.plaintext(), b"my secret data");
    Ok(())
}

#[tokio::test]
async fn ciphertext() -> Result<(), Error> {
    let esdk_client = Client::default();
    // api-example: api=decrypt way=ciphertext have="bytes in memory" takes=&[u8] default
    let ciphertext: Vec<u8> = make_encrypted_message().await;
    // api-example: call
    let decrypt_output = esdk_client
        .decrypt()
        // api-example: setter
        .ciphertext(&ciphertext)
        .keyring(make_raw_aes_keyring())
        .send()
        .await?;
    // api-example: end
    assert_eq!(decrypt_output.plaintext(), b"my secret data");

    // api-example: api=decrypt way=ciphertext have="the output of encrypt" takes=&Ciphertext
    let encrypt_output = esdk_client
        .encrypt()
        .plaintext(b"my secret data")
        .encryption_context("tenant", "my-tenant")
        .keyring(make_raw_aes_keyring())
        .send()
        .await?;
    // api-example: call
    let decrypt_output = esdk_client
        .decrypt()
        // api-example: setter
        .ciphertext(encrypt_output.ciphertext())
        .keyring(make_raw_aes_keyring())
        .send()
        .await?;
    // api-example: end
    assert_eq!(decrypt_output.plaintext(), b"my secret data");

    // api-example: api=decrypt way=set_ciphertext have="bytes in memory" takes=Option<&[u8]> alt
    let ciphertext: Vec<u8> = make_encrypted_message().await;
    // api-example: call
    let decrypt_output = esdk_client
        .decrypt()
        // api-example: setter
        .set_ciphertext(Some(&ciphertext))
        .keyring(make_raw_aes_keyring())
        .send()
        .await?;
    // api-example: end
    assert_eq!(decrypt_output.plaintext(), b"my secret data");

    // api-example: api=decrypt way=ciphertext left-out fails=validation
    let result = esdk_client
        .decrypt()
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
    let ciphertext = make_encrypted_message().await;
    // api-example: api=decrypt way=encryption_context have="a few pairs" takes=&str
    let decrypt_output = esdk_client
        .decrypt()
        .ciphertext(&ciphertext)
        // api-example: setter
        .encryption_context("tenant", "my-tenant")
        .keyring(make_raw_aes_keyring())
        .send()
        .await?;
    // api-example: end
    assert_eq!(decrypt_output.plaintext(), b"my secret data");

    // api-example: api=decrypt way=encryption_context have="a string from your config" takes=String
    let tenant: String = app_config().tenant;
    // api-example: call
    let decrypt_output = esdk_client
        .decrypt()
        .ciphertext(&ciphertext)
        // api-example: setter
        .encryption_context("tenant", tenant)
        .keyring(make_raw_aes_keyring())
        .send()
        .await?;
    // api-example: end
    assert_eq!(decrypt_output.plaintext(), b"my secret data");

    // set_encryption_context is the only way to pass a whole map, so it is its own choice.
    // api-example: api=decrypt way=set_encryption_context have="a map" takes=Option<EncryptionContext>
    let encryption_context = EncryptionContext::from([("tenant", "my-tenant")]);
    // api-example: call
    let decrypt_output = esdk_client
        .decrypt()
        .ciphertext(&ciphertext)
        // api-example: setter
        .set_encryption_context(Some(encryption_context))
        .keyring(make_raw_aes_keyring())
        .send()
        .await?;
    // api-example: end
    assert_eq!(decrypt_output.plaintext(), b"my secret data");

    // The message was encrypted with tenant = my-tenant.
    // api-example: api=decrypt way=encryption_context have="a value that does not match the message" takes=&str fails=encryption_context_mismatch
    let result = esdk_client
        .decrypt()
        .ciphertext(&ciphertext)
        // api-example: setter
        .encryption_context("tenant", "another-tenant")
        .keyring(make_raw_aes_keyring())
        .send()
        .await;
    // api-example: end
    assert!(result.is_err_and(|error| error.is_encryption_context_mismatch()));

    // api-example: api=decrypt way=encryption_context left-out
    let decrypt_output = esdk_client
        .decrypt()
        .ciphertext(&ciphertext)
        .keyring(make_raw_aes_keyring())
        .send()
        .await?;
    // api-example: end
    assert_eq!(
        decrypt_output.encryption_context().get("tenant"),
        Some("my-tenant")
    );
    Ok(())
}

#[tokio::test]
async fn keyring() -> Result<(), Error> {
    let esdk_client = Client::default();
    let ciphertext = make_encrypted_message().await;
    // api-example: api=decrypt way=keyring have="a keyring" takes=RawAesKeyring default
    let raw_aes_keyring = make_raw_aes_keyring();
    // api-example: call
    let decrypt_output = esdk_client
        .decrypt()
        .ciphertext(&ciphertext)
        // api-example: setter
        .keyring(raw_aes_keyring)
        .send()
        .await?;
    // api-example: end
    assert_eq!(decrypt_output.plaintext(), b"my secret data");

    // api-example: api=decrypt way=set_keyring have="a keyring" takes=Option<SharedKeyring> alt
    let raw_aes_keyring = make_raw_aes_keyring();
    // api-example: call
    let decrypt_output = esdk_client
        .decrypt()
        .ciphertext(&ciphertext)
        // api-example: setter
        .set_keyring(Some(raw_aes_keyring.into_shared()))
        .send()
        .await?;
    // api-example: end
    assert_eq!(decrypt_output.plaintext(), b"my secret data");

    // Decrypt needs a keyring or a CMM, and this call has the CMM.
    // api-example: api=decrypt way=keyring left-out
    let decrypt_output = esdk_client
        .decrypt()
        .ciphertext(&ciphertext)
        .cmm(DefaultCmm::new(make_raw_aes_keyring()))
        .send()
        .await?;
    // api-example: end
    assert_eq!(decrypt_output.plaintext(), b"my secret data");
    Ok(())
}

#[tokio::test]
async fn cmm() -> Result<(), Error> {
    let esdk_client = Client::default();
    let ciphertext = make_encrypted_message().await;
    // api-example: api=decrypt way=cmm have="a CMM" takes=DefaultCmm
    let default_cmm = DefaultCmm::new(make_raw_aes_keyring());
    // api-example: call
    let decrypt_output = esdk_client
        .decrypt()
        .ciphertext(&ciphertext)
        // api-example: setter
        .cmm(default_cmm)
        .send()
        .await?;
    // api-example: end
    assert_eq!(decrypt_output.plaintext(), b"my secret data");

    // api-example: api=decrypt way=set_cmm have="a CMM" takes=Option<SharedCmm> alt
    let cmm: Option<SharedCmm> = Some(SharedCmm::new(DefaultCmm::new(make_raw_aes_keyring())));
    // api-example: call
    let decrypt_output = esdk_client
        .decrypt()
        .ciphertext(&ciphertext)
        // api-example: setter
        .set_cmm(cmm)
        .send()
        .await?;
    // api-example: end
    assert_eq!(decrypt_output.plaintext(), b"my secret data");

    // api-example: api=decrypt way=cmm left-out
    let decrypt_output = esdk_client
        .decrypt()
        .ciphertext(&ciphertext)
        .keyring(make_raw_aes_keyring())
        .send()
        .await?;
    // api-example: end
    assert_eq!(decrypt_output.plaintext(), b"my secret data");
    Ok(())
}

#[tokio::test]
async fn keyring_or_cmm() -> Result<(), Error> {
    let esdk_client = Client::default();
    let ciphertext = make_encrypted_message().await;
    // api-example: api=decrypt way=keyring,cmm left-out fails=validation
    let result = esdk_client.decrypt().ciphertext(&ciphertext).send().await;
    // api-example: end
    assert!(result.is_err_and(|error| error.is_validation()));

    // api-example: api=decrypt way=keyring,cmm together fails=validation
    let result = esdk_client
        .decrypt()
        .ciphertext(&ciphertext)
        .keyring(make_raw_aes_keyring())
        .cmm(DefaultCmm::new(make_raw_aes_keyring()))
        .send()
        .await;
    // api-example: end
    assert!(result.is_err_and(|error| error.is_validation()));
    Ok(())
}
