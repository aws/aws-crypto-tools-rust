// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

//! Encrypts a message under an AWS KMS keyring and a raw AES keyring at once with a multi-keyring.
//!
//! Requires AWS credentials and access to the AWS KMS key below.

use aws_esdk::keyring::{AwsKmsKeyring, MultiKeyring, RawAesKeyring, SharedKeyring};
use aws_esdk::types::{AesWrappingAlg, EncryptionContext};
use aws_esdk::{aws_config, aws_sdk_kms};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // The AWS Crypto Tools CI test key.
    // Replace it with your own KMS key ARN.
    let kms_key_arn = "arn:aws:kms:us-west-2:658956600833:key/b3537ef1-d8dc-4780-9f5a-55776cbb2f7f";

    // The KMS client must be in the key's region.
    let sdk_config = aws_config::defaults(aws_config::BehaviorVersion::latest())
        .region(aws_config::Region::new("us-west-2"))
        .load()
        .await;

    // Encrypting needs kms:GenerateDataKey on this key, and decrypting needs kms:Decrypt.
    let kms_keyring = AwsKmsKeyring::builder()
        .kms_key_id(kms_key_arn)
        .kms_client(aws_sdk_kms::Client::new(&sdk_config))
        .build()
        .await?;

    // For demonstration only.
    // A real application must load its wrapping key from a secure store, never hardcode it.
    let raw_aes_keyring = RawAesKeyring::builder()
        .key_namespace("my-key-namespace")
        .key_name("my-key-name")
        .wrapping_key(vec![0x01u8; 32])
        .wrapping_alg(AesWrappingAlg::AlgAes256GcmIv12Tag16)
        .build()?;

    // The generator makes the data key: here, AWS KMS generates and wraps it.
    // Each child keyring then wraps the same data key,
    // so the message carries one encrypted data key per keyring.
    // A multi-keyring without a generator can decrypt but cannot encrypt.
    let multi_keyring = MultiKeyring::builder()
        .generator(kms_keyring.clone())
        .child_keyrings(raw_aes_keyring.clone())
        .build()?;

    let plaintext = b"Hello World";

    // The encryption context is authenticated, not encrypted, and is bound to the message.
    let encryption_context =
        EncryptionContext::from([("purpose", "example"), ("is not", "secret")]);

    let esdk = aws_esdk::Client::default();

    let encrypted = esdk
        .encrypt()
        .plaintext(plaintext)
        .set_encryption_context(Some(encryption_context.clone()))
        .keyring(multi_keyring.clone())
        .send()
        .await?;

    // On decrypt, the multi-keyring tries the generator, then each child in order,
    // and stops at the first keyring that unwraps a data key.
    // Any one keyring alone can decrypt the message too.
    // The raw AES keyring needs no call to AWS KMS.
    for keyring in [
        SharedKeyring::new(multi_keyring),
        SharedKeyring::new(kms_keyring),
        SharedKeyring::new(raw_aes_keyring),
    ] {
        let decrypted = esdk
            .decrypt()
            .ciphertext(encrypted.ciphertext())
            .set_encryption_context(Some(encryption_context.clone()))
            .keyring(keyring)
            .send()
            .await?;
        assert_eq!(
            decrypted.plaintext(),
            plaintext,
            "Decryption failed: plaintext mismatch"
        );
    }

    println!(
        "Success! The multi-keyring, the AWS KMS keyring, and the raw AES keyring each decrypted the message."
    );
    Ok(())
}
