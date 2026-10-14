// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

//! What a customer sees when an operation fails:
//! the variant, its details, and its `{}` and `{:#}` text.

mod fake_aws;

use aws_crypto_mpl::async_trait;
use aws_crypto_mpl::keyring::OnEncryptInput;
use aws_crypto_mpl::keyring::{OnDecryptInput, OnDecryptOutput, OnEncryptOutput};
use aws_crypto_mpl::keyring::{RawAesKeyring, SharedKeyring};
use aws_crypto_mpl::structures::EncryptionContext;
use aws_esdk::Client;
use aws_esdk::error::{
    BranchKey, Cache, DynamoDbTable, Error, KeyringResource, KmsKey, Resource, RetryKind, Service,
};
use aws_mpl_primitives::AesGcm;
use fake_aws::{BRANCH_KEY_ID, FakeAws, KEY_ARN, Reply, TABLE, VERSION};

fn context() -> EncryptionContext {
    let mut ec = EncryptionContext::new();
    ec.insert("tenant", "example");
    ec
}

async fn encrypt_with(keyring: impl aws_crypto_mpl::Keyring + 'static) -> Vec<u8> {
    Client::default()
        .encrypt()
        .plaintext(b"hello")
        .set_encryption_context(Some(context()))
        .keyring(keyring)
        .send()
        .await
        .unwrap()
        .into_ciphertext()
}

async fn decrypt_with(
    ciphertext: &[u8],
    keyring: impl aws_crypto_mpl::Keyring + 'static,
) -> Result<Vec<u8>, Error> {
    Client::default()
        .decrypt()
        .ciphertext(ciphertext)
        .keyring(keyring)
        .send()
        .await
        .map(|out| out.into_plaintext())
}

/// The error from decrypting, against `fake`, a message encrypted under the fake's branch key.
async fn hierarchical_decrypt_error(fake: FakeAws) -> Error {
    let ciphertext = encrypt_with(FakeAws::ok().keyring().await).await;
    decrypt_with(&ciphertext, fake.keyring().await)
        .await
        .expect_err("the fake fails the call")
}

/// `{:#}` up to the AWS SDK's own text, which this crate does not control.
fn alternate_before_sdk_text(e: &Error) -> String {
    let text = format!("{e:#}");
    let end = text
        .find(": service error")
        .map_or(text.len(), |i| i + ": service error".len());
    text[..end].to_owned()
}

#[tokio::test]
async fn kms_access_denied_while_decrypting_a_branch_key() {
    let err = hierarchical_decrypt_error(FakeAws::new(|op, _| {
        (op == "TrentService.Decrypt")
            .then(|| Reply::error(400, "AccessDeniedException", "6f1c2e9a"))
    }))
    .await;
    let Error::AccessDenied(e) = &err else {
        panic!("expected AccessDenied, got {err:?}");
    };
    assert_eq!(e.service(), Some(&Service::Kms));
    assert_eq!(e.resource(), Some(&Resource::KmsKey(KmsKey::new(KEY_ARN))));
    assert_eq!(e.code(), Some("AccessDeniedException"));
    assert_eq!(e.request_id(), Some("6f1c2e9a"));
    assert!(!e.is_credentials());
    assert!(!err.is_retryable());
    assert_eq!(
        err.to_string(),
        "AccessDenied: decrypt could not get decryption materials \
         (AWS KMS, KMS key arn:aws:kms:us-west-2:111122223333:key/1234abcd, AccessDeniedException, request 6f1c2e9a)"
    );
    assert_eq!(
        alternate_before_sdk_text(&err),
        "AccessDenied: decrypt could not get decryption materials \
         (AWS KMS, KMS key arn:aws:kms:us-west-2:111122223333:key/1234abcd, AccessDeniedException, request 6f1c2e9a): \
         AWS KMS Decrypt of branch key my-branch-key failed: service error"
    );
}

#[tokio::test]
async fn a_wrong_raw_aes_keyring_names_the_keyring_used() {
    let raw = |ns: &str, name: &str, byte: u8| {
        RawAesKeyring::builder()
            .key_namespace(ns)
            .key_name(name)
            .wrapping_key(vec![byte; 32])
            .wrapping_alg(AesGcm::Aes256Gcm)
            .build()
            .unwrap()
    };
    let ciphertext = encrypt_with(raw("other-namespace", "other-key", 1)).await;
    let err = decrypt_with(&ciphertext, raw("my-namespace", "my-key", 2))
        .await
        .unwrap_err();
    let Error::NoMatchingDataKey(e) = &err else {
        panic!("expected NoMatchingDataKey, got {err:?}");
    };
    assert_eq!(
        e.resource(),
        Some(&Resource::Keyring(KeyringResource::new(
            "my-namespace/my-key"
        )))
    );
    assert_eq!(e.encrypted_data_keys().len(), 1);
    assert_eq!(
        e.encrypted_data_keys()[0].key_provider_id(),
        "other-namespace"
    );
    assert!(
        e.encrypted_data_keys()[0]
            .key_provider_info()
            .starts_with(b"other-key")
    );
    assert!(err.collected().is_empty());
    assert_eq!(
        err.to_string(),
        "NoMatchingDataKey: decrypt could not get decryption materials \
         (keyring my-namespace/my-key; message has: other-namespace)"
    );
    assert_eq!(
        format!("{err:#}"),
        "NoMatchingDataKey: decrypt could not get decryption materials \
         (keyring my-namespace/my-key; message has: other-namespace): \
         encrypted data key 0 did not match the keyring, expected key provider id my-namespace"
    );
}

#[tokio::test]
async fn expired_credentials_on_dynamodb_get_item() {
    let err = hierarchical_decrypt_error(FakeAws::new(|op, _| {
        (op == "DynamoDB_20120810.GetItem")
            .then(|| Reply::error(400, "ExpiredTokenException", "ddb-request"))
    }))
    .await;
    let Error::AccessDenied(e) = &err else {
        panic!("expected AccessDenied, got {err:?}");
    };
    assert!(e.is_credentials());
    assert_eq!(e.service(), Some(&Service::DynamoDb));
    assert_eq!(
        e.resource(),
        Some(&Resource::DynamoDbTable(DynamoDbTable::new(TABLE)))
    );
    assert_eq!(e.code(), Some("ExpiredTokenException"));
    assert_eq!(e.request_id(), Some("ddb-request"));
}

#[tokio::test]
async fn a_missing_branch_key_version_record_names_the_branch_key_version() {
    let err = hierarchical_decrypt_error(FakeAws::new(|op, _| {
        (op == "DynamoDB_20120810.GetItem").then(|| Reply::ok("{}"))
    }))
    .await;
    let Error::ResourceNotFound(e) = &err else {
        panic!("expected ResourceNotFound, got {err:?}");
    };
    assert_eq!(e.service(), Some(&Service::DynamoDb));
    assert_eq!(
        e.resource(),
        Some(&Resource::BranchKey(
            BranchKey::new(BRANCH_KEY_ID).with_version(VERSION)
        ))
    );
}

#[tokio::test]
async fn a_corrupt_branch_key_record_is_invalid_materials_about_the_branch_key() {
    // A 16-byte branch key, where the record format requires 32.
    let err = hierarchical_decrypt_error(FakeAws::new(|op, _| {
        (op == "TrentService.Decrypt").then(|| {
            Reply::ok(format!(
                r#"{{"KeyId":"{KEY_ARN}","Plaintext":"QkJCQkJCQkJCQkJCQkJCQg==","EncryptionAlgorithm":"SYMMETRIC_DEFAULT"}}"#
            ))
        })
    }))
    .await;
    let Error::InvalidMaterials(e) = &err else {
        panic!("expected InvalidMaterials, got {err:?}");
    };
    assert_eq!(
        e.resource(),
        Some(&Resource::BranchKey(
            BranchKey::new(BRANCH_KEY_ID).with_version(VERSION)
        ))
    );
    assert_eq!(e.service(), Some(&Service::DynamoDb));
    assert_eq!(e.code(), None);
    assert!(!err.is_retryable());
}

#[tokio::test]
async fn kms_throttling_is_throttling_about_the_kms_key() {
    let err = hierarchical_decrypt_error(FakeAws::new(|op, _| {
        (op == "TrentService.Decrypt")
            .then(|| Reply::error(400, "ThrottlingException", "throttled-request"))
    }))
    .await;
    let Error::Throttling(e) = &err else {
        panic!("expected Throttling, got {err:?}");
    };
    assert_eq!(e.retry_kind(), Some(RetryKind::Throttling));
    assert_eq!(e.service(), Some(&Service::Kms));
    assert_eq!(e.resource(), Some(&Resource::KmsKey(KmsKey::new(KEY_ARN))));
    assert_eq!(e.code(), Some("ThrottlingException"));
}

#[tokio::test]
async fn the_materials_cache_timing_out_is_throttling_about_the_cache() {
    use aws_crypto_mpl::HierarchicalKeyring;
    use aws_crypto_mpl::aws_kms::__test_internals::{SCOPE_ID_ENCRYPT, build_cache_identifier};
    use aws_crypto_mpl::cmc::{SharedCmc, StormTrackingCmc};
    use std::time::{Duration, SystemTime};

    let now = SystemTime::now();
    let cache = StormTrackingCmc::builder()
        .clock(move || now)
        .build()
        .unwrap();
    // Another caller started fetching this branch key and never finished.
    let id = build_cache_identifier(SCOPE_ID_ENCRYPT, b"p", TABLE, BRANCH_KEY_ID, None);
    cache.mark_inflight(&id, now - cache.inflight_ttl() - Duration::from_secs(1));
    let keyring = HierarchicalKeyring::builder()
        .key_store(FakeAws::ok().key_store().await)
        .branch_key_id(BRANCH_KEY_ID)
        .ttl(Duration::from_secs(600))
        .partition_id("p")
        .cache(SharedCmc::new(cache))
        .build()
        .unwrap();
    let err = Client::default()
        .encrypt()
        .plaintext(b"hello")
        .keyring(keyring)
        .send()
        .await
        .unwrap_err();
    let Error::Throttling(e) = &err else {
        panic!("expected Throttling, got {err:?}");
    };
    assert_eq!(e.resource(), Some(&Resource::Cache(Cache::new())));
    assert_eq!(e.service(), None);
    assert_eq!(
        err.to_string(),
        "Throttling: encrypt could not get encryption materials (materials cache)"
    );
    assert_eq!(
        format!("{err:#}"),
        "Throttling: encrypt could not get encryption materials (materials cache): \
         timed out waiting for another caller to fetch branch key my-branch-key"
    );
}

#[tokio::test]
async fn a_tampered_frame_is_cryptographic() {
    let keyring = RawAesKeyring::builder()
        .key_namespace("ns")
        .key_name("name")
        .wrapping_key(vec![7; 32])
        .wrapping_alg(AesGcm::Aes256Gcm)
        .build()
        .unwrap();
    let mut ciphertext = Client::default()
        .encrypt()
        .plaintext(b"hello")
        .algorithm_suite_id(aws_esdk::AlgorithmSuiteId::AlgAes256GcmHkdfSha512CommitKey)
        .keyring(keyring.clone())
        .send()
        .await
        .unwrap()
        .into_ciphertext();
    // The last content byte of the final frame, just before its 16-byte tag.
    let i = ciphertext.len() - 17;
    ciphertext[i] ^= 1;
    let err = decrypt_with(&ciphertext, keyring).await.unwrap_err();
    assert!(err.is_cryptographic(), "{err:?}");
    assert!(!err.is_retryable());
}

#[tokio::test]
async fn an_encryption_context_mismatch_names_the_key_not_the_value() {
    let keyring = RawAesKeyring::builder()
        .key_namespace("ns")
        .key_name("name")
        .wrapping_key(vec![7; 32])
        .wrapping_alg(AesGcm::Aes256Gcm)
        .build()
        .unwrap();
    let ciphertext = encrypt_with(keyring.clone()).await;
    let mut other = EncryptionContext::new();
    other.insert("tenant", "a-different-value");
    let err = Client::default()
        .decrypt()
        .ciphertext(&ciphertext)
        .set_encryption_context(Some(other))
        .keyring(keyring)
        .send()
        .await
        .unwrap_err();
    assert!(err.is_encryption_context_mismatch(), "{err:?}");
    let alternate = format!("{err:#}");
    assert!(alternate.contains("key 'tenant'"), "{alternate}");
    for text in [err.to_string(), alternate, format!("{err:?}")] {
        assert!(!text.contains("a-different-value"), "{text}");
        assert!(!text.contains("example"), "{text}");
    }
}

fn transaction_canceled(reasons: &str) -> Reply {
    Reply {
        status: 400,
        body: format!(
            r#"{{"__type":"com.amazonaws.dynamodb.v20120810#TransactionCanceledException","message":"Transaction cancelled","CancellationReasons":[{reasons}]}}"#
        ),
        request_id: "Q2N0",
    }
}

#[tokio::test]
async fn version_key_condition_failure_is_a_concurrent_modification_conflict() {
    use aws_esdk::error::ConflictReason;
    let fake = FakeAws::new(|op, _| {
        (op == "DynamoDB_20120810.TransactWriteItems")
            .then(|| transaction_canceled(r#"{"Code":"None"},{"Code":"ConditionalCheckFailed"}"#))
    });
    let err = fake
        .key_store()
        .await
        .version_key()
        .branch_key_id(BRANCH_KEY_ID)
        .send()
        .await
        .unwrap_err();
    let aws_crypto_mpl::Error::Conflict(e) = &err else {
        panic!("expected Conflict, got {err:?}");
    };
    assert_eq!(e.reason(), Some(&ConflictReason::ConcurrentModification));
    assert_eq!(e.service(), Some(&Service::DynamoDb));
    assert_eq!(
        e.resource(),
        Some(&Resource::BranchKey(BranchKey::new(BRANCH_KEY_ID)))
    );
    assert_eq!(e.code(), Some("TransactionCanceledException"));
    assert_eq!(e.request_id(), Some("Q2N0"));
    assert!(!err.is_retryable());
    assert_eq!(
        err.to_string(),
        "Conflict: branch key my-branch-key was rotated concurrently \
         (Amazon DynamoDB, branch key my-branch-key, TransactionCanceledException, request Q2N0)"
    );
    let alternate = format!("{err:#}");
    assert!(
        alternate.starts_with(
            "Conflict: branch key my-branch-key was rotated concurrently \
             (Amazon DynamoDB, branch key my-branch-key, TransactionCanceledException, request Q2N0): \
             Service: DynamoDB TransactWriteItems failed (table KeyStoreTable): service error"
        ),
        "{alternate}"
    );
}

#[tokio::test]
async fn create_key_condition_failure_is_an_already_exists_conflict() {
    use aws_esdk::error::ConflictReason;
    let fake = FakeAws::new(|op, _| {
        (op == "DynamoDB_20120810.TransactWriteItems")
            .then(|| transaction_canceled(r#"{"Code":"ConditionalCheckFailed"}"#))
    });
    let err = fake
        .key_store()
        .await
        .create_key()
        .branch_key_id(BRANCH_KEY_ID)
        .set_encryption_context(Some(EncryptionContext::new()))
        .send()
        .await
        .unwrap_err();
    let aws_crypto_mpl::Error::Conflict(e) = &err else {
        panic!("expected Conflict, got {err:?}");
    };
    assert_eq!(e.reason(), Some(&ConflictReason::AlreadyExists));
    assert_eq!(
        e.resource(),
        Some(&Resource::BranchKey(BranchKey::new(BRANCH_KEY_ID)))
    );
    assert_eq!(err.message(), "branch key my-branch-key already exists");
}

#[tokio::test]
async fn a_transaction_conflict_is_a_retryable_service_error() {
    let fake = FakeAws::new(|op, _| {
        (op == "DynamoDB_20120810.TransactWriteItems")
            .then(|| transaction_canceled(r#"{"Code":"TransactionConflict"}"#))
    });
    let err = fake
        .key_store()
        .await
        .version_key()
        .branch_key_id(BRANCH_KEY_ID)
        .send()
        .await
        .unwrap_err();
    assert!(err.is_service(), "{err:?}");
    assert_eq!(err.retry_kind(), Some(RetryKind::Transient));
    assert_eq!(
        err.resource(),
        Some(&Resource::DynamoDbTable(DynamoDbTable::new(TABLE)))
    );
}

#[test]
fn name_is_the_variant_name() {
    use aws_esdk::error::{SerializationError, ThrottlingError};
    assert_eq!(
        Error::from(SerializationError::new("m")).name(),
        "Serialization"
    );
    assert_eq!(Error::from(ThrottlingError::new("m")).name(), "Throttling");
}

#[tokio::test]
async fn version_key_keeps_the_kms_classification_of_the_record_check() {
    let version_key_error = |code: &'static str| async move {
        FakeAws::new(move |op, _| {
            (op == "TrentService.ReEncrypt").then(|| Reply::error(400, code, "r"))
        })
        .key_store()
        .await
        .version_key()
        .branch_key_id(BRANCH_KEY_ID)
        .send()
        .await
        .unwrap_err()
    };
    let denied = version_key_error("AccessDeniedException").await;
    assert!(denied.is_access_denied(), "{denied:?}");
    assert_eq!(
        denied.resource(),
        Some(&Resource::KmsKey(KmsKey::new(KEY_ARN)))
    );
    let tampered = version_key_error("InvalidCiphertextException").await;
    assert!(tampered.is_cryptographic(), "{tampered:?}");
}

/// The error from encrypting under the fake's hierarchical keyring.
async fn hierarchical_encrypt_error(fake: FakeAws) -> Error {
    Client::default()
        .encrypt()
        .plaintext(b"hello")
        .keyring(fake.keyring().await)
        .send()
        .await
        .expect_err("the fake fails the call")
}

fn on(op: &'static str, reply: Reply) -> FakeAws {
    FakeAws::new(move |o, _| (o == op).then(|| reply.clone()))
}

#[tokio::test]
async fn dynamodb_access_denied_names_the_table() {
    let err = hierarchical_decrypt_error(on(
        "DynamoDB_20120810.GetItem",
        Reply::error(400, "AccessDeniedException", "ddb-denied"),
    ))
    .await;
    let Error::AccessDenied(e) = &err else {
        panic!("expected AccessDenied, got {err:?}");
    };
    assert!(!e.is_credentials());
    assert_eq!(e.service(), Some(&Service::DynamoDb));
    assert_eq!(
        e.resource(),
        Some(&Resource::DynamoDbTable(DynamoDbTable::new(TABLE)))
    );
    assert_eq!(e.code(), Some("AccessDeniedException"));
    assert_eq!(e.request_id(), Some("ddb-denied"));
}

#[tokio::test]
async fn a_missing_kms_key_names_the_kms_key() {
    let err = hierarchical_decrypt_error(on(
        "TrentService.Decrypt",
        Reply::error(400, "NotFoundException", "kms-not-found"),
    ))
    .await;
    let Error::ResourceNotFound(e) = &err else {
        panic!("expected ResourceNotFound, got {err:?}");
    };
    assert_eq!(e.service(), Some(&Service::Kms));
    assert_eq!(e.resource(), Some(&Resource::KmsKey(KmsKey::new(KEY_ARN))));
    assert_eq!(e.code(), Some("NotFoundException"));
}

#[tokio::test]
async fn a_missing_table_names_the_table() {
    let err = hierarchical_decrypt_error(on(
        "DynamoDB_20120810.GetItem",
        Reply::error(400, "ResourceNotFoundException", "ddb-not-found"),
    ))
    .await;
    let Error::ResourceNotFound(e) = &err else {
        panic!("expected ResourceNotFound, got {err:?}");
    };
    assert_eq!(e.service(), Some(&Service::DynamoDb));
    assert_eq!(
        e.resource(),
        Some(&Resource::DynamoDbTable(DynamoDbTable::new(TABLE)))
    );
    assert_eq!(e.code(), Some("ResourceNotFoundException"));
}

#[tokio::test]
async fn a_truncated_message_is_serialization() {
    let keyring = RawAesKeyring::builder()
        .key_namespace("ns")
        .key_name("name")
        .wrapping_key(vec![7; 32])
        .wrapping_alg(AesGcm::Aes256Gcm)
        .build()
        .unwrap();
    let ciphertext = encrypt_with(keyring.clone()).await;
    let err = decrypt_with(&ciphertext[..ciphertext.len() / 2], keyring)
        .await
        .unwrap_err();
    assert!(err.is_serialization(), "{err:?}");
    assert!(!err.is_retryable());
}

#[tokio::test]
async fn encrypt_kms_access_denied_names_the_kms_key() {
    let err = hierarchical_encrypt_error(on(
        "TrentService.Decrypt",
        Reply::error(400, "AccessDeniedException", "6f1c2e9a"),
    ))
    .await;
    let Error::AccessDenied(e) = &err else {
        panic!("expected AccessDenied, got {err:?}");
    };
    assert_eq!(e.service(), Some(&Service::Kms));
    assert_eq!(e.resource(), Some(&Resource::KmsKey(KmsKey::new(KEY_ARN))));
    assert_eq!(e.request_id(), Some("6f1c2e9a"));
    assert!(
        err.message()
            .starts_with("encrypt could not get encryption materials")
    );
}

#[tokio::test]
async fn encrypt_expired_credentials_are_credentials() {
    let err = hierarchical_encrypt_error(on(
        "DynamoDB_20120810.GetItem",
        Reply::error(400, "ExpiredTokenException", "ddb-request"),
    ))
    .await;
    let Error::AccessDenied(e) = &err else {
        panic!("expected AccessDenied, got {err:?}");
    };
    assert!(e.is_credentials());
    assert_eq!(
        e.resource(),
        Some(&Resource::DynamoDbTable(DynamoDbTable::new(TABLE)))
    );
}

#[tokio::test]
async fn encrypt_without_an_active_branch_key_names_the_branch_key() {
    let err = hierarchical_encrypt_error(on("DynamoDB_20120810.GetItem", Reply::ok("{}"))).await;
    let Error::ResourceNotFound(e) = &err else {
        panic!("expected ResourceNotFound, got {err:?}");
    };
    assert_eq!(
        e.resource(),
        Some(&Resource::BranchKey(BranchKey::new(BRANCH_KEY_ID)))
    );
}

#[tokio::test]
async fn create_key_kms_access_denied_names_the_kms_key() {
    let fake = on(
        "TrentService.GenerateDataKeyWithoutPlaintext",
        Reply::error(400, "AccessDeniedException", "gdk-denied"),
    );
    let err = fake
        .key_store()
        .await
        .create_key()
        .branch_key_id(BRANCH_KEY_ID)
        .set_encryption_context(Some(EncryptionContext::new()))
        .send()
        .await
        .unwrap_err();
    let aws_crypto_mpl::Error::AccessDenied(e) = &err else {
        panic!("expected AccessDenied, got {err:?}");
    };
    assert_eq!(e.service(), Some(&Service::Kms));
    assert_eq!(e.resource(), Some(&Resource::KmsKey(KmsKey::new(KEY_ARN))));
    assert_eq!(e.request_id(), Some("gdk-denied"));
}

#[tokio::test]
async fn version_key_without_an_active_branch_key_names_the_branch_key() {
    let err = on("DynamoDB_20120810.GetItem", Reply::ok("{}"))
        .key_store()
        .await
        .version_key()
        .branch_key_id(BRANCH_KEY_ID)
        .send()
        .await
        .unwrap_err();
    let aws_crypto_mpl::Error::ResourceNotFound(e) = &err else {
        panic!("expected ResourceNotFound, got {err:?}");
    };
    assert_eq!(
        e.resource(),
        Some(&Resource::BranchKey(BranchKey::new(BRANCH_KEY_ID)))
    );
}

/// Wraps the data key under two keyrings, so the message has two encrypted data keys.
struct Both(SharedKeyring, SharedKeyring);

#[async_trait]
impl aws_crypto_mpl::Keyring for Both {
    async fn on_encrypt(
        &self,
        input: OnEncryptInput,
    ) -> Result<OnEncryptOutput, aws_crypto_mpl::Error> {
        let materials = aws_crypto_mpl::Keyring::on_encrypt(&self.0, input)
            .await?
            .into_materials();
        self.1.on_encrypt().materials(materials).send().await
    }

    async fn on_decrypt(
        &self,
        _: OnDecryptInput,
    ) -> Result<OnDecryptOutput, aws_crypto_mpl::Error> {
        unreachable!("the tests decrypt with another keyring")
    }
}

#[tokio::test]
async fn failures_lists_every_attempt_behind_a_keyring_error() {
    // EDK 0 is another keyring's; EDK 1 has this keyring's name but a different key.
    let other = RawAesKeyring::builder()
        .key_namespace("other")
        .key_name("key")
        .wrapping_key(vec![1; 32])
        .wrapping_alg(AesGcm::Aes256Gcm)
        .build()
        .unwrap();
    let same_name_other_key = RawAesKeyring::builder()
        .key_namespace("ns")
        .key_name("key")
        .wrapping_key(vec![2; 32])
        .wrapping_alg(AesGcm::Aes256Gcm)
        .build()
        .unwrap();
    let ciphertext = encrypt_with(Both(
        SharedKeyring::new(other),
        SharedKeyring::new(same_name_other_key),
    ))
    .await;
    let keyring = RawAesKeyring::builder()
        .key_namespace("ns")
        .key_name("key")
        .wrapping_key(vec![3; 32])
        .wrapping_alg(AesGcm::Aes256Gcm)
        .build()
        .unwrap();
    let err = decrypt_with(&ciphertext, keyring).await.unwrap_err();

    assert!(err.is_cryptographic(), "{err:?}");
    assert!(err.collected().is_empty());
    let mpl = err.find_source::<aws_crypto_mpl::Error>().unwrap();
    assert_eq!(mpl.collected().len(), 2);

    let failures = err.failures();
    assert_eq!(failures.len(), 2);
    assert!(failures[0].is_no_matching_data_key(), "{:?}", failures[0]);
    assert!(failures[1].is_cryptographic(), "{:?}", failures[1]);
    assert!(
        failures[1]
            .find_source::<aws_mpl_primitives::Error>()
            .is_some(),
        "{:?}",
        failures[1]
    );
    assert_eq!(failures[1].message(), mpl.collected()[1].message());
}

#[tokio::test]
async fn failures_of_a_single_failure_is_itself() {
    let err = hierarchical_decrypt_error(on(
        "TrentService.Decrypt",
        Reply::error(400, "AccessDeniedException", "6f1c2e9a"),
    ))
    .await;
    let failures = err.failures();
    assert_eq!(failures.len(), 1);
    assert_eq!(failures[0].name(), err.name());
    assert_eq!(failures[0].message(), err.message());
    assert_eq!(failures[0].resource(), err.resource());
    assert_eq!(failures[0].request_id(), err.request_id());
}

#[tokio::test]
async fn two_attempts_denied_and_throttled_is_retryable_throttling() {
    use std::sync::Arc;
    use std::sync::atomic::{AtomicUsize, Ordering};
    let ciphertext = encrypt_with(Both(
        SharedKeyring::new(FakeAws::ok().keyring().await),
        SharedKeyring::new(FakeAws::ok().keyring().await),
    ))
    .await;
    let calls = Arc::new(AtomicUsize::new(0));
    let fake = FakeAws::new(move |op, _| {
        (op == "TrentService.Decrypt").then(|| {
            if calls.fetch_add(1, Ordering::SeqCst) == 0 {
                Reply::error(400, "AccessDeniedException", "req-1")
            } else {
                Reply::error(400, "ThrottlingException", "req-2")
            }
        })
    });
    let err = decrypt_with(&ciphertext, fake.keyring().await)
        .await
        .unwrap_err();
    assert!(err.is_throttling(), "{err:?}");
    assert_eq!(err.retry_kind(), Some(RetryKind::Throttling));
    assert_eq!(
        err.resource(),
        Some(&Resource::KmsKey(KmsKey::new(KEY_ARN)))
    );
    assert_eq!(err.request_id(), None);
    let failures = err.failures();
    assert_eq!(failures.len(), 2);
    assert!(failures[0].is_access_denied());
    assert_eq!(failures[0].request_id(), Some("req-1"));
    assert!(failures[1].is_throttling());
    assert_eq!(failures[1].request_id(), Some("req-2"));
}

#[tokio::test]
async fn a_clone_keeps_the_sdk_error_and_prints_the_same() {
    use aws_crypto_mpl::aws_sdk_kms::error::SdkError;
    use aws_crypto_mpl::aws_sdk_kms::operation::decrypt::DecryptError;
    let err = hierarchical_decrypt_error(on(
        "TrentService.Decrypt",
        Reply::error(400, "AccessDeniedException", "6f1c2e9a"),
    ))
    .await;
    let clone = err.clone();
    assert!(clone.find_source::<SdkError<DecryptError>>().is_some());
    assert_eq!(format!("{clone:#}"), format!("{err:#}"));
    assert_eq!(format!("{clone:?}"), format!("{err:?}"));
}

/// A key in another account, which only a discovery key store would call.
const RECORD_KEY_ARN: &str = "arn:aws:kms:us-west-2:444455556666:key/5678efgh";

/// A hierarchical keyring over a discovery key store: the KMS key comes from each branch key record.
async fn discovery_keyring(fake: &FakeAws) -> aws_crypto_mpl::HierarchicalKeyring {
    let key_store = aws_crypto_mpl::KeyStoreClient::builder()
        .ddb_table_name(TABLE)
        .logical_key_store_name(TABLE)
        .kms_configuration(aws_crypto_mpl::KmsConfiguration::Discovery(
            aws_crypto_mpl::Discovery::builder().build().unwrap(),
        ))
        .kms_client(fake.kms_client())
        .ddb_client(fake.ddb_client())
        .build()
        .await
        .unwrap();
    aws_crypto_mpl::HierarchicalKeyring::builder()
        .key_store(key_store)
        .branch_key_id(BRANCH_KEY_ID)
        .ttl(std::time::Duration::from_secs(600))
        .build()
        .unwrap()
}

#[tokio::test]
async fn a_discovery_key_store_names_the_kms_key_from_the_record() {
    // Every record names RECORD_KEY_ARN; AWS KMS denies decrypting under it.
    let fake = FakeAws::new(|op, body| match op {
        "DynamoDB_20120810.GetItem" => {
            let record_type = fake_aws::string_attribute(body, "type").unwrap_or("branch:ACTIVE");
            Some(Reply::ok(
                fake_aws::record(record_type, "AAAA", "").replace(KEY_ARN, RECORD_KEY_ARN),
            ))
        }
        "TrentService.Decrypt" => Some(Reply::error(400, "AccessDeniedException", "disc-req")),
        _ => None,
    });
    let err = Client::default()
        .encrypt()
        .plaintext(b"hello")
        .keyring(discovery_keyring(&fake).await)
        .send()
        .await
        .unwrap_err();
    let Error::AccessDenied(e) = &err else {
        panic!("expected AccessDenied, got {err:?}");
    };
    assert_eq!(e.service(), Some(&Service::Kms));
    assert_eq!(
        e.resource(),
        Some(&Resource::KmsKey(KmsKey::new(RECORD_KEY_ARN)))
    );
    assert_eq!(e.request_id(), Some("disc-req"));
    assert!(err.to_string().contains(RECORD_KEY_ARN), "{err}");
}
