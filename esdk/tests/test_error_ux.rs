// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

//! What a customer sees when an operation fails:
//! the variant, its details, and its `{}` and `{:#}` text.

mod fake_aws;

use aws_crypto_mpl::keyring::RawAesKeyring;
use aws_crypto_mpl::structures::EncryptionContext;
use aws_esdk::error::{Error, Resource, RetryKind, Service};
use aws_esdk::{DecryptInput, EncryptInput, decrypt, encrypt};
use aws_mpl_primitives::AesGcm;
use fake_aws::{BRANCH_KEY_ID, FakeAws, KEY_ARN, Reply, TABLE};

fn context() -> EncryptionContext {
    let mut ec = EncryptionContext::new();
    ec.insert("tenant", "example");
    ec
}

async fn encrypt_with(keyring: impl aws_crypto_mpl::Keyring + 'static) -> Vec<u8> {
    let input = EncryptInput::builder()
        .plaintext(b"hello")
        .encryption_context(context())
        .keyring(keyring)
        .build()
        .unwrap();
    encrypt(&input).await.unwrap().ciphertext
}

async fn decrypt_with(
    ciphertext: &[u8],
    keyring: impl aws_crypto_mpl::Keyring + 'static,
) -> Result<Vec<u8>, Error> {
    let input = DecryptInput::builder()
        .ciphertext(ciphertext)
        .keyring(keyring)
        .build()
        .unwrap();
    decrypt(&input).await.map(|out| out.plaintext)
}

/// A message encrypted under the fake's branch key, and the error from decrypting it
/// against `fake`.
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
    assert_eq!(e.service(), Some(Service::Kms));
    assert_eq!(e.resource(), Some(&Resource::KmsKey(KEY_ARN.into())));
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
        RawAesKeyring::new(ns, name, vec![byte; 32], AesGcm::Aes256Gcm).unwrap()
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
        Some(&Resource::Keyring("my-namespace/my-key".into()))
    );
    assert!(err.collected().is_empty());
    assert_eq!(
        format!("{err:#}"),
        "NoMatchingDataKey: decrypt could not get decryption materials (keyring my-namespace/my-key): \
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
    assert_eq!(e.service(), Some(Service::DynamoDb));
    assert_eq!(e.resource(), Some(&Resource::DynamoDbTable(TABLE.into())));
    assert_eq!(e.code(), Some("ExpiredTokenException"));
    assert_eq!(e.request_id(), Some("ddb-request"));
}

#[tokio::test]
async fn a_missing_branch_key_record_names_the_branch_key() {
    let err = hierarchical_decrypt_error(FakeAws::new(|op, _| {
        (op == "DynamoDB_20120810.GetItem").then(|| Reply::ok("{}"))
    }))
    .await;
    let Error::ResourceNotFound(e) = &err else {
        panic!("expected ResourceNotFound, got {err:?}");
    };
    assert_eq!(e.service(), Some(Service::DynamoDb));
    assert_eq!(
        e.resource(),
        Some(&Resource::BranchKey(BRANCH_KEY_ID.into()))
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
        Some(&Resource::BranchKey(BRANCH_KEY_ID.into()))
    );
    assert_eq!(e.service(), Some(Service::DynamoDb));
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
    assert_eq!(e.service(), Some(Service::Kms));
    assert_eq!(e.resource(), Some(&Resource::KmsKey(KEY_ARN.into())));
    assert_eq!(e.code(), Some("ThrottlingException"));
}

#[tokio::test]
async fn the_materials_cache_timing_out_is_throttling_about_the_cache() {
    use aws_crypto_mpl::HierarchicalKeyring;
    use aws_crypto_mpl::aws_kms::__test_internals::build_cache_identifier;
    use aws_crypto_mpl::aws_kms::hierarchical_keyring::SCOPE_ID_ENCRYPT;
    use aws_crypto_mpl::cmc::{CacheType, SharedCmc, StormTrackingCache, StormTrackingCmc};
    use std::time::{Duration, SystemTime};

    let now = SystemTime::now();
    let config = StormTrackingCache::builder().build().unwrap();
    let cache = StormTrackingCmc::with_clock(&config, move || now).unwrap();
    // Another caller started fetching this branch key and never finished.
    let id = build_cache_identifier(SCOPE_ID_ENCRYPT, b"p", TABLE, BRANCH_KEY_ID, None);
    cache.mark_inflight(&id, now - config.inflight_ttl() - Duration::from_secs(1));
    let keyring = HierarchicalKeyring::builder()
        .key_store(FakeAws::ok().key_store().await)
        .branch_key_id(BRANCH_KEY_ID)
        .ttl(Duration::from_secs(600))
        .partition_id("p")
        .cache(CacheType::Shared(SharedCmc::new(cache)))
        .build()
        .unwrap();
    let input = EncryptInput::builder()
        .plaintext(b"hello")
        .keyring(keyring)
        .build()
        .unwrap();
    let err = encrypt(&input).await.unwrap_err();
    let Error::Throttling(e) = &err else {
        panic!("expected Throttling, got {err:?}");
    };
    assert_eq!(e.resource(), Some(&Resource::Cache));
    assert_eq!(e.service(), None);
    assert_eq!(
        err.to_string(),
        "Throttling: encrypt could not get encryption materials (materials cache, retryable: throttling)"
    );
    assert_eq!(
        format!("{err:#}"),
        "Throttling: encrypt could not get encryption materials (materials cache, retryable: throttling): \
         timed out waiting for another caller to fetch branch key my-branch-key"
    );
}

#[tokio::test]
async fn a_tampered_frame_is_cryptographic() {
    let keyring = RawAesKeyring::new("ns", "name", vec![7; 32], AesGcm::Aes256Gcm).unwrap();
    let input = EncryptInput::builder()
        .plaintext(b"hello")
        .algorithm_suite_id(aws_esdk::AlgorithmSuiteId::AlgAes256GcmHkdfSha512CommitKey)
        .keyring(keyring.clone())
        .build()
        .unwrap();
    let mut ciphertext = encrypt(&input).await.unwrap().ciphertext;
    // The last content byte of the final frame, just before its 16-byte tag.
    let i = ciphertext.len() - 17;
    ciphertext[i] ^= 1;
    let err = decrypt_with(&ciphertext, keyring).await.unwrap_err();
    assert!(err.is_cryptographic(), "{err:?}");
    assert!(!err.is_retryable());
}

#[tokio::test]
async fn an_encryption_context_mismatch_names_the_key_not_the_value() {
    let keyring = RawAesKeyring::new("ns", "name", vec![7; 32], AesGcm::Aes256Gcm).unwrap();
    let ciphertext = encrypt_with(keyring.clone()).await;
    let mut other = EncryptionContext::new();
    other.insert("tenant", "a-different-value");
    let input = DecryptInput::builder()
        .ciphertext(&ciphertext)
        .encryption_context(other)
        .keyring(keyring)
        .build()
        .unwrap();
    let err = decrypt(&input).await.unwrap_err();
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
    use aws_crypto_mpl::Keystore;
    use aws_esdk::error::ConflictReason;
    let fake = FakeAws::new(|op, _| {
        (op == "DynamoDB_20120810.TransactWriteItems")
            .then(|| transaction_canceled(r#"{"Code":"None"},{"Code":"ConditionalCheckFailed"}"#))
    });
    let err = fake
        .key_store()
        .await
        .version_key(BRANCH_KEY_ID.into())
        .await
        .unwrap_err();
    let aws_crypto_mpl::Error::Conflict(e) = &err else {
        panic!("expected Conflict, got {err:?}");
    };
    assert_eq!(e.reason(), Some(ConflictReason::ConcurrentModification));
    assert_eq!(e.service(), Some(Service::DynamoDb));
    assert_eq!(
        e.resource(),
        Some(&Resource::BranchKey(BRANCH_KEY_ID.into()))
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
    use aws_crypto_mpl::Keystore;
    use aws_esdk::error::ConflictReason;
    let fake = FakeAws::new(|op, _| {
        (op == "DynamoDB_20120810.TransactWriteItems")
            .then(|| transaction_canceled(r#"{"Code":"ConditionalCheckFailed"}"#))
    });
    let err = fake
        .key_store()
        .await
        .create_key(Some(BRANCH_KEY_ID.into()), Some(EncryptionContext::new()))
        .await
        .unwrap_err();
    let aws_crypto_mpl::Error::Conflict(e) = &err else {
        panic!("expected Conflict, got {err:?}");
    };
    assert_eq!(e.reason(), Some(ConflictReason::AlreadyExists));
    assert_eq!(
        e.resource(),
        Some(&Resource::BranchKey(BRANCH_KEY_ID.into()))
    );
    assert_eq!(err.message(), "branch key my-branch-key already exists");
}

#[tokio::test]
async fn a_transaction_conflict_is_a_retryable_service_error() {
    use aws_crypto_mpl::Keystore;
    let fake = FakeAws::new(|op, _| {
        (op == "DynamoDB_20120810.TransactWriteItems")
            .then(|| transaction_canceled(r#"{"Code":"TransactionConflict"}"#))
    });
    let err = fake
        .key_store()
        .await
        .version_key(BRANCH_KEY_ID.into())
        .await
        .unwrap_err();
    assert!(err.is_service(), "{err:?}");
    assert_eq!(err.retry_kind(), Some(RetryKind::Transient));
    assert_eq!(err.resource(), Some(&Resource::DynamoDbTable(TABLE.into())));
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
    use aws_crypto_mpl::Keystore;
    let version_key_error = |code: &'static str| async move {
        FakeAws::new(move |op, _| {
            (op == "TrentService.ReEncrypt").then(|| Reply::error(400, code, "r"))
        })
        .key_store()
        .await
        .version_key(BRANCH_KEY_ID.into())
        .await
        .unwrap_err()
    };
    let denied = version_key_error("AccessDeniedException").await;
    assert!(denied.is_access_denied(), "{denied:?}");
    assert_eq!(denied.resource(), Some(&Resource::KmsKey(KEY_ARN.into())));
    let tampered = version_key_error("InvalidCiphertextException").await;
    assert!(tampered.is_cryptographic(), "{tampered:?}");
}
