// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

//! `ItemEncryptor` input errors, plaintext policies, tampering, and keyring failures.

mod item_encryptor_support;

use aws_db_esdk::async_trait;
use aws_db_esdk::aws_sdk_dynamodb::primitives::Blob;
use aws_db_esdk::aws_sdk_dynamodb::types::AttributeValue;
use aws_db_esdk::keyring::{
    Keyring, OnDecryptInput, OnDecryptOutput, OnEncryptInput, OnEncryptOutput,
};
use aws_db_esdk::mpl::Error as MplError;
use aws_db_esdk::types::{AlgorithmSuiteId, CryptoAction, PlaintextOverride};
use aws_db_esdk::{Error, ItemEncryptor};
use item_encryptor_support::*;

const HEADER: &str = "aws_dbe_head";
const FOOTER: &str = "aws_dbe_foot";

async fn encrypt(encryptor: &ItemEncryptor, input: Item) -> Result<Item, Error> {
    encryptor
        .encrypt_item()
        .plaintext_item(input)
        .send()
        .await
        .map(|o| o.into_encrypted_item())
}

async fn decrypt(encryptor: &ItemEncryptor, input: Item) -> Result<Item, Error> {
    encryptor
        .decrypt_item()
        .encrypted_item(input)
        .send()
        .await
        .map(|o| o.into_plaintext_item())
}

fn validation_message(result: Result<Item, Error>) -> String {
    match result {
        Err(Error::Validation(e)) => e.message().to_owned(),
        other => panic!("expected a Validation error, got {other:?}"),
    }
}

fn serialization_message(result: Result<Item, Error>) -> String {
    match result {
        Err(Error::Serialization(e)) => e.message().to_owned(),
        other => panic!("expected a Serialization error, got {other:?}"),
    }
}

async fn encrypted_v1_item() -> Item {
    encrypt(&default_encryptor(), v1_item()).await.unwrap()
}

fn binary(item: &Item, name: &str) -> Vec<u8> {
    match &item[name] {
        AttributeValue::B(b) => b.as_ref().to_vec(),
        other => panic!("{name} is not binary: {other:?}"),
    }
}

// --- Encrypt input errors ---

#[tokio::test]
async fn encrypt_requires_item() {
    let err = default_encryptor()
        .encrypt_item()
        .set_plaintext_item(None)
        .send()
        .await;
    assert_eq!(
        validation_message(err.map(|o| o.into_encrypted_item())),
        "plaintext_item is required"
    );
}

#[tokio::test]
async fn encrypt_rejects_unconfigured_attribute() {
    let mut input = v1_item();
    input.insert("unknown".to_owned(), s("other"));
    assert_eq!(
        validation_message(encrypt(&default_encryptor(), input).await),
        "No Crypto Action configured for attribute unknown"
    );
}

#[tokio::test]
async fn encrypt_lists_every_unconfigured_attribute_sorted() {
    let mut input = v1_item();
    input.insert("zz".to_owned(), s("1"));
    input.insert("aa".to_owned(), s("2"));
    assert_eq!(
        validation_message(encrypt(&default_encryptor(), input).await),
        "No Crypto Action configured for attribute aa\nNo Crypto Action configured for attribute zz"
    );
}

#[tokio::test]
async fn encrypt_rejects_missing_sort_key() {
    let encryptor = encryptor_from(
        config_builder(v1_actions())
            .sort_key_name("sort")
            .attribute_actions_on_encrypt("sort", CryptoAction::SignOnly),
    );
    let input = item([
        ("bar", s("key")),
        ("encrypt", s("foo")),
        ("sign", s("bar")),
        ("nothing", s("baz")),
    ]);
    assert_eq!(
        validation_message(encrypt(&encryptor, input).await),
        "On Encrypt : Sort key 'sort' does not exist in item. Item contains these attributes : bar encrypt nothing sign."
    );
}

#[tokio::test]
async fn encrypt_rejects_missing_partition_and_sort_key() {
    let encryptor = encryptor_from(
        config_builder(v1_actions())
            .sort_key_name("sort")
            .attribute_actions_on_encrypt("sort", CryptoAction::SignOnly),
    );
    assert_eq!(
        validation_message(encrypt(&encryptor, Item::new()).await),
        "On Encrypt : Partition key 'bar' does not exist in item. Sort key 'sort' does not exist in item. Item contains these attributes : item is empty."
    );
}

#[tokio::test]
async fn encrypt_rejects_missing_context_attribute() {
    let encryptor = encryptor_from(config_builder(v2_actions()));
    let input = item([
        ("bar", s("key")),
        ("encrypt", s("text")),
        ("nothing", s("baz")),
    ]);
    assert_eq!(
        validation_message(encrypt(&encryptor, input).await),
        "Attribute sign was configured with SIGN_AND_INCLUDE_IN_ENCRYPTION_CONTEXT but was not present in item to be encrypted."
    );
}

#[tokio::test]
async fn encrypt_lists_every_missing_context_attribute() {
    let mut acts = v2_actions();
    acts.insert(
        "sign2".to_owned(),
        CryptoAction::SignAndIncludeInEncryptionContext,
    );
    let encryptor = encryptor_from(config_builder(acts));
    let input = item([("bar", s("key"))]);
    assert_eq!(
        validation_message(encrypt(&encryptor, input).await),
        "These attributes were configured with SIGN_AND_INCLUDE_IN_ENCRYPTION_CONTEXT but were not present in item to be encrypted.sign,sign2"
    );
}

#[tokio::test]
async fn encrypt_rejects_attribute_name_over_65535_characters() {
    let mut input = v1_item();
    input.insert("a".repeat(65_536), s("x"));
    assert_eq!(
        validation_message(encrypt(&default_encryptor(), input).await),
        "plaintext_item has an attribute name longer than 65535 characters"
    );
}

#[tokio::test]
async fn encrypt_rejects_invalid_number() {
    let mut input = v1_item();
    input.insert(
        "sign".to_owned(),
        AttributeValue::N("not a number".to_owned()),
    );
    let err = encrypt(&default_encryptor(), input).await.unwrap_err();
    assert!(matches!(err, Error::Validation(_)), "{err:?}");
}

// --- Decrypt input errors ---

#[tokio::test]
async fn decrypt_requires_item() {
    let err = default_encryptor()
        .decrypt_item()
        .set_encrypted_item(None)
        .send()
        .await;
    assert_eq!(
        validation_message(err.map(|o| o.into_plaintext_item())),
        "encrypted_item is required"
    );
}

#[tokio::test]
async fn decrypt_rejects_missing_partition_key() {
    let mut encrypted = encrypted_v1_item().await;
    encrypted.remove("bar");
    assert_eq!(
        validation_message(decrypt(&default_encryptor(), encrypted).await),
        "On Decrypt : Partition key 'bar' does not exist in item. Item contains these attributes : aws_dbe_foot aws_dbe_head encrypt nothing sign."
    );
}

#[tokio::test]
async fn decrypt_rejects_malformed_header_attribute() {
    let encrypted = encrypted_v1_item().await;
    let cases: [(Option<AttributeValue>, &str); 4] = [
        (None, "Header field, \"aws_dbe_head\", not in item."),
        (
            Some(s("text")),
            "Header field, \"aws_dbe_head\", not binary",
        ),
        (
            Some(AttributeValue::B(Blob::new(Vec::new()))),
            "Unexpected empty header field.",
        ),
        (
            Some(AttributeValue::B(Blob::new(vec![3]))),
            "Header attribute has unexpected version number",
        ),
    ];
    for (header, expected) in cases {
        let mut item = encrypted.clone();
        match header {
            Some(h) => item.insert(HEADER.to_owned(), h),
            None => item.remove(HEADER),
        };
        assert_eq!(
            serialization_message(decrypt(&default_encryptor(), item).await),
            expected
        );
    }
}

// --- Plaintext policies ---

fn encryptor_with(policy: PlaintextOverride) -> ItemEncryptor {
    encryptor_from(config_builder(v1_actions()).plaintext_override(policy))
}

#[tokio::test]
async fn default_policy_rejects_plaintext_items() {
    let err = decrypt(&default_encryptor(), v1_item()).await;
    assert_eq!(
        serialization_message(err),
        "Encrypted item missing expected header and footer attributes"
    );
    let err = decrypt(
        &encryptor_with(PlaintextOverride::ForbidPlaintextWriteForbidPlaintextRead),
        v1_item(),
    )
    .await;
    assert_eq!(
        serialization_message(err),
        "Encrypted item missing expected header and footer attributes"
    );
}

#[tokio::test]
async fn force_plaintext_write_writes_items_unchanged() {
    let encryptor = encryptor_with(PlaintextOverride::ForcePlaintextWriteAllowPlaintextRead);
    let out = encryptor
        .encrypt_item()
        .plaintext_item(v1_item())
        .send()
        .await
        .unwrap();
    assert!(out.parsed_header().is_none());
    assert_eq!(
        out.algorithm_suite_id(),
        AlgorithmSuiteId::AlgAes256GcmHkdfSha512CommitKeyEcdsaP384SymsigHmacSha384
    );
    assert_eq!(out.encrypted_item(), &v1_item());

    let suite = AlgorithmSuiteId::AlgAes256GcmHkdfSha512CommitKeySymsigHmacSha384;
    let configured = encryptor_from(
        config_builder(v1_actions())
            .plaintext_override(PlaintextOverride::ForcePlaintextWriteAllowPlaintextRead)
            .algorithm_suite_id(suite),
    );
    let out = configured
        .encrypt_item()
        .plaintext_item(v1_item())
        .send()
        .await
        .unwrap();
    assert_eq!(out.algorithm_suite_id(), suite);
}

#[tokio::test]
async fn force_plaintext_write_still_validates_the_item() {
    let encryptor = encryptor_with(PlaintextOverride::ForcePlaintextWriteAllowPlaintextRead);
    let mut input = v1_item();
    input.remove("bar");
    let msg = validation_message(encrypt(&encryptor, input).await);
    assert!(
        msg.starts_with("On Encrypt : Partition key 'bar' does not exist in item."),
        "{msg}"
    );
}

#[tokio::test]
async fn allow_plaintext_read_reads_plaintext_and_encrypted_items() {
    let ciphertext = encrypted_v1_item().await;
    for policy in [
        PlaintextOverride::ForcePlaintextWriteAllowPlaintextRead,
        PlaintextOverride::ForbidPlaintextWriteAllowPlaintextRead,
    ] {
        let encryptor = encryptor_with(policy);
        let out = encryptor
            .decrypt_item()
            .encrypted_item(v1_item())
            .send()
            .await
            .unwrap();
        assert!(out.parsed_header().is_none());
        assert_eq!(out.plaintext_item(), &v1_item());
        let out = encryptor
            .decrypt_item()
            .encrypted_item(ciphertext.clone())
            .send()
            .await
            .unwrap();
        assert!(out.parsed_header().is_some());
        assert_eq!(out.plaintext_item(), &v1_item());
    }
}

#[tokio::test]
async fn forbid_plaintext_write_allow_read_encrypts() {
    let encryptor = encryptor_with(PlaintextOverride::ForbidPlaintextWriteAllowPlaintextRead);
    let out = encrypt(&encryptor, v1_item()).await.unwrap();
    assert!(out.contains_key(HEADER) && out.contains_key(FOOTER));
    assert_ne!(out["encrypt"], v1_item()["encrypt"]);
}

#[tokio::test]
async fn allow_plaintext_read_still_verifies_items_with_a_footer_only() {
    let mut item = encrypted_v1_item().await;
    item.remove(HEADER);
    let encryptor = encryptor_with(PlaintextOverride::ForbidPlaintextWriteAllowPlaintextRead);
    assert_eq!(
        serialization_message(decrypt(&encryptor, item).await),
        "Header field, \"aws_dbe_head\", not in item."
    );
}

// --- Tampering ---

#[tokio::test]
async fn tampered_signed_attribute_fails() {
    let mut item = encrypted_v1_item().await;
    item.insert("sign".to_owned(), s("tampered"));
    let err = decrypt(&default_encryptor(), item).await.unwrap_err();
    assert!(matches!(err, Error::Cryptographic(_)), "{err:?}");
}

#[tokio::test]
async fn tampered_partition_key_fails() {
    let mut item = encrypted_v1_item().await;
    item.insert("bar".to_owned(), s("other"));
    let err = decrypt(&default_encryptor(), item).await.unwrap_err();
    assert!(matches!(err, Error::Cryptographic(_)), "{err:?}");
}

#[tokio::test]
async fn tampered_encrypted_attribute_fails() {
    let mut item = encrypted_v1_item().await;
    let mut ct = binary(&item, "encrypt");
    *ct.last_mut().unwrap() ^= 1;
    item.insert("encrypt".to_owned(), AttributeValue::B(Blob::new(ct)));
    let err = decrypt(&default_encryptor(), item).await.unwrap_err();
    assert!(matches!(err, Error::Cryptographic(_)), "{err:?}");
}

#[tokio::test]
async fn removed_signed_attribute_fails() {
    let mut item = encrypted_v1_item().await;
    item.remove("sign");
    assert_eq!(
        serialization_message(decrypt(&default_encryptor(), item).await),
        "Schema changed : something that was signed is now unsigned."
    );
}

#[tokio::test]
async fn added_signed_attribute_fails() {
    let mut item = encrypted_v1_item().await;
    item.insert("sign2".to_owned(), s("added"));
    assert_eq!(
        serialization_message(decrypt(&default_encryptor(), item).await),
        "Schema changed : something that was unsigned is now signed."
    );
}

#[tokio::test]
async fn tampered_header_or_footer_fails() {
    let encrypted = encrypted_v1_item().await;
    for field in [HEADER, FOOTER] {
        let mut bytes = binary(&encrypted, field);
        *bytes.last_mut().unwrap() ^= 1;
        let mut item = encrypted.clone();
        item.insert(field.to_owned(), AttributeValue::B(Blob::new(bytes)));
        let err = decrypt(&default_encryptor(), item).await.unwrap_err();
        assert!(matches!(err, Error::Cryptographic(_)), "{field}: {err:?}");
    }
}

#[tokio::test]
async fn unsigned_attribute_may_change() {
    let mut item = encrypted_v1_item().await;
    item.insert("nothing".to_owned(), s("changed"));
    let out = decrypt(&default_encryptor(), item).await.unwrap();
    let mut expected = v1_item();
    expected.insert("nothing".to_owned(), s("changed"));
    assert_eq!(out, expected);
}

#[tokio::test]
async fn wrong_wrapping_key_fails() {
    let other = encryptor_from(config_builder(v1_actions()).keyring(keyring_with_key(vec![1; 32])));
    let err = decrypt(&other, encrypted_v1_item().await)
        .await
        .unwrap_err();
    // The raw AES keyring finds its own data key, but the tag does not verify.
    assert!(matches!(err, Error::Cryptographic(_)), "{err:?}");
    assert!(!err.is_retryable());
}

// --- Keyring failures keep their variant ---

struct FailingKeyring;

#[async_trait]
impl Keyring for FailingKeyring {
    async fn on_encrypt(&self, _: OnEncryptInput) -> Result<OnEncryptOutput, MplError> {
        Err(MplError::invalid_materials("encrypt refused"))
    }

    async fn on_decrypt(&self, _: OnDecryptInput) -> Result<OnDecryptOutput, MplError> {
        Err(MplError::no_matching_data_key("decrypt refused"))
    }
}

#[tokio::test]
async fn keyring_errors_keep_their_variant() {
    let failing = encryptor_from(config_builder(v1_actions()).keyring(FailingKeyring));
    let err = encrypt(&failing, v1_item()).await.unwrap_err();
    assert!(matches!(err, Error::InvalidMaterials(_)), "{err:?}");
    let err = decrypt(&failing, encrypted_v1_item().await)
        .await
        .unwrap_err();
    assert!(matches!(err, Error::NoMatchingDataKey(_)), "{err:?}");
}
