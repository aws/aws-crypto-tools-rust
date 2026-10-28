// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

//! `ItemEncryptor::decrypt_item`: its inputs, what it passes to the CMM, and its output.

mod item_encryptor_support;

use std::collections::BTreeSet;

use aws_db_esdk::aws_sdk_dynamodb::types::AttributeValue;
use aws_db_esdk::cmm::{
    Cmm, DecryptMaterialsInput, DecryptMaterialsOutput, GetEncryptionMaterialsInput,
    GetEncryptionMaterialsOutput,
};
use aws_db_esdk::mpl::Error as MplError;
use aws_db_esdk::mpl::types::DecryptionMaterials;
use aws_db_esdk::types::{CryptoAction, PlaintextOverride};
use aws_db_esdk::{Error, ItemEncryptor, ItemEncryptorBuilder, async_trait};
use item_encryptor_support::*;

async fn encrypt(encryptor: &ItemEncryptor, input: Item) -> Item {
    encryptor
        .encrypt_item()
        .plaintext_item(input)
        .send()
        .await
        .unwrap()
        .into_encrypted_item()
}

async fn decrypt(encryptor: &ItemEncryptor, input: Item) -> Result<Item, Error> {
    encryptor
        .decrypt_item()
        .encrypted_item(input)
        .send()
        .await
        .map(|o| o.into_plaintext_item())
}

#[tokio::test]
async fn decrypt_rejects_missing_sort_key() {
    let encryptor = encryptor_from(
        config_builder(v1_actions())
            .sort_key_name("sort")
            .attribute_actions_on_encrypt("sort", CryptoAction::SignOnly),
    );
    let mut input = v1_item();
    input.insert("sort".to_owned(), AttributeValue::N("7".to_owned()));
    let mut encrypted = encrypt(&encryptor, input).await;
    encrypted.remove("sort");
    let result = encryptor
        .decrypt_item()
        .encrypted_item(encrypted)
        .send()
        .await;
    let Err(Error::Validation(e)) = result else {
        panic!("expected a Validation error, got {result:?}");
    };

    //= spec/dynamodb-encryption-client/decrypt-item.md#input-dynamodb-item
    //= type=test
    //# If the [DynamoDB Item Encryptor](./ddb-item-encryptor.md)
    //# has a [DynamoDB Sort Key Name](./ddb-table-encryption-config.md#dynamodb-sort-key-name) configured,
    //# this item MUST include an Attribute with that name.
    assert_eq!(
        e.message(),
        "On Decrypt : Sort key 'sort' does not exist in item. Item contains these attributes : aws_dbe_foot aws_dbe_head bar encrypt nothing sign."
    );
}

#[tokio::test]
async fn decrypt_outputs_the_plaintext_item() {
    let encryptor = default_encryptor();
    let encrypted = encrypt(&encryptor, v1_item()).await;
    assert_ne!(encrypted["encrypt"], v1_item()["encrypt"]);
    let out = encryptor
        .decrypt_item()
        .encrypted_item(encrypted)
        .send()
        .await
        .unwrap();

    //= spec/dynamodb-encryption-client/decrypt-item.md#output
    //= type=test
    //= reason=The input's encrypt attribute was ciphertext, so equality shows the output is the decryption
    //# This operation MUST output the following:
    assert_eq!(out.plaintext_item(), &v1_item());
}

#[tokio::test]
async fn decrypt_passes_the_base_context() {
    let spy = SpyCmm::new();
    let encryptor = spy.encryptor();
    let encrypted = encrypt(&encryptor, v1_item()).await;
    encryptor
        .decrypt_item()
        .encrypted_item(encrypted)
        .send()
        .await
        .unwrap();
    let reproduced = spy.last_decrypt().reproduced_encryption_context().cloned();

    //= spec/dynamodb-encryption-client/decrypt-item.md#behavior
    //= type=test
    //# - Encryption Context MUST be the input Item's [DynamoDB Item Base Context](./encrypt-item.md#dynamodb-item-base-context).
    assert_eq!(reproduced.as_ref().map(to_map), Some(v1_base_context()));
}

/// Forwards to a [`SpyCmm`], but drops `aws-crypto-attr.bar` from the decryption materials' context.
#[derive(Clone)]
struct DroppingCmm(SpyCmm);

#[async_trait]
impl Cmm for DroppingCmm {
    async fn get_encryption_materials(
        &self,
        input: GetEncryptionMaterialsInput,
    ) -> Result<GetEncryptionMaterialsOutput, MplError> {
        self.0.get_encryption_materials(input).await
    }

    async fn decrypt_materials(
        &self,
        input: DecryptMaterialsInput,
    ) -> Result<DecryptMaterialsOutput, MplError> {
        let mat = self
            .0
            .decrypt_materials(input)
            .await?
            .into_decryption_materials();
        let mut ec = mat.encryption_context().clone();
        ec.remove("aws-crypto-attr.bar");
        let mut builder = DecryptionMaterials::builder()
            .algorithm_suite_id(mat.algorithm_suite_id())
            .encryption_context(ec)
            .set_verification_key(mat.verification_key().cloned())
            .set_symmetric_signing_key(mat.symmetric_signing_key().cloned());
        if let Some(key) = mat.plaintext_data_key() {
            builder = builder.plaintext_data_key(key.clone());
        }
        DecryptMaterialsOutput::builder()
            .decryption_materials(builder.build()?)
            .build()
    }
}

#[tokio::test]
async fn decrypt_wraps_the_cmm_in_a_required_context_cmm() {
    let spy = SpyCmm::new();
    let encrypted = encrypt(&spy.encryptor(), v1_item()).await;
    let dropping = encryptor_from(
        config_builder(v1_actions())
            .set_keyring(None)
            .cmm(DroppingCmm(spy.clone())),
    );
    let err = dropping
        .decrypt_item()
        .encrypted_item(encrypted)
        .send()
        .await
        .unwrap_err();

    //= spec/dynamodb-encryption-client/decrypt-item.md#behavior
    //= type=test
    //= reason=Only the required encryption context CMM rejects materials that lost a base context key
    //# This operation MUST create a
    //# [Required Encryption Context CMM](https://github.com/awslabs/private-aws-encryption-sdk-specification-staging/blob/dafny-verified/framework/required-encryption-context-cmm.md)
    //# with the following inputs:
    //
    //= spec/dynamodb-encryption-client/decrypt-item.md#behavior
    //= type=test
    //= reason=The configured CMM's materials were checked by the required context CMM, so it sits underneath
    //# - CMM MUST be the CMM constructed above.
    assert!(matches!(err, Error::InvalidMaterials(_)), "{err:?}");
    let source = std::error::Error::source(&err).map(ToString::to_string);
    assert!(
        source
            .as_deref()
            .is_some_and(|s| s.contains("Final encryption context missing required keys.")),
        "{err:?}"
    );
    let required: BTreeSet<String> = v1_base_context().into_keys().collect();
    assert_eq!(
        spy.last_decrypt()
            .reproduced_encryption_context()
            .map(|ec| ec.keys().map(str::to_owned).collect::<BTreeSet<_>>()),
        Some(required)
    );
}

#[tokio::test]
async fn decrypt_parsed_header_matches_the_stored_header() {
    let encryptor = default_encryptor();
    let encrypted = encrypt(&encryptor, v1_item()).await;
    let AttributeValue::B(head) = &encrypted[HEADER] else {
        panic!("header not binary");
    };
    let stored: Vec<String> = aws_db_esdk::describe_header_encrypted_data_keys(head.as_ref())
        .unwrap()
        .iter()
        .map(|d| d.key_provider_id().to_owned())
        .collect();
    let out = encryptor
        .decrypt_item()
        .encrypted_item(encrypted.clone())
        .send()
        .await
        .unwrap();
    let header = out.parsed_header().unwrap();
    let parsed: Vec<String> = header
        .encrypted_data_keys()
        .iter()
        .map(|k| k.key_provider_id().to_owned())
        .collect();

    //= spec/dynamodb-encryption-client/decrypt-item.md#behavior
    //= type=test
    //# The output MUST also include a [Parsed Header](#parsed-header) that contains
    //# data that was serialized into the header included in the output DynamoDb Item.
    assert_eq!(parsed, stored);
    let stored_keys: Vec<&str> = header.stored_encryption_context().keys().collect();
    assert_eq!(stored_keys, ["aws-crypto-public-key"]);
}

#[tokio::test]
async fn decrypt_parsed_header_contains_every_value() {
    let encryptor = default_encryptor();
    let encrypted = encrypt(&encryptor, v1_item()).await;
    let out = encryptor
        .decrypt_item()
        .encrypted_item(encrypted)
        .send()
        .await
        .unwrap();
    let header = out.parsed_header().unwrap();
    let mut full = v1_base_context();
    full.insert(
        "aws-crypto-public-key".to_owned(),
        header
            .stored_encryption_context()
            .get("aws-crypto-public-key")
            .unwrap()
            .to_owned(),
    );

    //= spec/dynamodb-encryption-client/decrypt-item.md#parsed-header
    //= type=test
    //# This structure MUST contain the following values,
    //# representing the deserialized form of the header of the input encrypted structure:
    assert_eq!(header.algorithm_suite_id(), DEFAULT_SUITE);
    assert_eq!(
        header.attribute_actions_on_encrypt(),
        &actions([
            ("bar", CryptoAction::SignOnly),
            ("encrypt", CryptoAction::EncryptAndSign),
            ("sign", CryptoAction::SignOnly),
        ])
    );
    assert_eq!(header.encrypted_data_keys().len(), 1);
    assert_eq!(header.encrypted_data_keys()[0].key_provider_id(), "foo");
    assert_eq!(
        header
            .stored_encryption_context()
            .keys()
            .collect::<Vec<_>>(),
        ["aws-crypto-public-key"]
    );
    assert_eq!(to_map(header.encryption_context()), full);
    assert_eq!(header.selector_context(), &item([("bar", s("key"))]));
}

#[tokio::test]
async fn decrypt_uses_the_v2_context_for_a_version_2_header() {
    let input = item([("bar", s("key")), ("encrypt", s("text")), ("sign", s("x"))]);
    let encrypted = encrypt(&encryptor_from(config_builder(v2_actions())), input.clone()).await;
    let AttributeValue::B(head) = &encrypted[HEADER] else {
        panic!("header not binary");
    };
    assert_eq!(head.as_ref()[0], 2);
    // The decrypting configuration is version 1.
    let out = default_encryptor()
        .decrypt_item()
        .encrypted_item(encrypted)
        .send()
        .await
        .unwrap();
    let ec = out.parsed_header().unwrap().encryption_context();

    //= spec/dynamodb-encryption-client/decrypt-item.md#dynamodb-item-base-context
    //= type=test
    //= reason=The decrypting config is version 1, so success shows the header's version 2 chose the context
    //# If the Version Number is 2, then the base context MUST be the [version 2](./encrypt-item.md#dynamodb-item-base-context-version-2) context.
    assert_eq!(out.plaintext_item(), &input);
    assert_eq!(ec.get("aws-crypto-attr.bar"), Some("key"));
    // A version 2 item's selector context names the table and key attributes.
    assert_eq!(
        out.parsed_header().unwrap().selector_context(),
        &item([
            ("bar", s("key")),
            ("sign", s("x")),
            ("aws_dbe_table_name", s("foo")),
            ("aws_dbe_partition_name", s("bar")),
        ])
    );
}

#[tokio::test]
async fn decrypt_uses_the_v1_context_for_a_version_1_header() {
    let encrypted = encrypt(&default_encryptor(), v1_item()).await;
    let AttributeValue::B(head) = &encrypted[HEADER] else {
        panic!("header not binary");
    };
    assert_eq!(head.as_ref()[0], 1);
    // The decrypting configuration is version 2.
    let out = encryptor_from(config_builder(v2_actions()))
        .decrypt_item()
        .encrypted_item(encrypted)
        .send()
        .await
        .unwrap();
    let ec = out.parsed_header().unwrap().encryption_context();

    //= spec/dynamodb-encryption-client/decrypt-item.md#dynamodb-item-base-context
    //= type=test
    //= reason=The decrypting config is version 2, so success shows the header's version 1 chose the context
    //# If the Version Number is 1, the base context MUST be the [version 1](./encrypt-item.md#dynamodb-item-base-context-version-1) context.
    assert_eq!(out.plaintext_item(), &v1_item());
    assert_eq!(ec.get("aws-crypto-attr.bar"), Some("AAFrZXk="));
}

fn build_message(builder: ItemEncryptorBuilder) -> String {
    match builder.build() {
        Err(Error::Validation(e)) => e.message().to_owned(),
        other => panic!("expected a Validation error, got {other:?}"),
    }
}

#[test]
fn signed_unauthenticated_attribute_is_rejected() {
    let named = config_builder(v1_actions())
        .attribute_actions_on_encrypt("nothing", CryptoAction::SignOnly)
        .build()
        .unwrap();

    //= spec/dynamodb-encryption-client/decrypt-item.md#signature-scope
    //= type=test
    //# If an Authenticate Action other than DO_NOTHING is configured for an attribute name included in [Unauthenticated Attributes](./ddb-table-encryption-config.md#unauthenticated-attributes)
    //# or beginning with the prefix specified in [Unauthenticated Attribute Prefix](./ddb-table-encryption-config.md#unauthenticated-attribute-prefix),
    //# this operation MUST yield an error.
    assert_eq!(
        build_message(ItemEncryptor::builder().table(TABLE, named)),
        "Attribute nothing is configured as SIGN_ONLY but it is also in unauthenticatedAttributes."
    );
    let prefixed = config_builder(v1_actions())
        .allowed_unsigned_attribute_prefix(":")
        .attribute_actions_on_encrypt(":x", CryptoAction::SignOnly)
        .build()
        .unwrap();
    assert_eq!(
        build_message(ItemEncryptor::builder().table(TABLE, prefixed)),
        "Attribute :x is configured as SIGN_ONLY but it also begins with the unauthenticatedPrefix."
    );
}

#[tokio::test]
async fn allow_plaintext_read_still_verifies_items_with_a_footer_only() {
    let mut item = encrypt(&default_encryptor(), v1_item()).await;
    item.remove(HEADER);
    let encryptor = encryptor_from(
        config_builder(v1_actions())
            .plaintext_override(PlaintextOverride::ForbidPlaintextWriteAllowPlaintextRead),
    );
    let result = decrypt(&encryptor, item).await;

    //= spec/dynamodb-encryption-client/decrypt-item.md#determining-plaintext-items
    //= type=test
    //# An item MUST be determined to be plaintext if it does not contain
    //# attributes with the names "aws_dbe_head" and "aws_dbe_foot".
    assert!(
        matches!(&result, Err(Error::Serialization(e)) if e.message() == "the item has no aws_dbe_head attribute"),
        "{result:?}"
    );
}

#[tokio::test]
async fn tampered_partition_key_fails() {
    let mut item = encrypt(&default_encryptor(), v1_item()).await;
    item.insert("bar".to_owned(), s("other"));
    let err = decrypt(&default_encryptor(), item).await.unwrap_err();

    //= spec/dynamodb-encryption-client/decrypt-item.md#behavior
    //= type=test
    //= reason=The schema signs the partition key, so a changed value fails verification
    //# - Authenticate Schema MUST be a [Authenticate Schema](../structured-encryption/structures.md#crypto-schema)
    //# built with the following requirements:
    assert!(matches!(err, Error::Cryptographic(_)), "{err:?}");
}
