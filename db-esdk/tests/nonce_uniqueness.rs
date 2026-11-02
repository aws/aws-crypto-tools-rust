// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

//! Nonce and IV uniqueness, observed on encrypted items.
//!
//! The encryptor encrypts each field with AES-256-GCM,
//! under a key and nonce derived from the data key, the item's message ID, and the field's position.
//! A repeated key and nonce pair breaks AES-GCM, so these tests check that:
//! - every encrypt draws a fresh random message ID
//! - two fields of one item never share a key and nonce
//! - the keyring wraps each data key under a fresh IV

mod item_encryptor_support;

use std::collections::HashSet;

use aws_db_esdk::aws_sdk_dynamodb::types::AttributeValue;
use aws_db_esdk::types::CryptoAction;
use item_encryptor_support::{
    Item, actions, config_builder, default_encryptor, encryptor_from, item, s, v1_item,
};

const ITEMS: usize = 500;
const HEADER: &str = "aws_dbe_head";
/// Raw AES keyring provider info ends with the 12-byte wrapping IV.
const WRAP_IV_LEN: usize = 12;

fn binary(item: &Item, name: &str) -> Vec<u8> {
    match &item[name] {
        AttributeValue::B(b) => b.as_ref().to_vec(),
        other => panic!("{name} is not binary: {other:?}"),
    }
}

/// The 32-byte message ID, which follows the 1-byte version and the 1-byte flavor in the header.
fn message_id(encrypted: &Item) -> Vec<u8> {
    binary(encrypted, HEADER)[2..34].to_vec()
}

#[tokio::test]
async fn repeated_encrypts_of_one_item_never_repeat_a_nonce() {
    let encryptor = default_encryptor();
    let input = v1_item();
    let mut ids = HashSet::new();
    let mut ciphertexts = HashSet::new();
    let mut wrap_ivs = HashSet::new();
    let mut data_keys = HashSet::new();
    for _ in 0..ITEMS {
        let out = encryptor
            .encrypt_item()
            .plaintext_item(input.clone())
            .send()
            .await
            .unwrap();
        let edks = out.parsed_header().unwrap().encrypted_data_keys().to_vec();
        let encrypted = out.into_encrypted_item();

        let id = message_id(&encrypted);
        assert_eq!(id.len(), 32);
        assert_ne!(id, vec![0u8; 32], "message ID must be random, not zero");
        ids.insert(id);
        ciphertexts.insert(binary(&encrypted, "encrypt"));

        assert_eq!(edks.len(), 1);
        let info = edks[0].key_provider_info();
        wrap_ivs.insert(info[info.len() - WRAP_IV_LEN..].to_vec());
        data_keys.insert(edks[0].ciphertext().to_vec());
    }
    assert_eq!(ids.len(), ITEMS, "every encrypt draws a fresh message ID");
    assert_eq!(
        ciphertexts.len(),
        ITEMS,
        "the same field never encrypts the same twice"
    );
    assert_eq!(
        wrap_ivs.len(),
        ITEMS,
        "every data key is wrapped under a fresh IV"
    );
    assert_eq!(
        data_keys.len(),
        ITEMS,
        "every encrypt uses a fresh data key"
    );
}

#[tokio::test]
async fn equal_fields_of_one_item_get_different_keys_and_nonces() {
    // Ten encrypted fields with the same value: equal ciphertexts would mean a shared key and nonce.
    let names: Vec<String> = (0..10).map(|n| format!("f{n}")).collect();
    let mut acts = actions([("bar", CryptoAction::SignOnly)]);
    let mut input = item([("bar", s("key"))]);
    for name in &names {
        acts.insert(name.clone(), CryptoAction::EncryptAndSign);
        input.insert(name.clone(), s("same value"));
    }
    let encryptor = encryptor_from(config_builder(acts));

    let encrypted = encryptor
        .encrypt_item()
        .plaintext_item(input.clone())
        .send()
        .await
        .unwrap()
        .into_encrypted_item();
    let ciphertexts: HashSet<Vec<u8>> = names.iter().map(|n| binary(&encrypted, n)).collect();
    assert_eq!(
        ciphertexts.len(),
        names.len(),
        "each field has its own key and nonce"
    );

    let decrypted = encryptor
        .decrypt_item()
        .encrypted_item(encrypted)
        .send()
        .await
        .unwrap();
    assert_eq!(decrypted.plaintext_item(), &input);
}
