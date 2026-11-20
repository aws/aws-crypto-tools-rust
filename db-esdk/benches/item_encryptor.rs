// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

//! Encrypt and decrypt throughput of `ItemEncryptor`, for a small and a large item,
//! with the symmetric-only and the ECDSA-signing algorithm suite.

use std::collections::HashMap;

use aws_db_esdk::aws_sdk_dynamodb::primitives::Blob;
use aws_db_esdk::aws_sdk_dynamodb::types::AttributeValue;
use aws_db_esdk::keyring::RawAesKeyring;
use aws_db_esdk::types::{AesWrappingAlg, AlgorithmSuiteId, CryptoAction};
use aws_db_esdk::{ItemEncryptor, TableConfig};
use criterion::{BatchSize, BenchmarkId, Criterion, Throughput, criterion_group, criterion_main};

type Item = HashMap<String, AttributeValue>;

const SUITES: [(&str, AlgorithmSuiteId); 2] = [
    (
        "symsig",
        AlgorithmSuiteId::AlgAes256GcmHkdfSha512CommitKeySymsigHmacSha384,
    ),
    (
        "ecdsa",
        AlgorithmSuiteId::AlgAes256GcmHkdfSha512CommitKeyEcdsaP384SymsigHmacSha384,
    ),
];

fn keyring() -> RawAesKeyring {
    RawAesKeyring::builder()
        .key_namespace("bench")
        .key_name("key")
        .wrapping_key(vec![7; 32])
        .wrapping_alg(AesWrappingAlg::AlgAes256GcmIv12Tag16)
        .build()
        .unwrap()
}

/// An item with a partition key and `attrs` more attributes, most of them encrypted.
/// The attributes cycle through string, binary, list, and map values,
/// so the benchmark serializes each kind of value.
fn make_item(attrs: usize) -> (Item, HashMap<String, CryptoAction>) {
    let mut item = Item::new();
    let mut actions = HashMap::new();
    item.insert("pk".to_owned(), AttributeValue::S("partition".to_owned()));
    actions.insert("pk".to_owned(), CryptoAction::SignOnly);
    for i in 0..attrs {
        let value = match i % 4 {
            0 => AttributeValue::S("x".repeat(64)),
            1 => AttributeValue::B(Blob::new(vec![i as u8; 256])),
            2 => AttributeValue::L((0..8).map(|n| AttributeValue::N(n.to_string())).collect()),
            _ => AttributeValue::M(
                (0..8)
                    .map(|n| (format!("k{n}"), AttributeValue::S(format!("v{n}"))))
                    .collect(),
            ),
        };
        let name = format!("attr{i:03}");
        let action = if i % 5 == 0 {
            CryptoAction::SignOnly
        } else {
            CryptoAction::EncryptAndSign
        };
        item.insert(name.clone(), value);
        actions.insert(name, action);
    }
    (item, actions)
}

fn encryptor(actions: HashMap<String, CryptoAction>, suite: AlgorithmSuiteId) -> ItemEncryptor {
    let config = TableConfig::builder()
        .partition_key_name("pk")
        .set_attribute_actions_on_encrypt(Some(actions))
        .algorithm_suite_id(suite)
        .keyring(keyring())
        .build()
        .unwrap();
    ItemEncryptor::builder()
        .table("bench", config)
        .build()
        .unwrap()
}

fn bench(c: &mut Criterion) {
    let rt = tokio::runtime::Builder::new_current_thread()
        .build()
        .unwrap();
    for (size_name, attrs) in [("small", 4), ("large", 200)] {
        let (item, actions) = make_item(attrs);
        let mut group = c.benchmark_group(format!("item_{size_name}"));
        group.throughput(Throughput::Elements(1));
        for (suite_name, suite) in SUITES {
            let enc = encryptor(actions.clone(), suite);
            group.bench_function(BenchmarkId::new("encrypt", suite_name), |b| {
                b.iter_batched(
                    || item.clone(),
                    |item| {
                        rt.block_on(enc.encrypt_item().plaintext_item(item).send())
                            .unwrap()
                    },
                    BatchSize::SmallInput,
                )
            });
            let ciphertext = rt
                .block_on(enc.encrypt_item().plaintext_item(item.clone()).send())
                .unwrap()
                .into_encrypted_item();
            group.bench_function(BenchmarkId::new("decrypt", suite_name), |b| {
                b.iter_batched(
                    || ciphertext.clone(),
                    |ciphertext| {
                        rt.block_on(enc.decrypt_item().encrypted_item(ciphertext).send())
                            .unwrap()
                    },
                    BatchSize::SmallInput,
                )
            });
        }
        group.finish();
    }
}

criterion_group!(benches, bench);
criterion_main!(benches);
