// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

//! Item encrypt/decrypt and `Client` put/get run concurrently across threads and tasks.
//!
//! One `ItemEncryptor` or `Client` is shared by every thread, the way a service shares
//! one client. Each encrypt must still draw its own message ID: two items with the
//! same message ID and data key get the same field keys and AES-GCM nonces.

mod client_support;
mod item_encryptor_support;

use std::collections::HashSet;
use std::sync::mpsc;
use std::time::Duration;

use aws_db_esdk::aws_sdk_dynamodb::types::AttributeValue;
use aws_db_esdk::{Client, ItemEncryptor};
use item_encryptor_support::{Item, default_encryptor, item, s};

const THREADS: usize = 8;
const ITERS_PER_THREAD: usize = 24;
const HEADER: &str = "aws_dbe_head";

/// The 32-byte message ID: header version (1) + flavor (1) + message ID (32).
fn message_id(encrypted: &Item) -> Vec<u8> {
    match &encrypted[HEADER] {
        AttributeValue::B(b) => b.as_ref()[2..34].to_vec(),
        other => panic!("header is not binary: {other:?}"),
    }
}

fn plaintext(t: usize, i: usize) -> Item {
    item([
        ("bar", s(&format!("key-{t}-{i}"))),
        ("encrypt", s(&format!("secret {t} {i}"))),
        ("sign", s("bar")),
        ("nothing", s("baz")),
    ])
}

/// Encrypt and decrypt `plaintext(t, i)` with `encryptor`; return the message ID.
async fn item_round_trip(encryptor: &ItemEncryptor, t: usize, i: usize) -> Vec<u8> {
    let input = plaintext(t, i);
    let encrypted = encryptor
        .encrypt_item()
        .plaintext_item(input.clone())
        .send()
        .await
        .unwrap()
        .into_encrypted_item();
    let id = message_id(&encrypted);
    let decrypted = encryptor
        .decrypt_item()
        .encrypted_item(encrypted)
        .send()
        .await
        .unwrap();
    assert_eq!(
        decrypted.plaintext_item(),
        &input,
        "round trip must return the item"
    );
    id
}

/// Run `f` on its own thread and fail if it does not finish within `secs`.
fn assert_completes_within(secs: u64, f: impl FnOnce() + Send + 'static) {
    let (tx, rx) = mpsc::channel();
    let worker = std::thread::spawn(move || {
        f();
        let _ = tx.send(());
    });
    if rx.recv_timeout(Duration::from_secs(secs)) == Err(mpsc::RecvTimeoutError::Timeout) {
        panic!("concurrent operations did not finish within {secs}s: likely deadlock");
    }
    // On a worker panic, recv returns Disconnected and this join re-raises the panic.
    worker.join().unwrap();
}

#[test]
fn shared_types_are_send_and_sync() {
    fn assert_send_sync<T: Send + Sync + 'static>() {}
    assert_send_sync::<ItemEncryptor>();
    assert_send_sync::<Client>();
    assert_send_sync::<aws_db_esdk::Error>();
}

#[test]
fn one_item_encryptor_shared_by_threads_round_trips_with_unique_message_ids() {
    let encryptor = default_encryptor();
    let handles: Vec<_> = (0..THREADS)
        .map(|t| {
            let encryptor = encryptor.clone();
            std::thread::spawn(move || {
                let rt = tokio::runtime::Builder::new_current_thread()
                    .enable_all()
                    .build()
                    .unwrap();
                rt.block_on(async {
                    let mut ids = Vec::with_capacity(ITERS_PER_THREAD);
                    for i in 0..ITERS_PER_THREAD {
                        ids.push(item_round_trip(&encryptor, t, i).await);
                    }
                    ids
                })
            })
        })
        .collect();

    let ids: Vec<Vec<u8>> = handles
        .into_iter()
        .flat_map(|h| h.join().expect("worker thread must not panic"))
        .collect();
    assert_eq!(ids.len(), THREADS * ITERS_PER_THREAD);
    let unique: HashSet<&Vec<u8>> = ids.iter().collect();
    assert_eq!(
        unique.len(),
        ids.len(),
        "message IDs must be unique across concurrent encrypts"
    );
}

#[test]
fn more_tasks_than_worker_threads_completes() {
    assert_completes_within(120, || {
        let rt = tokio::runtime::Builder::new_multi_thread()
            .worker_threads(2)
            .enable_all()
            .build()
            .unwrap();
        rt.block_on(async {
            let encryptor = default_encryptor();
            let mut set = tokio::task::JoinSet::new();
            for t in 0..64 {
                let encryptor = encryptor.clone();
                set.spawn(async move {
                    for i in 0..4 {
                        item_round_trip(&encryptor, t, i).await;
                    }
                });
            }
            while let Some(res) = set.join_next().await {
                res.expect("task must not panic");
            }
        });
    });
}

#[test]
fn one_client_shared_by_tasks_puts_and_gets_every_item() {
    assert_completes_within(120, || {
        let rt = tokio::runtime::Builder::new_multi_thread()
            .worker_threads(4)
            .enable_all()
            .build()
            .unwrap();
        rt.block_on(async {
            let (fake, client) = client_support::setup();
            let mut set = tokio::task::JoinSet::new();
            for t in 0..THREADS {
                let client = client.clone();
                set.spawn(async move {
                    for i in 0..ITERS_PER_THREAD {
                        let (bar, sign) = (format!("bar{t}"), format!("sign{i}"));
                        let item = client_support::full_item(&bar, &sign);
                        client
                            .put_item()
                            .table_name(client_support::TABLE)
                            .set_item(Some(item.clone()))
                            .send()
                            .await
                            .expect("the put succeeds");
                        let got = client
                            .get_item()
                            .table_name(client_support::TABLE)
                            .set_key(Some(client_support::key(&bar, &sign)))
                            .send()
                            .await
                            .expect("the get succeeds");
                        assert_eq!(got.item(), Some(&item), "get returns the put item");
                    }
                });
            }
            while let Some(res) = set.join_next().await {
                res.expect("task must not panic");
            }

            // Every stored item is encrypted under its own message ID.
            let stored = fake.items(client_support::TABLE);
            assert_eq!(stored.len(), THREADS * ITERS_PER_THREAD);
            let ids: HashSet<Vec<u8>> = stored.iter().map(message_id).collect();
            assert_eq!(ids.len(), stored.len(), "message IDs must be unique");
        });
    });
}
