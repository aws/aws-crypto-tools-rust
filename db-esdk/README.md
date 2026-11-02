# aws-db-esdk

A native Rust implementation of the AWS Database Encryption SDK for DynamoDB.

The AWS Database Encryption SDK encrypts and signs DynamoDB items on the client, before they are written.
Each item gets its own data key, protected by one or more wrapping keys from a _keyring_.
The SDK stores the encrypted data keys in the item, so you don't keep track of them yourself.

For each table, you choose what happens to each attribute:

| Action | Stored as | Covered by the signature |
|---|---|---|
| `EncryptAndSign` | ciphertext (binary) | yes |
| `SignAndIncludeInEncryptionContext` | plaintext | yes, and bound to the data key |
| `SignOnly` | plaintext | yes |
| `DoNothing` | plaintext | no |

Each encrypted item also gets two attributes:
`aws_dbe_head`, which holds the encrypted data keys,
and `aws_dbe_foot`, which holds the signatures.

The crate has two entry points:

- `aws_db_esdk::Client` has the same operations as `aws_sdk_dynamodb::Client`.
  It encrypts items on the way to DynamoDB, and verifies and decrypts them on the way back.
- `aws_db_esdk::ItemEncryptor` encrypts and decrypts one item at a time, with no call to DynamoDB,
  for example to decrypt an item from a DynamoDB stream.

Keyrings, cryptographic materials managers (CMMs), caches, and the branch key store
are in the `keyring`, `cmm`, `cmc`, and `key_store` modules.
They come from the Material Providers Library, which `aws_db_esdk::mpl` re-exports.

## Prerequisites

This crate is not on crates.io yet.
Build it from this repository, which also holds `aws-crypto-mpl` and the other crates it depends on.

Building needs:

- Rust and `cargo`
- a C/C++ compiler and CMake, for the default `aws-lc-sys` crypto backend
- Go, only for the `fips` feature, which builds the FIPS backend (`aws-lc-fips-sys`) from source

## Quickstart

Put an encrypted item into a table and get it back, with a raw AES keyring:

```rust
use std::collections::HashMap;

use aws_db_esdk::aws_sdk_dynamodb::types::AttributeValue;
use aws_db_esdk::keyring::RawAesKeyring;
use aws_db_esdk::types::{AesWrappingAlg, CryptoAction};
use aws_db_esdk::{TableConfig, aws_config, aws_sdk_dynamodb};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // For demonstration only.
    // A real application must load its wrapping key from a secure store, never hardcode it.
    let keyring = RawAesKeyring::builder()
        .key_namespace("my-key-namespace")
        .key_name("my-key-name")
        .wrapping_key(vec![0x01u8; 32])
        .wrapping_alg(AesWrappingAlg::AlgAes256GcmIv12Tag16)
        .build()?;

    // Every attribute you write needs an action.
    // The partition and sort keys must be `SignOnly`, since DynamoDB must read them.
    let table = TableConfig::builder()
        .partition_key_name("partition_key")
        .sort_key_name("sort_key")
        .attribute_actions_on_encrypt("partition_key", CryptoAction::SignOnly)
        .attribute_actions_on_encrypt("sort_key", CryptoAction::SignOnly)
        .attribute_actions_on_encrypt("secret", CryptoAction::EncryptAndSign)
        .keyring(keyring)
        .build()?;

    let sdk_config = aws_config::load_defaults(aws_config::BehaviorVersion::latest()).await;
    let ddb = aws_db_esdk::Client::builder()
        .ddb_client(aws_sdk_dynamodb::Client::new(&sdk_config))
        .table_encryption_configs("MyTable", table)
        .build()?;

    let item = HashMap::from([
        ("partition_key".to_string(), AttributeValue::S("id-1".into())),
        ("sort_key".to_string(), AttributeValue::N("0".into())),
        ("secret".to_string(), AttributeValue::S("encrypt and sign me!".into())),
    ]);
    ddb.put_item().table_name("MyTable").set_item(Some(item.clone())).send().await?;

    let key = HashMap::from([
        ("partition_key".to_string(), AttributeValue::S("id-1".into())),
        ("sort_key".to_string(), AttributeValue::N("0".into())),
    ]);
    let output = ddb
        .get_item()
        .table_name("MyTable")
        .set_key(Some(key))
        .consistent_read(true)
        .send()
        .await?;
    assert_eq!(output.item(), Some(&item));
    Ok(())
}
```

Requests for a table with no `TableConfig` pass through unchanged.

## Handling errors

Every operation returns one `aws_db_esdk::Error`.
Decide what to do from it in two steps:

1. If `is_retryable()` is true, the same call can succeed later.
2. Otherwise, match on the variant.
   For example, `NoMatchingDataKey` means that no keyring you gave can decrypt the item,
   and `Cryptographic` or `Serialization` means that the item was changed or is not an encrypted item.

`resource()`, `service()`, `code()`, and `request_id()` say which resource and AWS call failed.
When DynamoDB itself failed, `as_service_error()` returns DynamoDB's own error,
so code written for `aws_sdk_dynamodb` can still match it.
Error messages are for people and logs.
Their text can change in any release, so never match on them.
The `handling_errors` example shows each step.

## Searchable encryption

An encrypted attribute can't be queried directly.
A _beacon_ is a truncated HMAC of an attribute's plaintext that DynamoDB can index and query.
Configure beacons with `TableConfig::builder().search(..)`, from the types in `aws_db_esdk::search`.
The client writes each beacon to an attribute named `aws_dbe_b_<beacon>`; put your index on that attribute.
Then query the encrypted attribute by its own name, with the usual `query` and `scan` operations.
The client rewrites the query to use the beacon.
The `*_searchable_encryption` examples show each kind of beacon.

## Examples

Runnable examples live under [`examples/`](examples/).
Run one with `cargo run --example <name>`:

| Example | Shows | Needs AWS |
|---|---|---|
| `item_encryptor` | encrypt and decrypt an item with no call to DynamoDB | no |
| `custom_keyring` | implement your own keyring | no |
| `set_algorithm_suite` | encrypt with a non-default algorithm suite | no |
| `basic_put_get` | put and get an encrypted item with a raw AES keyring | DynamoDB |
| `multi_put_get` | batch and transaction reads and writes | DynamoDB |
| `custom_cmm` | implement your own cryptographic materials manager (CMM) | DynamoDB |
| `hierarchical_keyring` | put and get an item with a hierarchical keyring | KMS + DynamoDB |
| `get_encrypted_data_key_description` | list the keys that protect an item, without decrypting it | DynamoDB |
| `create_keystore_key` | create a branch key | KMS + DynamoDB |
| `rotate_branch_key` | create a branch key and rotate it | KMS + DynamoDB |
| `branch_key_supplier` | pick a branch key per tenant from each item's primary key | KMS + DynamoDB |
| `shared_storm_tracking_cache` | share one cache across two hierarchical keyrings | KMS + DynamoDB |
| `per_request_credentials` | call AWS KMS with credentials issued for one request | KMS + DynamoDB |
| `handling_errors` | handle the errors that the SDK returns | KMS + DynamoDB |
| `basic_searchable_encryption` | query an encrypted attribute through a standard beacon | KMS + DynamoDB |
| `compound_beacon_searchable_encryption` | query two encrypted attributes through one compound beacon | KMS + DynamoDB |
| `virtual_beacon_searchable_encryption` | query a beacon over a virtual field | KMS + DynamoDB |
| `beacon_styles_searchable_encryption` | the beacon styles: shared, set, and part-only beacons | KMS + DynamoDB |
| `complex_searchable_encryption` | a full table design with many beacons and 23 queries | KMS + DynamoDB |
| `migration_plaintext_to_awsdbe` | move a plaintext table to encrypted items, step by step | KMS + DynamoDB |

The examples that need AWS also need credentials, and the tables, KMS key, and key store named in each example's comments.
`get_encrypted_data_key_description` reads the item that `hierarchical_keyring` writes, so run `hierarchical_keyring` first.

## Cargo features

All of these except `fips` are on by default.

| Feature | What it adds | Without it |
|---|---|---|
| `kms` | the AWS KMS SDK, for the KMS keyrings and the built-in key store | use keyrings and a key store that don't call KMS |
| `default-aws-sdk-clients` | keyrings and the key store create their own KMS and DynamoDB clients from your AWS credentials and region (this pulls in `aws-config` and the AWS SDK's HTTPS and TLS client) | create the clients yourself and pass them in |
| `rt-tokio` | the tokio-based caches, which the hierarchical keyring uses by default | pass the hierarchical keyring a `cache`, such as `LocalCmc` |
| `aws-lc-sys` | the default crypto backend, AWS-LC | turn on `fips` instead |
| `fips` (off by default) | AWS-LC's FIPS module as the crypto backend; takes precedence over `aws-lc-sys` | |

To pick features, turn off the defaults and list the ones you want, with a crypto backend:

```toml
aws-db-esdk = { version = "0.1", default-features = false, features = ["aws-lc-sys", "kms", "rt-tokio"] }
```

## Development

Run these in the `db-esdk/` directory:

```bash
cargo build              # build the library
cargo build --examples   # build every example
cargo test               # run the test suite
make test                # run the test suite across feature combinations
make clippy              # lint across feature combinations
make examples            # run every example
make examples LOCAL_ONLY=--local-only   # run only the examples that don't need AWS
```

## Security

If you discover a potential security issue in this project we ask that you notify
AWS/Amazon Security via our
[vulnerability reporting page](http://aws.amazon.com/security/vulnerability-reporting/).
Please **do not** create a public GitHub issue.

## License

This project is licensed under the Apache-2.0 License.
