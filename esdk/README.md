# aws-esdk

A native Rust implementation of the AWS Encryption SDK.

The AWS Encryption SDK is a client-side encryption library.
It encrypts your data with a data key, and encrypts that data key with one or more wrapping keys from a _keyring_.
The encrypted message stores the encrypted data keys next to the ciphertext, so you don't keep track of them yourself.

Every operation starts from a [`Client`](#the-client):
`encrypt` and `decrypt` for data in memory,
and `encrypt_stream` and `decrypt_stream` for data too large to hold in memory.
Keyrings, cryptographic materials managers (CMMs), and caches are in the `keyring`, `cmm`, and `cmc` modules.
They come from the Material Providers Library, which `aws_esdk::mpl` re-exports.

## Prerequisites

This version of `aws-esdk` is not on crates.io yet.
The `aws-esdk` 1.x on crates.io is a different implementation with a different API.
Build this one from this repository, which also holds `aws-crypto-mpl` and the other crates it depends on.

Building needs:

- Rust and `cargo`
- a C/C++ compiler and CMake, for the default `aws-lc-sys` crypto backend
- Go, only for the `fips` feature, which builds the FIPS backend (`aws-lc-fips-sys`) from source

## Quickstart

Encrypt and decrypt a message with a raw AES keyring:

```rust
use aws_esdk::keyring::RawAesKeyring;
use aws_esdk::types::{AesWrappingAlg, EncryptionContext};

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

    // The encryption context is authenticated, not encrypted, and is bound to the message.
    let encryption_context = EncryptionContext::from([("purpose", "quickstart")]);

    let esdk = aws_esdk::Client::default();

    let encrypted = esdk
        .encrypt()
        .plaintext(b"the quick brown fox")
        .set_encryption_context(Some(encryption_context.clone()))
        .keyring(keyring.clone())
        .send()
        .await?;

    let decrypted = esdk
        .decrypt()
        .ciphertext(encrypted.ciphertext())
        .set_encryption_context(Some(encryption_context))
        .keyring(keyring)
        .send()
        .await?;

    assert_eq!(decrypted.plaintext(), b"the quick brown fox");
    Ok(())
}
```

## The `Client`

A `Client` holds two settings that apply to every operation it starts:
the commitment policy, and the maximum number of encrypted data keys in a message.
`Client::default()` uses the `RequireEncryptRequireDecrypt` commitment policy and no maximum.
To set them, use `Client::builder()`:

```rust
use aws_esdk::types::CommitmentPolicy;

let esdk = aws_esdk::Client::builder()
    .commitment_policy(CommitmentPolicy::RequireEncryptRequireDecrypt)
    .build()?;
let encrypted = esdk.encrypt().plaintext(plaintext).keyring(keyring).send().await?;
```

Or build a `Config` and pass it to `Client::from_conf`, as with `aws_sdk_kms::Client::from_conf`:

```rust
use aws_esdk::types::CommitmentPolicy;

let config = aws_esdk::Config::builder()
    .commitment_policy(CommitmentPolicy::RequireEncryptRequireDecrypt)
    .build()?;
let esdk = aws_esdk::Client::from_conf(config);
```

## Streaming

`encrypt_stream` and `decrypt_stream` read from a tokio `AsyncRead` and write to an `AsyncWrite`,
so memory use stays bounded however large the input is.

`decrypt_stream` writes plaintext before it has verified the whole message.
Act on that output only after it returns `Ok`.
If it returns an error, discard everything it wrote.

`decrypt_stream` rejects a signed message with more than one frame, and the default algorithm suite signs.
To stream such a message, encrypt it with an algorithm suite that doesn't sign.
Otherwise, decrypt it with `decrypt`.

## Examples

Runnable examples live under [`examples/`](examples/).
Run one with `cargo run --example <name>`:

| Example | Shows | Needs AWS |
|---|---|---|
| `raw_aes_keyring` | encrypt and decrypt with a raw AES keyring | no |
| `streaming` | encrypt and decrypt a file with `encrypt_stream` and `decrypt_stream` | no |
| `custom_keyring` | implement your own keyring | no |
| `custom_cmm` | implement your own cryptographic materials manager (CMM) | no |
| `set_algorithm_suite` | encrypt with a non-default algorithm suite | no |
| `set_commitment_policy` | encrypt and decrypt under a non-default commitment policy | no |
| `configure_client` | set the commitment policy, the encrypted data key limit, the algorithm suite and the frame length | no |
| `hierarchical_keyring` | encrypt and decrypt with a hierarchical keyring | KMS + DynamoDB |
| `branch_key_supplier` | pick a branch key per tenant | KMS + DynamoDB |
| `rotate_branch_key` | create a branch key and rotate it | KMS + DynamoDB |
| `shared_storm_tracking_cache` | share one cache across two hierarchical keyrings | KMS + DynamoDB |
| `handling_errors` | handle the errors a hierarchical keyring and its key store return | KMS + DynamoDB |
| `per_request_credentials` | call AWS KMS with credentials issued for one request | KMS + DynamoDB |

The examples that need AWS also need credentials, a KMS key, and a key store table in DynamoDB.

## Cargo features

All of these except `fips` are on by default.

| Feature | What it adds | Without it |
|---|---|---|
| `kms`, `ddb` | the AWS KMS and DynamoDB SDKs, for the built-in key store | use your own key store, or a keyring that doesn't need one |
| `default-aws-sdk-clients` | the key store builder creates its own KMS and DynamoDB clients from your AWS credentials and region (this pulls in `aws-config` and the AWS SDK's HTTPS and TLS client) | create the clients yourself and pass them with `kms_client` and `ddb_client` |
| `rt-tokio` | the tokio-based caches, which the hierarchical keyring uses by default | pass the hierarchical keyring a `cache`, such as `LocalCmc` |
| `aws-lc-sys` | the default crypto backend, AWS-LC | turn on `fips` instead |
| `fips` (off by default) | AWS-LC's FIPS module as the crypto backend; takes precedence over `aws-lc-sys` | |

To use FIPS, add `fips`. It takes precedence over the default backend:

```toml
aws-esdk = { version = "2", features = ["fips"] }
```

To pick features, turn off the defaults and list the ones you want, with a crypto backend:

```toml
# Bring your own KMS and DynamoDB clients, without aws-config or the default HTTPS client
aws-esdk = { version = "2", default-features = false, features = ["aws-lc-sys", "kms", "ddb", "rt-tokio"] }
```

## Development

Run these in the `esdk/` directory:

```bash
cargo build              # build the library
cargo build --examples   # build every example
cargo test               # run the test suite
make test                # run the test suite across feature combinations
make clippy              # lint across feature combinations
make examples            # run every example
make examples LOCAL_ONLY=--local-only   # run only the examples that don't need AWS
```

The `//=` and `//#` comments are [Duvet](https://github.com/awslabs/duvet) citations.
Each one ties a specification requirement to the code or test that satisfies it.
`make duvet` writes the compliance report as HTML under `.duvet/reports`.

## Security

If you discover a potential security issue in this project we ask that you notify
AWS/Amazon Security via our
[vulnerability reporting page](http://aws.amazon.com/security/vulnerability-reporting/).
Please **do not** create a public GitHub issue.

## License

This project is licensed under the Apache-2.0 License.
