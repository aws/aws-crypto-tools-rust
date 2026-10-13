# aws-esdk

A native Rust implementation of the AWS Encryption SDK.

The AWS Encryption SDK is a client-side encryption library.
It uses envelope encryption: a data key encrypts your data, and one or more wrapping keys in a _keyring_ encrypt that data key.
The encrypted message carries the encrypted data keys, so you don't track them separately.

Every operation starts on an [`Esdk`](#the-esdk-client) client.
The two primary operations are `encrypt` and `decrypt`.
Each has a streaming variant (`encrypt_stream` / `decrypt_stream`) for data too large to hold in memory.

## Prerequisites

`aws-esdk` is not yet published to crates.io.
Build it from this repository, which also holds the crates it depends on.

Building from source needs:

- Rust and `cargo`.
- A C/C++ compiler and CMake, to build the default `aws-lc-sys` crypto backend.
- Go, only for the optional `fips` feature.
  It switches the backend to `aws-lc-fips-sys`, which builds the FIPS module from source with CMake and Go.

The examples that use the hierarchical keyring also need AWS credentials, a KMS key, and a DynamoDB table (see [Examples](#examples)).

## Quickstart

A one-shot encrypt/decrypt round trip with a raw AES keyring:

```rust
use aws_crypto_mpl::{AesGcm, RawAesKeyring};
use aws_esdk::{EncryptionContext, Esdk};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // For demonstration only.
    // A real application must load its wrapping key from a secure store, never hardcode it.
    let keyring = RawAesKeyring::builder()
        .key_namespace("my-key-namespace")
        .key_name("my-key-name")
        .wrapping_key(vec![0x01u8; 32])
        .wrapping_alg(AesGcm::Aes256Gcm)
        .build()?;

    // The encryption context is authenticated, not encrypted, and is bound to the message.
    let mut encryption_context = EncryptionContext::new();
    encryption_context.insert("purpose", "quickstart");

    let esdk = Esdk::default();

    let encrypted = esdk
        .encrypt()
        .plaintext(b"the quick brown fox")
        .encryption_context(encryption_context.clone())
        .keyring(keyring.clone())
        .send()
        .await?;

    let decrypted = esdk
        .decrypt()
        .ciphertext(&encrypted.ciphertext)
        .encryption_context(encryption_context)
        .keyring(keyring)
        .send()
        .await?;

    assert_eq!(decrypted.plaintext, b"the quick brown fox");
    Ok(())
}
```

## The `Esdk` client

An `Esdk` client holds the commitment policy and the cap on encrypted data keys, and applies them to every operation it starts.
`Esdk::default()` uses the `RequireEncryptRequireDecrypt` policy and no cap.
Set either one with `Esdk::builder()`:

```rust
use aws_esdk::{CommitmentPolicy, Esdk};

let esdk = Esdk::builder()
    .commitment_policy(CommitmentPolicy::RequireEncryptRequireDecrypt)
    .build();
let encrypted = esdk.encrypt().plaintext(plaintext).keyring(keyring).send().await?;
```

## Streaming

`encrypt_stream` / `decrypt_stream` read from any tokio `AsyncRead` and write to any `AsyncWrite`, so memory use stays bounded however large the input is.

Streamed decrypt writes plaintext to the sink before it has verified the whole message.
It returns `Ok` only if the message authenticates.
If it returns an error, discard everything it wrote.

Streamed decrypt rejects a multi-frame message under a signing suite.
Encrypt such messages under a non-signing suite, or decrypt them with the one-shot `decrypt`.

## Examples

Runnable examples live under [`examples/`](examples/).
Run one with `cargo run --example <name>`:

| Example | Needs AWS |
|---|---|
| `raw_aes_keyring` | no |
| `streaming` | no |
| `custom_keyring` | no |
| `set_algorithm_suite` | no |
| `set_commitment_policy` | no |
| `signing_only_cmm` | no |
| `hierarchical_keyring` | KMS + DynamoDB |
| `branch_key_supplier` | KMS + DynamoDB |
| `rotate_branch_key` | KMS + DynamoDB |
| `shared_storm_tracking_cache` | KMS + DynamoDB |
| `handling_errors` | KMS + DynamoDB |
| `per_request_credentials` | KMS + DynamoDB |

`make examples` runs every example.
`make examples LOCAL_ONLY=--local-only` runs only the ones that don't need AWS.

## Build, test, and development

Run these in the `esdk/` directory:

```bash
cargo build              # build the library
cargo build --examples   # build every example
cargo test               # run the test suite
make test                # run the test suite across feature combinations
make examples            # run every example (LOCAL_ONLY=--local-only to skip the AWS ones)
make clippy              # lint across feature combinations
```

The library carries [Duvet](https://github.com/awslabs/duvet) citations (the `//=` / `//#` comments) that tie each specification requirement to the code and tests that satisfy it.
`make duvet` generates the compliance report as HTML under `.duvet/reports`.

## Security

If you discover a potential security issue in this project we ask that you notify
AWS/Amazon Security via our
[vulnerability reporting page](http://aws.amazon.com/security/vulnerability-reporting/).
Please **do not** create a public GitHub issue.

## License

This project is licensed under the Apache-2.0 License.
