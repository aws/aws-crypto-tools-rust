# aws-esdk

A native Rust implementation of the AWS Encryption SDK.

The AWS Encryption SDK is a client-side encryption library that makes it easier
to encrypt and decrypt data using industry standards and best practices. It uses
envelope encryption: your data is protected with a data key, and that data key is
protected by one or more wrapping keys held in a _keyring_. The encrypted data
keys travel alongside the ciphertext, so you don't track them separately.

The two primary operations are `encrypt` and `decrypt`. Each has a streaming
variant (`encrypt_stream` / `decrypt_stream`) for data too large to hold in
memory. Per-call configuration lives on the `EncryptInput` / `DecryptInput`
structs; the optional [`Esdk`](#the-esdk-client) client sets that configuration
once and reuses it.

## Prerequisites

`aws-esdk` is not yet published to crates.io. For now you consume it by building
from this repository, which also carries the in-repo crates it depends on.

Building from source needs:

- Rust and `cargo`.
- A C/C++ compiler and CMake, to build the default `aws-lc-sys` crypto backend.
- Go, only if you enable the optional `fips` feature. That switches the backend
  to `aws-lc-fips-sys`, which builds the FIPS module from source with CMake and
  Go. The default (non-FIPS) build does not need Go.
- AWS credentials, a KMS key, and a DynamoDB table for the hierarchical-keyring
  paths only (see [Examples](#examples)). The raw-AES, streaming, custom-keyring,
  and required-encryption-context paths run offline.

## Quickstart

A one-shot encrypt/decrypt round trip with a raw AES keyring:

```rust
use aws_esdk::{DecryptInput, EncryptInput, EncryptionContext, decrypt, encrypt, mpl};
use aws_mpl_legacy::dafny::types::AesWrappingAlg;
use aws_smithy_types::Blob;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // For demonstration only: a real application must source its wrapping key
    // from a secure store and never hardcode it.
    let keyring = mpl()
        .create_raw_aes_keyring()
        .key_namespace("my-key-namespace")
        .key_name("my-key-name")
        .wrapping_key(Blob::new([0x01u8; 32]))
        .wrapping_alg(AesWrappingAlg::AlgAes256GcmIv12Tag16)
        .send()
        .await?;

    // The encryption context is authenticated, not encrypted, and is bound to
    // the message.
    let mut encryption_context = EncryptionContext::new();
    encryption_context.insert("purpose".to_string(), "quickstart".to_string());

    let encrypted = encrypt(&EncryptInput::with_legacy_keyring(
        b"the quick brown fox",
        encryption_context.clone(),
        keyring.clone(),
    ))
    .await?;

    let decrypted = decrypt(&DecryptInput::with_legacy_keyring(
        &encrypted.ciphertext,
        encryption_context,
        keyring,
    ))
    .await?;

    assert_eq!(decrypted.plaintext, b"the quick brown fox");
    Ok(())
}
```

## The `Esdk` client

`encrypt` / `decrypt` take the commitment policy and encrypted-data-key cap on
each input. To set them once and reuse them, build an `Esdk` client and call its
methods instead:

```rust
use aws_esdk::{Esdk, EsdkCommitmentPolicy};

let esdk = Esdk::builder()
    .commitment_policy(EsdkCommitmentPolicy::RequireEncryptRequireDecrypt)
    .build();
let encrypted = esdk.encrypt(&input).await?;
```

Set the commitment policy and EDK cap in exactly one place — on the client or on
the input, not both.

## Streaming

`encrypt_stream` / `decrypt_stream` read from any `Read` and write to any
`Write`, processing arbitrarily large inputs in bounded memory.

Streamed decrypt releases plaintext to the sink before the whole message is
verified. It returns normally only if the message authenticates; if it errors,
discard everything it produced. Streamed decrypt also refuses a multi-frame
message under a signing suite — encrypt those under a non-signing suite, or
decrypt them with the one-shot `decrypt`.

## Examples

Runnable examples live under [`examples/`](examples/). Run one with
`cargo run --example <name>`:

| Example | Needs AWS |
|---|---|
| `raw_aes_keyring` | no |
| `streaming` | no |
| `custom_keyring` | no |
| `required_encryption_context` | no |
| `hierarchical_keyring` | yes — KMS + DynamoDB |

`make examples` runs every example; the hierarchical one needs AWS credentials.
Add `LOCAL_ONLY=--local-only` to run only the offline examples:
`make examples LOCAL_ONLY=--local-only`.

## Build, test, and development

`aws-esdk` builds as part of this repository. From a checkout, run these in the
`esdk/` directory:

```bash
cargo build              # build the library
cargo build --examples   # build every example, including hierarchical_keyring
cargo test               # run the test suite
make test                # run the test suite across feature combinations
make examples            # run every example (LOCAL_ONLY=--local-only for offline only)
make clippy              # lint across feature combinations
```

The library carries [Duvet](https://github.com/awslabs/duvet) citations (the
`//=` / `//#` comments) that tie each specification requirement to the code and
tests satisfying it. Generate the compliance report with `make duvet`; it writes
HTML under `.duvet/reports`.

## Security

If you discover a potential security issue in this project we ask that you notify
AWS/Amazon Security via our
[vulnerability reporting page](http://aws.amazon.com/security/vulnerability-reporting/).
Please **do not** create a public GitHub issue.

## License

This project is licensed under the Apache-2.0 License.
