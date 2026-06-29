// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

//! Happy-path basic round trip with the S3 Encryption Client (S3EC).
//!
//! Mirrors the "Encrypting and decrypting Amazon S3 objects" example from the
//! other-language S3EC clients (Java / Go): build a client with a KMS wrapping
//! key, `PutObject` a plaintext string, `GetObject` it back, and confirm the
//! decrypted bytes match what was uploaded.
//!
//! Run it with the bucket, object key, and KMS key id supplied via the
//! environment (so nothing is hardcoded):
//!
//! ```sh
//! export S3EC_BUCKET=my-bucket
//! export S3EC_KEY=my-object-key
//! export S3EC_KMS_KEY_ID=arn:aws:kms:us-west-2:111122223333:key/<key-id>
//! cargo run --example kms_round_trip
//! ```
//!
//! Requires AWS credentials in the ambient environment with `s3:PutObject` /
//! `s3:GetObject` on the bucket and `kms:GenerateDataKey` / `kms:Decrypt` on
//! the key.
//
// ===========================================================================
// PROPOSED ergonomic interface (ILLUSTRATIVE ONLY — not implemented).
//
// Everything in this comment block is a sketch of how the customer-facing API
// *could* look to match the other S3EC clients (Java/Go) and the AWS
// Encryption SDK for Rust, which are all keyring-first. Nothing below compiles
// today; it exists purely to show the intended shape. The real, working
// example follows further down and is unchanged.
//
// --- 1. Keyring as a first-class object, handed to the client -------------
//
// Instead of stuffing a raw `kms_key_id` (plus mutually-exclusive
// `aes_wrapping_key` / `rsa_wrapping_key`) into a config struct, the customer
// builds a keyring and gives it to the client — the same mental model as every
// other client:
//
//     let keyring = KmsKeyring::builder()
//         .key_id("arn:aws:kms:us-west-2:111122223333:key/<key-id>")
//         .build()?;                       // optionally .kms_client(my_kms)
//
//     let client = S3EncryptionClient::builder()
//         .keyring(keyring)                // <- the one materials provider
//         .build()                         // builds S3/KMS from the env
//         .await?;
//
// Raw keyrings look the same, so there are no illegal states to validate at
// runtime (no "all None" / "two set at once" config):
//
//     let keyring = AesKeyring::new(my_aes_256_key);          // raw AES
//     let keyring = RsaKeyring::from_key_pair(my_rsa_pair);   // raw RSA
//
// A terse shortcut can still exist for the common KMS case, but it is sugar
// over `keyring(...)`, not a separate config shape:
//
//     let client = S3EncryptionClient::builder()
//         .kms_key_id("arn:aws:kms:...")   // convenience == KmsKeyring::builder()
//         .build()
//         .await?;
//
// --- 2. Encryption context: an ordinary map, no `.to_string()` noise ------
//
// The public API accepts any iterable of string-ish pairs (or a plain
// `HashMap`) and canonicalizes to the internal sorted `BTreeMap` itself. The
// `BTreeMap` invariant stays an implementation detail and never leaks:
//
//     let ctx = [("purpose", "round-trip-example"),
//                ("origin",  "kms_round_trip.rs")];
//
// --- 3. Request builders: optional context/range, no positional `None`s ---
//
// Put: encryption context is optional; the common case is a one-liner.
//
//     client.put_object(&bucket, &key, plaintext)
//         .encryption_context(ctx)         // optional
//         .send()
//         .await?;
//
// Get: no more `get_object(.., &ctx, None, None)` — only set what you need.
//
//     let decrypted = client.get_object(&bucket, &key)
//         .encryption_context(ctx)         // optional, must match put
//         // .range("bytes=10-20")         // optional
//         .send()
//         .await?;
//     assert_eq!(decrypted.plaintext, plaintext);
//
// Net effect for the customer: build a keyring, build a client, put, get. No
// config struct with mutually-exclusive Options, no `BTreeMap`, no `to_string`,
// no placeholder `None` arguments.
// ===========================================================================

use std::collections::BTreeMap;

use aws_s3_encryption::{S3EncryptionClient, S3EncryptionConfig};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let bucket = std::env::var("S3EC_BUCKET")?;
    let key = std::env::var("S3EC_KEY")?;
    let kms_key_id = std::env::var("S3EC_KMS_KEY_ID")?;

    // 1. Instantiate the client with a KMS key as the wrapping key. The client
    //    builds its own S3 and KMS clients from the default AWS provider chain
    //    and defaults to the key-committing AES-GCM suite.
    //
    // PROPOSED: build a keyring, then a client (see the sketch at the top):
    //     let keyring = KmsKeyring::builder().key_id(kms_key_id).build()?;
    //     let client  = S3EncryptionClient::builder().keyring(keyring).build().await?;
    let config = S3EncryptionConfig {
        kms_key_id: Some(kms_key_id),
        ..Default::default()
    };
    let client = S3EncryptionClient::from_env(config).await?;

    let plaintext = b"the quick brown fox jumps over the lazy dog";

    // The encryption context is non-secret AAD bound to the ciphertext. The
    // same context supplied on encrypt MUST be supplied on decrypt, so the
    // round trip below passes `ctx` to both calls. An empty context
    // (`BTreeMap::new()`) is also valid for a minimal round trip.
    //
    // PROPOSED: a plain array of (&str, &str) pairs, no BTreeMap / no to_string:
    //     let ctx = [("purpose", "round-trip-example"), ("origin", "kms_round_trip.rs")];
    let ctx = BTreeMap::from([
        ("purpose".to_string(), "round-trip-example".to_string()),
        ("origin".to_string(), "kms_round_trip.rs".to_string()),
    ]);

    // 2. Encrypt + upload. The client wraps a fresh data key with the KMS key,
    //    encrypts the plaintext locally, and uploads the ciphertext plus the
    //    encrypted data key as object metadata.
    //
    // PROPOSED: encryption context is optional, set via a request builder:
    //     client.put_object(&bucket, &key, plaintext).encryption_context(ctx).send().await?;
    client.put_object(&bucket, &key, plaintext, &ctx).await?;
    println!("put encrypted object s3://{bucket}/{key}");

    // 3. Download + decrypt. The client unwraps the data key with KMS and
    //    decrypts the object body, returning the recovered plaintext.
    //
    // PROPOSED: no positional `None`s; only set what you need:
    //     let decrypted = client.get_object(&bucket, &key).encryption_context(ctx).send().await?;
    let decrypted = client
        .get_object(&bucket, &key, &ctx, None, None)
        .await?;

    // 4. Verify the round trip.
    assert_eq!(
        decrypted.plaintext, plaintext,
        "decrypted plaintext did not match the original"
    );
    println!(
        "round trip ok: decrypted {} bytes -> {:?}",
        decrypted.plaintext.len(),
        String::from_utf8_lossy(&decrypted.plaintext)
    );

    Ok(())
}
