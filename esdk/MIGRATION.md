# Migrating from `aws-esdk` 1.x to 2.x

`aws-esdk` 1.x is the AWS Encryption SDK for Rust built from the [Dafny implementation](https://github.com/aws/aws-encryption-sdk/tree/mainline/AwsEncryptionSDK/runtimes/rust).
`aws-esdk` 2.x is a native Rust implementation, in this repository.
Both read and write the same AWS Encryption SDK message format,
so messages 1.x encrypted decrypt with 2.x, and the other way around,
with the exception in [Messages from ESDK-NET v4.0.0](#messages-from-esdk-net-v400).

The API is new.
This guide lists what changed, what to replace it with, and where behavior differs.

> **Using an AI coding assistant?**
> Load the [migration skill](skills/migrate-1x-to-2x/SKILL.md) and ask it to migrate your code from `aws-esdk` 1.x to 2.x.
> It follows this guide.
> Review its changes as you would a person's, and run your tests:
> an assistant can make mistakes, and it cannot see how your application stores and handles messages.

> **Disclaimer.**
> This guide covers the public API of `aws-esdk` 1.x and the Material Providers Library it re-exports.
> It cannot cover every way an application uses them.
> Test the migrated code against messages your application encrypted with 1.x before you deploy it.

## Before you start: check that 2.x has what you use

2.x does not yet have every keyring and CMM 1.x has.
If your code uses one 2.x lacks, you cannot migrate that code yet.

| 1.x (`mpl.create_...`) | 2.x |
|---|---|
| `create_raw_aes_keyring` | `keyring::RawAesKeyring` |
| `create_aws_kms_hierarchical_keyring` | `keyring::HierarchicalKeyring` |
| `create_default_cryptographic_materials_manager` | `cmm::DefaultCmm` |
| `create_cryptographic_materials_cache` | `cmc::DefaultCmc`, `cmc::StormTrackingCmc`, `cmc::LocalCmc` |
| `create_aws_kms_keyring`, `create_aws_kms_multi_keyring` | not available |
| `create_aws_kms_discovery_keyring`, `create_aws_kms_discovery_multi_keyring` | not available |
| `create_aws_kms_mrk_keyring`, `create_aws_kms_mrk_multi_keyring` | not available |
| `create_aws_kms_mrk_discovery_keyring`, `create_aws_kms_mrk_discovery_multi_keyring` | not available |
| `create_aws_kms_rsa_keyring` | not available |
| `create_aws_kms_ecdh_keyring`, `create_raw_ecdh_keyring` | not available |
| `create_raw_rsa_keyring` | not available |
| `create_multi_keyring` | not available |
| `create_required_encryption_context_cmm` | not available |

You can still write your own keyring or CMM; see [Custom keyrings, CMMs, and suppliers](#custom-keyrings-cmms-and-suppliers).

## Dependencies

Change the `aws-esdk` version. Keep your other dependencies.

```toml
# 1.x
aws-esdk = "1"

# 2.x
aws-esdk = "2"
```

- 2.x is not on crates.io yet. Build it from this repository until it is.
- You can drop `aws-smithy-types` if only the ESDK used it: 2.x does not use `Blob`.
- 2.x re-exports the AWS SDK crates it takes clients from: `aws_esdk::aws_config`, `aws_esdk::aws_sdk_kms`, and `aws_esdk::aws_sdk_dynamodb`.
  You can use these instead of your own `aws-config`, `aws-sdk-kms`, and `aws-sdk-dynamodb` dependencies.
- 2.x uses Rust edition 2024, so it needs Rust 1.85 or later.
- The license changed from `ISC AND (Apache-2.0 OR ISC)` to `Apache-2.0`.

### Cargo features

| 1.x | 2.x |
|---|---|
| `fips` | `fips` |
| `non-fips` | `aws-lc-sys` (on by default) |
| (always on) | `kms`, `ddb`, `default-aws-sdk-clients`, `rt-tokio` (on by default) |

See the [README](README.md#cargo-features) for what each 2.x feature adds.

## Imports

| 1.x | 2.x |
|---|---|
| `aws_esdk::client::Client` | `aws_esdk::Client` |
| `aws_esdk::types::aws_encryption_sdk_config::AwsEncryptionSdkConfig` | `aws_esdk::Config`, or `aws_esdk::Client::builder()` |
| `aws_esdk::types::error::Error` | `aws_esdk::Error` |
| `aws_esdk::material_providers::client::Client` | none: build each keyring, CMM, and cache from its own builder |
| `aws_esdk::material_providers::types::material_providers_config::MaterialProvidersConfig` | none |
| `aws_esdk::material_providers::types::EsdkCommitmentPolicy` | `aws_esdk::types::CommitmentPolicy` |
| `aws_esdk::material_providers::types::EsdkAlgorithmSuiteId` | `aws_esdk::types::AlgorithmSuiteId` |
| `aws_esdk::material_providers::types::AesWrappingAlg` | `aws_esdk::types::AesWrappingAlg` |
| `std::collections::HashMap<String, String>` (encryption context) | `aws_esdk::types::EncryptionContext` |
| `aws_esdk::material_providers::types::keyring::KeyringRef` | `aws_esdk::keyring::SharedKeyring`, or pass the keyring itself |
| `aws_esdk::material_providers::types::cryptographic_materials_manager::CryptographicMaterialsManagerRef` | `aws_esdk::cmm::SharedCmm`, or pass the CMM itself |
| `aws_esdk::material_providers::types::error::Error` | `aws_esdk::mpl::Error` |
| `aws_esdk::key_store::client::Client` + `KeyStoreConfig` | `aws_esdk::key_store::DynamoDbKeyStore` |
| `aws_esdk::key_store::types::KmsConfiguration` | `aws_esdk::key_store::types::KmsConfiguration` |

## The client

```rust
// 1.x
let esdk_config = AwsEncryptionSdkConfig::builder()
    .commitment_policy(EsdkCommitmentPolicy::ForbidEncryptAllowDecrypt)
    .max_encrypted_data_keys(3)
    .build()?;
let esdk_client = esdk_client::Client::from_conf(esdk_config)?;

// 2.x
let esdk = aws_esdk::Client::builder()
    .commitment_policy(CommitmentPolicy::ForbidEncryptAllowDecrypt)
    .max_encrypted_data_keys(NonZeroUsize::new(3).unwrap())
    .build()?;
// or, with all defaults
let esdk = aws_esdk::Client::default();
```

- `Client::from_conf` no longer returns a `Result`. Remove its `?`.
- `max_encrypted_data_keys` takes a `NonZeroUsize`.
- `net_v4_0_0_retry_policy` is gone; see [Messages from ESDK-NET v4.0.0](#messages-from-esdk-net-v400).
- The default commitment policy is still `RequireEncryptRequireDecrypt`.

## Encrypt and decrypt

```rust
// 1.x
let encryption_response = esdk_client.encrypt()
    .plaintext(plaintext)
    .keyring(keyring.clone())
    .encryption_context(encryption_context.clone()) // HashMap<String, String>
    .send()
    .await?;
let ciphertext = encryption_response.ciphertext.expect("ciphertext");

let decryption_response = esdk_client.decrypt()
    .ciphertext(ciphertext)
    .keyring(keyring)
    .encryption_context(encryption_context)
    .send()
    .await?;
let plaintext = decryption_response.plaintext.expect("plaintext");

// 2.x
let encrypted = esdk.encrypt()
    .plaintext(plaintext)
    .keyring(keyring.clone())
    .set_encryption_context(Some(encryption_context.clone())) // EncryptionContext
    .send()
    .await?;

let decrypted = esdk.decrypt()
    .ciphertext(encrypted.ciphertext())
    .keyring(keyring)
    .set_encryption_context(Some(encryption_context))
    .send()
    .await?;
let plaintext: &[u8] = decrypted.plaintext();
```

- **Encryption context setter.** `encryption_context(key, value)` now adds one pair.
  To pass a whole map, use `set_encryption_context(Some(map))`.
- **Encryption context type.** Use `EncryptionContext`.
  It converts from `HashMap<String, String>`, `BTreeMap<String, String>`, and arrays of pairs, and back to `HashMap<String, String>`.
- **Inputs borrow.** `plaintext` and `ciphertext` take `&[u8]`, not an owned `Blob`.
- **Outputs are accessors.** `ciphertext`, `plaintext`, `encryption_context`, and `algorithm_suite_id` are methods, not `Option` fields, so drop the `.expect(...)`.
  `ciphertext()` returns `&Ciphertext` and `plaintext()` returns `&Plaintext`; both dereference to `&[u8]`.
  To take ownership, call `into_ciphertext()` or `into_plaintext()`, then `into_inner()` for a `Vec<u8>`.
- **CMM setter.** `materials_manager(...)` is now `cmm(...)`.
- **Frame length.** `frame_length` takes a `NonZeroU32`. The default is still 4096.
- **Algorithm suite.** `algorithm_suite_id` takes `aws_esdk::types::AlgorithmSuiteId`. The variant names did not change.

## Keyrings

Each keyring has its own builder. There is no Material Providers client.

### Raw AES keyring

```rust
// 1.x
let mpl = mpl_client::Client::from_conf(MaterialProvidersConfig::builder().build()?)?;
let keyring = mpl.create_raw_aes_keyring()
    .key_name("my-aes-key-name")
    .key_namespace("my-key-namespace")
    .wrapping_key(aes_key_bytes)
    .wrapping_alg(AesWrappingAlg::AlgAes256GcmIv12Tag16)
    .send()
    .await?;

// 2.x
let keyring = RawAesKeyring::builder()
    .key_name("my-aes-key-name")
    .key_namespace("my-key-namespace")
    .wrapping_key(aes_key_bytes)
    .wrapping_alg(AesWrappingAlg::AlgAes256GcmIv12Tag16)
    .build()?;
```

`RawAesKeyring::builder().build()` is not `async`.

### Hierarchical keyring and key store

```rust
// 1.x
let key_store = keystore_client::Client::from_conf(
    KeyStoreConfig::builder()
        .kms_client(kms_client)
        .ddb_client(ddb_client)
        .ddb_table_name(table_name)
        .logical_key_store_name(logical_name)
        .kms_configuration(KmsConfiguration::KmsKeyArn(kms_key_arn.to_string()))
        .build()?,
)?;
let keyring = mpl.create_aws_kms_hierarchical_keyring()
    .key_store(key_store.clone())
    .branch_key_id(branch_key_id)
    .ttl_seconds(600)
    .send()
    .await?;

// 2.x
let key_store = key_store::DynamoDbKeyStore::builder()
    .kms_client(kms_client)
    .ddb_client(ddb_client)
    .ddb_table_name(table_name)
    .logical_key_store_name(logical_name)
    .kms_configuration(KmsConfiguration::KmsKeyArn(kms_key_arn.into()))
    .build()
    .await?;
let keyring = HierarchicalKeyring::builder()
    .key_store(key_store.clone())
    .branch_key_id(branch_key_id)
    .ttl(Duration::from_secs(600))
    .build()
    .await?;
```

- `DynamoDbKeyStore::builder().build()` is `async`: without `kms_client` and `ddb_client`, it loads AWS config to create them.
- `ttl_seconds(i64)` is now `ttl(Duration)`. A zero TTL is an error.
- Key store operations keep their names, with shorter inputs and accessor outputs:

| 1.x | 2.x |
|---|---|
| `create_key().send().await?.branch_key_identifier.unwrap()` | `create_key().send().await?.into_branch_key_id()` |
| `version_key().branch_key_identifier(id)` | `version_key().branch_key_id(id)` |

### Sharing a cache between keyrings

```rust
// 1.x
let cache = mpl.create_cryptographic_materials_cache()
    .cache(CacheType::Default(DefaultCache::builder().entry_capacity(100).build()?))
    .send()
    .await?;
let shared = CacheType::Shared(cache);
// ... .cache(shared.clone()).partition_id(partition_id.clone())

// 2.x
let cache = DefaultCmc::builder().entry_capacity(100).build()?;
// ... .cache(cache.clone()).partition_id(partition_id)
```

A clone of a 2.x cache refers to the same cache. Pass the cache itself; there is no `CacheType` wrapper.
With no cache set, the hierarchical keyring still creates a storm-tracking cache with 1000 entries.

## Custom keyrings, CMMs, and suppliers

The extension traits are now `async`. Implement them with `#[aws_esdk::async_trait]`.

| 1.x trait | 2.x trait |
|---|---|
| `material_providers::types::keyring::Keyring` | `aws_esdk::keyring::Keyring` |
| `material_providers::types::cryptographic_materials_manager::CryptographicMaterialsManager` | `aws_esdk::cmm::Cmm` |
| `material_providers::types::branch_key_id_supplier::BranchKeyIdSupplier` | `aws_esdk::keyring::BranchKeySupplier` |

```rust
// 1.x
impl CryptographicMaterialsManager for MyCmm {
    fn get_encryption_materials(&self, input: GetEncryptionMaterialsInput)
        -> Result<GetEncryptionMaterialsOutput, Error>
    {
        tokio::task::block_in_place(|| {
            tokio::runtime::Handle::current().block_on(async {
                self.cmm.get_encryption_materials()
                    .encryption_context(input.encryption_context.unwrap())
                    // ...
                    .send().await
            })
        })
    }
}
let cmm_ref = CryptographicMaterialsManagerRef {
    inner: Arc::new(Mutex::new(MyCmm::new(keyring))),
};

// 2.x
#[async_trait]
impl Cmm for MyCmm {
    async fn get_encryption_materials(&self, input: GetEncryptionMaterialsInput)
        -> Result<GetEncryptionMaterialsOutput, MplError>
    {
        self.inner.get_encryption_materials()
            .set_encryption_context(Some(input.encryption_context().clone()))
            // ...
            .send().await
    }
}
// pass MyCmm itself: esdk.encrypt().cmm(my_cmm)
```

- Remove `block_in_place` and `block_on`; `.await` instead.
  Your code no longer needs a multi-threaded tokio runtime for this.
- Pass your keyring or CMM to `keyring(...)` or `cmm(...)` directly. You no longer wrap it in a `...Ref { inner: Arc<Mutex<_>> }`.
- Input fields are accessor methods. For example, `input.encryption_context.unwrap()` is now `input.encryption_context()`. An optional field's accessor still returns an `Option`.
- Return `aws_esdk::mpl::Error`. Build one with a constructor such as `MplError::validation("...")`,
  not `Error::AwsCryptographicMaterialProvidersException { message }`.
- A `BranchKeySupplier` returns `GetBranchKeyIdOutput`, which converts from `&str`: `Ok(branch_key_id.as_str().into())`.
- `DefaultCmm::new(keyring)` replaces `mpl.create_default_cryptographic_materials_manager().keyring(keyring).send()`, and is not `async`.

See [`examples/custom_keyring.rs`](examples/custom_keyring.rs), [`examples/custom_cmm.rs`](examples/custom_cmm.rs), and [`examples/branch_key_supplier.rs`](examples/branch_key_supplier.rs).

## Errors

1.x had a few broad variants that carried a message.
2.x has one variant per kind of failure, and each tells you what to do.

| Failure | 1.x (typical) | 2.x |
|---|---|---|
| bad input or configuration | `AwsEncryptionSdkException`, `AwsCryptographicMaterialProvidersException` | `Error::Validation` |
| no keyring could decrypt a data key | `AwsCryptographicMaterialProvidersError { error }` | `Error::NoMatchingDataKey` |
| encryption context does not match | `AwsEncryptionSdkException` | `Error::EncryptionContextMismatch` |
| tag or signature did not verify | `AwsEncryptionSdkException` | `Error::Cryptographic` |
| bytes are not a valid message | `AwsEncryptionSdkException` | `Error::Serialization` |
| AWS denied, throttled, not found, or failed | wrapped SDK error in `AwsCryptographicMaterialProvidersError` | `Error::AccessDenied`, `Error::Throttling`, `Error::ResourceNotFound`, `Error::Service`, `Error::Dispatch`, `Error::Conflict` |

- `Error` is `#[non_exhaustive]`. Every `match` needs a catch-all arm.
- Decide from the variant and its accessors (`is_retryable()`, `resource()`, `service()`), never from the message text.
- If your 1.x code matched on message strings, rewrite it to match variants.

See the [`error` module docs](src/error.rs) and [`examples/handling_errors.rs`](examples/handling_errors.rs).

## New in 2.x

- **Streaming.** `encrypt_stream` and `decrypt_stream` read from a tokio `AsyncRead` and write to an `AsyncWrite`. See [Streaming](README.md#streaming).
- **Per-request credentials.** See [`examples/per_request_credentials.rs`](examples/per_request_credentials.rs).

## Behavior changes

These changes compile cleanly but can change what your application does at run time.

### Messages from ESDK-NET v4.0.0

ESDK-NET v4.0.0 computed the header authentication tag differently from other implementations for some messages.
1.x accepted these by default: when the header check failed, it retried the ESDK-NET v4.0.0 way
(`net_v4_0_0_retry_policy`, default `ALLOW_RETRY`).

2.x has no retry. It rejects such a message, as it would a corrupt one.

If you may hold messages encrypted with ESDK-NET v4.0.0,
decrypt them with 1.x and re-encrypt them before you switch to 2.x.

### Encryption context setter adds instead of replacing

In 1.x, `encryption_context(map)` set the whole map.
In 2.x, `encryption_context(key, value)` adds one pair, and `set_encryption_context(Some(map))` sets the whole map.
Passing a map to `encryption_context` does not compile, so this shows up as a build error, not a silent change.

### Streaming decrypt writes unverified plaintext

This applies only if you adopt `decrypt_stream`.
It writes plaintext before it has checked the whole message.
Act on that output only after it returns `Ok`, and discard everything it wrote if it returns an error.
By default it rejects a signed message with more than one frame; see [Streaming](README.md#streaming).

### Errors you matched on

A failure that was `AwsEncryptionSdkException` or `AwsCryptographicMaterialProvidersError` in 1.x is now a specific variant.
Code that caught the old variants and treated them all alike must now match the new ones, or use a catch-all arm.
For example, decrypting with the wrong hierarchical keyring was `AwsCryptographicMaterialProvidersError` in 1.x and is `Error::NoMatchingDataKey` in 2.x.

## Example index

| Task | 1.x example | 2.x example |
|---|---|---|
| raw AES keyring | `keyring/raw_aes_keyring_example.rs` | [`raw_aes_keyring.rs`](examples/raw_aes_keyring.rs) |
| hierarchical keyring | `keyring/aws_kms_hierarchical/aws_kms_hierarchical_keyring_example.rs` | [`hierarchical_keyring.rs`](examples/hierarchical_keyring.rs) |
| branch key per tenant | `keyring/aws_kms_hierarchical/example_branch_key_id_supplier.rs` | [`branch_key_supplier.rs`](examples/branch_key_supplier.rs) |
| rotate a branch key | `keyring/aws_kms_hierarchical/version_branch_key_id_example.rs` | [`rotate_branch_key.rs`](examples/rotate_branch_key.rs) |
| shared cache | `keyring/aws_kms_hierarchical/shared_cache_across_hierarchical_keyrings_example.rs` | [`shared_storm_tracking_cache.rs`](examples/shared_storm_tracking_cache.rs) |
| custom CMM | `cryptographic_materials_manager/restrict_algorithm_suite/` | [`custom_cmm.rs`](examples/custom_cmm.rs) |
| commitment policy | `set_commitment_policy_example.rs` | [`set_commitment_policy.rs`](examples/set_commitment_policy.rs) |
| algorithm suite | `set_encryption_algorithm_suite_example.rs` | [`set_algorithm_suite.rs`](examples/set_algorithm_suite.rs) |

The 1.x examples are under [`AwsEncryptionSDK/runtimes/rust/examples`](https://github.com/aws/aws-encryption-sdk/tree/mainline/AwsEncryptionSDK/runtimes/rust/examples).
