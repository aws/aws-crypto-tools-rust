---
name: migrate-aws-esdk-1x-to-2x
description: Migrate Rust code from aws-esdk 1.x (the AWS Encryption SDK for Rust built from Dafny) to aws-esdk 2.x (the native Rust implementation). Use when a user asks to migrate, upgrade, or port code that uses the aws-esdk crate from 1.x to 2.x, or code that uses aws_esdk::material_providers, AwsEncryptionSdkConfig, or mpl.create_*_keyring.
---

# Migrate `aws-esdk` 1.x to 2.x

`aws-esdk` 1.x is built from the Dafny implementation. 2.x is a native Rust rewrite with a new API.
Both use the same message format, so data encrypted by one decrypts with the other,
except for messages written by ESDK-NET v4.0.0 (see Behavior changes).

The human-readable version of this skill is `esdk/MIGRATION.md` in [aws/aws-crypto-tools-rust](https://github.com/aws/aws-crypto-tools-rust/blob/main/esdk/MIGRATION.md).
When it and this skill disagree, the guide and the 2.x source win.

## Tell the user first

Before you change any code, tell the user, in your own words:

- You are an AI assistant and can make mistakes. They must review every change and run their tests.
- You cannot see how their application stores messages, so you cannot rule out the run-time behavior changes below. You will list the ones that may apply.
- Before deploying, they should decrypt messages their application encrypted with 1.x using the migrated code.

## Workflow

1. **Inventory.** Find every use of 1.x:
   `grep -rnE 'aws_esdk::|material_providers|AwsEncryptionSdkConfig|create_[a-z_]+_keyring|create_[a-z_]+_cryptographic_materials_manager|KeyStoreConfig|net_v4_0_0' --include='*.rs' .`
   and the `aws-esdk` line in every `Cargo.toml`.
2. **Check for blockers** (next section). If any blocker is present, stop and report it. Do not invent a replacement.
3. **Update dependencies** (Dependencies).
4. **Rewrite each use** with the mappings below.
5. **Build and test:** `cargo build --all-targets`, then `cargo test`. Fix every error. Do not silence one with `unwrap`, `allow`, or a removed test.
6. **Report:** list the files changed, any blockers, and every behavior change that may apply to this code, with the file and line that triggers it.

## Blockers: 1.x features 2.x lacks

2.x has only these materials:
`keyring::RawAesKeyring`, `keyring::HierarchicalKeyring`, `cmm::DefaultCmm`,
the caches `cmc::DefaultCmc`, `cmc::StormTrackingCmc`, `cmc::LocalCmc`,
and the key store `key_store::DynamoDbKeyStore`.

Any of these 1.x calls is a blocker. 2.x has no equivalent:

- `create_aws_kms_keyring`, `create_aws_kms_multi_keyring`
- `create_aws_kms_discovery_keyring`, `create_aws_kms_discovery_multi_keyring`
- `create_aws_kms_mrk_keyring`, `create_aws_kms_mrk_multi_keyring`
- `create_aws_kms_mrk_discovery_keyring`, `create_aws_kms_mrk_discovery_multi_keyring`
- `create_aws_kms_rsa_keyring`, `create_aws_kms_ecdh_keyring`, `create_raw_ecdh_keyring`, `create_raw_rsa_keyring`
- `create_multi_keyring`
- `create_required_encryption_context_cmm`

Do not reimplement these as custom keyrings or CMMs unless the user asks. A hand-written KMS or RSA keyring is security-sensitive code.

## Dependencies

- Replace `aws-esdk = "1..."` with `aws-esdk = "2"`. 2.x is not on crates.io yet; if the user has no source for it, say so.
- Leave other dependencies as they are, including `tokio`. 2.x needs Rust 1.85 or later (edition 2024).
- Remove `aws-smithy-types` only if nothing but the ESDK used it (2.x has no `Blob`).
- 2.x re-exports `aws_esdk::aws_config`, `aws_esdk::aws_sdk_kms`, `aws_esdk::aws_sdk_dynamodb`. The user's own `aws-config`, `aws-sdk-kms`, `aws-sdk-dynamodb` dependencies can stay.
- Features: `non-fips` becomes `aws-lc-sys` (default). `fips` stays `fips`.

## Mappings

### Imports and types

| 1.x | 2.x |
|---|---|
| `aws_esdk::client::Client` | `aws_esdk::Client` |
| `aws_esdk::types::aws_encryption_sdk_config::AwsEncryptionSdkConfig` | `aws_esdk::Config` or `aws_esdk::Client::builder()` |
| `aws_esdk::types::error::Error` | `aws_esdk::Error` |
| `material_providers::client::Client`, `MaterialProvidersConfig` | delete; use each type's builder |
| `material_providers::types::EsdkCommitmentPolicy` | `aws_esdk::types::CommitmentPolicy` |
| `material_providers::types::EsdkAlgorithmSuiteId` | `aws_esdk::types::AlgorithmSuiteId` (same variant names) |
| `material_providers::types::AesWrappingAlg` | `aws_esdk::types::AesWrappingAlg` |
| `HashMap<String, String>` encryption context | `aws_esdk::types::EncryptionContext` (`From<HashMap>`, `From<[(K, V); N]>`, `Into<HashMap>`) |
| `KeyringRef` | the keyring itself, or `aws_esdk::keyring::SharedKeyring` |
| `CryptographicMaterialsManagerRef` | the CMM itself, or `aws_esdk::cmm::SharedCmm` |
| `material_providers::types::error::Error` | `aws_esdk::mpl::Error` |
| `key_store::client::Client` + `KeyStoreConfig` | `aws_esdk::key_store::DynamoDbKeyStore` |
| `key_store::types::KmsConfiguration` | `aws_esdk::key_store::types::KmsConfiguration` |

### Client

- `AwsEncryptionSdkConfig::builder()...build()?` then `Client::from_conf(c)?` becomes `aws_esdk::Client::builder()...build()?`, or `aws_esdk::Client::default()` with no settings.
- `Client::from_conf` returns `Client`, not `Result`: remove its `?`.
- `max_encrypted_data_keys(n)` takes `NonZeroUsize`.
- `net_v4_0_0_retry_policy(...)`: delete, and record the ESDK-NET v4.0.0 behavior change in the report.

### Encrypt and decrypt

- `.encryption_context(map)` becomes `.set_encryption_context(Some(map.into()))`. In 2.x, `.encryption_context(k, v)` adds one pair.
- `.materials_manager(cmm)` becomes `.cmm(cmm)`.
- `.plaintext(...)` and `.ciphertext(...)` take `&[u8]`. Pass `encrypted.ciphertext()` straight to decrypt.
- Output `Option` fields become accessors; delete the `.expect`/`.unwrap`:
  - `resp.ciphertext.expect(..)` becomes `resp.ciphertext()` (`&Ciphertext`, derefs to `&[u8]`), or `resp.into_ciphertext().into_inner()` for `Vec<u8>`.
  - `resp.plaintext.expect(..)` becomes `resp.plaintext()`, or `resp.into_plaintext().into_inner()`.
  - `resp.encryption_context.unwrap()` becomes `resp.encryption_context()`; `resp.algorithm_suite_id.unwrap()` becomes `resp.algorithm_suite_id()`.
- Comparisons with `aws_smithy_types::Blob::new(x)` become comparisons with `x` (`Plaintext` and `Ciphertext` implement `PartialEq<[u8]>`, `PartialEq<&[u8]>`, `PartialEq<Vec<u8>>`).
- `.frame_length(n)` takes `NonZeroU32`.

### Keyrings, key store, caches

- `mpl.create_raw_aes_keyring()...send().await?` becomes `RawAesKeyring::builder()...build()?` (not async). Setters are the same.
- `mpl.create_aws_kms_hierarchical_keyring()...send().await?` becomes `HierarchicalKeyring::builder()...build().await?`.
  - `.ttl_seconds(n)` becomes `.ttl(Duration::from_secs(n))`. Zero is an error.
  - `.cache(CacheType::Shared(r))` becomes `.cache(cmc.clone())`. Clones share one cache.
- `keystore_client::Client::from_conf(KeyStoreConfig::builder()...build()?)?` becomes `key_store::DynamoDbKeyStore::builder()...build().await?` (async). Setters are the same; `KmsKeyArn(s.to_string())` can be `KmsKeyArn(s.into())`.
- `key_store.create_key().send().await?.branch_key_identifier.unwrap()` becomes `.send().await?.into_branch_key_id()`.
- `key_store.version_key().branch_key_identifier(id)` becomes `.version_key().branch_key_id(id)`.
- `mpl.create_cryptographic_materials_cache().cache(CacheType::Default(DefaultCache::builder().entry_capacity(n).build()?)).send().await?` becomes `DefaultCmc::builder().entry_capacity(n).build()?`.
- `mpl.create_default_cryptographic_materials_manager().keyring(k).send().await?` becomes `DefaultCmm::new(k)`.

### Custom keyrings, CMMs, branch key suppliers

| 1.x trait | 2.x trait |
|---|---|
| `Keyring` | `aws_esdk::keyring::Keyring` |
| `CryptographicMaterialsManager` | `aws_esdk::cmm::Cmm` |
| `BranchKeyIdSupplier` | `aws_esdk::keyring::BranchKeySupplier` |

- Add `#[aws_esdk::async_trait]` to the impl and make each method `async fn`.
- Remove every `tokio::task::block_in_place(|| Handle::current().block_on(async { ... }))` and `.await` the inner future directly. A `#[tokio::test(flavor = "multi_thread")]` that existed only for `block_in_place` can become `#[tokio::test]`.
- Return `aws_esdk::mpl::Error`. Replace `Error::AwsCryptographicMaterialProvidersException { message }` with `MplError::validation("...")` (or the constructor for the real failure kind).
- Input fields become accessor methods, for example `input.encryption_context.unwrap()` becomes `input.encryption_context()`. An optional field's accessor still returns `Option`; check the 2.x signature.
- A 1.x CMM unwrapping `AlgorithmSuiteId::Esdk(id)` no longer needs to: CMM inputs carry the ESDK suite ID directly. Signing checks can use `id.has_asymmetric_signing()`.
- When delegating to an inner `DefaultCmm`, forward every input field with its `set_` setter; see `esdk/examples/custom_cmm.rs`.
- `GetBranchKeyIdOutput::builder().branch_key_id(s).build().unwrap()` becomes `s.as_str().into()`.
- Delete `XxxRef { inner: Arc::new(Mutex::new(x)) }` wrappers; pass `x` to `.keyring(x)` or `.cmm(x)`.

### Errors

Rewrite every match on 1.x error variants. 2.x `Error` is `#[non_exhaustive]`, so every `match` needs `_ =>`.

| Failure | 1.x (typical) | 2.x |
|---|---|---|
| bad input or config | `AwsEncryptionSdkException`, `AwsCryptographicMaterialProvidersException` | `Error::Validation` |
| no keyring decrypts a data key | `AwsCryptographicMaterialProvidersError { .. }` | `Error::NoMatchingDataKey` |
| encryption context mismatch | `AwsEncryptionSdkException` | `Error::EncryptionContextMismatch` |
| tag or signature fails | `AwsEncryptionSdkException` | `Error::Cryptographic` |
| malformed message | `AwsEncryptionSdkException` | `Error::Serialization` |
| AWS call failed | wrapped in `AwsCryptographicMaterialProvidersError` | `AccessDenied`, `Throttling`, `ResourceNotFound`, `Service`, `Dispatch`, `Conflict` |

Never match on message text in the migrated code. Use the variant and `is_retryable()`, `resource()`, `service()`.
If the 1.x code matched message strings, rewrite it to variants and say so in the report.

## Behavior changes to report

For each one, say whether this codebase can hit it, and where.

1. **ESDK-NET v4.0.0 messages no longer decrypt.** 1.x retried a failed header check the ESDK-NET v4.0.0 way by default (`ALLOW_RETRY`). 2.x has no retry and rejects those messages. Applies if the application may decrypt messages written by ESDK for .NET v4.0.0. The fix is to decrypt and re-encrypt those messages with 1.x before switching.
2. **Error variants changed.** Code that handled `AwsEncryptionSdkException` / `AwsCryptographicMaterialProvidersError` now sees specific variants. Check that retry, alerting, and fallback logic still fire for the same failures. Example: wrong hierarchical keyring on decrypt was `AwsCryptographicMaterialProvidersError`, now `Error::NoMatchingDataKey`.
3. **`decrypt_stream` writes unverified plaintext.** Only if the migration introduces streaming. The caller must not act on output until `send` returns `Ok`, and must discard it on `Err`. By default it rejects multi-frame signed messages.
4. **`encryption_context` setter adds a pair.** This is a compile error when a map is passed, not a silent change. Mention it only if you rewrote such a call.

## Do not

- Do not mark the migration done while `cargo build` or `cargo test` fails.
- Do not replace a blocker keyring with a different keyring. Changing which keys protect data changes who can decrypt it.
- Do not change the commitment policy, algorithm suite, or encryption context values. Migrate them as they are.
- Do not delete tests that fail after migration; fix the code or report why.
