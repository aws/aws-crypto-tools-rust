// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

//! The caching CMM.
//!
//! The Dafny MPL has no caching CMM, so this follows the ESDK specification
//! (`spec/framework/caching-cmm.md`) and the Python ESDK's
//! `materials_managers/caching.py` where the specification is silent.

use std::borrow::Cow;
use std::sync::Arc;
use std::time::{Duration, SystemTime};

use async_trait::async_trait;
use aws_mpl_primitives::{DigestAlg, digest};

use super::{
    Cmm, DecryptMaterialsInput, DecryptMaterialsOutput, DefaultCmm, GetEncryptionMaterialsInput,
    GetEncryptionMaterialsOutput, SharedCmm,
};
use crate::Error;
use crate::cmc::entry::{BytesUsage, MessageUsage, UsageMetadata};
use crate::cmc::{CacheEntry, CachedMaterials, SharedCmc};
use crate::error::Kind;
use crate::keyring::SharedKeyring;
use crate::shared::IntoShared;
use crate::structures::{
    AlgorithmSuiteId, DecryptionMaterials, EncryptedDataKey, EncryptionContext,
    EncryptionMaterials, KeyDerivationAlgorithm,
};

const SHA512_LEN: usize = DigestAlg::Sha512.output_len();

/// The default and largest [`limit_bytes`](CachingCmmBuilder::limit_bytes): 2^63 - 1.
pub const MAX_LIMIT_BYTES: u64 = i64::MAX.unsigned_abs();

/// The default and largest [`limit_messages`](CachingCmmBuilder::limit_messages): 2^32.
pub const MAX_LIMIT_MESSAGES: u64 = 1 << 32;

/// A CMM that wraps another CMM and caches the materials it returns.
///
/// Reusing a data key saves calls to the key provider.
/// Encryption materials are reused until the entry is older than the TTL,
/// or encrypting another message would exceed the message or byte limit.
/// Suites without a key derivation function are never cached.
///
/// An encrypt request of unknown plaintext length, or longer than the byte limit,
/// bypasses the cache, as in the Python ESDK.
///
/// ```
/// use std::time::Duration;
/// use aws_crypto_mpl::cmc::LocalCmc;
/// use aws_crypto_mpl::cmm::CachingCmm;
/// use aws_crypto_mpl::keyring::RawAesKeyring;
/// use aws_crypto_mpl::types::AesWrappingAlg;
///
/// # fn main() -> Result<(), aws_crypto_mpl::Error> {
/// let keyring = RawAesKeyring::builder()
///     .key_namespace("ns")
///     .key_name("name")
///     .wrapping_key(vec![1u8; 32])
///     .wrapping_alg(AesWrappingAlg::AlgAes256GcmIv12Tag16)
///     .build()?;
/// let cmm = CachingCmm::builder()
///     .keyring(keyring)
///     .cache(LocalCmc::builder().entry_capacity(100).build()?)
///     .cache_limit_ttl(Duration::from_secs(60))
///     .limit_messages(10)
///     .build()?;
/// # Ok(())
/// # }
/// ```
#[derive(Clone, Debug)]
pub struct CachingCmm {
    inner: Arc<Inner>,
}

#[derive(Debug)]
struct Inner {
    underlying_cmm: SharedCmm,
    cache: SharedCmc,
    ttl: Duration,
    partition_id: String,
    partition_hash: [u8; SHA512_LEN],
    limit_bytes: u64,
    limit_messages: u64,
}

impl CachingCmm {
    /// `"caching"`.
    #[must_use]
    pub fn name(&self) -> Cow<'_, str> {
        Cow::Borrowed("caching")
    }

    /// Start a builder.
    #[must_use]
    pub fn builder() -> CachingCmmBuilder {
        CachingCmmBuilder::default()
    }

    /// The partition ID mixed into every cache identifier.
    #[must_use]
    pub fn partition_id(&self) -> &str {
        &self.inner.partition_id
    }

    /// How long a cached entry may be used.
    #[must_use]
    pub fn cache_limit_ttl(&self) -> Duration {
        self.inner.ttl
    }

    /// The most plaintext bytes one cached data key may encrypt.
    #[must_use]
    pub fn limit_bytes(&self) -> u64 {
        self.inner.limit_bytes
    }

    /// The most messages one cached data key may encrypt.
    #[must_use]
    pub fn limit_messages(&self) -> u64 {
        self.inner.limit_messages
    }
}

/// Builder for [`CachingCmm`].
#[derive(Clone, Debug, Default)]
#[non_exhaustive]
pub struct CachingCmmBuilder {
    underlying_cmm: Option<SharedCmm>,
    keyring: Option<SharedKeyring>,
    cache: Option<SharedCmc>,
    cache_limit_ttl: Option<Duration>,
    partition_id: Option<String>,
    limit_bytes: Option<u64>,
    limit_messages: Option<u64>,
}

impl CachingCmmBuilder {
    /// Set the CMM to call on a cache miss.
    /// Set this or [`keyring`](Self::keyring), not both.
    #[must_use]
    pub fn underlying_cmm(mut self, cmm: impl IntoShared<SharedCmm>) -> Self {
        self.underlying_cmm = Some(cmm.into_shared());
        self
    }

    /// Set or clear the underlying CMM from an `Option`.
    #[must_use]
    pub fn set_underlying_cmm(mut self, cmm: Option<SharedCmm>) -> Self {
        self.underlying_cmm = cmm;
        self
    }

    /// Set a keyring; the CMM calls a [`DefaultCmm`] over it on a cache miss.
    /// Set this or [`underlying_cmm`](Self::underlying_cmm), not both.
    #[must_use]
    pub fn keyring(mut self, keyring: impl IntoShared<SharedKeyring>) -> Self {
        self.keyring = Some(keyring.into_shared());
        self
    }

    /// Set or clear the keyring from an `Option`.
    #[must_use]
    pub fn set_keyring(mut self, keyring: Option<SharedKeyring>) -> Self {
        self.keyring = keyring;
        self
    }

    /// Set the cache that holds the materials.
    /// Required.
    ///
    /// Caching CMMs that share a cache share entries only when their partition IDs are equal.
    #[must_use]
    pub fn cache(mut self, cache: impl IntoShared<SharedCmc>) -> Self {
        self.cache = Some(cache.into_shared());
        self
    }

    /// Set or clear the cache from an `Option`.
    #[must_use]
    pub fn set_cache(mut self, cache: Option<SharedCmc>) -> Self {
        self.cache = cache;
        self
    }

    /// Set how long a cached entry may be used.
    /// Required, and must be greater than zero.
    #[must_use]
    pub fn cache_limit_ttl(mut self, ttl: Duration) -> Self {
        self.cache_limit_ttl = Some(ttl);
        self
    }

    /// Set or clear the TTL from an `Option`.
    #[must_use]
    pub fn set_cache_limit_ttl(mut self, ttl: Option<Duration>) -> Self {
        self.cache_limit_ttl = ttl;
        self
    }

    /// Set the partition ID.
    /// Defaults to a random UUID, so the CMM uses no other CMM's entries.
    #[must_use]
    pub fn partition_id(mut self, partition_id: impl Into<String>) -> Self {
        self.partition_id = Some(partition_id.into());
        self
    }

    /// Set or clear the partition ID from an `Option`.
    #[must_use]
    pub fn set_partition_id(mut self, partition_id: Option<String>) -> Self {
        self.partition_id = partition_id;
        self
    }

    /// Set the most plaintext bytes one cached data key may encrypt.
    /// Defaults to, and must not exceed, [`MAX_LIMIT_BYTES`].
    #[must_use]
    pub fn limit_bytes(mut self, limit_bytes: u64) -> Self {
        self.limit_bytes = Some(limit_bytes);
        self
    }

    /// Set or clear the byte limit from an `Option`.
    #[must_use]
    pub fn set_limit_bytes(mut self, limit_bytes: Option<u64>) -> Self {
        self.limit_bytes = limit_bytes;
        self
    }

    /// Set the most messages one cached data key may encrypt.
    /// Defaults to [`MAX_LIMIT_MESSAGES`]; must be from 1 to that value.
    #[must_use]
    pub fn limit_messages(mut self, limit_messages: u64) -> Self {
        self.limit_messages = Some(limit_messages);
        self
    }

    /// Set or clear the message limit from an `Option`.
    #[must_use]
    pub fn set_limit_messages(mut self, limit_messages: Option<u64>) -> Self {
        self.limit_messages = limit_messages;
        self
    }

    /// Build the CMM.
    ///
    /// # Errors
    ///
    /// - [`Validation`](crate::Error::Validation): the cache or TTL is unset, the TTL is zero,
    ///   neither or both of the underlying CMM and keyring are set,
    ///   or a limit is out of range.
    pub fn build(self) -> Result<CachingCmm, Error> {
        //= spec/framework/caching-cmm.md#initialization
        //# Additionally, the caller MUST provide one of the following values:
        let underlying_cmm = match (self.underlying_cmm, self.keyring) {
            (Some(cmm), None) => cmm,
            //= spec/framework/caching-cmm.md#initialization
            //# If the caller provides a keyring,
            //# then the caching CMM MUST set its underlying CMM
            //# to a [default CMM](default-cmm.md) initialized with the keyring.
            (None, Some(keyring)) => SharedCmm::new(DefaultCmm::new(keyring)),
            _ => {
                return Err(Error::new(
                    Kind::Validation,
                    "the caching CMM needs exactly one of underlying_cmm and keyring",
                ));
            }
        };
        let Some(cache) = self.cache else {
            return Err(Error::new(Kind::Validation, "cache is required"));
        };
        //= spec/framework/caching-cmm.md#cache-limit-ttl
        //# This value must be greater than zero.
        let ttl = match self.cache_limit_ttl {
            Some(ttl) if !ttl.is_zero() => ttl,
            Some(_) => {
                return Err(Error::new(
                    Kind::Validation,
                    "cache_limit_ttl must be greater than zero",
                ));
            }
            None => return Err(Error::new(Kind::Validation, "cache_limit_ttl is required")),
        };
        //= spec/framework/caching-cmm.md#limit-bytes
        //# If this parameter is not set, the caching CMM MUST set it to a value no more than 2^63-1.
        let limit_bytes = self.limit_bytes.unwrap_or(MAX_LIMIT_BYTES);
        if limit_bytes > MAX_LIMIT_BYTES {
            return Err(Error::new(
                Kind::Validation,
                format!("limit_bytes must be at most {MAX_LIMIT_BYTES}, got {limit_bytes}"),
            ));
        }
        //= spec/framework/caching-cmm.md#limit-messages
        //# If this parameter is not set, the caching CMM MUST set it to 2^32.
        let limit_messages = self.limit_messages.unwrap_or(MAX_LIMIT_MESSAGES);
        if limit_messages == 0 || limit_messages > MAX_LIMIT_MESSAGES {
            return Err(Error::new(
                Kind::Validation,
                format!(
                    "limit_messages must be from 1 to {MAX_LIMIT_MESSAGES}, got {limit_messages}"
                ),
            ));
        }
        //= spec/framework/caching-cmm.md#partition-id
        //# If this parameter is not set, the caching CMM MUST set a partition ID
        //# that uniquely identifies the respective caching CMM.
        let partition_id = self
            .partition_id
            .unwrap_or_else(|| uuid::Uuid::new_v4().to_string());
        let partition_hash = sha512(partition_id.as_bytes());
        Ok(CachingCmm {
            inner: Arc::new(Inner {
                underlying_cmm,
                cache,
                ttl,
                partition_id,
                partition_hash,
                limit_bytes,
                limit_messages,
            }),
        })
    }
}

fn sha512(data: &[u8]) -> [u8; SHA512_LEN] {
    let mut out = [0u8; SHA512_LEN];
    digest(DigestAlg::Sha512, data, &mut out).expect("output is exactly SHA-512 length");
    out
}

fn has_identity_kdf(id: AlgorithmSuiteId) -> bool {
    id.specification().encryption_kdf() == KeyDerivationAlgorithm::IdentityKdf
}

fn length_prefixed(out: &mut Vec<u8>, field: &[u8], what: &str) -> Result<(), Error> {
    let Ok(len) = u16::try_from(field.len()) else {
        return Err(Error::new(
            Kind::Validation,
            format!(
                "encrypted data key {what} is longer than {} bytes",
                u16::MAX
            ),
        ));
    };
    out.extend_from_slice(&len.to_be_bytes());
    out.extend_from_slice(field);
    Ok(())
}

/// An encrypted data key in the message header's encrypted data key entry format.
fn serialize_edk(edk: &EncryptedDataKey) -> Result<Vec<u8>, Error> {
    let mut out = Vec::new();
    length_prefixed(&mut out, edk.key_provider_id().as_bytes(), "provider ID")?;
    length_prefixed(&mut out, edk.key_provider_info(), "provider info")?;
    length_prefixed(&mut out, edk.ciphertext(), "ciphertext")?;
    Ok(out)
}

impl Inner {
    fn encrypt_cache_id(
        &self,
        suite: Option<AlgorithmSuiteId>,
        ec: &EncryptionContext,
    ) -> Result<Vec<u8>, Error> {
        let mut buf = Vec::with_capacity(3 * SHA512_LEN + 3);
        buf.extend_from_slice(&self.partition_hash);
        match suite {
            //= spec/framework/caching-cmm.md#encryption-materials-without-algorithm-suite
            //# If the Get Encryption Materials request does not specify an algorithm suite,
            //# then the cache entry identifier MUST be calculated
            //# as the SHA-512 hash of the concatenation of the following byte strings,
            //# in the order listed:
            None => buf.push(0x00),
            //= spec/framework/caching-cmm.md#encryption-materials-with-algorithm-suite
            //# If the Get Encryption Materials request does specify an algorithm suite,
            //# then the cache entry identifier MUST be calculated
            //# as the SHA-512 hash of the concatenation of the following byte strings,
            //# in the order listed:
            Some(id) => {
                buf.push(0x01);
                buf.extend_from_slice(&id.id_bytes());
            }
        }
        buf.extend_from_slice(&sha512(&ec.serialize()?));
        Ok(sha512(&buf).to_vec())
    }

    //= spec/framework/caching-cmm.md#decryption-materials
    //# When the caching CMM receives a Decrypt Materials request,
    //# it MUST calculate the cache entry identifier as
    //# the SHA-512 hash of the concatenation of the following byte strings,
    //# in the order listed:
    fn decrypt_cache_id(&self, input: &DecryptMaterialsInput) -> Result<Vec<u8>, Error> {
        let mut edk_hashes = input
            .encrypted_data_keys()
            .iter()
            .map(|edk| serialize_edk(edk).map(|bytes| sha512(&bytes)))
            .collect::<Result<Vec<_>, _>>()?;
        edk_hashes.sort_unstable();
        let mut buf = Vec::with_capacity((edk_hashes.len() + 3) * SHA512_LEN + 2);
        buf.extend_from_slice(&self.partition_hash);
        buf.extend_from_slice(&input.algorithm_suite_id().id_bytes());
        for hash in &edk_hashes {
            buf.extend_from_slice(hash);
        }
        buf.extend_from_slice(&[0u8; SHA512_LEN]);
        buf.extend_from_slice(&sha512(&input.encryption_context().serialize()?));
        Ok(sha512(&buf).to_vec())
    }

    fn exceeds_limits(&self, entry: &CacheEntry) -> bool {
        let usage = entry.usage_metadata();
        let age = SystemTime::now()
            .duration_since(entry.creation_time())
            .unwrap_or_default();
        age > self.ttl
            || usage.messages_used().get() > self.limit_messages
            || usage.bytes_used().get() > self.limit_bytes
    }

    async fn put(
        &self,
        id: Vec<u8>,
        materials: CachedMaterials,
        usage: UsageMetadata,
    ) -> Result<(), Error> {
        let now = SystemTime::now();
        //= spec/framework/caching-cmm.md#cache-limit-ttl
        //# The Caching CMM MUST set a time-to-live (TTL) for data keys in the CMC.
        let entry = CacheEntry::builder()
            .materials(materials)
            .creation_time(now)
            .expiry_time(now + self.ttl)
            .usage_metadata(usage)
            .build()?;
        self.cache
            .put_cache_entry()
            .identifier(id)
            .entry(entry)
            .send()
            .await?;
        Ok(())
    }

    /// Cached encryption materials for `id`, counting this message against them.
    /// `None` when the entry is missing or used up.
    async fn cached_encryption_materials(
        &self,
        id: &[u8],
        bytes: u64,
        input: &GetEncryptionMaterialsInput,
    ) -> Result<Option<EncryptionMaterials>, Error> {
        let Some(entry) = self
            .cache
            .get_cache_entry()
            .identifier(id)
            .send()
            .await?
            .into_entry()
        else {
            return Ok(None);
        };
        let CachedMaterials::Encryption(materials) = entry.materials() else {
            return Ok(None);
        };
        // Materials cached for different required keys would change which
        // encryption context pairs the message stores.
        if materials.required_encryption_context_keys() != input.required_encryption_context_keys()
        {
            return Ok(None);
        }
        //= spec/framework/caching-cmm.md#usage-stats
        //# When the caching CMM obtains encryption materials from the cryptographic materials cache,
        //# the caching CMM MUST update the usage stats for the cache entry retrieved.
        self.cache
            .update_usage_metadata()
            .identifier(id)
            .bytes_used(bytes)
            .send()
            .await?;
        if self.exceeds_limits(&entry) {
            self.cache
                .delete_cache_entry()
                .identifier(id)
                .send()
                .await?;
            return Ok(None);
        }
        Ok(Some(materials.clone()))
    }

    /// Cached decryption materials for `id`, if the request's reproduced
    /// encryption context matches the one they were made for.
    async fn cached_decryption_materials(
        &self,
        id: &[u8],
        input: &DecryptMaterialsInput,
    ) -> Result<Option<DecryptionMaterials>, Error> {
        let Some(entry) = self
            .cache
            .get_cache_entry()
            .identifier(id)
            .send()
            .await?
            .into_entry()
        else {
            return Ok(None);
        };
        let CachedMaterials::Decryption(materials) = entry.materials() else {
            return Ok(None);
        };
        // The cache identifier omits the reproduced encryption context, which
        // the underlying CMM checks and merges into the materials. A hit must
        // give the materials that CMM would have returned for this request.
        let ec = materials.encryption_context();
        let empty = EncryptionContext::default();
        let reproduced = input.reproduced_encryption_context().unwrap_or(&empty);
        let reproduced_matches = reproduced.iter().all(|(k, v)| ec.get(k) == Some(v));
        let required_supplied = materials
            .required_encryption_context_keys()
            .iter()
            .all(|k| reproduced.get(k).is_some() && reproduced.get(k) == ec.get(k));
        if !reproduced_matches || !required_supplied {
            return Ok(None);
        }
        Ok(Some(materials.clone()))
    }
}

#[async_trait]
impl Cmm for crate::shared::Builtin<CachingCmm> {
    fn name(&self) -> Cow<'_, str> {
        self.0.name()
    }

    async fn get_encryption_materials(
        &self,
        mut input: GetEncryptionMaterialsInput,
    ) -> Result<GetEncryptionMaterialsOutput, Error> {
        let inner = &self.0.inner;
        //= spec/framework/caching-cmm.md#get-encryption-materials
        //# If the [algorithm suite](algorithm-suites.md) requested contains a [Identity KDF](algorithm-suites.md#identity-kdf),
        //# the caching CMM MUST obtain the encryption materials by making a call to the underlying CMM's [Get Encryption Materials](cmm-interface.md#get-encryption-materials) function.
        if input.algorithm_suite_id().is_some_and(has_identity_kdf) {
            return Cmm::get_encryption_materials(&*inner.underlying_cmm.0, input).await;
        }
        // Like the Python ESDK, count usage only against a known length,
        // and never cache for a message that alone exceeds the byte limit.
        let bytes = match input.max_plaintext_length() {
            Some(bytes) if bytes <= inner.limit_bytes => bytes,
            _ => return Cmm::get_encryption_materials(&*inner.underlying_cmm.0, input).await,
        };

        //= spec/framework/caching-cmm.md#get-encryption-materials
        //# The caching CMM MUST use the formulas specified in [Appendix A](#appendix-a-cache-entry-identifier-formulas)
        //# in order to compute the [cache entry identifier](cryptographic-materials-cache.md#cache-identifier).
        let id = inner.encrypt_cache_id(input.algorithm_suite_id(), input.encryption_context())?;
        //= spec/framework/caching-cmm.md#get-encryption-materials
        //# If a cache entry is found, the caching CMM MUST return the encryption materials retrieved.
        if let Some(materials) = inner
            .cached_encryption_materials(&id, bytes, &input)
            .await?
        {
            return Ok(materials.into());
        }

        //= spec/framework/caching-cmm.md#get-encryption-materials
        //# If a cache entry is not found or the cache entry is expired, the caching CMM MUST then attempt to obtain the encryption materials
        //# by making a call to the underlying CMM's [Get Encryption Materials](cmm-interface.md#get-encryption-materials).
        // The materials may encrypt other messages, so the underlying CMM
        // does not see this message's length.
        input.max_plaintext_length = None;
        let output = Cmm::get_encryption_materials(&*inner.underlying_cmm.0, input).await?;
        let materials = output.encryption_materials();

        //= spec/framework/caching-cmm.md#get-encryption-materials
        //# If the [algorithm suite](algorithm-suites.md) requested contains an Identity KDF,
        //# the caching CMM MUST NOT store the encryption materials in the underlying CMC.
        if has_identity_kdf(materials.algorithm_suite_id()) {
            return Ok(output);
        }
        //= spec/framework/caching-cmm.md#usage-stats
        //# When the caching CMM stores encryption materials into the cryptographic materials cache,
        //# the caching CMM MUST set the initial usage stats for the cache entry.
        let usage = UsageMetadata::builder()
            .messages_used(MessageUsage::new(1))
            .bytes_used(BytesUsage::new(bytes))
            .build()?;
        //= spec/framework/caching-cmm.md#get-encryption-materials
        //# If the [algorithm suite](algorithm-suites.md) requested does not contain an [Identity KDF](algorithm-suites.md#identity-kdf),
        //# the caching CMM MUST add the encryption materials obtained from the underlying CMM into the underlying CMC.
        inner
            .put(id, CachedMaterials::Encryption(materials.clone()), usage)
            .await?;
        Ok(output)
    }

    async fn decrypt_materials(
        &self,
        input: DecryptMaterialsInput,
    ) -> Result<DecryptMaterialsOutput, Error> {
        let inner = &self.0.inner;
        //= spec/framework/caching-cmm.md#decrypt-materials
        //# If the [algorithm suite](algorithm-suites.md) requested contains a [Identity KDF](algorithm-suites.md#identity-kdf),
        //# the caching CMM MUST obtain the decryption materials by making a call to the underlying CMM's [Decrypt Materials](cmm-interface.md#decrypt-materials) function.
        //
        //= spec/framework/caching-cmm.md#decrypt-materials
        //# If the [algorithm suite](algorithm-suites.md) requested contains an Identity KDF,
        //# the caching CMM MUST NOT store the decryption materials in the underlying CMC.
        if has_identity_kdf(input.algorithm_suite_id()) {
            return Cmm::decrypt_materials(&*inner.underlying_cmm.0, input).await;
        }

        //= spec/framework/caching-cmm.md#decrypt-materials
        //# The caching CMM MUST use the formulas specified in [Appendix A](#appendix-a-cache-entry-identifier-formulas)
        //# in order to compute the [cache entry identifier](cryptographic-materials-cache.md#cache-identifier).
        let id = inner.decrypt_cache_id(&input)?;
        //= spec/framework/caching-cmm.md#decrypt-materials
        //# If a cache entry is found, the caching CMM MUST return the decryption materials retrieved.
        if let Some(materials) = inner.cached_decryption_materials(&id, &input).await? {
            return Ok(materials.into());
        }

        //= spec/framework/caching-cmm.md#decrypt-materials
        //# If a cache entry is not found or the cache entry is expired, the caching CMM MUST attempt to obtain the decryption materials
        //# by making a call to the underlying CMM's [Decrypt Materials](cmm-interface.md#decrypt-materials).
        let output = Cmm::decrypt_materials(&*inner.underlying_cmm.0, input).await?;
        //= spec/framework/caching-cmm.md#decrypt-materials
        //# If the [algorithm suite](algorithm-suites.md) requested does not contain an [Identity KDF](algorithm-suites.md#identity-kdf),
        //# the caching CMM MUST add the decryption materials obtained from the underlying CMM into the underlying CMC.
        inner
            .put(
                id,
                CachedMaterials::Decryption(output.decryption_materials().clone()),
                UsageMetadata::default(),
            )
            .await?;
        Ok(output)
    }
}
