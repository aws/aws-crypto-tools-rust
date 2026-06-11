// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

//! Caching CMM — a wrapper [`Cmm`] that memoizes materials by cache entry id.

use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use aws_lc_rs::digest::{Context, SHA384};
use aws_lc_rs::rand::{SecureRandom, SystemRandom};

use super::Cmm;
use super::cache::{CacheEntryId, CryptographicMaterialsCache, UsageStats};
use super::default_cmm::DefaultCmm;
use super::request::{DecryptMaterialsRequest, EncryptionMaterialsRequest};
use crate::keyring::Keyring;
use crate::structures::{
    AlgorithmSuiteId, DecryptionMaterials, EncryptedDataKey, EncryptionContext,
    EncryptionMaterials, KeyDerivationAlgorithm, MaterialsError,
};

// Cache identifier byte-format constants

/// Resource ID byte that identifies the Caching CMM in cache entry identifier
/// concatenations (Appendix A formulas).
//= ../spec/framework/caching-cmm.md#encryption-materials-without-algorithm-suite
//= type=implication
//# - MUST be the Resource ID for the Caching CMM (0x01)
//
//= ../spec/framework/caching-cmm.md#encryption-materials-with-algorithm-suite
//= type=implication
//# - MUST be the Resource ID for the Caching CMM (0x01)
//
//= ../spec/framework/caching-cmm.md#decryption-materials
//= type=implication
//# - MUST be the Resource ID for the Caching CMM (0x01)
const RESOURCE_ID_CACHING_CMM: u8 = 0x01;

/// Scope ID byte that identifies the Encrypt scope in cache entry identifier
/// concatenations.
//= ../spec/framework/caching-cmm.md#encryption-materials-without-algorithm-suite
//= type=implication
//# - MUST be the Scope ID for Encrypt (0x01)
//
//= ../spec/framework/caching-cmm.md#encryption-materials-with-algorithm-suite
//= type=implication
//# - MUST be the Scope ID for Encrypt (0x01)
const SCOPE_ID_ENCRYPT: u8 = 0x01;

/// Scope ID byte that identifies the Decrypt scope in cache entry identifier
/// concatenations.
//= ../spec/framework/caching-cmm.md#decryption-materials
//= type=implication
//# - MUST be the Scope ID for Decrypt (0x02)
const SCOPE_ID_DECRYPT: u8 = 0x02;

/// Algorithm Suite Hex byte that indicates "Encryption Materials Without
/// Algorithm Suite" in the encrypt-no-suite cache entry identifier formula.
//= ../spec/framework/caching-cmm.md#encryption-materials-without-algorithm-suite
//= type=implication
//# - MUST be the Algorithm Suite Hex byte `0x00` to indicate Encryption Materials Without Algorithm Suite
const NO_ALGORITHM_SUITE_INDICATOR: u8 = 0x00;

/// Algorithm Suite Hex byte that indicates "Encryption Materials With
/// Algorithm Suite" in the encrypt-with-suite cache entry identifier formula.
//= ../spec/framework/caching-cmm.md#encryption-materials-with-algorithm-suite
//= type=implication
//# - MUST be the Algorithm Suite Hex byte `0x01` to indicate Encryption Materials With Algorithm Suite
const WITH_ALGORITHM_SUITE_INDICATOR: u8 = 0x01;

/// The single-byte separator used between fields in cache entry identifier
/// concatenations.
const NULL_BYTE: u8 = 0x00;

// Default values for optional configuration parameters

/// Default `limit_bytes` value: `2^63 - 1` (the largest signed 64-bit integer).
/// The spec requires this default to be "no more than 2^63-1"; we pick the
/// maximum allowed value.
const DEFAULT_LIMIT_BYTES: u64 = i64::MAX as u64;

/// Default `limit_messages` value: `2^32`.
const DEFAULT_LIMIT_MESSAGES: u64 = 1u64 << 32;

/// Number of random bytes used to construct a default partition ID. 16 bytes
/// = 128 bits of entropy → collision probability between two CMMs is ~2^-64.
const PARTITION_ID_RANDOM_BYTES: usize = 16;

// CachingCmm

/// A [`Cmm`] that wraps an underlying CMM and memoizes its responses in a
/// [`CryptographicMaterialsCache`]. See `spec/framework/caching-cmm.md` for
/// the full behavior.
///
/// Construct via [`CachingCmm::new`] (when supplying an underlying CMM
/// directly) or [`CachingCmm::with_keyring`] (when supplying a keyring; the
/// caching CMM auto-wraps it in a [`DefaultCmm`]).
pub struct CachingCmm {
    underlying: Arc<dyn Cmm>,
    cmc: Arc<dyn CryptographicMaterialsCache>,
    ttl: Duration,
    //= ../spec/framework/caching-cmm.md#partition-id
    //= type=implication
    //# The Partition ID MUST NOT be changed after initialization.
    partition_id: String,
    //= ../spec/framework/caching-cmm.md#limit-bytes
    //= type=implication
    //# The maximum number of bytes that MAY be encrypted by a single data key.
    limit_bytes: u64,
    //= ../spec/framework/caching-cmm.md#limit-messages
    //= type=implication
    //# The maximum number of messages that MAY be encrypted by a single data key.
    limit_messages: u64,
}

impl CachingCmm {
    /// Construct a `CachingCmm` from an underlying CMM, a CMC, and a TTL.
    /// Optional configuration (partition ID, limit bytes, limit messages) may
    /// be supplied via the `with_*` builder methods; missing values default
    /// per the spec.
    //= ../spec/framework/caching-cmm.md#initialization
    //# On caching CMM initialization,
    //# the caller MUST provide the following values:
    //
    //= ../spec/framework/caching-cmm.md#initialization
    //# Additionally, the caller MUST provide one of the following values:
    pub fn new(
        cmc: Arc<dyn CryptographicMaterialsCache>,
        ttl: Duration,
        underlying: Arc<dyn Cmm>,
    ) -> Self {
        //= ../spec/framework/caching-cmm.md#underlying-cryptographic-materials-cache
        //= reason=Default partition_id is a fresh random string per CachingCmm; two CMMs sharing one CMC produce different cache ids and therefore cannot read each other's entries.
        //# Multiple caching CMMs MAY share the same cryptographic materials cache,
        //# but by default MUST NOT use each other's cache entries.
        //
        //= ../spec/framework/caching-cmm.md#partition-id
        //# If this parameter is not set, the caching CMM MUST set a partition ID
        //# that uniquely identifies the respective caching CMM.
        let partition_id = generate_unique_partition_id();

        Self {
            underlying,
            cmc,
            ttl,
            partition_id,
            //= ../spec/framework/caching-cmm.md#limit-bytes
            //# If this parameter is not set, the caching CMM MUST set it to a value no more than 2^63-1.
            limit_bytes: DEFAULT_LIMIT_BYTES,
            //= ../spec/framework/caching-cmm.md#limit-messages
            //# If this parameter is not set, the caching CMM MUST set it to 2^32.
            limit_messages: DEFAULT_LIMIT_MESSAGES,
        }
    }

    /// Construct a `CachingCmm` from a keyring rather than an underlying CMM.
    /// The caching CMM auto-wraps the keyring in a [`DefaultCmm`].
    pub fn with_keyring(
        cmc: Arc<dyn CryptographicMaterialsCache>,
        ttl: Duration,
        keyring: Arc<dyn Keyring>,
    ) -> Self {
        //= ../spec/framework/caching-cmm.md#initialization
        //# If the caller provides a keyring,
        //# then the caching CMM MUST set its underlying CMM
        //# to a [default CMM](default-cmm.md) initialized with the keyring.
        let underlying: Arc<dyn Cmm> = Arc::new(DefaultCmm::new(keyring));
        Self::new(cmc, ttl, underlying)
    }

    /// Override the partition ID (default: a per-CMM-unique random string).
    //= ../spec/framework/caching-cmm.md#initialization
    //# Finally, the caching CMM MUST optionally accept the following values:
    pub fn with_partition_id(mut self, partition_id: String) -> Self {
        self.partition_id = partition_id;
        self
    }

    /// Override the `limit_bytes` cap (default: `2^63 - 1`).
    pub fn with_limit_bytes(mut self, limit_bytes: u64) -> Self {
        self.limit_bytes = limit_bytes;
        self
    }

    /// Override the `limit_messages` cap (default: `2^32`).
    pub fn with_limit_messages(mut self, limit_messages: u64) -> Self {
        self.limit_messages = limit_messages;
        self
    }

    /// Returns the partition ID this CMM uses when computing cache entry identifiers.
    pub fn partition_id(&self) -> &str {
        &self.partition_id
    }

    /// Returns the configured `limit_bytes` threshold.
    pub fn limit_bytes(&self) -> u64 {
        self.limit_bytes
    }

    /// Returns the configured `limit_messages` threshold.
    pub fn limit_messages(&self) -> u64 {
        self.limit_messages
    }
}

// Cmm trait implementation

#[async_trait]
impl Cmm for CachingCmm {
    async fn get_encryption_materials(
        &self,
        request: EncryptionMaterialsRequest,
    ) -> Result<EncryptionMaterials, MaterialsError> {
        // Identity-KDF suites MUST bypass the cache entirely. Detection uses
        // the resolved suite (or, if unspecified, the policy's default).
        if has_identity_kdf_for_request(&request) {
            //= ../spec/framework/caching-cmm.md#get-encryption-materials
            //# If the [algorithm suite](algorithm-suites.md) requested contains a [Identity KDF](algorithm-suites.md#identity-kdf),
            //# the caching CMM MUST obtain the encryption materials by making a call to the underlying CMM's [Get Encryption Materials](cmm-interface.md#get-encryption-materials) function.
            //
            //= ../spec/framework/caching-cmm.md#get-encryption-materials
            //= reason=Early-return short-circuits before any cmc.put_encrypt call; identity-KDF materials are never written to the CMC on this path.
            //# If the [algorithm suite](algorithm-suites.md) requested contains an Identity KDF,
            //# the caching CMM MUST NOT store the encryption materials in the underlying CMC.
            return self.underlying.get_encryption_materials(request).await;
        }

        //= ../spec/framework/caching-cmm.md#get-encryption-materials
        //# The caching CMM MUST use the formulas specified in [Appendix A](#appendix-a-cache-entry-identifier-formulas)
        //# in order to compute the [cache entry identifier](cryptographic-materials-cache.md#cache-identifier).
        let id = match request.algorithm_suite_id() {
            None => compute_cache_id_for_encrypt_no_suite(
                &self.partition_id,
                request.encryption_context(),
            )?,
            Some(suite) => compute_cache_id_for_encrypt_with_suite(
                &self.partition_id,
                suite,
                request.encryption_context(),
            )?,
        };

        //= ../spec/framework/caching-cmm.md#get-encryption-materials
        //# Otherwise, the caching CMM MUST attempt to find the [encryption materials](structures.md#encryption-materials)
        //# from the underlying [cryptographic materials cache (CMC)](#underlying-cryptographic-materials-cache).
        if let Some(cached) = self.cmc.get_encrypt(&id).await {
            //= ../spec/framework/caching-cmm.md#usage-stats
            //= reason=A cache hit consumes one message; bytes-encrypted is incremented by the caller-supplied plaintext length when known. Here we credit one message and zero bytes; bytes are credited as the caller observes plaintext volume.
            //# When the caching CMM obtains encryption materials from the cryptographic materials cache,
            //# the caching CMM MUST update the usage stats for the cache entry retrieved.
            self.cmc.update_usage_encrypt(&id, 1, 0).await;

            //= ../spec/framework/caching-cmm.md#get-encryption-materials
            //# If a cache entry is found, the caching CMM MUST return the encryption materials retrieved.
            return Ok(cached);
        }

        //= ../spec/framework/caching-cmm.md#get-encryption-materials
        //# If a cache entry is not found or the cache entry is expired, the caching CMM MUST then attempt to obtain the encryption materials
        //# by making a call to the underlying CMM's [Get Encryption Materials](cmm-interface.md#get-encryption-materials).
        let materials = self.underlying.get_encryption_materials(request).await?;

        //= ../spec/framework/caching-cmm.md#get-encryption-materials
        //# If the [algorithm suite](algorithm-suites.md) requested does not contain an [Identity KDF](algorithm-suites.md#identity-kdf),
        //# the caching CMM MUST add the encryption materials obtained from the underlying CMM into the underlying CMC.
        //
        //= ../spec/framework/caching-cmm.md#cache-limit-ttl
        //# The Caching CMM MUST set a time-to-live (TTL) for data keys in the CMC.
        //
        //= ../spec/framework/caching-cmm.md#usage-stats
        //# When the caching CMM stores encryption materials into the cryptographic materials cache,
        //# the caching CMM MUST set the initial usage stats for the cache entry.
        self.cmc
            .put_encrypt(&id, materials.clone(), UsageStats::default(), self.ttl)
            .await;

        Ok(materials)
    }

    async fn decrypt_materials(
        &self,
        request: DecryptMaterialsRequest,
    ) -> Result<DecryptionMaterials, MaterialsError> {
        let suite = request.algorithm_suite_id();
        if has_identity_kdf(suite) {
            //= ../spec/framework/caching-cmm.md#decrypt-materials
            //# If the [algorithm suite](algorithm-suites.md) requested contains a [Identity KDF](algorithm-suites.md#identity-kdf),
            //# the caching CMM MUST obtain the decryption materials by making a call to the underlying CMM's [Decrypt Materials](cmm-interface.md#decrypt-materials) function.
            //
            //= ../spec/framework/caching-cmm.md#decrypt-materials
            //= reason=Early-return short-circuits before any cmc.put_decrypt call; identity-KDF materials are never written to the CMC on this path.
            //# If the [algorithm suite](algorithm-suites.md) requested contains an Identity KDF,
            //# the caching CMM MUST NOT store the decryption materials in the underlying CMC.
            return self.underlying.decrypt_materials(request).await;
        }

        //= ../spec/framework/caching-cmm.md#decrypt-materials
        //# The caching CMM MUST use the formulas specified in [Appendix A](#appendix-a-cache-entry-identifier-formulas)
        //# in order to compute the [cache entry identifier](cryptographic-materials-cache.md#cache-identifier).
        let id = compute_cache_id_for_decrypt(
            &self.partition_id,
            suite,
            request.encrypted_data_keys(),
            request.encryption_context(),
        )?;

        //= ../spec/framework/caching-cmm.md#decrypt-materials
        //# Otherwise, the caching CMM MUST attempt to find the [decryption materials](structures.md#decryption-materials)
        //# from the [underlying CMC](#underlying-cryptographic-materials-cache).
        if let Some(cached) = self.cmc.get_decrypt(&id).await {
            //= ../spec/framework/caching-cmm.md#decrypt-materials
            //# If a cache entry is found, the caching CMM MUST return the decryption materials retrieved.
            return Ok(cached);
        }

        //= ../spec/framework/caching-cmm.md#decrypt-materials
        //# If a cache entry is not found or the cache entry is expired, the caching CMM MUST attempt to obtain the decryption materials
        //# by making a call to the underlying CMM's [Decrypt Materials](cmm-interface.md#decrypt-materials).
        let materials = self.underlying.decrypt_materials(request).await?;

        //= ../spec/framework/caching-cmm.md#decrypt-materials
        //# If the [algorithm suite](algorithm-suites.md) requested does not contain an [Identity KDF](algorithm-suites.md#identity-kdf),
        //# the caching CMM MUST add the decryption materials obtained from the underlying CMM into the underlying CMC.
        self.cmc.put_decrypt(&id, materials.clone(), self.ttl).await;

        Ok(materials)
    }
}

// Helpers

/// Returns `true` when the suite uses an Identity KDF.
fn has_identity_kdf(suite_id: AlgorithmSuiteId) -> bool {
    matches!(
        suite_id.specification().encryption_kdf(),
        KeyDerivationAlgorithm::IdentityKdf
    )
}

/// Resolve the suite for an encrypt request and ask whether it is Identity-KDF.
/// When the request omits the suite, the policy default is consulted.
fn has_identity_kdf_for_request(request: &EncryptionMaterialsRequest) -> bool {
    let resolved = match request.algorithm_suite_id() {
        Some(id) => id,
        None => request.commitment_policy().default_algorithm_suite_id(),
    };
    has_identity_kdf(resolved)
}

/// Generate a random partition ID by drawing 16 bytes from the system CSPRNG
/// and hex-encoding them. Two CachingCMMs constructed without explicit
/// partition IDs will produce different default partition IDs with collision
/// probability ~2^-64.
pub fn generate_unique_partition_id() -> String {
    let mut buf = [0u8; PARTITION_ID_RANDOM_BYTES];
    let rng = SystemRandom::new();
    rng.fill(&mut buf)
        .expect("CSPRNG failure during partition_id generation");
    let mut hex = String::with_capacity(PARTITION_ID_RANDOM_BYTES * 2);
    for b in &buf {
        hex.push_str(&format!("{b:02x}"));
    }
    hex
}

// ----------------------------------------------------------------------------
// Cache entry identifier formulas (Appendix A)
// ----------------------------------------------------------------------------

/// Finalize a cache entry identifier from the bytes accumulated by a per-formula builder.
//= ../spec/framework/caching-cmm.md#appendix-a-cache-entry-identifier-formulas
//# When accessing the underlying CMC,
//# the caching CMM MUST use the formulas specified in this appendix
//# in order to compute the [cache entry identifier](cryptographic-materials-cache.md#cache-identifier).
//
//= ../spec/framework/caching-cmm.md#resource-suffix
//= reason=Each compute_cache_id_for_* function appends Resource ID, Scope ID, Partition ID, and Resource Suffix separated by NULL_BYTE; finalize_cache_id then takes the SHA-384 of the concatenated buffer.
//# The aforementioned 4 definitions ([Resource Identifier](#resource-identifier),
//# [Scope Identifier](#scope-identifier), [Partition ID](#partition-id-1),
//# and [Resource Suffix](#resource-suffix)) MUST be appended together with the null byte,
//# 0x00, and the SHA384 of the result should be taken as the final cache identifier.
fn finalize_cache_id(buf: &[u8]) -> CacheEntryId {
    let mut ctx = Context::new(&SHA384);
    ctx.update(buf);
    let digest = ctx.finish();
    let mut id = [0u8; 48];
    id.copy_from_slice(digest.as_ref());
    CacheEntryId(id)
}

/// Cache entry identifier formula for encrypt requests that DO NOT specify
/// an algorithm suite.
#[allow(clippy::vec_init_then_push)]
pub fn compute_cache_id_for_encrypt_no_suite(
    partition_id: &str,
    ec: &EncryptionContext,
) -> Result<CacheEntryId, MaterialsError> {
    //= ../spec/framework/caching-cmm.md#encryption-materials-without-algorithm-suite
    //# If the Get Encryption Materials request does not specify an algorithm suite,
    //# then the cache entry identifier MUST be calculated
    //# as the SHA-384 hash of the concatenation of the following byte strings,
    //# in the order listed:
    let mut buf: Vec<u8> = Vec::new();
    buf.push(RESOURCE_ID_CACHING_CMM);
    buf.push(NULL_BYTE);
    buf.push(SCOPE_ID_ENCRYPT);
    buf.push(NULL_BYTE);

    //= ../spec/framework/caching-cmm.md#encryption-materials-without-algorithm-suite
    //= type=implication
    //# - MUST be the UTF-8 encoding of the caching CMM’s Partition ID
    buf.extend_from_slice(partition_id.as_bytes());
    buf.push(NULL_BYTE);

    buf.push(NO_ALGORITHM_SUITE_INDICATOR);
    buf.push(NULL_BYTE);

    //= ../spec/framework/caching-cmm.md#encryption-materials-without-algorithm-suite
    //# - MUST be the serialized encryption context
    buf.extend_from_slice(&ec.serialize()?);

    Ok(finalize_cache_id(&buf))
}

/// Cache entry identifier formula for encrypt requests that DO specify an
/// algorithm suite.
#[allow(clippy::vec_init_then_push)]
pub fn compute_cache_id_for_encrypt_with_suite(
    partition_id: &str,
    suite: AlgorithmSuiteId,
    ec: &EncryptionContext,
) -> Result<CacheEntryId, MaterialsError> {
    //= ../spec/framework/caching-cmm.md#encryption-materials-with-algorithm-suite
    //# If the Get Encryption Materials request does specify an algorithm suite,
    //# then the cache entry identifier MUST be calculated
    //# as the SHA-384 hash of the concatenation of the following byte strings,
    //# in the order listed:
    let mut buf: Vec<u8> = Vec::new();
    buf.push(RESOURCE_ID_CACHING_CMM);
    buf.push(NULL_BYTE);
    buf.push(SCOPE_ID_ENCRYPT);
    buf.push(NULL_BYTE);

    //= ../spec/framework/caching-cmm.md#encryption-materials-with-algorithm-suite
    //= type=implication
    //# - MUST be the UTF-8 encoding of the caching CMM’s Partition ID
    buf.extend_from_slice(partition_id.as_bytes());
    buf.push(NULL_BYTE);

    buf.push(WITH_ALGORITHM_SUITE_INDICATOR);
    buf.push(NULL_BYTE);

    //= ../spec/framework/caching-cmm.md#encryption-materials-with-algorithm-suite
    //= type=implication
    //# - MUST be the two-byte Algorithm Suite ID corresponding to the algorithm suite in the request
    buf.extend_from_slice(&suite.id_bytes());
    buf.push(NULL_BYTE);

    //= ../spec/framework/caching-cmm.md#encryption-materials-with-algorithm-suite
    //# - MUST be the serialized encryption context
    buf.extend_from_slice(&ec.serialize()?);

    Ok(finalize_cache_id(&buf))
}

/// Cache entry identifier formula for decrypt requests.
#[allow(clippy::vec_init_then_push)]
pub fn compute_cache_id_for_decrypt(
    partition_id: &str,
    suite: AlgorithmSuiteId,
    edks: &[EncryptedDataKey],
    ec: &EncryptionContext,
) -> Result<CacheEntryId, MaterialsError> {
    //= ../spec/framework/caching-cmm.md#decryption-materials
    //# When the caching CMM receives a Decrypt Materials request,
    //# it MUST calculate the cache entry identifier as
    //# the SHA-384 hash of the concatenation of the following byte strings,
    //# in the order listed:
    let mut buf: Vec<u8> = Vec::new();
    buf.push(RESOURCE_ID_CACHING_CMM);
    buf.push(NULL_BYTE);
    buf.push(SCOPE_ID_DECRYPT);
    buf.push(NULL_BYTE);

    //= ../spec/framework/caching-cmm.md#decryption-materials
    //= type=implication
    //# - MUST be the UTF-8 encoding of the caching CMM’s Partition ID
    buf.extend_from_slice(partition_id.as_bytes());
    buf.push(NULL_BYTE);

    //= ../spec/framework/caching-cmm.md#decryption-materials
    //= type=implication
    //# - MUST be the two-byte Algorithm Suite ID corresponding to the algorithm suite in the request
    buf.extend_from_slice(&suite.id_bytes());
    buf.push(NULL_BYTE);

    // Serialize each EDK in the message-header wire shape, then sort the
    // serialized blobs lexicographically (Vec<u8>'s default Ord is lex-byte
    // ordering) and concatenate.
    let mut serialized_edks: Vec<Vec<u8>> = edks
        .iter()
        .map(serialize_edk_for_cache_id)
        .collect::<Result<Vec<_>, _>>()?;
    serialized_edks.sort();

    //= ../spec/framework/caching-cmm.md#decryption-materials
    //# - MUST be the concatenation of the lexicographically-sorted serialized encrypted data keys,
    //# where serialization is as defined in the [Encrypted Data Key Entries specification](../data-format/message-header.md#encrypted-data-key-entries).
    for edk_bytes in &serialized_edks {
        buf.extend_from_slice(edk_bytes);
    }
    buf.push(NULL_BYTE);

    //= ../spec/framework/caching-cmm.md#decryption-materials
    //# - MUST be the serialized encryption context
    buf.extend_from_slice(&ec.serialize()?);

    Ok(finalize_cache_id(&buf))
}

/// Serialize a single EDK in the wire shape defined by
/// `data-format/message-header.md#encrypted-data-key-entries`:
///   key_provider_id_len: u16 BE, key_provider_id (UTF-8 bytes),
///   key_provider_info_len: u16 BE, key_provider_info,
///   ciphertext_len: u16 BE, ciphertext.
pub fn serialize_edk_for_cache_id(edk: &EncryptedDataKey) -> Result<Vec<u8>, MaterialsError> {
    let pid_bytes = edk.key_provider_id.as_bytes();
    let info_bytes = &edk.key_provider_info[..];
    let ct_bytes = &edk.ciphertext[..];

    let Ok(pid_len) = u16::try_from(pid_bytes.len()) else {
        return Err(MaterialsError::new(format!(
            "EDK key_provider_id length {} exceeds u16::MAX",
            pid_bytes.len()
        )));
    };
    let Ok(info_len) = u16::try_from(info_bytes.len()) else {
        return Err(MaterialsError::new(format!(
            "EDK key_provider_info length {} exceeds u16::MAX",
            info_bytes.len()
        )));
    };
    let Ok(ct_len) = u16::try_from(ct_bytes.len()) else {
        return Err(MaterialsError::new(format!(
            "EDK ciphertext length {} exceeds u16::MAX",
            ct_bytes.len()
        )));
    };

    let mut out =
        Vec::with_capacity(2 + pid_bytes.len() + 2 + info_bytes.len() + 2 + ct_bytes.len());
    out.extend_from_slice(&pid_len.to_be_bytes());
    out.extend_from_slice(pid_bytes);
    out.extend_from_slice(&info_len.to_be_bytes());
    out.extend_from_slice(info_bytes);
    out.extend_from_slice(&ct_len.to_be_bytes());
    out.extend_from_slice(ct_bytes);
    Ok(out)
}

// Test-only re-exports

/// Internal helpers re-exported for integration tests under `tests/`. Not part
/// of the public API; do not depend on this module from production code.
#[doc(hidden)]
pub mod __test_internals {
    pub use super::{
        compute_cache_id_for_decrypt, compute_cache_id_for_encrypt_no_suite,
        compute_cache_id_for_encrypt_with_suite, generate_unique_partition_id,
        serialize_edk_for_cache_id,
    };
}
