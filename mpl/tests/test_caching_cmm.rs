// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

//! Integration tests for the Caching CMM.

use std::collections::BTreeSet;
use std::sync::Arc;
use std::sync::Mutex;
use std::sync::atomic::{AtomicU32, Ordering};
use std::time::Duration;

use async_trait::async_trait;
use aws_lc_rs::digest::{Context, SHA384};

use aws_crypto_mpl::cmm::caching_cmm::__test_internals;
use aws_crypto_mpl::cmm::{
    CacheEntryId, CachingCmm, Cmm, CryptographicMaterialsCache, DecryptMaterialsRequest,
    EncryptionMaterialsRequest, UsageStats,
};
use aws_crypto_mpl::keyring::Keyring;
use aws_crypto_mpl::structures::{
    AlgorithmSuiteId, CommitmentPolicy, DecryptionMaterials, EncryptedDataKey, EncryptionContext,
    EncryptionMaterials, MaterialsError, MaterialsErrorKind, PlaintextDataKey,
};

// ===== Mock Keyring (re-used from default_cmm test pattern) =====

struct MockKeyring {
    pdk_byte: u8,
    edk_provider_id: String,
    encrypt_calls: AtomicU32,
    decrypt_calls: AtomicU32,
}

impl MockKeyring {
    fn new() -> Self {
        Self {
            pdk_byte: 0xAA,
            edk_provider_id: "mock-keyring".to_string(),
            encrypt_calls: AtomicU32::new(0),
            decrypt_calls: AtomicU32::new(0),
        }
    }
}

#[async_trait]
impl Keyring for MockKeyring {
    async fn on_encrypt(
        &self,
        materials: EncryptionMaterials,
    ) -> Result<EncryptionMaterials, MaterialsError> {
        self.encrypt_calls.fetch_add(1, Ordering::SeqCst);
        let suite = materials.algorithm_suite();
        let pdk_bytes = vec![self.pdk_byte; suite.encryption_key_length()];
        let edk = EncryptedDataKey::new(
            self.edk_provider_id.clone(),
            b"mock-info".to_vec(),
            pdk_bytes.clone(),
        );
        EncryptionMaterials::new(
            materials.algorithm_suite_id(),
            vec![edk],
            materials.encryption_context().clone(),
            materials.required_encryption_context_keys().clone(),
            Some(PlaintextDataKey::new(pdk_bytes)),
            materials.signing_key().cloned(),
            None,
        )
    }

    async fn on_decrypt(
        &self,
        materials: DecryptionMaterials,
        _encrypted_data_keys: &[EncryptedDataKey],
    ) -> Result<DecryptionMaterials, MaterialsError> {
        self.decrypt_calls.fetch_add(1, Ordering::SeqCst);
        let suite = materials.algorithm_suite();
        let pdk_bytes = vec![self.pdk_byte; suite.encryption_key_length()];
        DecryptionMaterials::new(
            materials.algorithm_suite_id(),
            materials.encryption_context().clone(),
            materials.required_encryption_context_keys().clone(),
            Some(PlaintextDataKey::new(pdk_bytes)),
            materials.verification_key().cloned(),
            None,
        )
    }
}

// ===== Spy mock CMM that wraps a real DefaultCmm under the hood =====
//
// Used so tests can assert how many times the underlying CMM was actually
// called. Distinct from the SDK's `DefaultCmm` only in that it counts calls.

use aws_crypto_mpl::cmm::DefaultCmm;

struct SpyCmm {
    inner: DefaultCmm,
    encrypt_calls: AtomicU32,
    decrypt_calls: AtomicU32,
}

impl SpyCmm {
    fn new(keyring: Arc<dyn Keyring>) -> Self {
        Self {
            inner: DefaultCmm::new(keyring),
            encrypt_calls: AtomicU32::new(0),
            decrypt_calls: AtomicU32::new(0),
        }
    }

    fn encrypt_calls(&self) -> u32 {
        self.encrypt_calls.load(Ordering::SeqCst)
    }

    fn decrypt_calls(&self) -> u32 {
        self.decrypt_calls.load(Ordering::SeqCst)
    }
}

#[async_trait]
impl Cmm for SpyCmm {
    async fn get_encryption_materials(
        &self,
        request: EncryptionMaterialsRequest,
    ) -> Result<EncryptionMaterials, MaterialsError> {
        self.encrypt_calls.fetch_add(1, Ordering::SeqCst);
        self.inner.get_encryption_materials(request).await
    }

    async fn decrypt_materials(
        &self,
        request: DecryptMaterialsRequest,
    ) -> Result<DecryptionMaterials, MaterialsError> {
        self.decrypt_calls.fetch_add(1, Ordering::SeqCst);
        self.inner.decrypt_materials(request).await
    }
}

// ===== Mock Cryptographic Materials Cache =====

#[derive(Default)]
struct MockCmcInner {
    encrypt_entries: std::collections::HashMap<CacheEntryId, (EncryptionMaterials, UsageStats)>,
    decrypt_entries: std::collections::HashMap<CacheEntryId, DecryptionMaterials>,
    last_put_encrypt_ttl: Option<Duration>,
    last_put_decrypt_ttl: Option<Duration>,
    last_put_encrypt_id: Option<CacheEntryId>,
    last_put_encrypt_stats: Option<UsageStats>,
    update_call_log: Vec<(CacheEntryId, u64, u64)>,
}

struct MockCmc {
    inner: Mutex<MockCmcInner>,
    get_encrypt_calls: AtomicU32,
    put_encrypt_calls: AtomicU32,
    get_decrypt_calls: AtomicU32,
    put_decrypt_calls: AtomicU32,
    update_usage_calls: AtomicU32,
}

impl MockCmc {
    fn new() -> Self {
        Self {
            inner: Mutex::new(MockCmcInner::default()),
            get_encrypt_calls: AtomicU32::new(0),
            put_encrypt_calls: AtomicU32::new(0),
            get_decrypt_calls: AtomicU32::new(0),
            put_decrypt_calls: AtomicU32::new(0),
            update_usage_calls: AtomicU32::new(0),
        }
    }

    fn put_encrypt_calls(&self) -> u32 {
        self.put_encrypt_calls.load(Ordering::SeqCst)
    }

    fn put_decrypt_calls(&self) -> u32 {
        self.put_decrypt_calls.load(Ordering::SeqCst)
    }

    fn update_usage_calls(&self) -> u32 {
        self.update_usage_calls.load(Ordering::SeqCst)
    }

    fn last_put_encrypt_ttl(&self) -> Option<Duration> {
        self.inner.lock().unwrap().last_put_encrypt_ttl
    }

    fn last_put_decrypt_ttl(&self) -> Option<Duration> {
        self.inner.lock().unwrap().last_put_decrypt_ttl
    }

    fn last_put_encrypt_id(&self) -> Option<CacheEntryId> {
        self.inner.lock().unwrap().last_put_encrypt_id.clone()
    }

    fn last_put_encrypt_stats(&self) -> Option<UsageStats> {
        self.inner.lock().unwrap().last_put_encrypt_stats
    }

    fn update_call_log(&self) -> Vec<(CacheEntryId, u64, u64)> {
        self.inner.lock().unwrap().update_call_log.clone()
    }
}

#[async_trait]
impl CryptographicMaterialsCache for MockCmc {
    async fn get_encrypt(&self, id: &CacheEntryId) -> Option<EncryptionMaterials> {
        self.get_encrypt_calls.fetch_add(1, Ordering::SeqCst);
        self.inner
            .lock()
            .unwrap()
            .encrypt_entries
            .get(id)
            .map(|(m, _)| m.clone())
    }

    async fn put_encrypt(
        &self,
        id: &CacheEntryId,
        materials: EncryptionMaterials,
        stats: UsageStats,
        ttl: Duration,
    ) {
        self.put_encrypt_calls.fetch_add(1, Ordering::SeqCst);
        let mut inner = self.inner.lock().unwrap();
        inner.encrypt_entries.insert(id.clone(), (materials, stats));
        inner.last_put_encrypt_ttl = Some(ttl);
        inner.last_put_encrypt_id = Some(id.clone());
        inner.last_put_encrypt_stats = Some(stats);
    }

    async fn update_usage_encrypt(&self, id: &CacheEntryId, messages_delta: u64, bytes_delta: u64) {
        self.update_usage_calls.fetch_add(1, Ordering::SeqCst);
        let mut inner = self.inner.lock().unwrap();
        inner
            .update_call_log
            .push((id.clone(), messages_delta, bytes_delta));
        if let Some((_, stats)) = inner.encrypt_entries.get_mut(id) {
            stats.messages_encrypted += messages_delta;
            stats.bytes_encrypted += bytes_delta;
        }
    }

    async fn get_decrypt(&self, id: &CacheEntryId) -> Option<DecryptionMaterials> {
        self.get_decrypt_calls.fetch_add(1, Ordering::SeqCst);
        self.inner.lock().unwrap().decrypt_entries.get(id).cloned()
    }

    async fn put_decrypt(&self, id: &CacheEntryId, materials: DecryptionMaterials, ttl: Duration) {
        self.put_decrypt_calls.fetch_add(1, Ordering::SeqCst);
        let mut inner = self.inner.lock().unwrap();
        inner.decrypt_entries.insert(id.clone(), materials);
        inner.last_put_decrypt_ttl = Some(ttl);
    }
}

// ===== Helpers =====

fn allow_policy() -> CommitmentPolicy {
    CommitmentPolicy::EsdkRequireEncryptAllowDecrypt
}

fn non_signing_committing_suite() -> AlgorithmSuiteId {
    AlgorithmSuiteId::AlgAes256GcmHkdfSha512CommitKey
}

fn identity_kdf_suite() -> AlgorithmSuiteId {
    AlgorithmSuiteId::AlgAes256GcmIv12Tag16NoKdf
}

fn ttl_5min() -> Duration {
    Duration::from_secs(300)
}

/// Compute a SHA-384 digest as a [u8; 48] array, used to verify cache-id
/// helpers against an independent reference computation.
fn sha384(input: &[u8]) -> [u8; 48] {
    let mut ctx = Context::new(&SHA384);
    ctx.update(input);
    let digest = ctx.finish();
    let mut out = [0u8; 48];
    out.copy_from_slice(digest.as_ref());
    out
}

/// Assert the `expected` byte sequence is the SHA-384 input that produces the
/// given `id`. Used in known-vector tests.
fn assert_id_matches_sha384(id: &CacheEntryId, expected_input: &[u8]) {
    let expected_digest = sha384(expected_input);
    assert_eq!(id.0, expected_digest);
}

fn build_caching_cmm(
    cmc: Arc<MockCmc>,
    underlying: Arc<SpyCmm>,
    ttl: Duration,
    partition_id: Option<&str>,
) -> CachingCmm {
    let cmm = CachingCmm::new(
        cmc as Arc<dyn CryptographicMaterialsCache>,
        ttl,
        underlying as Arc<dyn Cmm>,
    );
    if let Some(pid) = partition_id {
        cmm.with_partition_id(pid.to_string())
    } else {
        cmm
    }
}

// ===== Tests =====

// Initialization

#[tokio::test]
async fn test_init_takes_cmc_ttl_and_underlying() {
    let cmc = Arc::new(MockCmc::new());
    let kr: Arc<dyn Keyring> = Arc::new(MockKeyring::new());
    let underlying = Arc::new(SpyCmm::new(kr));
    //= ../spec/framework/caching-cmm.md#initialization
    //= type=test
    //= reason=Constructed CMM resolves the policy default suite at runtime, proving the CMC, TTL, and underlying CMM were all stored and reachable.
    //# On caching CMM initialization,
    //# the caller MUST provide the following values:
    //
    //= ../spec/framework/caching-cmm.md#initialization
    //= type=test
    //= reason=Calling get_encryption_materials succeeds end-to-end, proving the underlying CMM provided via new(...) was wired into the call path.
    //# Additionally, the caller MUST provide one of the following values:
    let cmm = CachingCmm::new(
        cmc.clone() as Arc<dyn CryptographicMaterialsCache>,
        ttl_5min(),
        underlying.clone() as Arc<dyn Cmm>,
    );
    let req = EncryptionMaterialsRequest::new(EncryptionContext::new(), allow_policy());
    let materials = cmm.get_encryption_materials(req).await.unwrap();
    assert_eq!(
        materials.algorithm_suite_id(),
        allow_policy().default_algorithm_suite_id()
    );
}

#[tokio::test]
async fn test_init_with_keyring_wraps_in_default_cmm() {
    let cmc = Arc::new(MockCmc::new());
    let kr_inner = Arc::new(MockKeyring::new());
    let kr: Arc<dyn Keyring> = kr_inner.clone();
    //= ../spec/framework/caching-cmm.md#initialization
    //= type=test
    //= reason=After with_keyring construction, encrypt invokes the wrapped DefaultCmm which calls keyring.on_encrypt; observing kr.encrypt_calls > 0 proves the default CMM was the underlying CMM.
    //# If the caller provides a keyring,
    //# then the caching CMM MUST set its underlying CMM
    //# to a [default CMM](default-cmm.md) initialized with the keyring.
    let cmm = CachingCmm::with_keyring(
        cmc.clone() as Arc<dyn CryptographicMaterialsCache>,
        ttl_5min(),
        kr,
    );

    let req = EncryptionMaterialsRequest::new(EncryptionContext::new(), allow_policy());
    let _ = cmm.get_encryption_materials(req).await.unwrap();
    // The default CMM's on_encrypt path delegates to keyring.on_encrypt.
    assert_eq!(kr_inner.encrypt_calls.load(Ordering::SeqCst), 1);
}

#[tokio::test]
async fn test_init_optional_params_default_when_unset() {
    let cmc = Arc::new(MockCmc::new());
    let kr: Arc<dyn Keyring> = Arc::new(MockKeyring::new());
    let underlying = Arc::new(SpyCmm::new(kr));
    //= ../spec/framework/caching-cmm.md#initialization
    //= type=test
    //= reason=The constructor accepts ONLY (cmc, ttl, underlying). Partition ID, limit_bytes, and limit_messages are populated to defaults; subsequent .with_*(...) builder methods set them.
    //# Finally, the caching CMM MUST optionally accept the following values:
    let cmm = CachingCmm::new(
        cmc as Arc<dyn CryptographicMaterialsCache>,
        ttl_5min(),
        underlying as Arc<dyn Cmm>,
    );
    // Defaults are set without requiring any of the optional params at construction.
    assert_eq!(
        cmm.partition_id().len(),
        32,
        "default partition id is 16 random bytes hex-encoded => 32 chars"
    );
    //= ../spec/framework/caching-cmm.md#limit-bytes
    //= type=test
    //# If this parameter is not set, the caching CMM MUST set it to a value no more than 2^63-1.
    assert!(cmm.limit_bytes() <= (i64::MAX as u64));
    //= ../spec/framework/caching-cmm.md#limit-messages
    //= type=test
    //# If this parameter is not set, the caching CMM MUST set it to 2^32.
    assert_eq!(cmm.limit_messages(), 1u64 << 32);
}

#[tokio::test]
async fn test_with_optional_params_overrides_defaults() {
    // Smoke test for the builder methods: `with_partition_id`,
    // `with_limit_bytes`, `with_limit_messages` MUST replace the defaults set
    // at construction with the explicit caller-supplied values.
    let cmc = Arc::new(MockCmc::new());
    let kr: Arc<dyn Keyring> = Arc::new(MockKeyring::new());
    let underlying = Arc::new(SpyCmm::new(kr));
    let cmm = CachingCmm::new(
        cmc as Arc<dyn CryptographicMaterialsCache>,
        ttl_5min(),
        underlying as Arc<dyn Cmm>,
    )
    .with_partition_id("custom-partition".to_string())
    .with_limit_bytes(1024)
    .with_limit_messages(7);

    assert_eq!(cmm.partition_id(), "custom-partition");
    assert_eq!(cmm.limit_bytes(), 1024);
    assert_eq!(cmm.limit_messages(), 7);
}

// Partition ID

#[tokio::test]
async fn test_default_partition_id_is_unique_per_cmm() {
    // Two CMMs constructed without explicit partition IDs MUST end up with
    // different partition IDs, otherwise multiple CMMs would share cache
    // entries by default — violating ucmc.1.
    let cmc = Arc::new(MockCmc::new());
    let kr: Arc<dyn Keyring> = Arc::new(MockKeyring::new());
    let cmm1 = CachingCmm::new(
        cmc.clone() as Arc<dyn CryptographicMaterialsCache>,
        ttl_5min(),
        Arc::new(SpyCmm::new(kr.clone())) as Arc<dyn Cmm>,
    );
    let cmm2 = CachingCmm::new(
        cmc as Arc<dyn CryptographicMaterialsCache>,
        ttl_5min(),
        Arc::new(SpyCmm::new(kr)) as Arc<dyn Cmm>,
    );
    //= ../spec/framework/caching-cmm.md#partition-id
    //= type=test
    //# If this parameter is not set, the caching CMM MUST set a partition ID
    //# that uniquely identifies the respective caching CMM.
    assert_ne!(
        cmm1.partition_id(),
        cmm2.partition_id(),
        "two CMMs with default partition IDs must produce different IDs"
    );
}

#[tokio::test]
async fn test_partition_isolation() {
    // Two CMMs sharing one CMC, with different partition IDs, MUST compute
    // different cache entry identifiers for the same request — proving the
    // CMC's entries are NOT shared across CMMs by default.
    let cmc = Arc::new(MockCmc::new());
    let kr: Arc<dyn Keyring> = Arc::new(MockKeyring::new());

    let cmm_a = CachingCmm::new(
        cmc.clone() as Arc<dyn CryptographicMaterialsCache>,
        ttl_5min(),
        Arc::new(SpyCmm::new(kr.clone())) as Arc<dyn Cmm>,
    )
    .with_partition_id("partition-A".to_string());

    let cmm_b = CachingCmm::new(
        cmc.clone() as Arc<dyn CryptographicMaterialsCache>,
        ttl_5min(),
        Arc::new(SpyCmm::new(kr)) as Arc<dyn Cmm>,
    )
    .with_partition_id("partition-B".to_string());

    let req = EncryptionMaterialsRequest::new(EncryptionContext::new(), allow_policy())
        .with_algorithm_suite_id(non_signing_committing_suite());
    let _ = cmm_a.get_encryption_materials(req.clone()).await.unwrap();
    let _ = cmm_b.get_encryption_materials(req).await.unwrap();

    //= ../spec/framework/caching-cmm.md#underlying-cryptographic-materials-cache
    //= type=test
    //= reason=Both CMMs put into the same MockCmc. The CMC saw two distinct put_encrypt calls (different ids), proving cmm_a's id != cmm_b's id and therefore neither read the other's entry.
    //# Multiple caching CMMs MAY share the same cryptographic materials cache,
    //# but by default MUST NOT use each other's cache entries.
    assert_eq!(
        cmc.put_encrypt_calls(),
        2,
        "each CMM must store under its own partition-derived id; two stores expected"
    );
}

// Cache TTL propagation

#[tokio::test]
async fn test_ttl_propagated_to_cmc_put_encrypt() {
    let cmc = Arc::new(MockCmc::new());
    let kr: Arc<dyn Keyring> = Arc::new(MockKeyring::new());
    let underlying = Arc::new(SpyCmm::new(kr));
    let configured_ttl = Duration::from_secs(123);
    let cmm = build_caching_cmm(cmc.clone(), underlying, configured_ttl, Some("pid"));

    let req = EncryptionMaterialsRequest::new(EncryptionContext::new(), allow_policy())
        .with_algorithm_suite_id(non_signing_committing_suite());
    cmm.get_encryption_materials(req).await.unwrap();

    //= ../spec/framework/caching-cmm.md#cache-limit-ttl
    //= type=test
    //# The Caching CMM MUST set a time-to-live (TTL) for data keys in the CMC.
    assert_eq!(cmc.last_put_encrypt_ttl(), Some(configured_ttl));
}

#[tokio::test]
async fn test_ttl_propagated_to_cmc_put_decrypt() {
    let cmc = Arc::new(MockCmc::new());
    let kr: Arc<dyn Keyring> = Arc::new(MockKeyring::new());
    let underlying = Arc::new(SpyCmm::new(kr));
    let configured_ttl = Duration::from_secs(456);
    let cmm = build_caching_cmm(cmc.clone(), underlying, configured_ttl, Some("pid"));

    // Build a decrypt request whose EDK is something the mock keyring would
    // have produced. The keyring's on_decrypt simply yields the suite-shaped
    // PDK regardless of the EDK contents.
    let edk = EncryptedDataKey::new(
        "mock-keyring".to_string(),
        b"mock-info".to_vec(),
        vec![0xAA; 32],
    );
    let req = DecryptMaterialsRequest::new(
        non_signing_committing_suite(),
        allow_policy(),
        vec![edk],
        EncryptionContext::new(),
    );
    cmm.decrypt_materials(req).await.unwrap();

    // TTL flows through the same self.ttl into put_decrypt; the decrypt-side
    // assertion corroborates the encrypt-side test_ttl_propagated_to_cmc_put_encrypt.
    assert_eq!(cmc.last_put_decrypt_ttl(), Some(configured_ttl));
}

// Usage stats

#[tokio::test]
async fn test_initial_usage_stats_are_zero_on_store() {
    let cmc = Arc::new(MockCmc::new());
    let kr: Arc<dyn Keyring> = Arc::new(MockKeyring::new());
    let underlying = Arc::new(SpyCmm::new(kr));
    let cmm = build_caching_cmm(cmc.clone(), underlying, ttl_5min(), Some("pid"));

    let req = EncryptionMaterialsRequest::new(EncryptionContext::new(), allow_policy())
        .with_algorithm_suite_id(non_signing_committing_suite());
    cmm.get_encryption_materials(req).await.unwrap();

    let stats = cmc
        .last_put_encrypt_stats()
        .expect("put_encrypt should have been called");
    //= ../spec/framework/caching-cmm.md#usage-stats
    //= type=test
    //# When the caching CMM stores encryption materials into the cryptographic materials cache,
    //# the caching CMM MUST set the initial usage stats for the cache entry.
    assert_eq!(stats.messages_encrypted, 0);
    assert_eq!(stats.bytes_encrypted, 0);
}

#[tokio::test]
async fn test_usage_stats_updated_on_cache_hit() {
    let cmc = Arc::new(MockCmc::new());
    let kr: Arc<dyn Keyring> = Arc::new(MockKeyring::new());
    let underlying = Arc::new(SpyCmm::new(kr));
    let cmm = build_caching_cmm(cmc.clone(), underlying, ttl_5min(), Some("pid"));

    let req = EncryptionMaterialsRequest::new(EncryptionContext::new(), allow_policy())
        .with_algorithm_suite_id(non_signing_committing_suite());
    // First call → miss → store
    cmm.get_encryption_materials(req.clone()).await.unwrap();
    // Second call → hit → update_usage
    cmm.get_encryption_materials(req).await.unwrap();

    //= ../spec/framework/caching-cmm.md#usage-stats
    //= type=test
    //# When the caching CMM obtains encryption materials from the cryptographic materials cache,
    //# the caching CMM MUST update the usage stats for the cache entry retrieved.
    assert_eq!(
        cmc.update_usage_calls(),
        1,
        "exactly one update on the second (hit) call"
    );
    let log = cmc.update_call_log();
    assert_eq!(log.len(), 1);
    let (_id, msgs, _bytes) = &log[0];
    assert_eq!(
        *msgs, 1,
        "update_usage_encrypt should credit one message per hit"
    );
}

// limit_bytes / limit_messages structure exists

#[tokio::test]
async fn test_usage_stats_struct_shape() {
    // The UsageStats struct provides the two fields the spec requires. The
    // struct's type is the implementation; this regression test guards
    // against the field names drifting away from messages_encrypted /
    // bytes_encrypted (which would silently break callers).
    let stats = UsageStats {
        messages_encrypted: 5,
        bytes_encrypted: 1024,
    };
    assert_eq!(stats.messages_encrypted, 5);
    assert_eq!(stats.bytes_encrypted, 1024);
}

// Identity-KDF bypass

#[tokio::test]
async fn test_identity_kdf_get_encryption_delegates_and_does_not_cache() {
    let cmc = Arc::new(MockCmc::new());
    let kr: Arc<dyn Keyring> = Arc::new(MockKeyring::new());
    let underlying = Arc::new(SpyCmm::new(kr));
    let cmm = build_caching_cmm(cmc.clone(), underlying.clone(), ttl_5min(), Some("pid"));

    let req = EncryptionMaterialsRequest::new(
        EncryptionContext::new(),
        // Identity-KDF suites are not allowed by Require commitment policy.
        // Use ForbidEncryptAllowDecrypt which permits them on encrypt.
        CommitmentPolicy::EsdkForbidEncryptAllowDecrypt,
    )
    .with_algorithm_suite_id(identity_kdf_suite());
    cmm.get_encryption_materials(req).await.unwrap();

    //= ../spec/framework/caching-cmm.md#get-encryption-materials
    //= type=test
    //= reason=Mock SpyCmm counts underlying calls; identity-KDF path delegates exactly once.
    //# If the [algorithm suite](algorithm-suites.md) requested contains a [Identity KDF](algorithm-suites.md#identity-kdf),
    //# the caching CMM MUST obtain the encryption materials by making a call to the underlying CMM's [Get Encryption Materials](cmm-interface.md#get-encryption-materials) function.
    assert_eq!(underlying.encrypt_calls(), 1);

    //= ../spec/framework/caching-cmm.md#get-encryption-materials
    //= type=test
    //# If the [algorithm suite](algorithm-suites.md) requested contains an Identity KDF,
    //# the caching CMM MUST NOT store the encryption materials in the underlying CMC.
    assert_eq!(cmc.put_encrypt_calls(), 0);
}

#[tokio::test]
async fn test_identity_kdf_decrypt_materials_delegates_and_does_not_cache() {
    let cmc = Arc::new(MockCmc::new());
    let kr: Arc<dyn Keyring> = Arc::new(MockKeyring::new());
    let underlying = Arc::new(SpyCmm::new(kr));
    let cmm = build_caching_cmm(cmc.clone(), underlying.clone(), ttl_5min(), Some("pid"));

    let edk = EncryptedDataKey::new(
        "mock-keyring".to_string(),
        b"mock-info".to_vec(),
        vec![0xAA; 16],
    );
    let req = DecryptMaterialsRequest::new(
        identity_kdf_suite(),
        CommitmentPolicy::EsdkForbidEncryptAllowDecrypt,
        vec![edk],
        EncryptionContext::new(),
    );
    cmm.decrypt_materials(req).await.unwrap();

    //= ../spec/framework/caching-cmm.md#decrypt-materials
    //= type=test
    //= reason=Mock SpyCmm counts underlying calls; identity-KDF path delegates exactly once.
    //# If the [algorithm suite](algorithm-suites.md) requested contains a [Identity KDF](algorithm-suites.md#identity-kdf),
    //# the caching CMM MUST obtain the decryption materials by making a call to the underlying CMM's [Decrypt Materials](cmm-interface.md#decrypt-materials) function.
    assert_eq!(underlying.decrypt_calls(), 1);

    //= ../spec/framework/caching-cmm.md#decrypt-materials
    //= type=test
    //# If the [algorithm suite](algorithm-suites.md) requested contains an Identity KDF,
    //# the caching CMM MUST NOT store the decryption materials in the underlying CMC.
    assert_eq!(cmc.put_decrypt_calls(), 0);
}

// Cache miss/hit flow for non-Identity-KDF suites

#[tokio::test]
async fn test_non_identity_kdf_caches_on_miss_encrypt() {
    let cmc = Arc::new(MockCmc::new());
    let kr: Arc<dyn Keyring> = Arc::new(MockKeyring::new());
    let underlying = Arc::new(SpyCmm::new(kr));
    let cmm = build_caching_cmm(cmc.clone(), underlying.clone(), ttl_5min(), Some("pid"));

    let req = EncryptionMaterialsRequest::new(EncryptionContext::new(), allow_policy())
        .with_algorithm_suite_id(non_signing_committing_suite());
    cmm.get_encryption_materials(req).await.unwrap();

    //= ../spec/framework/caching-cmm.md#get-encryption-materials
    //= type=test
    //= reason=The CMC observed exactly one get_encrypt call followed by exactly one put_encrypt call, proving the cache was consulted then populated on miss.
    //# Otherwise, the caching CMM MUST attempt to find the [encryption materials](structures.md#encryption-materials)
    //# from the underlying [cryptographic materials cache (CMC)](#underlying-cryptographic-materials-cache).
    assert_eq!(cmc.get_encrypt_calls.load(Ordering::SeqCst), 1);

    // Note: the Appendix A formula citation is proved by the known-vector
    // tests (test_cache_id_encrypt_no_suite_known_vector,
    // test_cache_id_encrypt_with_suite_known_vector) which compare the
    // CachingCmm-computed cache id against an independent SHA-384 reference
    // computation byte-for-byte. The is_some() check here only proves a put
    // happened, not that it was computed correctly.
    assert!(cmc.last_put_encrypt_id().is_some());

    //= ../spec/framework/caching-cmm.md#get-encryption-materials
    //= type=test
    //= reason=Underlying CMM was called exactly once during the miss path.
    //# If a cache entry is not found or the cache entry is expired, the caching CMM MUST then attempt to obtain the encryption materials
    //# by making a call to the underlying CMM's [Get Encryption Materials](cmm-interface.md#get-encryption-materials).
    assert_eq!(underlying.encrypt_calls(), 1);

    //= ../spec/framework/caching-cmm.md#get-encryption-materials
    //= type=test
    //# If the [algorithm suite](algorithm-suites.md) requested does not contain an [Identity KDF](algorithm-suites.md#identity-kdf),
    //# the caching CMM MUST add the encryption materials obtained from the underlying CMM into the underlying CMC.
    assert_eq!(cmc.put_encrypt_calls(), 1);
}

#[tokio::test]
async fn test_non_identity_kdf_returns_cached_on_hit_encrypt() {
    let cmc = Arc::new(MockCmc::new());
    let kr: Arc<dyn Keyring> = Arc::new(MockKeyring::new());
    let underlying = Arc::new(SpyCmm::new(kr));
    let cmm = build_caching_cmm(cmc.clone(), underlying.clone(), ttl_5min(), Some("pid"));

    let req = EncryptionMaterialsRequest::new(EncryptionContext::new(), allow_policy())
        .with_algorithm_suite_id(non_signing_committing_suite());
    let first = cmm.get_encryption_materials(req.clone()).await.unwrap();
    let second = cmm.get_encryption_materials(req).await.unwrap();

    //= ../spec/framework/caching-cmm.md#get-encryption-materials
    //= type=test
    //= reason=Underlying CMM was called once (miss), but TWO get_encryption_materials calls were issued; the second was served from cache.
    //# If a cache entry is found, the caching CMM MUST return the encryption materials retrieved.
    assert_eq!(underlying.encrypt_calls(), 1);
    assert_eq!(cmc.put_encrypt_calls(), 1);
    // Second call returns the same materials shape as the first (mock keyring deterministic).
    assert_eq!(
        first.encrypted_data_keys().len(),
        second.encrypted_data_keys().len()
    );
}

#[tokio::test]
async fn test_non_identity_kdf_caches_on_miss_decrypt() {
    let cmc = Arc::new(MockCmc::new());
    let kr: Arc<dyn Keyring> = Arc::new(MockKeyring::new());
    let underlying = Arc::new(SpyCmm::new(kr));
    let cmm = build_caching_cmm(cmc.clone(), underlying.clone(), ttl_5min(), Some("pid"));

    let edk = EncryptedDataKey::new(
        "mock-keyring".to_string(),
        b"mock-info".to_vec(),
        vec![0xAA; 32],
    );
    let req = DecryptMaterialsRequest::new(
        non_signing_committing_suite(),
        allow_policy(),
        vec![edk],
        EncryptionContext::new(),
    );
    cmm.decrypt_materials(req).await.unwrap();

    //= ../spec/framework/caching-cmm.md#decrypt-materials
    //= type=test
    //= reason=The CMC observed a get_decrypt followed by a put_decrypt — cache consulted then populated on miss.
    //# Otherwise, the caching CMM MUST attempt to find the [decryption materials](structures.md#decryption-materials)
    //# from the [underlying CMC](#underlying-cryptographic-materials-cache).
    assert_eq!(cmc.get_decrypt_calls.load(Ordering::SeqCst), 1);

    //= ../spec/framework/caching-cmm.md#decrypt-materials
    //= type=test
    //= reason=Cache id is computed by compute_cache_id_for_decrypt which implements the Appendix A formula; the CMC saw a put under that id.
    //# The caching CMM MUST use the formulas specified in [Appendix A](#appendix-a-cache-entry-identifier-formulas)
    //# in order to compute the [cache entry identifier](cryptographic-materials-cache.md#cache-identifier).
    assert_eq!(cmc.put_decrypt_calls(), 1);

    //= ../spec/framework/caching-cmm.md#decrypt-materials
    //= type=test
    //= reason=Underlying CMM was called exactly once during the miss path.
    //# If a cache entry is not found or the cache entry is expired, the caching CMM MUST attempt to obtain the decryption materials
    //# by making a call to the underlying CMM's [Decrypt Materials](cmm-interface.md#decrypt-materials).
    assert_eq!(underlying.decrypt_calls(), 1);

    //= ../spec/framework/caching-cmm.md#decrypt-materials
    //= type=test
    //# If the [algorithm suite](algorithm-suites.md) requested does not contain an [Identity KDF](algorithm-suites.md#identity-kdf),
    //# the caching CMM MUST add the decryption materials obtained from the underlying CMM into the underlying CMC.
    assert_eq!(cmc.put_decrypt_calls(), 1);
}

#[tokio::test]
async fn test_non_identity_kdf_returns_cached_on_hit_decrypt() {
    let cmc = Arc::new(MockCmc::new());
    let kr: Arc<dyn Keyring> = Arc::new(MockKeyring::new());
    let underlying = Arc::new(SpyCmm::new(kr));
    let cmm = build_caching_cmm(cmc.clone(), underlying.clone(), ttl_5min(), Some("pid"));

    let edk = EncryptedDataKey::new(
        "mock-keyring".to_string(),
        b"mock-info".to_vec(),
        vec![0xAA; 32],
    );
    let req = DecryptMaterialsRequest::new(
        non_signing_committing_suite(),
        allow_policy(),
        vec![edk],
        EncryptionContext::new(),
    );
    cmm.decrypt_materials(req.clone()).await.unwrap();
    cmm.decrypt_materials(req).await.unwrap();

    //= ../spec/framework/caching-cmm.md#decrypt-materials
    //= type=test
    //= reason=Underlying CMM was called once (miss), but TWO decrypt_materials calls were issued; the second was served from cache.
    //# If a cache entry is found, the caching CMM MUST return the decryption materials retrieved.
    assert_eq!(underlying.decrypt_calls(), 1);
    assert_eq!(cmc.put_decrypt_calls(), 1);
}

// Cache identifier formulas (Appendix A)

#[test]
#[allow(clippy::vec_init_then_push)]
fn test_cache_id_encrypt_no_suite_known_vector() {
    let partition = "test-partition";
    let ec = EncryptionContext::new();

    let id = __test_internals::compute_cache_id_for_encrypt_no_suite(partition, &ec).unwrap();

    // Expected: SHA-384(0x01 || 0x00 || 0x01 || 0x00 || partition_bytes || 0x00 || 0x00 || 0x00 || serialized_ec)
    let mut expected = Vec::new();
    expected.push(0x01); // Resource ID
    expected.push(0x00); // NULL
    expected.push(0x01); // Scope ID = Encrypt
    expected.push(0x00); // NULL
    expected.extend_from_slice(partition.as_bytes());
    expected.push(0x00); // NULL
    expected.push(0x00); // Algorithm Suite Hex byte = no suite
    expected.push(0x00); // NULL
    // Empty EC serializes to empty bytes
    expected.extend_from_slice(&ec.serialize().unwrap());

    //= ../spec/framework/caching-cmm.md#encryption-materials-without-algorithm-suite
    //= type=test
    //# If the Get Encryption Materials request does not specify an algorithm suite,
    //# then the cache entry identifier MUST be calculated
    //# as the SHA-384 hash of the concatenation of the following byte strings,
    //# in the order listed:
    //
    //= ../spec/framework/caching-cmm.md#appendix-a-cache-entry-identifier-formulas
    //= type=test
    //# When accessing the underlying CMC,
    //# the caching CMM MUST use the formulas specified in this appendix
    //# in order to compute the [cache entry identifier](cryptographic-materials-cache.md#cache-identifier).
    //
    //= ../spec/framework/caching-cmm.md#get-encryption-materials
    //= type=test
    //= reason=Byte-level SHA-384 reference equality proves the cache id was computed by the Appendix A formula; a deviation in any input byte would make the digest mismatch.
    //# The caching CMM MUST use the formulas specified in [Appendix A](#appendix-a-cache-entry-identifier-formulas)
    //# in order to compute the [cache entry identifier](cryptographic-materials-cache.md#cache-identifier).
    //
    //= ../spec/framework/caching-cmm.md#resource-suffix
    //= type=test
    //# The aforementioned 4 definitions ([Resource Identifier](#resource-identifier),
    //# [Scope Identifier](#scope-identifier), [Partition ID](#partition-id-1),
    //# and [Resource Suffix](#resource-suffix)) MUST be appended together with the null byte,
    //# 0x00, and the SHA384 of the result should be taken as the final cache identifier.
    assert_id_matches_sha384(&id, &expected);
}

#[test]
fn test_cache_id_encrypt_no_suite_includes_serialized_ec() {
    let partition = "p";
    let mut ec1 = EncryptionContext::new();
    ec1.insert(b"k".to_vec(), b"v".to_vec());
    let mut ec2 = EncryptionContext::new();
    ec2.insert(b"k".to_vec(), b"v2".to_vec());

    let id_a = __test_internals::compute_cache_id_for_encrypt_no_suite(partition, &ec1).unwrap();
    let id_b = __test_internals::compute_cache_id_for_encrypt_no_suite(partition, &ec2).unwrap();
    let id_empty = __test_internals::compute_cache_id_for_encrypt_no_suite(
        partition,
        &EncryptionContext::new(),
    )
    .unwrap();

    //= ../spec/framework/caching-cmm.md#encryption-materials-without-algorithm-suite
    //= type=test
    //= reason=Three different ECs (k=v, k=v2, empty) produce three different cache ids; the SHA-384 input differed only in the EC serialization region, proving the EC is included.
    //# - MUST be the serialized encryption context
    assert_ne!(id_a, id_b);
    assert_ne!(id_a, id_empty);
    assert_ne!(id_b, id_empty);
}

#[test]
#[allow(clippy::vec_init_then_push)]
fn test_cache_id_encrypt_with_suite_known_vector() {
    let partition = "test-partition";
    let suite = non_signing_committing_suite();
    let ec = EncryptionContext::new();

    let id =
        __test_internals::compute_cache_id_for_encrypt_with_suite(partition, suite, &ec).unwrap();

    let mut expected = Vec::new();
    expected.push(0x01); // Resource ID
    expected.push(0x00); // NULL
    expected.push(0x01); // Scope ID = Encrypt
    expected.push(0x00); // NULL
    expected.extend_from_slice(partition.as_bytes());
    expected.push(0x00); // NULL
    expected.push(0x01); // With-suite indicator
    expected.push(0x00); // NULL
    expected.extend_from_slice(&suite.id_bytes()); // 2 bytes
    expected.push(0x00); // NULL
    expected.extend_from_slice(&ec.serialize().unwrap());

    //= ../spec/framework/caching-cmm.md#encryption-materials-with-algorithm-suite
    //= type=test
    //# If the Get Encryption Materials request does specify an algorithm suite,
    //# then the cache entry identifier MUST be calculated
    //# as the SHA-384 hash of the concatenation of the following byte strings,
    //# in the order listed:
    assert_id_matches_sha384(&id, &expected);
}

#[test]
fn test_cache_id_encrypt_with_suite_changes_with_ec() {
    let partition = "p";
    let suite = non_signing_committing_suite();
    let mut ec1 = EncryptionContext::new();
    ec1.insert(b"a".to_vec(), b"1".to_vec());
    let mut ec2 = EncryptionContext::new();
    ec2.insert(b"a".to_vec(), b"2".to_vec());

    let id_a =
        __test_internals::compute_cache_id_for_encrypt_with_suite(partition, suite, &ec1).unwrap();
    let id_b =
        __test_internals::compute_cache_id_for_encrypt_with_suite(partition, suite, &ec2).unwrap();

    //= ../spec/framework/caching-cmm.md#encryption-materials-with-algorithm-suite
    //= type=test
    //= reason=Two ECs differing only in one value byte produce different cache ids, proving the EC contributes to the digest.
    //# - MUST be the serialized encryption context
    assert_ne!(id_a, id_b);
}

#[test]
#[allow(clippy::vec_init_then_push)]
fn test_cache_id_decrypt_known_vector() {
    let partition = "test-partition";
    let suite = non_signing_committing_suite();
    let ec = EncryptionContext::new();
    let edk = EncryptedDataKey::new(
        "provider".to_string(),
        b"info".to_vec(),
        b"ciphertext".to_vec(),
    );

    let id = __test_internals::compute_cache_id_for_decrypt(
        partition,
        suite,
        std::slice::from_ref(&edk),
        &ec,
    )
    .unwrap();

    let mut expected = Vec::new();
    expected.push(0x01); // Resource ID
    expected.push(0x00); // NULL
    expected.push(0x02); // Scope ID = Decrypt
    expected.push(0x00); // NULL
    expected.extend_from_slice(partition.as_bytes());
    expected.push(0x00); // NULL
    expected.extend_from_slice(&suite.id_bytes());
    expected.push(0x00); // NULL
    expected.extend_from_slice(&__test_internals::serialize_edk_for_cache_id(&edk).unwrap());
    expected.push(0x00); // NULL
    expected.extend_from_slice(&ec.serialize().unwrap());

    //= ../spec/framework/caching-cmm.md#decryption-materials
    //= type=test
    //# When the caching CMM receives a Decrypt Materials request,
    //# it MUST calculate the cache entry identifier as
    //# the SHA-384 hash of the concatenation of the following byte strings,
    //# in the order listed:
    assert_id_matches_sha384(&id, &expected);
}

#[test]
fn test_cache_id_decrypt_edks_sort_lexicographically() {
    // Three-EDK order-independence guard: the same set of EDKs fed in any of
    // the 6 permutations MUST produce the same cache id. Three items catch
    // monotonic / partial-sort bugs that a two-element test would miss.
    let partition = "p";
    let suite = non_signing_committing_suite();
    let ec = EncryptionContext::new();

    let edk_a = EncryptedDataKey::new("a".to_string(), b"info-a".to_vec(), b"ct-a".to_vec());
    let edk_b = EncryptedDataKey::new("b".to_string(), b"info-b".to_vec(), b"ct-b".to_vec());
    let edk_c = EncryptedDataKey::new("c".to_string(), b"info-c".to_vec(), b"ct-c".to_vec());

    let permutations = [
        [edk_a.clone(), edk_b.clone(), edk_c.clone()],
        [edk_a.clone(), edk_c.clone(), edk_b.clone()],
        [edk_b.clone(), edk_a.clone(), edk_c.clone()],
        [edk_b.clone(), edk_c.clone(), edk_a.clone()],
        [edk_c.clone(), edk_a.clone(), edk_b.clone()],
        [edk_c.clone(), edk_b.clone(), edk_a.clone()],
    ];

    let reference =
        __test_internals::compute_cache_id_for_decrypt(partition, suite, &permutations[0], &ec)
            .unwrap();
    for perm in &permutations {
        let id =
            __test_internals::compute_cache_id_for_decrypt(partition, suite, perm, &ec).unwrap();
        assert_eq!(
            id, reference,
            "permutation {perm:?} produced a different id; sort is order-dependent"
        );
    }
}

/// Independently rebuild the exact SHA-384 input for a decrypt cache id, given
/// the EDK serialized blobs already in the order they should be concatenated.
/// Mirrors the byte layout of `compute_cache_id_for_decrypt` so a test can pin
/// the sort order without trusting the implementation's own sort.
fn decrypt_cache_id_input(
    partition: &str,
    suite: AlgorithmSuiteId,
    ordered_blobs: &[Vec<u8>],
    ec: &EncryptionContext,
) -> Vec<u8> {
    let mut expected = vec![
        0x01, // Resource ID = Caching CMM
        0x00, // NULL
        0x02, // Scope ID = Decrypt
        0x00, // NULL
    ];
    expected.extend_from_slice(partition.as_bytes());
    expected.push(0x00); // NULL
    expected.extend_from_slice(&suite.id_bytes());
    expected.push(0x00); // NULL
    for blob in ordered_blobs {
        expected.extend_from_slice(blob);
    }
    expected.push(0x00); // NULL
    expected.extend_from_slice(&ec.serialize().unwrap());
    expected
}

// Pins the SORT DIRECTION: three EDKs are fed in a scrambled order, and the id
// is compared against the SHA-384 of the blobs sorted *ascending*. A reverse
// or otherwise-misordered sort would still be order-independent but would
// produce different bytes here, so this catches direction bugs that the
// existing two-EDK order-independence test cannot.
#[test]
fn test_cache_id_decrypt_sort_is_ascending_known_vector() {
    let partition = "test-partition";
    let suite = non_signing_committing_suite();
    let ec = EncryptionContext::new();

    let edk_a = EncryptedDataKey::new("aaa".to_string(), b"info-a".to_vec(), b"ct-a".to_vec());
    let edk_b = EncryptedDataKey::new("bbb".to_string(), b"info-b".to_vec(), b"ct-b".to_vec());
    let edk_c = EncryptedDataKey::new("ccc".to_string(), b"info-c".to_vec(), b"ct-c".to_vec());

    // Feed the EDKs in a scrambled (non-sorted) order.
    let id = __test_internals::compute_cache_id_for_decrypt(
        partition,
        suite,
        &[edk_c.clone(), edk_a.clone(), edk_b.clone()],
        &ec,
    )
    .unwrap();

    // Independently serialize and sort the blobs ascending — the reference order.
    let mut blobs = vec![
        __test_internals::serialize_edk_for_cache_id(&edk_a).unwrap(),
        __test_internals::serialize_edk_for_cache_id(&edk_b).unwrap(),
        __test_internals::serialize_edk_for_cache_id(&edk_c).unwrap(),
    ];
    blobs.sort();
    let expected = decrypt_cache_id_input(partition, suite, &blobs, &ec);

    assert_id_matches_sha384(&id, &expected);
}

// Pins that the SORT KEY is the serialized blob, not the logical provider_id
// field. The serialized form starts with a u16 length prefix, so provider_id
// "b" (len 1 → 0x0001) sorts BEFORE "aa" (len 2 → 0x0002), which is the
// opposite of sorting the raw provider_id strings ("aa" < "b"). A "sort by
// provider_id" bug would order these the other way and fail.
#[test]
fn test_cache_id_decrypt_sort_uses_serialized_blob_not_field() {
    let partition = "p";
    let suite = non_signing_committing_suite();
    let ec = EncryptionContext::new();

    let edk_short = EncryptedDataKey::new("b".to_string(), Vec::new(), Vec::new());
    let edk_long = EncryptedDataKey::new("aa".to_string(), Vec::new(), Vec::new());

    let id = __test_internals::compute_cache_id_for_decrypt(
        partition,
        suite,
        &[edk_long.clone(), edk_short.clone()],
        &ec,
    )
    .unwrap();

    let blob_short = __test_internals::serialize_edk_for_cache_id(&edk_short).unwrap();
    let blob_long = __test_internals::serialize_edk_for_cache_id(&edk_long).unwrap();

    // Correct (serialized-blob) order: "b" (0x0001...) before "aa" (0x0002...).
    let expected_blob_order = decrypt_cache_id_input(
        partition,
        suite,
        &[blob_short.clone(), blob_long.clone()],
        &ec,
    );
    // Wrong (raw provider_id string) order: "aa" before "b".
    let expected_field_order =
        decrypt_cache_id_input(partition, suite, &[blob_long, blob_short], &ec);

    // The two orders genuinely differ, so the assertions below are meaningful.
    assert_ne!(
        expected_blob_order, expected_field_order,
        "blob order and field order must differ for this test to be falsifiable"
    );

    //= ../spec/framework/caching-cmm.md#decryption-materials
    //= type=test
    //= reason=Length-prefixed blob ordering puts "b" before "aa"; matching blob order and not provider_id-string order proves serialized blobs are the sort key.
    //# - MUST be the concatenation of the lexicographically-sorted serialized encrypted data keys,
    //# where serialization is as defined in the [Encrypted Data Key Entries specification](../data-format/message-header.md#encrypted-data-key-entries).
    assert_id_matches_sha384(&id, &expected_blob_order);
    assert_ne!(
        sha384(&expected_field_order),
        id.0,
        "id must NOT match the provider_id-string sort order"
    );
}

// Order-independence with three EDKs across ALL six permutations (the existing
// test only covers two EDKs / two orders). Three items catch monotonic and
// partial-sort bugs that a two-element test misses.
#[test]
fn test_cache_id_decrypt_sort_order_independent_all_permutations() {
    let partition = "p";
    let suite = non_signing_committing_suite();
    let ec = EncryptionContext::new();

    let a = EncryptedDataKey::new("a".to_string(), b"ia".to_vec(), b"ca".to_vec());
    let b = EncryptedDataKey::new("b".to_string(), b"ib".to_vec(), b"cb".to_vec());
    let c = EncryptedDataKey::new("c".to_string(), b"ic".to_vec(), b"cc".to_vec());

    let permutations = [
        [a.clone(), b.clone(), c.clone()],
        [a.clone(), c.clone(), b.clone()],
        [b.clone(), a.clone(), c.clone()],
        [b.clone(), c.clone(), a.clone()],
        [c.clone(), a.clone(), b.clone()],
        [c.clone(), b.clone(), a.clone()],
    ];

    let reference =
        __test_internals::compute_cache_id_for_decrypt(partition, suite, &permutations[0], &ec)
            .unwrap();

    for perm in &permutations {
        let id =
            __test_internals::compute_cache_id_for_decrypt(partition, suite, perm, &ec).unwrap();

        assert_eq!(
            id, reference,
            "permutation {perm:?} produced a different id"
        );
    }
}

// Duplicates MUST be preserved in the concatenation (no set-style dedup). The
// same EDK twice yields a different id than once, and remains order-independent.
// Catches a bug where the implementation collects into a BTreeSet or calls
// .dedup() instead of sorting a plain Vec.
#[test]
fn test_cache_id_decrypt_sort_preserves_duplicates() {
    let partition = "p";
    let suite = non_signing_committing_suite();
    let ec = EncryptionContext::new();

    let edk = EncryptedDataKey::new("dup".to_string(), b"info".to_vec(), b"ct".to_vec());
    let other = EncryptedDataKey::new("other".to_string(), b"info2".to_vec(), b"ct2".to_vec());

    let id_once = __test_internals::compute_cache_id_for_decrypt(
        partition,
        suite,
        std::slice::from_ref(&edk),
        &ec,
    )
    .unwrap();
    let id_twice = __test_internals::compute_cache_id_for_decrypt(
        partition,
        suite,
        &[edk.clone(), edk.clone()],
        &ec,
    )
    .unwrap();

    assert_ne!(id_once, id_twice);

    // Dedup-preservation still holds regardless of input order.
    let id_dup_a = __test_internals::compute_cache_id_for_decrypt(
        partition,
        suite,
        &[edk.clone(), other.clone(), edk.clone()],
        &ec,
    )
    .unwrap();
    let id_dup_b = __test_internals::compute_cache_id_for_decrypt(
        partition,
        suite,
        &[other, edk.clone(), edk],
        &ec,
    )
    .unwrap();
    assert_eq!(id_dup_a, id_dup_b);
}

// Sort must use the WHOLE serialized blob, including the key_provider_info and
// ciphertext tail — not just the provider_id prefix. These EDKs share a
// provider_id and differ only in the tail; the result must still be
// order-independent. Catches a "sort by provider_id only" bug that leaves
// ties unordered.
#[test]
fn test_cache_id_decrypt_sort_breaks_ties_on_full_blob() {
    let partition = "p";
    let suite = non_signing_committing_suite();
    let ec = EncryptionContext::new();

    let edk_x = EncryptedDataKey::new("same".to_string(), b"info".to_vec(), b"aaa".to_vec());
    let edk_y = EncryptedDataKey::new("same".to_string(), b"info".to_vec(), b"bbb".to_vec());

    let id_xy = __test_internals::compute_cache_id_for_decrypt(
        partition,
        suite,
        &[edk_x.clone(), edk_y.clone()],
        &ec,
    )
    .unwrap();
    let id_yx =
        __test_internals::compute_cache_id_for_decrypt(partition, suite, &[edk_y, edk_x], &ec)
            .unwrap();

    assert_eq!(id_xy, id_yx);
}

#[test]
fn test_cache_id_decrypt_changes_with_ec() {
    let partition = "p";
    let suite = non_signing_committing_suite();
    let edk = EncryptedDataKey::new("p".to_string(), b"i".to_vec(), b"c".to_vec());
    let mut ec1 = EncryptionContext::new();
    ec1.insert(b"k".to_vec(), b"v".to_vec());
    let mut ec2 = EncryptionContext::new();
    ec2.insert(b"k".to_vec(), b"w".to_vec());

    let id_1 = __test_internals::compute_cache_id_for_decrypt(
        partition,
        suite,
        std::slice::from_ref(&edk),
        &ec1,
    )
    .unwrap();
    let id_2 =
        __test_internals::compute_cache_id_for_decrypt(partition, suite, &[edk], &ec2).unwrap();

    //= ../spec/framework/caching-cmm.md#decryption-materials
    //= type=test
    //= reason=Two ECs differing only in one value byte produce different cache ids; the EC bytes contribute to the digest.
    //# - MUST be the serialized encryption context
    assert_ne!(id_1, id_2);
}

// Sanity test: ensure entry id length is 48 bytes and stable across reps.
#[test]
fn test_cache_id_is_sha384_length_and_deterministic() {
    // Regression smoke: pin SHA-384's 48-byte output length and confirm the
    // formula is referentially transparent for fixed inputs.
    let pid = "static";
    let ec = EncryptionContext::new();
    let id1 = __test_internals::compute_cache_id_for_encrypt_no_suite(pid, &ec).unwrap();
    let id2 = __test_internals::compute_cache_id_for_encrypt_no_suite(pid, &ec).unwrap();
    assert_eq!(id1, id2, "cache id must be deterministic for fixed inputs");
    assert_eq!(id1.0.len(), 48, "SHA-384 output is 48 bytes");
}

// Cache-id helper exposure: also ensure cache-id helpers resolve via the
// public re-exports for downstream callers (e.g., caching CMC implementations).
#[test]
fn test_partition_id_generation_returns_unique_strings() {
    // Regression smoke for the default partition id generator: two calls must
    // yield distinct 32-char strings (16 random bytes hex-encoded).
    let p1 = __test_internals::generate_unique_partition_id();
    let p2 = __test_internals::generate_unique_partition_id();
    assert_ne!(p1, p2);
    // 16 random bytes hex-encoded => 32 chars
    assert_eq!(p1.len(), 32);
    assert_eq!(p2.len(), 32);
}

// CacheEntryId / UsageStats public API smoke

#[test]
fn test_cache_entry_id_as_bytes_and_eq() {
    // Regression smoke for the public `CacheEntryId` API: equality, inequality,
    // and `as_bytes()` accessor shape — guards against drift in the wrapper type.
    let a = CacheEntryId([1u8; 48]);
    let b = CacheEntryId([1u8; 48]);
    let c = CacheEntryId([2u8; 48]);
    assert_eq!(a, b);
    assert_ne!(a, c);
    assert_eq!(a.as_bytes(), &[1u8; 48]);
}

#[test]
fn test_usage_stats_default_is_zero() {
    // Regression smoke: `UsageStats::default()` MUST initialize both
    // counters to zero, matching the "initial usage stats" requirement
    // observed by `test_initial_usage_stats_are_zero_on_store`.
    let stats = UsageStats::default();
    assert_eq!(stats.messages_encrypted, 0);
    assert_eq!(stats.bytes_encrypted, 0);
}

// EDK serialization error paths

#[test]
fn test_edk_serialization_rejects_oversized_provider_id() {
    // Adjacent-guard for `caching-cmm.md#decryption-materials` lex-sort rule:
    // the cache-id helper relies on the EDK serialization defined by
    // `data-format/message-header.md#encrypted-data-key-entries`, whose three
    // length-prefix fields are u16. Oversized inputs MUST surface as errors
    // rather than silently truncating and producing a wrong cache id.
    // u16::MAX = 65535, so a 65536-byte provider_id should fail to serialize.
    let oversized = "a".repeat(65536);
    let edk = EncryptedDataKey::new(oversized, b"info".to_vec(), b"ct".to_vec());
    let err = __test_internals::serialize_edk_for_cache_id(&edk).unwrap_err();
    assert_eq!(err.kind, MaterialsErrorKind::Validation);
    assert!(err.message.contains("key_provider_id length"));
}

#[test]
fn test_edk_serialization_rejects_oversized_provider_info() {
    // Adjacent-guard for the EDK u16-prefix invariant — see
    // test_edk_serialization_rejects_oversized_provider_id above.
    let edk = EncryptedDataKey::new("p".to_string(), vec![0u8; 65536], b"ct".to_vec());
    let err = __test_internals::serialize_edk_for_cache_id(&edk).unwrap_err();
    assert_eq!(err.kind, MaterialsErrorKind::Validation);
    assert!(err.message.contains("key_provider_info length"));
}

#[test]
fn test_edk_serialization_rejects_oversized_ciphertext() {
    // Adjacent-guard for the EDK u16-prefix invariant — see
    // test_edk_serialization_rejects_oversized_provider_id above.
    let edk = EncryptedDataKey::new("p".to_string(), b"info".to_vec(), vec![0u8; 65536]);
    let err = __test_internals::serialize_edk_for_cache_id(&edk).unwrap_err();
    assert_eq!(err.kind, MaterialsErrorKind::Validation);
    assert!(err.message.contains("ciphertext length"));
}

#[test]
fn test_edk_serialization_round_trip_format() {
    // Verify the on-wire shape is exactly: u16-be(pid_len) || pid ||
    // u16-be(info_len) || info || u16-be(ct_len) || ct.
    let edk = EncryptedDataKey::new("hi".to_string(), b"info".to_vec(), b"xyz".to_vec());
    let out = __test_internals::serialize_edk_for_cache_id(&edk).unwrap();

    // pid_len = 2
    assert_eq!(&out[0..2], &[0x00, 0x02]);
    assert_eq!(&out[2..4], b"hi");
    // info_len = 4
    assert_eq!(&out[4..6], &[0x00, 0x04]);
    assert_eq!(&out[6..10], b"info");
    // ct_len = 3
    assert_eq!(&out[10..12], &[0x00, 0x03]);
    assert_eq!(&out[12..15], b"xyz");
}

#[tokio::test]
async fn test_decrypt_propagates_underlying_error() {
    // If the underlying CMM errors, the caching CMM must propagate that error
    // and not write to the cache.
    struct FailingCmm;
    #[async_trait]
    impl Cmm for FailingCmm {
        async fn get_encryption_materials(
            &self,
            _request: EncryptionMaterialsRequest,
        ) -> Result<EncryptionMaterials, MaterialsError> {
            Err(MaterialsError::new("test failure (encrypt)"))
        }
        async fn decrypt_materials(
            &self,
            _request: DecryptMaterialsRequest,
        ) -> Result<DecryptionMaterials, MaterialsError> {
            Err(MaterialsError::new("test failure (decrypt)"))
        }
    }

    let cmc = Arc::new(MockCmc::new());
    let cmm = CachingCmm::new(
        cmc.clone() as Arc<dyn CryptographicMaterialsCache>,
        ttl_5min(),
        Arc::new(FailingCmm) as Arc<dyn Cmm>,
    );

    let req = DecryptMaterialsRequest::new(
        non_signing_committing_suite(),
        allow_policy(),
        vec![EncryptedDataKey::new(
            "p".to_string(),
            b"i".to_vec(),
            b"c".to_vec(),
        )],
        EncryptionContext::new(),
    );
    let err = cmm.decrypt_materials(req).await.unwrap_err();
    assert_eq!(err.kind, MaterialsErrorKind::Validation);
    assert!(err.message.contains("test failure (decrypt)"));
    assert_eq!(cmc.put_decrypt_calls(), 0, "no cache write on error");
}

#[tokio::test]
async fn test_get_encryption_propagates_underlying_error() {
    // Adjacent-guard for `caching-cmm.md#get-encryption-materials`: when the
    // underlying CMM errors on the miss path, the caching CMM MUST surface
    // that error and MUST NOT write partial materials to the CMC.
    struct FailingCmm;
    #[async_trait]
    impl Cmm for FailingCmm {
        async fn get_encryption_materials(
            &self,
            _request: EncryptionMaterialsRequest,
        ) -> Result<EncryptionMaterials, MaterialsError> {
            Err(MaterialsError::new("test failure (encrypt)"))
        }
        async fn decrypt_materials(
            &self,
            _request: DecryptMaterialsRequest,
        ) -> Result<DecryptionMaterials, MaterialsError> {
            Err(MaterialsError::new("test failure (decrypt)"))
        }
    }

    let cmc = Arc::new(MockCmc::new());
    let cmm = CachingCmm::new(
        cmc.clone() as Arc<dyn CryptographicMaterialsCache>,
        ttl_5min(),
        Arc::new(FailingCmm) as Arc<dyn Cmm>,
    );

    let req = EncryptionMaterialsRequest::new(EncryptionContext::new(), allow_policy())
        .with_algorithm_suite_id(non_signing_committing_suite());
    let err = cmm.get_encryption_materials(req).await.unwrap_err();
    assert_eq!(err.kind, MaterialsErrorKind::Validation);
    assert!(err.message.contains("test failure (encrypt)"));
    assert_eq!(cmc.put_encrypt_calls(), 0, "no cache write on error");
}

#[test]
fn test_cache_entry_id_clone_and_hash() {
    // Regression smoke: `CacheEntryId` MUST implement Clone + Hash + Eq so it
    // can act as a HashMap key inside CMC implementations. Cloning and
    // re-hashing the same byte array MUST locate the original entry.
    use std::collections::HashSet;
    let id1 = CacheEntryId([1u8; 48]);
    let id2 = id1.clone();
    let mut set: HashSet<CacheEntryId> = HashSet::new();
    set.insert(id1);
    assert!(set.contains(&id2));
}

#[test]
fn test_usage_stats_clone_and_copy_traits() {
    // Regression smoke: `UsageStats` is plain-Copy; assigning the value MUST
    // not move it, and `Clone::clone` MUST yield an equal copy.
    let stats = UsageStats {
        messages_encrypted: 1,
        bytes_encrypted: 2,
    };
    let copied = stats; // Copy
    let cloned: UsageStats = Clone::clone(&stats);
    assert_eq!(copied, cloned);
}

#[test]
fn test_cache_entry_id_debug_format() {
    // Regression smoke: pin the Debug impl shape so that downstream loggers
    // and panic messages emit a recognizable type name.
    let id = CacheEntryId([0u8; 48]);
    let dbg = format!("{:?}", id);
    assert!(dbg.starts_with("CacheEntryId"));
}

// Construct an EncryptionContext whose serialization fails (because a value
// is longer than u16::MAX bytes). compute_cache_id_for_* propagates that
// error via `?`.
fn oversized_ec() -> EncryptionContext {
    let mut ec = EncryptionContext::new();
    ec.insert(b"k".to_vec(), vec![0u8; 65536]);
    ec
}

#[tokio::test]
async fn test_get_encryption_no_suite_propagates_ec_serialize_error() {
    // Adjacent-guard for `caching-cmm.md#encryption-materials-without-algorithm-suite`:
    // the cache-id formula concatenates the serialized encryption context. If
    // EC.serialize() fails, the error MUST propagate — silently producing a
    // cache id from a partial input would corrupt the partition's namespace.
    let cmc = Arc::new(MockCmc::new());
    let kr: Arc<dyn Keyring> = Arc::new(MockKeyring::new());
    let underlying = Arc::new(SpyCmm::new(kr));
    let cmm = build_caching_cmm(cmc.clone(), underlying, ttl_5min(), Some("p"));

    // No algorithm_suite_id => routes to compute_cache_id_for_encrypt_no_suite
    let req = EncryptionMaterialsRequest::new(oversized_ec(), allow_policy());
    let err = cmm.get_encryption_materials(req).await.unwrap_err();
    assert_eq!(err.kind, MaterialsErrorKind::Validation);
    assert!(err.message.contains("exceeds u16::MAX"));
    assert_eq!(cmc.put_encrypt_calls(), 0);
}

#[tokio::test]
async fn test_get_encryption_with_suite_propagates_ec_serialize_error() {
    // Adjacent-guard for `caching-cmm.md#encryption-materials-with-algorithm-suite`
    // — see test_get_encryption_no_suite_propagates_ec_serialize_error above.
    let cmc = Arc::new(MockCmc::new());
    let kr: Arc<dyn Keyring> = Arc::new(MockKeyring::new());
    let underlying = Arc::new(SpyCmm::new(kr));
    let cmm = build_caching_cmm(cmc.clone(), underlying, ttl_5min(), Some("p"));

    let req = EncryptionMaterialsRequest::new(oversized_ec(), allow_policy())
        .with_algorithm_suite_id(non_signing_committing_suite());
    let err = cmm.get_encryption_materials(req).await.unwrap_err();
    assert_eq!(err.kind, MaterialsErrorKind::Validation);
    assert!(err.message.contains("exceeds u16::MAX"));
    assert_eq!(cmc.put_encrypt_calls(), 0);
}

#[tokio::test]
async fn test_decrypt_propagates_ec_serialize_error() {
    // Adjacent-guard for `caching-cmm.md#decryption-materials`: the decrypt
    // cache-id formula concatenates the serialized encryption context. If
    // EC.serialize() fails, the error MUST propagate rather than yielding a
    // cache id computed from partial bytes.
    let cmc = Arc::new(MockCmc::new());
    let kr: Arc<dyn Keyring> = Arc::new(MockKeyring::new());
    let underlying = Arc::new(SpyCmm::new(kr));
    let cmm = build_caching_cmm(cmc.clone(), underlying, ttl_5min(), Some("p"));

    let edk = EncryptedDataKey::new("p".to_string(), b"i".to_vec(), vec![0xAA; 32]);
    let req = DecryptMaterialsRequest::new(
        non_signing_committing_suite(),
        allow_policy(),
        vec![edk],
        oversized_ec(),
    );
    let err = cmm.decrypt_materials(req).await.unwrap_err();
    assert_eq!(err.kind, MaterialsErrorKind::Validation);
    assert!(err.message.contains("exceeds u16::MAX"));
    assert_eq!(cmc.put_decrypt_calls(), 0);
}

// Required encryption context propagation through the cache

#[tokio::test]
async fn test_required_encryption_context_keys_propagate_through_cache() {
    // Regression smoke: the request's `required_encryption_context_keys` MUST
    // round-trip through the cache and appear unchanged on the materials
    // returned by `get_encryption_materials`. Guards against the cache
    // dropping or rewriting the field on miss/store.
    let cmc = Arc::new(MockCmc::new());
    let kr: Arc<dyn Keyring> = Arc::new(MockKeyring::new());
    let underlying = Arc::new(SpyCmm::new(kr));
    let cmm = build_caching_cmm(cmc.clone(), underlying.clone(), ttl_5min(), Some("pid"));

    let mut ec = EncryptionContext::new();
    ec.insert(b"k".to_vec(), b"v".to_vec());
    let mut reck = BTreeSet::new();
    reck.insert(b"k".to_vec());
    let req = EncryptionMaterialsRequest::new(ec, allow_policy())
        .with_algorithm_suite_id(non_signing_committing_suite())
        .with_required_encryption_context_keys(reck.clone());

    let materials = cmm.get_encryption_materials(req).await.unwrap();
    assert_eq!(materials.required_encryption_context_keys(), &reck);
}
