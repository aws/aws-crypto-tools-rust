# BUG-06: The hierarchical keyring cache-identifier preimage is not injective when fields contain NUL bytes

Summary: `build_cache_identifier` joins the partition ID, logical key store name, branch key ID and version with single `0x00` separators and no length prefixes. If a field contains `0x00`, two different keyring configurations produce the same SHA-384 cache identifier, so they can read each other's branch key materials from a `Shared` cache. The code follows the layout the spec mandates.

- Confidence: Confirmed by test
- Spec conflict: yes, but the conflict is inside the spec. The code matches the mandated layout in Appendix A exactly, and that layout breaks the spec's own statement that keyrings with different partition IDs "CANNOT share" cache entries.
- Severity: Low. Exploiting this needs a `Shared` cache plus the ability to pick NUL-containing configuration values (partition ID, logical key store name, or branch key ID). If those preconditions hold, the impact is cross-keyring use of branch key materials.
- Related IDs: VR-2026-T13; TM-MPL-009, TM-MPL-010

## Location

Verified against `HEAD a1e23d7`. `mpl/src/aws_kms/cache_entry_identifier.rs:35-66` (`build_cache_identifier`):

```rust
42    let mut buf: Vec<u8> = vec![
43        RESOURCE_ID_HIERARCHICAL_KEYRING,
44        NULL_BYTE,
45        scope_id,
46        NULL_BYTE,
47    ];
49    buf.extend_from_slice(partition_id);
50    buf.push(NULL_BYTE);
52    buf.extend_from_slice(logical_key_store_name.as_bytes());
53    buf.push(NULL_BYTE);
55    buf.extend_from_slice(branch_key_id.as_bytes());
57    if let Some(version) = branch_key_version {
58        buf.push(NULL_BYTE);
59        buf.extend_from_slice(version.as_bytes());
60    }
```

The call sites are `hierarchical_keyring.rs:306` (OnEncrypt) and `:550` (OnDecrypt). The inputs aren't checked for NUL anywhere:
- The partition ID is `s.into_bytes()` of the caller's string (`hierarchical_keyring.rs:196`), or 16 random bytes (`generate_partition_id`, `:269`), which can contain `0x00`.
- The logical key store name is a plain `String` in `mpl/src/keystore/config.rs`. I found no NUL validation by code reading.
- The branch key ID comes from the keyring configuration or a branch key ID supplier (`resolve_branch_key_id`, called at `:299` and `:398`). The version is a 36-character hyphenated UUID string, so it can't contain NUL.

## Expected behavior

`spec/framework/aws-kms/aws-kms-hierarchical-keyring.md#encryption-materials` (and `#decryption-materials`, which uses the same wording):

> All the above fields must be separated by a single NULL_BYTE `0x00`.

The code follows this. The same document, `#partition-id-2` (the "Partition ID" subsection of Shared Cache Considerations), says:

> If the Partition ID is set by the user and is different for two Hierarchical Keyrings (or another Material Provider),
> they CANNOT share the same cache entries in the cache.

and `#shared-cache-considerations` says:

> Users MUST make sure that all of Partition ID, Logical Key Store Name of the Key Store for the Hierarchical Keyring
> and Branch Key ID are set to be the same for two Hierarchical Keyrings if and only they want the keyrings to share
> cache entries.

The "CANNOT share" guarantee holds only when the fields contain no `0x00`. The spec doesn't forbid NUL in any of these fields, so the two sections conflict for NUL-containing inputs. The spec's related MUST, "Users MUST NEVER have two different physical Key Stores with the same Logical Key Store Name" (`#logical-key-store-name`), isn't violated in this reproducer, because the two logical names differ.

## Actual behavior

1. Keyring A uses partition ID `"tenant\0x"` and logical name `"L"`. Keyring B uses partition ID `"tenant"` and logical name `"x\0L"`. Both use branch key ID `"bk"`.
2. Both preimages are `02 00 01 00 "tenant" 00 "x" 00 "L" 00 "bk"`, so the cache identifiers are equal.
3. The same shift works for any pair of adjacent fields. For example, logical name `"L"` with branch key ID `"bk\0x"` collides with logical name `"L\0bk"` with branch key ID `"x"` in the decrypt scope.
4. Both keyrings share a `LocalCmc` as `CacheType::Shared`. A calls OnEncrypt, which fetches A's branch key from keystore A and caches it. B then calls OnEncrypt, gets a cache hit, never calls keystore B, and wraps its data key under A's branch key.

## Impact

- Preconditions: (i) the keyrings share one `Cmc` instance (`CacheType::Shared`), which means they're in the same process; (ii) at least one keyring's partition ID, logical key store name, or branch key ID contains `0x00` at a position chosen to line up with the other keyring's fields; (iii) both keyrings use the same branch key ID suffix (or the equivalent shifted split).
- Realistic exploitability: low. The values come from application configuration, not from message bytes. The realistic case is a multi-tenant application that builds partition IDs or logical names from tenant-supplied strings without rejecting NUL. A branch key ID supplier that returns attacker-influenced strings derived from the encryption context is a second path.
- If those preconditions hold, the consequences are as follows. The keyring that hits the other's entry wraps data keys under, or unwraps with, branch key materials its own keystore never returned. Depending on direction, that means data encrypted for one tenant is wrapped under a branch key another tenant controls (a confidentiality issue), or a tenant decrypts using cached materials it has no KMS access to. In the reverse direction, the entry's owner sees messages its own keystore can't decrypt later. The spec already says a shared cache gives access to materials a keyring "MAY or MAY NOT have direct access to". This finding is that the partition boundary meant to prevent that can be crossed.
- Default random partition IDs contain `0x00` with roughly 6% probability (1 − (255/256)^16). To collide with one, the other keyring would need to know those random bytes, and its logical name, which is a Rust `String`, would have to carry the tail as valid UTF-8. I consider that not practical.
- The Dafny MPL builds the same preimage in `GetActiveCacheId` / `GetVersionCacheId`, with no NUL check in those methods ([AwsKmsHierarchicalKeyring.dfy](https://github.com/aws/aws-cryptographic-material-providers-library/blob/main/AwsCryptographicMaterialProviders/dafny/AwsCryptographicMaterialProviders/src/Keyrings/AwsKms/AwsKmsHierarchicalKeyring.dfy)). I didn't check whether the Dafny constructor validates partition IDs or logical names.

## Reproduction / evidence

Reproducer: `mpl/tests/zz_bugrepro_06_cache_id_nul.rs` (a temporary untracked test, removed from the tree after the run; full source below, copy in `.agents/tasks/bug-reports/reproducers/`). Command: `cd mpl && cargo test --test zz_bugrepro_06_cache_id_nul -- --nocapture`.

```rust
// TEMPORARY reproducer for BUG-06 (T13). Delete after running.
use std::sync::{Arc, Mutex};
use async_trait::async_trait;
use aws_crypto_mpl::aws_kms::__test_internals::{build_cache_identifier, unwrap};
use aws_crypto_mpl::aws_kms::hierarchical_keyring::{SCOPE_ID_DECRYPT, SCOPE_ID_ENCRYPT};
use aws_crypto_mpl::cmc::cache_config::CacheType;
use aws_crypto_mpl::keystore::{KeyStoreInfo, Keystore, KeystoreError, KmsConfiguration};
use aws_crypto_mpl::structures::{
    AlgorithmSuiteId, BeaconKeyMaterials, BranchKeyMaterials, EncryptionContext,
    EncryptionMaterials,
};
use aws_crypto_mpl::{Cmc, HierarchicalKeyring, Keyring, LocalCmc};
const BKID: &str = "bk";
const VERSION: &str = "11111111-2222-4333-8444-555555555555";
struct NamedKeystore {
    logical: &'static str,
    key_byte: u8,
    active_calls: Mutex<u32>,
}
impl NamedKeystore {
    fn materials(&self) -> BranchKeyMaterials {
        BranchKeyMaterials::new([self.key_byte; 32], BKID.into(), VERSION.into(), EncryptionContext::new()).unwrap()
    }
}
#[async_trait]
impl Keystore for NamedKeystore {
    fn get_key_store_info(&self) -> Result<KeyStoreInfo, KeystoreError> {
        Ok(KeyStoreInfo {
            keystore_id: "id".into(),
            keystore_name: "t".into(),
            logical_keystore_name: self.logical.into(),
            grant_tokens: vec![],
            kms_configuration: KmsConfiguration::Discovery,
        })
    }
    async fn create_key_store(&self) -> Result<String, KeystoreError> { unimplemented!() }
    async fn create_key(&self, _: Option<String>, _: Option<EncryptionContext>) -> Result<String, KeystoreError> { unimplemented!() }
    async fn version_key(&self, _: String) -> Result<(), KeystoreError> { unimplemented!() }
    async fn get_active_branch_key(&self, _: String) -> Result<BranchKeyMaterials, KeystoreError> {
        *self.active_calls.lock().unwrap() += 1;
        Ok(self.materials())
    }
    async fn get_branch_key_version(&self, _: String, _: String) -> Result<BranchKeyMaterials, KeystoreError> { Ok(self.materials()) }
    async fn get_beacon_key(&self, _: String) -> Result<BeaconKeyMaterials, KeystoreError> { unimplemented!() }
}
#[test]
fn identifier_collides_when_fields_contain_nul() {
    let a_enc = build_cache_identifier(SCOPE_ID_ENCRYPT, b"tenant\0x", "L", BKID, None);
    let b_enc = build_cache_identifier(SCOPE_ID_ENCRYPT, b"tenant", "x\0L", BKID, None);
    println!("REPRO BUG-06 encrypt-scope ids equal for (p=\"tenant\\0x\", n=\"L\") vs (p=\"tenant\", n=\"x\\0L\"): {}", a_enc == b_enc);
    let a_dec = build_cache_identifier(SCOPE_ID_DECRYPT, b"p", "L", "bk\0x", Some(VERSION));
    let b_dec = build_cache_identifier(SCOPE_ID_DECRYPT, b"p", "L\0bk", "x", Some(VERSION));
    println!("REPRO BUG-06 decrypt-scope ids equal for (n=\"L\", bkid=\"bk\\0x\") vs (n=\"L\\0bk\", bkid=\"x\"): {}", a_dec == b_dec);
    let c = build_cache_identifier(SCOPE_ID_ENCRYPT, b"tenantx", "L", BKID, None);
    println!("REPRO BUG-06 control (no NUL, p=\"tenantx\") equal to first: {}", a_enc == c);
}
#[tokio::test]
async fn shared_cache_serves_other_keyrings_branch_key() {
    let shared: Arc<dyn Cmc> = Arc::new(LocalCmc::new(1000, 1).unwrap());
    let ks_a = Arc::new(NamedKeystore { logical: "L", key_byte: 0xA1, active_calls: Mutex::new(0) });
    let ks_b = Arc::new(NamedKeystore { logical: "x\0L", key_byte: 0xB2, active_calls: Mutex::new(0) });
    let kr_a = HierarchicalKeyring::new(ks_a.clone(), 3600, Some(BKID.into()), None, Some(CacheType::Shared(shared.clone())), Some("tenant\0x".into())).unwrap();
    let kr_b = HierarchicalKeyring::new(ks_b.clone(), 3600, Some(BKID.into()), None, Some(CacheType::Shared(shared.clone())), Some("tenant".into())).unwrap();
    let em = || EncryptionMaterials::new(AlgorithmSuiteId::AlgAes256GcmIv12Tag16NoKdf, vec![], EncryptionContext::new(), Default::default(), None, None, None).unwrap();
    kr_a.on_encrypt(em()).await.unwrap();
    let out_b = kr_b.on_encrypt(em()).await.unwrap();
    println!(
        "REPRO BUG-06 keystore A get_active calls = {}, keystore B get_active calls = {}",
        *ks_a.active_calls.lock().unwrap(),
        *ks_b.active_calls.lock().unwrap()
    );
    let ct = &out_b.encrypted_data_keys()[0].ciphertext;
    println!(
        "REPRO BUG-06 keyring B's EDK unwraps with keystore A's branch key: {}; with keystore B's own branch key: {}",
        unwrap(&ks_a.materials(), &EncryptionContext::new(), ct).is_ok(),
        unwrap(&ks_b.materials(), &EncryptionContext::new(), ct).is_ok()
    );
}
```

The reproducer uses a test `Keystore`. The real `BranchKeyStore` path needs DynamoDB and KMS, so it wasn't run.

Observed output (`.agents/tasks/bug-reports/logs/bugrepro06.log`):

```text
running 2 tests
REPRO BUG-06 encrypt-scope ids equal for (p="tenant\0x", n="L") vs (p="tenant", n="x\0L"): true
REPRO BUG-06 decrypt-scope ids equal for (n="L", bkid="bk\0x") vs (n="L\0bk", bkid="x"): true
REPRO BUG-06 control (no NUL, p="tenantx") equal to first: false
test identifier_collides_when_fields_contain_nul ... ok
REPRO BUG-06 keystore A get_active calls = 1, keystore B get_active calls = 0
REPRO BUG-06 keyring B's EDK unwraps with keystore A's branch key: true; with keystore B's own branch key: false
test shared_cache_serves_other_keyrings_branch_key ... ok
test result: ok. 2 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.02s
```

## Fix options

1. Reject `0x00` in caller-supplied partition IDs and logical key store names in `HierarchicalKeyring::new`, and in resolved branch key IDs before building the identifier.
   - Pros: the preimage stays byte-identical to the spec for every input that's accepted today without NUL, which covers all realistic configurations. Nothing changes for current users, and the cost is a byte scan per field.
   - Cons: it's a behavior change for anyone using NUL (rejected at construction, or at OnEncrypt/OnDecrypt for supplier-provided IDs). It also diverges from the Dafny MPL unless Dafny adds the same check. The default random partition ID isn't covered. It could be regenerated until it's NUL-free, but that changes its distribution slightly, and the residual risk there is already negligible.
2. Change the preimage to length-prefixed fields (for example, a u16 or u32 big-endian length before each variable field).
   - Pros: the encoding becomes injective for all inputs, with no input restrictions.
   - Cons: it needs a spec change and the same change in every runtime. Cache identifiers aren't persisted, so the compatibility cost mostly falls on any cross-runtime shared cache implementation, which I'm not aware of in practice. It still diverges from the current spec text until the spec is updated.
3. Documentation only. State in the rustdoc and the spec that these fields MUST NOT contain `0x00` when a `Shared` cache is used.
   - Pros: no code or behavior change.
   - Cons: the guarantee rests on user discipline. That's the same weakness the logical-name MUST already has.

Recommendation: option 1 for caller-supplied strings, plus a spec issue that either adds the NUL restriction (codifying option 1) or moves to option 2 across runtimes.

## Questions for the engineers

1. Should the spec forbid NUL in partition IDs, logical key store names and branch key IDs, or move to a length-prefixed preimage?
2. Is it acceptable for the Rust MPL to reject NUL-containing values before the Dafny MPL and the other runtimes do the same?
3. Do any known integrations derive partition IDs or logical names from tenant- or request-supplied strings, or run a branch key ID supplier that passes encryption-context values through unchanged?
4. Should the default 16-byte random partition ID be made NUL-free, or is the residual risk acceptable as is?
