# Specification Security Analysis: AWS Cryptographic Material Providers Library (native-Rust MPL)

> Pipeline artifact — Stage 1 (Specification Ingestion). Produced by the `spec-analyzer` agent against the `esdk-native-mpl` working tree.
>
> **Note on Duvet:** the inline `//= spec/... //# ...` Duvet annotations are **not** present in this checked-out branch's `mpl/src`/`mpl/tests`. They live on the separate `duvet/mpl-annotations` branch. Requirement→code mapping below was therefore done by reading `spec/framework/*.md` and the code directly. Onboarding Duvet onto this branch (or treating this document as the baseline map) is itself a traceability gap.

Scope: key management only — keyrings (`on_encrypt`/`on_decrypt`), CMM materials, branch-key derivation (KBKDF) and wrapping, branch-key-store record integrity and authenticated encryption context, KMS key-id/ARN and MRK matching, algorithm-suite selection and commitment policy, the local + storm-tracking caches, and secret-material lifetime/zeroization. ESDK message-format serialization is out of scope.

Sources: `mpl/src/**`, `prim/src/**`, and `spec/framework/*.md` (submodule populated).

## Architecture Overview

The MPL sits between an ESDK client and the crypto/AWS boundaries. A CMM resolves an algorithm suite and (for signing suites) an ECDSA keypair, then delegates data-key wrapping to a Keyring. Keyrings either wrap locally (RawAesKeyring) or through a branch-key hierarchy (HierarchicalKeyring → cache → BranchKeyStore → KMS/DDB). All primitive crypto is funneled through the `prim` crate (`aws-mpl-primitives`), a thin safe wrapper over `aws-lc-rs`.

```
   ESDK client
        │  EncryptionMaterialsRequest / DecryptMaterialsRequest
        ▼
   ┌─────────────┐   suite + commitment policy resolution
   │ DefaultCmm  │   ECDSA keypair gen (signing suites); pub key → EC["aws-crypto-public-key"]
   └─────┬───────┘   reproduced-EC merge on decrypt
         │ on_encrypt / on_decrypt(materials, edks)
         ▼
   ┌───────────────────────────────┐
   │ Keyring (trait)               │
   │  ├─ RawAesKeyring             │ AES-GCM wrap w/ local key; AAD = serialized EC
   │  └─ HierarchicalKeyring       │
   │        │ resolve branch_key_id (static or supplier)
   │        │ cache_id = SHA-384(scope‖partition‖logicalName‖bkid[‖version])
   │        ▼
   │   ┌─────────┐ miss  ┌──────────────┐ KMS Decrypt/GenDataKey/ReEncrypt
   │   │  Cmc    │──────▶│ BranchKeyStore│───────────────► AWS KMS
   │   │ Local / │       │  (DDB items)  │───────────────► Amazon DynamoDB
   │   │ Storm   │◀──────│  auth-EC bind │
   │   └─────────┘  put  └──────────────┘
   │        │ BranchKeyMaterials(32B branch key)
   │        ▼ branch_key_wrap::wrap/unwrap
   │   KBKDF-CTR-HMAC-SHA256 → 32B derivedBranchKey; AES-256-GCM; AAD binds label‖bkid‖version‖EC
   └───────────────────────────────┘
         │ all primitive crypto
         ▼
   aws-mpl-primitives (prim)  →  aws-lc-rs  (AES-GCM, HMAC, SHA-2, KBKDF, HKDF, ECDSA, CSPRNG)
```

## Component Inventory

| Component | File | Role | Security Properties |
|-----------|------|------|---------------------|
| `prim` crate | `prim/src/lib.rs`, `ecdsa.rs`, `hkdf.rs` | Only crypto primitive surface | AES-GCM seal/open, HMAC, SHA-256/384/512, KBKDF-CTR-HMAC, HKDF, ECDSA sign/verify/keygen, `generate_random_bytes` CSPRNG; constant-time compare; enforces output-buffer lengths; redacts secret key material in `Debug` |
| `Keyring` trait | `keyring/mod.rs` | Abstract wrap/unwrap contract | `on_encrypt`/`on_decrypt`; `Send + Sync` |
| `RawAesKeyring` | `keyring/raw_aes_keyring.rs` | Local AES-GCM wrapping | Validates key length vs suite; rejects `aws-kms`-prefixed namespace; serialized EC as AAD; 12B random IV; redacts wrapping key |
| `HierarchicalKeyring` | `aws_kms/hierarchical_keyring.rs` | KMS-backed branch-key hierarchy | TTL>0; XOR of static bkid / supplier; cache fallthrough; per-EDK filter by provider-id + bkid; aggregates errors |
| `branch_key_wrap` | `aws_kms/branch_key_wrap.rs` | Pure crypto wrap/unwrap of DK under branch key | KBKDF-CTR-HMAC-SHA256 → 32B key; AES-256-GCM; AAD binds label‖bkid‖version‖EC; strict 36-char UUID parse; layout `salt16‖iv12‖version16‖ct‖tag16` |
| `cache_entry_identifier` | `aws_kms/cache_entry_identifier.rs` | Derive cache id | SHA-384 over scope‖partition‖logicalName‖bkid[‖version], null-separated |
| `aws_kms_mrk_match_for_decrypt` | `aws_kms/mrk_match.rs` | MRK equality for decrypt | Rejects alias ARNs defensively; exact match else region-insensitive MRK compare |
| `DefaultCmm` | `cmm/default_cmm.rs` | Suite + policy resolution, signing keypair, EC merge | Enforces commitment policy on encrypt/decrypt; refuses to overwrite reserved EC key; merges reproduced EC with mismatch rejection; extracts/validates verification key |
| `BranchKeyStore` | `keystore/branch_key_store.rs` | DDB+KMS keystore | Validates ARN & table name at construction; atomic `TransactWriteItems` with `attribute_not_exists` guards; optimistic-lock version bump; re-encrypt-to-self to authenticate ACTIVE record |
| `kms_ops` | `keystore/kms_ops.rs` | KMS read/wrap helpers | Builds authenticated EC (every attr except `enc` + `tablename`); binds EC as KMS AAD on Decrypt/GenDataKey/ReEncrypt; resolves/validates ARN; rejects alias in Discovery |
| `kms_config` | `keystore/kms_config.rs` | ARN parse/validate/compat | Rejects non-`kms`, alias; MRK-aware compatibility |
| `record` | `keystore/record.rs` | Record↔materials mapping | Reconstructs auth-EC; strict `type`/`version` validation; branch key MUST be exactly 32 bytes |
| `LocalCmc` | `cmc/local.rs` | In-memory LRU cache, TTL pruning | Single Mutex; capacity 0 = no-store; `Arc<CacheEntry>` clones |
| `StormTrackingCmc` | `cmc/storm_tracking.rs` | Stampede protection | Per-key inflight leader election; lock never held across `.await`; config ordering invariants; inflight TTL |
| Structures | `structures/*.rs` | Materials + suite tables | Suite specification table; materials constructors enforce presence/length invariants; secret newtypes redact `Debug`; `PlaintextDataKey::zeroize` |

## Cryptographic Operations

| Operation | Algorithm | Key Material | Purpose |
|-----------|-----------|--------------|---------|
| Data-key wrap (raw AES) | AES-128/192/256-GCM, 12B IV, 16B tag | local wrapping key (128/192/256-bit) | Wrap PDK; AAD = serialized EC |
| Branch-key derivation | KBKDF-CTR-HMAC-SHA256 (NIST SP 800-108 §4.1), fixed-info `"aws-kms-hierarchy"‖0x00‖salt(16)‖0x00000100` | 32B branch key | Derive 32B `derivedBranchKey` per wrap (fresh 16B salt) |
| Data-key wrap (hierarchical) | AES-256-GCM, 12B random IV, 16B tag | `derivedBranchKey` | Wrap PDK; AAD binds `"aws-kms-hierarchy"‖bkid‖version(16)‖serialized EC` |
| Branch-key protection (at rest) | AWS KMS `GenerateDataKeyWithoutPlaintext`/`ReEncrypt`/`Decrypt`, EC as KMS AAD | KMS CMK (single-key or discovery) | Persist/decrypt 32B branch keys in DDB |
| PDK / salt / IV / partition-id generation | `aws-lc-rs` CSPRNG (`generate_random_bytes`) | — | All randomness in the crate routes through this one primitive |
| Message signing keypair | ECDSA P-256/SHA-256 or P-384/SHA-384; DER private key, X9.62-compressed public (33/49B) | ephemeral per encrypt | CMM attaches signing key; public key published in EC |
| Cache id | SHA-384 (48B digest) | — | Domain-separated cache key |
| Suite key derivation (message) | HKDF-SHA256/384/512 (suite-dependent); Identity KDF for NoKdf suites | — | Suite table; message-level derivation is ESDK's, MPL exposes the parameters |
| Constant-time compare | `aws-lc-rs` `verify_slices_are_equal` | — | Available primitive |

Suite table (`structures/algorithm_suite.rs`) covers the 11 ESDK suites (IDs `00 14`…`05 78`); every suite is AES-GCM, 12B IV, 16B tag; commit-key suites (`04 78`, `05 78`) use HKDF-SHA512 for both encryption and commitment KDF, message-format v2, 32B suite data. DBE/S3EC suites are intentionally unimplemented.

## Key Hierarchy

1. AWS KMS CMK (root of trust; never leaves KMS).
2. Branch key — 32 random bytes generated by KMS `GenerateDataKeyWithoutPlaintext`, stored wrapped in DDB, bound to an authenticated EC (branch-key-id, version, create-time, kms-arn, hierarchy-version, logical keystore name as `tablename`, plus custom `aws-crypto-ec:` pairs). ACTIVE + one DECRYPT_ONLY record per version; a beacon key record too.
3. `derivedBranchKey` — 32 bytes from KBKDF-CTR-HMAC-SHA256(branch key; salt=16 random bytes; label `"aws-kms-hierarchy"`), one per wrap. Never persisted.
4. Plaintext data key (PDK) — random per message (or supplied), wrapped by `derivedBranchKey` (hierarchical) or the local wrapping key (raw AES).

Rotation guidance (spec Appendix B): the 16B salt gives ~2^96 safe derivations before AES-GCM key/IV-reuse risk; annual branch-key rotation recommended.

## Trust Boundaries

| Boundary | From | To | Data Crossing |
|----------|------|----|---------------|
| Client → CMM/Keyring | untrusted request | in-process MPL | encryption context, algorithm suite id, commitment policy, reproduced EC, EDK list, PDK (encrypt) |
| MPL → AWS KMS | in-process | KMS service | wrapped branch-key ciphertext, EC (as KMS AAD), grant tokens, key id/ARN; returns plaintext branch key |
| MPL → Amazon DynamoDB | in-process | DDB service | branch-key items (attributes + `enc` blob); returns stored records |
| Keyring ↔ Cache | in-process | in-process/shared | `BranchKeyMaterials` (contains 32B plaintext branch key) held in cache for TTL |
| MPL → `prim`/aws-lc-rs | in-process | FFI/native | keys, plaintexts, IVs, AAD |
| EDK ciphertext (on wire) | producer | consumer | `salt‖iv‖version‖ct‖tag` (hierarchical) or provider-info‖ct‖tag (raw AES); version and bkid are unauthenticated-until-KDF/AAD |

Most security-relevant: the plaintext branch key lives in memory inside `BranchKeyMaterials` and inside the cache for the whole TTL; the cache may be `Shared` across keyrings, so the cache-id domain separation (partition id + logical keystore name) is the control that prevents cross-tenant material reuse.

## Data Flows

Encrypt (hierarchical):
1. CMM resolves suite (policy default or validated request suite) and, for signing suites, generates ECDSA keypair and inserts base64 public key into a copy of the EC under `aws-crypto-public-key` (refuses if already present).
2. Keyring resolves branch-key-id (static or supplier over the EC).
3. Cache id = SHA-384(0x02‖0x00‖scope=0x01‖0x00‖partition‖0x00‖logicalName‖0x00‖bkid).
4. On cache hit within TTL, reuse `BranchKeyMaterials`; else `get_active_branch_key` from keystore (KMS Decrypt with authenticated EC), then put into cache with `now + ttl` expiry.
5. `wrap`: fresh 16B salt + 12B IV → KBKDF derive 32B key → AES-256-GCM encrypt PDK with AAD = label‖bkid‖version(16)‖serialized EC → assemble `salt‖iv‖version‖ct‖tag`.
6. EDK = { provider-id `"aws-kms-hierarchy"`, provider-info = bkid bytes, ciphertext }.

Decrypt (hierarchical):
1. CMM validates suite against policy for decrypt; merges message EC with reproduced EC (mismatch → fail; reproduced-only keys appended and marked Required).
2. Signing suite: extract + base64-decode verification key from merged EC (missing → fail). Non-signing: reserved key present → fail.
3. Keyring filters EDKs by provider-id and provider-info == resolved bkid.
4. Parse 16B version from ciphertext at offset 28; cache id uses scope=0x02 and includes the version.
5. Cache hit within TTL else `get_branch_key_version` (KMS Decrypt); `unwrap`: re-derive key from stored salt, rebuild AAD from materials' bkid/version + decryption EC, AES-256-GCM open.
6. On success, set PDK on materials; if every candidate fails, aggregate errors.

Keystore CreateKey / VersionKey:
- CreateKey: single-key KMS config required; GenerateDataKeyWithoutPlaintext for DECRYPT_ONLY, ReEncrypt to ACTIVE, GenerateDataKey for beacon; three items written atomically with `attribute_not_exists` guards.
- VersionKey: read ACTIVE; authenticate it by ReEncrypt-to-self with the reconstructed EC (tamper detection); write new DECRYPT_ONLY (must-not-exist) + overwrite ACTIVE guarded by `#enc = :encOld` (optimistic lock).

## Security Configuration Options

| Option | Default | Impact |
|--------|---------|--------|
| Commitment policy | caller-supplied | Governs which suites are allowed for encrypt/decrypt and the default suite; `RequireEncryptRequireDecrypt` forces committing suites both ways |
| Algorithm suite id | policy default | Determines key size, KDF, signing; NoKdf/non-committing weaker than HKDF/commit-key suites |
| `RawAesKeyring` wrapping alg / key | caller-supplied | 128/192/256-bit; key length must match alg; namespace must not start with `aws-kms` |
| `ttl_seconds` (hierarchical) | must be > 0 | Branch-key material lifetime in cache; longer TTL = fewer KMS calls but longer plaintext-key residency |
| `CacheType` | `Default` (1000-entry local) | `Shared` cache spans keyrings — relies on cache-id domain separation |
| `partition_id` | fresh v4 UUID | Distinguishes keyrings sharing a cache; caller-supplied string reused across processes for cache sharing |
| `KmsConfiguration` | caller-supplied | `KmsKeyArn` (byte-equal), `KmsMrKeyArn` (MRK match), `Discovery`/`MrDiscovery` (accept record ARN, reject alias) — controls which CMK may unwrap a record |
| Grant tokens | none | Passed to all KMS calls |
| Storm-tracking knobs | — | grace_period/interval, fan_out, inflight_ttl, sleep_milli; ordering invariants enforced; grace < TTL enforced by keyring |

## Security Invariants (MUST requirements, verified against spec + code)

- Raw AES: "MUST use the serialized encryption context as the additional authenticated data (AAD)" — enforced; EC serialized before any encryption so an unserializable EC fails the op (`raw_aes_keyring.rs`).
- Raw AES: namespace "MUST NOT accept a key namespace of 'aws-kms'" — implemented as a prefix check (also blocks `aws-kms-hierarchy`/`-rsa`/`-ecdh` impersonation).
- Raw AES OnDecrypt: if materials already contain a PDK, "the keyring MUST fail and MUST NOT modify" — enforced; "If no decryption succeeds, the keyring MUST fail" — enforced with aggregated typed errors.
- Hierarchical wrap: MUST 16B random salt, 12B random IV, KBKDF-CTR-HMAC-SHA256 → 32B key, AES-256-GCM with derived IV, 16B tag, AAD = the specified concatenation — all match the spec's numbered steps.
- Hierarchical AAD: `"aws-kms-hierarchy"(17)‖branch-key-id‖version(16)‖EC` — exact.
- Hierarchical EDK: provider-id MUST be `"aws-kms-hierarchy"`, provider-info MUST be the branch-key-id — exact; decrypt MUST filter by both before touching the keystore.
- Hierarchical OnDecrypt failure: MUST yield an error including all collected errors — implemented via `MaterialsError::collection`.
- CMM: commitment policy MUST constrain encrypt (`allows_for_encrypt`) and decrypt (`allows_for_decrypt`); default suite per policy — enforced.
- CMM reproduced-EC merge: shared keys MUST agree (else `EncryptionContextValueMismatch`); reproduced-only pairs appended and become Required Encryption Context Keys so the decryptor rebuilds the same AAD.
- Materials constructors: Required EC keys MUST ⊆ EC; EDKs empty when no PDK; signing/verification/symmetric keys present only when the suite calls for it; verification key length MUST equal the suite's SEC1-compressed length.
- Keystore: KMS Decrypt/ReEncrypt/GenerateDataKey MUST bind the authenticated EC (every record attribute except `enc`, plus `tablename`=logical name) as the KMS AAD; branch key MUST be exactly 32 bytes; record `type`/`version` strictly validated.
- Keystore ARN: config ARN MUST be `kms` service and MUST NOT be an alias; record ARN MUST be compatible with config (byte-equal or MRK match); Discovery MUST reject alias record ARNs.
- MRK match: byte-equal else region-insensitive MRK-ARN compare; alias ARNs rejected (defensive deviation, documented).
- KBKDF/HMAC/digest primitives: output buffer length checked against the algorithm (error, not panic) before writing.

## Constraints and Trade-offs

- **No Duvet coverage in this working tree:** there are no `//=`/`//#` annotations in `mpl/src`/`mpl/tests` on this branch (they exist on `duvet/mpl-annotations`), so requirement→code/test traceability here is manual. A verification gap worth closing.
- Cache holds plaintext branch keys for the whole TTL. `BranchKeyMaterials` redacts `Debug` but does not implement zeroize-on-drop; only `PlaintextDataKey` has an explicit `zeroize` (manual, not `Drop`-driven). Secret residency in the cache and in `SigningKey`/`SymmetricSigningKey` (no zeroization) is a trade-off favoring simplicity/performance over guaranteed scrubbing. Verification/threat-modeling target.
- `PlaintextDataKey::zeroize` uses `write_volatile` in a loop but is not invoked on drop and does not fence against compiler/allocator copies (Vec growth/realloc may leave stale copies) — best-effort, not guaranteed.
- Shared cache correctness depends entirely on cache-id domain separation (partition id + logical keystore name). The code documents that two physical key stores MUST NOT share a logical name; nothing enforces it — a misconfiguration collapses the separation. High-value invariant to model.
- ECDSA fixed-length DER signing retries up to 128 times (probabilistic, ~2^-128 exhaustion) — correct but worth noting for timing analysis.
- Storm-tracking cache requires a Tokio runtime (`tokio::time::sleep`); other runtimes panic on the blocking path.
- Branch-key version parsing (`uuid_str_to_16_bytes`) strictly requires the 36-char hyphenated form; `BranchKeyMaterials::new` does not re-validate the version, trusting upstream to supply a canonical UUID — a latent assumption to verify.
- Ambiguity / silent areas (potential threat surfaces): encryption-context serialization caps entries/lengths at u16::MAX (documented unreachable, returns error); the on-wire branch-key `version` field is not independently authenticated except through the AAD/KDF binding; error messages carry KMS/DDB SDK errors as causes — spot check shows key bytes are redacted and errors carry lengths/ids not key bytes.

## Concise Summary (for threat modeling & verification recommendation)

Key components: `prim` (single crypto choke-point over aws-lc-rs), `RawAesKeyring` and `HierarchicalKeyring` (the two Keyring impls), `branch_key_wrap` (pure KBKDF+AES-GCM wrap/unwrap), `DefaultCmm` (suite/policy resolution, ECDSA keypair, reproduced-EC merge), `BranchKeyStore` + `kms_ops` (DDB/KMS with authenticated-EC binding), `LocalCmc`/`StormTrackingCmc` (caches), and the materials structs (invariant enforcement).

Trust boundaries: client→CMM (untrusted EC/suite/EDKs), MPL→KMS and MPL→DDB (branch-key protection with EC as KMS AAD), and Keyring↔Cache (plaintext 32B branch key resident for the full TTL, possibly in a Shared cache).

Cryptographic operations: AES-128/192/256-GCM (12B IV, 16B tag), KBKDF-CTR-HMAC-SHA256 (32B derivedBranchKey, 16B salt), HKDF-SHA256/384/512, ECDSA P-256/P-384, SHA-384 cache ids, CSPRNG via aws-lc-rs.

Most security-critical invariants to verify/model:
1. Hierarchical wrap AAD = `"aws-kms-hierarchy"‖bkid‖version(16)‖serialized EC` and KBKDF fixed-info = `label‖0x00‖salt‖0x00000100` — the sole integrity binding on wrapped data keys.
2. Keystore KMS calls MUST bind the authenticated EC (all attrs except `enc` + `tablename`); branch key MUST be exactly 32 bytes; VersionKey authenticates ACTIVE via ReEncrypt-to-self + optimistic `#enc = :encOld` lock.
3. Cache-id domain separation (partition id + logical keystore name + scope byte) is the only guard against cross-context branch-key reuse in a Shared cache; nothing enforces unique logical names.
4. Commitment-policy gating on encrypt/decrypt and materials-constructor invariants (RECK ⊆ EC, key presence/length tied to suite, verification-key length).
5. MRK/ARN matching (`aws_kms_mrk_match_for_decrypt`, `is_arn_compatible`) controls which CMK may unwrap a record; alias ARNs rejected.
6. Secret lifetime: plaintext branch keys and signing keys are not zeroized on drop; `PlaintextDataKey::zeroize` is manual/best-effort. Prime target for memory-disclosure threat modeling and no-leak / zeroization proofs.
7. `prim` primitive length checks (KBKDF/HMAC/digest/AES/ECDSA buffer sizes) — candidates for Verus bounds/no-panic proofs.
