# Threat Model: AWS Cryptographic Material Providers Library (MPL)

> Pipeline artifact, Stage 2 (Threat Modeling). Produced by the `threat-model-generator` agent against the `esdk-native-mpl` working tree.
>
> - **Code analyzed:** `mpl/`, `prim/` identical to `origin/main` `620771c` (branch `MPL-Verus`). Previous version of this document analyzed `a1e23d7`.
> - **Status:** Draft for verification prioritization.
> - **Scope:** `mpl/` (key management) built on `prim/` (safe aws-lc-rs wrappers). Message-format concerns (ESDK) are OUT OF SCOPE. The ESDK and the C++ shim appear only as callers.
> - **Methodology:** STRIDE with likelihood × impact risk rating (matrix in the appendix). Each threat has a stable ID `TM-MPL-NNN` referenced by the verification-recommender. IDs are never renumbered or deleted; a threat that no longer applies is marked Retired.
> - Every current `file:line` below was checked against HEAD in this step (see `.agents/tasks/pipeline-rerun-620771c/stage2-notes.md`). Inputs: Stage 1 `docs/spec-security-analysis.md`, `scope.md`, and `docs/bug-reports/RECHECK-main-620771c.md`.
>
> **Note on Duvet:** main has no Duvet config for the MPL. The only configs are `esdk/.duvet/config.toml` and `esdk/shims/aws-esdk-cpp/.duvet/config.toml`, and neither covers an MPL framework spec. `mpl/` and `prim/` contain exactly one annotation block (`mpl/src/cmc/entry.rs:201-204`, `cryptographic-materials-cache.md#usage-metadata`, `type=implication`), which CI does not check. Mitigations below cite code locations and spec sections directly. The gap is tracked as TM-MPL-019.
>
> **Note on cited advisories:** CVE-2026-6550 / GHSA-v638-38fc-rhfv is **verified**. Stage 0 found it, and this step repeated the lookup: the [GitHub Advisory Database entry](https://github.com/advisories/GHSA-v638-38fc-rhfv) and [AWS Security Bulletin 2026-017-aws](https://aws.amazon.com/security/security-bulletins/2026-017-aws/) both describe a key-commitment policy bypass through a shared key cache in the AWS Encryption SDK for Python (also: [repository advisory](https://github.com/aws/aws-encryption-sdk-python/security/advisories/GHSA-v638-38fc-rhfv), [NVD](https://nvd.nist.gov/vuln/detail/CVE-2026-6550)). It does not apply to current MPL code, which has no caching CMM (see TM-MPL-008, TM-MPL-010). Content was rephrased for compliance with licensing restrictions.

## Changes since previous version (a1e23d7 -> 620771c)

20 commits touch `mpl/` and `prim/` (141 files, +32298 / −8753, mostly generated error code, test servers and tests). Fixed on main: BUG-02, BUG-03, BUG-09 (all `e9bde48`, #98). Still open: BUG-01, BUG-04, BUG-05(a), BUG-05(b), BUG-06, BUG-07(a/b), BUG-08.

Rating changes:

| ID | Threat | Old risk | New risk | What changed | Evidence |
|---|---|---|---|---|---|
| TM-MPL-009 | Cache-identifier collision | Medium (High × Low) | **High** (High × Medium) | Likelihood Low → Medium. The old rating assumed the identifier was injective. BUG-06 is a confirmed open defect on main: keyring B was served key store A's branch key end to end | RECHECK BUG-06 (2 passed; key store B never called); `cache_entry_identifier.rs:42-60` (unchanged since a1e23d7); no NUL check on inputs (`hierarchical_keyring.rs:596`, `:600-605`) |
| TM-MPL-010 | Shared-cache confusion | Medium (High × Low) | **High** (High × Medium) | Likelihood Low → Medium (BUG-06 realizes this threat). The "cached suite vs commitment policy" residual is withdrawn: only branch keys are cached, and they do not depend on the policy. Exact TTL check (BUG-09 fixed) | As above; `CachedMaterials::BranchKey` at `hierarchical_keyring.rs:700`, `:943`; `:989-995` |
| TM-MPL-015 | Secret material not zeroized | Medium (High × Low) | **Low** (Medium × Low) | Severity High → Medium. Zeroize-on-drop now covers every long-lived secret type. Only transient and error-path copies remain | `algorithm_suite.rs:505`, `:571`, `:655`; `branch_key_materials.rs:205-219`; `beacon_key_materials.rs:221-235`; `raw_aes_keyring.rs:72-78`, `:233-239`; `branch_key_wrap.rs:135`; `record.rs:100`, `:173` |
| TM-MPL-024 | **New:** C++ shim dereferences raw handles to MPL objects | n/a | **Medium** (High × Low) | New attack surface: the shim was retargeted onto the native MPL in `e9bde48` (#98) | `esdk/shims/aws-esdk-cpp/src/lib.rs:720`, `:728`, `:1564-1565`, `:1655` |

Rating unchanged, but mitigation or status changed (each carries a "Changed since a1e23d7" note below):

| ID | Change |
|---|---|
| TM-MPL-003 | Supplier is a public trait (`hierarchical_keyring.rs:187`). A supplier returning NUL-containing ids is one BUG-06 path |
| TM-MPL-005 | BUG-08 (dead collision branch, informational) confirmed still present. No security impact |
| TM-MPL-006 | Stronger: keyrings cannot change the suite (transition checks), PDK length bound to the suite (BUG-02 fixed), ESDK re-checks CMM output against the policy. FORBID default suite is now `03 78` (a documented spec deviation) |
| TM-MPL-007 | BUG-04 confirmed open: MRDiscovery rewrites the region of non-MRK ARNs. It fails closed |
| TM-MPL-008 | CVE-2026-6550 now verified. Not applicable to the current code |
| TM-MPL-013 | EC `from_bytes` is now strict about order, duplicates and UTF-8 (BUG-03 fixed) |
| TM-MPL-017 | Transition checks stop a keyring from altering the EC or required EC keys |
| TM-MPL-018 | **Mitigation regressed:** `StormTrackingCmcBuilder::build` no longer enforces the spec's Inflight TTL ≤ Grace Period, Grace Interval ≤ Grace Period, or "at least 1". BUG-01(b/c) overflow panics are open. The lock-poison panic was removed from the hot path |
| TM-MPL-019 | Duvet status re-measured: there is no MPL config and only 1 annotation. The spec now floats on `master` (#91) instead of a pinned submodule |
| TM-MPL-020 | User agent corrected: `AwsCryptographicMPL-Rust/<version>` on every KMS call |
| TM-MPL-021 | Previous residual closed: `PlaintextDataKey`, `SigningKey` and `SymmetricSigningKey` redact `Debug`. Errors carry `DataKeyInfo` without ciphertext |
| TM-MPL-022 | The default cache is now `DefaultCmc` (storm-tracking, capacity 1000) |
| TM-MPL-023 | BUG-02 fixed. EDK-count O(n²) error memory fixed (#186). BUG-05(a), BUG-05(b), BUG-01(a/d) and BUG-07(b) recorded |

Location updates only (logic unchanged): TM-MPL-001, 002, 004, 011, 012, 014, 016.

Retired: **none**. Every threat still applies to current code.

Considered and **not** added as new threats:
- Pluggable `KeyStore` / `Cmc` / supplier traits. These are not new: the RECHECK adaptation notes show that the old `Keystore` trait (whose fake returned a logical name) and `CacheType::Shared(Arc<dyn Cmc>)` existed at a1e23d7. Their unchecked results are now recorded under TM-MPL-005/009/010.
- Materials checks run only on the fluent `send()` path. This is a mitigation. Bypassing it requires the caller's own direct trait call.
- Optional cargo features (#136). This is configuration, with no attacker. See section 9.
- Test servers (`mpl/test-server`, `prim/test-server`). They bind `127.0.0.1` (`mpl/test-server/src/main.rs:27`, `prim/test-server/src/main.rs:24`) and are not shipped. Flagged only.
- Spec floating on `master`. Folded into TM-MPL-019.
- EDK-count memory amplification. This surface existed before and was fixed by #186. Folded into TM-MPL-023.
- Caching CMM (CVE-2026-6550 class). No caching CMM exists in the code. Recorded as a future-work note under TM-MPL-008/010.

Bug → threat mapping (current status):

| Bug | Status on main | Threat(s) | Effect on rating |
|---|---|---|---|
| BUG-01 `SystemTime + Duration` overflow panic | Open | TM-MPL-018, TM-MPL-023 | None (config-driven, availability) |
| BUG-02 PDK length not enforced | **Fixed** | TM-MPL-006, TM-MPL-023 | Mitigation added. No old rating depended on it |
| BUG-03 EC deserialize accepts unsorted | **Fixed** | TM-MPL-013 | Mitigation added |
| BUG-04 MRDiscovery rewrites non-MRK region | Open | TM-MPL-007 | None (fails closed) |
| BUG-05(a) `.expect` on ECDSA keygen | Open | TM-MPL-023 | None |
| BUG-05(b) 44–59-byte EDK reaches key store | Open (likely not a bug) | TM-MPL-023 | None |
| BUG-06 cache id not injective with NUL | Open, end-to-end confirmed | TM-MPL-009, TM-MPL-010, TM-MPL-003 | **009 and 010 raised to High** |
| BUG-07(a) `aes_encrypt` leaves plaintext on `Err` | Open | TM-MPL-015 | Counted in the Low residual |
| BUG-07(b) `aes_decrypt` guard weaker than callee | Open | TM-MPL-023 | None |
| BUG-08 dead collision branch | Open (informational) | TM-MPL-005 | None |
| BUG-09 TTL admits ttl + 1 s | **Fixed** | TM-MPL-010 | Mitigation added |

## 1. Executive Summary

The MPL produces and manages data keys, branch keys and key wrapping for the AWS Encryption SDK and related clients. Its security rests on six things:
- (a) AES-GCM wrapping in the raw-AES and hierarchical keyrings.
- (b) KBKDF branch-key derivation.
- (c) AWS KMS as the root of trust for branch and beacon keys.
- (d) DynamoDB as tamper-evident (KMS-authenticated) branch-key storage.
- (e) An in-process cache that reduces KMS calls.
- (f) Commitment-policy and algorithm-suite selection enforced by the CMM. On `main`, materials-transition checks run on every fluent `send()` and enforce this further.

Since a1e23d7 the code has gained:
- Zeroize-on-drop for all long-lived secret types.
- Constant-time comparison of secrets.
- Plaintext-data-key length enforcement.
- Strict encryption-context decoding.
- Exact cache-TTL comparison.
- Dafny-derived materials checks.
- A single error model that never carries EDK ciphertext.

`mpl/` and `prim/` no longer contain any `unsafe` code.

Highest-priority residual risks for formal verification:
1. Cache-identifier injectivity and cross-keyring isolation (TM-MPL-009, TM-MPL-010). This risk is now High because BUG-06 is confirmed on main.
2. Branch-key record substitution and the authenticated-EC binding (TM-MPL-005).
3. AES-GCM IV uniqueness in both keyrings (TM-MPL-011, TM-MPL-012).
4. Branch-key AAD and KBKDF fixed-info construction (TM-MPL-013, TM-MPL-014).
5. MRK/ARN resolution, where BUG-04 is open (TM-MPL-004, TM-MPL-007).
6. Commitment-policy enforcement (TM-MPL-006).
7. Storm-tracking configuration and state machine. Validation has regressed against the spec (TM-MPL-018).
8. The new C++ shim handle boundary (TM-MPL-024).

## 2. System Overview

```
                Caller (ESDK / C++ shim / DB-ESDK / S3EC)
                                 |
        SharedCmm::get_encryption_materials() / decrypt_materials() .send()
                                 v
   +---------------------------------------------------------------+
   | SharedCmm send(): check_*_materials_complete (output)         |  cmm/fluent_builders.rs:171,:319
   |   DefaultCmm: commitment policy + suite, ECDSA keygen,        |  cmm/default_cmm.rs
   |   reproduced-EC merge                                         |
   +---------------------------------------------------------------+
                                 |  SharedKeyring::on_encrypt()/on_decrypt() .send()
                                 v
   +---------------------------------------------------------------+
   | SharedKeyring send(): check_*_transition(before, after)       |  keyring/fluent_builders.rs:82,:163
   |   RawAesKeyring                 HierarchicalKeyring           |
   +---------------------------------------------------------------+
        |                              |                 |
   AES-GCM (prim)              SharedCmc cache     SharedKeyStore
   local wrapping key          DefaultCmc=          DynamoDbKeyStore
   (zeroize on drop)           StormTracking->Local    |          |
                               (in-process)          AWS KMS   Amazon DynamoDB
                                    |              (EC as AAD) (branch-key records)
                          branch_key_wrap (KBKDF + AES-256-GCM, derived key Zeroizing)
                                    |
                              prim (aws-mpl-primitives)
                    AES-GCM / KBKDF / HKDF / HMAC / ECDSA / digest / RNG / ct-compare
                                    |
                     aws-lc-rs (aws-lc-sys or FIPS) FFI; no `unsafe` in mpl/ or prim/
```

Trust: the process, the local AES wrapping key and the in-process cache are trusted. AWS KMS is the trusted root of trust for branch and beacon keys. DynamoDB is untrusted for integrity; the KMS EC binding makes its records tamper-evident. `aws-lc-rs` is reached only through the safe `prim` wrappers. User-supplied `KeyStore`, `Cmc` and `BranchKeyIdSupplier` implementations are trusted code whose results are not validated (TB7). C++ callers reach MPL objects through raw handles in the shim (TB8).

## 3. Assets

| ID | Asset | Type | Notes |
|----|-------|------|-------|
| A1 | Plaintext data keys (`PlaintextDataKey`) | Confidentiality | Zeroized on drop (`structures/algorithm_suite.rs:505`). Length bound to the suite (`:547`) |
| A2 | Branch keys (`BranchKeyMaterials.branch_key`, `[u8;32]`) | Confidentiality | Root of the derived-key hierarchy. Cached in-process for the TTL. Zeroized on drop (`structures/branch_key_materials.rs:205-219`) |
| A3 | Derived branch keys (`derivedBranchKey`, 32 B) | Confidentiality | Transient AES-256-GCM key per wrap/unwrap, `Zeroizing` (`aws_kms/branch_key_wrap.rs:125`, `:135`) |
| A4 | Raw-AES wrapping key | Confidentiality | Long-lived local secret. Zeroized on drop (`keyring/raw_aes_keyring.rs:72-78`) |
| A5 | ECDSA signing key (`SigningKey`) | Confidentiality/Integrity | Generated per encryption for signing suites. Zeroized on drop (`algorithm_suite.rs:571`) |
| A6 | Beacon keys | Confidentiality | Searchable-encryption root key. Zeroized on drop (`structures/beacon_key_materials.rs:221-235`) |
| A7 | Branch-key-store DDB records (`enc`, `kms-arn`, EC attrs) | Integrity | Tamper-evidence via the KMS EC binding |
| A8 | Encryption context / AAD | Integrity | Binds ciphertext to context. Must survive the round trip |
| A9 | Algorithm suite id + commitment policy | Integrity | Determines whether key commitment is required |
| A10 | Cache entries (branch-key materials + creation/expiry) | Conf./Integrity/Avail. | In-process. Keyed by a SHA-384 identifier |
| A11 | KMS grant tokens / key ARNs (config) | Integrity | Determine which KMS key authorizes operations |
| A12 | CSPRNG output (IVs, salts, data keys, partition id) | Integrity | From `prim::generate_random_bytes` (`prim/src/lib.rs:128`) |

## 4. Actors

Legitimate: the application caller; KMS (root of trust); DynamoDB (storage); operators configuring the key store and keyrings.

Threat actors:
- TA1, DynamoDB tamperer: read/write access to the branch-key table but NOT to KMS keys.
- TA2, malicious or confused caller: controls the encryption context, reproduced EC, algorithm-suite id and branch-key supplier inputs, and can submit crafted EDKs (count, provider id/info, ciphertext) on decrypt.
- TA3, co-tenant sharing a cache: can influence its own partition id, logical key store name or branch-key id (for example, values derived from a tenant name).
- TA4, in-process memory adversary: reads freed heap, core dumps or swap (post-exploitation, cold-boot).
- TA5, network attacker between the MPL and KMS/DDB. TLS is assumed; the residual is downgrade or DoS.
- TA6, supply-chain adversary targeting `aws-lc-rs`, `uuid`, `lru`, `zeroize`, or the SDK dependencies.
- TA7, C++ caller of the shim that passes dangling or forged handles (bug or hostile code in the same process). New, see TM-MPL-024.

## 5. Trust Boundaries

| ID | Boundary | Crossing | Controls |
|----|----------|----------|----------|
| TB1 | Caller ↔ MPL API | Materials requests, EC, EDKs, suite id | CMM validation, reserved-key checks, commitment policy, materials checks on `send()` |
| TB2 | MPL ↔ AWS KMS | GenerateDataKeyWithoutPlaintext / ReEncrypt / Decrypt | KMS auth, EC as AAD, key-ARN restriction, grant tokens |
| TB3 | MPL ↔ DynamoDB | GetItem / TransactWriteItems | KMS EC binding makes records tamper-evident; conditional writes |
| TB4 | Keyring ↔ in-process cache | put/get cache entry | SHA-384 cache identifier (not injective with NUL, BUG-06), exact TTL, materials-kind check |
| TB5 | `mpl`/`prim` ↔ `aws-lc-rs` FFI | AES-GCM/KDF/ECDSA/RNG calls | Safe `prim` wrappers, length checks, `Nonce::try_assume_unique_for_key` |
| TB6 | Process memory ↔ OS | Freed heap, swap, core dump | Zeroize-on-drop for secret types, `Debug` redaction. Transient copies remain (TM-MPL-015) |
| TB7 | MPL ↔ user-supplied components | `KeyStore`, `Cmc`, `BranchKeyIdSupplier`, user `Keyring`/`Cmm` | Keyring/CMM output checked by `send()`. Key store, cache and supplier output not checked (`key_store/client_impl.rs:305-308`, `:373-376`). Only the material kind of a cache entry is checked (`aws_kms/hierarchical_keyring.rs:1000`) |
| TB8 | C++ ↔ shim ↔ MPL (new) | Raw handle pointers to keyrings, CMMs, caches, clients | Null checks only (`esdk/shims/aws-esdk-cpp/src/lib.rs:720`) |

## 6. Data Flow Diagrams

Encrypt (hierarchical):
```
caller EC ──> SharedCmm.get_encryption_materials().send()
                  │ DefaultCmm: suite = policy default or requested (allows_for_encrypt)
                  │ reserved key check; ECDSA keygen (.expect, BUG-05a)
                  v
            SharedKeyring.on_encrypt().send()
                  │ resolve branch_key_id (static | supplier(EC))
                  │ cache_id = SHA384(0x02‖0‖0x01‖0‖partition‖0‖logicalName‖0‖bkid)   (BUG-06)
             cache hit (elapsed <= ttl)? ── yes ──> branch_key_wrap::wrap
                  │ no                                    ^
                  v                                       │ KBKDF(salt) -> derivedKey (Zeroizing)
          KeyStore.get_active_branch_key                  │ AES-256-GCM(iv, aad=label‖bkid‖ver‖EC)
                  │ KMS Decrypt(enc, auth EC as AAD)      │
                  v                                       │
     put cache (expiry = now + ttl, unchecked: BUG-01) ───┘
                  v
     EDK{ kpid="aws-kms-hierarchy", kpinfo=resolved bkid, ct=salt‖iv‖ver‖enc‖tag }
                  │ check_encryption_transition; check_encryption_materials_complete
```

Decrypt (hierarchical):
```
EDKs + reproduced EC ──> SharedCmm.decrypt_materials().send()
      │ allows_for_decrypt(suite); merge reproduced EC; verification key
      v
 SharedKeyring.on_decrypt().send()  (filter kpid, UTF-8 kpinfo, bkid equality)
      │ len >= 44 -> version = ct[28..44]   (60-byte check later: BUG-05b)
      │ cache_id = SHA384(0x02‖0‖0x02‖0‖partition‖0‖logicalName‖0‖bkid‖0‖version)
   cache hit (elapsed <= ttl) or KeyStore.get_branch_key_version -> BranchKeyMaterials
      │ branch_key_wrap::unwrap: len >= 60; KBKDF(salt) -> AES-256-GCM open(iv, aad)
      v
   add_data_key (length checked) -> check_decryption_transition -> check_decryption_materials_complete
```

## 7. Threat Identification (STRIDE)

### Spoofing
| ID | Threat | Component |
|----|--------|-----------|
| TM-MPL-001 | Raw-AES keyring emits an EDK whose key-provider-id impersonates an AWS KMS keyring | `RawAesKeyringBuilder::build` |
| TM-MPL-002 | Forged branch-key-store record decrypts under an attacker-influenced KMS key (key-id confusion) | `kms_ops::decrypt_branch_key` |
| TM-MPL-003 | Malicious branch-key supplier returns an attacker-chosen branch key id | `HierarchicalKeyring::resolve_branch_key_id`, `BranchKeyIdSupplier` |

### Tampering
| ID | Threat | Component |
|----|--------|-----------|
| TM-MPL-004 | ARN/MRK match logic accepts a non-matching key ARN (over-permissive match) | `mrk_match`, `kms_config::is_arn_compatible` |
| TM-MPL-005 | Branch-key record substitution: swap in a valid record from another branch-key-id/version | `DynamoDbKeyStore`, `kms_ops`, `record` |
| TM-MPL-013 | Branch-key wrap/unwrap AAD built inconsistently, breaking context binding | `branch_key_wrap::compute_aad` |
| TM-MPL-016 | VersionKey optimistic-lock bypass overwrites the ACTIVE record (version race) | `DynamoDbKeyStore::version_key` |
| TM-MPL-017 | Encryption-context / reproduced-EC merge lets an attacker drop or alter bound context | `default_cmm::merge_reproduced_encryption_context` |

### Repudiation
| ID | Threat | Component |
|----|--------|-----------|
| TM-MPL-020 | No audit binding between an MPL operation and the KMS/DDB calls it triggered | key store, keyring |

### Information Disclosure
| ID | Threat | Component |
|----|--------|-----------|
| TM-MPL-015 | Secret material (branch keys, data keys, derived keys, wrapping key) not zeroized | structures, `branch_key_wrap`, `raw_aes_keyring`, `prim` |
| TM-MPL-021 | Secret bytes leak via `Debug`/error/log formatting | structures, error model |
| TM-MPL-010 | Shared-cache confusion serves branch-key materials to a keyring that should not access them | `cache_entry_identifier`, `hierarchical_keyring` |

### Denial of Service
| ID | Threat | Component |
|----|--------|-----------|
| TM-MPL-018 | Storm-tracking misconfiguration or logic error causes a stampede, deadlock, InFlightTTL failures or a panic | `cmc/storm_tracking` |
| TM-MPL-022 | Cache exhaustion / eviction thrash forces a KMS-call storm (throttling) | `cmc/local`, `cmc/default` |
| TM-MPL-023 | Malformed EDK/ciphertext or extreme configuration triggers a panic or resource blow-up instead of an error | `branch_key_wrap::unwrap`, keyrings, `default_cmm` |

### Elevation of Privilege
| ID | Threat | Component |
|----|--------|-----------|
| TM-MPL-006 | Algorithm-suite downgrade / commitment-policy bypass | `default_cmm`, `commitment_policy`, materials checks |
| TM-MPL-007 | Discovery/MRDiscovery config decrypts a record under an alias or attacker-region key | `kms_ops::resolve_key_store_arn` |
| TM-MPL-009 | Cache-identifier collision returns the wrong branch-key materials | `cache_entry_identifier` |
| TM-MPL-011 | AES-GCM IV reuse in the raw-AES keyring | `raw_aes_keyring::wrap_data_key`, `prim::aes_encrypt` |
| TM-MPL-012 | AES-GCM salt/IV reuse in branch-key wrap (birthday-bound collision) | `branch_key_wrap::wrap` |
| TM-MPL-014 | KBKDF fixed-info / L-value misuse weakens branch-key derivation | `branch_key_wrap::derive_branch_key` |
| TM-MPL-008 | Non-committing suite reused where commitment is expected (Invisible Salamanders) | `commitment_policy`, `default_cmm` |
| TM-MPL-019 | Missing Duvet coverage lets a spec MUST silently regress | whole library |
| TM-MPL-024 | C++ shim dereferences a dangling or forged handle to an MPL object (new) | `esdk/shims/aws-esdk-cpp` (boundary) |

## 8. Threat Analysis and Mitigations (per threat)

**TM-MPL-001 (S): Raw-AES key-provider-id impersonation.** Attack: the caller sets `key_namespace = "aws-kms"` (or `aws-kms-hierarchy`), so its EDKs look like KMS-keyring EDKs. Mitigation: `RawAesKeyringBuilder::build` rejects any namespace that starts with `aws-kms` (`mpl/src/keyring/raw_aes_keyring.rs:52`, `:360`). The spec section is raw-aes-keyring.md. Severity Medium, Likelihood Low → Low. Residual: the check is only a prefix heuristic. (Location only: the check moved from `new()` into `build()`.)

**TM-MPL-002 (S): Branch-key record decrypts under an attacker-influenced KMS key.** Attack: TA1 writes a record whose `kms-arn` points at an attacker-controlled key. Mitigation: for `KmsKeyArn`/`KmsMrKeyArn`, `resolve_key_store_arn` sends the CONFIGURED ARN as `KeyId` after the compatibility check (`mpl/src/key_store/kms_ops.rs:88`, `:94-95`, `:105`). `DynamoDbKeyStore::build` validates the configured ARN (`key_store/branch_key_store.rs:381`). The spec section is branch-key-store.md (`KeyId` rule). Severity Critical, Likelihood Low → Medium. Residual: by spec, Discovery modes trust the record ARN (`kms_ops.rs:96-103`). (Location only.)

**TM-MPL-003 (S): Malicious branch-key supplier.** The supplier is caller-provided trusted code (public trait `BranchKeyIdSupplier`, `mpl/src/aws_kms/hierarchical_keyring.rs:187`). The resolved id is bound into the cache id (`:665`, `:908`) and the EDK provider info (`:722`). The AAD uses the id of the returned materials (`branch_key_wrap.rs:61`), so a mismatched id fails authentication on decrypt. Severity Medium, Likelihood Low → Low. **Changed since a1e23d7:** a supplier that returns attacker-influenced ids containing `0x00` (for example, ids derived from the EC) is one of the BUG-06 collision paths (TM-MPL-009). The rating is unchanged because the collision is rated under TM-MPL-009.

**TM-MPL-004 (T): Over-permissive ARN/MRK match.** Mitigation: `aws_kms_mrk_match_for_decrypt` rejects aliases (`mpl/src/aws_kms/mrk_match.rs:24-28`). It returns true only on byte equality or, for MRK ARNs (`is_multi_region_arn`, `:52`; `key/mrk-` prefix `:57`), when every part except the region is equal. `is_arn_compatible` is at `mpl/src/key_store/kms_config.rs:86`. The spec section is aws-kms-mrk-match-for-decrypt.md. Severity High, Likelihood Low → Medium. Residual: ad-hoc `split(':')` ARN parsers, a strong verification candidate. The private `rewrite_arn_region`/`reject_alias_arn` still have no direct tests (Stage 1/scope). (Location only.)

**TM-MPL-005 (T): Branch-key record substitution.** Mitigation: every non-`enc` attribute (branch-key-id, type, version, kms-arn, hierarchy-version, create-time, custom EC, plus `tablename` = logical name) is put in the KMS encryption context. KMS Decrypt/ReEncrypt then authenticates it as AAD (`kms_ops::build_authenticated_encryption_context`, `mpl/src/key_store/kms_ops.rs:49`; DDB codec `key_store/branch_key_store.rs:1089`, `:1141`). Materials are rebuilt only from the authenticated EC, with a strict 32-byte branch-key check (`key_store/record.rs:95`, `:164`). The spec section is branch-key-store.md. Severity Critical, Likelihood Medium → High (mitigated). Residual: correctness rests on the reconstructed EC exactly matching the write-time EC, which is the top verification target. A user-supplied `KeyStore` sits outside this mitigation entirely, and the keyring does not compare the returned materials' bkid/version with the request (`hierarchical_keyring.rs:692-696`, `:934-939`; `key_store/client_impl.rs:305-308`). On decrypt the AAD still binds them. **Changed since a1e23d7:** BUG-08 is confirmed still present (`key_store/encryption_context.rs:92-102`: a custom-EC collision `Err` that can never trigger, because prefixed keys from a `BTreeMap` cannot collide). This is informational and does not change the rating.

**TM-MPL-006 (E): Suite downgrade / commitment-policy bypass.** Attack (Invisible Salamanders class): force encryption or decryption with a non-committing suite where commitment is required. Mitigations:
- `DefaultCmm` rejects a requested suite that is not `allows_for_encrypt` (`mpl/src/cmm/default_cmm.rs:97`) and a message suite that is not `allows_for_decrypt` (`:184`). The tables are at `mpl/src/structures/commitment_policy.rs:62`, `:77`.
- New: the transition check stops a keyring from changing the suite (`mpl/src/structures/materials_checks.rs:78-81`, decrypt `:117`). It runs on every `SharedKeyring` `send()` (`keyring/fluent_builders.rs:82`, `:163`).
- New: the PDK length is bound to the suite's key length (`algorithm_suite.rs:547`; BUG-02 fixed).
- New, caller-side: the ESDK re-checks the CMM's returned suite against its policy (`esdk/src/materials.rs:130`, `:202`; `esdk/src/decrypt.rs:413`). This matters because `SharedCmm::send()` checks only completeness, not the policy (`materials_checks.rs:157-187`).

The spec section is commitment-policy.md. Severity Critical, Likelihood Low → Medium. **Changed since a1e23d7:** the mitigations are stronger. The `FORBID_ENCRYPT_ALLOW_DECRYPT` default suite is now `03 78` (`commitment_policy.rs:46-50`), a documented deviation from the spec's `00 14`. It is stronger and still non-committing, as FORBID requires. The rating is unchanged: the allow tables have not been proven correct and have no Duvet trace.

**TM-MPL-007 (E): Discovery/MRDiscovery alias or attacker-region key.** Mitigation: `resolve_key_store_arn` rejects alias ARNs for both discovery modes (`kms_ops.rs:96-103`, `reject_alias_arn` `:118`). It is called from `decrypt_branch_key` (`:162`, `:179`). Severity High, Likelihood Low → Medium. **Changed since a1e23d7:** BUG-04 is confirmed open. The MrDiscovery arm rewrites the region of *any* record ARN, including single-Region keys (`:100-103`, `rewrite_arn_region` `:144`; no `mrk-` check). branch-key-store.md#mrdiscovery says "Any MRK ARN discovered will be changed", while the KeyId rule in the same document says "with the region replaced". The effect is a KMS call to an ARN for a key that does not exist or is a different key, so it fails closed; it does not decrypt under an attacker key. The KMS-side behavior needs AWS and was not run. The rating is unchanged.

**TM-MPL-008 (E): Non-committing suite reuse (Invisible Salamanders).** Grounded in Invisible Salamanders (Dodis et al., IACR 2019/016) and **CVE-2026-6550 / GHSA-v638-38fc-rhfv (verified)**. In the AWS Encryption SDK for Python, a caching CMM shared by clients with different commitment policies could serve non-committing materials. Mitigation as TM-MPL-006. Commit-key suites (`05 78`) are the default under the REQUIRE policies (`commitment_policy.rs:43-58`). Severity High, Likelihood Low → Medium. **Changed since a1e23d7:** the CVE is now verified. It does not apply to current code, because `mpl/src/cmm/` contains no caching CMM. `CachedMaterials::Encryption`/`Decryption` exist (`mpl/src/cmc/entry.rs:26`, `:28`), so any future caching CMM must bind the commitment policy (or the suite) into its cache id.

**TM-MPL-009 (E): Cache-identifier collision.** The identifier is SHA-384 over `0x02 ‖ 0 ‖ scope ‖ 0 ‖ partition ‖ 0 ‖ logicalName ‖ 0 ‖ bkid [‖ 0 ‖ version]`, with single NUL separators and no length prefixes (`mpl/src/aws_kms/cache_entry_identifier.rs:35`, `:42-60`). The call sites are `hierarchical_keyring.rs:665`, `:908`. The layout is exactly what aws-kms-hierarchical-keyring.md requires ("All the above fields must be separated by a single NULL_BYTE"). The spec's #partition-id section also says keyrings with different partition IDs "CANNOT share" cache entries, and that holds only if no field contains `0x00`.

Attack (BUG-06, confirmed on main):
1. Keyring A uses partition `"tenant\0x"` and logical name `"L"`. Keyring B uses partition `"tenant"` and logical name `"x\0L"`. Both use bkid `"bk"`.
2. The two preimages are identical, so the cache ids are equal.
3. With one shared cache, A's OnEncrypt caches A's branch key. B then gets a hit, never calls key store B, and wraps its data key under A's branch key.
4. The same shift works between any two adjacent fields.

Nothing checks the inputs. The partition id is the caller's raw bytes (`hierarchical_keyring.rs:596`). The default random 16-byte UUID can contain `0x00` (`:626`). The logical name is used as the key store returns it (`:600-605`). The bkid comes from config or a supplier. The only post-hit guard is the material-kind check (`:1000`). Severity High (cross-tenant use of a branch key: B's data becomes decryptable by holders of key store A's access, and not by B's own key store). Likelihood **Medium**. Risk **High**.

**Changed since a1e23d7 (Medium → High):** the old Low likelihood assumed the identifier was injective, so a collision needed a SHA-384 break or a hypothetical separator flaw. That separator flaw is now a confirmed, open defect, with end-to-end evidence on main (RECHECK BUG-06: 2 passed; key store B called 0 times; B's EDK unwraps only with A's key). `cache_entry_identifier.rs` has had no commits since a1e23d7. What remains is a configuration precondition that the MPL does not check: a shared cache, plus NUL-containing values in partition id, logical name or bkid. These values can come from tenant names, from a user `KeyStore`'s logical name, or from an EC-driven supplier.

The Medium likelihood rates the multi-tenant shared-cache deployment that the spec's Partition ID guidance is written for. BUG-06 keeps bug severity Low because it weighs typical deployments. Reviewers who judge NUL-containing tenant input unrealistic can return this to Medium risk. Fix: reject `0x00` in these fields, or length-prefix them. Length-prefixing needs a spec change and breaks cross-runtime cache-id compatibility. Coverage: hierarchical tests cover cache-id separation (`mpl/tests/test_aws_kms_hierarchical_keyring.rs`, per scope) but have no NUL case.

**TM-MPL-010 (I/E): Shared-cache confusion.** Attack: two keyrings that should be isolated share cache entries, so one reuses branch-key materials it could not fetch itself. Mitigations:
- The default partition id is a fresh random v4 UUID (`hierarchical_keyring.rs:626`), so keyrings are isolated by default.
- Shared-cache scope is opt-in. The spec says users MUST set all three fields the same if, and only if, they want sharing.
- The cache returns only `BranchKey` entries to the keyring (kind check `:1000`).
- Entries older than the TTL are refetched. The comparison is now exact (`:989-995`; BUG-09 fixed).

Severity High, Likelihood **Medium**, Risk **High**. **Changed since a1e23d7 (Medium → High):** BUG-06 (TM-MPL-009) is a concrete, confirmed way to realize this threat across keyrings that have *different* partition ids. A user-supplied `Cmc` can also return any entry for any id; only its kind is checked (TB7). It can also report `grace_period() = None` (trait default, `mpl/src/cmc/mod.rs:88-90`), which skips the grace-vs-TTL check (`hierarchical_keyring.rs:585`). The earlier residual "no cross-check that a cached suite's commitment matches the current policy" is **withdrawn**. The keyring caches only `CachedMaterials::BranchKey` (`:700`, `:943`), and branch keys do not depend on the commitment policy. The CVE-2026-6550 class applies only to a future caching CMM (TM-MPL-008). TM-MPL-009 and TM-MPL-010 share one root cause and one fix.

**TM-MPL-011 (E): AES-GCM IV reuse in the raw-AES keyring.** Mitigation: a fresh 12-byte IV from the CSPRNG for each wrap (`mpl/src/keyring/raw_aes_keyring.rs:146`, `:151-152`), passed to `prim::aes_encrypt` (`Nonce::try_assume_unique_for_key`, `prim/src/lib.rs:188`). Severity Critical, Likelihood Low → Medium. Residual: uniqueness rests on a 96-bit random nonce, so reuse is bounded only by the birthday bound. There is still no two-call IV-distinctness test (scope). This is a prime verification target. (Location only.)

**TM-MPL-012 (E): Salt/IV reuse in branch-key wrap.** Mitigation: a fresh 16-byte salt and 12-byte IV for each `wrap` (`mpl/src/aws_kms/branch_key_wrap.rs:157`, `:164`, `:170`). The salt gives a fresh derived key for each wrap. The Appendix B birthday analysis motivates yearly rotation. Severity Critical, Likelihood Low → Medium. (Location only.)

**TM-MPL-013 (T): Branch-key AAD inconsistency.** Mitigation: `compute_aad` builds `"aws-kms-hierarchy" ‖ bkid ‖ version(16 B) ‖ serialized EC` the same way on wrap and unwrap (`branch_key_wrap.rs:61`). The version is parsed strictly as a 36-character canonical UUID (`:92`). The spec section is aws-kms-hierarchical-keyring.md. Severity High, Likelihood Low → Medium. **Changed since a1e23d7:** `EncryptionContext::from_bytes` now rejects out-of-order and duplicate keys and invalid UTF-8 (`mpl/src/structures/encryption_context.rs:145`, `:202`, `:208`; BUG-03 fixed), so a decoded EC has one canonical form. The rating is unchanged. Residual: serialization determinism and version-format strictness are still unproven, and `from_bytes` accepts empty keys (`test_deserialize_accepts_empty_key_length_currently_unenforced`, `mpl/tests/test_encryption_context.rs:468`, per scope).

**TM-MPL-014 (E): KBKDF fixed-info misuse.** Mitigation: fixed info = `Label("aws-kms-hierarchy") ‖ 0x00 ‖ salt ‖ L_be32(256)` (NIST SP 800-108 counter-mode HMAC-SHA-256), computed by `prim::kbkdf_ctr_hmac` (`prim/src/lib.rs:313`). Output is 32 bytes into a `Zeroizing` buffer (`branch_key_wrap.rs:122-136`). Severity High, Likelihood Low → Medium. Residual: correctness of the byte layout and the L value is a strong verification candidate. (Location only; the output is now wiped on drop, see TM-MPL-015.)

**TM-MPL-015 (I): Secret material not zeroized.** Mitigations (new since a1e23d7, #131 and #158):
- `PlaintextDataKey`, `SigningKey` and `SymmetricSigningKey` derive `Zeroize, ZeroizeOnDrop` (`mpl/src/structures/algorithm_suite.rs:505`, `:571`, `:655`).
- `BranchKeyMaterials` and its builder zeroize on drop (`structures/branch_key_materials.rs:205-219`). So do `BeaconKeyMaterials` and its builder (`structures/beacon_key_materials.rs:221-235`), and the raw-AES wrapping key in both the keyring and its builder (`keyring/raw_aes_keyring.rs:72-78`, `:233-239`).
- The derived branch key is `Zeroizing` (`aws_kms/branch_key_wrap.rs:135`). So is the decrypted branch key during record parsing (`key_store/record.rs:100`, `:173`).
- The `unsafe write_volatile` loop is gone. `mpl/src` and `prim/src` have no `unsafe` code.

Residual exposures that remain:
- The raw-AES decrypt buffer on the AES-error and wrong-length paths (`raw_aes_keyring.rs:471`, `:489`).
- The `Vec` returned by `branch_key_wrap::unwrap` before it is wrapped in `PlaintextDataKey`.
- The KMS SDK response `Blob` that holds the plaintext branch key (`key_store/kms_ops.rs:207`).
- BUG-07(a): `prim::aes_encrypt` copies the plaintext into the output buffer before the key and nonce checks that can return `Err` (`prim/src/lib.rs:185-188`). The MPL callers then drop that buffer without wiping it.
- Copies left behind when a `Vec` reallocates.
- By design, the cache holds plaintext branch keys for the TTL.

Severity **Medium** (only transient or error-path copies remain; every long-lived secret is wiped), Likelihood Low → **Low**. **Changed since a1e23d7 (Medium → Low):** the original finding ("no zeroization anywhere") no longer holds. Verification candidate: prove that no secret buffer outlives its scope without being wiped, starting with the residual sites above.

**TM-MPL-016 (T): VersionKey optimistic-lock bypass.** Mitigation: before rotating, VersionKey authenticates the ACTIVE record with a KMS ReEncrypt-to-self. It then writes in one `TransactWriteItems`: `attribute_not_exists` for the new DECRYPT_ONLY item (`mpl/src/key_store/branch_key_store.rs:743`) and `attribute_exists(#branch_key_id) AND #enc = :encOld` for ACTIVE (`:752`). The function is at `version_key` (`:641`). Severity Medium → Low. (Location only.)

**TM-MPL-017 (T): Reproduced-EC merge tampering.** Mitigation: `merge_reproduced_encryption_context` fails when a shared key's values disagree and appends reproduced-only pairs as required EC keys (`mpl/src/cmm/default_cmm.rs:198`, `:273`). The spec section is cmm-interface.md. Severity High, Likelihood Low → Medium. **Changed since a1e23d7:** the transition checks now reject a keyring that changes the EC or the required EC keys (`materials_checks.rs:82-89` encrypt; the decrypt transition at `:117` checks the same fields). The rating is unchanged: the merge itself is still the only guard that the decryptor's AAD equals the encryptor's, and it is a verification target.

**TM-MPL-018 (D): Storm-tracking correctness.** Current mitigations:
- Fan-out bounds concurrent refreshes (`mpl/src/cmc/storm_tracking.rs:274`, `:310`).
- The lock is never held across `.await`.
- A poisoned lock maps to a `Kind::Internal` error instead of a panic (`state_locked`, `:239`, `:248`).
- `put_cache_entry` writes the inner cache before it clears the in-flight mark (`:710`).
- The hierarchical keyring rejects a cache grace period ≥ TTL (`hierarchical_keyring.rs:585`).

Severity Medium, Likelihood Medium → Medium.

**Changed since a1e23d7 (mitigation regressed, rating unchanged).** The previous version recorded `grace_interval ≤ inflight_ttl ≤ grace_period` and "all ≥ 1" as enforced. That is no longer true. `StormTrackingCmcBuilder::build` (`:606`) checks only `fan_out ≥ 1` (`:613`), `in_flight_ttl > 0` (`:616`), `sleep > 0`, and `grace_interval ≤ in_flight_ttl` (`:622`). It does not enforce the spec's "Grace Interval MUST be ≤ Grace Period" or "Inflight TTL MUST be ≤ Grace Period" (storm-tracking-cryptographic-materials-cache.md), or "at least 1" for the grace period and grace interval. `test_durations_are_stored_exactly` (`mpl/tests/test_storm_tracking_cmc.rs:388`) accepts `grace_period = 0`.

BUG-01(b/c) is open. A very large `grace_interval` or `in_flight_ttl` panics on `now + in_flight_ttl` (`:333`) and on `inflight + grace_interval` (`:680`), because there is no upper bound. A user `Cmc` that reports no grace period bypasses the keyring's grace-vs-TTL check (TM-MPL-010). The rating is unchanged because the impact is availability and the defaults (`:110-121`) are valid. This is a strong verification target (the single-in-flight invariant, plus the spec ordering once it is restored).

**TM-MPL-019 (E): Missing Duvet coverage.** Finding: spec MUSTs are not mechanically traced for the MPL. Severity Medium, Likelihood Medium → Medium. **Changed since a1e23d7 (status refined, rating unchanged):**
- The previous note pointed at a `duvet/mpl-annotations` branch. `main` contains no MPL Duvet config; the only configs are `esdk/.duvet/config.toml` and `esdk/shims/aws-esdk-cpp/.duvet/config.toml`.
- `mpl/` and `prim/` hold one annotation block (`mpl/src/cmc/entry.rs:201-204`), which no config checks. ESDK, by contrast, has about 2100 `//=` lines (scope).
- Since #91 (`6ef7d80`) the spec is not a submodule. It is fetched from `scripts/spec-source.json` at `ref = "master"`, so the spec revision floats and a spec change can arrive silently (scope; MPL-relevant framework docs are byte-identical to `master` `877edcc` as of 2026-11-02).

Recommendation: add `mpl/.duvet/config.toml` and annotations for the commitment policy, MRK match, AAD, cache id, key-store auth EC and storm-tracking constraints, and pin the spec revision.

**TM-MPL-020 (R): No operation ↔ KMS/DDB audit binding.** Mitigations: KMS/DDB CloudTrail. Every KMS call now carries the framework metadata `AwsCryptographicMPL-Rust/<version>` in its user agent (`mpl/src/aws_kms/user_agent.rs:9`, `:15-19`; applied at `key_store/kms_ops.rs:187-188`, `:239-240`, `:286-287`). Severity Low → Low. **Changed since a1e23d7:** the previous text cited an `aws-kms-hierarchy` user agent, which was inaccurate. CloudTrail can now attribute KMS calls to the MPL, but not to a specific MPL operation or message.

**TM-MPL-021 (I): Secret leakage via `Debug`/logging.** Mitigations:
- `Debug` is redacted for `PlaintextDataKey`, `SigningKey` and `SymmetricSigningKey` (`algorithm_suite.rs:566`, `:614`, `:699`), for `BranchKeyMaterials` (`branch_key_materials.rs:58`, `:196`), for beacon keys (`beacon_key_materials.rs:203-209`), and for the raw-AES wrapping key (`raw_aes_keyring.rs:87`).
- The new error model attaches EDK info as `DataKeyInfo`, which holds the provider id and info but never the ciphertext (`structures/encrypted_data_key.rs:148-151`).
- Key-store errors name attributes and their types, never values (`key_store/branch_key_store.rs:1140`).

Severity Medium, Likelihood Low → Low. **Changed since a1e23d7:** the previous residual ("confirm `PlaintextDataKey`/`SigningKey` `Debug` redaction") is closed. Errors still carry resource ids (bkid, KMS ARN, table name) and raw-AES provider info (key name + IV). None of these is secret.

**TM-MPL-022 (D): Cache exhaustion → KMS storm.** Mitigation: with `rt-tokio`, the default hierarchical cache is `DefaultCmc` (`hierarchical_keyring.rs:567-573`): storm-tracking over a 1000-entry LRU with tail pruning (`cmc/local.rs:166`). Storm tracking coalesces refreshes. Severity Low, Likelihood Medium → Low. **Changed since a1e23d7:** the default changed from a plain local LRU to `DefaultCmc`. Without `rt-tokio`, the caller must supply a cache (`:575-580`).

**TM-MPL-023 (D): Panic or resource blow-up on malformed input or extreme configuration.** Mitigations:
- `try_decrypt_edk` checks for ≥ 44 bytes before reading the version (`hierarchical_keyring.rs:879`; the `.expect` at `:892` cannot fire after that check).
- `branch_key_wrap::unwrap` checks for ≥ 60 bytes before slicing (`branch_key_wrap.rs:236`; the expects at `:249`, `:252`, `:256` cannot fire after it).
- `EncryptionContext::from_bytes` returns errors on any malformed input (`structures/encryption_context.rs:145`).

Severity Medium, Likelihood Low → Low. **Changed since a1e23d7:**
- (1) BUG-02 is fixed. A wrong-length unwrapped key is rejected when it is added to the materials (`hierarchical_keyring.rs:767`; `algorithm_suite.rs:547`), and the raw-AES keyring checks the length too (`raw_aes_keyring.rs:489`).
- (2) #186 removed an O(n²) memory blow-up in the attacker-controlled EDK count. The EDK list is now attached once, to the aggregate error (`raw_aes_keyring.rs:517`; hierarchical `:784`; tests `mpl/tests/test_keyring_memory.rs:100`, `:113`).
- (3) Still open: BUG-05(a), where `ecdsa_generate_keypair(..).expect(..)` (`cmm/default_cmm.rs:138`) panics if key generation ever fails; BUG-05(b), where a 44–59-byte EDK costs one key-store call before it is rejected; BUG-01(a/d), where a huge configured TTL panics on `now + ttl` (`hierarchical_keyring.rs:702`, `:945`; only zero is rejected, `:547`); and BUG-07(b), where `aes_decrypt` maps every callee error to "authentication tag did not match" (`prim/src/lib.rs:215`, `:229`), which is misleading for a buffer-length error.

These are configuration-driven or practically unreachable, so the rating is unchanged.

**TM-MPL-024 (E/T): C++ shim dereferences a dangling or forged handle to an MPL object. (New.)** New attack surface: `e9bde48` (#98) retargeted the C++ shim onto the native MPL. Its `#[cxx::bridge]` hands C++ raw handles to MPL keyrings, CMMs, caches and SDK clients. `require_handle` null-checks a pointer and then dereferences it in `unsafe { &*ptr }` (`esdk/shims/aws-esdk-cpp/src/lib.rs:715`, `:720`, `:728`). Optional KMS/DDB client handles and cache handles are dereferenced with `unsafe { ptr.as_ref() }` (`:1564-1565`, `:1655`). Attack: TA7 (a C++ bug or hostile in-process code) passes a dangling or type-confused handle. The dereference is then undefined behavior inside a process that holds wrapping keys and branch keys. That can mean memory disclosure or corruption of MPL state, for example a cache handle aliasing another tenant's cache. Mitigations: null checks, typed `cxx` bindings, and the lifetime rules in spec `shim/shim.md#handles-and-lifetimes` (the annotation at `lib.rs:717-719`). The shim has its own Duvet config. This is the only `unsafe` code that reaches MPL objects; `mpl/src` and `prim/src` have none. Severity High, Likelihood Low (it needs a caller-side lifetime bug) → Medium. Owner: the shim, outside `mpl/`/`prim/`. It is listed here because it is the boundary through which C++ users reach MPL key material.

## 9. Implementation-Specific Considerations

- All randomness (IVs, salts, data keys, the default partition-id UUID) flows through `prim::generate_random_bytes` (`prim/src/lib.rs:128`). Key-store branch-key ids and versions use `Uuid::new_v4()` (`key_store/branch_key_store.rs:556-557`, `:703`); they are not secret.
- `prim::aes_encrypt`/`aes_decrypt` use `LessSafeKey` with `Nonce::try_assume_unique_for_key` (`prim/src/lib.rs:188`, `:224`). GCM nonce uniqueness is the caller's obligation, so the IV generation in the keyrings (TM-MPL-011/012) is load-bearing.
- `mpl/src` and `prim/src` contain no `unsafe` code. The only `unsafe` code that reaches MPL users is in the C++ shim (TM-MPL-024). Test-only `unsafe` is in the custom allocators of `mpl/tests/test_keyring_memory.rs` and `esdk/tests/test_body_allocation.rs` (scope).
- Materials checks (Dafny `Materials.dfy` port, `structures/materials_checks.rs`) run only through `SharedKeyring`/`SharedCmm` `send()`. Built-ins implement their traits only through the crate-private `Builtin<T>` (`mpl/src/shared.rs:110`), so every MPL and ESDK path is checked. A caller that invokes its own `Keyring`/`Cmm` trait impl directly bypasses the checks by its own choice.
- Code paths depend on the Cargo feature set (`kms`, `ddb`, `default-aws-sdk-clients`, `rt-tokio`, `test-utils`, `aws-lc-sys`, `fips`). Without `rt-tokio` there is no storm-tracking or default cache. `fips` switches the crypto backend. The ESDK depends on the MPL with `default-features = false`. Verification claims must name the feature set they cover.
- Branch-key version handling: 16 bytes on the wire at ciphertext offset 28, converted to the canonical hyphenated UUID for the key-store lookup (`hierarchical_keyring.rs:894`) and re-validated when the AAD is built (`branch_key_wrap.rs:92`). The two representations must round-trip.
- Remaining non-test panics: `default_cmm.rs:123`, `:138` (BUG-05a); `user_agent.rs:17` (static metadata); the fixed-size `try_into().expect` calls (cannot fire after the length checks); `cache_entry_identifier.rs:64`; the storm-tracking introspection accessors (`storm_tracking.rs:199`, `:213`, `:227`); and the unchecked `SystemTime + Duration` additions (BUG-01).
- The test servers (`mpl/test-server`, `prim/test-server`) listen on `127.0.0.1` only and are not part of the published crates. Out of scope; flagged only.

## 10. Residual Risks

| ID | Residual risk | Rating | Change |
|----|---------------|--------|--------|
| TM-MPL-009/010 | Cache id not injective when a field contains NUL (BUG-06). A shared cache can cross partition boundaries | High | ↑ from Medium |
| TM-MPL-005 | Record substitution resistance rests on exact auth-EC reconstruction. User key stores are unchecked | High | = |
| TM-MPL-011/012 | GCM IV/salt uniqueness rests on CSPRNG randomness, not counters | Medium | = |
| TM-MPL-004/007 | Ad-hoc ARN/alias/MRK string parsing not verified. MRDiscovery rewrites non-MRK regions (BUG-04, fails closed) | Medium | = |
| TM-MPL-006/008 | Commitment enforcement depends on unproven per-suite allow tables | Medium | = |
| TM-MPL-018 | Storm-tracking config no longer validated per spec. Large durations panic (BUG-01) | Medium | = (mitigation regressed) |
| TM-MPL-002 | Discovery-mode decryption trusts the record's `kms-arn` | Medium | = |
| TM-MPL-019 | No Duvet traceability of MPL spec MUSTs. The spec revision floats on `master` | Medium | = |
| TM-MPL-024 | Shim `unsafe` handle derefs: UB on a dangling/forged C++ handle | Medium | new |
| TM-MPL-015 | Transient/error-path copies of secrets (decrypt buffers, KMS `Blob`, BUG-07a) | Low | ↓ from Medium |
| TM-MPL-023 | Config-driven panics (BUG-01, BUG-05a). Short-EDK key-store call (BUG-05b) | Low | = |

## 11. Recommendations

Configuration hardening:
- Prefer single-key `KmsKeyArn`/`KmsMrKeyArn` over Discovery and MRDiscovery (TM-MPL-002/007).
- Default to REQUIRE_ENCRYPT_REQUIRE_DECRYPT with commit-key suites (TM-MPL-006/008).
- When sharing a cache, derive partition ids and logical names only from validated, NUL-free values; keep the default random partition id unless sharing is intended (TM-MPL-009/010).
- Keep storm-tracking settings within the spec's ordering (Grace Interval ≤ Inflight TTL ≤ Grace Period, each ≥ 1 s), and keep TTL ≫ grace period (TM-MPL-018).
- Use bounded durations (TM-MPL-018/023).

Implementation improvements:
- Reject `0x00` in partition id, logical key store name and branch-key id at keyring build/resolve time, or raise a spec change to length-prefix the cache-id fields; add a NUL regression test (TM-MPL-009/010, BUG-06).
- Use `checked_add` for every `SystemTime + Duration`, or bound durations in `build()` (BUG-01).
- Restore the spec's storm-tracking constraints in `StormTrackingCmcBuilder::build` (TM-MPL-018).
- Rewrite the region only for `mrk-` ARNs in MRDiscovery (BUG-04, TM-MPL-007).
- Return an error instead of `.expect` on ECDSA keygen (BUG-05a).
- Truncate the output buffer on `aes_encrypt` `Err`, align the `aes_decrypt` guard with its callee, and fix its error text (BUG-07).
- Wipe the transient decrypt buffers listed in TM-MPL-015.
- Add `mpl/.duvet/config.toml`, annotate the MPL MUSTs, and pin the spec revision (TM-MPL-019).
- Any future caching CMM must bind the commitment policy (or the suite) into its cache id (TM-MPL-008/010, CVE-2026-6550).
- Shim: keep handles typed, and consider generation-checked handles instead of raw pointers (TM-MPL-024).

Operational practices:
- Rotate branch keys roughly yearly (TM-MPL-012).
- Scope KMS grants tightly (TM-MPL-002).
- Enable CloudTrail on the KMS keys and the DDB table, and use the MPL user agent to attribute calls (TM-MPL-020).
- Never configure two physical key stores with the same logical name (spec, `#logical-key-store-name`).

## 12. References

- spec/framework (local copy, MPL-relevant sections identical to `master` `877edcc` as of 2026-11-02): algorithm-suites.md, commitment-policy.md, branch-key-store.md (#mrdiscovery, KeyId rule), cmm-interface.md, default-cmm.md, structures.md, keyring-interface.md, raw-aes-keyring.md, aws-kms/aws-kms-hierarchical-keyring.md (cache-id formulas, #partition-id, #logical-key-store-name, Appendix B), aws-kms/aws-kms-mrk-match-for-decrypt.md, cryptographic-materials-cache.md, local-cryptographic-materials-cache.md, storm-tracking-cryptographic-materials-cache.md (constraints). Shim: spec/shim/shim.md#handles-and-lifetimes.
- Code: `mpl/src/{keyring/{raw_aes_keyring,fluent_builders}.rs, aws_kms/{hierarchical_keyring,branch_key_wrap,mrk_match,cache_entry_identifier,user_agent}.rs, key_store/{branch_key_store,kms_ops,kms_config,record,encryption_context,client_impl}.rs, cmm/{default_cmm,fluent_builders}.rs, cmc/{local,storm_tracking,default,entry,mod}.rs, structures/{algorithm_suite,materials_checks,commitment_policy,encryption_context,branch_key_materials,beacon_key_materials,encrypted_data_key}.rs, shared.rs}`, `prim/src/lib.rs`, `esdk/src/materials.rs`, `esdk/shims/aws-esdk-cpp/src/lib.rs`.
- Pipeline inputs: `docs/spec-security-analysis.md`; `docs/bug-reports/RECHECK-main-620771c.md`; `docs/bug-reports/README.md`; `docs/bug-reports/BUG-01..BUG-09`; `.agents/tasks/pipeline-rerun-620771c/{scope.md,stage2-notes.md}`.
- CVE-2026-6550 / GHSA-v638-38fc-rhfv (verified): [GitHub Advisory Database](https://github.com/advisories/GHSA-v638-38fc-rhfv), [aws-encryption-sdk-python advisory](https://github.com/aws/aws-encryption-sdk-python/security/advisories/GHSA-v638-38fc-rhfv), [NVD](https://nvd.nist.gov/vuln/detail/CVE-2026-6550), [AWS Security Bulletin 2026-017-aws](https://aws.amazon.com/security/security-bulletins/2026-017-aws/). Summary: in the ESDK for Python, a shared caching CMM could serve non-committing materials across differing commitment policies. Content was rephrased for compliance with licensing restrictions.
- Invisible Salamanders / encryptment: Dodis, Grubbs, Ristenpart, Woodage, IACR ePrint 2019/016 (https://eprint.iacr.org/2019/016). Content was rephrased for compliance with licensing restrictions.
- AWS KMS key-derivation construction: Gueron, RWC 2018.
- NIST SP 800-108 (KBKDF), SP 800-38D (GCM), RFC 5869 (HKDF).

## Appendix: Threat Risk Matrix

Rating rule (unchanged from the previous version, now stated explicitly):

| Severity \ Likelihood | Low | Medium | High |
|---|---|---|---|
| Critical | Medium | High | High |
| High | Medium | High | High |
| Medium | Low | Medium | High |
| Low | Low | Low | Medium |

| ID | STRIDE | Severity | Likelihood | Risk (a1e23d7) | Risk (620771c) | Note |
|----|--------|----------|-----------|----------------|----------------|------|
| TM-MPL-001 | S | Medium | Low | Low | Low | location only |
| TM-MPL-002 | S | Critical | Low | Medium | Medium | location only |
| TM-MPL-003 | S | Medium | Low | Low | Low | BUG-06 path noted |
| TM-MPL-004 | T | High | Low | Medium | Medium | location only |
| TM-MPL-005 | T | Critical | Medium | High | High | BUG-08 informational |
| TM-MPL-006 | E | Critical | Low | Medium | Medium | mitigations strengthened |
| TM-MPL-007 | E | High | Low | Medium | Medium | BUG-04 open, fails closed |
| TM-MPL-008 | E | High | Low | Medium | Medium | CVE verified, not applicable |
| TM-MPL-009 | E | High | Low → **Medium** | Medium | **High** | BUG-06 confirmed end to end |
| TM-MPL-010 | I/E | High | Low → **Medium** | Medium | **High** | BUG-06; commitment residual withdrawn |
| TM-MPL-011 | E | Critical | Low | Medium | Medium | location only |
| TM-MPL-012 | E | Critical | Low | Medium | Medium | location only |
| TM-MPL-013 | T | High | Low | Medium | Medium | BUG-03 fixed |
| TM-MPL-014 | E | High | Low | Medium | Medium | location only |
| TM-MPL-015 | I | High → **Medium** | Low | Medium | **Low** | zeroize-on-drop added |
| TM-MPL-016 | T | Medium | Low | Low | Low | location only |
| TM-MPL-017 | T | High | Low | Medium | Medium | transition checks added |
| TM-MPL-018 | D | Medium | Medium | Medium | Medium | config validation regressed; BUG-01 |
| TM-MPL-019 | E | Medium | Medium | Medium | Medium | Duvet re-measured; spec floats |
| TM-MPL-020 | R | Low | Low | Low | Low | user agent corrected |
| TM-MPL-021 | I | Medium | Low | Low | Low | residual closed |
| TM-MPL-022 | D | Low | Medium | Low | Low | default cache now `DefaultCmc` |
| TM-MPL-023 | D | Medium | Low | Low | Low | BUG-02 fixed, #186; BUG-01/05/07b open |
| TM-MPL-024 | E/T | High | Low | n/a | **Medium** | new (C++ shim handles) |
