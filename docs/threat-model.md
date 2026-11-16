# Threat Model: AWS Cryptographic Material Providers Library (MPL)

> Pipeline artifact, Stage 2 (Threat Modeling), **second pass**. Produced by the `threat-model-generator` agent against the `esdk-native-mpl` working tree at HEAD `851977d` (branch `MPL-Verus`).
>
> - **Code analyzed:** `mpl/` and `prim/` are unchanged since `620771c`. `.agents/tasks/pipeline-pass2/scope.md` records that `git diff 620771c 5f2dc72` touches only `esdk/shims/aws-esdk-cpp/` (#188 `41f1d51`, #189 `5f2dc72`). This step had no shell, so `git` was not re-run. Earlier versions of this document analyzed `a1e23d7` and then `620771c`.
> - **Citation method:** every current `file:line` below was re-checked in this step. Single lines come from workspace grep match lines (a grep context line is numbered one too high, so only match lines were used) or from `read_file` offsets counted by hand (`offset N` shows line `N+1` first). Ranges end on lines that were counted. Details and the corrections found are in `.agents/tasks/pipeline-pass2/stage2-notes.md`.
> - **Status:** Draft for verification prioritization.
> - **Scope:** `mpl/` (key management) built on `prim/` (safe aws-lc-rs wrappers). Message-format concerns (ESDK) are OUT OF SCOPE. The ESDK and the C++ shim appear only as callers.
> - **Methodology:** STRIDE with likelihood × impact risk rating (matrix in the appendix). Each threat has a stable ID `TM-MPL-NNN` referenced by the verification-recommender. IDs are never renumbered or deleted; a threat that no longer applies is marked Retired.
> - **Inputs:** `docs/spec-security-analysis.md` (Stage 1, second pass), `.agents/tasks/pipeline-pass2/{scope.md,stage1-notes.md}`, `.agents/tasks/pipeline-rerun-620771c/`, `docs/bug-reports/RECHECK-main-620771c.md`, `docs/bug-reports/README.md`.
>
> **Note on Duvet:** `main` has no Duvet config for the MPL. The only configs are `esdk/.duvet/config.toml` and `esdk/shims/aws-esdk-cpp/.duvet/config.toml`. The ESDK config lists `spec/framework/transitive-requirements.md` (`esdk/.duvet/config.toml:37`, ESDK-level HKDF/ECDSA text) and no MPL framework document. `mpl/` and `prim/` contain exactly one annotation block (`mpl/src/cmc/entry.rs:201-204`, `cryptographic-materials-cache.md#usage-metadata`, `type=implication`), which CI does not check. Mitigations below cite code locations and spec sections directly. The gap is tracked as TM-MPL-019.
>
> **Note on cited advisories (VERIFIED, scoped):** CVE-2026-6550 / GHSA-v638-38fc-rhfv is verified. This step re-fetched the [GitHub Advisory Database entry](https://github.com/advisories/GHSA-v638-38fc-rhfv). It describes a key-commitment policy bypass in the **AWS Encryption SDK for Python**: two Python clients with different commitment policies share one `CachingCryptoMaterialsManager`, the weaker-policy client encrypts first, and the cache then serves non-committing materials to the stricter client. It was fixed in ESDK for Python 3.3.1 and 4.0.5. Further sources: [AWS Security Bulletin 2026-017-aws](https://aws.amazon.com/security/security-bulletins/2026-017-aws/), [repository advisory](https://github.com/aws/aws-encryption-sdk-python/security/advisories/GHSA-v638-38fc-rhfv), [NVD](https://nvd.nist.gov/vuln/detail/CVE-2026-6550). **It is a Python-ESDK caching-CMM issue and does not apply to this code:** `mpl/src/cmm/` has no caching CMM, and the hierarchical keyring caches only branch keys, which do not depend on the commitment policy (see TM-MPL-008, TM-MPL-010). Content was rephrased for compliance with licensing restrictions.

## Second pass (HEAD 851977d): changes

Method: each of TM-MPL-001..024 was re-derived from the code and spec (likelihood, severity, mitigation, residual), not copied. A statement is marked **re-confirmed** when the re-assessment agreed with the existing text. Stage 1's second pass was the input for new attack surface. Items from Stage 1 that were found by static reasoning only are labeled "static reasoning" and were not executed.

### Summary

| Class | Items |
|---|---|
| **Rating changes** | **None** for TM-MPL-001..024. Two new threats: TM-MPL-025 (Medium, provisional) and TM-MPL-026 (Low) |
| **Re-confirmed** (text and rating kept, citations re-checked) | TM-MPL-001, 004, 007, 008, 012, 013, 016, 017, 019, 020, 022. The rating-neutral extensions below also re-confirmed the rating of the threats they touch |
| **Extended** (rating re-derived and kept; new residual or new evidence) | TM-MPL-002, 003, 005, 006, 009, 010, 011, 014, 015, 018, 021, 023, 024 |
| **Corrected** | Citations and wording of the previous version (table below). Two of Stage 1's own second-pass citations were also off by one; an independent review fixed those and the further citation slips listed in the last row of the table below |
| **New** | TM-MPL-025 (decrypt-input amplification), TM-MPL-026 (loopback test servers use ambient AWS credentials). New sub-surfaces under existing IDs: C++ `Keyring::adopt` (TM-024), authentic-record rollback (TM-005), Discovery on the encrypt path (TM-002) |
| **Retired** | **None.** Every threat still applies to the current code |

### Rating changes and decisions (old → new, why, evidence)

| ID | Old risk | New risk | Why (or why not) | Evidence |
|---|---|---|---|---|
| TM-MPL-025 | n/a | **Medium** (Medium × Medium), provisional | New attack surface found by re-reading the decrypt path: the sender of a ciphertext controls the EDK count and the branch-key version bytes. Each EDK that names the configured branch key id costs a cache lookup plus, on a miss, a key-store read. A failed read is never cached, and it leaves an in-flight mark. By default the EDK count is uncapped. Static reasoning; a reproducer is recommended before this is treated as confirmed | `hierarchical_keyring.rs:752-770`, `:889-894`, `:901-959`; `storm_tracking.rs:115`, `:274-280`, `:310-315`, `:320-337`; `esdk/src/config.rs:35`, `:42`; `mpl/tests/test_keyring_memory.rs:4` |
| TM-MPL-026 | n/a | **Low** (Medium × Low) | New: four loopback test servers have no authentication. The MPL one builds AWS clients from request-chosen regions, tables and KMS ARNs, using ambient credentials. Test-only, not published | `mpl/test-server/src/main.rs:26-27`; `mpl/test-server/src/handlers.rs:137-147`, `:425-430`; `mpl/test-server/Cargo.toml:6` |
| TM-MPL-018 | Medium | Medium (kept) | Re-derived. Two liveness gaps (stale in-flight mark, no-deadline waiter) and a BUG-01 effect (panic under the state lock poisons it) were added. If a reproducer shows the stale-mark wedge, severity could be High, but at Likelihood Low the risk stays Medium (High × Low). No change without a reproducer | `storm_tracking.rs:249-255`, `:322-323`, `:313`, `:333`, `:680`, `:739-740` |
| TM-MPL-024 | Medium | Medium (kept) | Re-derived. New sub-surface (`Keyring::adopt` takes a type-erased `void*` and wraps it with `from_raw`, with no check). Same boundary, same actor, same owner. Neither #188 nor #189 changed a handle or lifetime path | `esdk/shims/aws-esdk-cpp/src/lib.rs:728`, `:1570-1571`, `:1661`, `:2059-2066`; `src/EncryptionSDK.cpp:541-547`; `include/aws/esdk/EncryptionSDK.h:656-664` |
| TM-MPL-009 / 010 | High | High (kept) | Re-derived from `cache_entry_identifier.rs:42-60` (unchanged) and BUG-06. Likelihood stays Medium. The bug report now rates BUG-06 High, consistent with this row; see the note at the end of this document | RECHECK BUG-06; `cache_entry_identifier.rs:35-60` |
| TM-MPL-015 | Low | Low (kept) | New residuals found (cache residency beyond the TTL; `SignatureKeyPair` private key in a plain `Vec` on one error path). Both need TA4 (already inside the process), so the likelihood does not change | `cmc/local.rs:69`, `:131`, `:166`; `prim/src/ecdsa.rs:324-326`, `:387`, `:391-392` |

### Corrected (previous version → now)

| Item | Previous text | Corrected | Evidence |
|---|---|---|---|
| Shim `unsafe` citations (TM-024, section 5 TB8, section 9) | `lib.rs:1564-1565`, `:1655` | `lib.rs:1570-1571`, `:1661`. #188 inserted 6 lines in `ddb_client` before them. `:715`, `:720`, `:728` did not move | `esdk/shims/aws-esdk-cpp/src/lib.rs:728`, `:1570`, `:1571`, `:1661` |
| `Debug` redaction citations (TM-021) | `algorithm_suite.rs:566`, `:614`, `:699`; `branch_key_materials.rs:58`, `:196`; `beacon_key_materials.rs:203-209` | The `impl Debug` lines: `algorithm_suite.rs:564`, `:612`, `:696`; `branch_key_materials.rs:55`, `:191`; `beacon_key_materials.rs:57`, `:191`. The old `beacon` range did not point at a `Debug` impl | grep match lines in those files |
| Storm-tracking defaults (TM-018) | `storm_tracking.rs:110-121` | `:109-121` (the first constant is at `:109`; the default in-flight TTL is `:119` with its spec-conflict comment at `:117-118`) | `storm_tracking.rs:106-126` read |
| `put_cache_entry` (TM-018) | `:710` only | `:710` is the function. The in-flight mark is cleared at `:725`, after the inner put at `:721` | `storm_tracking.rs:710-727` |
| User agent (TM-020) | `user_agent.rs:15-19` | Unchanged. `:15-19` is correct: the function ends at `:19`, the last line of the file. An earlier draft of this pass wrote `:15-20`, which does not exist; found and reverted in review. `.expect` is at `:17` | `user_agent.rs:9`, `:15`, `:17`, `:19` |
| Test-server bind (section 9) | `main.rs:27`, `:24` | The loopback address is built at `mpl/test-server/src/main.rs:26` and bound at `:27`; `prim/test-server/src/main.rs:23` and `:24`; the other two servers `:26` and `:27` | grep of `127.0.0.1` / `bind(` in the four `main.rs` |
| Duvet note | "neither config covers an MPL framework spec" | Still true, but the ESDK config does list one `spec/framework/` file (`transitive-requirements.md`, ESDK-level text) | `esdk/.duvet/config.toml:37` |
| Hierarchical default cache | `:567-573` | `:567-574` (the default arm ends at `.into_shared(),`), plus the no-`rt-tokio` error at `:575-581`; grace check `:584-593`; partition id `:595-598`; logical name `:600-605` | `hierarchical_keyring.rs:567-605` read |
| Citation slips found in independent review | `storm_tracking.rs:321` (F5), `:321-323`, `:321-337`, `:710-728`; `branch_key_wrap.rs:255`; `user_agent.rs:15-20`; `hierarchical_keyring.rs:901-960`; `mrk_match.rs:24-28`; `prim/src/ecdsa.rs:282-296`; `encrypted_data_key.rs:148-151` | `:320` (`unwrap_or(Duration::ZERO)`), `:322-323`, `:320-337`, `:710-727`; `:254` (`let _version`); `:15-19` (the file ends at `:19`); `:901-959`; `:24-27`; `:282-293`; `:147-152` | Each checked against the current file |

## Changes since previous version (a1e23d7 -> 620771c) (first-pass history, kept)

20 commits touch `mpl/` and `prim/` (141 files, +32298 / −8753, mostly generated error code, test servers and tests). Fixed on main: BUG-02, BUG-03, BUG-09 (all `e9bde48`, #98). Still open: BUG-01, BUG-04, BUG-05(a), BUG-05(b), BUG-06, BUG-07(a/b), BUG-08.

Rating changes made in that pass:

| ID | Threat | Old risk | New risk | What changed | Evidence |
|---|---|---|---|---|---|
| TM-MPL-009 | Cache-identifier collision | Medium (High × Low) | **High** (High × Medium) | Likelihood Low → Medium. The old rating assumed the identifier was injective. BUG-06 is a confirmed open defect on main: keyring B was served key store A's branch key end to end | RECHECK BUG-06 (2 passed; key store B never called); `cache_entry_identifier.rs:42-60` (unchanged since a1e23d7); no NUL check on inputs (`hierarchical_keyring.rs:596`, `:600-605`) |
| TM-MPL-010 | Shared-cache confusion | Medium (High × Low) | **High** (High × Medium) | Likelihood Low → Medium (BUG-06 realizes this threat). The "cached suite vs commitment policy" residual is withdrawn: only branch keys are cached, and they do not depend on the policy. Exact TTL check (BUG-09 fixed) | As above; `CachedMaterials::BranchKey` at `hierarchical_keyring.rs:700`, `:943`; `:989-995` |
| TM-MPL-015 | Secret material not zeroized | Medium (High × Low) | **Low** (Medium × Low) | Severity High → Medium. Zeroize-on-drop now covers every long-lived secret type. Only transient and error-path copies remain | `algorithm_suite.rs:505`, `:571`, `:655`; `branch_key_materials.rs:205-219`; `beacon_key_materials.rs:221-235`; `raw_aes_keyring.rs:72-78`, `:233-239`; `branch_key_wrap.rs:135`; `record.rs:100`, `:173` |
| TM-MPL-024 | **New:** C++ shim dereferences raw handles to MPL objects | n/a | **Medium** (High × Low) | New attack surface: the shim was retargeted onto the native MPL in `e9bde48` (#98) | `esdk/shims/aws-esdk-cpp/src/lib.rs:720`, `:728` (the other two citations moved; see "Corrected" above) |

Rating unchanged in that pass, but mitigation or status changed: TM-MPL-003 (supplier is a public trait, `hierarchical_keyring.rs:187`), 005 (BUG-08 confirmed, informational), 006 (stronger: transition checks, PDK length, ESDK re-check; FORBID default suite `03 78`), 007 (BUG-04 open, fails closed), 008 (CVE verified, not applicable), 013 (BUG-03 fixed), 017 (transition checks), **018 (mitigation regressed: `build()` no longer enforces the spec ordering)**, 019 (Duvet re-measured), 020 (user agent corrected), 021 (`Debug` redaction residual closed), 022 (default cache is `DefaultCmc`), 023 (BUG-02 fixed, #186). Location-only updates: TM-MPL-001, 002, 004, 011, 012, 014, 016.

Considered and **not** added in that pass (status as of this pass):
- Pluggable `KeyStore` / `Cmc` / supplier traits: not new. Folded into TM-MPL-005/009/010.
- Materials checks run only on the fluent `send()` path: this is a mitigation.
- Optional cargo features (#136): configuration, no attacker (section 9).
- Test servers: flagged only then. **Now TM-MPL-026** (this pass found they build AWS clients from request data with ambient credentials).
- Spec floating on `master`: folded into TM-MPL-019.
- EDK-count memory amplification: fixed by #186. **The call-count and wall-clock amplification is now TM-MPL-025.**
- Caching CMM (CVE-2026-6550 class): no caching CMM exists; future-work note under TM-MPL-008/010.

### Bug → threat mapping (current status, with the second-pass effect on other threats)

| Bug | Status on main | Threat(s) | Effect on rating | Effect on other threats (second pass) |
|---|---|---|---|---|
| BUG-01 `SystemTime + Duration` overflow panic | Open | TM-MPL-018, 023 | None (config-driven, availability) | **(b) and (c) panic while the storm-tracking state mutex is held** (`storm_tracking.rs:333` and `:680` run inside `classify_and_mark` / `wait_for_leader` under the guard, `:739-740`, `:388-397`). Unwinding poisons the mutex, and every later call on that cache returns `Internal` ("cache lock poisoned", `:248`). One panic therefore becomes a persistent outage of that cache instance. Still config-driven. (a) and (d) (`hierarchical_keyring.rs:702`, `:945`) panic outside any lock |
| BUG-02 PDK length not enforced | **Fixed** | TM-MPL-006, 023 | Mitigation added | none |
| BUG-03 EC deserialize accepts unsorted | **Fixed** | TM-MPL-013 | Mitigation added | none |
| BUG-04 MRDiscovery rewrites non-MRK region | Open | TM-MPL-007 | None (fails closed) | **Does not widen TM-MPL-002.** An attacker who can write the record already controls the ARN's region and account |
| BUG-05(a) `.expect` on ECDSA keygen | Open | TM-MPL-023 | None | none |
| BUG-05(b) 44–59-byte EDK reaches key store | Open (likely not a bug) | TM-MPL-023, **025** | None | A 44-byte ciphertext is enough to trigger the key-store read, so the sender's cost per EDK is minimal. It is not the cause of TM-MPL-025 (a valid-length EDK does the same) |
| BUG-06 cache id not injective with NUL | Open, end-to-end confirmed | TM-MPL-009, 010, 003 | **009 and 010 are High** | Also reachable on decrypt through a supplier that maps message EC to an id containing NUL (TM-MPL-003). The in-flight marks of colliding keyrings are shared, because they are keyed by the same id. The branch-key version cannot carry NUL: it is rendered as hex and hyphens (`hierarchical_keyring.rs:894`) |
| BUG-07(a) `aes_encrypt` leaves plaintext on `Err` | Open | TM-MPL-015 | Counted in the Low residual | none |
| BUG-07(b) `aes_decrypt` guard weaker than callee | Open | TM-MPL-023 | None | none |
| BUG-08 dead collision branch | Open (informational) | TM-MPL-005 | None | none |
| BUG-09 TTL admits ttl + 1 s | **Fixed** | TM-MPL-010 | Mitigation added | none |

## 1. Executive Summary

The MPL produces and manages data keys, branch keys and key wrapping for the AWS Encryption SDK and related clients. Its security rests on six things:
- (a) AES-GCM wrapping in the raw-AES and hierarchical keyrings.
- (b) KBKDF branch-key derivation.
- (c) AWS KMS as the root of trust for branch and beacon keys.
- (d) DynamoDB as tamper-evident (KMS-authenticated) branch-key storage.
- (e) An in-process cache that reduces KMS calls.
- (f) Commitment-policy and algorithm-suite selection enforced by the CMM. Materials-transition checks run on every fluent `send()` and enforce this further.

Since a1e23d7 the code has gained zeroize-on-drop for all long-lived secret types, constant-time comparison of secrets, plaintext-data-key length enforcement, strict encryption-context decoding, exact cache-TTL comparison, Dafny-derived materials checks, and an error model that never carries EDK ciphertext. `mpl/` and `prim/` contain no `unsafe` code.

Highest-priority residual risks for formal verification:
1. Cache-identifier injectivity and cross-keyring isolation (TM-MPL-009, TM-MPL-010). High, because BUG-06 is confirmed on main.
2. Branch-key record substitution, the authenticated-EC binding, and the unchecked freshness of the ACTIVE record (TM-MPL-005).
3. AES-GCM IV uniqueness in both keyrings (TM-MPL-011, TM-MPL-012).
4. Branch-key AAD and KBKDF fixed-info construction (TM-MPL-013, TM-MPL-014). The spec does not give the fixed-info layout, so interoperability rests on the code.
5. MRK/ARN resolution, where BUG-04 is open (TM-MPL-004, TM-MPL-007).
6. Commitment-policy enforcement (TM-MPL-006).
7. Storm-tracking configuration, state machine and liveness (TM-MPL-018), and the decrypt-input amplification it enables (TM-MPL-025, new, provisional).
8. The C++ shim handle boundary, now including `Keyring::adopt` (TM-MPL-024).

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

   C++ callers --> aws-esdk-cpp shim (cxx bridge) --> SharedKeyring / SharedCmc / clients
        raw `*const T` handles (borrow, `lib.rs:728`, `:1570-1571`, `:1661`)
        and type-erased `void*` adoption (`Keyring::adopt`, `lib.rs:2059`)
```

Trust: the process, the local AES wrapping key and the in-process cache are trusted. AWS KMS is the trusted root of trust for branch and beacon keys. DynamoDB is untrusted for integrity; the KMS EC binding makes its records tamper-evident, but not fresh (TM-MPL-005). `aws-lc-rs` is reached only through the safe `prim` wrappers. User-supplied `KeyStore`, `Cmc` and `BranchKeyIdSupplier` implementations are trusted code whose results are not validated (TB7). C++ callers reach MPL objects through raw handles in the shim (TB8). The sender of a ciphertext is untrusted and controls the decrypt-side inputs (TB1, section 5a).

## 3. Assets

| ID | Asset | Type | Notes |
|----|-------|------|-------|
| A1 | Plaintext data keys (`PlaintextDataKey`) | Confidentiality | Zeroized on drop (`structures/algorithm_suite.rs:505`). Length bound to the suite (`:547`) |
| A2 | Branch keys (`BranchKeyMaterials.branch_key`, `[u8;32]`) | Confidentiality | Root of the derived-key hierarchy. Cached in-process for the TTL, and longer if the entry is not read (TM-MPL-015). Zeroized on drop (`structures/branch_key_materials.rs:205-219`) |
| A3 | Derived branch keys (`derivedBranchKey`, 32 B) | Confidentiality | Transient AES-256-GCM key per wrap/unwrap, `Zeroizing` (`aws_kms/branch_key_wrap.rs:125`, `:135`) |
| A4 | Raw-AES wrapping key | Confidentiality | Long-lived local secret. Zeroized on drop (`keyring/raw_aes_keyring.rs:72-78`) |
| A5 | ECDSA signing key (`SigningKey`) | Confidentiality/Integrity | Generated per encryption for signing suites. Zeroized on drop (`algorithm_suite.rs:571`) |
| A6 | Beacon keys | Confidentiality | Searchable-encryption root key. Zeroized on drop (`structures/beacon_key_materials.rs:221-235`) |
| A7 | Branch-key-store DDB records (`enc`, `kms-arn`, EC attrs) | Integrity | Tamper-evidence via the KMS EC binding. No freshness guarantee |
| A8 | Encryption context / AAD | Integrity | Binds ciphertext to context. Must survive the round trip |
| A9 | Algorithm suite id + commitment policy | Integrity | Determines whether key commitment is required |
| A10 | Cache entries (branch-key materials + creation/expiry) | Conf./Integrity/Avail. | In-process. Keyed by a SHA-384 identifier |
| A11 | KMS grant tokens / key ARNs (config) | Integrity | Determine which KMS key authorizes operations |
| A12 | CSPRNG output (IVs, salts, data keys, partition id) | Integrity | From `prim::generate_random_bytes` (`prim/src/lib.rs:128`) |
| A13 | Ambient AWS credentials of a developer or CI host | Confidentiality/Integrity | Used by the loopback test servers (TM-MPL-026) |
| A14 | Key-store read capacity and request latency on the decrypt path | Availability | Spent per EDK on decrypt (TM-MPL-025) |

## 4. Actors

Legitimate: the application caller; KMS (root of trust); DynamoDB (storage); operators configuring the key store and keyrings.

Threat actors:
- TA1, DynamoDB tamperer: read/write access to the branch-key table but NOT to KMS keys (unless it also controls a KMS key whose policy admits the application role; see TM-MPL-002).
- TA2, malicious or confused caller: controls the encryption context, reproduced EC, algorithm-suite id and branch-key supplier inputs on encrypt.
- TA3, co-tenant sharing a cache: can influence its own partition id, logical key store name or branch-key id (for example, values derived from a tenant name).
- TA4, in-process memory adversary: reads freed heap, core dumps or swap (post-exploitation, cold-boot).
- TA5, network attacker between the MPL and KMS/DDB. TLS is assumed; the residual is downgrade or DoS.
- TA6, supply-chain adversary targeting `aws-lc-rs`, `uuid`, `lru`, `zeroize`, or the SDK dependencies.
- TA7, C++ caller of the shim that passes dangling, forged or double-adopted handles (bug or hostile code in the same process). See TM-MPL-024.
- TA8, ciphertext submitter (**new in the second pass**): anyone who can hand the service a message to decrypt, or who can modify a stored message. Unauthenticated. On decrypt it controls the message's encryption context, the EDK count (up to 65,535 per message; no ESDK cap by default), each EDK's provider id, provider info and ciphertext (including the 16 branch-key version bytes at offset 28), and the algorithm suite id. See section 5a and TM-MPL-025. TA2's decrypt-side powers belong to TA8.
- TA9, local process on a developer or CI host (**new**): can connect to `127.0.0.1`. See TM-MPL-026.

## 5. Trust Boundaries

| ID | Boundary | Crossing | Controls |
|----|----------|----------|----------|
| TB1 | Caller / ciphertext sender ↔ MPL API | Materials requests, EC, EDKs, suite id | CMM validation, reserved-key checks, commitment policy, materials checks on `send()`. On decrypt, nothing bounds the EDK count in the MPL (TM-MPL-025) |
| TB2 | MPL ↔ AWS KMS | GenerateDataKeyWithoutPlaintext / ReEncrypt / Decrypt | KMS auth, EC as AAD, key-ARN restriction, grant tokens |
| TB3 | MPL ↔ DynamoDB | GetItem / TransactWriteItems | KMS EC binding makes records tamper-evident; conditional writes. `GetItem` is not a consistent read (`key_store/branch_key_store.rs:148`, `:155-163`) |
| TB4 | Keyring ↔ in-process cache | put/get cache entry | SHA-384 cache identifier (not injective with NUL, BUG-06), exact TTL, materials-kind check |
| TB5 | `mpl`/`prim` ↔ `aws-lc-rs` FFI | AES-GCM/KDF/ECDSA/RNG calls | Safe `prim` wrappers, length checks, `Nonce::try_assume_unique_for_key` |
| TB6 | Process memory ↔ OS | Freed heap, swap, core dump | Zeroize-on-drop for secret types, `Debug` redaction. Transient copies remain (TM-MPL-015) |
| TB7 | MPL ↔ user-supplied components | `KeyStore`, `Cmc`, `BranchKeyIdSupplier`, user `Keyring`/`Cmm` | Keyring/CMM output checked by `send()`. Key store, cache and supplier output not checked (`key_store/client_impl.rs:305-308`, `:373-376`; `aws_kms/hierarchical_keyring.rs:260-263`). Only the material kind of a cache entry is checked (`:1000`) |
| TB8 | C++ ↔ shim ↔ MPL | Raw handle pointers to keyrings, key stores, caches and SDK clients (borrowed), and a type-erased keyring pointer (adopted) | Null checks only on borrow (`esdk/shims/aws-esdk-cpp/src/lib.rs:720`); none on adopt (`src/EncryptionSDK.cpp:541-547`) |
| TB9 | Loopback client ↔ test server ↔ MPL (**new**) | CBOR requests on `127.0.0.1` that build keyrings and AWS clients | Loopback bind only; no authentication. Not published (`publish = false`) |

### 5a. Attacker-controlled inputs per trust boundary (second pass)

| Boundary | Input the attacker controls | Where it is consumed | Bound or validation today | Threat |
|---|---|---|---|---|
| TB1 (decrypt) | Message EC (keys, values) | `EncryptionContext::from_bytes` (`structures/encryption_context.rs:145`); AAD; supplier input (`hierarchical_keyring.rs:747`, `:831`) | Strict UTF-8, order and duplicate checks. Empty keys accepted (`mpl/tests/test_encryption_context.rs:468`) | 013, 017, 003 |
| TB1 (decrypt) | Algorithm suite id | `DefaultCmm` `allows_for_decrypt` (`default_cmm.rs:184`); ESDK check before the CMM (`esdk/src/decrypt.rs:413`) | Policy tables | 006, 008 |
| TB1 (decrypt) | EDK count, provider id, provider info | Filter loop (`hierarchical_keyring.rs:752-763`); raw-AES `decryptable_edk_iv` (`raw_aes_keyring.rs:191`) | Provider id and info must match. **No count bound** unless the ESDK is configured (`esdk/src/config.rs:35`, `:42`) | 025, 023 |
| TB1 (decrypt) | EDK ciphertext length and content, including the 16 version bytes | `try_decrypt_edk` (`hierarchical_keyring.rs:867-894`), `branch_key_wrap::unwrap` (`branch_key_wrap.rs:230-240`) | Length ≥ 44 then ≥ 60; version rendered as canonical UUID text (no NUL possible) | 023, 025 |
| TB1 (encrypt) | EC, partition id, supplier output, requested suite | Cache id (`hierarchical_keyring.rs:665`); reserved-key check (`default_cmm.rs:113`) | No NUL check; no length bound | 009, 010, 006 |
| TB1 (decrypt) | Reproduced EC | `merge_reproduced_encryption_context` (`default_cmm.rs:198`, `:273`) | Shared keys must agree | 017 |
| TB2 | Plaintext branch key length, error strings | `record.rs:164` (32-byte check); `Error::from_sdk` classification | KMS is trusted | 005, 023 |
| TB3 | Any attribute of a record, `kms-arn`, `enc` | `record_from_ddb_item` (`branch_key_store.rs:1141`); auth EC; `resolve_key_store_arn` (`kms_ops.rs:88`) | Strict attribute types; every attribute authenticated by KMS; ARN trusted only in Discovery | 002, 005, 007 |
| TB4 / TB7 | Cache entry returned for an id; key store result; supplier id | `hierarchical_keyring.rs:928`, `:1000`; `client_impl.rs:307`, `:375` | Kind check only | 009, 010 |
| TB8 | Handle values, ownership, thread of free | `require_handle` (`lib.rs:715-728`), `as_ref` (`:1570-1571`, `:1661`), `adopt` | Null check on borrow only | 024 |
| TB9 | Region, table name, KMS ARN, wrapping key, TTL | `mpl/test-server/src/handlers.rs:137-147` | None | 026 |

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
                  │ KMS Decrypt(enc, auth EC as AAD)      │   (under Discovery the KMS key is the
                  v                                       │    record's own ARN, TM-002)
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
      │ for each matching EDK, one after another:
      │   len >= 44 -> version = ct[28..44]   (60-byte check later: BUG-05b)
      │   cache_id = SHA384(0x02‖0‖0x02‖0‖partition‖0‖logicalName‖0‖bkid‖0‖version)
      │   cache hit (elapsed <= ttl) or KeyStore.get_branch_key_version -> BranchKeyMaterials
      │      (a failed key-store read is not cached; the in-flight mark stays, TM-025)
      │   branch_key_wrap::unwrap: len >= 60; KBKDF(salt) -> AES-256-GCM open(iv, aad)
      v
   add_data_key (length checked) -> check_decryption_transition -> check_decryption_materials_complete
```

## 7. Threat Identification (STRIDE)

### Spoofing
| ID | Threat | Component |
|----|--------|-----------|
| TM-MPL-001 | Raw-AES keyring emits an EDK whose key-provider-id impersonates an AWS KMS keyring | `RawAesKeyringBuilder::build` |
| TM-MPL-002 | Forged branch-key-store record decrypts under an attacker-influenced KMS key (key-id confusion) | `kms_ops::decrypt_branch_key` |
| TM-MPL-003 | Malicious branch-key supplier, or message-driven supplier input, returns an attacker-chosen branch key id | `HierarchicalKeyring::resolve_branch_key_id`, `BranchKeyIdSupplier` |

### Tampering
| ID | Threat | Component |
|----|--------|-----------|
| TM-MPL-004 | ARN/MRK match logic accepts a non-matching key ARN (over-permissive match) | `mrk_match`, `kms_config::is_arn_compatible` |
| TM-MPL-005 | Branch-key record substitution or rollback: swap in a valid record from another branch-key-id/version, or replay an older ACTIVE record | `DynamoDbKeyStore`, `kms_ops`, `record` |
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
| TM-MPL-015 | Secret material (branch keys, data keys, derived keys, wrapping key) not zeroized or kept past its use | structures, `branch_key_wrap`, `raw_aes_keyring`, `prim`, `LocalCmc` |
| TM-MPL-021 | Secret bytes or attacker-supplied text leak via `Debug`/error/log formatting | structures, error model |
| TM-MPL-010 | Shared-cache confusion serves branch-key materials to a keyring that should not access them | `cache_entry_identifier`, `hierarchical_keyring` |

### Denial of Service
| ID | Threat | Component |
|----|--------|-----------|
| TM-MPL-018 | Storm-tracking misconfiguration or logic error causes a stampede, deadlock, InFlightTTL failures, a stale-mark wedge or a panic | `cmc/storm_tracking` |
| TM-MPL-022 | Cache exhaustion / eviction thrash forces a KMS-call storm (throttling) | `cmc/local`, `cmc/default` |
| TM-MPL-023 | Malformed EDK/ciphertext or extreme configuration triggers a panic or resource blow-up instead of an error | `branch_key_wrap::unwrap`, keyrings, `default_cmm` |
| TM-MPL-025 | Decrypt-input amplification: EDK count and branch-key versions chosen by the sender drive key-store reads, in-flight slots and wall-clock time (**new, provisional**) | `hierarchical_keyring::on_decrypt`, `cmc/storm_tracking` |

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
| TM-MPL-024 | C++ shim dereferences or adopts a dangling, forged or double-owned handle to an MPL object | `esdk/shims/aws-esdk-cpp` (boundary) |
| TM-MPL-026 | Unauthenticated loopback test server exercises ambient AWS credentials for any local process (**new**) | `mpl/test-server` (and the other three) |

## 8. Threat Analysis and Mitigations (per threat)

**TM-MPL-001 (S): Raw-AES key-provider-id impersonation.** Attack: the caller sets `key_namespace = "aws-kms"` (or `aws-kms-hierarchy`), so its EDKs look like KMS-keyring EDKs. Mitigation: `RawAesKeyringBuilder::build` (`mpl/src/keyring/raw_aes_keyring.rs:350`) rejects any namespace that starts with `aws-kms` (constant `:52`, check `:360`). The spec section is raw-aes-keyring.md. Severity Medium, Likelihood Low → Low. Residual: the check is a prefix test on the exact bytes; other keyrings compare the provider id exactly, so a case variant does not impersonate. **Re-confirmed.**

**TM-MPL-002 (S): Branch-key record decrypts under an attacker-influenced KMS key.** Attack: TA1 writes a record whose `kms-arn` points at an attacker-controlled key. Mitigation: for `KmsKeyArn`/`KmsMrKeyArn`, `resolve_key_store_arn` sends the CONFIGURED ARN as `KeyId` after the compatibility check (`mpl/src/key_store/kms_ops.rs:88`, `:94-95`, `:105`; the id reaches KMS at `:183`). `DynamoDbKeyStore::build` validates the configured ARN (`key_store/branch_key_store.rs:381`). The spec section is branch-key-store.md (`KeyId` rule). Severity Critical, Likelihood Low → Medium. Residual: by spec, Discovery modes trust the record ARN (`kms_ops.rs:96-103`).

**Second pass (sharpened, rating unchanged).** Discovery is not decrypt-only in this code. The hierarchical keyring calls `get_active_branch_key` on ENCRYPT (`hierarchical_keyring.rs:692`). That method runs the same `decrypt_branch_key` with the record's ARN (`branch_key_store.rs:792`, `:801`), and only CreateKey/VersionKey refuse Discovery (`:112-121`). So a TA1 who can write the table, and who controls a KMS key whose key policy lets the application's role call Decrypt, can plant an ACTIVE record whose branch key the attacker knows. New encryptions then wrap data keys under it. The spec's "identical Logical Keystore Name" proviso does not stop this, because `tablename` is part of the encryption context that the attacker chooses when encrypting under their own key. The preconditions (Discovery or MRDiscovery configured, DDB write, an attacker key policy, no IAM scoping of `kms:Decrypt`) keep Likelihood at Low. The control is configuration: use a single-key configuration, or scope `kms:Decrypt` in IAM. BUG-04 (TM-MPL-007) does not widen this, because an attacker who can write the record already controls the ARN's region and account.

**TM-MPL-003 (S): Malicious or message-driven branch-key supplier.** The supplier is caller-provided trusted code (public trait `BranchKeyIdSupplier`, `mpl/src/aws_kms/hierarchical_keyring.rs:187`; its handle runs no checks, `:260-263`). The resolved id is bound into the cache id (`:665`, `:908`) and the EDK provider info (`:722`). The AAD uses the id of the returned materials (`branch_key_wrap.rs:61`), so a mismatched id fails authentication on decrypt. Severity Medium, Likelihood Low → Low. A supplier that returns attacker-influenced ids containing `0x00` is one of the BUG-06 collision paths (rated under TM-MPL-009).

**Second pass (residual added, rating unchanged).** On decrypt the supplier's input is the message's encryption context (`:747`, `:831`; with `DefaultCmm` it is the merged context, `default_cmm.rs:198`). The sender controls that context, and it is not authenticated until a data key is recovered. So whoever submits a ciphertext picks the branch-key id the service looks up, as long as the EDK's provider info names the same id (`:752-763`). Consequences: (a) the service's own role fetches and caches any tenant's branch key on request; no key reaches the sender, because unwrap still needs the right key; (b) the error type distinguishes an unknown version (a `ResourceNotFound` from the key store) from an authentication failure, which is a small existence oracle if errors reach the sender; (c) both feed TM-MPL-025. Deciding which tenant ids may be decrypted is the application's job, so the rating stays Low.

**TM-MPL-004 (T): Over-permissive ARN/MRK match.** Mitigation: `aws_kms_mrk_match_for_decrypt` rejects aliases (`mpl/src/aws_kms/mrk_match.rs:24-27`; it returns `false` even for two identical alias ARNs, a documented spec deviation that fails closed). It returns true only on byte equality or, for MRK ARNs (`is_multi_region_arn`, `:52`; `key/mrk-` prefix `:57`), when every part except the region is equal (the `split(':')` parse at `:38-41` is index-safe because both inputs already passed the six-segment check). `is_arn_compatible` is at `mpl/src/key_store/kms_config.rs:86`. The spec section is aws-kms-mrk-match-for-decrypt.md. Severity High, Likelihood Low → Medium. Residual: ad-hoc `split(':')` ARN parsers, a strong verification candidate. The private `rewrite_arn_region`/`reject_alias_arn` still have no direct tests (Stage 1/scope). **Re-confirmed.**

**TM-MPL-005 (T): Branch-key record substitution or rollback.** Mitigation: every non-`enc` attribute (branch-key-id, type, version, kms-arn, hierarchy-version, create-time, custom EC, plus `tablename` = logical name) is put in the KMS encryption context (`key_store/branch_key_store.rs:132-136`). KMS Decrypt/ReEncrypt then authenticates it as AAD (`kms_ops::build_authenticated_encryption_context`, `mpl/src/key_store/kms_ops.rs:49`; DDB codec `branch_key_store.rs:1089`, `:1141`). Materials are rebuilt only from the authenticated EC, with a strict 32-byte branch-key check (`key_store/record.rs:95`, `:164`). The spec section is branch-key-store.md. Severity Critical, Likelihood Medium → High (mitigated). Residual: correctness rests on the reconstructed EC exactly matching the write-time EC, which is the top verification target. A user-supplied `KeyStore` sits outside this mitigation entirely, and the keyring does not compare the returned materials' bkid/version with the request (`hierarchical_keyring.rs:692-696`, `:934-939`; `key_store/client_impl.rs:305-308`, `:373-376`). On decrypt the AAD still binds them. BUG-08 is still present (`key_store/encryption_context.rs:91-102`: a custom-EC collision `Err` that can never trigger, because prefixed keys from a `BTreeMap` cannot collide). It is informational.

**Second pass (residual added, rating unchanged): authentic-record rollback.** An older ACTIVE record of the same branch key id is a valid, KMS-authenticated record: its `version` and `create-time` sit inside the authenticated EC. So a TA1 with DDB write access can put an earlier copy of the ACTIVE item back, and `get_active_branch_key` accepts it. The keyring then encrypts under an older branch-key version. No key is disclosed, and decrypt of existing messages is unaffected because the version comes from the EDK. The effect is a rotation rollback, which matters because rotation bounds the salt/IV birthday risk (TM-MPL-012). Nothing detects it. `fetch_record` uses a plain `GetItem` with no consistent-read flag (`branch_key_store.rs:148`, `:155-163`; `consistent_read` appears nowhere in `mpl/src`), and the keyring does not remember the highest version it has seen. VersionKey's optimistic lock (`:752`) protects concurrent rotations by the library, not against table tampering. The rating is unchanged: the core property (a record cannot be forged or moved to another id or version) holds, and this is a freshness gap that needs DDB write access.

**TM-MPL-006 (E): Suite downgrade / commitment-policy bypass.** Attack (Invisible Salamanders class): force encryption or decryption with a non-committing suite where commitment is required. Mitigations:
- `DefaultCmm` rejects a requested suite that is not `allows_for_encrypt` (`mpl/src/cmm/default_cmm.rs:97`) and a message suite that is not `allows_for_decrypt` (`:184`). The tables are at `mpl/src/structures/commitment_policy.rs:62`, `:77`.
- The transition check stops a keyring from changing the suite (`mpl/src/structures/materials_checks.rs:78-81`, decrypt `:117`). It runs on every `SharedKeyring` `send()` (`keyring/fluent_builders.rs:82`, `:163`).
- The PDK length is bound to the suite's key length (`algorithm_suite.rs:547`; BUG-02 fixed).
- Caller-side: the ESDK checks the message's suite against its policy before calling the CMM (`esdk/src/decrypt.rs:413`) and re-checks the CMM's returned suite (`esdk/src/materials.rs:130`, `:202`).

The spec section is commitment-policy.md. Severity Critical, Likelihood Low → Medium. The `FORBID_ENCRYPT_ALLOW_DECRYPT` default suite is `03 78` (`commitment_policy.rs:43-50`), a documented deviation from the spec's `00 78` (`ESDK.ALG_AES_256_GCM_IV12_TAG16_NO_KDF`). It is stronger and still non-committing, as FORBID requires. The DBE policy is not implemented (`commitment_policy.rs:8-10`). The rating is unchanged: the allow tables have not been proven correct and have no Duvet trace.

**Second pass (residual added, rating unchanged).** `SharedCmm::send()` checks only that its output is complete (`cmm/fluent_builders.rs:171`, `:319`; `materials_checks.rs:157`, `:177`). It does not re-check the request's commitment policy, the requested suite, the RECK superset or PDK/EDK correspondence. The built-in `DefaultCmm` enforces the first two itself, and the ESDK re-checks the policy. A user-written `Cmm` used by another consumer of the MPL (DB-ESDK, S3EC, which live outside this repo) therefore has no policy backstop inside the MPL. `max_plaintext_length` is carried in `GetEncryptionMaterialsInput` (`cmm/types.rs:23`, `:66`) but `DefaultCmm` never reads it; no attacker is involved, and a future caching CMM would need it.

**TM-MPL-007 (E): Discovery/MRDiscovery alias or attacker-region key.** Mitigation: `resolve_key_store_arn` rejects alias ARNs for both discovery modes (`kms_ops.rs:96-103`, `reject_alias_arn` `:118`). It is called from `decrypt_branch_key` (`:162`, `:179`). Severity High, Likelihood Low → Medium. BUG-04 is confirmed open: the MrDiscovery arm rewrites the region of *any* record ARN, including single-Region keys (`:100-103`, `rewrite_arn_region` `:144`; no `mrk-` check). branch-key-store.md#mrdiscovery says "Any MRK ARN discovered will be changed", while the KeyId rule in the same document says "with the region replaced". The effect is a KMS call to an ARN for a key that does not exist or is a different key, so it fails closed. The KMS-side behavior needs AWS and was not run. **Re-confirmed.**

**TM-MPL-008 (E): Non-committing suite reuse (Invisible Salamanders).** Grounded in Invisible Salamanders (Dodis et al., IACR 2019/016) and **CVE-2026-6550 / GHSA-v638-38fc-rhfv (verified, Python ESDK; not applicable here)**. The advisory's conditions (two clients with different commitment policies sharing one caching CMM, weaker client first, matching encryption contexts, default suite) all require a caching CMM. Mitigation as TM-MPL-006. Commit-key suites (`05 78`) are the default under the REQUIRE policies (`commitment_policy.rs:43-58`). Severity High, Likelihood Low → Medium. `mpl/src/cmm/` contains no caching CMM. `CachedMaterials::Encryption`/`Decryption` exist (`mpl/src/cmc/entry.rs:26`, `:28`), so any future caching CMM must bind the commitment policy (or the suite) into its cache id. **Re-confirmed.**

**TM-MPL-009 (E): Cache-identifier collision.** The identifier is SHA-384 over `0x02 ‖ 0 ‖ scope ‖ 0 ‖ partition ‖ 0 ‖ logicalName ‖ 0 ‖ bkid [‖ 0 ‖ version]`, with single NUL separators and no length prefixes (`mpl/src/aws_kms/cache_entry_identifier.rs:35`, `:42-60`). The call sites are `hierarchical_keyring.rs:665`, `:908`. The layout is exactly what aws-kms-hierarchical-keyring.md requires ("All the above fields must be separated by a single NULL_BYTE"). The spec's #partition-id section also says keyrings with different partition IDs "CANNOT share" cache entries, and that holds only if no field contains `0x00`.

Attack (BUG-06, confirmed on main):
1. Keyring A uses partition `"tenant\0x"` and logical name `"L"`. Keyring B uses partition `"tenant"` and logical name `"x\0L"`. Both use bkid `"bk"`.
2. The two preimages are identical, so the cache ids are equal.
3. With one shared cache, A's OnEncrypt caches A's branch key. B then gets a hit, never calls key store B, and wraps its data key under A's branch key.
4. The same shift works between any two adjacent fields.

Nothing checks the inputs. The partition id is the caller's raw bytes (`hierarchical_keyring.rs:596`). The default random 16-byte UUID can contain `0x00` (`:626`). The logical name is used as the key store returns it (`:600-605`). The bkid comes from config or a supplier. The only post-hit guard is the material-kind check (`:1000`). Severity High (cross-tenant use of a branch key: B's data becomes decryptable by holders of key store A's access, and not by B's own key store). Likelihood **Medium**. Risk **High**.

**Second pass: re-derived, kept at High.** `cache_entry_identifier.rs` is unchanged since a1e23d7, and RECHECK BUG-06 still shows 2 passed with key store B called 0 times. The version field cannot be a NUL vector, because it is rendered as hex digits and hyphens (`hierarchical_keyring.rs:894`); the vectors are the partition id, the logical name and the bkid. What remains is a configuration precondition that the MPL does not check: a shared cache, plus NUL-containing values from tenant names, from a user `KeyStore`'s logical name, or from an EC-driven supplier. The Medium likelihood rates the multi-tenant shared-cache deployment that the spec's Partition ID guidance is written for. Reviewers who judge NUL-containing tenant input unrealistic can return this to Medium risk. Fix: reject `0x00` in these fields, or length-prefix them. Length-prefixing needs a spec change and breaks cross-runtime cache-id compatibility. Coverage: hierarchical tests cover cache-id separation (`mpl/tests/test_aws_kms_hierarchical_keyring.rs`, per scope) but have no NUL case. See the note at the end of this document on the BUG-06 severity in the bug report.

**TM-MPL-010 (I/E): Shared-cache confusion.** Attack: two keyrings that should be isolated share cache entries, so one reuses branch-key materials it could not fetch itself. Mitigations:
- The default partition id is a fresh random v4 UUID (`hierarchical_keyring.rs:626`), so keyrings are isolated by default.
- Shared-cache scope is opt-in. The spec says users MUST set all three fields the same if, and only if, they want sharing.
- The cache returns only `BranchKey` entries to the keyring (kind check `:1000`).
- Entries older than the TTL are refetched. The comparison is exact (`:989-995`; BUG-09 fixed).

Severity High, Likelihood **Medium**, Risk **High**. BUG-06 (TM-MPL-009) is a concrete, confirmed way to realize this threat across keyrings that have *different* partition ids. A user-supplied `Cmc` can also return any entry for any id; only its kind is checked (TB7). It can also report `grace_period() = None` (trait default, `mpl/src/cmc/mod.rs:88-90`), which skips the grace-vs-TTL check (`hierarchical_keyring.rs:584-593`); the check is generic, so only a cache that overrides `grace_period` is covered. The earlier residual "no cross-check that a cached suite's commitment matches the current policy" stays **withdrawn**: the keyring caches only `CachedMaterials::BranchKey` (`:700`, `:943`), and branch keys do not depend on the commitment policy. TM-MPL-009 and TM-MPL-010 share one root cause and one fix.

**Second pass (two residuals added, rating unchanged).** (1) A collision that needs no NUL: two physical key stores configured with the same logical name, the same partition id and the same bkid share cache ids. The spec forbids this configuration (`#logical-key-store-name`; `cache_entry_identifier.rs:11-14`), and nothing in the MPL can detect it because the logical name is whatever the key store reports. (2) `cache_entry_within_limits` maps a `duration_since` error to zero elapsed (`hierarchical_keyring.rs:991-994`). An entry whose creation time is in the future (a wall-clock step backwards, or a user cache) therefore counts as fresh. This matches the spec formula `now - creation <= ttl`, and all TTL checks use wall-clock `SystemTime`. The effect is bounded by the clock step.

**TM-MPL-011 (E): AES-GCM IV reuse in the raw-AES keyring.** Mitigation: a fresh 12-byte IV from the CSPRNG for each wrap (`mpl/src/keyring/raw_aes_keyring.rs:146`, `:151-152`), passed to `prim::aes_encrypt` (`Nonce::try_assume_unique_for_key`, `prim/src/lib.rs:188`). Severity Critical, Likelihood Low → Medium. Residual: uniqueness rests on a 96-bit random nonce, so reuse is bounded only by the birthday bound. NIST SP 800-38D limits a key to 2^32 invocations when the IV is random; the keyring keeps no wrap counter, and a long-lived wrapping key on a high-volume service can approach that over its life (for example, one wrap per message at 100 messages per second is about 500 days). There is still no two-call IV-distinctness test (scope). This is a prime verification target. **Second pass: re-confirmed;** the usage bound was added as an operational residual and does not change the rating.

**TM-MPL-012 (E): Salt/IV reuse in branch-key wrap.** Mitigation: a fresh 16-byte salt and 12-byte IV for each `wrap` (`mpl/src/aws_kms/branch_key_wrap.rs:157`, `:164`, `:170`). The salt gives a fresh derived key for each wrap. The Appendix B birthday analysis motivates yearly rotation (note the rollback residual under TM-MPL-005). Severity Critical, Likelihood Low → Medium. **Re-confirmed.**

**TM-MPL-013 (T): Branch-key AAD inconsistency.** Mitigation: `compute_aad` builds `"aws-kms-hierarchy" ‖ bkid ‖ version(16 B) ‖ serialized EC` the same way on wrap and unwrap (`branch_key_wrap.rs:61`). The version is parsed strictly as a 36-character canonical UUID (`:92`). The spec section is aws-kms-hierarchical-keyring.md. Severity High, Likelihood Low → Medium. `EncryptionContext::from_bytes` rejects out-of-order and duplicate keys and invalid UTF-8 (`mpl/src/structures/encryption_context.rs:145`, `:202`, `:208`; BUG-03 fixed), so a decoded EC has one canonical form. Residual: serialization determinism and version-format strictness are still unproven, and `from_bytes` accepts empty keys (`test_deserialize_accepts_empty_key_length_currently_unenforced`, `mpl/tests/test_encryption_context.rs:468`). **Re-confirmed.**

**TM-MPL-014 (E): KBKDF fixed-info misuse.** Mitigation: fixed info = `Label("aws-kms-hierarchy") ‖ 0x00 ‖ salt ‖ L_be32(256)` (NIST SP 800-108 counter-mode HMAC-SHA-256), computed by `prim::kbkdf_ctr_hmac` (`prim/src/lib.rs:313`). The derivation is `derive_branch_key` (`branch_key_wrap.rs:122`); the 32-byte output goes into a `Zeroizing` buffer (`:135-136`). Severity High, Likelihood Low → Medium. Residual: correctness of the byte layout and the L value is a strong verification candidate. **Second pass:** the spec gives the salt, the key and the label for this KDF, but not the fixed-info byte layout (Stage 1 N11a). Interoperability with other MPL runtimes therefore rests on the code and its comment, not on the specification, and a proof can only be stated against the code. No Dafny source was read, so no Dafny-conformance claim is made. Rating unchanged.

**TM-MPL-015 (I): Secret material not zeroized or kept past its use.** Mitigations (since a1e23d7, #131 and #158):
- `PlaintextDataKey`, `SigningKey` and `SymmetricSigningKey` derive `Zeroize, ZeroizeOnDrop` (`mpl/src/structures/algorithm_suite.rs:505`, `:571`, `:655`).
- `BranchKeyMaterials` and its builder zeroize on drop (`structures/branch_key_materials.rs:205-219`). So do `BeaconKeyMaterials` and its builder (`structures/beacon_key_materials.rs:221-235`), and the raw-AES wrapping key in both the keyring and its builder (`keyring/raw_aes_keyring.rs:72-78`, `:233-239`).
- The derived branch key is `Zeroizing` (`aws_kms/branch_key_wrap.rs:135`). So is the decrypted branch key during record parsing (`key_store/record.rs:100`, `:173`).
- No `unsafe` code in `mpl/src` or `prim/src`.

Residual exposures that remain:
- The raw-AES decrypt buffer on the AES-error and wrong-length paths (`raw_aes_keyring.rs:471`, `:489`).
- The `Vec` returned by `branch_key_wrap::unwrap` before it is wrapped in `PlaintextDataKey`.
- The KMS SDK response `Blob` that holds the plaintext branch key (`key_store/kms_ops.rs:207`).
- BUG-07(a): `prim::aes_encrypt` copies the plaintext into the output buffer before the key and nonce checks that can return `Err` (`prim/src/lib.rs:185-188`). The MPL callers then drop that buffer without wiping it.
- Copies left behind when a `Vec` reallocates.
- By design, the cache holds plaintext branch keys for the TTL.

**Second pass (two residuals added, rating unchanged).** (1) Residency can exceed the TTL. `LocalCmc` drops an expired entry only when it is read, when it falls in the pruned LRU tail (`entry_pruning_tail_size`, default 1 per `get_fresh`: `cmc/local.rs:69`, `:131`, `:166`), or when it is evicted at capacity. An entry that nobody reads again stays in memory, in plaintext, until then. The CMC spec says an implementation SHOULD provide a way to avoid this ("Background Processing"). Entries are zeroized on drop, not on expiry. (2) `prim::ecdsa_generate_keypair` holds the private key DER in a plain `Vec` (`prim/src/ecdsa.rs:387`) inside `SignatureKeyPair`, which is `Clone` and not zeroizing (`:324-326`); on the length-check error path (`:391-392`) that `Vec` is dropped without a wipe. On the success path the `Vec` is moved, not cloned, into the zeroizing `SigningKey` (`default_cmm.rs:137-149`). Both residuals need TA4, who is already inside the process and can read live cache entries, so the likelihood stays Low.

Severity **Medium** (only transient or error-path copies and unread expired entries remain; every long-lived secret is wiped on drop), Likelihood Low → **Low**. Verification candidate: prove that no secret buffer outlives its scope without being wiped, starting with the residual sites above.

**TM-MPL-016 (T): VersionKey optimistic-lock bypass.** Mitigation: before rotating, VersionKey authenticates the ACTIVE record with a KMS ReEncrypt-to-self. It then writes in one `TransactWriteItems`: `attribute_not_exists` for the new DECRYPT_ONLY item (`mpl/src/key_store/branch_key_store.rs:743`) and `attribute_exists(#branch_key_id) AND #enc = :encOld` for ACTIVE (`:752`). The function is at `version_key` (`:641`). Severity Medium → Low. **Re-confirmed.** (A stale `GetItem` makes the `#enc = :encOld` condition fail and surfaces as a conflict; it does not corrupt the table.)

**TM-MPL-017 (T): Reproduced-EC merge tampering.** Mitigation: `merge_reproduced_encryption_context` fails when a shared key's values disagree (`Kind::EncryptionContextMismatch`) and appends reproduced-only pairs as required EC keys (`mpl/src/cmm/default_cmm.rs:198`, `:273`). The spec section is cmm-interface.md. Severity High, Likelihood Low → Medium. The transition checks reject a keyring that changes the EC or the required EC keys (`materials_checks.rs:82-89` encrypt; the decrypt transition at `:117` checks the same fields). The merge itself is still the only guard that the decryptor's AAD equals the encryptor's, and it is a verification target. **Re-confirmed.**

**TM-MPL-018 (D): Storm-tracking correctness.** Current mitigations:
- Fan-out bounds concurrent refreshes (`mpl/src/cmc/storm_tracking.rs:274`, `:310`).
- The lock is never held across `.await`.
- A poisoned lock maps to a `Kind::Internal` error instead of a panic on the hot path (`state_locked`, `:239`, `:248`).
- `put_cache_entry` writes the inner cache before it clears the in-flight mark (`:710`, `:721`, `:725`).
- The hierarchical keyring rejects a cache grace period ≥ TTL when the cache reports one (`hierarchical_keyring.rs:584-593`).

Severity Medium, Likelihood Medium → Medium.

**Mitigation regressed (first pass, still true).** `StormTrackingCmcBuilder::build` (`:606`) checks only `fan_out ≥ 1` (`:613`), `in_flight_ttl > 0` (`:616`), `sleep > 0` (`:619`), and `grace_interval ≤ in_flight_ttl` (`:622`). It does not enforce the spec's "Grace Interval MUST be ≤ Grace Period" or "Inflight TTL MUST be ≤ Grace Period" (storm-tracking-cryptographic-materials-cache.md, Consistency), or "at least 1" for the grace period and grace interval. `test_durations_are_stored_exactly` (`mpl/tests/test_storm_tracking_cmc.rs:388`) accepts `grace_period = 0`. The spec also conflicts with itself: its default Inflight TTL (20 s) exceeds its default Grace Period (10 s), which its own ordering MUST forbids; the code uses 10 s (`storm_tracking.rs:117-119`).

**Second pass (re-derived; three liveness findings, rating kept at Medium).** All three are static reasoning, not run:
1. **Stale in-flight mark (wedge).** A leader that never calls `put_cache_entry` (a key-store error, or a cancelled caller) leaves its key marked in flight. The error path does not clear it, and `state_locked` deliberately skips the caller's own key when it prunes (`:249-255`). After `in_flight_ttl` (default 10 s), every miss for that key returns `Throttling` at classification (`:322-323`) and never becomes a leader, so nothing can clear the mark except a `put` for it (impossible) or a call for a *different* key that prunes it. Recovery before the TTL is possible: between the grace interval (1 s) and the TTL, the next call takes the leader slot again (`:337`). So the wedge needs the next call for that key to arrive more than `in_flight_ttl` after the failure and no other key's call to intervene. A low-traffic, single-key, encrypt-only service is exposed; a service that also decrypts is not, because the decrypt ids differ and prune the mark. `test_get_miss_inflight_exceeds_ttl_fails` (`mpl/tests/test_storm_tracking_cmc.rs:761`) encodes the error for a pre-marked key; it does not test recovery. The spec says a request "returns an 'InFlightTTL exceeded' error" but not who clears the mark.
2. **A fan-out-saturated waiter has no deadline of its own.** For a cache miss on a key that is not in flight while the fan-out is full, the decision is `Wait { deadline: None }` (`:310-313`), and `wait_for_leader` (`:360`) then ends only when a slot frees (`:389-397`: a prune after `in_flight_ttl`, or a `put`). The spec's FanOut text also ends a blocked request "when the amount of time that request has been outstanding exceeds the Inflight TTL".
3. **BUG-01 plus the state lock.** BUG-01(c) (`:333`, `now + in_flight_ttl`) and (b) (`:680`, `inflight + grace_interval`) panic inside `classify_and_mark` and `wait_for_leader` while the guard from `state_locked` is held (`:739-740`, `:388-397`). Unwinding poisons the mutex, and every later call on that cache instance returns `Internal` "cache lock poisoned" (`:248`). Only a config with an unbounded duration reaches it, so it stays a configuration hazard, but the failure is then permanent for that cache.

If a reproducer confirms finding 1, severity could rise to High; at Likelihood Low the risk is still Medium, so the rating is unchanged. The attacker-driven side of these liveness gaps is TM-MPL-025. This remains a strong verification target (the single-in-flight invariant, plus the spec ordering once it is restored).

**TM-MPL-019 (E): Missing Duvet coverage.** Finding: spec MUSTs are not mechanically traced for the MPL. Severity Medium, Likelihood Medium → Medium.
- `main` contains no MPL Duvet config. The only configs are `esdk/.duvet/config.toml` and `esdk/shims/aws-esdk-cpp/.duvet/config.toml`; the ESDK one lists `spec/framework/transitive-requirements.md` (`:37`) and no MPL document.
- `mpl/` and `prim/` hold one annotation block (`mpl/src/cmc/entry.rs:201-204`), which no config checks. ESDK, by contrast, has about 2100 `//=` lines (scope).
- Since #91 (`6ef7d80`) the spec is not a submodule. It is fetched from `scripts/spec-source.json` at `ref = "master"`, so the spec revision floats and a spec change can arrive silently. Remote `master` is now `94c2bfe`; the setup step found that only `client-apis/decrypt.md` changed since `877edcc` and that `framework/` did not (scope, not re-diffed here).

Recommendation: add `mpl/.duvet/config.toml` and annotations for the commitment policy, MRK match, AAD, cache id, key-store auth EC and storm-tracking constraints, and pin the spec revision. **Re-confirmed.**

**TM-MPL-020 (R): No operation ↔ KMS/DDB audit binding.** Mitigations: KMS/DDB CloudTrail. Every KMS call carries the framework metadata `AwsCryptographicMPL-Rust/<version>` in its user agent (`mpl/src/aws_kms/user_agent.rs:9`, `:15-19`; applied at `key_store/kms_ops.rs:187-188`, `:239-240`, `:286-287`). Severity Low → Low. CloudTrail can attribute KMS calls to the MPL, but not to a specific MPL operation or message. **Re-confirmed.**

**TM-MPL-021 (I): Secret leakage via `Debug`/logging.** Mitigations:
- `Debug` is redacted for `PlaintextDataKey`, `SigningKey` and `SymmetricSigningKey` (`algorithm_suite.rs:564`, `:612`, `:696`), for `BranchKeyMaterials` and its builder (`branch_key_materials.rs:55`, `:191`), for beacon keys (`beacon_key_materials.rs:57`, `:191`), for the raw-AES keyring (`raw_aes_keyring.rs:80`, wrapping key at `:87`) and for `prim`'s `SignatureKeyPair` (`prim/src/ecdsa.rs:335`).
- The error model attaches EDK info as `DataKeyInfo`, which holds the provider id and info but never the ciphertext (`structures/encrypted_data_key.rs:147-152`; `prim/src/error.rs:378`).
- Key-store errors name attributes and their types, never values (`key_store/branch_key_store.rs:1140`).

Severity Medium, Likelihood Low → Low.

**Second pass (residual added, rating unchanged).** `NoMatchingDataKey` keeps the message's EDK identities: `with_encrypted_data_keys` (`mpl/src/error/generated.rs:1064`) and the public getter `encrypted_data_keys()` (`:1591`). `DataKeyInfo`'s `Debug` prints the provider info as text when it is UTF-8 and as hex otherwise (`prim/src/error.rs:406-409`). That info is a KMS key ARN (with an account id) or a branch-key id, and it comes from attacker-supplied message bytes. It is not secret, but it is attacker-controlled text and an account-id disclosure if errors are logged verbatim or returned to the sender. Together with the existence oracle in TM-MPL-003 this is why callers should not return MPL errors to the ciphertext sender. Errors still carry resource ids (bkid, KMS ARN, table name) and raw-AES provider info (key name + IV); none of these is secret.

**TM-MPL-022 (D): Cache exhaustion → KMS storm.** Mitigation: with `rt-tokio`, the default hierarchical cache is `DefaultCmc` (`hierarchical_keyring.rs:567-574`): storm-tracking over a 1000-entry LRU with tail pruning (`cmc/local.rs:166`). Storm tracking coalesces refreshes. Without `rt-tokio`, the caller must supply a cache (`:575-581`). Severity Low, Likelihood Medium → Low. **Second pass: re-confirmed;** one observation supports the rating. A key-store lookup that fails is never put in the cache (`hierarchical_keyring.rs:931-955`), so an attacker cannot evict legitimate entries by feeding unknown versions. Eviction pressure needs *valid* versions, which are bounded by the number of rotations. The remaining cost of unknown versions is key-store reads, handled in TM-MPL-025.

**TM-MPL-023 (D): Panic or resource blow-up on malformed input or extreme configuration.** Mitigations:
- `try_decrypt_edk` checks for ≥ 44 bytes before reading the version (`hierarchical_keyring.rs:879`; the `.expect` at `:892` cannot fire after that check).
- `branch_key_wrap::unwrap` checks for ≥ 60 bytes before slicing (`branch_key_wrap.rs:236`; the expects at `:249`, `:252`, `:256` cannot fire after it).
- `EncryptionContext::from_bytes` returns errors on any malformed input (`structures/encryption_context.rs:145`).

Severity Medium, Likelihood Low → Low.
- (1) BUG-02 is fixed. A wrong-length unwrapped key is rejected when it is added to the materials (`hierarchical_keyring.rs:767`; `algorithm_suite.rs:547`), and the raw-AES keyring checks the length too (`raw_aes_keyring.rs:489`).
- (2) #186 removed an O(n²) memory blow-up in the attacker-controlled EDK count. The EDK list is now attached once, to the aggregate error (`raw_aes_keyring.rs:517`; hierarchical `:784`; tests `mpl/tests/test_keyring_memory.rs:100`, `:113`, which check memory growth only, not call count or elapsed time; see TM-MPL-025).
- (3) Still open: BUG-05(a), where `ecdsa_generate_keypair(..).expect(..)` (`cmm/default_cmm.rs:137-138`) panics if key generation ever fails; BUG-05(b), where a 44–59-byte EDK costs one key-store call before it is rejected; BUG-01(a/d), where a huge configured TTL panics on `now + ttl` (`hierarchical_keyring.rs:702`, `:945`; only zero is rejected, `:547`); BUG-01(b/c), see TM-MPL-018; and BUG-07(b), where `aes_decrypt` maps every callee error to "authentication tag did not match" (`prim/src/lib.rs:215`, `:229`), which is misleading for a buffer-length error.

These are configuration-driven or practically unreachable, so the rating is unchanged. **Re-confirmed.**

**TM-MPL-024 (E/T): C++ shim dereferences or adopts a dangling, forged or double-owned handle to an MPL object.** The shim's `#[cxx::bridge]` (`esdk/shims/aws-esdk-cpp/src/lib.rs:167`) hands C++ opaque Rust resources: `KeyStore`, `Keyring`, `CryptographicMaterialsCache`, KMS and DynamoDB clients. C++ owns each one as a `rust::Box`, so the shim has no delete functions (`:423-424`). Two kinds of pointer cross the boundary.

*(a) Borrowed handles.* The bridge input structs carry `*const T` (`keyring` `:274`, `:300`; `key_store` `:398`; `cache` `:401`; `kms_client`, `ddb_client` `:372-373`). `require_handle` null-checks a pointer and then dereferences it in `unsafe { &*ptr }` (`:715`, `:720`, `:728`). Optional KMS/DDB clients and the cache are dereferenced with `unsafe { … .as_ref() }` (`:1570`, `:1571`, `:1661`), where null means "not supplied". Attack: TA7 passes a dangling or type-confused pointer. The dereference is then undefined behavior inside a process that holds wrapping keys and branch keys, which can mean memory disclosure or corruption of MPL state.

*(b) Adopted keyring (added in the second pass; a first-pass gap).* `aws_esdk_cpp::into_keyring_handle` turns any `IntoShared<SharedKeyring>` into a type-erased `*mut c_void` (`Box::into_raw(Box::new(Keyring { .. })).cast()`, `lib.rs:2059-2066`). C++ `Keyring::adopt(void*)` hands that pointer to `rust::Box<::ffi::Keyring>::from_raw(static_cast<::ffi::Keyring*>(raw_handle))` (`src/EncryptionSDK.cpp:541-547`). There is no null check, no type check and no ownership check. The header says any other pointer is undefined behavior and that each handle may be adopted at most once (`include/aws/esdk/EncryptionSDK.h:656-664`); the shim's own spec annotation records this as a target obligation that "the shim does not detect" (`lib.rs:2051-2054`). A wrong pointer is type confusion, and a second adoption of the same handle is a double free, in a process that holds keys.

**Lifetime and aliasing review.** The Rust side takes only shared references (`&*ptr`, `as_ref()`) and clones `Arc`s and SDK clients (`.inner.clone()`). It creates no `&mut` from a handle. Handles are not held across `block_on`: encrypt and decrypt clone the keyring before `.send()` and then run `TOKIO_RUNTIME.block_on(..)` (`:1311`, `:1346`), and key-store and keyring creation clone the client and cache handles before building (`:1570-1574`, `:1661`). `require_handle<'a, T>` returns an unbounded lifetime `'a` (`:715`), so the compiler cannot tell a reference that outlives its handle; today every caller consumes it immediately. The shipped C++ facade keeps dependencies alive through `detail::Retained` (key store and cache impls kept inside the keyring impl), so a facade user cannot free a dependency early. The residual risk is therefore concentrated in (i) callers that bypass the facade and use the raw bridge, (ii) a handle freed on another thread between the null check and the clone, and (iii) `adopt`.

**After #188 and #189.** #188 (`41f1d51`) adds the caller's retry config to the DynamoDB client config (`ddb_client`, `lib.rs:1403`; the retry lines are `:1412-1416`), because that client ignores the `SdkConfig` retry config. It moved the later `unsafe` lines down by 6 and changes no handle or lifetime path. #189 (`5f2dc72`) changes build and link only. The current files link the shim archive by path (`CMakeLists.txt:39-53`, `Makefile:4-12`, `performance-tests/Makefile:10-13`), and `build.rs:5-11` compiles the cxx bridge and `EncryptionSDK.cpp` into the same staticlib, so there is one cxx runtime. The test-server build script sets an rpath to the shim's own `target/<profile>` directory (`test-server/build.rs:46-49`), which is a development convenience and not a runtime path. Neither commit changes a trust boundary; their diffs were not read in this step (no shell), and these statements are from the current files and `scope.md`'s file list. The only other `unsafe` in the shim tree is test code (`src/tests.rs:1634`, `Box::from_raw` after `into_keyring_handle`).

Mitigations: null checks on borrowed handles, typed `cxx` bindings, `Retained` dependencies in the facade, and the lifetime rules in spec `shim/shim.md#handles-and-lifetimes` (annotation at `lib.rs:717-719`). The shim has its own Duvet config. This is the only `unsafe` code that reaches MPL objects; `mpl/src` and `prim/src` have none. Severity High, Likelihood Low (it needs a caller-side lifetime or ownership bug) → Medium. Owner: the shim, outside `mpl/`/`prim/`. It is listed here because it is the boundary through which C++ users reach MPL key material. **Second pass: rating re-derived and kept; scope extended with `adopt`.**

**TM-MPL-025 (D): Decrypt-input amplification of key-store reads, in-flight slots and wall-clock time. (New, provisional: static reasoning, not run.)** Attacker: TA8, the sender of a ciphertext, with no credentials. Surface: `HierarchicalKeyring::on_decrypt` processes every EDK that names the configured branch key id, one after another, and for each one it reads the 16 version bytes from the ciphertext (`hierarchical_keyring.rs:751-772`, `:889-894`). The provider id and info that pass the filter are public (the bkid is in every message header), so crafting them costs nothing.

Amplification paths:
1. **One key-store read per EDK.** `decrypt_edk_at_version` (`:901`) looks the id up in the cache and, on a miss, calls `get_branch_key_version` (`:934`), one DynamoDB `GetItem` for a version that does not exist. A failure returns at the `.await?` (`:938`) before the `put_cache_entry` (`:941-955`), so there is no negative caching. A message can list up to 65,535 EDKs (`mpl/tests/test_keyring_memory.rs:4`), and the ESDK cap `max_encrypted_data_keys` defaults to `None` (`esdk/src/config.rs:35`, `:42`). One small message can therefore trigger tens of thousands of sequential reads, and a stored message can be made slow by prepending bogus EDKs, because this work happens before the header is authenticated.
2. **In-flight slots.** With the default `DefaultCmc`, each distinct unknown version marks a cache id in flight (`storm_tracking.rs:315`) and never clears it (TM-MPL-018, finding 1). The default fan-out is 20 (`:115`). Twenty distinct versions fill it for up to `in_flight_ttl` (10 s). While it is full, a legitimate cache *miss* for a new key waits (`:310-313`), and the waiter has no deadline of its own (TM-MPL-018, finding 2). Cache *hits* are still served (`:274-280`). An attacker who keeps sending can keep the slots full.
3. **Wall-clock per request.** If the same unknown version is repeated across EDKs, the second lookup finds the mark within the grace interval and waits for it (`:326-335`, `wait_for_leader` `:360-398`) until the 1 s grace interval ends, then re-marks and fails again. Each duplicate costs about one second of one task, with no CPU or I/O during the wait. A message with N duplicates holds a request for about N seconds.
4. **Tenant fetches through a supplier.** With a `BranchKeyIdSupplier`, the sender also picks the bkid (TM-MPL-003), so valid but foreign tenant ids cost one DDB read and one KMS Decrypt each (once per TTL, then cached).

Mitigations: only EDKs that name the configured (or supplier-chosen) bkid are attempted (`:752-763`); the version must have 16 bytes (`:879`); a failed lookup cannot evict legitimate entries (TM-MPL-022); cache hits survive a full fan-out; #186 removed the memory growth (`test_keyring_memory.rs:100`, `:113`). Not mitigated: the per-message EDK count, per-message key-store budget, negative caching, and an overall deadline. Residual: the cost is DynamoDB read capacity (and a KMS call per valid foreign version), latency of the affected requests, and availability of cache-miss refreshes under paths 2 and 3.

Severity Medium (availability and cost; no confidentiality or integrity effect), Likelihood Medium (any service that decrypts third-party ciphertext, with the default uncapped EDK count), Risk **Medium**. Provisional because paths 2 and 3 need a reproducer (a test that sends N EDKs with distinct unknown versions through a `DefaultCmc` and counts key-store calls and elapsed time; and one with duplicate versions). Path 1 follows directly from the code and the default configuration.

**TM-MPL-026 (E/I): Unauthenticated loopback test server exercises ambient AWS credentials for any local process. (New.)** Four test-server crates exist: `mpl/test-server`, `prim/test-server`, `esdk/test-server` and `esdk/shims/aws-esdk-cpp/test-server`. All bind `127.0.0.1` only (`mpl/test-server/src/main.rs:26-27`; `prim/test-server/src/main.rs:23-24`; `esdk/test-server/src/main.rs:26-27`; `esdk/shims/aws-esdk-cpp/test-server/src/main.rs:26-27`), and none authenticates a caller. The MPL one builds an AWS KMS client and a DynamoDB client from request-chosen regions and then a `DynamoDbKeyStore` from a request-chosen table name, logical name and KMS configuration, using the ambient credential chain (`mpl/test-server/src/handlers.rs:137-147`, `:425-430`). It also builds keyrings from request bytes, including a raw wrapping key, and holds the repo's own `Keyring` and `BranchKeyIdSupplier` implementations (`handlers.rs:442`, `:471`). Attack: TA9, any process on the host (or a container sharing the host network), asks a running server to call KMS and DynamoDB with the developer's or CI job's credentials against any table or key those credentials can reach. Mitigations: loopback bind, `publish = false` in all four `Cargo.toml` files (line 6), and the servers are not part of the published crates. A web page would need a CORS pre-flight to send the CBOR content type to these servers; that was not tested here. Severity Medium (credential misuse on a dev/CI host), Likelihood Low (needs a running server and a local attacker), Risk **Low**. Out of the library's attack surface; recorded so that nobody binds these elsewhere or runs them with production credentials.

## 9. Implementation-Specific Considerations

- All randomness (IVs, salts, data keys, the default partition-id UUID) flows through `prim::generate_random_bytes` (`prim/src/lib.rs:128`). Key-store branch-key ids and versions use `Uuid::new_v4()` (`key_store/branch_key_store.rs:556-557`, `:703`); they are not secret.
- `prim::aes_encrypt`/`aes_decrypt` use `LessSafeKey` with `Nonce::try_assume_unique_for_key` (`prim/src/lib.rs:188`, `:224`). GCM nonce uniqueness is the caller's obligation, so the IV generation in the keyrings (TM-MPL-011/012) is load-bearing.
- `mpl/src` and `prim/src` contain no `unsafe` code (grep finds only the lint name `unsafe_op_in_unsafe_fn` at `prim/src/lib.rs:33`). The only `unsafe` code that reaches MPL users is in the C++ shim (TM-MPL-024: `lib.rs:728`, `:1570`, `:1571`, `:1661`; test-only `tests.rs:1634`). Test-only `unsafe` is also in the custom allocators of `mpl/tests/test_keyring_memory.rs` and `esdk/tests/test_body_allocation.rs` (scope).
- Materials checks (Dafny `Materials.dfy` port, `structures/materials_checks.rs`) run only through `SharedKeyring`/`SharedCmm` `send()`. Built-ins implement their traits only through the crate-private `Builtin<T>` (`mpl/src/shared.rs:110`), so every MPL and ESDK path is checked. A caller that invokes its own `Keyring`/`Cmm` trait impl directly bypasses the checks by its own choice. `SharedKeyring::send()` validates the input materials only after the keyring has run, because the transition check calls `check_*_materials(old)` (`materials_checks.rs:76`, `:121`); a rejected input has therefore already caused any KMS/DDB calls.
- Code paths depend on the Cargo feature set (`kms`, `ddb`, `default-aws-sdk-clients`, `rt-tokio`, `test-utils`, `aws-lc-sys`, `fips`). Without `rt-tokio` there is no storm-tracking or default cache, and no grace-vs-TTL check. `fips` switches the crypto backend. The ESDK depends on the MPL with `default-features = false`. Verification claims must name the feature set they cover.
- Branch-key version handling: 16 bytes on the wire at ciphertext offset 28, converted to the canonical hyphenated UUID for the key-store lookup (`hierarchical_keyring.rs:894`) and re-validated when the AAD is built (`branch_key_wrap.rs:92`). The two representations must round-trip. The unwrap parses the wire version and discards it (`_version`, `branch_key_wrap.rs:254`); the AAD uses the materials' version.
- Remaining non-test panics: `default_cmm.rs:123`, `:137-138` (BUG-05a); `user_agent.rs:17` (static metadata); the fixed-size `try_into().expect` calls (cannot fire after the length checks); `cache_entry_identifier.rs:64`; the storm-tracking introspection accessors (`storm_tracking.rs:199`, `:213`, `:227`); and the unchecked `SystemTime + Duration` additions (BUG-01).
- The test servers listen on `127.0.0.1` only and are not published (TM-MPL-026).

### 9a. Fail-open versus fail-closed review (second pass)

Fail-closed behaviors that carry security weight: policy checks reject (`default_cmm.rs:97`, `:184`); an EDK whose provider id or bkid does not match is skipped (`hierarchical_keyring.rs:752-763`) and an empty result is `NoMatchingDataKey`; a wrong-kind cache entry is an error (`:1000`); lock poison maps to `Internal` (`storm_tracking.rs:248`; `cmc/local.rs:119-121`); an in-flight TTL breach is `Throttling` (`storm_tracking.rs:322-323`); unwrap and the length checks return errors (`branch_key_wrap.rs:236`; `record.rs:164`); a malformed key or signature in `ecdsa_verify` is `Ok(false)`, i.e. rejection (`prim/src/ecdsa.rs:282-293`); an alias ARN, including a byte-identical one, never matches (`mrk_match.rs:25-28`).

Fail-open or unchecked behaviors:

| # | Behavior | Evidence | Effect | Threat |
|---|---|---|---|---|
| F1 | A cache whose `Cmc::grace_period()` returns the default `None` skips the grace-vs-TTL check | `cmc/mod.rs:88-90`; `hierarchical_keyring.rs:584-585` | Misconfiguration accepted silently | 010, 018 |
| F2 | `SharedKeyStore` results are not compared with the request; `SharedBranchKeyIdSupplier` output is not checked | `client_impl.rs:305-308`, `:373-376`; `hierarchical_keyring.rs:260-263` | Wrong or empty ids flow into the cache id and the EDK | 003, 005, 009 |
| F3 | `SharedCmc` returns any entry for any id; only the kind is checked | `hierarchical_keyring.rs:1000` | Cross-keyring materials after a collision | 009, 010 |
| F4 | A cache entry with a future creation time counts as fresh | `hierarchical_keyring.rs:991-994` | Entry outlives its TTL by the clock step | 010 |
| F5 | In the storm tracker, a mark or elapsed time that lies in the future is treated as elapsed zero or kept (`unwrap_or(Duration::ZERO)`, `map_or(true, ..)`) | `storm_tracking.rs:320`, `:253-254` | After a backwards clock step, marks persist | 018 |
| F6 | `SharedCmm::send()` does not re-check policy, requested suite, RECK superset or PDK/EDK correspondence | `cmm/fluent_builders.rs:171`, `:319` | A user CMM has no backstop inside the MPL | 006 |
| F7 | Materials builders do not require a signing or verification key for a signing suite; only `send()` checks | `materials_checks.rs:18`, `:37` | Builder-only callers can hold incomplete materials | 006 |
| F8 | `SharedKeyring::send()` validates its input after running the keyring | `keyring/fluent_builders.rs:81-84`; `materials_checks.rs:76` | Side effects precede the rejection | 006 |
| F9 | `from_bytes` accepts empty EC keys | `mpl/tests/test_encryption_context.rs:468` | Permissive decoding | 013 |
| F10 | `DefaultCmm` ignores `max_plaintext_length` | `cmm/types.rs:23`, `:66` | Spec-defined limit unused | 006 |
| F11 | The key store reads with `GetItem` and no consistent-read flag; the keyring keeps no record of the highest version it has seen | `branch_key_store.rs:155-163` | Stale or replayed ACTIVE record accepted | 005 |
| F12 | Discovery modes use the record's own `kms-arn`, on encrypt too | `kms_ops.rs:96-103`; `branch_key_store.rs:792`, `:801` | Trust moves to IAM | 002 |

### 9b. DoS amplification paths (second pass)

| # | Path | Attacker input | Cost to attacker | Cost to service | Bound today |
|---|---|---|---|---|---|
| D1 | Per-EDK key-store read on decrypt | EDK count × distinct versions | One EDK per read (44 bytes of ciphertext is enough, BUG-05b) | One DDB `GetItem` per EDK, sequential | ESDK `max_encrypted_data_keys`, default `None` (TM-025) |
| D2 | In-flight slot exhaustion | 20 distinct unknown versions | 20 EDKs | Cache-miss refreshes wait for up to 10 s, repeatedly | Fan-out 20, in-flight TTL 10 s (TM-025, 018) |
| D3 | Duplicate-version waits | Same unknown version repeated | N EDKs | About N seconds of one request | None (TM-025) |
| D4 | Foreign tenant ids via supplier | EC and EDK provider info | One EDK | DDB read plus KMS Decrypt per valid foreign version, once per TTL | Supplier trust (TM-003) |
| D5 | Stale in-flight mark | A key-store error or a cancelled caller | n/a (not attacker-driven) | Same-key `Throttling` after 10 s until another key prunes it | None (TM-018) |
| D6 | Panic under the state lock | Unbounded configured duration | n/a (configuration) | Permanent `Internal` for that cache (BUG-01) | None (TM-018) |
| D7 | Raw-AES decrypt buffer per EDK | EDK ciphertext up to 65,535 bytes | Bytes per EDK | One allocation per EDK, freed each iteration | #186 memory test (TM-023) |

### 9c. Cross-component confused-deputy cases (second pass)

1. **Shared cache across keyrings** (BUG-06, and the same-logical-name misconfiguration): keyring B acts with keyring A's branch key (TM-009, TM-010).
2. **Supplier driven by an unauthenticated EC:** the service's role fetches whichever tenant's branch key the message names (TM-003, TM-025).
3. **Discovery trust of a table record:** the application's `kms:Decrypt` permission is applied to a key the table writer chose, on encrypt as well as decrypt (TM-002).
4. **User `KeyStore` and `Cmc` results:** accepted without comparison with the request (F2, F3; TM-005). The AAD binds the materials' bkid and version on decrypt, but the EDK's provider info is the *resolved* bkid (`hierarchical_keyring.rs:722`), so a key store that returns another id's materials produces undecryptable EDKs rather than mis-attributed ones.
5. **A future caching CMM sharing a `SharedCmc` with a hierarchical keyring:** the cache id spaces are disjoint only by construction. `CachedMaterials` kinds already exist (`cmc/entry.rs:26-32`) and the kind check at `hierarchical_keyring.rs:1000` is the only guard (TM-008).
6. **Test servers:** ambient credentials driven by any local process (TM-026).
7. **C++ handles:** a handle or adopted pointer is trusted as the type it claims to be (TM-024).
8. **ESDK re-check:** the ESDK re-validates the CMM's output against the commitment policy (`esdk/src/materials.rs:130`, `:202`), which is the backstop for F6.

## 10. Residual Risks

| ID | Residual risk | Rating | Change |
|----|---------------|--------|--------|
| TM-MPL-009/010 | Cache id not injective when a field contains NUL (BUG-06); same-logical-name misconfiguration. A shared cache can cross partition boundaries | High | = |
| TM-MPL-005 | Record substitution resistance rests on exact auth-EC reconstruction. User key stores are unchecked. An older authentic ACTIVE record can be replayed (no freshness) | High | = (rollback residual added) |
| TM-MPL-025 | Sender-controlled EDK count and versions drive key-store reads, in-flight slots and wall-clock time; no negative cache, no default cap (provisional) | Medium | **new** |
| TM-MPL-011/012 | GCM IV/salt uniqueness rests on CSPRNG randomness, not counters; no wrap counter against the 2^32 bound | Medium | = |
| TM-MPL-004/007 | Ad-hoc ARN/alias/MRK string parsing not verified. MRDiscovery rewrites non-MRK regions (BUG-04, fails closed) | Medium | = |
| TM-MPL-006/008 | Commitment enforcement depends on unproven per-suite allow tables. A user CMM has no policy backstop inside the MPL | Medium | = |
| TM-MPL-018 | Storm-tracking config not validated per spec. Stale-mark wedge and no-deadline waiter (static reasoning). Large durations panic under the lock and poison it (BUG-01) | Medium | = (extended) |
| TM-MPL-002 | Discovery-mode encrypt and decrypt trust the record's `kms-arn` | Medium | = (sharpened) |
| TM-MPL-019 | No Duvet traceability of MPL spec MUSTs. The spec revision floats on `master` | Medium | = |
| TM-MPL-024 | Shim `unsafe` handle derefs and type-erased `adopt`: UB on a dangling, forged or double-adopted C++ handle | Medium | = (scope extended) |
| TM-MPL-015 | Transient/error-path copies of secrets; expired cache entries resident until read; `SignatureKeyPair` error path | Low | = |
| TM-MPL-023 | Config-driven panics (BUG-01, BUG-05a). Short-EDK key-store call (BUG-05b) | Low | = |
| TM-MPL-026 | Loopback test servers use ambient AWS credentials for any local process | Low | **new** |
| TM-MPL-003/021/022 | Message-driven supplier input; attacker-supplied provider info in errors; unknown versions cannot evict cache entries | Low | = |

## 11. Recommendations

Configuration hardening:
- Prefer single-key `KmsKeyArn`/`KmsMrKeyArn` over Discovery and MRDiscovery; if Discovery is required, scope `kms:Decrypt` in IAM to the intended keys (TM-MPL-002/007).
- Default to REQUIRE_ENCRYPT_REQUIRE_DECRYPT with commit-key suites (TM-MPL-006/008).
- When sharing a cache, derive partition ids and logical names only from validated, NUL-free values; keep the default random partition id unless sharing is intended; never reuse a logical key store name across physical key stores (TM-MPL-009/010).
- Set the ESDK `max_encrypted_data_keys` to a small number for any service that decrypts ciphertext from third parties, and set request timeouts (TM-MPL-025).
- Keep storm-tracking settings within the spec's ordering (Grace Interval ≤ Inflight TTL ≤ Grace Period, each ≥ 1 s), and keep TTL ≫ grace period (TM-MPL-018).
- Use bounded durations (TM-MPL-018/023).
- Do not return MPL errors verbatim to the sender of a ciphertext, and escape provider info when logging (TM-MPL-003/021).
- Run the test servers only on development hosts without production credentials (TM-MPL-026).

Implementation improvements:
- Reject `0x00` in partition id, logical key store name and branch-key id at keyring build/resolve time, or raise a spec change to length-prefix the cache-id fields; add a NUL regression test (TM-MPL-009/010, BUG-06).
- Bound the per-message key-store work on decrypt: count distinct versions per call, cache negative results briefly, and give the whole decrypt a deadline (TM-MPL-025). Add the two reproducers described there.
- Clear the in-flight mark when a refresh fails (or have the keyring report a failed refresh), and give a fan-out-saturated waiter its own deadline (TM-MPL-018, findings 1 and 2).
- Use `checked_add` for every `SystemTime + Duration`, bound durations in `build()`, and compute deadlines before taking the state lock so that no panic can poison it (BUG-01, TM-MPL-018).
- Restore the spec's storm-tracking constraints in `StormTrackingCmcBuilder::build` (TM-MPL-018).
- Let a cache that refreshes early be required to report its grace period, or warn when it returns `None` (TM-MPL-010).
- Rewrite the region only for `mrk-` ARNs in MRDiscovery (BUG-04, TM-MPL-007).
- Return an error instead of `.expect` on ECDSA keygen (BUG-05a).
- Truncate the output buffer on `aes_encrypt` `Err`, align the `aes_decrypt` guard with its callee, and fix its error text (BUG-07).
- Wipe the transient decrypt buffers listed in TM-MPL-015; wrap the private key `Vec` in `ecdsa_generate_keypair` in `Zeroizing`; consider an active sweep of expired `LocalCmc` entries (TM-MPL-015).
- Add `mpl/.duvet/config.toml`, annotate the MPL MUSTs, and pin the spec revision (TM-MPL-019).
- Any future caching CMM must bind the commitment policy (or the suite) into its cache id (TM-MPL-008/010, CVE-2026-6550 class).
- Shim: keep handles typed; give `Keyring::adopt` a null check and a type tag, or a generation-checked handle table instead of raw pointers; document that raw-bridge callers must not free a handle while a call is running (TM-MPL-024).

Operational practices:
- Rotate branch keys roughly yearly (TM-MPL-012), and alert if the ACTIVE record's version goes backwards (TM-MPL-005). Restrict DynamoDB write access to the key-store table (TM-MPL-005).
- Rotate a raw-AES wrapping key before roughly 2^32 wraps (TM-MPL-011).
- Scope KMS grants tightly (TM-MPL-002).
- Enable CloudTrail on the KMS keys and the DDB table, and use the MPL user agent to attribute calls (TM-MPL-020).
- Never configure two physical key stores with the same logical name (spec, `#logical-key-store-name`).
- Monitor DynamoDB read throttling on the key-store table as a signal for TM-MPL-025.

## 12. References

- spec/framework (local copy; MPL-relevant sections identical to remote `master` as of the setup step, `94c2bfe`, per scope): algorithm-suites.md, commitment-policy.md, branch-key-store.md (#discovery, #mrdiscovery, KeyId rule, #logical-keystore-name), cmm-interface.md, default-cmm.md, structures.md, keyring-interface.md, raw-aes-keyring.md, aws-kms/aws-kms-hierarchical-keyring.md (cache-id formulas, #partition-id, #logical-key-store-name, Appendix B), aws-kms/aws-kms-mrk-match-for-decrypt.md, cryptographic-materials-cache.md, local-cryptographic-materials-cache.md, storm-tracking-cryptographic-materials-cache.md (FanOut, Inflight TTL, Consistency). Shim: spec/shim/shim.md#handles-and-lifetimes, #adopting-custom-implementations.
- Code: `mpl/src/{keyring/{raw_aes_keyring,fluent_builders}.rs, aws_kms/{hierarchical_keyring,branch_key_wrap,mrk_match,cache_entry_identifier,user_agent}.rs, key_store/{branch_key_store,kms_ops,kms_config,record,encryption_context,client_impl}.rs, cmm/{default_cmm,fluent_builders}.rs, cmc/{local,storm_tracking,default,entry,mod}.rs, structures/{algorithm_suite,materials_checks,commitment_policy,encryption_context,branch_key_materials,beacon_key_materials,encrypted_data_key}.rs, error/generated.rs, shared.rs}`, `prim/src/{lib,ecdsa,error}.rs`, `esdk/src/{materials,decrypt,config}.rs`, `esdk/shims/aws-esdk-cpp/{src/lib.rs,src/EncryptionSDK.cpp,include/aws/esdk/EncryptionSDK.h,build.rs,CMakeLists.txt,Makefile}`, `mpl/test-server/src/{main,handlers}.rs`.
- Pipeline inputs: `docs/spec-security-analysis.md`; `docs/bug-reports/RECHECK-main-620771c.md`; `docs/bug-reports/README.md`; `docs/bug-reports/BUG-01..BUG-09`; `.agents/tasks/pipeline-pass2/{scope.md,stage1-notes.md,stage2-notes.md}`; `.agents/tasks/pipeline-rerun-620771c/{scope.md,stage2-notes.md}`.
- CVE-2026-6550 / GHSA-v638-38fc-rhfv (verified; ESDK for Python caching CMM; not applicable to this code): [GitHub Advisory Database](https://github.com/advisories/GHSA-v638-38fc-rhfv), [aws-encryption-sdk-python advisory](https://github.com/aws/aws-encryption-sdk-python/security/advisories/GHSA-v638-38fc-rhfv), [NVD](https://nvd.nist.gov/vuln/detail/CVE-2026-6550), [AWS Security Bulletin 2026-017-aws](https://aws.amazon.com/security/security-bulletins/2026-017-aws/). Summary: in the ESDK for Python, a shared caching CMM could serve non-committing materials across differing commitment policies. Content was rephrased for compliance with licensing restrictions.
- Invisible Salamanders / encryptment: Dodis, Grubbs, Ristenpart, Woodage, IACR ePrint 2019/016 (https://eprint.iacr.org/2019/016). Content was rephrased for compliance with licensing restrictions.
- AWS KMS key-derivation construction: Gueron, RWC 2018.
- NIST SP 800-108 (KBKDF), SP 800-38D (GCM, including the 2^32 limit for random IVs), RFC 5869 (HKDF).

## Appendix: Threat Risk Matrix

Rating rule (unchanged from the previous version):

| Severity \ Likelihood | Low | Medium | High |
|---|---|---|---|
| Critical | Medium | High | High |
| High | Medium | High | High |
| Medium | Low | Medium | High |
| Low | Low | Low | Medium |

| ID | STRIDE | Severity | Likelihood | Risk (a1e23d7) | Risk (620771c) | Risk (851977d) | Note |
|----|--------|----------|-----------|----------------|----------------|----------------|------|
| TM-MPL-001 | S | Medium | Low | Low | Low | Low | re-confirmed |
| TM-MPL-002 | S | Critical | Low | Medium | Medium | Medium | sharpened: Discovery on encrypt path |
| TM-MPL-003 | S | Medium | Low | Low | Low | Low | message-driven supplier input noted |
| TM-MPL-004 | T | High | Low | Medium | Medium | Medium | re-confirmed |
| TM-MPL-005 | T | Critical | Medium | High | High | High | rollback residual added |
| TM-MPL-006 | E | Critical | Low | Medium | Medium | Medium | SharedCmm backstop residual |
| TM-MPL-007 | E | High | Low | Medium | Medium | Medium | BUG-04 open, fails closed |
| TM-MPL-008 | E | High | Low | Medium | Medium | Medium | CVE verified, not applicable |
| TM-MPL-009 | E | High | Medium | Medium | **High** | **High** | BUG-06 open; re-derived |
| TM-MPL-010 | I/E | High | Medium | Medium | **High** | **High** | BUG-06; same-name and future-time residuals |
| TM-MPL-011 | E | Critical | Low | Medium | Medium | Medium | 2^32 usage bound noted |
| TM-MPL-012 | E | Critical | Low | Medium | Medium | Medium | re-confirmed |
| TM-MPL-013 | T | High | Low | Medium | Medium | Medium | BUG-03 fixed |
| TM-MPL-014 | E | High | Low | Medium | Medium | Medium | spec silent on fixed info |
| TM-MPL-015 | I | Medium | Low | Medium | **Low** | Low | cache residency, keypair error path |
| TM-MPL-016 | T | Medium | Low | Low | Low | Low | re-confirmed |
| TM-MPL-017 | T | High | Low | Medium | Medium | Medium | re-confirmed |
| TM-MPL-018 | D | Medium | Medium | Medium | Medium | Medium | liveness gaps; BUG-01 poisons the lock |
| TM-MPL-019 | E | Medium | Medium | Medium | Medium | Medium | re-confirmed |
| TM-MPL-020 | R | Low | Low | Low | Low | Low | re-confirmed |
| TM-MPL-021 | I | Medium | Low | Low | Low | Low | provider info in errors |
| TM-MPL-022 | D | Low | Medium | Low | Low | Low | invalid versions cannot evict |
| TM-MPL-023 | D | Medium | Low | Low | Low | Low | re-confirmed |
| TM-MPL-024 | E/T | High | Low | n/a | Medium | Medium | `adopt` added; #188/#189 no change |
| TM-MPL-025 | D | Medium | Medium | n/a | n/a | **Medium** | new, provisional (static reasoning) |
| TM-MPL-026 | E/I | Medium | Low | n/a | n/a | **Low** | new, test-only |

Retired: none.

## Impact on verification targets

Basis changes since the last Stage 3 run (`docs/verification-targets.md`, T01..T26 and C01..C08), so that the orchestrator can decide whether to refresh Stage 3. No existing threat rating changed, so no target's score input changed through a rating; the items below are changes of evidence, scope or citation.

| Target | Basis changed | Refresh? |
|---|---|---|
| **T25** (C++ shim handles, TM-MPL-024) | Its citations `lib.rs:1564-1565`, `:1655` are stale (now `:1570-1571`, `:1661`). Its scope must now include the type-erased `Keyring::adopt` path (`lib.rs:2059-2066`, `EncryptionSDK.cpp:541-547`), which is outside a Rust-side null-dominance proof | **Yes** (citations and scope) |
| **T21** (storm tracking, TM-MPL-018) | Liveness properties added: stale in-flight mark never cleared on error, no-deadline waiter, panic under the state lock poisons it (BUG-01 b/c) | **Yes** (new properties; may need a concurrency reproducer) |
| **T06** (`SystemTime + Duration`, BUG-01) | For `storm_tracking.rs:333`, `:680` the consequence is persistent `Internal` after poison, not one panic. The property "no overflow panic" is unchanged | Optional (note only) |
| **T14** (`cache_entry_within_limits` etc., TM-MPL-010) | The exact-TTL property must say what happens for a creation time in the future (`hierarchical_keyring.rs:991-994`). It currently counts as fresh | Optional (property wording) |
| **T13** (`build_cache_identifier`, TM-MPL-009/010) | Property unchanged. Vectors clarified: partition id, logical name and bkid carry NUL; the version cannot. A second, NUL-free collision exists by misconfiguration (same logical name) | No |
| **T19** (hierarchical bkid binding, TM-MPL-003) | The supplier input on decrypt is the unauthenticated message EC; the filter only checks equality with the supplier's result | Optional (scope note) |
| **T22** (`Debug` + `DataKeyInfo`, TM-MPL-021) | `NoMatchingDataKey` exposes provider info through `Debug` and `encrypted_data_keys()`; ciphertext stays excluded. `Debug` citations moved to the `impl` lines | Optional |
| **T26** (transient secret buffers, TM-MPL-015) | Two residuals added: expired `LocalCmc` entries stay resident until read, and `ecdsa_generate_keypair` leaves the private key `Vec` un-wiped on its error path (`ecdsa.rs:387`, `:391-392`) | **Yes** (add the two sites) |
| **T01 / T02 / T03** (TM-MPL-005, TM-MPL-002) | Properties unchanged. The new rollback residual is not provable from the code and is outside T01/T02. T03's pinned-mode scope stays correct; Discovery on the encrypt path is covered by T17's area but T17 is not about confidentiality of the branch key | No (optionally record rollback as a non-goal) |
| **T05** (KBKDF fixed info, TM-MPL-014) | Basis clarified: the spec does not give the layout, so the property is stated against the code | No |
| **T09** (commitment policy, TM-MPL-006) | Scope note: `SharedCmm::send()` does not check policy; the proof covers `DefaultCmm` gates plus the ESDK re-check | No |
| **T16** (malformed-input panics, TM-MPL-023) | Unchanged | No |
| T04, T07, T10, T11, T12, T15, T17, T18, T20, T23, T24, C01..C08 | Unchanged | No |
| **No target yet** | TM-MPL-025 (bounded work per decrypt; recommend a new target and two reproducers) and TM-MPL-026 (test-only; no target needed) | Add a candidate for TM-MPL-025 |

### Resolution (HEAD `9955ecd`)

The table above is kept as written (history). The refresh of `docs/verification-targets.md` and `docs/verification-targets/01-threat-driven.md` applied it as follows. "Rank" is the rank in the combined list in `docs/verification-targets.md` section 1. No threat rating changed.

| Target | Applied | Resulting ID and score | Where |
|---|---|---|---|
| T25 | Yes | T25, 1.44 (unchanged, rank 30). Citations moved; `Keyring::adopt` added to the scope | `verification-targets.md:15`; `01-threat-driven.md:18` |
| T21 | Yes | T21, 1.96 → 2.24 (rank 23). Coverage gap 0.7 → 0.8; properties (g), (h), (i) added | `verification-targets.md:14`; `01-threat-driven.md:17` |
| T06 | Yes (note) | T06, 4.20 (unchanged, rank 11) | `verification-targets.md:18`; `01-threat-driven.md:21` |
| T14 | Yes (property wording) | T14, 3.78 (unchanged, rank 13) | `verification-targets.md:18`; `01-threat-driven.md:22` |
| T13 | No change needed | T13, 4.41 (rank 9) | `verification-targets.md:74` |
| T19 | Yes (scope note) | T19, 1.92 (unchanged, rank 27) | `verification-targets.md:18`; `01-threat-driven.md:23` |
| T22 | Yes | T22, 1.60 (unchanged, rank 29) | `verification-targets.md:18`; `01-threat-driven.md:24` |
| T26 | Yes | T26, 3.20 (unchanged, rank 15). Sites F4 and F5 added | `verification-targets.md:16`; `01-threat-driven.md:19` |
| T01, T02, T03 | Note only (rollback is a non-goal) | T01 8.96, T02 6.72, T03 5.12, all unchanged | `verification-targets.md:17`, `:18`; `01-threat-driven.md:20`, `:26` |
| T05, T09, T16, others | T09: scope note. The rest: no change | T09 2.56; T05 4.32; T16 2.24 | `verification-targets.md:18`; `01-threat-driven.md:25` |
| TM-MPL-025 (no target yet) | Yes: new target | **T27**, 3.78 (rank 14; rank 10 among the threat-driven targets). Provisional, because TM-MPL-025 is unconfirmed | `verification-targets.md:13`, `:79`; `01-threat-driven.md:16`, `:96` |
| TM-MPL-026 (no target needed) | Yes: recorded as fully excluded | No target. Row in the out-of-scope tables | `verification-targets.md:506`; `01-threat-driven.md:1491` |

Result: 33 active targets (was 32), 26 threat-driven and 7 capability-driven; T08 and C06 stay retired. The targets documents now count TM-MPL-001..026.

The completeness audit (`docs/completeness-audit.md`) found no missed threat. It found one small spec-clause gap (G1, applied to T02), one editorial error (G2) and one editorial staleness (G4-1); none changes a rating or adds a threat.

Note: the bug report for BUG-06 (`docs/bug-reports/`) now rates BUG-06 High. It was raised from Low on the owner's decision after the main re-check, so it is consistent with TM-MPL-009 and TM-MPL-010 (High) here. No threat rating changed because of this.
