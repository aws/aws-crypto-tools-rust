# Threat Model: AWS Cryptographic Material Providers Library (MPL)

> Pipeline artifact — Stage 2 (Threat Modeling). Produced by the `threat-model-generator` agent against the `esdk-native-mpl` working tree.
>
> **Status:** Draft for verification prioritization.
> **Scope:** `mpl/` (key management) built on `prim/` (safe aws-lc-rs wrappers). Message-format concerns (ESDK) are OUT OF SCOPE.
> **Methodology:** STRIDE with likelihood × impact risk rating. Each threat has a stable ID `TM-MPL-NNN` referenced by the verification-recommender.
>
> **Note on Duvet:** there are no inline `//= spec` / `//#` annotations in this branch's `mpl/src` or `mpl/tests` (they live on `duvet/mpl-annotations`). Mitigations below cite code locations + spec sections directly; the missing on-branch Duvet coverage is itself tracked as TM-MPL-019.
>
> **Note on cited advisories:** the shared-cache commitment-bypass class is real and documented (Invisible Salamanders; AWS S3EC key-commitment advisory). One referenced identifier (`CVE-2026-6550` / `GHSA-v638-38fc-rhfv`) was supplied by the generating agent and has **not been independently verified** in this session — treat the *class* of attack as authoritative and the specific identifier as unconfirmed pending a lookup.

## 1. Executive Summary

The MPL produces and manages data keys, branch keys, and key wrapping for the AWS Encryption SDK and related clients. Its security rests on: (a) AES-GCM wrapping in the raw-AES keyring and hierarchical keyring, (b) KBKDF/HKDF branch-key derivation, (c) AWS KMS as the root of trust for branch/beacon keys, (d) DynamoDB as tamper-evident (KMS-authenticated) branch-key storage, (e) an in-process cache to reduce KMS calls, and (f) commitment-policy + algorithm-suite selection enforced by the CMM.

The dominant threats are: branch-key-store record tampering/substitution (mitigated by KMS-authenticated encryption context binding), KMS key-id/ARN confusion and MRK matching on decrypt, algorithm-suite downgrade / commitment-policy bypass (Invisible Salamanders class), cache poisoning/confusion and storm-tracking correctness, KBKDF/HKDF fixed-info misuse, AES-GCM nonce reuse in the raw-AES keyring, and secret-material exposure due to absent zeroization.

Highest-priority residual risks for formal verification: (1) AES-GCM IV uniqueness in the raw-AES keyring and hierarchical keyring wrap (TM-MPL-011, TM-MPL-012); (2) branch-key AAD/fixed-info construction correctness (TM-MPL-013, TM-MPL-014); (3) cache-identifier collision resistance and cross-keyring confusion (TM-MPL-009, TM-MPL-010); (4) MRK/ARN match logic (TM-MPL-004, TM-MPL-007); (5) commitment-policy enforcement on both encrypt and decrypt (TM-MPL-006); (6) storm-tracking cache correctness (TM-MPL-018); (7) secret zeroization (TM-MPL-015).

## 2. System Overview

```
                         Caller (ESDK / DB-ESDK / S3EC)
                                    |
                         get_encryption_materials / decrypt_materials
                                    v
                          +---------------------+
                          |   DefaultCmm        |  commitment-policy + suite
                          | (cmm/default_cmm)   |  resolution, ECDSA keygen,
                          +---------------------+  reproduced-EC merge
                                    |
                             on_encrypt / on_decrypt
                                    v
              +-----------------------------------------------+
              |                 Keyring                       |
              |  RawAesKeyring          HierarchicalKeyring   |
              +-----------------------------------------------+
                 |                        |            |
        AES-GCM (prim)          Cmc cache        Keystore (BranchKeyStore)
        local wrapping key      (Local/Storm)         |         |
                                    |            AWS KMS    Amazon DynamoDB
                                (in-process)   (wrap/unwrap) (branch-key records)
                                    |
                          branch_key_wrap (KBKDF + AES-GCM)
                                    |
                              prim (aws-lc-rs)
                          AES-GCM / KBKDF / HKDF / ECDSA / digest / RNG
                                    |
                              aws-lc-rs FFI (unsafe edge, reached only via safe prim)
```

Trust: the process, the local AES wrapping key, and the in-process cache are trusted; AWS KMS is the trusted root of trust for branch/beacon keys; DynamoDB is untrusted-for-integrity storage made tamper-evident by KMS EC binding; `aws-lc-rs` is reached only through the safe `prim` wrappers.

## 3. Assets

| ID | Asset | Type | Notes |
|----|-------|------|-------|
| A1 | Plaintext data keys (`PlaintextDataKey`) | Confidentiality | The keys the whole library protects. In memory during wrap/unwrap. |
| A2 | Branch keys (`BranchKeyMaterials.branch_key`, `[u8;32]`) | Confidentiality | Root of the derived-key hierarchy; cached in-process. |
| A3 | Derived branch keys (`derivedBranchKey`, 32B) | Confidentiality | Transient AES-256-GCM cipher key per wrap/unwrap. |
| A4 | Raw-AES wrapping key (`RawAesKeyring.wrapping_key`) | Confidentiality | Long-lived local secret. |
| A5 | ECDSA signing key (`SigningKey`) | Confidentiality/Integrity | Generated per encryption for signing suites. |
| A6 | Beacon keys | Confidentiality | Searchable-encryption root key. |
| A7 | Branch-key-store DDB records (`enc`, `kms-arn`, EC attrs) | Integrity | Tamper-evidence via KMS EC binding. |
| A8 | Encryption context / AAD | Integrity | Binds ciphertext to context; must survive round-trip. |
| A9 | Algorithm suite id + commitment policy | Integrity | Determines whether key commitment is required. |
| A10 | Cache entries (branch-key materials + TTL) | Conf./Integrity/Avail. | In-process; keyed by SHA-384 identifier. |
| A11 | KMS grant tokens / key ARNs (config) | Integrity | Determine which KMS key authorizes operations. |
| A12 | CSPRNG output (IVs, salts, data keys) | Integrity | From `prim::generate_random_bytes` (aws-lc-rs `rand::fill`). |

## 4. Actors

Legitimate: application caller; KMS (root of trust); DynamoDB (storage); operators configuring keystore/keyring.

Threat actors:
- TA1 — DynamoDB tamperer: read/write access to the branch-key table but NOT to KMS keys.
- TA2 — Malicious/confused caller: controls encryption context, reproduced EC, algorithm-suite id, branch-key supplier, and can submit crafted EDKs on decrypt.
- TA3 — Co-tenant sharing a `Shared` cache (partition-id/logical-name collision).
- TA4 — In-process memory adversary: reads freed heap / core dumps / swap (post-exploitation, cold-boot).
- TA5 — Network attacker between MPL and KMS/DDB (assumed TLS; residual is downgrade/DoS).
- TA6 — Supply-chain adversary targeting `aws-lc-rs`/`uuid`/`lru`/SDK deps.

## 5. Trust Boundaries

| ID | Boundary | Crossing | Controls |
|----|----------|----------|----------|
| TB1 | Caller ↔ MPL API | Materials requests, EC, EDKs, suite id | CMM validation, reserved-key checks, commitment policy |
| TB2 | MPL ↔ AWS KMS | GenerateDataKeyWithoutPlaintext / ReEncrypt / Decrypt | KMS auth, EC-as-AAD, key-ARN restriction, grant tokens |
| TB3 | MPL ↔ DynamoDB | GetItem / TransactWriteItems | KMS EC binding makes records tamper-evident; conditional writes |
| TB4 | Keyring ↔ in-process cache | put/get cache entry | SHA-384 cache identifier, TTL, materials-kind check |
| TB5 | `mpl`/`prim` ↔ `aws-lc-rs` FFI | AES-GCM/KDF/ECDSA/RNG calls | Safe `prim` wrappers, length checks, `Nonce::try_assume_unique_for_key` |
| TB6 | Process memory ↔ OS | Freed heap, swap, core dump | Debug redaction only; NO zeroization |

## 6. Data Flow Diagrams

Encrypt (hierarchical):
```
caller EC ──> DefaultCmm.get_encryption_materials
                  │ resolve suite (commitment policy), maybe ECDSA keygen
                  v
            Keyring.on_encrypt
                  │ resolve branch_key_id
                  │ cache_id = SHA384(0x02|0x01|partition|logicalName|bkid)
             cache hit? ── yes ──> branch_key_wrap::wrap
                  │ no                       ^
                  v                          │
          Keystore.get_active_branch_key     │ KBKDF(salt) -> derivedKey
                  │ KMS Decrypt(enc, EC-AAD) │ AES-256-GCM(iv, aad=label|bkid|ver|EC)
                  v                          │
             put cache (TTL) ────────────────┘
                  v
     EDK{ kpid="aws-kms-hierarchy", kpinfo=bkid, ct=salt|iv|ver|enc|tag }
```

Decrypt (hierarchical):
```
EDK + reproduced EC ──> DefaultCmm.decrypt_materials
      │ allows_for_decrypt(suite)? ; merge reproduced EC
      v
 Keyring.on_decrypt (filter kpid + bkid)
      │ parse version bytes from ct[28..44]
      │ cache_id = SHA384(0x02|0x02|partition|logicalName|bkid|version)
   cache/keystore fallthrough -> BranchKeyMaterials
      │ branch_key_wrap::unwrap: KBKDF(salt) -> AES-256-GCM open(iv, aad)
      v
   PlaintextDataKey
```

## 7. Threat Identification (STRIDE)

### Spoofing
| ID | Threat | Component |
|----|--------|-----------|
| TM-MPL-001 | Raw-AES keyring emits EDK whose key-provider-id impersonates an AWS KMS keyring | RawAesKeyring::new |
| TM-MPL-002 | Forged branch-key-store record decrypts under an attacker-influenced KMS key (key-id confusion) | kms_ops::decrypt_branch_key |
| TM-MPL-003 | Malicious branch-key supplier returns an attacker-chosen branch key id | HierarchicalKeyring::resolve_branch_key_id |

### Tampering
| ID | Threat | Component |
|----|--------|-----------|
| TM-MPL-004 | ARN/MRK match logic accepts a non-matching key ARN (over-permissive match) | mrk_match, kms_config::is_arn_compatible |
| TM-MPL-005 | Branch-key record substitution: swap a valid record from another branch-key-id/version | branch_key_store, kms_ops |
| TM-MPL-013 | Branch-key wrap/unwrap AAD constructed inconsistently, breaking context binding | branch_key_wrap::compute_aad |
| TM-MPL-016 | VersionKey optimistic-lock bypass overwrites ACTIVE record (version race) | branch_key_store::version_key |
| TM-MPL-017 | Encryption-context / reproduced-EC merge lets attacker drop or alter bound context | default_cmm::merge_reproduced_encryption_context |

### Repudiation
| ID | Threat | Component |
|----|--------|-----------|
| TM-MPL-020 | No audit binding between an MPL operation and the KMS/DDB calls it triggered | keystore, keyring |

### Information Disclosure
| ID | Threat | Component |
|----|--------|-----------|
| TM-MPL-015 | Secret material (branch keys, data keys, derived keys, wrapping key) not zeroized on drop | structures, branch_key_wrap, raw_aes_keyring |
| TM-MPL-021 | Secret bytes leak via Debug/error/log formatting | structures, error paths |
| TM-MPL-010 | Shared-cache confusion serves branch-key materials to a keyring that should not access them | cache_entry_identifier, hierarchical_keyring |

### Denial of Service
| ID | Threat | Component |
|----|--------|-----------|
| TM-MPL-018 | Storm-tracking cache mis-configuration or logic error causes stampede / deadlock / InFlightTTL failures | cmc/storm_tracking |
| TM-MPL-022 | Cache exhaustion / eviction thrash forces KMS-call storm (throttling) | cmc/local |
| TM-MPL-023 | Malformed EDK/ciphertext triggers panic instead of error | branch_key_wrap::unwrap, hierarchical_keyring |

### Elevation of Privilege
| ID | Threat | Component |
|----|--------|-----------|
| TM-MPL-006 | Algorithm-suite downgrade / commitment-policy bypass: decrypt a non-committing suite under REQUIRE_DECRYPT, or bypass commitment via cache | default_cmm, commitment_policy, cmc |
| TM-MPL-007 | Discovery/MRDiscovery config decrypts a record under an alias or attacker-region MRK | kms_ops::resolve_keystore_arn |
| TM-MPL-009 | Cache-identifier collision returns wrong branch-key materials | cache_entry_identifier |
| TM-MPL-011 | AES-GCM IV reuse in raw-AES keyring (nonce-reuse → key/AAD compromise) | raw_aes_keyring::on_encrypt, prim::aes_encrypt |
| TM-MPL-012 | AES-GCM salt/IV reuse in branch-key wrap (birthday-bound collision) | branch_key_wrap::wrap |
| TM-MPL-014 | KBKDF fixed-info / L-value misuse weakens branch-key derivation | branch_key_wrap::derive_branch_key |
| TM-MPL-008 | Non-committing suite reused where commitment expected (Invisible Salamanders) | commitment_policy, default_cmm |
| TM-MPL-019 | Missing Duvet coverage lets a spec MUST silently regress | whole library |

## 8. Threat Analysis and Mitigations (per threat)

**TM-MPL-001 (S) — Raw-AES key-provider-id impersonation.** Attack: caller sets `key_namespace = "aws-kms"` (or `aws-kms-hierarchy`) so its EDKs look like KMS-keyring EDKs. Mitigation: `RawAesKeyring::new` rejects any namespace equal to or starting with `aws-kms` (prefix check) — `raw_aes_keyring.rs`; raw-aes-keyring.md. Severity Medium, Likelihood Low → Low. Residual: prefix heuristic only.

**TM-MPL-002 (S) — Branch-key record decrypts under attacker-influenced KMS key.** Attack: TA1 writes a record with a `kms-arn` pointing at an attacker-controlled key. Mitigation: for `KmsKeyArn`/`KmsMrKeyArn`, `resolve_keystore_arn` forces `KeyId` = the CONFIGURED ARN, so KMS decrypts under the trusted key — `kms_ops.rs`; branch-key-store.md. Severity Critical, Likelihood Low → Medium. Residual: Discovery modes trust the record ARN.

**TM-MPL-003 (S) — Malicious branch-key supplier.** Supplier is caller-provided trusted code; the chosen id is bound into cache-id and AAD, so a wrong id fails authentication. Severity Medium → Low.

**TM-MPL-004 (T) — Over-permissive ARN/MRK match.** Mitigation: `aws_kms_mrk_match_for_decrypt` returns true only on exact equality or, for MRK ARNs, equality of partition/service/accountId/resourceType/resource with region omitted — `mrk_match.rs`; aws-kms-mrk-match-for-decrypt.md. Aliases rejected. Severity High, Likelihood Low → Medium. Residual: ad-hoc ARN string parsers — strong verification candidate.

**TM-MPL-005 (T) — Branch-key record substitution.** Mitigation: every non-`enc` attribute (branch-key-id, type, version, kms-arn, hierarchy-version, custom EC, `tablename`=logical-name) is placed in the KMS encryption context and authenticated by KMS Decrypt/ReEncrypt as AAD — `kms_ops::build_authenticated_encryption_context`; branch-key-store.md. Severity Critical, Likelihood Medium → High (mitigated). Residual: relies on reconstructed EC exactly matching write-time EC — top verification target.

**TM-MPL-006 (E) — Suite downgrade / commitment-policy bypass.** Attack (Invisible Salamanders class): force decryption of a non-committing suite where commitment is required. Mitigation: `DefaultCmm.get_encryption_materials` rejects a requested suite not `allows_for_encrypt`; `decrypt_materials` rejects one not `allows_for_decrypt` — `default_cmm.rs`; commitment-policy.md. Severity Critical, Likelihood Low → Medium. Residual: correctness of per-suite allow tables — verification candidate.

**TM-MPL-007 (E) — Discovery/MRDiscovery alias or attacker-region MRK.** Mitigation: `resolve_keystore_arn` rejects alias ARNs and, for MRDiscovery, rewrites only the region to the configured region — `kms_ops.rs`; branch-key-store.md. Severity High, Likelihood Low → Medium. Residual: `parse_arn` + region-rewrite string surgery are verification targets.

**TM-MPL-008 (E) — Non-committing suite reuse (Invisible Salamanders).** Grounded in Invisible Salamanders (Dodis et al., IACR 2019/016) and the AWS S3EC key-commitment advisory. Mitigation as TM-MPL-006; commit-key suites are default under REQUIRE policies. Severity High → Medium.

**TM-MPL-009 (E) — Cache-identifier collision.** Mitigation: identifier = SHA-384 over null-separated `resource-id | scope | partition | logicalName | bkid [ | version ]` — `cache_entry_identifier.rs`; hierarchical-keyring.md Appendix A. Severity High, Likelihood Low → Medium. Residual: separator/domain-separation correctness, second-preimage assumption — verification candidate.

**TM-MPL-010 (I/E) — Shared-cache confusion.** Attack: two keyrings with the same partition-id + logical-name + bkid share cache entries; a keyring without direct KMS access reuses materials, or a non-committing entry is reused where commitment is expected. Mitigation: default partition-id is a fresh random v4 UUID (isolation by default); shared-cache scope is opt-in and documented as MUST-match-only-if-intended. Severity High, Likelihood Low → Medium. Residual: no cross-check that a cached suite's commitment matches the current policy. (Related to the shared-cache commitment-bypass advisory class; specific CVE id unverified.)

**TM-MPL-011 (E) — AES-GCM IV reuse in raw-AES keyring.** Mitigation: fresh 12-byte IV from the CSPRNG per `on_encrypt`, passed to `prim::aes_encrypt` (`Nonce::try_assume_unique_for_key`) — `raw_aes_keyring.rs`, `prim/src/lib.rs`. Severity Critical, Likelihood Low → Medium. Residual: uniqueness rests on 96-bit random nonce → birthday-bound reuse. Prime verification target.

**TM-MPL-012 (E) — Salt/IV reuse in branch-key wrap.** Mitigation: fresh 16-byte salt + 12-byte IV per `wrap` (224 bits); Appendix B birthday analysis → 2^96 wraps before 2^-32 collision, motivating yearly rotation — `branch_key_wrap::wrap`. Severity Critical, Likelihood Low → Medium. Verification target alongside TM-MPL-011.

**TM-MPL-013 (T) — Branch-key AAD inconsistency.** Mitigation: `compute_aad` builds `"aws-kms-hierarchy" | bkid | version(16B) | serialized-EC` identically on wrap and unwrap; version parsed strictly as 36-char canonical UUID — `branch_key_wrap.rs`; hierarchical-keyring.md. Severity High → Medium. Residual: EC serialization determinism + version-format strictness are verification targets.

**TM-MPL-014 (E) — KBKDF fixed-info misuse.** Mitigation: fixed-info = `Label("aws-kms-hierarchy") | 0x00 | salt | L_be32(256)` (NIST SP 800-108 §4.1 counter-mode HMAC-SHA-256) via `prim::kbkdf_ctr_hmac`; 32-byte output — `branch_key_wrap::derive_branch_key`. Severity High → Medium. Residual: byte-layout + L value correctness — strong verification candidate.

**TM-MPL-015 (I) — No zeroization of secret material.** Finding: no `zeroize`/`Zeroize`/`Drop` for `BranchKeyMaterials.branch_key`, derived-key locals, `PlaintextDataKey` (has manual `zeroize`, not Drop-driven), or `RawAesKeyring.wrapping_key`. Debug is redacted but freed heap/swap/core dumps retain plaintext (TA4). Severity High, Likelihood Low → Medium. Mitigation: none automatic. Verification candidate: prove no secret buffer outlives its scope without being zeroized; prove the `zeroize` loop is complete + in-bounds.

**TM-MPL-016 (T) — VersionKey optimistic-lock bypass.** Mitigation: conditional `attribute_exists(branch-key-id) AND enc = :encOld` for ACTIVE + `attribute_not_exists` for new DECRYPT_ONLY in one `TransactWriteItems`, with KMS ReEncrypt re-auth of old ACTIVE — `branch_key_store::version_key`. Severity Medium → Low.

**TM-MPL-017 (T) — Reproduced-EC merge tampering.** Mitigation: `merge_reproduced_encryption_context` fails on shared-key value disagreement and appends reproduced-only pairs as Required Encryption Context Keys — `default_cmm.rs`; cmm-interface.md. Severity High → Medium. Residual: sole guard that decryptor AAD equals encryptor AAD — verification target.

**TM-MPL-018 (D) — Storm-tracking correctness.** Mitigation: `ValidatedConfig::from_raw` enforces `grace_interval <= inflight_ttl <= grace_period` and all-≥1 bounds; lock never held across `.await`; put writes inner cache before clearing inflight — `cmc/storm_tracking.rs`; storm-tracking spec. Severity Medium, Likelihood Medium → Medium. Residual: intricate state machine (liveness/safety); Tokio-only (`tokio::time::sleep`). Strong verification target.

**TM-MPL-019 (E) — Missing Duvet coverage.** Finding: no inline annotations in `mpl/src`/`mpl/tests` on this branch, so spec MUSTs are not mechanically traced. Severity Medium → Medium. Recommendation: add Duvet annotations for commitment-policy, MRK-match, AAD, cache-id, keystore-auth requirements.

**TM-MPL-020 (R) — No operation↔KMS/DDB audit binding.** Mitigation: KMS/DDB CloudTrail; `aws-kms-hierarchy` user-agent. Severity Low → Low.

**TM-MPL-021 (I) — Secret leakage via Debug/logging.** Mitigation: `RawAesKeyring`/`BranchKeyMaterials` redact Debug; errors carry messages not key bytes. Severity Medium → Low. Residual: confirm `PlaintextDataKey`/`SigningKey` Debug redaction.

**TM-MPL-022 (D) — Cache exhaustion → KMS storm.** Mitigation: default 1000-entry LRU with TTL-aware pruning; storm-tracking coalesces refreshes. Severity Low → Low.

**TM-MPL-023 (D) — Panic on malformed ciphertext.** Mitigation: `branch_key_wrap::unwrap` length-checks against a fixed overhead before slicing; `try_decrypt_edk` bounds-checks before reading version; `uuid_str_to_16_bytes` returns error not panic. Severity Medium → Low. Residual: `expect`s rely on preceding length checks — verification candidate for panic-freedom.

## 9. Implementation-Specific Considerations

- All randomness (IVs, salts, data keys, default partition-id UUID) flows through `prim::generate_random_bytes` → aws-lc-rs `rand::fill`, centralizing entropy on one audited primitive.
- `prim::aes_encrypt`/`aes_decrypt` use `LessSafeKey` + `Nonce::try_assume_unique_for_key`: GCM nonce-uniqueness is the CALLER's obligation, so IV-generation correctness in the keyrings (TM-MPL-011/012) is load-bearing.
- The `aws-lc-rs` FFI edge is reached only via `prim`; `prim` enforces buffer-length invariants and forbids panics via clippy lints.
- Branch-key version handling: 16 bytes on-wire at ct offset 28; converted to canonical hyphenated UUID for keystore lookup and re-validated on AAD build — two representations that must round-trip.
- No zeroization anywhere (TM-MPL-015) is the single largest code-level gap versus a defense-in-depth ideal.

## 10. Residual Risks

| ID | Residual risk | Rating |
|----|---------------|--------|
| TM-MPL-011/012 | GCM IV/salt uniqueness rests on CSPRNG randomness, not counters | Medium |
| TM-MPL-015 | Secret key bytes remain in freed heap/swap/core dumps | Medium |
| TM-MPL-004/007 | Ad-hoc ARN/alias/MRK string parsing not yet verified | Medium |
| TM-MPL-010 | Shared-cache reuse can bypass commitment expectations | Medium |
| TM-MPL-006/008 | Commitment enforcement depends on per-suite allow-table correctness | Medium |
| TM-MPL-018 | Storm-tracking state machine liveness/safety; Tokio-only | Medium |
| TM-MPL-002 | Discovery-mode decryption trusts the record's `kms-arn` | Medium |
| TM-MPL-019 | No Duvet traceability of spec MUSTs to code/tests | Medium |
| TM-MPL-023 | Panic-freedom rests on length-check-before-slice discipline | Low-Med |

## 11. Recommendations

Configuration hardening: prefer single-key `KmsKeyArn`/`KmsMrKeyArn` over Discovery (TM-MPL-002/007); default to REQUIRE_ENCRYPT_REQUIRE_DECRYPT / commit-key suites (TM-MPL-006/008); set a unique partition-id only when cache sharing is intended (TM-MPL-010); keep storm-tracking TTL ≫ grace period on a Tokio runtime (TM-MPL-018).

Implementation improvements: introduce zeroize-on-drop for secret types (TM-MPL-015); add Duvet annotations (TM-MPL-019); promote ARN parsing to a verified module (TM-MPL-004/007); add a cache-entry check that a served suite's commitment matches the current policy (TM-MPL-010).

Operational practices: rotate branch keys ~yearly (TM-MPL-012); scope KMS grants tightly (TM-MPL-002); enable CloudTrail on KMS keys and the DDB table (TM-MPL-020).

## 12. References

- spec/framework: algorithm-suites.md, commitment-policy.md, branch-key-store.md, cmm-interface.md, default-cmm.md, structures.md, keyring-interface.md, raw-aes-keyring.md, aws-kms/aws-kms-hierarchical-keyring.md (Appendix A & B), aws-kms/aws-kms-mrk-match-for-decrypt.md, local-cryptographic-materials-cache.md, storm-tracking-cryptographic-materials-cache.md.
- Code: `mpl/src/{keyring/raw_aes_keyring.rs, aws_kms/{hierarchical_keyring,branch_key_wrap,mrk_match,cache_entry_identifier}.rs, keystore/{branch_key_store,kms_ops}.rs, cmm/default_cmm.rs, cmc/{local,storm_tracking}.rs, structures/branch_key_materials.rs}, prim/src/lib.rs`.
- Invisible Salamanders / encryptment: Dodis, Grubbs, Ristenpart, Woodage, IACR ePrint 2019/016 (https://eprint.iacr.org/2019/016). Content rephrased for compliance with licensing restrictions.
- AWS KMS key-derivation construction: Gueron, RWC 2018.
- NIST SP 800-108 (KBKDF), SP 800-38D (GCM), RFC 5869 (HKDF).
- Shared-cache commitment-bypass advisory class referenced during generation as CVE-2026-6550 / GHSA-v638-38fc-rhfv — **identifier unverified in this session**; the attack class (commitment bypass via shared key cache) is authoritative regardless.

## Appendix: Threat Risk Matrix

| ID | STRIDE | Severity | Likelihood | Risk |
|----|--------|----------|-----------|------|
| TM-MPL-001 | S | Medium | Low | Low |
| TM-MPL-002 | S | Critical | Low | Medium |
| TM-MPL-003 | S | Medium | Low | Low |
| TM-MPL-004 | T | High | Low | Medium |
| TM-MPL-005 | T | Critical | Medium | High |
| TM-MPL-006 | E | Critical | Low | Medium |
| TM-MPL-007 | E | High | Low | Medium |
| TM-MPL-008 | E | High | Low | Medium |
| TM-MPL-009 | E | High | Low | Medium |
| TM-MPL-010 | I/E | High | Low | Medium |
| TM-MPL-011 | E | Critical | Low | Medium |
| TM-MPL-012 | E | Critical | Low | Medium |
| TM-MPL-013 | T | High | Low | Medium |
| TM-MPL-014 | E | High | Low | Medium |
| TM-MPL-015 | I | High | Low | Medium |
| TM-MPL-016 | T | Medium | Low | Low |
| TM-MPL-017 | T | High | Low | Medium |
| TM-MPL-018 | D | Medium | Medium | Medium |
| TM-MPL-019 | E | Medium | Medium | Medium |
| TM-MPL-020 | R | Low | Low | Low |
| TM-MPL-021 | I | Medium | Low | Low |
| TM-MPL-022 | D | Low | Medium | Low |
| TM-MPL-023 | D | Medium | Low | Low |
