# Verus Verification Targets — AWS Cryptographic Material Providers Library (native Rust)

> Pipeline artifact — Stage 3, Step 3 of 4 (merge, rank, assemble). **Refreshed for main `620771c`** (branch `MPL-Verus`; `mpl/`, `prim/`, `esdk/` identical to `origin/main` `620771c`). Previous version analyzed `a1e23d7`.
> Inputs: `docs/verification-targets/01-threat-driven.md` (VR-2026-T01..T26), `docs/verification-targets/02-capability-driven.md` (VR-2026-C01..C08), `docs/threat-model.md` (TM-MPL-001..024), `docs/spec-security-analysis.md`, `docs/bug-reports/RECHECK-main-620771c.md`, `.agents/tasks/pipeline-rerun-620771c/scope.md`, `.kiro/agents/verification-recommender.md`.
> Full per-target YAML lives in the two intermediate files. This document is the consolidated, ranked view. Validation: `docs/verification-targets/04-validation.md`.

## 0. Methodology notes

- **Formula.** `Priority = Severity × Coverage_Gap × Feasibility × Blast_Radius`. Every score was recomputed from its factors (see 04-validation check 5).
- **Two feasibility scales.** Threat-driven targets take Severity and Feasibility from the primary threat's rating (Critical/High/Medium/Low = 4/3/2/1; Likelihood Low → 0.4, Medium → 0.7). Capability-driven targets use the consequence of the latent defect for Severity and reachability for Feasibility (1.0 all inputs, 0.7 caller-chosen input/config, 0.4 only on regression or no in-repo caller).
- **New gap level 0.4**: near-exhaustive tests plus a runtime check that enforces the same property on the production path (used for T09, T15).
- **Combined tie-break.** Score descending, then higher severity, then origin (T before C), then target ID.
- **No `unsafe` in `mpl/src` or `prim/src`** (`\bunsafe\b` has no match). The old `PlaintextDataKey::zeroize` loop is gone, so T08 is retired. The only `unsafe` that reaches MPL objects is in the C++ shim (T25).
- **Duvet**: one annotation block (`mpl/src/cmc/entry.rs:201-205`), not checked by any config. Gaps are justified by named tests; tests never close a gap.
- **Bugs**: open BUG-01, 04, 05(a), 05(b), 06, 07(a/b), 08; fixed BUG-02, 03, 09.
- **CVE-2026-6550 / GHSA-v638-38fc-rhfv is verified** (threat model). It concerns a shared caching CMM; the repo has none, so no score depends on it. Future-work note on T14. Content was rephrased for compliance with licensing restrictions.
- **IDs are stable.** Retired targets keep their IDs and are listed, not deleted. New IDs: T25, T26, C07, C08.
- **No source changes.** Findings that need a behavior change are listed in §7.

## 0.1 Refresh summary (a1e23d7 → 620771c)

| ID | Status | Old | New | Driver |
|---|---|---|---|---|
| T08 | **Retired** | 3.84 | — | Unsafe zeroize loop removed (a864ad8); `PlaintextDataKey` derives `Zeroize, ZeroizeOnDrop` (`algorithm_suite.rs:505`) |
| C06 | **Retired** | 1.96 | — | Integer-division unit conversion removed; check is one `Duration` compare (`hierarchical_keyring.rs:585`) |
| T25 | **New** | — | 1.44 | TM-MPL-024 (C++ shim raw handles) |
| T26 | **New** | — | 3.20 | TM-MPL-015 residual (transient / error-path secret buffers); successor of T08 |
| C07 | **New** | — | 5.04 | Materials transition checks (`materials_checks.rs`, #167) |
| C08 | **New** | — | 0.96 | Usage-counter arithmetic (`CacheEntry::record_use`, `entry.rs:206`) |
| T13 | Rescored | 2.52 | 4.41 | TM-MPL-009 Likelihood Low → Medium (BUG-06 confirmed) |
| T14 | Rescored | 2.52 | 3.78 | TM-MPL-010 Likelihood → Medium; BUG-09 fixed + regression test (gap 0.7 → 0.6) |
| T09 | Rescored | 3.20 | 2.56 | Keyring suite frame now enforced by transition checks (gap 0.5 → 0.4) |
| T15 | Rescored | 2.40 | 1.92 | BUG-03 fixed; strict `from_bytes` (gap 0.5 → 0.4) |
| T21 | Rescored | 1.68 | 1.96 | Builder spec ordering regressed; tests encode it (gap 0.6 → 0.7) |
| C04 | Rescored | 5.60 | 2.80 | BUG-02 fixed; expected outcome FAIL → VERIFY (gap 1.0 → 0.5) |
| all others | Locations / names | — | unchanged | `keystore/` → `key_store/`, builders replace `new()`/`from_raw`, `ttl: Duration`, `to_bytes`/`from_bytes` |

## 1. Combined ranked summary

| Rank | Score | Origin | Target | Property | Agent | Ref | Effort |
|---|---|---|---|---|---|---|---|
| 1 | 8.96 | T | T01 key-store auth-EC builders (`kms_ops.rs:49`, `branch_key_store.rs:132`, `:1089`, `:1141`) | Write-time EC == KMS-AAD EC == reconstruction EC | verus-header-parsing-proofs | TM-MPL-005, TM-MPL-002 | 2 weeks |
| 2 | 6.72 | T | T02 `record::branch_key_materials_from_authenticated_encryption_context` (`record.rs:95`) | Exact Ok/Err characterization | verus-header-parsing-proofs | TM-MPL-005 | 1 week |
| 3 | 6.72 | C | C01 `key_store/encryption_context.rs` builders ∘ `record.rs` reconstruction | Round trip on (id, version, custom EC); collision branch dead (BUG-08) | verus-header-parsing-proofs | cap:cat1 (1c) | 1 week |
| 4 | 6.40 | C | C02 `prim::ecdsa` `sign_fixed_len` (`ecdsa.rs:180`) and callers | ≤ 128 attempts; no panic; no partial write | verus-zero-panic | cap:cat2 (2d) | 1 week |
| 5 | 5.60 | C | C03 `prim::{hmac, digest, aes_encrypt, aes_decrypt, hkdf*, kbkdf_ctr_hmac}`, `DigestContext::finish` | No panic; exact length contract | verus-zero-panic | cap:cat2 (2a/2d) | 1 week |
| 6 | 5.12 | T | T03 `kms_ops::resolve_key_store_arn` pinned modes (`kms_ops.rs:88`) | KeyId is always the configured ARN | verus-header-parsing-proofs | TM-MPL-002 | 1 day |
| 7 | 5.04 | C | C07 `materials_checks` transitions + `send()` wiring | Keyring may only add PDK/EDKs; every `send()` checks | verus-header-parsing-proofs | cap:cat1 (1a/1b) | 1 week |
| 8 | 4.48 | T | T04 `branch_key_wrap::wrap` (`:157`) | Fresh salt + IV per call; 60+n layout | verus-unsafe-ffi-safety | TM-MPL-012 | 1 week |
| 9 | 4.41 | T | T13 `build_cache_identifier` (`cache_entry_identifier.rs:35`) + keyring inputs | Injective iff fields NUL-free (BUG-06 counterexample) | verus-header-parsing-proofs | TM-MPL-009, TM-MPL-010 | 1 week |
| 10 | 4.32 | T | T05 `branch_key_wrap::derive_branch_key` (`:122`) | KBKDF fixed-info layout, 32 B out | verus-header-parsing-proofs | TM-MPL-014 | 1 day |
| 11 | 4.20 | T | T06 `SystemTime + Duration` (`hierarchical_keyring.rs:702`, `:945`; `storm_tracking.rs:333`, `:680`) | No overflow panic (expected FAIL, BUG-01) | verus-zero-panic | TM-MPL-018, 022, 023 | 1 week |
| 12 | 3.84 | T | T07 raw-AES wrap/unwrap + `prim::aes_*` | Fresh 12 B IV; length preconditions | verus-unsafe-ffi-safety | TM-MPL-011 | 1 week |
| 13 | 3.78 | T | T14 `as_branch_key_materials` (`:1000`), `cache_entry_within_limits` (`:989`), `generate_partition_id` (`:626`) | Only BranchKey entries; exact `Duration` TTL; v4 id | verus-header-parsing-proofs | TM-MPL-010 | 1 week |
| 14 | 3.20 | T | T26 transient / error-path secret buffers | Wiped or moved to `ZeroizeOnDrop` on every exit (expected FAIL, BUG-07a) | verus-unsafe-ffi-safety | TM-MPL-015 | 2 weeks |
| 15 | 2.88 | T | T10 `compute_aad` (`:61`), UUID codec | AAD layout; UUID round trip | verus-header-parsing-proofs | TM-MPL-013 | 1 week |
| 16 | 2.88 | T | T11 `aws_kms_mrk_match_for_decrypt` (`mrk_match.rs:24`), `is_arn_compatible` | MRK match semantics | verus-header-parsing-proofs | TM-MPL-004 | 2 weeks |
| 17 | 2.88 | T | T12 `merge_reproduced_encryption_context` (`default_cmm.rs:273`) | Union on agreement | verus-header-parsing-proofs | TM-MPL-017 | 1 week |
| 18 | 2.80 | C | C04 PDK length invariant (`check_data_key_length`, `algorithm_suite.rs:547`) | PDK length = suite key length (expected VERIFY) | verus-header-parsing-proofs | cap:cat1 (1a) | 1 week |
| 19 | 2.56 | T | T09 commitment policy + `DefaultCmm` gates | Allow-tables match spec | verus-header-parsing-proofs | TM-MPL-006, TM-MPL-008 | 1 week |
| 20 | 2.40 | C | C05 suite table | Refines spec; ids injective | verus-header-parsing-proofs | cap:cat1 (1a) | 1 day |
| 21 | 2.24 | T | T16 malformed-input panic sites | No panic on malformed EDK/EC/ARN | verus-zero-panic | TM-MPL-023 | 1 week |
| 22 | 1.96 | T | T21 `cmc/storm_tracking.rs` (`build` `:606`) | Spec ordering (expected FAIL); `\|inflight\| ≤ fan_out` | verus-zero-panic (+ concurrency) | TM-MPL-018 | 1 month |
| 23 | 1.92 | T | T15 `EncryptionContext::{to_bytes, from_bytes}` (`:91`, `:145`) | Canonical codec (expected VERIFY) | verus-header-parsing-proofs | TM-MPL-013, TM-MPL-017 | 2 weeks |
| 24 | 1.92 | T | T17 Discovery / MRDiscovery ARN (`kms_ops.rs:96-102`, `:118`, `:144`) | Region rewrite only for MRKs (expected FAIL, BUG-04) | verus-header-parsing-proofs | TM-MPL-007 | 1 week |
| 25 | 1.92 | T | T18 `version_key` EC derivation (`branch_key_store.rs:641`, `:706-722`) | Preserves id/arn/hv/tablename/custom EC | verus-header-parsing-proofs | TM-MPL-016 | 1 week |
| 26 | 1.92 | T | T19 hierarchical bkid binding | Only matching EDKs attempted | verus-header-parsing-proofs | TM-MPL-003 | 1 week |
| 27 | 1.68 | T | T20 raw-AES provider-info codec (`:129`, `:191`) | Round trip, total | verus-header-parsing-proofs | TM-MPL-023, 011, 001 | 1 week |
| 28 | 1.60 | T | T22 `Debug` + error `DataKeyInfo` | Independent of secret bytes | verus-unsafe-ffi-safety | TM-MPL-021 | 1 week |
| 29 | 1.44 | T | T25 C++ shim handles (`esdk/shims/aws-esdk-cpp/src/lib.rs:715`, `:728`, `:1564-1565`, `:1655`) | Every deref null-dominated | verus-unsafe-ffi-safety | TM-MPL-024 | 1 week |
| 30 | 1.26 | T | T23 `LocalCmc` (`cmc/local.rs`) | Capacity + TTL invariants | verus-zero-panic | TM-MPL-022 | 2 weeks |
| 31 | 1.20 | T | T24 `RawAesKeyringBuilder::build` (`:350`, check `:360`) | No `aws-kms` namespace | verus-header-parsing-proofs | TM-MPL-001 | 1 day |
| 32 | 0.96 | C | C08 `CacheEntry::record_use` (`entry.rs:206`) + `update_usage_metadata` | Counters never wrap; overflow evicts | verus-zero-panic | cap:cat2 (2b) | 1 day |
| — | Retired | T | T08 ~~`PlaintextDataKey::zeroize` unsafe loop~~ | code removed (a864ad8) | — | (TM-MPL-015 → T26) | — |
| — | Retired | C | C06 ~~grace-vs-TTL integer division~~ | code removed | — | — | — |

Totals: **32 active targets**, 25 threat-driven (T01–T07, T09–T26) and 7 capability-driven (C01–C05, C07, C08), plus 2 retired (T08, C06). Agent routing: verus-header-parsing-proofs ×20, verus-zero-panic ×7, verus-unsafe-ffi-safety ×5.

## 2. Detailed recommendations (YAML)

The ten highest-ranked targets plus the two new threat-driven targets (T26, T25). 8 threat-driven, 4 capability-driven. `rank` is the combined rank from §1. Full versions (with formal specs) are in 01 §3 and 02 §3.

```yaml
recommendation:
  id: VR-2026-T01
  rank: 1
  priority_score: 8.96
  origin: threat-driven
  target:
    crate: aws-crypto-mpl
    file: mpl/src/key_store/kms_ops.rs; mpl/src/key_store/branch_key_store.rs; mpl/src/key_store/record.rs
    function: >
      kms_ops::build_authenticated_encryption_context (:49); DynamoDbKeyStore::build_auth_ec (:132);
      item_from_ec_and_enc (:1089); record_from_ddb_item (:1141); record::{encryption_context_from_item (:37), to_attribute_map (:61)} (test-utils)
  property: "Builders agree with the spec auth EC (all attributes except enc, plus tablename); write→read reproduces exactly the KMS-authenticated EC."
  tool: Verus
  agent: verus-header-parsing-proofs
  estimated_effort: 2 weeks
  threat_references:
    - {id: TM-MPL-005, category: Tampering, description: "Branch-key record substitution"}
    - {id: TM-MPL-002, category: Spoofing, description: "Forged record decrypts under attacker-influenced key"}
  trace_to_spec: "spec/framework/branch-key-store.md#encryption-context, #authenticating-a-keystore-item, #record-format"
  coverage_gap: 0.8
  coverage_evidence: "test_key_store_record.rs covers only test-utils helpers; production builders are reached only by live-AWS integ tests."
  scoring: {severity: 4, coverage_gap: 0.8, feasibility: 0.7, blast_radius: 4, product: "4 × 0.8 × 0.7 × 4 = 8.96"}
  quick_win: false     # 2 weeks
  dependencies: []
```

```yaml
recommendation:
  id: VR-2026-T02
  rank: 2
  priority_score: 6.72
  origin: threat-driven
  target:
    crate: aws-crypto-mpl
    file: mpl/src/key_store/record.rs
    function: branch_key_materials_from_authenticated_encryption_context (:95); custom_encryption_context_from_authenticated_encryption_context (:79)
  property: "Ok iff valid type/version, branch-key-id present and 32-byte plaintext; outputs exactly determined; otherwise Err(Kind::InvalidMaterials)."
  tool: Verus
  agent: verus-header-parsing-proofs
  estimated_effort: 1 week
  threat_references:
    - {id: TM-MPL-005, category: Tampering, description: "Reconstruction must not accept a mis-typed or mis-versioned record"}
  trace_to_spec: "spec/framework/branch-key-store.md#branch-key-materials-from-authenticated-encryption-context"
  coverage_gap: 0.6
  coverage_evidence: "test_key_store_record.rs (23 tests, e.g. materials_branch_key_rejects_wrong_length :169)."
  scoring: {severity: 4, coverage_gap: 0.6, feasibility: 0.7, blast_radius: 4, product: "4 × 0.6 × 0.7 × 4 = 6.72"}
  quick_win: true
  dependencies: []
```

```yaml
recommendation:
  id: VR-2026-C01
  rank: 3
  priority_score: 6.72
  origin: capability-driven
  target:
    crate: aws-crypto-mpl
    file: mpl/src/key_store/encryption_context.rs; mpl/src/key_store/record.rs
    function: build_base (:40), active_encryption_context (:117), decrypt_only_encryption_context (:137), beacon_key_encryption_context (:160); record.rs (:79, :95, :37, :61)
  property: "CreateKey ECs reconstruct to exactly (id, version, custom EC); prefix/strip inverse; collision Err (:95-101) unreachable (BUG-08); record→EC→record identity off tablename/enc."
  tool: Verus
  agent: verus-header-parsing-proofs
  estimated_effort: 1 week
  threat_references: []
  capability_reference: {category: 1, invariant: "Key-store EC builders and the reconstruction decoder are exact inverses on (branch-key-id, version, custom EC)."}
  trace_to_spec: "spec/framework/branch-key-store.md#encryption-context, #active-encryption-context, #decrypt_only-encryption-context"
  coverage_gap: 0.8
  coverage_evidence: "Each half tested alone (test_key_store_encryption_context.rs, test_key_store_record.rs); no composition test."
  scoring: {severity: 3, coverage_gap: 0.8, feasibility: 0.7, blast_radius: 4, product: "3 × 0.8 × 0.7 × 4 = 6.72"}
  quick_win: true
  dependencies: [VR-2026-T02]
```

```yaml
recommendation:
  id: VR-2026-C02
  rank: 4
  priority_score: 6.40
  origin: capability-driven
  target:
    crate: aws-mpl-primitives
    file: prim/src/ecdsa.rs
    function: sign_fixed_len (:180); check_sig_len (:200); ecdsa_sign (:224); ecdsa_sign_digest (:253); ecdsa_verify (:282); ecdsa_verify_context (:305)
  property: "≤ 128 sign_once calls; copy only on exact length; buffer untouched on Err; verify never Err."
  tool: Verus
  agent: verus-zero-panic
  estimated_effort: 1 week
  threat_references: []
  capability_reference: {category: 2, invariant: "The ECDSA retry loop terminates, never panics, and never partially writes the buffer."}
  trace_to_spec: "spec/framework/algorithm-suites.md#asymmetric-signature-algorithm; baseline assurance"
  coverage_gap: 0.8
  coverage_evidence: "prim/tests/test_ecdsa.rs; oracle not injectable, so retry exhaustion is untested."
  scoring: {severity: 2, coverage_gap: 0.8, feasibility: 1.0, blast_radius: 4, product: "2 × 0.8 × 1.0 × 4 = 6.40"}
  quick_win: true
  dependencies: []
```

```yaml
recommendation:
  id: VR-2026-C03
  rank: 5
  priority_score: 5.60
  origin: capability-driven
  target:
    crate: aws-mpl-primitives
    file: prim/src/lib.rs; prim/src/ecdsa.rs; prim/src/hkdf.rs
    function: hmac (:241), digest (:272), aes_encrypt (:175), aes_decrypt (:206), kbkdf_ctr_hmac (:313), DigestContext::finish (ecdsa.rs:82), hkdf (hkdf.rs:46), hkdf_no_salt (:76), hkdf_expand (:101)
  property: "No panic for any argument; exact Ok/Err length contract; aes_decrypt Ok ⇒ |pt| == |ct|."
  tool: Verus
  agent: verus-zero-panic
  estimated_effort: 1 week
  threat_references: []
  capability_reference: {category: 2, invariant: "No reachable panic path in the prim crypto wrappers."}
  trace_to_spec: "supports spec/framework/algorithm-suites.md lengths; baseline assurance"
  coverage_gap: 0.7
  coverage_evidence: "prim/tests negative-length tests; no wrong-length finish buffer, no over-long aes_decrypt buffer."
  scoring: {severity: 2, coverage_gap: 0.7, feasibility: 1.0, blast_radius: 4, product: "2 × 0.7 × 1.0 × 4 = 5.60"}
  quick_win: false
  dependencies: []
```

```yaml
recommendation:
  id: VR-2026-T03
  rank: 6
  priority_score: 5.12
  origin: threat-driven
  target:
    crate: aws-crypto-mpl
    file: mpl/src/key_store/kms_ops.rs
    function: resolve_key_store_arn (:88; pinned arms :94-95; compat check :105); caller decrypt_branch_key (:162, call :179)
  property: "In KmsKeyArn / KmsMrKeyArn modes the KMS KeyId is always the configured ARN; Ok iff compatible, else Err(Kind::Validation)."
  tool: Verus
  agent: verus-header-parsing-proofs
  estimated_effort: 1 day
  threat_references:
    - {id: TM-MPL-002, category: Spoofing, description: "Forged record decrypts under attacker-influenced KMS key — pinned-mode slice"}
  trace_to_spec: "spec/framework/branch-key-store.md#aws-kms-branch-key-decryption"
  coverage_gap: 0.8
  coverage_evidence: "No direct unit test (pub(crate)); predicate tested in test_key_store_kms_config.rs; end-to-end only integ."
  scoring: {severity: 4, coverage_gap: 0.8, feasibility: 0.4, blast_radius: 4, product: "4 × 0.8 × 0.4 × 4 = 5.12"}
  quick_win: false
  dependencies: [VR-2026-T11]
```

```yaml
recommendation:
  id: VR-2026-C07
  rank: 7
  priority_score: 5.04
  origin: capability-driven
  target:
    crate: aws-crypto-mpl
    file: mpl/src/structures/materials_checks.rs; mpl/src/keyring/fluent_builders.rs; mpl/src/cmm/fluent_builders.rs
    function: check_encryption_transition (:72); check_decryption_transition (:117); check_*_materials_complete (:157, :177); send() wiring (keyring :82, :163; cmm :171, :319)
  property: "Transition Ok iff the keyring only added a PDK (when absent) and EDKs, with suite/EC/required keys/signing or verification key unchanged; every fluent send() returns Ok only after the check passes."
  tool: Verus
  agent: verus-header-parsing-proofs
  estimated_effort: 1 week
  threat_references: []
  capability_reference: {category: 1, invariant: "On every fluent path a keyring cannot change the suite, EC, required keys or signing/verification key."}
  trace_to_spec: "spec/framework/keyring-interface.md#onencrypt, #ondecrypt; spec/framework/cmm-interface.md"
  coverage_gap: 0.6
  coverage_evidence: "test_materials_checks.rs (27 tests, e.g. on_encrypt_rejects_a_changed_algorithm_suite :271)."
  scoring: {severity: 3, coverage_gap: 0.6, feasibility: 0.7, blast_radius: 4, product: "3 × 0.6 × 0.7 × 4 = 5.04"}
  quick_win: false
  dependencies: []
```

```yaml
recommendation:
  id: VR-2026-T04
  rank: 8
  priority_score: 4.48
  origin: threat-driven
  target:
    crate: aws-crypto-mpl
    file: mpl/src/aws_kms/branch_key_wrap.rs
    function: wrap (:157; salt :164; IV :170)
  property: "Fresh 16 B salt and 12 B IV per call; output = salt‖iv‖uuid(version)‖ct‖tag, |out| = 60 + |pt|; aws-lc-rs preconditions hold."
  tool: Verus
  agent: verus-unsafe-ffi-safety
  estimated_effort: 1 week
  threat_references:
    - {id: TM-MPL-012, category: Elevation of Privilege, description: "Salt/IV reuse in branch-key wrap — structural slice"}
  trace_to_spec: "spec/framework/aws-kms/aws-kms-hierarchical-keyring.md#branch-key-wrapping"
  coverage_gap: 0.7
  coverage_evidence: "wrap_ciphertext_layout_lengths_match_spec (:939), wrap_two_calls_produce_distinct_ciphertexts (:1168)."
  scoring: {severity: 4, coverage_gap: 0.7, feasibility: 0.4, blast_radius: 4, product: "4 × 0.7 × 0.4 × 4 = 4.48"}
  quick_win: false
  dependencies: [VR-2026-T05, VR-2026-T10]
```

```yaml
recommendation:
  id: VR-2026-T13
  rank: 9
  priority_score: 4.41
  origin: threat-driven
  target:
    crate: aws-crypto-mpl
    file: mpl/src/aws_kms/cache_entry_identifier.rs; mpl/src/aws_kms/hierarchical_keyring.rs
    function: build_cache_identifier (:35; preimage :42-60; .expect :64); call sites (:665, :908); inputs partition id (:595-599, :626), logical name (:605)
  property: "Exact NUL-separated preimage; scope separation; injective iff partition / logical name / bkid / version are NUL-free (BUG-06 counterexample otherwise)."
  tool: Verus
  agent: verus-header-parsing-proofs
  estimated_effort: 1 week
  threat_references:
    - {id: TM-MPL-009, category: Elevation of Privilege, description: "Cache-identifier collision (BUG-06 confirmed on main)"}
    - {id: TM-MPL-010, category: Information Disclosure / EoP, description: "Shared-cache confusion"}
  trace_to_spec: "spec/framework/aws-kms/aws-kms-hierarchical-keyring.md#appendix-a-cache-entry-identifier-formulas, #partition-id"
  coverage_gap: 0.7
  coverage_evidence: "cache_entry_identifier_* tests (:647, :680, :708, :736, :770); no NUL case."
  scoring: {severity: 3, coverage_gap: 0.7, feasibility: 0.7, blast_radius: 3, product: "3 × 0.7 × 0.7 × 3 = 4.41"}
  quick_win: false
  dependencies: []
```

```yaml
recommendation:
  id: VR-2026-T05
  rank: 10
  priority_score: 4.32
  origin: threat-driven
  target:
    crate: aws-crypto-mpl
    file: mpl/src/aws_kms/branch_key_wrap.rs
    function: derive_branch_key (:122; Zeroizing output :125/:135; kbkdf call :136)
  property: "Fixed-info = \"aws-kms-hierarchy\" ‖ 0x00 ‖ salt ‖ 0x00000100 (38 B); HMAC-SHA-256; 32 B output."
  tool: Verus
  agent: verus-header-parsing-proofs
  estimated_effort: 1 day
  threat_references:
    - {id: TM-MPL-014, category: Elevation of Privilege, description: "KBKDF fixed-info / L-value misuse"}
  trace_to_spec: "spec/framework/aws-kms/aws-kms-hierarchical-keyring.md#branch-key-wrapping; NIST SP 800-108 §4.1"
  coverage_gap: 0.9
  coverage_evidence: "Self-consistent round trips only; prim vectors test the primitive (test_kbkdf_ctr_hmac_raw_vectors :329)."
  scoring: {severity: 3, coverage_gap: 0.9, feasibility: 0.4, blast_radius: 4, product: "3 × 0.9 × 0.4 × 4 = 4.32"}
  quick_win: false
  dependencies: []
```

```yaml
recommendation:
  id: VR-2026-T26
  rank: 14
  priority_score: 3.20
  origin: threat-driven
  target:
    crate: aws-crypto-mpl + aws-mpl-primitives
    file: mpl/src/keyring/raw_aes_keyring.rs; prim/src/lib.rs; mpl/src/aws_kms/branch_key_wrap.rs; mpl/src/key_store/kms_ops.rs
    function: raw-AES on_decrypt buffer (:471, :489); wrap_data_key output Vec (:162); prim::aes_encrypt (:175, copy :185 before Err :188); branch_key_wrap::unwrap (:230); decrypt_branch_key plaintext
  property: "Every buffer that held key plaintext is wiped or moved into a ZeroizeOnDrop owner on every exit path. Expected FAIL: raw-AES decrypt Err / wrong-length paths and BUG-07a."
  tool: Verus
  agent: verus-unsafe-ffi-safety
  estimated_effort: 2 weeks
  threat_references:
    - {id: TM-MPL-015, category: Information Disclosure, description: "Transient and error-path secret copies"}
  trace_to_spec: "spec/framework/structures.md#plaintext-data-key; baseline assurance"
  coverage_gap: 1.0
  coverage_evidence: "Zeroize tests cover types only (:248, :228); no test of transient buffers."
  scoring: {severity: 2, coverage_gap: 1.0, feasibility: 0.4, blast_radius: 4, product: "2 × 1.0 × 0.4 × 4 = 3.20"}
  quick_win: false
  dependencies: []
```

```yaml
recommendation:
  id: VR-2026-T25
  rank: 29
  priority_score: 1.44
  origin: threat-driven
  target:
    crate: aws-esdk-cpp shim (outside mpl/ and prim/)
    file: esdk/shims/aws-esdk-cpp/src/lib.rs
    function: require_handle (:715; null check :720; deref :728); nullable client handles (:1564, :1565); nullable cache handle (:1655); into_keyring_handle (:2054)
  property: "Every raw-handle deref is dominated by a null check; null required handle → Validation error; null optional handle → core default. Non-null validity is a trusted caller precondition."
  tool: Verus
  agent: verus-unsafe-ffi-safety
  estimated_effort: 1 week
  threat_references:
    - {id: TM-MPL-024, category: Elevation of Privilege / Tampering, description: "Shim dereferences a dangling or forged handle to an MPL object"}
  trace_to_spec: "spec/shim/shim.md#handles-and-lifetimes"
  coverage_gap: 0.6
  coverage_evidence: "esdk/shims/aws-esdk-cpp/src/tests.rs: require_handle_rejects_null_and_borrows_non_null (:715), null keyring / key-store tests (:733, :746, :791)."
  scoring: {severity: 3, coverage_gap: 0.6, feasibility: 0.4, blast_radius: 2, product: "3 × 0.6 × 0.4 × 2 = 1.44"}
  quick_win: false
  dependencies: []
```

## 3. Coverage-gap analysis

No Verus proof exists for any target. Files are under `mpl/tests/` unless prefixed. "integ" = live-AWS.

| Target | Existing tests | Gap | Justification |
|---|---|---|---|
| T01 | test_key_store_record.rs; test_key_store_branch_key_store_integ.rs (integ) | 0.8 | Unit tests reach only test-utils helpers |
| T02 | test_key_store_record.rs | 0.6 | Broad branch examples |
| C01 | test_key_store_encryption_context.rs; test_key_store_record.rs | 0.8 | No composition test |
| C02 | prim/tests/test_ecdsa.rs | 0.8 | Oracle not injectable |
| C03 | prim/tests/test_{hmac,digest,aes,hkdf,kbkdf_ctr_hmac,ecdsa}.rs | 0.7 | Direct negative-length tests; two gaps |
| T03 | test_key_store_kms_config.rs; integ | 0.8 | Function untested directly |
| C07 | test_materials_checks.rs (new, 27) | 0.6 | Broad examples, no field-by-field statement |
| T04 | test_aws_kms_hierarchical_keyring.rs | 0.7 | Layout, distinctness, tamper |
| T13 | test_aws_kms_hierarchical_keyring.rs | 0.7 | No NUL case (BUG-06) |
| T05 | test_aws_kms_hierarchical_keyring.rs; prim/tests/test_kbkdf_ctr_hmac.rs | 0.9 | Self-consistent only |
| T06 | test_aws_kms_hierarchical_keyring.rs; test_storm_tracking_cmc.rs | 1.0 | No large-Duration test |
| T07 | test_raw_aes_keyring.rs; prim/tests/test_aes.rs | 0.8 | No two-call IV test |
| T14 | test_aws_kms_hierarchical_keyring.rs | 0.6 | BUG-09 regression test added; no wrong-kind entry |
| T26 | test_encryption_materials.rs; test_decryption_materials.rs | 1.0 | Types only, no transient buffers |
| T10 | test_aws_kms_hierarchical_keyring.rs | 0.6 | Layout + mismatch tests |
| T11 | test_aws_kms_mrk_match.rs; test_key_store_kms_config.rs | 0.6 | Example tests |
| T12 | test_default_cmm.rs | 0.6 | Example tests |
| C04 | test_encryption_materials.rs; test_decryption_materials.rs | 0.5 | All four entry points tested (BUG-02 fix) |
| T09 | test_commitment_policy.rs; test_default_cmm.rs; test_materials_checks.rs | 0.4 | Near-exhaustive + runtime frame check |
| C05 | test_algorithm_suite_id.rs (22) | 0.5 | Finite domain; cross-crate untested |
| T16 | hierarchical, raw-AES, EC, MRK tests | 0.7 | Direct malformed-input tests |
| T21 | test_storm_tracking_cmc.rs (33) | 0.7 | Tests encode the regressed contract (:388) |
| T15 | test_encryption_context.rs (45) | 0.4 | Strict decoder + order/UTF-8 tests |
| T17 | test_key_store_kms_config.rs; test_key_store_branch_key_store.rs; integ | 0.8 | No non-MRK MRDiscovery test |
| T18 | test_key_store_branch_key_store.rs; integ | 0.8 | Inline derivation only via integ |
| T19 | test_aws_kms_hierarchical_keyring.rs | 0.6 | Skip-filter and supplier tests |
| T20 | test_raw_aes_keyring.rs | 0.7 | Wire format + negatives |
| T22 | test_algorithm_suite.rs; test_raw_aes_keyring.rs; others | 0.5 | Redaction test per type |
| T25 | esdk/shims/aws-esdk-cpp/src/tests.rs | 0.6 | Null checks tested; dangling untestable |
| T23 | test_local_cmc.rs | 0.6 | Capacity, TTL, pruning |
| T24 | test_raw_aes_keyring.rs | 0.5 | Reserved-prefix tests |
| C08 | test_local_cmc.rs (:729) | 0.6 | Overflow-deletes test |

## 4. Risk summary by STRIDE category

From `docs/threat-model.md` §7 (TM-MPL-024 listed under Elevation of Privilege). "Verified" is 0: no Verus proof exists yet.

| Category | Threats | Verified | With target | Fully excluded | Targets | Top-priority target |
|---|---|---|---|---|---|---|
| Spoofing | 3 (001, 002, 003) | 0 | 3 | 0 | T01, T03, T19, T20, T24 | T01 (8.96, via 002); primary-002 T03 (5.12) |
| Tampering | 5 (004, 005, 013, 016, 017) | 0 | 5 | 0 | T01, T02, T10, T11, T12, T15, T18 | T01 (8.96) |
| Repudiation | 1 (020) | 0 | 0 | 1 | — | — |
| Information Disclosure | 3 (010, 015, 021) | 0 | 3 | 0 | T13, T14, T22, T26 | T13 (4.41, via 010); primary-010 T14 (3.78) |
| Denial of Service | 3 (018, 022, 023) | 0 | 3 | 0 | T06, T16, T20, T21, T23 | T06 (4.20) |
| Elevation of Privilege | 9 (006, 007, 008, 009, 011, 012, 014, 019, 024) | 0 | 8 | 1 (019) | T04, T05, T07, T09, T13, T17, T20, T25 | T04 (4.48) |
| **Total** | **24** | **0** | **22** | **2** | 25 threat-driven targets | |

Capability-driven targets by closest category (advisory): Tampering/integrity — C01 (6.72), C07 (5.04), C04 (2.80), C05 (2.40); DoS — C02 (6.40), C03 (5.60), C08 (0.96).

## 5. Quick wins (score > 6.0 AND effort ≤ 1 week)

| Rank | Target | Score | Effort | Origin |
|---|---|---|---|---|
| 2 | VR-2026-T02 reconstruction Ok/Err | 6.72 | 1 week | T |
| 3 | VR-2026-C01 EC builder ∘ reconstruction | 6.72 | 1 week | C |
| 4 | VR-2026-C02 ECDSA bounded retry | 6.40 | 1 week | C |

Unchanged from the previous run. T01 (8.96) needs 2 weeks. Cheap targets below threshold: T03 (5.12, 1 day), T05 (4.32, 1 day), C05 (2.40, 1 day).

## 6. Out of scope / not Verus-provable

Full table in 01 §4. Fully excluded: **TM-MPL-019** (Duvet/process; spec floats on `master`) and **TM-MPL-020** (audit/operational). Partial exclusions keep crypto hardness, external-service semantics, probabilistic bounds, allocator/OS memory, caller-supplied components (`KeyStore`, `Cmc`, `BranchKeyIdSupplier`, C++ callers of the shim) and the `zeroize` / `cxx` crates as trusted or excluded. Capability candidates rejected: 02 §5 (R2–R16; R1 withdrawn because counter code now exists, see C08).

## 7. Findings recorded, not changed

Each needs an owner decision.

- T06 (BUG-01): `SystemTime + Duration` overflow panics for large accepted `ttl`, `grace_interval`, `in_flight_ttl`.
- T13 (BUG-06): cache-id preimage not injective with NUL in partition id / logical name / bkid; end-to-end confirmed.
- T17 (BUG-04): MRDiscovery rewrites the region of non-MRK ARNs (fails closed).
- T21: `StormTrackingCmcBuilder::build` no longer enforces Grace Interval ≤ Grace Period, Inflight TTL ≤ Grace Period, or minimums.
- T16 (BUG-05a/b): `default_cmm.rs:138` `.expect` on ECDSA keygen; 44–59-byte EDK costs one key-store lookup.
- T26 (BUG-07a): `prim::aes_encrypt` leaves plaintext in the caller's buffer on `Err`; raw-AES decrypt buffer not wiped on error paths.
- C03 (BUG-07b): `aes_decrypt` guard weaker than its callee; misleading error text.
- C01(c) (BUG-08): dead collision `Err` in `build_base`.
- C07: fields not constrained by `check_encryption_transition` (symmetric signing keys, EDK order) to be compared with Dafny `Materials.dfy`.
- Closed since a1e23d7: C04-F1/F2 (BUG-02), T15 unsorted-accept (BUG-03), T14 `ttl + 1 s` (BUG-09).
