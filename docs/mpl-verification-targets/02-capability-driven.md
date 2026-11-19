# Capability-Driven Verus Verification Targets — AWS MPL (native Rust)

> Pipeline artifact — Stage 3, Step 2 of 4 (capability-driven entry path, the Stage 2' sweep). **Refreshed for HEAD `9955ecd`** (branch `MPL-Verus`; `mpl/` and `prim/` identical to `origin/main` `620771c`; `esdk/` differs from `620771c` only by #188 and #189). The `620771c` refresh (previous version analyzed `a1e23d7`) is kept in §0.
> Inputs: `mpl/src`, `prim/src`, `mpl/tests`, `prim/tests`, `spec/framework/*.md`, `docs/mpl-threat-model.md` (TM-MPL-001..026), `docs/mpl-completeness-audit.md`, `.agents/tasks/pipeline-rerun-620771c/scope.md`, `.agents/tasks/docs-sync-9955ecd/scores.md`, and Step 1 output `docs/mpl-verification-targets/01-threat-driven.md`.
> Methodology: `.kiro/agents/mpl-ai-verification-pipeline.md` (Stage 2'), `.kiro/agents/mpl-verus-capabilities.md`, `.kiro/agents/mpl-verification-recommender.md`.
> Every target has `origin: capability-driven` and a `capability_reference` in place of a threat. Candidates already scoped by Step 1 are listed in §4, not re-issued.

## Refresh (HEAD 9955ecd)

No capability-driven target was added, removed or re-scored. C01 to C08 keep their scores, ranks and YAML (C06 stays retired). `mpl/` and `prim/` did not change since `620771c`, so every `mpl/` and `prim/` citation below still holds; the shim citations moved with #188. The refresh re-ran the sweep over the Step 1 changes (new T27, re-scored T21, wider T25 and T26, the G1 clause in T02) and updated the text that follows them.

| Item | Change in this document |
|---|---|
| New capability target | **None.** See "Decision" below. Recorded as R17 in §5 |
| §4 overlap rows | T21 builder row: states that property (a) is expected FAIL and is a one-day slice of the one-month T21. T26 row: adds the expired `LocalCmc` entries and the un-wiped `ecdsa_generate_keypair` private-key `Vec` (`prim/src/ecdsa.rs:387`, `:391-392`), which no C target scopes. T25 row: citations moved (`lib.rs:1564-1565` → `:1570-1571`, `:1655` → `:1661`) and the type-erased `Keyring::adopt` path is added as the part a Rust-side proof cannot cover. Two new rows: the EDK loop bound (T27, cat 2d) and the G1 clause that a branch key record MUST include `create-time` and `hierarchy-version` (T02, cat 1a) |
| §4 T21 concurrency row | Notes the added liveness properties (g), (h), (i) |
| Threat range | Inputs now cite TM-MPL-001..026 (completeness audit G4-1). TM-MPL-026 (test-only loopback servers) has no capability candidate; it is a fully excluded threat in 01 §4 |
| §5, §6, §7 | R17 added (candidate rejected); a finding line for the T21 builder bounds; accounting recounted (17 overlap rows, 16 rejected candidates) |

**Decision: no capability-driven sibling of T21 for the storm-tracking builder.** The question was whether `StormTrackingCmcBuilder::build` no longer enforcing the spec bounds (Inflight TTL ≤ Grace Period, Grace Interval ≤ Grace Period, "at least 1") justifies a C target. It does not.

1. **The property is already a target.** T21 (a) states the exact `build` Ok/Err characterization, including the missing constraints, marked expected FAIL. The §4 rule is that a candidate already scoped by Step 1 is listed, not re-issued. A sibling would restate the same pure function, spec text and agent.
2. **What the code enforces against the spec.** The spec requires Grace Interval ≤ Grace Period and Inflight TTL ≤ Grace Period (`spec/framework/storm-tracking-cryptographic-materials-cache.md:136-137`) and at least 1 for each value (`:59`, `:71`, `:92`). `build` checks only `fan_out == 0` (`mpl/src/cmc/storm_tracking.rs:613`), `in_flight_ttl.is_zero()` (`:616`), `sleep.is_zero()` (`:619`) and `grace_interval > in_flight_ttl` (`:622`, spec `:138`). `test_durations_are_stored_exactly` (`mpl/tests/test_storm_tracking_cmc.rs:388`) accepts `grace_period = Duration::ZERO`.
3. **The bound is not yet well defined.** The spec's own defaults break its ordering (Inflight TTL 20 s, Grace Period 10 s); the code uses 10 s on purpose (`storm_tracking.rs:117-119`). "At least 1" is in the configured time unit, while the code takes a `Duration` and tests accept sub-second values (`test_sub_second_grace_period_is_honored`, `test_storm_tracking_cmc.rs:283`). The owner has to choose the minimum before a proof can state it; T21 (a) keeps it symbolic.
4. **It would not change the order of work.** With this document's conventions a sibling scores 2 (consequence: a spec-MUST violation that downstream accepts) × 0.9 (tests exist and encode the regressed contract) × 0.7 (caller-chosen configuration) × 2 (opt-in storm-tracking cache) = 2.52. That is far below the 6.0 quick-win threshold. It would also not address BUG-01, which needs upper bounds (T06), not lower bounds.

## Proofs written (HEAD d288750)

This file covers C01 and C02; T01, T02, T03, T05 and T13 are in `01-threat-driven.md`. Seven targets have a Verus proof in `verus-proofs/` (T02, C01, C02, T03 and T05 at HEAD `d288750`; T01 and T13 at HEAD `4964d66`; run again with `~/verus/verus verus-proofs/<file>.rs` from the repo root, Verus 0.2026.07.12.0b42f4c). Each is a proof about a hand-written, re-typed model of the shipped Rust. None verifies the shipped code: the code is not inside `verus!`, is not compiled by Verus, and nothing detects a later edit to `mpl/` or `prim/`. The link between model and code is a correspondence table in each file header, reviewed by a human. Read every status as: the logic of the model is machine-checked; the model's fidelity to the code is audited, not checked. Sources: `verus-proofs/README.md` (T02, C01, C02, T01, T13) and `verus-proofs/README-t03-t05.md` (T03, T05). The T01 proof copies the C01 model unchanged and adds the KMS leg and other items; the statement of what is new is in the cross-branch section of `docs/mpl-verification-targets.md`. C03 has a different kind of status, described in the subsection after the canonical strings: in-crate, on the shipped prim code, on branch `Mahnush_Verus`, not on this branch. C02 is partly superseded by VR-008 on that branch.

| Target | Proof file | Result line (re-run) | Status | Assumptions |
|---|---|---|---|---|
| C01 | [`c01_ec_roundtrip.rs`](../../verus-proofs/c01_ec_roundtrip.rs) | `verification results:: 40 verified, 0 errors` | Proved (model level, not the shipped code, under stated hypotheses). | A_ITER (`custom.iter()` yields each key once; precondition of every builder theorem); A_STR; A_BLD; A_DDB and A_NAME for the `theorem_prod_*` results; T02 model copied into the file. |
| C02 | [`c02_sign_fixed_len.rs`](../../verus-proofs/c02_sign_fixed_len.rs) | `verification results:: 21 verified, 0 errors` | Proved (model level, not the shipped code, under stated hypotheses). | vstd `assume_specification` for `copy_from_slice` (A1); abstract signing closure (A3); `Backend` trait without contracts stands for aws-lc-rs (A4); ghost call log checked by hand (A5). |

Canonical status strings (the same text is in each YAML `proof_status` field and in the `Proof status` column):

- C01: Proved (model level, not the shipped code, under stated hypotheses): 40 verified, 0 errors
- C02: Proved (model level, not the shipped code, under stated hypotheses): 21 verified, 0 errors
- C03: Partly proved (in-crate, on the shipped prim code, on branch Mahnush_Verus, not on this branch, under trusted aws-lc-rs assumptions A1-A20): 18 verified, 0 errors
- C02, relation added (the C02 status string above is unchanged): Partly superseded by VR-008 (in-crate, on the shipped prim code, on branch Mahnush_Verus, not on this branch): retry bound, termination, guarded copy

**Scores are unchanged.** Scores, ranks, coverage gaps, feasibility, severity and the quick-wins list in this document record the pre-proof prioritization and were not changed by these proofs. A model-level proof is not a proof of the shipped code, and re-scoring would be arbitrary. Coverage gaps will be recalculated when a proof is linked to the shipped code (for example with `cargo verus` on the crate, or by moving the logic into `verus!`). The same holds for C03: its proof is on `Mahnush_Verus`, not on this branch, so C03 stays at 5.60, rank 3, coverage gap 0.7.

### C03: in-crate proof on branch Mahnush_Verus (not on this branch)

C03 has a different kind of proof from C01 and C02. Verus checks the real prim code, not a re-typed model. It lives on branch `Mahnush_Verus` of aws/aws-crypto-tools-rust (PR #103) as VR-013 (`hmac_core`, `digest_core`, `digest_finish_core`, `kbkdf_core`, `fill_random_core`, `ct_equal_core`) and VR-014 (the BUG-07 buffer facts in `aes_encrypt_core` and `aes_decrypt_core`), and is **not on this branch**: `prim/` here equals `main` `620771c` and has no Verus annotation. Nothing was merged, checked out or modified; the branch was read with `git fetch` and `git show`.

- Status: Partly proved (in-crate, on the shipped prim code, on branch Mahnush_Verus, not on this branch, under trusted aws-lc-rs assumptions A1-A20): 18 verified, 0 errors
- Result line: `verification results:: 18 verified, 0 errors` (crate aws-mpl-primitives). Re-run at `8d6381e` (the current tip; commits `ed4a81e` and `43b9ff7` hold VR-013 and VR-014, the later two are docs only) with `cargo verus verify` and with `cargo verus verify --no-default-features --features aws-lc-sys`, from `prim/`. Same count at `43b9ff7` in our earlier review (`.agents/tasks/review-vr013-vr014/report.md`, verdict "Consistent with gaps"). The 18 counts every verified function of the crate on that branch (VR-006, VR-008, VR-009 prim half, VR-013, VR-014); the base gave 10.
- Trusted base: 20 `assume_specification` (A1 to A20) about aws-lc-rs in `prim/src/aws_lc_specs.rs`, each assumed not to panic; no `assume`, `admit`, external function or `unsafe`. Our review judged all 20 TRUE for aws-lc-rs 1.18.1; the FIPS C side is unchecked.
- Gaps: `hkdf` and `hkdf_expand` "`Ok` implies `len(okm)` in 16, 24 or 32" and "no listed function panics" are not proved end to end (VR-009 proves only the decision functions); `DigestContext::digest`'s call to `finish` is unmodeled; adapters outside `verus!` (`format!` messages, `get_aes_alg`, the `DigestAlg` to `KbkdfCtrHmacAlgorithmId` match) are unproved; the `constant_time_equal` and `generate_random_bytes` proofs add little beyond A13 and A12; for BUG-07(a) the key/nonce `Err` buffer (`old ++ message`) and the seal-`Err` length and prefix are exported postconditions, but the `Ok`-case order `old ++ ciphertext ++ tag` is an in-body assert and the `+ 16` relies on A19, and the seal-`Err` tail bytes are not described; BUG-07(b) is assumption-relative (A20), not proved; zeroization is not covered.
- BUG-07 and BUG-10: the caller impact of BUG-07(a) (the plaintext data key left in the caller's buffer after an `aes_encrypt` `Err`) and BUG-10 (`RawAesKeyring::on_decrypt` drops an authenticated data key un-wiped) are code reading in mpl, tracked in T26, and are not proved by C03.

C02 and VR-008. The retry bound (at most 128 attempts), termination and the guarded `copy_from_slice` of `sign_fixed_len` are also proved on the real loop on `Mahnush_Verus` as VR-008. That content of C02 is superseded. C02 is not a duplicate and is not demoted: it remains the only statement of T1 as a postcondition, T3 (no partial write), T4 (which `Err` exits exist), T5 (`check_sig_len`), T6 (the `ecdsa_sign*` wrong-length contract) and the three non-vacuity witnesses. VR-008 has no `ensures`, and `check_sig_len` and `ecdsa_sign*` are outside `verus!` there. Recorded status of C02: Proved at model level (unchanged); partly superseded by VR-008 (in-crate, `Mahnush_Verus`). The cross-branch table and the full C03 tables are in `docs/mpl-verification-targets.md` ("Proofs written").

### Findings from the proofs

- **BUG-08 (C01).** The collision `Err` branch in `build_base` is dead if and only if A_ITER holds (a `BTreeMap` yields each key once), and live if a key repeats. Model level.
- **C02 assumption.** The no-partial-write claim relies on vstd's own `assume_specification` for `<[T]>::copy_from_slice`, listed in the proof's TCB.
- **C03 / BUG-07(a) (not on this branch).** On `Mahnush_Verus`, Verus proves in prim that a key or nonce `Err` of `aes_encrypt` leaves exactly `old ++ message` in the caller's buffer, and that a seal `Err` keeps the length `old + len(message)` and the prefix `old`. The `Ok`-case order is an in-body assert. BUG-07(b) is recorded relative to A20, not proved.
- **BUG-10 (Low, code reading).** `RawAesKeyring::on_decrypt` drops an authenticated plaintext data key un-wiped on the wrong-length path. It maps to TM-MPL-015 and T26, not to C03.

### Next steps for the proofs

- Link each proof to the shipped code (`cargo verus` on the crate, or move the logic into `verus!`), then recalculate its coverage gap.
- Add a CI step that runs the proof files and fails on any change to the result lines (T02 is expected to show `1 errors` until G1 is fixed).
- C03: decide how the in-crate prim proofs reach this branch (merge or port `prim/`); an owner decision, not done here.

## 0. What changed since a1e23d7

| ID | Change | Old score | New score | Reason |
|---|---|---|---|---|
| C04 | Rescored, expected outcome flipped | 5.60 | 2.80 | BUG-02 fixed (`e9bde48`): `check_data_key_length` (`mpl/src/structures/algorithm_suite.rs:547`) runs in both `add_data_key`s and both materials builders, and the hierarchical keyring now goes through `add_data_key` (`hierarchical_keyring.rs:767`). F1/F2 are gone; the proof is now expected to VERIFY. Direct tests exist, so gap 1.0 → 0.5. |
| C06 | **Retired** | 1.96 | — | Its code is gone. The Seconds/Milliseconds integer-division conversion in `HierarchicalKeyring::new` no longer exists. The check is now one `Duration` comparison, `cache.grace_period()` `>= ttl` (`hierarchical_keyring.rs:585`), which is exact by construction. |
| C07 | **New** | — | 5.04 | Materials transition / completeness checks (`mpl/src/structures/materials_checks.rs`, new in #167). |
| C08 | **New** | — | 0.96 | Usage-counter arithmetic now exists (`CacheEntry::record_use`, `mpl/src/cmc/entry.rs:206`, `checked_add` at `:213-214`). Previously rejected as R1 because no counter code existed; R1 is withdrawn. |
| C01, C02, C03, C05 | Location / name updates only | | unchanged | `keystore/` → `key_store/`; `prim` line shifts (error-message and guard edits). |

## 0.1 Repo facts re-confirmed for this step

- **No `unsafe` in `mpl/src` or `prim/src`** (`\bunsafe\b` has no match). Category 3 (low-level/unsafe) has no surface in `mpl`/`prim` any more. The shim's `unsafe` is threat-driven T25.
- **No raw C FFI** in `mpl`/`prim`; `prim` uses the aws-lc-rs safe API.
- **Interior mutability:** still only `std::sync::Mutex` (`cmc/local.rs`, `cmc/storm_tracking.rs`, `cmc/entry.rs` usage metadata).
- **Duvet:** one annotation (`mpl/src/cmc/entry.rs:201-205`), unchecked by any config. Gaps cite tests only.
- **`prim` is shared with the ESDK**, so a `prim` proof protects both crates.
- **Out of scope throughout:** cryptographic hardness, KMS/DynamoDB semantics, probabilistic secrecy.

## 1. Scoring conventions for capability-driven targets

`Priority = Severity × Coverage_Gap × Feasibility × Blast_Radius`.

| Factor | Rule |
|---|---|
| Severity (1–4) | Consequence of the latent defect the proof rules out. 4 = memory corruption / secret disclosure. 3 = silently wrong key material, key identity, suite or bound context. 2 = panic, hang, fail-closed availability loss, or a spec-MUST violation that downstream rejects. 1 = cosmetic. |
| Coverage_Gap (0–1) | Same scale as Step 1, including the new 0.4 level (near-exhaustive tests plus a runtime check enforcing the same property). |
| Feasibility (0–1) | Reachability. 1.0 = must hold for every argument of a public function. 0.7 = caller-chosen configuration or API input on a specific path. 0.4 = only if constant data or an internal invariant regresses, or no in-repo caller reaches it today. |
| Blast_Radius (1–4) | Same scale as Step 1. |

Ties: higher severity, then higher feasibility, then ID. Quick win: score > 6.0 and effort ≤ 1 week.

## 2. Summary table (ranked)

| Rank | ID | Score | Origin | Target | Property | Agent | Ref | Effort | Proof status |
|---|---|---|---|---|---|---|---|---|---|
| 1 | VR-2026-C01 | 6.72 | C | `key_store/encryption_context.rs` builders ∘ `key_store/record.rs` reconstruction | CreateKey ECs reconstruct to exactly (id, version, custom EC); collision branch dead (BUG-08); record→EC→record inverse | mpl-verus-header-parsing-proofs | cap:cat1 (1c) | 1 week (quick win) | Proved (model level, not the shipped code, under stated hypotheses): 40 verified, 0 errors |
| 2 | VR-2026-C02 | 6.40 | C | `prim::ecdsa` `sign_fixed_len`, `check_sig_len`, `ecdsa_sign*`, `ecdsa_verify*` | ≤ 128 `sign_once` calls; no panic; buffer written only with an exact-length candidate | mpl-verus-zero-panic | cap:cat2 (2d) | 1 week (quick win) | Proved (model level, not the shipped code, under stated hypotheses): 21 verified, 0 errors. Partly superseded by VR-008 (in-crate, on the shipped prim code, on branch Mahnush_Verus, not on this branch): retry bound, termination, guarded copy |
| 3 | VR-2026-C03 | 5.60 | C | `prim::{hmac, digest, aes_encrypt, aes_decrypt, hkdf*, kbkdf_ctr_hmac}`, `DigestContext::finish` | No panic on any input; exact Ok/Err length contract | mpl-verus-zero-panic | cap:cat2 (2a/2d) | 1 week | Partly proved (in-crate, on the shipped prim code, on branch Mahnush_Verus, not on this branch, under trusted aws-lc-rs assumptions A1-A20): 18 verified, 0 errors |
| 4 | VR-2026-C07 | 5.04 | C | `materials_checks::{check_encryption_transition, check_decryption_transition, check_*_materials_complete}` + `send()` wiring | Transition accepted iff the keyring only added a PDK (when absent) and EDKs; every fluent `send()` runs the check | mpl-verus-header-parsing-proofs | cap:cat1 (1a/1b) | 1 week | None yet |
| 5 | VR-2026-C04 | 2.80 | C | PDK length invariant (`check_data_key_length`, `add_data_key` ×2, materials `build` ×2, keyring producers) | Every materials PDK has the suite's `encryption_key_length` (expected to VERIFY) | mpl-verus-header-parsing-proofs | cap:cat1 (1a) | 1 week | None yet |
| 6 | VR-2026-C05 | 2.40 | C | `AlgorithmSuiteId::specification`, `id_bytes`, `verification_key_length` | Suite table refines spec; ids injective, never `00 00`; cross-crate length agreement | mpl-verus-header-parsing-proofs | cap:cat1 (1a) | 1 day | None yet |
| 7 | VR-2026-C08 | 0.96 | C | `CacheEntry::record_use` + `Cmc::update_usage_metadata` impls | Counters never wrap; both change together or neither; overflow deletes the entry | mpl-verus-zero-panic | cap:cat2 (2b) | 1 day | None yet |
| — | VR-2026-C06 | Retired | C | ~~`HierarchicalKeyring::new` grace-vs-TTL integer division~~ | — | — | — | — | None (retired) |

Quick wins: **C01**, **C02**.

Foundational: C03 is assumed by T04, T05, T07, T13. C01 links T01 and T02 end to end and is reused by T18. C07 supplies the keyring-frame lemma that T09 and T12 rely on.

## 3. Detailed recommendations (YAML)

```yaml
recommendation:
  id: VR-2026-C01
  rank: 1
  priority_score: 6.72
  origin: capability-driven
  target:
    crate: aws-crypto-mpl
    file: mpl/src/key_store/encryption_context.rs; mpl/src/key_store/record.rs
    function: >
      encryption_context::{build_base (:40, private; collision Err :95-101), active_encryption_context (:117),
      decrypt_only_encryption_context (:137), beacon_key_encryption_context (:160)};
      record::{branch_key_materials_from_authenticated_encryption_context (:95),
      custom_encryption_context_from_authenticated_encryption_context (:79),
      encryption_context_from_item (:37, test-utils), to_attribute_map (:61, test-utils)};
      production pair: create_key builders (branch_key_store.rs:569-572) and get_* reconstruction (:814, :852, get_beacon_key :868)
  property: >
    (a) For every accepted CreateKey input with non-empty branch_key_id, non-empty version v and a UTF-8
    custom EC C, reconstructing the ACTIVE or DECRYPT_ONLY EC with a 32-byte plaintext returns materials
    with exactly that id, v and C; a beacon EC returns Err. (b) Prefixing and stripping of
    `aws-crypto-ec:` are exact inverses. (c) The "collides after prefixing" Err in build_base is
    unreachable (BUG-08, confirmed open). (d) to_attribute_map(encryption_context_from_item(r, n), r.enc) == r
    iff r has no "tablename"/"enc" attribute.
  formal_spec: |
    proof fn builder_reconstruction_round_trip(input, v, pt)
      requires input.branch_key_id@.len() > 0, v.len() > 0, pt.len() == 32, utf8_ok(custom(input))
      ensures forall|ec| active_encryption_context(&input, v) == Ok(ec) || decrypt_only_encryption_context(&input, v) == Ok(ec)
                ==> branch_key_materials_from_authenticated_encryption_context(&ec, pt) matches Ok(m)
                    && m.branch_key_id@ == input.branch_key_id@ && m.branch_key_version@ == v && m.encryption_context@ == custom_or_empty(input)@
    fn build_base(input, t) -> (r) ensures r matches Err(e) ==> !(e.message()@.contains("collides"@))
    proof fn record_reverse(r, n) ensures (to_attribute_map(&encryption_context_from_item(&r, n), r.enc) == r)
                                     <==> (!r.attributes@.contains_key("tablename"@) && !r.attributes@.contains_key("enc"@))
  tool: Verus
  agent: mpl-verus-header-parsing-proofs
  estimated_effort: 1 week
  threat_references: []
  capability_reference:
    category: 1          # 1c round trip, 1b Map refinement
    invariant: >
      Key-store EC builders and the reconstruction decoder are exact inverses on (branch-key-id, version,
      custom EC); the collision branch is dead; record↔EC conversion is the identity off "tablename"/"enc".
  trace_to_spec: >
    spec/framework/branch-key-store.md#encryption-context, #active-encryption-context, #decrypt_only-encryption-context,
    #beacon-key-encryption-context, #record-format
  coverage_gap: 0.8
  coverage_evidence: >
    mpl/tests/test_key_store_encryption_context.rs (17 tests, builders alone, e.g. active_is_decrypt_only_with_type_and_version_overrides :214);
    mpl/tests/test_key_store_record.rs (23 tests, reconstruction on hand-built maps; item_encryption_context_round_trips :306 is EC→record→EC only).
    No test composes them, reaches the collision branch, or covers record→EC→record.
  rationale: |
    A silent mismatch returns materials whose custom EC differs from what was stored, and no cryptographic
    check catches it because stripping happens after KMS authentication. (d) now concerns test-utils-only
    helpers, so it is lower value than (a)–(c); kept for completeness. Unchanged score.
  scoring:
    severity: 3
    coverage_gap: 0.8
    feasibility: 0.7
    blast_radius: 4
    product: "3 × 0.8 × 0.7 × 4 = 6.72"
  quick_win: true
  proof_status: "Proved (model level, not the shipped code, under stated hypotheses): 40 verified, 0 errors"
  proof_file: verus-proofs/c01_ec_roundtrip.rs
  dependencies: [VR-2026-T02]
```

```yaml
recommendation:
  id: VR-2026-C02
  rank: 2
  priority_score: 6.40
  origin: capability-driven
  target:
    crate: aws-mpl-primitives
    file: prim/src/ecdsa.rs
    function: >
      sign_fixed_len (:180, private; copy_from_slice :188); MAX_SIGN_ATTEMPTS (:148); check_sig_len (:200);
      ecdsa_sign (:224); ecdsa_sign_digest (:253); ecdsa_verify (:282); ecdsa_verify_context (:305)
  property: >
    sign_fixed_len calls sign_once at most 128 times and always returns; copy_from_slice runs only on an
    exact-length candidate; on Err the buffer is unmodified. ecdsa_sign / ecdsa_sign_digest return Err unless
    |signature| == signature_len(alg) and never panic. ecdsa_verify / ecdsa_verify_context never return Err.
  formal_spec: |
    fn sign_fixed_len(signature: &mut [u8], sign_once) -> (r)
      ensures ghost_calls <= 128
      ensures r.is_Ok() ==> exists|i| ghost_cand[i]@.len() == old(signature)@.len() && signature@ == ghost_cand[i]@
      ensures r.is_Err() ==> signature@ == old(signature)@
    fn check_sig_len(alg, s) -> (r) ensures r.is_Ok() <==> s@.len() == signature_len(alg)
    fn ecdsa_verify(alg, key, msg, sig) -> (r) ensures r.is_Ok()
  tool: Verus
  agent: mpl-verus-zero-panic
  estimated_effort: 1 week
  threat_references: []
  capability_reference:
    category: 2          # 2d total error handling + bounded termination
    invariant: "The ECDSA signing retry loop terminates after ≤ 128 attempts on every input, never panics, and writes the caller's buffer only with an exact-length signature."
  trace_to_spec: "spec/framework/algorithm-suites.md#asymmetric-signature-algorithm; baseline assurance, no single MPL clause"
  coverage_gap: 0.8
  coverage_evidence: "prim/tests/test_ecdsa.rs (e.g. test_ecdsa_sign_rejects_wrong_length_buffer :143). sign_fixed_len's oracle cannot be injected, so retry exhaustion and no-partial-write are untested."
  rationale: "Latent-hang shape on the default encrypt path (0x0578 is the REQUIRE_* default). The 2^-128 exhaustion probability is excluded. Unchanged."
  scoring:
    severity: 2
    coverage_gap: 0.8
    feasibility: 1.0
    blast_radius: 4
    product: "2 × 0.8 × 1.0 × 4 = 6.40"
  quick_win: true
  proof_status: "Proved (model level, not the shipped code, under stated hypotheses): 21 verified, 0 errors"
  proof_file: verus-proofs/c02_sign_fixed_len.rs
  proof_note: "Partly superseded by VR-008 (in-crate, on the shipped prim code, on branch Mahnush_Verus, not on this branch): the retry bound (at most 128 attempts), termination and the guarded copy_from_slice are also proved on the real loop (sign_fixed_len_core). This target stays the only statement of T1 as a postcondition (at most 128 closure calls), T3 (no partial write: Err leaves the buffer unchanged, Ok writes one whole candidate), T4 (which Err exits exist), T5 (check_sig_len), T6 (ecdsa_sign* wrong-length contract) and the three non-vacuity witnesses. The status above is unchanged. It is not a duplicate and is not demoted."
  dependencies: []
```

```yaml
recommendation:
  id: VR-2026-C03
  rank: 3
  priority_score: 5.60
  origin: capability-driven
  target:
    crate: aws-mpl-primitives
    file: prim/src/lib.rs; prim/src/ecdsa.rs; prim/src/hkdf.rs
    function: >
      hmac (lib.rs:241; copy :260); digest (:272; copy :285); aes_encrypt (:175; slice :186); aes_decrypt (:206; guard :215);
      kbkdf_ctr_hmac (:313); DigestContext::finish (ecdsa.rs:82; copy :90); hkdf (hkdf.rs:46); hkdf_no_salt (:76; slice :84); hkdf_expand (:101)
  property: >
    No listed function panics for any arguments. hmac/digest/finish return Err unless |out| equals the
    output length, and only then copy. aes_encrypt's `&mut cipher_text[old_size..]` is in range and Ok ⇒
    |ct| = old + |msg| + 16. aes_decrypt Ok ⇒ |pt| == |ct|. hkdf_no_salt's `&salt[..sz]` is in range.
    hkdf/hkdf_expand Ok ⇒ |okm| ∈ {16, 24, 32}.
  formal_spec: |
    fn hmac(alg, key, msg, out) -> (r) ensures r.is_Ok() <==> out@.len() == get_digest_alg(alg).output_len()
    fn digest(alg, data, out) -> (r) ensures r.is_Ok() <==> out@.len() == get_digest_alg(alg).output_len()
    fn aes_encrypt(alg, iv, key, msg, aad, ct) -> (r) ensures r.is_Ok() ==> ct@.len() == old(ct)@.len() + msg@.len() + 16
    fn aes_decrypt(alg, key, ct, tag, iv, aad, pt) -> (r) ensures r.is_Ok() ==> pt@.len() == ct@.len()
  tool: Verus
  agent: mpl-verus-zero-panic
  estimated_effort: 1 week
  threat_references: []
  capability_reference:
    category: 2          # 2a slice bounds, 2d length-checked copy_from_slice
    invariant: "No reachable panic path in the prim crypto wrappers; each Ok implies an exact output length (decrypt: |pt| == |ct|)."
  trace_to_spec: "supports spec/framework/algorithm-suites.md lengths; baseline assurance, no single clause"
  coverage_gap: 0.7
  coverage_evidence: >
    prim/tests: test_hmac.rs::test_hmac_rejects_wrong_length_output_buffer (:111), test_aes.rs::test_aes_decrypt_output_buffer_too_small (:138),
    digest/hkdf/kbkdf negative-length tests. Gaps unchanged: no wrong-length buffer to DigestContext::finish, no over-long aes_decrypt buffer.
  rationale: |
    hmac and digest now take the length from the aws-lc algorithm (lib.rs:244-248, :274-278) so a table
    disagreement surfaces as Err, not a panic; that simplifies the proof. Expected finding unchanged (BUG-07b):
    prim's aes_decrypt guard rejects only |pt| < |ct| (:215) and maps every callee error to "authentication tag
    did not match", while aws-lc-rs rejects any |pt| ≠ |ct|.
  scoring:
    severity: 2
    coverage_gap: 0.7
    feasibility: 1.0
    blast_radius: 4
    product: "2 × 0.7 × 1.0 × 4 = 5.60"
  quick_win: false
  proof_status: "Partly proved (in-crate, on the shipped prim code, on branch Mahnush_Verus, not on this branch, under trusted aws-lc-rs assumptions A1-A20): 18 verified, 0 errors"
  proof_location: "Branch Mahnush_Verus of aws/aws-crypto-tools-rust (PR #103), VR-013 (hmac_core, digest_core, digest_finish_core, kbkdf_core, fill_random_core, ct_equal_core) and VR-014 (BUG-07 buffer facts in aes_encrypt_core, aes_decrypt_core). NOT on MPL-Verus: prim/ here equals main 620771c and has no Verus annotation. Commits ed4a81e (feat) and 43b9ff7 (docs); tip read 8d6381e (the later commits change docs only)."
  proof_result: "verification results:: 18 verified, 0 errors (aws-mpl-primitives), from `cargo verus verify` (default features) and `cargo verus verify --no-default-features --features aws-lc-sys` in prim/, re-run at 8d6381e; same count at 43b9ff7 in our earlier review. 18 counts every verified function in the prim crate on that branch (VR-006, VR-008, VR-009 prim half, VR-013, VR-014); the base 6b51de8 gave 10."
  proof_trusted_base: "20 assume_specification (A1-A20) about aws-lc-rs in prim/src/aws_lc_specs.rs, each assumed not to panic; no assume, admit, external fn or unsafe. All judged TRUE for aws-lc-rs 1.18.1 by our review; the FIPS C side is unchecked."
  proof_not_covered: >
    hkdf and hkdf_expand "Ok implies len(okm) in {16, 24, 32}" and "no listed function panics" end to end (VR-009 proves only the decision functions);
    DigestContext::digest's call to finish; adapters outside verus! (format! messages, get_aes_alg, the DigestAlg to KbkdfCtrHmacAlgorithmId match);
    constant_time_equal and generate_random_bytes add little beyond assumptions A13 and A12; BUG-07(a): key/nonce Err buffer = old ++ message and seal-Err length and prefix
    are exported ensures, but the Ok-case order "old ++ ciphertext ++ tag" is an in-body assert and +16 relies on A19, and seal-Err tail bytes are not described;
    BUG-07(b) is assumption-relative (A20, A-OPEN), not proved; nothing about zeroization.
  related_bugs:
    - {bug: "BUG-07(a)", evidence: "prim-side buffer facts proved in-crate on Mahnush_Verus (VR-014); caller impact is code reading", threat: TM-MPL-015, target: "T26 (F2), T07 (e)"}
    - {bug: "BUG-07(b)", evidence: "recorded, relative to assumption A20, not proved", threat: TM-MPL-023, target: C03}
    - {bug: BUG-10, evidence: "code reading", threat: TM-MPL-015, target: T26, note: "not part of C03: the buffers are in mpl, not prim"}
  dependencies: []
```

```yaml
recommendation:
  id: VR-2026-C07
  rank: 4
  priority_score: 5.04
  origin: capability-driven
  target:
    crate: aws-crypto-mpl
    file: mpl/src/structures/materials_checks.rs; mpl/src/keyring/fluent_builders.rs; mpl/src/cmm/fluent_builders.rs
    function: >
      check_encryption_materials (:18); check_decryption_materials (:37); check_encryption_transition (:72);
      check_decryption_transition (:117); check_encryption_materials_complete (:157); check_decryption_materials_complete (:177);
      wiring: SharedKeyring on_encrypt/on_decrypt send() (keyring/fluent_builders.rs:82, :163),
      SharedCmm get_encryption_materials/decrypt_materials send() (cmm/fluent_builders.rs:171, :319)
  property: >
    (a) check_encryption_transition(old, new) is Ok exactly when both pass check_encryption_materials, the
    suite, EC, required EC keys and signing key are unchanged, new has a PDK, an existing old PDK is unchanged
    (ct_eq), and new's EDKs contain all of old's. (b) check_decryption_transition(old, new) is Ok exactly when
    old has no PDK, suite / EC / required EC keys / verification key are unchanged and new has a PDK.
    (c) The *_complete checks are Ok exactly when the PDK (and for encrypt ≥ 1 EDK) is present and the base
    check passes. (d) Every SharedKeyring / SharedCmm send() returns Ok only if the corresponding check
    returned Ok. The proof must state the fields the transition does NOT constrain (e.g.
    symmetric_signing_keys are not compared in check_encryption_transition, :72-106; EDK order is not
    checked, only containment) so they can be compared with Dafny `Materials.dfy` by the owner.
  formal_spec: |
    spec fn valid_enc_transition(o: EncMat, n: EncMat) -> bool {
        base_ok_e(o) && base_ok_e(n) && n.suite == o.suite && n.ec == o.ec && n.reck == o.reck && n.sk == o.sk
        && n.pdk.is_some() && (o.pdk matches Some(k) ==> n.pdk == Some(k)) && o.edks.to_set().subset_of(n.edks.to_set()) }
    fn check_encryption_transition(o, n) -> (r) ensures r.is_Ok() <==> valid_enc_transition(o@, n@)
    fn check_decryption_transition(o, n) -> (r) ensures r.is_Ok() <==> valid_dec_transition(o@, n@)
    // wiring (pure fragment of the async send()):
    ensures send_result.is_Ok() ==> valid_enc_transition(before@, output.materials@)
  tool: Verus
  agent: mpl-verus-header-parsing-proofs
  estimated_effort: 1 week
  threat_references: []
  capability_reference:
    category: 1          # 1a pre/post adherence, 1b refinement of the Dafny transition predicates
    invariant: >
      On every fluent path a keyring can only add a plaintext data key (when none exists) and encrypted data
      keys; it cannot change the suite, encryption context, required keys or signing/verification key.
  trace_to_spec: >
    spec/framework/keyring-interface.md#onencrypt, #ondecrypt; spec/framework/cmm-interface.md#get-encryption-materials,
    #decrypt-materials; spec/framework/structures.md (encryption / decryption materials)
  coverage_gap: 0.6
  coverage_evidence: >
    mpl/tests/test_materials_checks.rs (27 tests, new), e.g. on_encrypt_rejects_a_changed_algorithm_suite (:271),
    on_encrypt_rejects_a_changed_encryption_context (:281). Broad example coverage; no exhaustive field-by-field statement.
  rationale: |
    New code (#167) that now carries part of the commitment-policy and EC-binding argument (T09, T12). A
    silent gap would let any keyring passed through SharedKeyring (including user keyrings) swap the suite
    or EC without detection. The checks are pure comparisons over small structs, a good Verus fit. Bypass by
    calling a Keyring/Cmm trait impl directly is the caller's choice and is excluded.
  scoring:
    severity: 3          # silently changed suite / bound context
    coverage_gap: 0.6
    feasibility: 0.7     # any caller-supplied keyring reaches it through send()
    blast_radius: 4      # every MPL and ESDK path goes through send()
    product: "3 × 0.6 × 0.7 × 4 = 5.04"
  quick_win: false       # score < 6.0
  proof_status: "None yet"
  dependencies: []
```

```yaml
recommendation:
  id: VR-2026-C04
  rank: 5
  priority_score: 2.80
  origin: capability-driven
  target:
    crate: aws-crypto-mpl
    file: >
      mpl/src/structures/algorithm_suite.rs; mpl/src/structures/encryption_materials.rs; mpl/src/structures/decryption_materials.rs;
      mpl/src/keyring/raw_aes_keyring.rs; mpl/src/aws_kms/hierarchical_keyring.rs
    function: >
      check_data_key_length (algorithm_suite.rs:547); EncryptionMaterials::add_data_key (encryption_materials.rs:48, check :60),
      EncryptionMaterialsBuilder::build (:358, check :365); DecryptionMaterials::add_data_key (decryption_materials.rs:45, check :56),
      DecryptionMaterialsBuilder::build (:295, check :303); generate_random_data_key (raw_aes_keyring.rs:535, hierarchical_keyring.rs:975);
      raw-AES on_decrypt length check (:489); hierarchical on_decrypt add_data_key (:767), on_encrypt add_data_key (:727)
  property: >
    pdk_ok(m): a present plaintext data key has length == suite encryption_key_length. Every materials value
    that exists satisfies pdk_ok, because every constructor and every PDK-adding method checks it.
    EXPECTED TO VERIFY on 620771c (BUG-02 fixed); the previous F1/F2 failures no longer exist.
  formal_spec: |
    spec fn pdk_ok(m) -> bool { m.plaintext_data_key matches Some(k) ==> k@.len() == m.algorithm_suite_id.specification().encryption_key_length() }
    fn check_data_key_length(s, k) -> (r) ensures r.is_Ok() <==> k@.len() == s.encryption_key_length()
    fn EncryptionMaterialsBuilder::build(self) -> (r) ensures r matches Ok(m) ==> pdk_ok(m)
    fn add_data_key(self, k, ..) -> (r) requires pdk_ok(self) ensures r matches Ok(m) ==> pdk_ok(m)
    fn generate_random_data_key(s) -> (r) ensures r matches Ok(k) ==> k@.len() == s.encryption_key_length()
  tool: Verus
  agent: mpl-verus-header-parsing-proofs
  estimated_effort: 1 week
  threat_references: []
  capability_reference:
    category: 1          # 1a struct invariant
    invariant: "Every EncryptionMaterials / DecryptionMaterials value with a plaintext data key has exactly the suite's encryption-key length."
  trace_to_spec: >
    spec/framework/keyring-interface.md#generate-data-key; spec/framework/structures.md#plaintext-data-key;
    spec/framework/algorithm-suites.md#encryption-key-length
  coverage_gap: 0.5
  coverage_evidence: >
    test_encryption_materials.rs::{test_add_data_key_rejects_wrong_length (:429), test_build_rejects_wrong_length_plaintext_data_key (:456)};
    test_decryption_materials.rs::{test_add_data_key_rejects_wrong_length (:401), test_build_rejects_wrong_length_plaintext_data_key (:413)}.
  rationale: |
    Rescored after BUG-02 fix. The value is now regression-proofing a struct invariant that the ESDK relies on
    (esdk/src/key_derivation.rs:79 still re-checks). Severity unchanged; gap drops because the boundary is
    directly tested at all four entry points.
  scoring:
    severity: 2
    coverage_gap: 0.5
    feasibility: 0.7
    blast_radius: 4
    product: "2 × 0.5 × 0.7 × 4 = 2.80"
  quick_win: false
  proof_status: "None yet"
  dependencies: []
```

```yaml
recommendation:
  id: VR-2026-C05
  rank: 6
  priority_score: 2.40
  origin: capability-driven
  target:
    crate: aws-crypto-mpl (+ aws-mpl-primitives constants)
    file: mpl/src/structures/algorithm_suite.rs; prim/src/lib.rs; prim/src/ecdsa.rs
    function: AlgorithmSuiteId::{specification, id_bytes, has_asymmetric_signing, has_symmetric_signing}; AlgorithmSuite::verification_key_length; prim::AesGcm key length; prim::field_size; prim::signature_len
  property: >
    For all 11 suites, specification() equals the algorithm-suites.md row. Lemmas: id_bytes injective and never
    00 00; key length ∈ {16,24,32} and equal to the matching AES key length; commit_kdf ⟺ format v2 ⟺ suite data 32;
    verification_key_length == prim::field_size (33/49); has_symmetric_signing false for every ESDK suite.
  formal_spec: |
    fn specification(self) -> (s) ensures s == row(self)
    proof fn ids_injective(a, b) requires a.id_bytes() == b.id_bytes() ensures a == b
    proof fn vk_len_matches_prim(a) ensures a.specification().verification_key_length() == a.specification().asymmetric_signature_algorithm().map(prim_field_size)
  tool: Verus
  agent: mpl-verus-header-parsing-proofs
  estimated_effort: 1 day
  threat_references: []
  capability_reference:
    category: 1
    invariant: "The suite table is exactly the spec table; ids are unique and non-reserved; its lengths agree with prim's constants."
  trace_to_spec: "spec/framework/algorithm-suites.md#supported-algorithm-suites-enum, #encryption-key-length, #algorithm-suite-id"
  coverage_gap: 0.5
  coverage_evidence: "mpl/tests/test_algorithm_suite_id.rs (22 tests, e.g. test_hex_ids_are_unique_across_all_suites :97, test_reserved_id_00_00_is_not_used :111). Cross-crate agreement untested."
  rationale: "Cheap regression-proofing; supplies the 'suite key length is a valid AES key length' lemma for C03/C04/T07. Unchanged."
  scoring:
    severity: 3
    coverage_gap: 0.5
    feasibility: 0.4
    blast_radius: 4
    product: "3 × 0.5 × 0.4 × 4 = 2.40"
  quick_win: false
  proof_status: "None yet"
  dependencies: []
```

```yaml
recommendation:
  id: VR-2026-C08
  rank: 7
  priority_score: 0.96
  origin: capability-driven
  target:
    crate: aws-crypto-mpl
    file: mpl/src/cmc/entry.rs; mpl/src/cmc/local.rs; mpl/src/cmc/mod.rs
    function: >
      CacheEntry::record_use (entry.rs:206; checked_add :213-214; Duvet implication :201-205);
      Cmc::update_usage_metadata contract (mod.rs:79) and LocalCmc impl (local.rs:326)
  property: >
    record_use(bytes) returns true and increments messages_used by 1 and bytes_used by bytes, or returns
    false and leaves both unchanged; neither counter ever wraps. Both counters change under one lock
    acquisition (the Duvet "atomic" implication). update_usage_metadata deletes the entry exactly when
    record_use returns false and does nothing when there is no entry.
  formal_spec: |
    fn record_use(&self, bytes: u64) -> (r: bool)
      ensures r ==> self.usage@ == UsageMetadata { messages_used: old.messages_used + 1, bytes_used: old.bytes_used + bytes }
      ensures !r ==> self.usage@ == old(self).usage@ && (old.messages_used == u64::MAX || old.bytes_used + bytes > u64::MAX)
    fn update_usage_metadata(&self, input) -> (r) ensures entry_deleted(input.identifier) <==> ghost_record_use_returned_false
  tool: Verus
  agent: mpl-verus-zero-panic
  estimated_effort: 1 day
  threat_references: []
  capability_reference:
    category: 2          # 2b integer overflow freedom
    invariant: "Cache usage counters never overflow or update partially; overflow evicts the entry."
  trace_to_spec: "spec/framework/cryptographic-materials-cache.md#usage-metadata, #update-usage-metadata"
  coverage_gap: 0.6
  coverage_evidence: "mpl/tests/test_local_cmc.rs::test_update_usage_metadata_deletes_entry_on_overflow (:729) and the other usage-metadata tests added since a1e23d7."
  rationale: |
    New code; replaces the old R1 rejection ("no counter arithmetic exists"). Low priority because no in-repo
    component calls update_usage_metadata (the hierarchical keyring caches only branch keys and there is no
    caching CMM), but a future caching CMM would enforce its usage limits through exactly this code.
  scoring:
    severity: 2          # wrap would let a future caching CMM exceed its usage limits
    coverage_gap: 0.6
    feasibility: 0.4     # no in-repo caller today
    blast_radius: 2      # Cmc API users only
    product: "2 × 0.6 × 0.4 × 2 = 0.96"
  quick_win: false
  proof_status: "None yet"
  dependencies: []
```

```yaml
recommendation:
  id: VR-2026-C06
  status: Retired
  retired_in: 620771c refresh
  previous_score: 1.96
  origin: capability-driven
  former_target: "HierarchicalKeyring::new storm-tracking grace-vs-TTL check with Seconds/Milliseconds integer division (was hierarchical_keyring.rs:178-190 at a1e23d7)"
  reason: >
    Code gone. HierarchicalKeyring::new and the StormTrackingCache/TimeUnits configuration were replaced by
    builders that take Duration. The check is now `if let Some(grace_period) = cache.grace_period() && grace_period >= ttl`
    (hierarchical_keyring.rs:584-585), a single Duration comparison with no unit conversion, division or
    overflow risk. Nothing non-trivial is left to prove. The remaining risk (a user Cmc returning
    grace_period() = None skips the check) is a trusted-caller note under TM-MPL-010, not a code property.
  successor: none
  proof_status: "None (retired)"
```

## 4. Overlaps with Step 1

The Stage 2' sweep produced each candidate below, but a Step 1 target already scopes it.

| Capability candidate (category) | Step 1 target | Overlap | What the capability view adds |
|---|---|---|---|
| Secret buffers wiped on every exit path (cat 3a analogue, no `unsafe` left) | **T26** | Full | Category 3 no longer has an `unsafe` surface in `mpl`/`prim`; the capability view only adds that the `zeroize` crate's derive is TCB. The old T08 overlap row is retired with T08. Two residual sites added to T26 at `9955ecd` fall outside every C target: expired `LocalCmc` entries stay resident until read (`mpl/src/cmc/local.rs:131`, `:166`; C08 and T23 do not scope them) and `ecdsa_generate_keypair` leaves the private-key `Vec` un-wiped on its error return (`prim/src/ecdsa.rs:387`, `:391-392`; C02 does not list `ecdsa_generate_keypair`). Also in T26 and outside every C target: BUG-10 (the raw-AES `on_decrypt` wrong-length path, `raw_aes_keyring.rs:489-494`, and `branch_key_wrap::unwrap`'s plain `Vec<u8>`, `:275`), and the BUG-07(a) caller impact at `wrap_data_key` and `branch_key_wrap::wrap`; the buffers are in `mpl`, which no C target covers. |
| `EncryptionContext::{to_bytes, from_bytes}` canonical codec (cat 1c) | **T15**, **T16** | Full | With BUG-03 fixed, the Vest non-malleability shape is now the expected theorem, not a counterexample. |
| `record.rs` `to_attribute_map` / `encryption_context_from_item` (cat 1c) | **T01** | Partial | Reverse direction stays in C01(d); both helpers are now `test-utils` only. |
| `branch_key_materials_from_authenticated_encryption_context` (cat 1a) | **T02** | Full for the decoder | C01 reuses T02's spec. |
| `SystemTime + Duration` adds (`hierarchical_keyring.rs:702`, `:945`; `storm_tracking.rs:333`, `:680`) (cat 2b) | **T06** | Full | Still the only arithmetic panic sites in `cmc/` besides the new counter code (C08, which uses `checked_add`). Subtraction is total: `within_grace_period` uses `checked_sub` (`storm_tracking.rs:667-668`), `duration_since` mapped with `unwrap_or(Duration::ZERO)`, `prune_tail` uses `min` (`local.rs:167`). |
| `StormTrackingCmcBuilder::build` constraints; grace formulas (cat 1a/2b) | **T21** (a) | Full | Property (a) is expected FAIL: `build` enforces `fan_out ≥ 1`, `in_flight_ttl > 0`, `sleep > 0` and Grace Interval ≤ Inflight TTL (`storm_tracking.rs:613`, `:616`, `:619`, `:622`) but not the spec's Grace Interval ≤ Grace Period, Inflight TTL ≤ Grace Period or "at least 1" bounds. It is a cheap slice (about a day) of the one-month T21 and needs the owner to choose the minimum first. No C sibling: see the Refresh note and R17 |
| `LocalCmc` capacity and prune (cat 2b) | **T23** | Full | — |
| Storm-tracking concurrency (cat 4a/4b) | **T21** | Full | Concurrency specialist hand-off unchanged. T21 now also lists (g) a stale in-flight mark never cleared after a failed refresh, (h) a fan-out-full waiter with no deadline (`storm_tracking.rs:313`) and (i) a panic under the state lock that poisons it; all three are expected FAIL and are stated over the pure classify step. |
| `cache_entry_within_limits` (cat 1a) | **T14** (b) | Full | Truncation note withdrawn (BUG-09 fixed, full `Duration` compare at `:994`). |
| KBKDF fixed-info (cat 1d) | **T05** | Full | — |
| `prim::aes_*` caller preconditions (cat 3b) | **T07** | Partial | C03 keeps the unconditional half. VR-014 (on `Mahnush_Verus`, not on this branch) proves the prim-side buffer facts of BUG-07; the caller side (what mpl and the ESDK do with the buffer) stays with T26 and T07 (code reading). |
| Commitment-policy tables (cat 1a) | **T09** | Partial | C05 covers the rest of the suite table; C07 supplies the keyring-frame lemma. |
| MPL `.expect` / slice / index sites (cat 2a/2d) | **T16** (and T17 for `parse_arn`) | Full | — |
| `ecdsa_generate_keypair(..).expect` (`default_cmm.rs:138`) | **T16** | Full | Expected-unprovable (BUG-05a). |
| Shim raw-handle dereferences (cat 3b) | **T25** | Full for the Rust side | Outside `mpl`/`prim`; same agent. Citations at `9955ecd`: `require_handle` `esdk/shims/aws-esdk-cpp/src/lib.rs:715`, deref `:728`, nullable client handles `:1570-1571`, cache handle `:1661` (moved by #188). The type-erased path is also in T25: `into_keyring_handle` (`lib.rs:2059`) returns a non-null unique `Box` (provable), while C++ `Keyring::adopt` (`EncryptionSDK.cpp:541-547`) calls `from_raw` with no null, type or ownership check. That half is a caller obligation outside the proof (01 §4, TM-MPL-024) |
| Bounded work in the `HierarchicalKeyring::on_decrypt` EDK loop (cat 2d bounded termination) | **T27** | Full | The loop (`hierarchical_keyring.rs:751-772`) and the per-version key-store read (`:934`, `:947`) are the only unbounded-by-constant work on the decrypt path. T27 states key-store calls and iterations as a function of the EDK list (verifies) and the absence of a constant bound (expected FAIL). Provisional until a reproducer for TM-MPL-025 exists |
| Branch key record MUST include `create-time` and `hierarchy-version`, otherwise the operation MUST fail (cat 1a; completeness audit G1) | **T02** | Full for the decoder | The clause is part of T02's Ok/Err characterization (expected FAIL on read). C01 only covers records produced by the CreateKey builders, which always write both attributes (`key_store/encryption_context.rs:67`, `:77`), so it neither needs nor reuses the clause |

## 5. Considered and rejected

| # | Candidate | Reason |
|---|---|---|
| R1 | ~~Cache usage-counter overflow~~ | **Withdrawn**: counter code now exists and is target C08. |
| R2 | `constant_time_equal` / `ct_eq` is constant-time (`prim/src/lib.rs:291`; `algorithm_suite.rs:541`, `:607`, `:691`) | Verus does not model timing. |
| R3 | RNG output quality; partition-id / IV / salt uniqueness | Probabilistic. |
| R4 | `sign_fixed_len` exhaustion probability ≤ 2^-128 | Probabilistic; only the termination bound is in C02. |
| R5 | Security of AES-GCM, ECDSA, HMAC, HKDF, KBKDF, SHA-384 | Cryptographic hardness. |
| R6 | Termination of error-chain walks over `dyn Error::source()` (`find_source`, `mpl/src/error.rs`) | Depends on third-party trait objects being acyclic. |
| R7 | Raw C-FFI soundness inside aws-lc-rs | Third-party TCB. |
| R8 | Interior-mutability / custom lock protocols | Only `std::sync::Mutex`; the one protocol is T21. |
| R9 | `DigestContext::new` / `new_from_ecdsa` always Ok; trivial matches | No proof content beyond C05. |
| R10 | `Duration` setters in builders | Total; nothing to prove. |
| R11 | Zeroize-on-drop of long-lived secret types | Now implemented by the `zeroize` derive and manual `Drop` (`raw_aes_keyring.rs:73-78`, `:234-239`); the crate is TCB. Residual transient buffers are T26. |
| R12 | `wait_for_leader` under a non-Tokio executor | Runtime requirement. |
| R13 | Allocation failure in `extend_from_slice` | Allocator outside Verus's model. |
| R14 (new) | Builder getter/setter consistency (`mpl/src/builder.rs`, `test_builder_getters.rs`) | Plumbing with no security property; tested. |
| R15 (new) | Cargo feature-combination equivalence (`kms`, `ddb`, `rt-tokio`, `fips`, …) | Configuration, not a code property; each proof must name its feature set instead. |
| R16 (new) | Generated error code (`mpl/src/error/generated.rs`, `prim/src/error/generated.rs`) | Generated data types; redaction of error data is in T22. |
| R17 (new, `9955ecd`) | Capability sibling of T21 (a): `StormTrackingCmcBuilder::build` lower-bound and ordering constraints (Inflight TTL ≤ Grace Period, Grace Interval ≤ Grace Period, "at least 1") | Already target T21 (a), expected FAIL. The bound is undefined until the owner picks the minimum (spec time unit versus `Duration`; the spec's default Inflight TTL breaks its own ordering). A sibling would score 2.52 (2 × 0.9 × 0.7 × 2) and would not address BUG-01. See the Refresh note |

## 6. Findings recorded, not changed

- C01(c): BUG-08 dead collision `Err` in `build_base` (`key_store/encryption_context.rs:95-101`), still present.
- C03: BUG-07(b) `aes_decrypt` guard weaker than its callee; misleading error text (`prim/src/lib.rs:215`, error mapping after the callee). Recorded, not proved: the VR-014 core states it relative to A20 on `Mahnush_Verus`. The BUG-07(a) prim-side buffer facts are proved there (partly proved, not on this branch).
- T26, not a C target: BUG-10 (Low, code reading) `RawAesKeyring::on_decrypt` drops an authenticated plaintext data key un-wiped when its length is wrong (`raw_aes_keyring.rs:489-494`); `branch_key_wrap::unwrap` holds a plain `Vec<u8>` (`:275`).
- C07: fields not constrained by `check_encryption_transition` (symmetric signing keys; EDK order) should be compared with Dafny `Materials.dfy` by the owner.
- C04-F1 / C04-F2 from the previous run: **closed** by BUG-02 fix.
- T21 (a), not a C target: `StormTrackingCmcBuilder::build` no longer enforces the spec's Inflight TTL ≤ Grace Period, Grace Interval ≤ Grace Period or "at least 1" bounds (`storm_tracking.rs:613-622`), and `test_durations_are_stored_exactly` (`test_storm_tracking_cmc.rs:388`) accepts `grace_period = 0`. Owner decision; see R17.

## 7. Accounting

- **7 active capability-driven targets** (C01–C05, C07, C08) plus **1 retired** (C06). All carry `origin: capability-driven` and a `capability_reference`. Category split: cat 1 ×4 (C01, C04, C05, C07), cat 2 ×3 (C02, C03, C08). No cat 3 or cat 4 target: no `unsafe` remains in `mpl`/`prim`, and concurrency stays with T21.
- **Routing:** mpl-verus-header-parsing-proofs ×4 (C01, C04, C05, C07), mpl-verus-zero-panic ×3 (C02, C03, C08).
- **17 overlap rows** with Step 1 (§4), covering T01, T02, T05, T06, T07, T09, T14, T15, T16, T17, T21, T23, T25, T26, T27 (15 distinct targets; T02 and T21 have two rows each).
- **16 candidates rejected** (R2–R17; R1 withdrawn).
