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

This file covers C01, C02, C04, C05, C07 and C08; T01, T02, T03, T04, T05, T06, T10, T12, T13 and T24 are in `01-threat-driven.md`. Sixteen targets have a Verus proof in `verus-proofs/` (T02, C01, C02, T03 and T05 at HEAD `d288750`; T01 and T13 at HEAD `4964d66`; T04 at HEAD `d6e42d8`; T06 at HEAD `19deef7`; C05, T24, C08 and C04 at HEAD `ad3522b`; C07, T10 and T12 at HEAD `cff28df`; run again with `~/verus/verus verus-proofs/<file>.rs` from the repo root, Verus 0.2026.07.12.0b42f4c). Each is a proof about a hand-written, re-typed model of the shipped Rust. None verifies the shipped code: the code is not inside `verus!`, is not compiled by Verus, and nothing detects a later edit to `mpl/` or `prim/`. The link between model and code is a correspondence table in each file header, reviewed by a human. Read every status as: the logic of the model is machine-checked; the model's fidelity to the code is audited, not checked. Sources: `verus-proofs/README.md` (T02, C01, C02, T01, T13, T04, T06, C05, T24, C08, C04, C07, T10, T12) and `verus-proofs/README-t03-t05.md` (T03, T05). The T01 proof copies the C01 model unchanged and adds the KMS leg and other items; the statement of what is new is in the cross-branch section of `docs/mpl-verification-targets.md`. C03 has a different kind of status, described in the subsection after the canonical strings: in-crate, on the shipped prim code, on branch `Mahnush_Verus`, not on this branch. C02 is partly superseded by VR-008 on that branch.

| Target | Proof file | Result line (re-run) | Status | Assumptions |
|---|---|---|---|---|
| C01 | [`c01_ec_roundtrip.rs`](../../verus-proofs/c01_ec_roundtrip.rs) | `verification results:: 40 verified, 0 errors` | Proved (model level, not the shipped code, under stated hypotheses). | A_ITER (`custom.iter()` yields each key once; precondition of every builder theorem); A_STR; A_BLD; A_DDB and A_NAME for the `theorem_prod_*` results; T02 model copied into the file. |
| C02 | [`c02_sign_fixed_len.rs`](../../verus-proofs/c02_sign_fixed_len.rs) | `verification results:: 21 verified, 0 errors` | Proved (model level, not the shipped code, under stated hypotheses). | vstd `assume_specification` for `copy_from_slice` (A1); abstract signing closure (A3); `Backend` trait without contracts stands for aws-lc-rs (A4); ghost call log checked by hand (A5). |
| C05 | [`c05_algorithm_suite_table.rs`](../../verus-proofs/c05_algorithm_suite_table.rs) | `verification results:: 22 verified, 0 errors` | Proved (model level, not the shipped code, under stated hypotheses). This is a consistency check of the suite table against the spec text, not a deep property. Two tables typed in by hand (one from `algorithm_suite.rs`, one from `algorithm-suites.md`) are compared field by field for all 11 ESDK rows, and the domain is finite. Proved: the model of `specification()` equals each of the 11 spec rows; ids are injective, never `00 00`, and differ from the seven S3EC and DBE spec ids; `ALL` is complete, has no duplicate and is in ascending id order; `from_id_bytes` inverts `id_bytes` and returns `None` for any other id; key commitment, format version 2 and suite data length 32 hold together; no suite has a symmetric signature algorithm; key lengths and verification key lengths agree with the prim and esdk constants (also hand copies). It does NOT show that the shipped code has these properties, that the spec is right, how callers use the table, or that any threat is mitigated. C05 maps to no TM-MPL threat. The 22 tests in `mpl/tests/test_algorithm_suite_id.rs` already cover the same finite domain, so the added value is low. No gap found, no EXPECTED_FAIL. Not a duplicate of anything on `Mahnush_Verus`: see "C05 against Mahnush_Verus" in `docs/mpl-verification-targets.md`. | Assumed, copied by hand: A_SPEC_COPY, A_CODE_COPY, A_PRIM_COPY. Assumed: A_FMT, A_NA, A_INT, A_FIND, A_VSTD. Code reading: H_MODEL_MATCH, H_TABLE_ONLY, H_ONLY_ESDK, H_ALL, H_FROM_ID, H_CURVE_MAP, H_AES_MAP, H_NO_SALT. |
| C08 | [`c08_cache_usage_counters.rs`](../../verus-proofs/c08_cache_usage_counters.rs) | `verification results:: 20 verified, 0 errors` | Proved (model level, not the shipped code, under stated hypotheses). The model uses the real widths: `u64` counters and a `u64` byte count per call. `record_use` is an executable model that uses `u64::checked_add`, and Verus checks it for every `u64` input: no arithmetic overflow; it succeeds exactly when neither `messages + 1` nor `bytes + b` exceeds `u64::MAX`; on success the counters are the exact sums; on failure both are unchanged. One `update_usage_metadata` call on an unpoisoned cache evicts the entry exactly when `record_use` fails. A poisoned store returns `Err(Internal)` and changes nothing. For any start counters and any call sequence, the entry survives exactly when the exact totals fit in `u64`, and then its counters equal the totals. The no-wrap part is short: it rests on the std contract of `checked_add` (vstd carries it as an `assume_specification`, cross-checked by a hand-written equivalent). The per-identifier statements are relative to A_NO_ALIAS (no `CacheEntry` handle is stored under two identifiers), A_ALL_CALLS and A_NO_PUT. The code does not enforce A_NO_ALIAS, because `put_cache_entry` takes a cloneable handle. It does NOT show that the shipped code has these properties (code reading finds no input at which it wraps or panics, and the model proof is consistent with that), concurrency (only some serial order is modeled), LRU order, capacity, TTL, or any usage limit policy. No in-repo code calls `update_usage_metadata` or compares the counters with a maximum. C08 has no threat reference, so no threat status changes. No gap found, no EXPECTED_FAIL. Not a duplicate of anything on `Mahnush_Verus`: see "C08 against Mahnush_Verus" in `docs/mpl-verification-targets.md`. | Assumed: A_VSTD (includes vstd's `assume_specification` for `u64::checked_add`), A_LOCK_EXCL, A_NO_ALIAS, A_ALL_CALLS, A_NO_PUT. Code reading: H_STD_CHECKED_ADD, H_ONLY_SITES, H_NO_PANIC_IN_GUARD, H_STORE_FLOW, H_LRU_OPS, H_BUILDER_ANY, H_DELEGATION, H_ARC_SHARED, H_MODEL_MATCH. |
| C04 | [`c04_pdk_length_invariant.rs`](../../verus-proofs/c04_pdk_length_invariant.rs) | `verification results:: 24 verified, 0 errors` | Proved (model level, not the shipped code, under stated hypotheses). The model has one function per code path that builds or accepts a plaintext data key (PDK) in `mpl/`: the four accept paths (encryption and decryption `add_data_key` and `build`), the builder setters, `Clone`, both random generators, raw-AES and hierarchical `on_decrypt`, and the public `PlaintextDataKey::new`. Proved: `check_data_key_length` accepts exactly the suite key length; the generators build the suite length; no sequence of the modeled paths, in any order and with any input length, gives a materials value whose PDK length differs from its suite's `encryption_key_length`; a present PDK has `len * 8` equal to the spec key length and KDF input length columns (two hand-copied columns). The suite table is copied from C05. It does NOT show that the shipped code has these properties, that the path list is complete (code reading), that the PDK is random or secret, that the spec is right, or that any threat is mitigated. The check is one `!=`, the four entry points are tested directly, and `esdk/src/key_derivation.rs:79,179` re-checks the length (not modeled). No gap found, no EXPECTED_FAIL. Not a duplicate of anything on `Mahnush_Verus`: see "C04 against Mahnush_Verus" in `docs/mpl-verification-targets.md`. | Assumed, copied by hand: A_TABLE_COPY (a copy of the C05 copy), A_SPEC_COLS_COPY. Assumed: A_FIT, A_OTHER_OK, A_ERR, A_LEN, A_RNG_FAIL, A_VSTD. Code reading: H_MODEL_MATCH, H_CLOSED, H_NO_MUT, H_SUITE_FIXED, H_BUILD_SAME_SUITE, H_BUILD_OTHER, H_ENC_DEC_SAME, H_GEN_SUITE, H_FILL_SLICE, H_VEC_LEN, H_RAW_DEC_LOOP, H_HIER_DEC_LOOP, H_NO_OTHER_PRODUCER, H_TABLE_ONLY. |
| C07 | [`c07_materials_checks.rs`](../../verus-proofs/c07_materials_checks.rs) | `verification results:: 65 verified, 0 errors` | Proved (model level, not the shipped code, under stated hypotheses). The model covers `check_encryption_transition`, `check_decryption_transition`, the two `*_complete` checks and the models of the four fluent `send()` bodies. Proved: each transition check accepts exactly the conjunction of field conditions over all 7 fields of the encryption materials and all 6 of the decryption materials, with one rejection lemma per rule (nine encrypt, eight decrypt); the EDK rule is a multiset containment test (every old EDK occurs in the new list at least as often, position and order do not matter); an accepted pair differs only in the PDK and the EDK list (encrypt) or only in the PDK (decrypt), relative to H_BUILD_SYM and H_ALL_BUILT; a keyring that only uses `add_data_key` and `add_encrypted_data_key` is accepted; accepted encrypt transitions compose; after an accepted decrypt transition no further one is accepted. In the model of `send()`, any keyring or CMM behavior returns Ok only after the check passed. That result follows from how the model of `send()` is written (call the keyring, check against the clone taken before, return the output only on Ok). It is not a proof about the shipped call paths. **That every call path reaches a `send()` body is code reading only** (grep, then read; table W1 to W12 in the proof header): keyring calls through a `SharedKeyring` or a built-in keyring run the transition check; CMM calls run the completeness check only, on the output alone (T09, not proved); a direct call of `Keyring::on_encrypt` on a caller's own type skips the check (no such call in `mpl/src`, `esdk/src`, the examples, the tests or the test server). Partly a consistency check: eight of the nine encrypt rules and all eight decrypt rules are plain field tests that the model transcribes and the theorem restates in the target's wording, so Verus checks that the two wordings agree, not that the code matches. The EDK rule, the all-fields frame, the composition lemma and the `send()` model are the added content. Latent finding F1: neither transition check reads the symmetric signing keys; with all 11 suite rows the builders keep that field empty, so no reachable pair differs there (stated as a proved fact about the predicate, not as a failing proof). It does NOT show that the shipped code has these properties, that every `send()` path runs the check, that a keyring is correct, that the CMM returns what it was asked for (T09), or any threat status: C07 cites no threat. No gap that fails a proof, no EXPECTED_FAIL. Not a duplicate of anything on `Mahnush_Verus`: see "C07 against Mahnush_Verus" in `docs/mpl-verification-targets.md`. | Assumed: A_STR, A_BYTES, A_EDK_ABS, A_CT_EQ (`ct_eq` is byte equality; the aws-lc-rs 1.18.1 Rust source was read, the C `CRYPTO_memcmp` was not), A_SUITE_COPY (hand copy of the two suite flags), A_ERR, A_SPEC_FN, A_VSTD. Code reading: H_MODEL_MATCH, H_ALL_FIELDS, H_SUITE_ID, H_ALL_BUILT, H_BUILD_SYM, H_SEND_BODY, H_NO_INTERIOR, H_DIRECT_CALL, H_WIRING. |

Canonical status strings (the same text is in each YAML `proof_status` field and in the `Proof status` column):

- C01: Proved (model level, not the shipped code, under stated hypotheses): 40 verified, 0 errors
- C02: Proved (model level, not the shipped code, under stated hypotheses): 21 verified, 0 errors
- C05: Proved (model level, not the shipped code, under stated hypotheses): 22 verified, 0 errors
- C08: Proved (model level, not the shipped code, under stated hypotheses): 20 verified, 0 errors
- C04: Proved (model level, not the shipped code, under stated hypotheses): 24 verified, 0 errors
- C07: Proved (model level, not the shipped code, under stated hypotheses): 65 verified, 0 errors
- C03: Partly proved (in-crate, on the shipped prim code, on branch Mahnush_Verus, not on this branch, under trusted aws-lc-rs assumptions A1-A20): 18 verified, 0 errors
- C02, relation added (the C02 status string above is unchanged): Partly superseded by VR-008 (in-crate, on the shipped prim code, on branch Mahnush_Verus, not on this branch): retry bound, termination, guarded copy

**Scores are unchanged.** Scores, ranks, coverage gaps, feasibility, severity and the quick-wins list in this document record the pre-proof prioritization and were not changed by these proofs. A model-level proof is not a proof of the shipped code, and re-scoring would be arbitrary. Coverage gaps will be recalculated when a proof is linked to the shipped code (for example with `cargo verus` on the crate, or by moving the logic into `verus!`). The same holds for C03: its proof is on `Mahnush_Verus`, not on this branch, so C03 stays at 5.60, rank 3, coverage gap 0.7. The same holds for C04, C05 and C08: C04 stays at 2.80 (rank 5 in this file, rank 19 overall, gap 0.5, effort 1 week); C05 stays at 2.40 (rank 6, rank 21 overall, gap 0.5, effort 1 day); C08 stays at 0.96 (rank 7, rank 33 overall, gap 0.6, effort 1 day). C07 stays at 5.04 (rank 4 in this file, rank 7 overall, gap 0.6, effort 1 week). None of them is a quick win.

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
- **C05: no gap found at model level; a consistency check, not a deep result.** The model of `specification()` equals the spec row for all 11 ESDK suites (`theorem_table_refines_spec`), including the points a reader might doubt: `05 78` and `04 78` carry format 2 and suite data length 32 with HKDF-SHA-512 as the commit KDF; `02 14` is the only SHA-256 ECDSA suite; no suite has a symmetric signature algorithm. Ids are injective and never `00 00`, and they differ from the seven S3EC and DBE spec ids. `ALL` lists every suite once in ascending id order, and `from_id_bytes` inverts `id_bytes`. This compares two tables typed in by hand over a finite domain. The 22 tests in `mpl/tests/test_algorithm_suite_id.rs` already cover the same facts, so the proof is a regression guard for the model. It adds the tie to the prim and esdk length constants, which are also hand copies. Nothing is left failing, and no EXPECTED_FAIL obligation was written, because the table equals the spec text.
- **C05, what is not shown.** That the shipped code has these properties (the code is not inside `verus!`); that the spec text is correct; how callers use the table (data key length checks are C04; decrypt handling of an unknown id is T09 and C07); S3EC and DBE suites (only their ids are modeled); the spec salt length column (the code has no salt field). A consistent error typed into both copies survives (mutant m21). The script `c05-copy-check.py` (49 of 49 checks) compares the copies with the Rust source and the spec file. It is a script, not a proof.
- **C05, observations (not gaps).** O2: the doc comment on `id_bytes` says ids are unique across the suites of every format, but only the ESDK format exists in the code, so uniqueness across formats is proved for the spec ids only. O3: the header of `spec/framework/algorithm-suites.md` says version 0.4.0, while its change log lists 0.5.0 as the newest entry (a spec document nit).
- **C05, mutation checks.** 23 variants of the model were run (record in `.agents/tasks/mpl-four-proofs/c05-mutation-run.txt`). Verus rejects 21. Two survive, both predicted: m21 (the same wrong id typed into both copies; the copy-check script catches it) and m22 (the id comparison removed from the refinement relation, a missing field that Verus cannot see). These checks cover edits to the model only, not edits to the code.
- **C08: no gap found at model level.** Code reading finds no input at which `record_use` wraps or panics, and the model proof is consistent with that. `record_use` (`mpl/src/cmc/entry.rs:206-223`) computes both `checked_add` sums before it stores either. On overflow it returns false and writes nothing, and `LocalCmc::update_usage_metadata` (`local.rs:326-342`) then deletes the entry. Verus proves for every `u64` input: no arithmetic overflow in the executable model; success exactly when neither `messages + 1` nor `bytes + b` exceeds `u64::MAX`; on success the counters are the exact sums; on failure both are unchanged. For any start counters and any sequence of calls, the entry survives exactly when the exact totals fit in `u64`, and then its counters equal the totals. Nothing is left failing, and no EXPECTED_FAIL obligation was written. The no-wrap part is short: it rests on `u64::checked_add` returning None exactly on overflow (vstd's `assume_specification`, cross-checked by a hand-written equivalent). The both-or-neither update, the exact eviction rule and the exact-total statement carry more content.
- **C08, O4: aliasing (observation, not a wrap).** The cache map holds `CacheEntry` handles, and a handle shares its counters with its clones. `put_cache_entry` takes a cloneable handle, so one handle can be stored under two identifiers through the public API, and the code does not prevent it. The model gives each identifier its own counters (A_NO_ALIAS), so no obligation fails. The clause "no other identifier changes" of `theorem_update_step` and the per-identifier exact totals of `theorem_cache_refines_entry_run` and `theorem_no_wrap_any_calls` are stated relative to A_NO_ALIAS, and they do not hold for an aliased state. Per-call no wrap, both-or-neither and eviction of the addressed slot do not depend on it. This was added after the proofs review.
- **C08, O1: an evicted handle is not frozen (observation, not a gap).** Eviction removes the map slot. It does not freeze the shared counters. A handle taken earlier from `get_cache_entry` still accepts `record_use`. After a failed call the counters are unchanged, so a later call on that handle with fewer bytes can succeed (`lemma_evicted_handle_is_not_frozen`). The counters stay exact. Whether it matters depends on a future caching CMM.
- **C08, O2 and O3: spec text and scope.** The only normative text on usage metadata is `spec/framework/cryptographic-materials-cache.md` :93, "Updating usage metadata SHOULD be atomic." The spec has no update-usage-metadata operation and no overflow rule. The `trace_to_spec` of the C08 YAML cites `#update-usage-metadata`, which does not exist in the spec checkout; it is not changed here. The overflow-evicts behavior comes from the trait doc (`mod.rs` :75-79) and the code. No in-repo code calls `update_usage_metadata`, and none compares the counters with a maximum, so the property is for a future caller. `2^64` messages or bytes is beyond any real workload, so this is a robustness property.
- **C08, what is not shown.** That the shipped code has these properties. Concurrency: the model runs calls one at a time (A_LOCK_EXCL). That every change to a counter goes through `update_usage_metadata` addressed to its own identifier (A_ALL_CALLS; `record_use` is `pub`). LRU order, capacity, TTL, pruning, `put`, `get` and `delete`. Any usage limit policy. C08 has no threat reference, so no threat status changes.
- **C08, mutation checks.** 30 variants of the model were run (record in `.agents/tasks/mpl-four-proofs/c08-mutation-run.txt`). Verus rejects 28. Two survive, both predicted: the width of the identifier element type (the model never reads identifier bytes) and a redundant `assert` hint. An edit to the executable `record_use` is seen only through its own `ensures`, because the cache-level theorems use the specification form. These checks cover edits to the model only, not edits to the code.
- **C04: no gap found at model level.** The model has one function per code path that builds or accepts a plaintext data key (PDK) in `mpl/`. Verus proves that `check_data_key_length` (`algorithm_suite.rs:547`) is Ok exactly when the length equals the suite's `encryption_key_length`; that the four accept paths (encryption and decryption `add_data_key` and `build`) store a PDK only when it passes; that both random generators build the suite length; and that from any builder state, any finite sequence of the eight modeled paths in any order gives only materials with a PDK of the suite length and the suite chosen at build (`theorem_c04_closure`). The suite table is a copy of the C05 table, which is a hand copy of `algorithm_suite.rs`. The targets document expected VERIFY after the BUG-02 fix, and that is the result. The model does not contain the pre-fix code, so it does not re-prove that BUG-02 caused the earlier failure. Nothing is left failing, and no EXPECTED_FAIL obligation was written.
- **C04, what the proof adds.** The check itself is one `!=` on two `usize` values, its proof mirrors the code, and the four entry points have direct tests (`mpl/tests/test_encryption_materials.rs:429,456`, `test_decryption_materials.rs:401,413`). The added value is the list of paths and the closure over all of them. The closure rests on code reading (H_CLOSED): the only writes to the PDK field are in the two `add_data_key` and the two `build`; the fields are private; the structs are `#[non_exhaustive]`; there is no `&mut self` method and no `unsafe` in `mpl/src`. A new constructor or setter would break it. C04 maps to no TM-MPL threat (nearest: TM-MPL-006 and TM-MPL-023, BUG-02, already fixed).
- **C04, observations (not gaps).** O1: the `PlaintextDataKey` type enforces no length (`new` and `From<Vec<u8>>` are public). The invariant rests on the four checks and the privacy of the materials fields, and `lemma_witnesses` shows that the type alone allows a wrong-length PDK. O2: in raw-AES `on_decrypt` the length test at `:489` is redundant for the invariant, because `add_data_key` checks again. It changes behavior: a wrong length skips to the next EDK, where the check alone would stop the loop with Err. O3 (code reading, not a proved lemma): in hierarchical `on_decrypt` there is no test before `add_data_key` (`:767`), so a wrong-length result from `branch_key_wrap::unwrap` ends `on_decrypt` with Err and later EDKs are not tried. It fails closed. O4: the spec says the encryption-materials PDK must fit the KDF and the decryption-materials PDK the encryption algorithm (`structures.md:227`, `:323`). The code uses `encryption_key_length` for both, and for the 11 suites the spec KDF input length equals the key length (two hand-copied spec columns). Reading "fit the specification" as the key length is an assumption (A_FIT). O5: `esdk/src/key_derivation.rs` re-checks the PDK length (`:79`, `:179`, not modeled), so the C04 check is a second line of defense, not the only one.
- **C04, what is not shown.** That the shipped code has these properties. That the path list is complete (code reading with grep support). That the PDK is random, secret, zeroized or the right bytes. That the spec is right. The esdk consumers, the KMS, the key store, the cache, `unwrap`, AES-GCM and the RNG values. That any threat is mitigated.
- **C04, mutation checks.** 34 variants of the model were run (record in `.agents/tasks/mpl-four-proofs/c04-mutation-run.txt`). Verus rejects 31. Three survive, all explained: a generated key stored without `add_data_key` (its length comes from `vec![0u8; encryption_key_length()]`, not from the check), a no-op refactor of the executable generator, and the same wrong key length typed into every copy (the copy-check script, 75 of 75 checks, catches it). `lemma_step_dispatch` is a definition check that exists only to catch an edit of `step`. These checks cover edits to the model only, not edits to the code.
- **C07: no gap found that fails a proof at model level; F1 is latent.** The model has the two transition checks (`materials_checks.rs:72-108`, `:117-150`), the two completeness checks and the four fluent `send()` bodies. Verus proves the exact accept list of each transition check over every field of both materials structs, one rejection lemma per rule, the EDK rule as a multiset test, the frame (an accepted pair differs only in the PDK and EDKs, or only in the PDK, relative to H_BUILD_SYM and H_ALL_BUILT), acceptance of honest mutator keyrings, composition of accepted encrypt transitions and single use of a decrypt transition. Nothing is left failing and no EXPECTED_FAIL was written.
- **C07, what the proof adds.** Eight of the nine encrypt rules and all eight decrypt rules are plain field tests (`==`, `is_some`, `is_none`). The model transcribes them and the theorem restates them in the target's wording, so that part is a consistency check of two wordings. The added content is the EDK rule (the greedy matching with `used` flags shown equal to a count test), the frame over all fields including the ones the check does not read, the composition and single-use lemmas, and the model of `send()`.
- **C07, the `send()` wiring is code reading only.** The model of `send()` shows that, if `send()` is written as modeled, any keyring behavior returns Ok only after the transition check passed. That follows from how the model is written. The shipped `send()` bodies were read (H_SEND_BODY) and the call paths were found by grep (table W1 to W12 in the proof header, section 3). Result: every keyring call through a `SharedKeyring` or a built-in keyring runs the transition check (`keyring/fluent_builders.rs:78-85`, `:159-166`, also `default_cmm.rs:167-170`, `:244-248`). Every CMM call through a `SharedCmm` or `DefaultCmm` runs the completeness check only, on the output alone, with no `before` to compare with (`cmm/fluent_builders.rs:168-174`, `:316-322`); that is T09 and is not proved. `Keyring` and `Cmm` are public traits, so an implementor can call its own method directly and skip the check (H_DIRECT_CALL). No such call exists in `mpl/src`, `esdk/src`, the examples, the tests or the test server. Five scratch reproducers under `.agents/tasks/bug-reports/reproducers/` call the trait method directly against an older API; none is in a crate. The table is a snapshot: a new call site would break it.
- **C07, F1: symmetric signing keys are not compared (latent, not a defect today).** `check_encryption_transition` never reads `symmetric_signing_keys`, and `check_decryption_transition` never reads `symmetric_signing_key`. No test covers either. With all 11 suite rows the builders reject those fields (`has_symmetric_signing` is false on every row), so a pair that differs there cannot be built, and the frame theorem holds relative to H_BUILD_SYM. The protection is in the builders, not in the transition check, and a future suite with symmetric signing would remove it. `lemma_f1_symmetric_keys_are_not_compared` proves that the predicate accepts such a pair. The target text already asked the owner to compare this and the EDK order with Dafny `Materials.dfy`, which was not read here.
- **C07, observations (not gaps).** (a) The EDK rule counts repeats: the target's `formal_spec` writes `to_set().subset_of`, while the code and the test at :337 are multiset (`lemma_removing_a_duplicate_is_rejected`). (b) EDK order and position are not checked, as the doc comment and the test at :250 say (`lemma_reordered_and_inserted_edks_accepted`). (c) With a PDK already in the old materials, an unchanged copy is accepted (`lemma_noop_with_pdk_is_accepted`); `keyring-interface.md` :126-127 says a keyring that attempted neither behavior MUST fail, and the check does not enforce that. Recorded for the owner; it is not a failing obligation, because the check's own comment says what a keyring may do. (d) Neither transition reads the PDK length; that is C04 (`lemma_transitions_do_not_read_pdk_length`). (e) The transition and completeness predicates are independent (T09 boundary). (f) The base check on `old` and on `new` always agree on an otherwise accepted pair, so each is redundant given the other; only the reported error changes.
- **C07, what is not shown.** That the shipped code has these properties (H_MODEL_MATCH). That every `send()` path runs the check (code reading). That a keyring is correct: PDK randomness or length, that an EDK decrypts to the PDK, EDK content (abstract, A_EDK_ABS). That the CMM returns what it was asked for (T09). Async behavior, panics, error kinds and messages. That any threat is mitigated: C07 has `threat_references: []`. That the 27 tests in `mpl/tests/test_materials_checks.rs` pass; they were read, not run, for this proof.
- **C07, mutation checks.** 55 variants of the model were run (local record `.agents/tasks/mpl-batch2-proofs/c07-mutation-run.txt`, not part of the commit). Verus rejects 51. Four survive, all equivalent: each removes one of the two base checks (on `old` or on `new`) from a transition, and the transition already requires suite, key and context to be equal between the two, so only the reported error changes. Removing both is rejected. A consistent error typed into both copies of the suite flags would also survive (A_SUITE_COPY). These checks cover edits to the model only, not edits to the code.

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
| 4 | VR-2026-C07 | 5.04 | C | `materials_checks::{check_encryption_transition, check_decryption_transition, check_*_materials_complete}` + `send()` wiring | Transition accepted iff the keyring only added a PDK (when absent) and EDKs; every fluent `send()` runs the check | mpl-verus-header-parsing-proofs | cap:cat1 (1a/1b) | 1 week | Proved (model level, not the shipped code, under stated hypotheses): 65 verified, 0 errors |
| 5 | VR-2026-C04 | 2.80 | C | PDK length invariant (`check_data_key_length`, `add_data_key` ×2, materials `build` ×2, keyring producers) | Every materials PDK has the suite's `encryption_key_length` (expected to VERIFY) | mpl-verus-header-parsing-proofs | cap:cat1 (1a) | 1 week | Proved (model level, not the shipped code, under stated hypotheses): 24 verified, 0 errors |
| 6 | VR-2026-C05 | 2.40 | C | `AlgorithmSuiteId::specification`, `id_bytes`, `verification_key_length` | Suite table refines spec; ids injective, never `00 00`; cross-crate length agreement | mpl-verus-header-parsing-proofs | cap:cat1 (1a) | 1 day | Proved (model level, not the shipped code, under stated hypotheses): 22 verified, 0 errors |
| 7 | VR-2026-C08 | 0.96 | C | `CacheEntry::record_use` + `Cmc::update_usage_metadata` impls | Counters never wrap; both change together or neither; overflow deletes the entry | mpl-verus-zero-panic | cap:cat2 (2b) | 1 day | Proved (model level, not the shipped code, under stated hypotheses): 20 verified, 0 errors |
| — | VR-2026-C06 | Retired | C | ~~`HierarchicalKeyring::new` grace-vs-TTL integer division~~ | — | — | — | — | None (retired) |

Quick wins: **C01**, **C02**.

Foundational: C03 is assumed by T04, T05, T07, T13. C01 links T01 and T02 end to end and is reused by T18. C07 supplies the keyring-frame lemma that T09 and T12 rely on. The C07 proof (model level) now states that frame for the transition checks; the T12 proof does not use it.

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
  proof_status: "Proved (model level, not the shipped code, under stated hypotheses): 65 verified, 0 errors"
  proof_file: verus-proofs/c07_materials_checks.rs
  proof_note: "Model level, not the shipped code. Verus proves the exact accept list of both transition checks over every field of both materials structs, one rejection lemma per rule, the EDK rule as a multiset test (the formal_spec above writes a set; the code and test :337 count repeats), the frame (an accepted pair differs only in the PDK and EDKs, or only in the PDK, relative to H_BUILD_SYM and H_ALL_BUILT), composition and single use. In the model of send(), Ok implies the check passed; that follows from how send() is modeled. That every call path reaches a send() body is code reading only (table W1 to W12 in the proof header); CMM send() runs the completeness check only (T09). Eight of nine encrypt rules and all eight decrypt rules are field tests restated, so part of this is a consistency check. F1 (latent): neither transition reads the symmetric signing keys; the builders keep them empty for all 11 suites. Not shown: the shipped code, keyring correctness, any threat (none cited). No EXPECTED_FAIL. No duplicate on branch Mahnush_Verus."
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
  proof_status: "Proved (model level, not the shipped code, under stated hypotheses): 24 verified, 0 errors"
  proof_file: verus-proofs/c04_pdk_length_invariant.rs
  proof_note: "Model level, not the shipped code. One model function per code path that builds or accepts a PDK in mpl; Verus proves check_data_key_length is exact and that no sequence of the modeled paths gives a PDK length different from the suite key length. The suite table is a copy of the C05 copy. Not shown: the shipped code, that the path list is complete (code reading), randomness or secrecy of the PDK, any threat mitigation. The check is one comparison and the four entry points have direct tests. No gap found, no EXPECTED_FAIL. No duplicate on branch Mahnush_Verus."
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
  proof_status: "Proved (model level, not the shipped code, under stated hypotheses): 22 verified, 0 errors"
  proof_file: verus-proofs/c05_algorithm_suite_table.rs
  proof_note: "Model level, not the shipped code. A consistency check of the suite table against the spec text: two hand-typed tables compared for all 11 ESDK rows, plus ids, ALL, from_id_bytes, commitment fields and length constants. 22 existing tests cover the same finite domain, so the added value is low. Not shown: the shipped code, that the spec is right, caller use of the table. No gap found, no EXPECTED_FAIL. No duplicate on branch Mahnush_Verus."
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
  proof_status: "Proved (model level, not the shipped code, under stated hypotheses): 20 verified, 0 errors"
  proof_file: verus-proofs/c08_cache_usage_counters.rs
  proof_note: "Model level, not the shipped code. record_use never wraps a u64 counter (checked_add), updates both counters or neither, and update_usage_metadata evicts the entry exactly when record_use fails; exact totals over any call sequence are relative to A_NO_ALIAS, A_ALL_CALLS and A_NO_PUT. The code does not enforce A_NO_ALIAS. Not shown: the shipped code, concurrency, LRU order, TTL, any usage limit policy. No gap found, no EXPECTED_FAIL. No duplicate on branch Mahnush_Verus."
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
- C07: fields not constrained by `check_encryption_transition` (symmetric signing keys; EDK order) should be compared with Dafny `Materials.dfy` by the owner. The C07 proof (model level) shows what the check does and does not read: `symmetric_signing_keys` and `symmetric_signing_key` are not compared, which no reachable pair can exploit while the builders keep them empty for all 11 suites (latent); EDK order is not checked and the EDK rule is a multiset test. The comparison with Dafny `Materials.dfy` was not done. That every `send()` path runs the check is code reading, not proved.
- C04-F1 / C04-F2 from the previous run: **closed** by BUG-02 fix.
- T21 (a), not a C target: `StormTrackingCmcBuilder::build` no longer enforces the spec's Inflight TTL ≤ Grace Period, Grace Interval ≤ Grace Period or "at least 1" bounds (`storm_tracking.rs:613-622`), and `test_durations_are_stored_exactly` (`test_storm_tracking_cmc.rs:388`) accepts `grace_period = 0`. Owner decision; see R17.

## 7. Accounting

- **7 active capability-driven targets** (C01–C05, C07, C08) plus **1 retired** (C06). All carry `origin: capability-driven` and a `capability_reference`. Category split: cat 1 ×4 (C01, C04, C05, C07), cat 2 ×3 (C02, C03, C08). No cat 3 or cat 4 target: no `unsafe` remains in `mpl`/`prim`, and concurrency stays with T21.
- **Routing:** mpl-verus-header-parsing-proofs ×4 (C01, C04, C05, C07), mpl-verus-zero-panic ×3 (C02, C03, C08).
- **17 overlap rows** with Step 1 (§4), covering T01, T02, T05, T06, T07, T09, T14, T15, T16, T17, T21, T23, T25, T26, T27 (15 distinct targets; T02 and T21 have two rows each).
- **16 candidates rejected** (R2–R17; R1 withdrawn).
