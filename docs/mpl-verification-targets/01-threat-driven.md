# Threat-Driven Verus Verification Targets — AWS MPL (native Rust)

> Pipeline artifact — Stage 3, Step 1 of 4 (threat-driven entry path). **Refreshed for HEAD `9955ecd`** (branch `MPL-Verus`; `mpl/` and `prim/` identical to `origin/main` `620771c`; `esdk/` differs from `620771c` only by #188 and #189). The refresh for main `620771c` (previous version analyzed `a1e23d7`) is kept in section 0.
> Inputs: `docs/mpl-threat-model.md` (TM-MPL-001..026, second pass at `851977d`), `docs/mpl-spec-security-analysis.md`, `docs/mpl-completeness-audit.md`, `docs/mpl-bug-reports/RECHECK-main-620771c.md`, `.agents/tasks/pipeline-rerun-620771c/scope.md`, `mpl/src`, `prim/src`, `mpl/tests`, `prim/tests`, `esdk/shims/aws-esdk-cpp/src`.
> Methodology: `.kiro/agents/mpl-verification-recommender.md`, `.kiro/agents/mpl-ai-verification-pipeline.md`, `.kiro/agents/mpl-verus-capabilities.md`.
> Every target has `origin: threat-driven`. At `620771c` every `file:line` was re-checked (see `.agents/tasks/pipeline-rerun-620771c/stage3-notes.md`). In the `9955ecd` refresh every `file:line` that was added or moved was re-checked on HEAD with `sed` / `grep` (see `.agents/tasks/docs-sync-9955ecd/notes-targets-threat-driven.md`). Older `mpl/` and `prim/` citations still hold because those trees are unchanged.

## Refresh (HEAD 9955ecd)

This refresh applies the "Impact on verification targets" list of `docs/mpl-threat-model.md` (second pass, TM-MPL-001..026) and the results of `docs/mpl-completeness-audit.md` (no missed threat; one gap G1; editorial item G4-1). No threat rating changed and `mpl/`, `prim/` did not change, so no score moved because of code. Scores moved only where the evidence for a property changed. Target IDs are stable; T08 and C06 stay retired.

### What changed

| ID | Threat refs | Kind | Old score | New score | Change |
|---|---|---|---|---|---|
| T27 | TM-MPL-025 | **New target** | — | **3.78** | Bound on key-store calls and loop work per decrypt, given the EDK list. Provisional until a reproducer exists (section 3, T27) |
| T21 | TM-MPL-018 | **Re-scored** | 1.96 | **2.24** | Properties (g) stale in-flight mark, (h) waiter with no deadline, (i) panic under the state lock added. Coverage gap 0.7 → 0.8 |
| T25 | TM-MPL-024 | Citations and scope | 1.44 | 1.44 | `lib.rs:1564-1565` → `:1570-1571`, `:1655` → `:1661`, `into_keyring_handle` `:2054` → `:2059`. Scope now includes the type-erased `Keyring::adopt` path; the Rust-provable part and the part outside the proof are stated. Score unchanged |
| T26 | TM-MPL-015 | Scope | 3.20 | 3.20 | Two residual sites added: expired `LocalCmc` entries resident until read (F4) and the un-wiped private-key `Vec` on `ecdsa_generate_keypair`'s error path (F5). Score unchanged |
| T02 | TM-MPL-005 | Property (G1) | 6.72 | 6.72 | Spec clause "a branch key record MUST include `create-time` and `hierarchy-version`; otherwise the operation MUST fail" added to the property and formal spec; expected FAIL. No new target. Score unchanged |
| T06 | TM-MPL-018, 022, 023 | Note | 4.20 | 4.20 | Consequence for the two `storm_tracking.rs` sites is a persistent `Internal` error after the lock is poisoned, not one panic |
| T14 | TM-MPL-010 | Note | 3.78 | 3.78 | Property (b) now states that a creation time in the future counts as fresh (`hierarchical_keyring.rs:991-994`) |
| T19 | TM-MPL-003 | Note | 1.92 | 1.92 | Scope note: on decrypt the supplier's input is the unauthenticated message EC |
| T22 | TM-MPL-021 | Note | 1.60 | 1.60 | `NoMatchingDataKey` exposes provider info through `Debug` and `encrypted_data_keys()`; ciphertext stays excluded. `Debug` citations moved to the `impl` lines |
| T09 | TM-MPL-006, 008 | Note | 2.56 | 2.56 | `SharedCmm::send()` checks completeness only, not the policy; cited |
| T01, T02, T03 | TM-MPL-005, 002 | Note | — | unchanged | Rollback of an authentic older record recorded as a non-goal; T03 scope note for Discovery on the encrypt path |

Other edits: section 2 ranks and counts (26 active targets; T27 is inserted at rank 10, and T26 and every target ranked below it move down by one); section 4 gains a "fully excluded" row for TM-MPL-026 and a row for TM-MPL-025, and the TM-MPL-005, 015 and 024 rows are updated and the TM-MPL-018 rows name T27 (it cites TM-MPL-018 as a secondary threat); section 5 gains C3 to C5; section 6 now accounts for TM-MPL-001..026. Every place that said "TM-MPL-001..024" now says "001..026". Quick wins are unchanged (T02 only).

### Arithmetic for every re-scored or new target

`Priority = Severity × Coverage_Gap × Feasibility × Blast_Radius`, with the conventions of section 1.

**T21 (re-scored).** Severity 2 (TM-MPL-018 Medium, kept in the second pass). Feasibility 0.7 (Likelihood Medium). Blast radius 2 (storm-tracking cache, unchanged). Coverage gap 0.7 → 0.8. Evidence from `mpl/tests/test_storm_tracking_cmc.rs` (33 tests) and a search of `mpl/src` and `mpl/tests`: of the nine properties now listed, (b) to (e) have direct tests including negative cases, (a) has tests that encode the regressed contract (`test_durations_are_stored_exactly` :388 accepts `grace_period = 0`), (g) has no test (`test_get_miss_inflight_exceeds_ttl_fails` :761 pre-marks the key and never tests recovery after a failed refresh), (h) has tests that pass with the defect (`test_get_miss_blocks_when_fanout_saturated_until_key_appears` :699 and `test_block_miss_not_inflight_prunes_stale_entries_in_loop` :1021 end the wait by a `put` or a prune, so a missing deadline is not detectable), and (i) and (f) have no test (`grep poison` in `mpl/tests` finds nothing). That is "some unit tests", the 0.8 level of section 1. It is not 0.9 because (b) to (e) are still directly tested, and not 0.7 because three added properties have no detecting test. `2 × 0.8 × 0.7 × 2 = 2.24`. The value equals an earlier draft's, but it was recomputed from the test list above. T21 now ties T16 (2.24, severity 2); the tie is broken by ID, so T16 is rank 16 and T21 rank 17 (both one lower than before, because T27 was inserted above them).

**T27 (new).** Severity 2 (TM-MPL-025 Risk Medium: Severity Medium × Likelihood Medium, provisional). Feasibility 0.7 (Likelihood Medium). Coverage gap 0.9: `mpl/tests/test_keyring_memory.rs:100` and `:113` decrypt with many EDKs but check memory only, and the hierarchical case is built so that "decrypt never calls the key store" (the keys are for another keyring). `FakeKeyStore` counts `get_version` calls (`test_aws_kms_hierarchical_keyring.rs:1306`), but the only test with several matching EDKs (`on_decrypt_with_several_failing_edks_aggregates_without_a_single_cause` :1998) uses two ciphertexts that are too short, so they fail before any key-store call, and it asserts error aggregation, not a call count. No test asserts a bound. These tests exist and cannot detect the defect, which is the 0.9 level. Blast radius 3: the loop runs in every `HierarchicalKeyring::on_decrypt`, but it is exploitable only in a service that decrypts ciphertext from a third party and uses a key-store-backed hierarchical keyring, a deployment condition like the shared-cache condition behind T13 and T14 (both 3). It is not 4 because services that decrypt only their own ciphertext are not reachable by TA8. `2 × 0.9 × 0.7 × 3 = 3.78`. T27 ties T14 (3.78); T14 has the higher severity (3 against 2), so T14 stays at rank 9 and T27 takes rank 10.

**Unchanged scores (stated so that no one re-derives them).** T25: gap stays 0.6 because the added `adopt` scope has no Rust-side check to test and its provable slice (non-null result of `into_keyring_handle`) is covered by `tests.rs:1624`; `3 × 0.6 × 0.4 × 2 = 1.44`. T26: gap stays 1.0 (no test checks that any transient, error-path or expired-entry buffer is wiped; `test_pruning_does_not_evict_outside_tail` :465 pins the residency of F4 but does not test wiping); `2 × 1.0 × 0.4 × 4 = 3.20`. T02: gap stays 0.6 because the 23 tests still cover most branches and the G1 clause adds one untested branch pair (the audit says to re-score only if the gap changes); `4 × 0.6 × 0.7 × 4 = 6.72`.

**Not provable or not confirmed (read before using T27 and T21).** TM-MPL-025 is unconfirmed until a reproducer exists: a test that sends N EDKs with distinct unknown versions through a `DefaultCmc` and counts key-store calls and elapsed time, and one with duplicate versions. The wedge and the no-deadline waiter in T21 (g) and (h) are also static reasoning and need a concurrency reproducer. Rankings that include T27 and T21 are provisional on these.

## Proofs written (HEAD d288750)

This file covers T01, T02, T03, T04, T05 and T13; C01 and C02 are in `02-capability-driven.md`. Eight targets have a Verus proof in `verus-proofs/` (T02, C01, C02, T03 and T05 at HEAD `d288750`; T01 and T13 at HEAD `4964d66`; T04 at HEAD `d6e42d8`; run again with `~/verus/verus verus-proofs/<file>.rs` from the repo root, Verus 0.2026.07.12.0b42f4c). Each is a proof about a hand-written, re-typed model of the shipped Rust. None verifies the shipped code: the code is not inside `verus!`, is not compiled by Verus, and nothing detects a later edit to `mpl/` or `prim/`. The link between model and code is a correspondence table in each file header, reviewed by a human. Read every status as: the logic of the model is machine-checked; the model's fidelity to the code is audited, not checked. Sources: `verus-proofs/README.md` (T02, C01, C02, T01, T13, T04) and `verus-proofs/README-t03-t05.md` (T03, T05). C03 is recorded in `02-capability-driven.md` and the merged document: it is partly proved in-crate on branch `Mahnush_Verus` (not on this branch), a different kind of status from the model-level proofs here. For T26 this file now records BUG-10 and the BUG-07(a) caller impact (T26 YAML and section 7). The duplicate check of T01, T04 and T13 against branch `Mahnush_Verus` (no duplicate) and the statement of what T01 adds to C01 are in the cross-branch section of `docs/mpl-verification-targets.md`. Scores are unchanged.

| Target | Proof file | Result line (re-run) | Status | Assumptions |
|---|---|---|---|---|
| T02 | [`t02_record_reconstruction.rs`](../../verus-proofs/t02_record_reconstruction.rs) | `verification results:: 21 verified, 1 errors` | Partly proved (model level, not the shipped code, under stated hypotheses). The one error is the intentional G1 obligation `lemma_g1_spec_soundness_FAILS`. | Verus, Z3, vstd `Seq`/`Map`/`Set` axioms; A_STR (`String` is `Seq<char>`); nine hand-copied string constants. |
| T03 | [`t03_resolve_pinned_arn.rs`](../../verus-proofs/t03_resolve_pinned_arn.rs) | `verification results:: 39 verified, 0 errors` | Proved (model level, not the shipped code, under stated hypotheses). Discovery and MrDiscovery arms are out of scope (BUG-04, T17). | H_ORACLE, H_BUILD, H_CALLER, A_STR, A_MR. |
| T05 | [`t05_kbkdf_fixed_info.rs`](../../verus-proofs/t05_kbkdf_fixed_info.rs) | `verification results:: 33 verified, 0 errors` | Proved (model level, not the shipped code, under stated hypotheses). The KBKDF output is uninterpreted, so this shows which arguments the primitive receives, not that the derived key is correct. | A_KDF (uninterpreted `kbkdf_spec`), A_STD, A_LBL. |
| T01 | [`t01_keystore_auth_ec.rs`](../../verus-proofs/t01_keystore_auth_ec.rs) | `verification results:: 52 verified, 0 errors` | Proved (model level, not the shipped code, under stated hypotheses). KMS and DynamoDB are modeled by assumptions, so the KMS leg is proved relative to A_KMS and A_DDB, not checked. Not a duplicate of C01 (see the cross-branch section of `docs/mpl-verification-targets.md`). | Assumed: A_KMS, A_DDB, A_NUM, A_NAME, A_ITER, A_ARN, A_STR, A_BLD. Premises: H_WF, H_ENUM. Code reading: H_SAME_EC. The C01 and T02 models are copied into the file. |
| T13 | [`t13_cache_identifier.rs`](../../verus-proofs/t13_cache_identifier.rs) | `verification results:: 42 verified, 1 errors` | Partly proved (model level, not the shipped code, under stated hypotheses). The one error is the intentional BUG-06 obligation `lemma_bug06_injectivity_without_nul_precondition_EXPECTED_FAIL`. | Assumed: A_DIGEST_CR (SHA-384 modeled as an injective function), H_LEN_FITS (length-prefixed fix only). Code reading: H_MODEL_MATCH, H_BYTES, H_SCOPE_PAIRING, H_VERSION_NO_NUL, H_NO_DIGEST_ERROR. |
| T04 | [`t04_branch_key_wrap.rs`](../../verus-proofs/t04_branch_key_wrap.rs) | `verification results:: 45 verified, 0 errors` | Proved (model level, not the shipped code, under stated hypotheses). What is proved is the structure around the draws: on every call that returns Ok, two separate generator calls (salt 16 bytes, then IV 12 bytes); the salt feeds the KDF and the IV feeds AES-GCM; the output is salt, IV, version, ciphertext and tag, with 60 + n bytes (the 16 + n tail rests on A_AES). It does NOT prove that the salt or the IV is fresh, random or unique: that comes from the aws-lc-rs generator, which the model assumes only as A_RNG. Not a duplicate of anything on `Mahnush_Verus`: see "T04 against Mahnush_Verus" in `docs/mpl-verification-targets.md`. | Assumed: A_RNG (each call fills the whole buffer or fails; nothing about the values), A_KDF, A_AES, A_STD, A_VSTD, A_TYP, A_ALLOC. Premise only: H_RNG_DIFFERS. Not assumed, not used, not proved: A_RNG_FRESH. Code reading: H_MODEL_MATCH, H_AAD_PURE, H_NO_STATE, H_WIPE. |

Canonical status strings (the same text is in each YAML `proof_status` field and in the `Proof status` column):

- T02: Partly proved (model level, not the shipped code, under stated hypotheses): 21 verified, 1 errors
- T03: Proved (model level, not the shipped code, under stated hypotheses): 39 verified, 0 errors
- T05: Proved (model level, not the shipped code, under stated hypotheses): 33 verified, 0 errors
- T01: Proved (model level, not the shipped code, under stated hypotheses): 52 verified, 0 errors
- T13: Partly proved (model level, not the shipped code, under stated hypotheses): 42 verified, 1 errors
- T04: Proved (model level, not the shipped code, under stated hypotheses): 45 verified, 0 errors

**Scores are unchanged.** Scores, ranks, coverage gaps, feasibility, severity and the quick-wins list in this document record the pre-proof prioritization and were not changed by these proofs. A model-level proof is not a proof of the shipped code, and re-scoring would be arbitrary. Coverage gaps will be recalculated when a proof is linked to the shipped code (for example with `cargo verus` on the crate, or by moving the logic into `verus!`). T01 stays at 8.96 (rank 1, gap 0.8) and T13 at 4.41 (gap 0.7); neither is a quick win. T04 stays at 4.48 (rank 4 in this file, rank 8 overall, gap 0.7, effort 1 week); it is not a quick win.

### Findings from the proofs

- **G1 confirmed formally (T02).** The code accepts a branch-key record that lacks `create-time` and `hierarchy-version`: the outcome is identical with or without them (`lemma_g1_code_ignores_fields`, `lemma_g1_witness_accepted_without_fields`), and the spec property fails as `lemma_g1_spec_soundness_FAILS`. The code is more permissive than the spec, never stricter (`lemma_g1_spec_completeness`).
- **O1, DEV-ALIAS (T03).** Two byte-identical alias ARNs fail the code's MRK match, where the spec text matches. This is a documented deviation, stricter than the spec, and unreachable for any configuration `build()` accepts (H_BUILD).
- **O2 (T03).** The model of ARN validity accepts an ARN with empty partition, region and account, which is looser than the spec. It does not affect the T03 property (the KMS `KeyId` is the configured ARN either way). It is a conformance gap in config validation.
- **F1 (T05).** The spec does not state the KBKDF fixed-info layout `"aws-kms-hierarchy" || 0x00 || salt(16) || 00 00 01 00` (38 bytes, 32-byte output). This is a spec gap, not a code defect.
- **T01: no gap found at model level.** The write-time EC, the EC KMS binds (the AAD) and the EC the reconstruction reads are equal for a record written under one EC, and KMS Decrypt with that AAD returns the generated key (T01-C, `theorem_three_way`). Nothing is left failing. The KMS leg rests on the assumption A_KMS (KMS binds the EC given at generate and at the ReEncrypt destination, and accepts Decrypt only for an equal EC), which Verus does not check. The claim that `create_key` and `version_key` pass one EC to both KMS and `item_from_ec_and_enc` (H_SAME_EC) is code reading.
- **O1 (T01, code reading plus the proved agreement).** The reconstruction reads its attributes from `build_auth_ec` (`branch_key_store.rs:132`), while KMS authenticates `build_authenticated_encryption_context` (`kms_ops.rs:49`). They are two separately written functions with no shared code. T01-A proves they agree today. An edit to one alone, for example dropping `tablename`, would let the reconstruction read attributes KMS did not authenticate. Verus rejects six mutants of the model (a dropped `tablename` in either builder, an item that keeps `tablename`, a Decrypt that accepts any AAD, a ReEncrypt that checks the wrong EC, a rotated ACTIVE EC that keeps the old type; record in `.agents/tasks/t01-t13/t01-mutations.txt`). These checks cover edits to the model only, not edits to the code.
- **O2 to O5 (T01).** O2 (proved, `theorem_sn_tag_not_authenticated`): the DynamoDB S or N tag is not authenticated, and no consumer sees it. O3 (proved at model level): an item attribute named `tablename` is ignored and replaced by the reader's name in both builders. O4 (proved): T01 holds for items with or without `create-time` and `hierarchy-version`, so G1 stays a T02 finding. O5: rollback of an authentic older record is outside the property (TM-MPL-005 non-goal), because an older record's EC is genuine and T01-E accepts it.
- **BUG-06 confirmed formally (T13).** At model level the cache identifier preimage of `build_cache_identifier` is injective for the two call shapes if and only if every input field is free of `0x00` (`theorem_t13_iff`; `theorem_t13_iff_identifier` for the identifiers, under A_DIGEST_CR for the if half; the only-if half needs no assumption). The BUG-06 collisions are proved for the encrypt scope and for the decrypt scope (`lemma_bug06_witness_collides`). The spec property for all inputs, with no NUL precondition, is the intentional expected-FAIL obligation `lemma_bug06_injectivity_without_nul_precondition_EXPECTED_FAIL` (postcondition not satisfied at `t13_cache_identifier.rs:1019`). `lemma_bug06_failing_claim_is_false` shows the claim is false, not only unproved. The obligation is not weakened, assumed or commented out.
- **Fix options at model level (T13).** The NUL-free precondition (BUG-06 fix option 1) gives injective identifiers under A_DIGEST_CR (`lemma_nul_free_precondition_gives_identifier_injectivity`). A length-prefixed encoding (fix option 2) is injective for all inputs with no NUL precondition, under A_DIGEST_CR and H_LEN_FITS (every field shorter than 2^32 bytes, which a real fix must check), and the BUG-06 pairs separate (`lemma_lp_*`, `theorem_lp_*`). This is a model of a proposed fix, not a statement about the shipped code. Encrypt and decrypt identifiers never coincide (`lemma_scope_separation`), and the pairing of scope byte and version (H_SCOPE_PAIRING, code reading) is needed for part of the proof (`lemma_pairing_is_needed`).
- **Limits (T13, code reading).** The version string is a hyphenated UUID and cannot contain `0x00` (H_VERSION_NO_NUL), so in the realistic form the NUL-free condition is on the partition id, the logical key store name and the branch key id (`theorem_t13_iff_realistic`). The only-if direction builds a colliding partner as a tuple of byte fields. When the NUL is in the partition id, the partner's name takes the bytes after the NUL, which may not be valid UTF-8, so the proof does not decide that every NUL-bearing configuration has a realizable partner (H_BYTES). The ASCII BUG-06 examples do exist. The proof does not show that a deployment can be configured to collide (BUG-06 states the preconditions: a Shared cache and attacker-influenced NUL-bearing values). The layout is modeled as shipped and equals the layout the spec mandates, so the defect is in the spec text too.
- **T04: no gap found at model level.** On every call that returns Ok, `wrap` makes two separate generator calls, the 16-byte salt and then the 12-byte IV (a call can fail before or after the draws). The salt goes to the KDF and the IV to AES-GCM, and the output is `salt ‖ IV ‖ version ‖ ciphertext ‖ tag` with `60 + n` bytes (`t04_branch_key_wrap.rs`, R1 to R4; the `16 + n` tail rests on A_AES). No expected-FAIL obligation is included, because no code gap against the spec steps S1 to S6 was found. Every `ensures` is partial correctness (`r is Ok ==> ...`): nothing proves that `wrap` can return Ok.
- **T04, what is not proved (TM-MPL-012).** The proof does not show that the salt or the IV is fresh, random, unpredictable or unique, and it does not show that two calls use different salts or IVs. Freshness comes from the random number generator in aws-lc-rs (`rand::fill`, called by `generate_random_bytes`), which a model must assume. The model assumes only A_RNG: each call fills the whole buffer or fails, and each successful call is logged once, with nothing assumed about the values. A generator that returns zeros every time meets A_RNG (`toy_generate_random_bytes`). A_RNG_FRESH (uniform, independent draws) is not assumed, not used and not proved. The collision bound for random salts and IVs and the yearly rotation advice of TM-MPL-012 stay a probabilistic argument. The only distinctness result is conditional (R8): if the draws of two calls differ (H_RNG_DIFFERS, a premise that is never established), the outputs differ. `wrap_twice` shows that two calls use four distinct log positions, which does not mean four different values.
- **T04, limits.** The `60 + n` length rests on A_AES, and the shipped `debug_assert_eq!` (`branch_key_wrap.rs:209`) that would catch a violation is compiled out in release builds. `unwrap` parses the version field but never uses it (`_version`, `:254`), so R6 and R7 show only that the layout carries it, and they cover the layout, not the plaintext round trip. The ghost log covers one call chain, and the aws-lc-rs generator is process-global (H_NO_STATE, code reading). The wiping of the derived key (H_WIPE) is code reading, not proved.
- **T04, O1 (code reading, low, not a proof obligation).** If `aes_encrypt` returns Err after it has appended the message, `output` can hold a clear copy of the data key, and `wrap` drops it as a plain `Vec<u8>` without wiping it. The two argument-shape checks cannot fail in `wrap` (types), so only a failing seal reaches this; which inputs make aws-lc-rs fail was not examined. The model has no memory contents, so no honest expected-FAIL obligation can be written for it. This is the `wrap` caller impact already recorded under BUG-07(a) and T26.
- **T04, mutation checks.** Verus rejects 18 of 19 mutants of the model (swapped offsets, one generator call reused for both draws, a zero salt or a zero IV in the KDF or AES call, swapped call order, a wrong length constant, an ignored salt-draw failure and others; record in `.agents/tasks/t04-verus/mutations.md`). One survives: a `wrap` that always returns Err (MA), because every `ensures` is partial correctness. These checks cover edits to the model only, not edits to the code.

### Next steps for the proofs

- Link each proof to the shipped code (`cargo verus` on the crate, or move the logic into `verus!`), then recalculate its coverage gap.
- Owner decisions: enforce `create-time` and `hierarchy-version` on a read path (G1); state the KBKDF fixed-info layout in the spec (F1); decide whether config validation should reject ARNs with empty parts (O2).

## 0. What changed since a1e23d7 (previous refresh, kept)

This section is the `620771c` history. Scores and shim line numbers in it are as of that refresh; the `9955ecd` refresh above moved the shim citations (see the T25 row of the refresh table) and changed T21 (1.96 → 2.24). Sections 2 to 6 are current.

| ID | Change | Old score | New score | Reason |
|---|---|---|---|---|
| T08 | **Retired** | 3.84 | — | Its code is gone. The `unsafe { write_volatile }` loop in `PlaintextDataKey::zeroize` was replaced by `#[derive(Clone, Zeroize, ZeroizeOnDrop)]` (`mpl/src/structures/algorithm_suite.rs:505`, commit a864ad8 / #131). A search for `\bunsafe\b` in `mpl/src` and `prim/src` finds nothing. TM-MPL-015 is now covered by the new T26. |
| T26 | **New** (TM-MPL-015 residual) | — | 3.20 | Secret buffers on transient and error paths that are not wiped. Replaces T08 as the TM-MPL-015 target. |
| T25 | **New** (TM-MPL-024) | — | 1.44 | C++ shim raw-handle dereferences (`esdk/shims/aws-esdk-cpp/src/lib.rs:715`, `:728`, and at `620771c` `:1564-1565`, `:1655`; now `:1570-1571`, `:1661`). |
| T13 | Rescored | 2.52 | 4.41 | TM-MPL-009 Likelihood Low → Medium (BUG-06 confirmed end to end). Feasibility 0.4 → 0.7. |
| T14 | Rescored | 2.52 | 3.78 | TM-MPL-010 Likelihood Low → Medium (feasibility 0.7). BUG-09 fixed plus regression test, so gap 0.7 → 0.6. |
| T09 | Rescored | 3.20 | 2.56 | Gap 0.5 → 0.4. The keyring "suite unchanged" frame that T09 assumed is now enforced at runtime by `check_encryption_transition` / `check_decryption_transition` and tested in `test_materials_checks.rs`. |
| T15 | Rescored | 2.40 | 1.92 | BUG-03 fixed: `from_bytes` rejects out-of-order and duplicate keys and invalid UTF-8. Gap 0.5 → 0.4. The expected counterexample is gone; the proof should now verify. |
| T21 | Rescored | 1.68 | 1.96 | Gap 0.6 → 0.7. `StormTrackingCmcBuilder::build` no longer enforces the spec ordering, and `test_durations_are_stored_exactly` asserts the regressed contract. Property (a) is now expected to FAIL. |
| others | Location / name updates only | | unchanged | `keystore/` → `key_store/`, `resolve_keystore_arn` → `resolve_key_store_arn`, `BranchKeyStore` → `DynamoDbKeyStore`, `HierarchicalKeyring::new` → `HierarchicalKeyringBuilder::build`, `RawAesKeyring::new` → `RawAesKeyringBuilder::build`, `ValidatedConfig::from_raw` → `StormTrackingCmcBuilder::build`, `EncryptionContext::{serialize,deserialize}` → `{to_bytes,from_bytes}`, `ttl_seconds: u64` → `ttl: Duration`, error kinds now `crate::error::Kind`. |

Retired threats: none (threat model: "Retired: none"). No active target cites retired code.

## 0.1 Repo facts re-confirmed for this step

- **No `unsafe` in `mpl/src` or `prim/src`.** `\bunsafe\b` has no match (the lint name `unsafe_op_in_unsafe_fn` at `prim/src/lib.rs:33` is one identifier). The only `unsafe` reaching MPL objects is in the C++ shim (`esdk/shims/aws-esdk-cpp/src/lib.rs:728`, `:1570`, `:1571`, `:1661`; at `620771c` the last three were `:1564`, `:1565`, `:1655`, moved by #188), which is T25. The shim also has a type-erased ownership transfer that is not an `unsafe` block in the Rust source: `into_keyring_handle` calls the safe `Box::into_raw` (`lib.rs:2059-2066`) and C++ `Keyring::adopt` calls `rust::Box::from_raw` (`EncryptionSDK.cpp:541-547`). It is also in T25.
- **No raw C FFI in `mpl`/`prim`.** `prim` still calls aws-lc-rs only through its safe API.
- **Duvet:** one annotation block in `mpl/`/`prim/` (`mpl/src/cmc/entry.rs:201-205`, `cryptographic-materials-cache.md#usage-metadata`, `type=implication`). No Duvet config covers MPL sources, so it is not checked. Coverage gaps below are justified by named tests only. Tests lower a gap but never close it.
- **Bugs:** open BUG-01, 04, 05(a), 05(b), 06, 07(a/b), 08, 10 (BUG-10 added after the audit, by code reading). Fixed BUG-02, 03, 09 (`e9bde48`).
- **CVE-2026-6550 / GHSA-v638-38fc-rhfv is verified** by the threat model ([GitHub advisory](https://github.com/advisories/GHSA-v638-38fc-rhfv), [NVD](https://nvd.nist.gov/vuln/detail/CVE-2026-6550), [AWS bulletin 2026-017-aws](https://aws.amazon.com/security/security-bulletins/2026-017-aws/)). It concerns a shared caching CMM in the Python ESDK. This repo has no caching CMM (`mpl/src/cmm/` = `default_cmm.rs`, `fluent_builders.rs`, `mod.rs`, `types.rs`), so it does not raise any feasibility score here. It is recorded as a future-work note on T14. Content was rephrased for compliance with licensing restrictions.

## 1. Scoring conventions (applied uniformly)

`Priority = Severity × Coverage_Gap × Feasibility × Blast_Radius`

| Factor | Rule |
|---|---|
| Severity (1–4) | From the threat-model risk matrix for the target's **primary** threat: Critical=4, High=3, Medium=2, Low=1. Same severity for a threat in every target that cites it. |
| Feasibility (0–1) | From the primary threat's Likelihood: **Low → 0.4, Medium → 0.7**. |
| Blast_Radius (1–4) | 4 = every MPL consumer / every hierarchical-keyring, key-store or CMM user. 3 = widely used but feature-specific (raw AES keyring, shared cache, VersionKey). 2 = opt-in configuration or a single integration surface (storm-tracking cache, Discovery/MRDiscovery, the C++ shim). 1 = narrow. |
| Coverage_Gap (0–1) | 1.0 = no test exercises the property. 0.9 = only tests that cannot detect a defect. 0.8 = some unit tests, or private code exercised only by live-AWS tests. 0.7 = direct unit tests including negative cases. 0.6 = broad example tests of most branches. 0.5 = near-exhaustive tests over a small finite domain. **0.4 (new level) = near-exhaustive tests plus a runtime check that enforces the same property on the production path.** |

Ties: higher severity, then target ID.

Proof-technique notes (unchanged): pure fragments must be extracted from `async fn`s during the proof stage (behavior-preserving, not done here). External crates (`uuid`, `lru`, `zeroize`, `aws-lc-rs`, `std::time::SystemTime`, `core::fmt`, `cxx`) need Verus external specifications, which are trusted (TCB) and must never be used as `assume` to force a pass. Verification claims must name the Cargo feature set (`kms`, `ddb`, `default-aws-sdk-clients`, `rt-tokio`, `test-utils`, `fips`).

## 2. Summary table (ranked)

| Rank | ID | Score | Origin | Target | Property | Agent | Ref | Effort | Proof status |
|---|---|---|---|---|---|---|---|---|---|
| 1 | VR-2026-T01 | 8.96 | T | key-store auth-EC builders (`build_authenticated_encryption_context`, `DynamoDbKeyStore::build_auth_ec`, `item_from_ec_and_enc`, `record_from_ddb_item`) | Write-time EC == KMS-AAD EC == reconstruction EC | mpl-verus-header-parsing-proofs | TM-MPL-005, TM-MPL-002 | 2 weeks | Proved (model level, not the shipped code, under stated hypotheses): 52 verified, 0 errors |
| 2 | VR-2026-T02 | 6.72 | T | `record::branch_key_materials_from_authenticated_encryption_context` | Exact Ok/Err characterization, including the spec clause that a record MUST include `create-time` and `hierarchy-version` (expected FAIL, G1) | mpl-verus-header-parsing-proofs | TM-MPL-005 | 1 week (quick win) | Partly proved (model level, not the shipped code, under stated hypotheses): 21 verified, 1 errors |
| 3 | VR-2026-T03 | 5.12 | T | `kms_ops::resolve_key_store_arn` (pinned modes) | KMS KeyId is always the configured ARN | mpl-verus-header-parsing-proofs | TM-MPL-002 | 1 day | Proved (model level, not the shipped code, under stated hypotheses): 39 verified, 0 errors |
| 4 | VR-2026-T04 | 4.48 | T | `branch_key_wrap::wrap` | Fresh 16 B salt + 12 B IV per call, exact 60+n layout | mpl-verus-unsafe-ffi-safety | TM-MPL-012 | 1 week | Proved (model level, not the shipped code, under stated hypotheses): 45 verified, 0 errors |
| 5 | VR-2026-T13 | 4.41 | T | `cache_entry_identifier::build_cache_identifier` + keyring inputs | Exact preimage; scope separation; injective iff fields NUL-free (BUG-06 counterexample otherwise) | mpl-verus-header-parsing-proofs | TM-MPL-009, TM-MPL-010 | 1 week | Partly proved (model level, not the shipped code, under stated hypotheses): 42 verified, 1 errors |
| 6 | VR-2026-T05 | 4.32 | T | `branch_key_wrap::derive_branch_key` | KBKDF fixed-info = label‖0x00‖salt‖be32(256), 32 B out | mpl-verus-header-parsing-proofs | TM-MPL-014 | 1 day | Proved (model level, not the shipped code, under stated hypotheses): 33 verified, 0 errors |
| 7 | VR-2026-T06 | 4.20 | T | `SystemTime + Duration` sites (keyring, storm tracking) | No overflow panic for any accepted config (expected FAIL, BUG-01) | mpl-verus-zero-panic | TM-MPL-018, TM-MPL-022, TM-MPL-023 | 1 week | None yet |
| 8 | VR-2026-T07 | 3.84 | T | `RawAesKeyring` wrap/unwrap + `prim::aes_{en,de}crypt` | Fresh 12 B IV per call; length preconditions | mpl-verus-unsafe-ffi-safety | TM-MPL-011 | 1 week | None yet |
| 9 | VR-2026-T14 | 3.78 | T | `as_branch_key_materials`, `cache_entry_within_limits`, `generate_partition_id` | Only BranchKey entries used; exact `Duration` TTL gate; v4 partition id | mpl-verus-header-parsing-proofs | TM-MPL-010 | 1 week | None yet |
| 10 | VR-2026-T27 | 3.78 | T | `HierarchicalKeyring::on_decrypt` EDK loop → `try_decrypt_edk` → `decrypt_edk_at_version` (cache lookup, key-store read) | Key-store calls and loop iterations per decrypt are bounded as a function of the EDK list; no constant cap exists today (provisional, TM-MPL-025 unconfirmed) | mpl-verus-zero-panic | TM-MPL-025, TM-MPL-018 | 1 week | None yet |
| 11 | VR-2026-T26 | 3.20 | T | Transient / error-path secret buffers (raw-AES decrypt buffer, `prim::aes_encrypt` output on `Err`, `unwrap` output, KMS plaintext) | Every secret buffer is wiped or moved into a `ZeroizeOnDrop` type on every exit path (expected FAIL: BUG-07a, un-wiped decrypt buffers, `ecdsa_generate_keypair` error path); expired `LocalCmc` entries resident until read | mpl-verus-unsafe-ffi-safety | TM-MPL-015 | 2 weeks | None yet |
| 12 | VR-2026-T10 | 2.88 | T | `compute_aad`, `uuid_str_to_16_bytes`, `uuid_16_bytes_to_str` | AAD layout exact; UUID round trip | mpl-verus-header-parsing-proofs | TM-MPL-013 | 1 week | None yet |
| 13 | VR-2026-T11 | 2.88 | T | `aws_kms_mrk_match_for_decrypt`, `is_arn_compatible` | Match iff identical or MRKs equal except region; aliases rejected | mpl-verus-header-parsing-proofs | TM-MPL-004 | 2 weeks | None yet |
| 14 | VR-2026-T12 | 2.88 | T | `default_cmm::merge_reproduced_encryption_context` | Merged EC = union on agreement; nothing dropped | mpl-verus-header-parsing-proofs | TM-MPL-017 | 1 week | None yet |
| 15 | VR-2026-T09 | 2.56 | T | `CommitmentPolicy::*`, `DefaultCmm`, transition-check frame | Allow-tables match spec; CMM gates encrypt/decrypt | mpl-verus-header-parsing-proofs | TM-MPL-006, TM-MPL-008 | 1 week | None yet |
| 16 | VR-2026-T16 | 2.24 | T | malformed-input panic sites (`unwrap`, `try_decrypt_edk`, raw-AES decrypt, `from_bytes`, MRK `pa[5]`, `.expect`s) | No panic on any malformed EDK/EC/ARN input | mpl-verus-zero-panic | TM-MPL-023 | 1 week | None yet |
| 17 | VR-2026-T21 | 2.24 | T | `cmc/storm_tracking.rs` | Builder enforces spec ordering (expected FAIL); `\|inflight\| ≤ fan_out`; ≤ 1 leader per grace interval; a failed leader's mark is cleared or ages out (expected FAIL); every waiter has a deadline (expected FAIL); no panic under the state lock | mpl-verus-zero-panic (+ concurrency specialist) | TM-MPL-018 | 1 month | None yet |
| 18 | VR-2026-T15 | 1.92 | T | `EncryptionContext::{to_bytes, from_bytes}` | Canonical codec; `from_bytes(b) = Ok(ec) ⇒ to_bytes(ec) = b` | mpl-verus-header-parsing-proofs | TM-MPL-013, TM-MPL-017 | 2 weeks | None yet |
| 19 | VR-2026-T17 | 1.92 | T | `resolve_key_store_arn` (Discovery/MRDiscovery), `reject_alias_arn`, `rewrite_arn_region`, `parse_arn` | Alias rejection; region-only rewrite of MRK ARNs (expected FAIL, BUG-04) | mpl-verus-header-parsing-proofs | TM-MPL-007 | 1 week | None yet |
| 20 | VR-2026-T18 | 1.92 | T | `<Builtin<DynamoDbKeyStore> as KeyStore>::version_key` EC derivation | New ACTIVE/DECRYPT_ONLY ECs preserve id/arn/hv/tablename/custom EC | mpl-verus-header-parsing-proofs | TM-MPL-016 | 1 week | None yet |
| 21 | VR-2026-T19 | 1.92 | T | `HierarchicalKeyring` bkid binding (`resolve_branch_key_id`, `on_encrypt`, `on_decrypt`, `try_decrypt_edk`, `decrypt_edk_at_version`) | Only matching provider-id + bkid EDKs attempted; bkid bound everywhere | mpl-verus-header-parsing-proofs | TM-MPL-003 | 1 week | None yet |
| 22 | VR-2026-T20 | 1.68 | T | `RawAesKeyring::{serialize_provider_info, decryptable_edk_iv}` | Provider-info codec round trip, total | mpl-verus-header-parsing-proofs | TM-MPL-023, TM-MPL-011, TM-MPL-001 | 1 week | None yet |
| 23 | VR-2026-T22 | 1.60 | T | `Debug` impls of secret-bearing types + error `DataKeyInfo` | Output independent of secret bytes | mpl-verus-unsafe-ffi-safety | TM-MPL-021 | 1 week | None yet |
| 24 | VR-2026-T25 | 1.44 | T | C++ shim handle boundary (`require_handle`, nullable client/cache handles, `into_keyring_handle` / `Keyring::adopt`) | Every raw-handle deref is preceded by a null check; null → error or default. The type-erased `Keyring::adopt` path is in scope, but only its Rust half (non-null, unique `Box`) is provable | mpl-verus-unsafe-ffi-safety | TM-MPL-024 | 1 week | None yet |
| 25 | VR-2026-T23 | 1.26 | T | `cmc/local.rs` `LocalCmc` | `len ≤ entry_capacity`; get never returns expired; prune safe | mpl-verus-zero-panic | TM-MPL-022 | 2 weeks | None yet |
| 26 | VR-2026-T24 | 1.20 | T | `RawAesKeyringBuilder::build` | No built keyring has namespace prefixed `aws-kms` | mpl-verus-header-parsing-proofs | TM-MPL-001 | 1 day | None yet |
| — | VR-2026-T08 | Retired | T | ~~`PlaintextDataKey::zeroize` unsafe loop~~ | — | — | (was TM-MPL-015) | — | None (retired) |

26 active threat-driven targets, 1 retired. Quick win (score > 6.0 and effort ≤ 1 week): **VR-2026-T02** only. T01 scores higher but needs 2 weeks.

## 3. Detailed recommendations (YAML)

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
      kms_ops::build_authenticated_encryption_context (kms_ops.rs:49, KMS Decrypt AAD, called at :170);
      DynamoDbKeyStore::build_auth_ec (branch_key_store.rs:132; reconstruction in get_active_branch_key :792,
      get_branch_key_version :827, get_beacon_key :868, and the VersionKey ReEncrypt EC at :671);
      item_from_ec_and_enc (:1089, write) / record_from_ddb_item (:1141, read);
      record::encryption_context_from_item (record.rs:37) / to_attribute_map (:61) — both #[cfg(feature = "test-utils")]
  property: >
    The builders that produce the authenticated EC agree exactly with the spec definition
    (every item attribute except `enc`, plus `tablename` = configured logical key store name),
    and a stored item read back (item_from_ec_and_enc → DDB → record_from_ddb_item → build_auth_ec)
    reproduces exactly the EC KMS authenticated at write time: no attribute dropped, added or
    altered, Number attributes round-trip as the same decimal string.
  formal_spec: |
    spec fn auth_ec(attrs: Map<Seq<char>,Seq<char>>, n: Seq<char>) -> Map<Seq<char>,Seq<char>>
        { attrs.remove("enc"@).insert("tablename"@, n) }
    fn build_authenticated_encryption_context(a, n) -> (ec) ensures ec@ == auth_ec(a@, n@)
    fn build_auth_ec(&self, r) -> (ec)
        requires !r.attributes@.contains_key("enc"@)
        ensures ec@ == auth_ec(r.attributes@, self.inner.logical_key_store_name@)
    // write→read (AttributeValue modeled as S | N | B):
    requires ec@["tablename"@] == n@ && !ec@.contains_key("enc"@)
    ensures record_from_ddb_item(item_from_ec_and_enc(ec, enc)) == Ok(r) && r.enc@ == enc@ && auth_ec(r.attributes@, n@) == ec@
  tool: Verus
  agent: mpl-verus-header-parsing-proofs
  estimated_effort: 2 weeks
  threat_references:
    - {id: TM-MPL-005, category: Tampering, description: "Branch-key record substitution; residual = reconstructed EC must exactly match write-time EC"}
    - {id: TM-MPL-002, category: Spoofing, description: "Forged record decrypts under attacker-influenced key; EC binding makes forgery detectable"}
  trace_to_spec: >
    spec/framework/branch-key-store.md#encryption-context, #authenticating-a-keystore-item,
    #aws-kms-branch-key-decryption, #record-format, #writing-branch-key-and-beacon-key-to-keystore
  coverage_gap: 0.8
  coverage_evidence: >
    mpl/tests/test_key_store_record.rs::item_encryption_context_round_trips (:306) covers only the
    test-utils record.rs helpers, which production never calls. The production builders are private
    and are reached only by the live-AWS tests in mpl/tests/test_key_store_branch_key_store_integ.rs.
    Unchanged since a1e23d7.
  rationale: |
    KMS EC-as-AAD is the only integrity control on DynamoDB records. Equality depends on separately
    written builders plus an S/N AttributeValue round trip. Still the top residual of TM-MPL-005.
    Needs pure helpers extracted for the AttributeValue mapping and an abstract model of
    aws_sdk_dynamodb::AttributeValue (TCB). A user-supplied KeyStore is outside this proof (TB7).
    Non-goal (second pass): rollback of an older, authentic ACTIVE record. Its EC is genuine, so no
    property of these builders distinguishes it (TM-MPL-005 residual; see section 4).
  scoring:
    severity: 4        # TM-MPL-005 Critical
    coverage_gap: 0.8
    feasibility: 0.7   # TM-MPL-005 Likelihood Medium
    blast_radius: 4
    product: "4 × 0.8 × 0.7 × 4 = 8.96"
  quick_win: false     # 2 weeks
  proof_status: "Proved (model level, not the shipped code, under stated hypotheses): 52 verified, 0 errors"
  proof_file: verus-proofs/t01_keystore_auth_ec.rs
  proof_note: "KMS and DynamoDB are modeled by assumptions (A_KMS, A_DDB), not checked. Overlaps C01 (40 verified): the C01 and T02 models are copied unchanged. New versus C01: the KMS-AAD builder as its own function, the KMS call model, the loop-based item and record mapping, VersionKey, and the authenticity theorem T01-E. No duplicate on branch Mahnush_Verus."
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
    function: branch_key_materials_from_authenticated_encryption_context (:95); custom_encryption_context_from_authenticated_encryption_context (:79); malformed (:188)
  property: >
    Returns Ok(materials) exactly when the EC has a valid `type` ("branch:ACTIVE" with a `version`
    strictly extending "branch:version:", or a type strictly extending "branch:version:"), a
    `branch-key-id`, and the plaintext is 32 bytes. Output fields are then exactly determined.
    Every other input yields Err with Kind::InvalidMaterials.
    Spec completeness clause (completeness audit G1, EXPECTED FAIL on 9955ecd): the spec requires a
    branch key record to include `create-time` and `hierarchy-version`, and says that when the record
    does not contain the defined fields the operation MUST fail. The EC is built from every record
    attribute except `enc`, so "record contains the field" is "EC contains the field". The Ok
    characterization therefore also requires both keys. Today neither key is read on any read path,
    so an EC without them is accepted. Where the check lives is an owner decision: here, or in
    `record_from_ddb_item` (T01's read side), which is where the spec says the operation MUST fail.
    The pure predicate and the proof are the same in either place.
  formal_spec: |
    fn branch_key_materials_from_authenticated_encryption_context(ec, pt) -> (r)
      ensures r.is_Ok() <==> ec@.contains_key("type"@)
                && (ec@["type"@] == "branch:ACTIVE"@ ==> ec@.contains_key("version"@))
                && strict_prefix("branch:version:"@, ver_src(ec@))
                && ec@.contains_key("branch-key-id"@) && pt@.len() == 32
                && ec@.contains_key("create-time"@) && ec@.contains_key("hierarchy-version"@)   // G1: FAILS today
      ensures r matches Ok(m) ==> m.branch_key@ == pt@ && m.branch_key_id@ == ec@["branch-key-id"@]
                && m.branch_key_version@ == ver_src(ec@).subrange(15, ver_src(ec@).len() as int)
                && m.encryption_context@ == custom(ec@)
      ensures r matches Err(e) ==> e.kind() == Kind::InvalidMaterials
    // Record-completeness view of the same clause (spec: every defined field present, else MUST fail):
    //   record_from_ddb_item(item) matches Ok(r) ==> r.enc present && auth_ec(r.attributes@, n@) contains
    //   "branch-key-id", "type", "kms-arn", "create-time", "hierarchy-version"   // only `enc` is required today
    // `kms-arn` is already required one step later, by decrypt_branch_key (kms_ops.rs:172).
  tool: Verus
  agent: mpl-verus-header-parsing-proofs
  estimated_effort: 1 week
  threat_references:
    - {id: TM-MPL-005, category: Tampering, description: "Reconstruction must not accept a mis-typed or mis-versioned record"}
  trace_to_spec: >
    spec/framework/branch-key-store.md#branch-key-materials-from-authenticated-encryption-context,
    #custom-encryption-context-from-authenticated-encryption-context,
    #record-format (:677 "A branch key record MUST include", `create-time` :690, `hierarchy-version` :692),
    #getactivebranchkey / #getbranchkeyversion / #getbeaconkey ("If the record does not contain the
    defined fields, this operation MUST fail": :531, :553, :574)
  coverage_gap: 0.6
  coverage_evidence: >
    mpl/tests/test_key_store_record.rs (23 tests): branch-type, version, beacon, wrong-length
    (materials_branch_key_rejects_wrong_length :169) and custom-EC extraction cases.
    No test builds a record or EC without `create-time` or `hierarchy-version` (completeness audit G1).
  rationale: |
    Final decode of KMS-authenticated data into the materials every hierarchical wrap/unwrap uses.
    Straight-line Map code. The decrypted key is now held in Zeroizing during parsing (record.rs:100),
    which does not change the functional property. Paired with T01 it closes
    "authenticated bytes → correct materials".
    G1 (second-pass audit): code and spec evidence. `record_from_ddb_item` (branch_key_store.rs:1141-1200)
    requires only `enc` and checks attribute types; this function (record.rs:95) requires `type`,
    `version` (ACTIVE only), `branch-key-id` and a 32-byte key (:164); `decrypt_branch_key` requires
    `kms-arn` (kms_ops.rs:172). `ATTR_CREATE_TIME` and `ATTR_HIERARCHY_VERSION` occur in mpl/src only on
    write paths (branch_key_store.rs:711, :1098; encryption_context.rs:67, :77). Impact is low because a
    record altered after encryption fails KMS Decrypt (the EC is the AAD); only a record from a
    non-conforming writer that never had the fields is accepted, and no key is exposed or mis-selected.
    The gap is kept at 0.6: the 23 tests still cover most branches and the clause adds one untested
    branch pair, so the score is unchanged. Non-goal (second pass): rollback of an older, authentic ACTIVE
    record is not decided here (TM-MPL-005 residual; no property of this function can tell it apart).
  scoring:
    severity: 4
    coverage_gap: 0.6
    feasibility: 0.7
    blast_radius: 4
    product: "4 × 0.6 × 0.7 × 4 = 6.72"
  quick_win: true      # score > 6.0, effort ≤ 1 week
  proof_status: "Partly proved (model level, not the shipped code, under stated hypotheses): 21 verified, 1 errors"
  proof_file: verus-proofs/t02_record_reconstruction.rs
  dependencies: []
```

```yaml
recommendation:
  id: VR-2026-T03
  rank: 3
  priority_score: 5.12
  origin: threat-driven
  target:
    crate: aws-crypto-mpl
    file: mpl/src/key_store/kms_ops.rs (+ caller decrypt_branch_key :162; version_key in branch_key_store.rs:641)
    function: resolve_key_store_arn (:88; KmsKeyArn / KmsMrKeyArn arms :94-95, compatibility check :105, Ok :113)
  property: >
    In single-key modes the KeyId sent to KMS Decrypt/ReEncrypt is always the CONFIGURED ARN, never
    the record's `kms-arn`. Success iff the record ARN is compatible (byte-equal for KmsKeyArn,
    MRK-match for KmsMrKeyArn); otherwise Err with Kind::Validation. decrypt_branch_key passes only
    this value as key_id (:179, :183).
  formal_spec: |
    fn resolve_key_store_arn(c, rec, bkid) -> (r: Result<String, Error>)
      requires c is KmsKeyArn || c is KmsMrKeyArn
      ensures r matches Ok(k) ==> k@ == configured(c)@
      ensures r.is_Ok() <==> compat_spec(c, rec@)
      ensures r matches Err(e) ==> e.kind() == Kind::Validation
  tool: Verus
  agent: mpl-verus-header-parsing-proofs
  estimated_effort: 1 day
  threat_references:
    - {id: TM-MPL-002, category: Spoofing, description: "Forged record decrypts under attacker-influenced KMS key — pinned-mode slice"}
  trace_to_spec: "spec/framework/branch-key-store.md#aws-kms-branch-key-decryption, #aws-key-arn-compatibility"
  coverage_gap: 0.8
  coverage_evidence: >
    resolve_key_store_arn is pub(crate) with no direct unit test. The compatibility predicate is
    tested in mpl/tests/test_key_store_kms_config.rs (22 tests). End-to-end coverage is live-AWS only.
  rationale: "Code-level control for Critical TM-MPL-002; cheap because the property is 'returns the configured string'. Logic unchanged since a1e23d7 (renamed). Scope note (second pass): the Discovery and MRDiscovery arms are not covered here. Discovery also runs on the encrypt path (hierarchical_keyring.rs:692 → get_active_branch_key, branch_key_store.rs:792, :801), where the record's ARN is trusted by spec; that is a configuration control (TM-MPL-002 residual), and T17 is about alias and region handling, not branch-key confidentiality."
  scoring:
    severity: 4        # TM-MPL-002 Critical
    coverage_gap: 0.8
    feasibility: 0.4   # Low
    blast_radius: 4
    product: "4 × 0.8 × 0.4 × 4 = 5.12"
  quick_win: false
  proof_status: "Proved (model level, not the shipped code, under stated hypotheses): 39 verified, 0 errors"
  proof_file: verus-proofs/t03_resolve_pinned_arn.rs
  dependencies: [VR-2026-T11]   # soft: gives compat_spec its MRK meaning
```

```yaml
recommendation:
  id: VR-2026-T04
  rank: 4
  priority_score: 4.48
  origin: threat-driven
  target:
    crate: aws-crypto-mpl
    file: mpl/src/aws_kms/branch_key_wrap.rs
    function: wrap (:157; salt draw :164, IV draw :170)
  property: >
    Fresh local 16-byte salt and 12-byte IV per call, each filled by one successful RNG call before
    use, no cross-call state. Output is exactly salt‖iv‖uuid_bytes(version)‖ct‖tag with
    |output| = 60 + |pt|. aws-lc-rs preconditions hold (key 32 bytes, IV 12). On Err the partially
    built output is dropped and never returned.
  formal_spec: |
    fn wrap(m, ec, pt) -> (r)
      ensures r matches Ok(out) ==> out@.len() == 60 + pt@.len()
        && out@.subrange(0,16) == ghost_salt_draw@ && out@.subrange(16,28) == ghost_iv_draw@
        && out@.subrange(28,44) == uuid_bytes(m.branch_key_version@)
        && out@.subrange(44, out@.len() as int) == gcm_seal_spec(kdf(m.branch_key@, ghost_salt_draw@), ghost_iv_draw@, compute_aad_spec(m, ec), pt@)
  tool: Verus
  agent: mpl-verus-unsafe-ffi-safety
  estimated_effort: 1 week
  threat_references:
    - {id: TM-MPL-012, category: Elevation of Privilege, description: "AES-GCM salt/IV reuse in branch-key wrap — lengths and fresh-per-call structure"}
  trace_to_spec: "spec/framework/aws-kms/aws-kms-hierarchical-keyring.md#branch-key-wrapping, #ciphertext"
  coverage_gap: 0.7
  coverage_evidence: >
    mpl/tests/test_aws_kms_hierarchical_keyring.rs: wrap_ciphertext_layout_lengths_match_spec (:939),
    wrap_two_calls_produce_distinct_ciphertexts (:1168), unwrap_too_short_ciphertext_returns_error (:1187), round trips.
  rationale: "prim uses Nonce::try_assume_unique_for_key, so nonce discipline is on the caller. Structural half provable; the 224-bit collision bound is excluded."
  scoring:
    severity: 4
    coverage_gap: 0.7
    feasibility: 0.4
    blast_radius: 4
    product: "4 × 0.7 × 0.4 × 4 = 4.48"
  quick_win: false
  proof_status: "Proved (model level, not the shipped code, under stated hypotheses): 45 verified, 0 errors"
  proof_file: verus-proofs/t04_branch_key_wrap.rs
  proof_note: "The model proves the structure around the draws (two separate generator calls per call that returns Ok, salt to the KDF, IV to AES-GCM, 60 + n layout relative to A_AES), not that the salt or the IV is fresh or unique: freshness comes from the aws-lc-rs generator, assumed only as A_RNG (the draws may be any values). The only distinctness result is conditional: if the draws of two calls differ (H_RNG_DIFFERS, never established), the outputs differ. No expected-FAIL obligation. All ensures are partial correctness (nothing proves wrap returns Ok). No duplicate on branch Mahnush_Verus."
  dependencies: [VR-2026-T05, VR-2026-T10]
```

```yaml
recommendation:
  id: VR-2026-T13
  rank: 5
  priority_score: 4.41
  origin: threat-driven
  target:
    crate: aws-crypto-mpl
    file: mpl/src/aws_kms/cache_entry_identifier.rs; mpl/src/aws_kms/hierarchical_keyring.rs
    function: >
      build_cache_identifier (cache_entry_identifier.rs:35; preimage :42-60; .expect :64);
      call sites HierarchicalKeyring on_encrypt (:665) and decrypt_edk_at_version (:908);
      field sources: partition id (:595-599, raw caller bytes or generate_partition_id :626),
      logical name from the key store (:605), bkid from config or supplier (resolve_branch_key_id :831)
  property: >
    The SHA-384 preimage is exactly 0x02‖0x00‖scope‖0x00‖partition‖0x00‖logicalName‖0x00‖bkid[‖0x00‖version].
    Encrypt and decrypt scopes never share a preimage. The preimage is injective in
    (partition, logicalName, bkid, version) WHEN those fields contain no 0x00 byte; without that
    precondition injectivity is FALSE (BUG-06). The internal `.expect` is unreachable.
  formal_spec: |
    spec fn pre(s, p, n, b, v) -> Seq<u8>
      { seq![0x02, 0x00, s, 0x00] + p + seq![0x00] + n + seq![0x00] + b + match v { Some(x) => seq![0x00] + x, None => seq![] } }
    fn build_cache_identifier(s, p, n, b, v) -> (out: [u8; 48]) ensures out@ == sha384_spec(pre(s, p@, n@, b@, v@))
    proof fn scope_separation(..) requires s1 != s2 ensures pre(s1, ..) != pre(s2, ..)
    proof fn injective_nul_free(..) requires no_nul(p1) && no_nul(n1) && no_nul(b1) && no_nul_opt(v1) && (same for 2)
                                             && pre(s,p1,n1,b1,v1) == pre(s,p2,n2,b2,v2)
                                    ensures p1 == p2 && n1 == n2 && b1 == b2 && v1 == v2
    // EXPECTED COUNTEREXAMPLE without no_nul (BUG-06, do not axiomatize away):
    //   (p="tenant\0x", n="L") vs (p="tenant", n="x\0L"), same bkid → equal preimages
  tool: Verus
  agent: mpl-verus-header-parsing-proofs
  estimated_effort: 1 week
  threat_references:
    - {id: TM-MPL-009, category: Elevation of Privilege, description: "Cache-identifier collision returns wrong branch-key materials (BUG-06 confirmed on main)"}
    - {id: TM-MPL-010, category: Information Disclosure / EoP, description: "Shared-cache confusion"}
  trace_to_spec: >
    spec/framework/aws-kms/aws-kms-hierarchical-keyring.md#appendix-a-cache-entry-identifier-formulas, #partition-id
  coverage_gap: 0.7
  coverage_evidence: >
    mpl/tests/test_aws_kms_hierarchical_keyring.rs: cache_entry_identifier_for_encrypt_matches_manual_sha384 (:647),
    ..._for_decrypt_matches_manual_sha384 (:680), ..._encrypt_and_decrypt_differ_for_same_inputs (:708),
    ..._distinct_branch_key_ids_produce_distinct_outputs (:736), ..._distinct_versions_produce_distinct_outputs (:770).
    No NUL-in-field case (BUG-06 has no regression test in mpl/tests).
  rationale: |
    Rescored: TM-MPL-009 Likelihood is now Medium because BUG-06 is a confirmed open defect (RECHECK:
    keyring B served key store A's branch key; key store B called 0 times). cache_entry_identifier.rs
    is unchanged since a1e23d7. The proof gives the exact injectivity boundary and the counterexample.
    A fix (reject 0x00 at build/resolve time, or length-prefix with a spec change) is an owner decision;
    once a NUL check exists at the call sites, `no_nul` becomes a provable precondition. SHA-384
    collision resistance is excluded.
  scoring:
    severity: 3        # TM-MPL-009 High
    coverage_gap: 0.7
    feasibility: 0.7   # TM-MPL-009 Likelihood Medium (was Low)
    blast_radius: 3    # matters for shared caches
    product: "3 × 0.7 × 0.7 × 3 = 4.41"
  quick_win: false
  proof_status: "Partly proved (model level, not the shipped code, under stated hypotheses): 42 verified, 1 errors"
  proof_file: verus-proofs/t13_cache_identifier.rs
  proof_note: "The one error is the intentional expected-FAIL obligation lemma_bug06_injectivity_without_nul_precondition_EXPECTED_FAIL (BUG-06, High, open). The model identifier is injective if and only if the fields are NUL-free; a length-prefixed encoding is injective for all inputs (fix option 2, model only). No duplicate on branch Mahnush_Verus."
  dependencies: []
```

```yaml
recommendation:
  id: VR-2026-T05
  rank: 6
  priority_score: 4.32
  origin: threat-driven
  target:
    crate: aws-crypto-mpl
    file: mpl/src/aws_kms/branch_key_wrap.rs
    function: derive_branch_key (private, :122; returns Zeroizing<[u8; 32]> :125, buffer :135, kbkdf_ctr_hmac call :136)
  property: >
    Fixed-info is exactly "aws-kms-hierarchy"(17) ‖ 0x00 ‖ salt(16) ‖ 0x00000100 (38 bytes),
    PRF HMAC-SHA-256, IKM the 32-byte branch key, OKM 32 bytes. wrap and unwrap reach the KDF only
    through this function.
  formal_spec: |
    fn derive_branch_key(bk: &[u8;32], salt: &[u8;16]) -> (r: Result<Zeroizing<[u8;32]>, Error>)
      ensures ghost_info@ == b"aws-kms-hierarchy"@ + seq![0x00u8] + salt@ + seq![0x00u8, 0x00, 0x01, 0x00]
           && ghost_info@.len() == 38 && ghost_alg == DigestAlg::Sha256 && ghost_okm_len == 32
      ensures r matches Ok(k) ==> (*k)@ == kbkdf_ctr_hmac_spec(Sha256, bk@, ghost_info@, 32)   // uninterpreted, TCB
  tool: Verus
  agent: mpl-verus-header-parsing-proofs
  estimated_effort: 1 day
  threat_references:
    - {id: TM-MPL-014, category: Elevation of Privilege, description: "KBKDF fixed-info / L-value misuse weakens branch-key derivation"}
  trace_to_spec: "spec/framework/aws-kms/aws-kms-hierarchical-keyring.md#branch-key-wrapping; NIST SP 800-108 §4.1"
  coverage_gap: 0.9
  coverage_evidence: >
    Round trips in test_aws_kms_hierarchical_keyring.rs use the same function on both sides, so
    layout drift is undetected. prim/tests/test_kbkdf_ctr_hmac.rs::test_kbkdf_ctr_hmac_raw_vectors (:329) tests only the primitive.
  rationale: "Interop-breaking, possibly weakening, invisible to self-consistent tests. Output now Zeroizing (daac26c), which does not change the layout property."
  scoring:
    severity: 3
    coverage_gap: 0.9
    feasibility: 0.4
    blast_radius: 4
    product: "3 × 0.9 × 0.4 × 4 = 4.32"
  quick_win: false
  proof_status: "Proved (model level, not the shipped code, under stated hypotheses): 33 verified, 0 errors"
  proof_file: verus-proofs/t05_kbkdf_fixed_info.rs
  dependencies: []
```

```yaml
recommendation:
  id: VR-2026-T06
  rank: 7
  priority_score: 4.20
  origin: threat-driven
  target:
    crate: aws-crypto-mpl
    file: mpl/src/aws_kms/hierarchical_keyring.rs; mpl/src/cmc/storm_tracking.rs
    function: >
      on_encrypt `now + self.inner.ttl` (hierarchical_keyring.rs:702); decrypt_edk_at_version `now + self.inner.ttl` (:945);
      StormTrackingCmc::classify_and_mark `now + self.inner.in_flight_ttl` (storm_tracking.rs:333; the state lock is held, taken at :739-740);
      within_grace_interval `inflight + grace_interval` (:680; also called from wait_for_leader at :394 while the guard from :388 is held);
      bounds would live in HierarchicalKeyringBuilder::build (:535; only ttl.is_zero() at :547) and
      StormTrackingCmcBuilder::build (:606; no upper bounds)
  property: >
    No `SystemTime + Duration` addition panics for any configuration the builders accept.
    EXPECTED TO FAIL as written (BUG-01 open): ttl is now a Duration, so Duration::MAX (or any value
    past the platform SystemTime range) is accepted and std's Add panics on overflow.
    Consequence (second pass): the two storm_tracking.rs sites panic while the state mutex is held, so
    unwinding poisons it and every later call on that cache instance returns Internal ("cache lock
    poisoned", :248). One panic is a persistent outage of that cache. The two hierarchical_keyring.rs sites
    panic outside any lock. The property itself, "no overflow panic", is unchanged.
  formal_spec: |
    // SystemTime::add(t, d) requires st_add_ok(t, d)   (TCB external spec)
    fn HierarchicalKeyringBuilder::build(self) -> (r) ensures r matches Ok(k) ==> k.ttl() <= MAX_TTL
    fn StormTrackingCmcBuilder::build(self) -> (r) ensures r matches Ok(c) ==> c.grace_interval() <= MAX_D && c.in_flight_ttl() <= MAX_D
    // add sites verify only once those bounds exist (or the adds become checked_add mapped to an error)
  tool: Verus
  agent: mpl-verus-zero-panic
  estimated_effort: 1 week
  threat_references:
    - {id: TM-MPL-018, category: Denial of Service, description: "Storm-tracking mis-configuration causes failures — here a process panic"}
    - {id: TM-MPL-022, category: Denial of Service, description: "Cache configuration → availability"}
    - {id: TM-MPL-023, category: Denial of Service, description: "Panic instead of error (config-driven)"}
  trace_to_spec: >
    spec/framework/aws-kms/aws-kms-hierarchical-keyring.md#cache-limit-ttl;
    spec/framework/storm-tracking-cryptographic-materials-cache.md#grace-interval, #inflight-ttl
  coverage_gap: 1.0
  coverage_evidence: >
    No large-Duration test: a search for u64::MAX / Duration::MAX in the hierarchical and storm-tracking
    tests finds none (scope). Sub-second tests (build_with_sub_second_ttl_keeps_it_exactly :225) use small values.
  rationale: "BUG-01 confirmed still present by RECHECK. Choosing a bound is an owner decision; Verus closes it afterwards. The lock-poisoning consequence at storm_tracking.rs:333 and :680 does not change the score inputs; the lock-handling slice (compute deadlines before taking the lock) is tracked in T21 (i)."
  scoring:
    severity: 2        # TM-MPL-018 Medium
    coverage_gap: 1.0
    feasibility: 0.7   # TM-MPL-018 Likelihood Medium
    blast_radius: 3
    product: "2 × 1.0 × 0.7 × 3 = 4.20"
  quick_win: false
  proof_status: "None yet"
  dependencies: []
```

```yaml
recommendation:
  id: VR-2026-T07
  rank: 8
  priority_score: 3.84
  origin: threat-driven
  target:
    crate: aws-crypto-mpl + aws-mpl-primitives
    file: mpl/src/keyring/raw_aes_keyring.rs; prim/src/lib.rs
    function: >
      RawAesKeyringBuilder::build (:350); RawAesKeyring::wrap_data_key (:146; IV :152, aes_encrypt call :163);
      <Builtin<RawAesKeyring> as Keyring>::on_encrypt (:399) / on_decrypt (:422; aes_decrypt call :472);
      prim::aes_encrypt (lib.rs:175) / aes_decrypt (:206)
  property: >
    (a) |wrapping_key| == wrapping_alg key length for every built keyring. (b) wrap_data_key allocates
    a fresh 12-byte IV per call, filled by one RNG call, never stored in self; the same bytes are the
    GCM nonce and the provider-info IV. (c) Every aes_encrypt/aes_decrypt call meets the aws-lc-rs
    preconditions (key length, |iv| == 12, |tag| == 16, |pt| == |ct|), so the only aes_decrypt Err is an
    authentication failure. (d) Ok ⇒ |EDK.ciphertext| == |pdk| + 16.
  formal_spec: |
    spec fn inv(k) -> bool { k.inner.wrapping_key@.len() == k.inner.wrapping_alg.key_len() }
    fn build(self) -> (r) ensures r matches Ok(k) ==> inv(k)
    fn wrap_data_key(&self, pdk, aad) -> (r) requires inv(*self)
      ensures r matches Ok(e) ==> e.ciphertext@.len() == pdk@.len() + 16
           && e.key_provider_info@.subrange(|name|+8, |name|+20) == ghost_iv_draw@
  tool: Verus
  agent: mpl-verus-unsafe-ffi-safety
  estimated_effort: 1 week
  threat_references:
    - {id: TM-MPL-011, category: Elevation of Privilege, description: "AES-GCM IV reuse in raw-AES keyring — length + fresh-per-call structure"}
  trace_to_spec: "spec/framework/raw-aes-keyring.md#onencrypt, #ondecrypt, #iv, #wrapping-algorithm, #wrapping-key"
  coverage_gap: 0.8
  coverage_evidence: >
    mpl/tests/test_raw_aes_keyring.rs (25 tests, incl. test_encrypted_data_key_wire_format :406);
    prim/tests/test_aes.rs (bad key/IV length, test_aes_decrypt_output_buffer_too_small :138).
    Still no two-call IV-distinctness test (scope).
  rationale: "Unchanged logic; locations moved into the builder and wrap_data_key. The BUG-07a plaintext residue on aes_encrypt Err is now tracked in T26."
  scoring:
    severity: 4
    coverage_gap: 0.8
    feasibility: 0.4
    blast_radius: 3
    product: "4 × 0.8 × 0.4 × 3 = 3.84"
  quick_win: false
  proof_status: "None yet"
  dependencies: [VR-2026-T20]
```

```yaml
recommendation:
  id: VR-2026-T14
  rank: 9
  priority_score: 3.78
  origin: threat-driven
  target:
    crate: aws-crypto-mpl
    file: mpl/src/aws_kms/hierarchical_keyring.rs
    function: >
      as_branch_key_materials (:1000); cache_entry_within_limits (:989; `elapsed <= ttl` :994);
      generate_partition_id (:626); cache puts in on_encrypt (:700) and decrypt_edk_at_version (:943)
  property: >
    (a) The keyring only puts CachedMaterials::BranchKey; any other variant read back yields Err.
    (b) A cached entry is used only if elapsed(now, creation_time) ≤ ttl, compared as full Durations
    (clock-skew Err mapped to 0). Consequence stated explicitly: an entry whose creation_time is later than
    `now` has elapsed = 0, so it counts as fresh (`unwrap_or(Duration::ZERO)` :993, `elapsed <= ttl` :994).
    The keyring writes entries with `creation_time(now)` (:701, :944), so a future time arises only from a
    clock step backwards or an entry put by other code into a shared cache. The proof states the
    behavior; whether it should be rejected is an owner decision. (c) The default partition id is 16 bytes with the v4 version nibble and
    RFC 4122 variant. (d) Cached entries carry no suite or commitment state.
  formal_spec: |
    fn as_branch_key_materials(e) -> (r) ensures r.is_Ok() <==> e.materials() is BranchKey
    fn cache_entry_within_limits(e, ttl: Duration) -> (r: bool) ensures r <==> elapsed_sat(ghost_now, e.creation_time()) <= ttl
    // elapsed_sat(now, c) == if c > now { 0 } else { now - c }   // so a future creation time is fresh
    fn generate_partition_id() -> (r) ensures r matches Ok(v) ==> v@.len() == 16 && (v@[6] >> 4) == 4 && (v@[8] >> 6) == 2
  tool: Verus
  agent: mpl-verus-header-parsing-proofs
  estimated_effort: 1 week
  threat_references:
    - {id: TM-MPL-010, category: Information Disclosure / EoP, description: "Shared-cache confusion"}
  trace_to_spec: >
    spec/framework/aws-kms/aws-kms-hierarchical-keyring.md#partition-id, #cache-limit-ttl, #shared-cache-considerations
  coverage_gap: 0.6
  coverage_evidence: >
    mpl/tests/test_aws_kms_hierarchical_keyring.rs: partition_id_default_is_16_byte_v4_uuid (:289),
    build_with_shared_cache_round_trips_provided_cache (:484), BUG-09 regression
    on_encrypt_ttl_compares_the_full_duration (:1547). No test injects a wrong-kind cache entry.
  rationale: |
    Rescored: TM-MPL-010 Likelihood Medium (feasibility 0.7). BUG-09 is fixed, so (b) is now expected to
    verify exactly (the old "ttl + 1 s" truncation note is withdrawn). The default partition id can
    contain 0x00, which links to T13. Future work: if a caching CMM is added, its cache id must bind the
    commitment policy or suite (CVE-2026-6550 class); that would be a new target.
  scoring:
    severity: 3        # TM-MPL-010 High
    coverage_gap: 0.6
    feasibility: 0.7   # Likelihood Medium (was Low)
    blast_radius: 3
    product: "3 × 0.6 × 0.7 × 3 = 3.78"
  quick_win: false
  proof_status: "None yet"
  dependencies: [VR-2026-T13]
```

```yaml
recommendation:
  id: VR-2026-T27     # provisional: TM-MPL-025 is static reasoning, unconfirmed until a reproducer exists
  rank: 10
  priority_score: 3.78
  origin: threat-driven
  target:
    crate: aws-crypto-mpl
    file: mpl/src/aws_kms/hierarchical_keyring.rs; mpl/src/cmc/storm_tracking.rs
    function: >
      <Builtin<HierarchicalKeyring> as Keyring>::on_decrypt (:734; supplier-resolved bkid :746-748; EDK loop :751-772,
      filter :752-762, per-EDK attempt :764, error collection :770);
      try_decrypt_edk (:867; length guard :879; version bytes :889-894);
      decrypt_edk_at_version (:901; cache id :908; cache lookup :916-924; key-store read `get_branch_key_version` :934-938;
      put after a successful read :947-953, so a failed read is never cached);
      StormTrackingCmc::classify_and_mark (storm_tracking.rs:264; new key marks a slot in flight :315; fan-out-full wait :310-313;
      duplicate-version wait :326-335); DEFAULT_STORM_FAN_OUT = 20 (:115)
  property: >
    For one decrypt call with an EDK list E and a resolved branch-key id b, let M be the EDKs that pass the
    filter (provider id "aws-kms-hierarchy" and provider info equal to b) and have a ciphertext of at least
    44 bytes. (a) The loop runs at most |E| iterations and makes at most |M| cache lookups and at most |M|
    key-store reads; each read is for the version bytes of one EDK. This verifies on the current code. The cost of
    one read inside the KeyStore (a DynamoDB GetItem and, for an existing record, a KMS Decrypt) is not modeled. (b) EXPECTED TO FAIL: no bound on key-store
    reads that is independent of the sender-chosen |E| exists. The reads are |M| for |M| distinct unknown
    versions, up to 65,535 per message (test_keyring_memory.rs:4), and duplicates of the same unknown version
    re-read, because there is no negative cache and no per-decrypt budget. The proof states the exact bound
    (a) and returns the counterexample to (b); which bound to add (an EDK cap in the MPL, a per-decrypt budget,
    de-duplication of versions within one call, negative caching) is an owner decision. The spec says OnDecrypt
    MUST attempt each EDK in the filtered set (aws-kms-hierarchical-keyring.md:242), so a constant cap is a
    deviation unless the ESDK limit `max_encrypted_data_keys` (default None, esdk/src/config.rs:35, :42) is the
    place that applies it. Excluded: wall-clock time (each duplicate unknown version waits about one grace
    interval, TM-MPL-025 path 3), DynamoDB capacity and KMS cost, and the interleaving of in-flight slots
    (path 2), which belongs to T21 (g) and (h).
  formal_spec: |
    // ghost: ks_calls counts get_branch_key_version calls during one on_decrypt. The KeyStore trait call is an
    // external spec (TCB) that increments it by one. Pure loop fragments are extracted from the async fns.
    spec fn matching(es: Seq<Edk>, b: Seq<char>) -> Seq<Edk>
      { es.filter(|e| e.provider_id == "aws-kms-hierarchy"@ && utf8(e.provider_info) == Some(b) && e.ciphertext.len() >= 44) }
    fn on_decrypt(&self, input) -> (r)
      ensures ghost_iterations <= input.encrypted_data_keys@.len()
      ensures ghost_ks_calls <= matching(input.encrypted_data_keys@, ghost_bkid@).len()          // (a) verifies
      ensures ghost_ks_calls <= MAX_KS_CALLS_PER_DECRYPT                                          // (b) FAILS: no such constant exists
      ensures ghost_ks_calls <= distinct_versions(matching(input.encrypted_data_keys@, ghost_bkid@))  // (b') FAILS: duplicates re-read
    // counterexample for (b): |E| = 65,535 EDKs naming b, each with a distinct unknown version at ciphertext[28..44]
    // counterexample for (b'): the same unknown version repeated n times
  tool: Verus
  agent: mpl-verus-zero-panic   # loop-bound and termination proofs over a pure extraction, as for the sign_fixed_len bound
  estimated_effort: 1 week
  threat_references:
    - {id: TM-MPL-025, category: Denial of Service, description: "Decrypt-input amplification: sender-chosen EDK count and branch-key versions drive key-store reads, in-flight slots and wall-clock time (provisional, static reasoning)"}
    - {id: TM-MPL-018, category: Denial of Service, description: "Paths 2 and 3 rely on the stale in-flight mark and the no-deadline waiter (T21 (g), (h))"}
  trace_to_spec: >
    spec/framework/aws-kms/aws-kms-hierarchical-keyring.md#ondecrypt (:236-249; no bound is specified, the proof is stated
    against the code as baseline assurance); spec/framework/storm-tracking-cryptographic-materials-cache.md#fanout
  coverage_gap: 0.9
  coverage_evidence: >
    mpl/tests/test_keyring_memory.rs::raw_aes_keyring (:100) and ::hierarchical_keyring (:113) decrypt with many
    EDKs but check memory growth only, and the hierarchical case is built so that decrypt never calls the key
    store ("every key is for another keyring"). FakeKeyStore counts get_version calls
    (test_aws_kms_hierarchical_keyring.rs:1306) and asserts single-EDK counts (:1764, :2192), but the only
    several-EDK test (on_decrypt_with_several_failing_edks_aggregates_without_a_single_cause :1998) uses
    ciphertexts shorter than 44 bytes that fail before any key-store call. No test asserts a bound on key-store
    calls per decrypt, and none sends two matching EDKs through the cache and key store.
  rationale: |
    New in the second pass (TM-MPL-025, Risk Medium = Severity Medium x Likelihood Medium, provisional). Path 1
    (one key-store read per matching EDK, no negative cache, no default cap) follows from the code and the default
    configuration. Paths 2 and 3 need a reproducer, and so does the whole threat: a test that sends N EDKs with
    distinct unknown versions through a DefaultCmc and counts key-store calls and elapsed time, and a second one
    with duplicate versions. Until a reproducer exists the threat is unconfirmed and this target is provisional.
    The proof adds value either way: (a) is the exact linear cost, (b) is a precise statement of what is missing,
    and the same loop shape is reused by T19 and T16. BUG-05(b) (a 44-59 byte EDK reaches the key store) is not
    the cause: a valid-length EDK does the same. Blast radius 3 and not 4: reachable only in a service that
    decrypts ciphertext from a third party with a key-store-backed hierarchical keyring.
  scoring:
    severity: 2        # TM-MPL-025 Medium
    coverage_gap: 0.9
    feasibility: 0.7   # TM-MPL-025 Likelihood Medium
    blast_radius: 3
    product: "2 × 0.9 × 0.7 × 3 = 3.78"
  quick_win: false
  proof_status: "None yet"
  dependencies: [VR-2026-T21]   # soft: paths 2 and 3 use T21's in-flight findings
```

```yaml
recommendation:
  id: VR-2026-T26
  rank: 11
  priority_score: 3.20
  origin: threat-driven
  target:
    crate: aws-crypto-mpl + aws-mpl-primitives
    file: mpl/src/keyring/raw_aes_keyring.rs; prim/src/lib.rs; mpl/src/aws_kms/branch_key_wrap.rs; mpl/src/aws_kms/hierarchical_keyring.rs; mpl/src/key_store/kms_ops.rs; mpl/src/cmc/local.rs; prim/src/ecdsa.rs
    function: >
      <Builtin<RawAesKeyring> as Keyring>::on_decrypt (plaintext buffer `vec![0u8; ..]` :471, aes_decrypt-Err path, wrong-length path :489);
      RawAesKeyring::wrap_data_key (`ciphertext` Vec :162 receiving plaintext from aes_encrypt :163);
      prim::aes_encrypt (plaintext copied :185 before the key/nonce checks that can return Err, :188);
      branch_key_wrap::unwrap (:230, returns Vec<u8>) → HierarchicalKeyring::on_decrypt (:767, PlaintextDataKey::new);
      kms_ops::decrypt_branch_key (KMS plaintext Blob `.into_inner()`, returned Vec) → record.rs:100 Zeroizing;
      LocalCmc::get_fresh (local.rs:131) and prune_tail (:166), with CACHE_PRUNING_TAIL_SIZE = 1 (:69): an expired entry is
      dropped only when it is read, falls in the pruned tail, or is evicted at capacity;
      prim::ecdsa_generate_keypair (ecdsa.rs:373: private-key DER copied into a plain `Vec` at :387, dropped on the length-check
      error return :391-392; SignatureKeyPair is `Clone` and not zeroizing, :324-326), whose only in-repo caller moves the
      Vec into the zeroizing SigningKey on success (default_cmm.rs:139, :148)
  property: >
    For each listed function and every exit path (Ok, every Err, every `?`), each heap buffer that has
    held plaintext key bytes is either moved into a ZeroizeOnDrop / Zeroizing owner or zeroized before it
    is dropped. EXPECTED TO FAIL on at least: (F1) raw-AES on_decrypt drops `plaintext_dk` unwiped on the
    aes_decrypt-Err and wrong-length paths; (F2) BUG-07a, prim::aes_encrypt leaves plaintext in the
    caller's buffer on Err and wrap_data_key drops it unwiped; (F3) unwrap's returned Vec and the KMS
    plaintext Vec are plain Vec<u8> between producer and wrapper; (F4) a cache entry holding branch-key
    materials stays resident in plaintext after its expiry time until it is read, pruned or evicted
    (the entry is zeroized on drop, not on expiry), so residency can exceed the TTL; (F5) ecdsa_generate_keypair
    drops `signing_key` (the private-key DER) unwiped when the verification-key length check fails. F4 and F5
    need TA4 (already inside the process), so the threat's likelihood is unchanged. The spec itself says an
    implementation SHOULD avoid F4 (cryptographic-materials-cache.md#background-processing, :179-184).
  formal_spec: |
    // ghost: secret(buf) set when key bytes are written; wiped(buf) set by Zeroize::zeroize or by moving buf
    // into a ZeroizeOnDrop type (zeroize crate drop semantics = TCB external spec)
    spec fn clean_exit(bufs: Set<BufId>) -> bool { forall|b| bufs.contains(b) && secret(b) ==> wiped(b) || moved_to_zod(b) }
    fn on_decrypt(&self, input) -> (r) ensures clean_exit(ghost_local_bufs)        // expected: FAILS (F1)
    fn aes_encrypt(alg, iv, key, msg, aad, ct) -> (r) ensures r.is_Err() ==> ct@ == old(ct)@   // expected: FAILS (F2, BUG-07a)
    fn unwrap(m, ec, ct) -> (r) ensures r matches Ok(v) ==> caller_obligation_wrap(v)          // discharged at hierarchical_keyring.rs:767
    fn ecdsa_generate_keypair(alg) -> (r) ensures r.is_Err() ==> no_live_unwiped(ghost_signing_key_vec)   // expected: FAILS (F5, ecdsa.rs:391-392)
    spec fn wiped_at_expiry(c: LocalCmc, now) -> bool { forall|e| c.store@.contains(e) ==> e.expiry_time() > now }
    fn get_fresh(&self, id) -> (r) ensures wiped_at_expiry(*self, ghost_now)                    // expected: FAILS (F4): only the tail and the read id are checked
  tool: Verus
  agent: mpl-verus-unsafe-ffi-safety
  estimated_effort: 2 weeks
  threat_references:
    - {id: TM-MPL-015, category: Information Disclosure, description: "Secret material not zeroized — transient and error-path copies, expired cache entries resident until read, un-wiped ECDSA private-key Vec on an error path (residual after zeroize-on-drop)"}
  trace_to_spec: "spec/framework/structures.md#plaintext-data-key ('kept secret'); no clause mandates zeroization — baseline assurance; spec/framework/cryptographic-materials-cache.md#background-processing (SHOULD remove expired entries, relevant to F4)"
  coverage_gap: 1.0
  coverage_evidence: >
    Zeroize tests cover the types only (test_encryption_materials.rs::test_plaintext_data_key_zeroize :248,
    test_decryption_materials.rs::test_plaintext_data_key_zeroize_decryption :228). No test checks the
    transient or error-path buffers listed here. For F4, test_local_cmc.rs::test_pruning_does_not_evict_outside_tail (:465)
    asserts that an expired entry outside the pruning tail survives, so the tests encode the residency. For F5, the
    error return is unreachable from a test (key length is fixed by the algorithm), and no test checks wiping.
  rationale: |
    Replaces retired T08. The long-lived secret types now zeroize on drop, so TM-MPL-015 was lowered to
    Medium/Low; what remains is exactly these transient sites (threat model §8 TM-MPL-015 residuals,
    mpl-spec-security-analysis.md). Verus does not model Drop natively, so the proof needs ghost "secret /
    wiped" state over local buffers; that is why the effort is 2 weeks. Fixes (Zeroizing buffers;
    truncate or wipe the output on aes_encrypt Err) change behavior and are owner decisions.
    Second pass (TM-MPL-015, rating Low unchanged): F4 and F5 were added; the score does not change because the
    gap was already 1.0. A fix for F4 (an active sweep of expired entries) or F5 (Zeroizing around the Vec)
    is an owner decision. Excluded: Vec reallocation copies, allocator/OS residency, the cache holding branch
    keys for the TTL by design, aws-lc-rs internal buffers (including the `EcPrivateKeyRfc5915Der` it returns).
  scoring:
    severity: 2        # TM-MPL-015 Medium (was High)
    coverage_gap: 1.0
    feasibility: 0.4   # Low
    blast_radius: 4
    product: "2 × 1.0 × 0.4 × 4 = 3.20"
  quick_win: false
  proof_status: "None yet"
  related_bugs:
    - {bug: BUG-10, severity: Low, evidence: "code reading, no proof (mpl is not Verus-enabled)", threat: TM-MPL-015, target: T26, note: "RawAesKeyring::on_decrypt drops an authenticated plaintext data key un-wiped on the wrong-length path (site F1); branch_key_wrap::unwrap holds a plain Vec<u8> (site F3)"}
    - {bug: "BUG-07(a)", evidence: "prim-side facts proved in-crate on Mahnush_Verus (C03, VR-014); caller impact is code reading", threat: TM-MPL-015, target: "T26 (F2)", note: "callers wrap_data_key and branch_key_wrap::wrap drop the plaintext data key un-wiped on an aes_encrypt Err; cannot fire today"}
  scope_note: >
    Scope note only; no property, score, coverage gap, feasibility or severity changed. BUG-10 is the bug report for site F1's wrong-length continue
    (raw_aes_keyring.rs:489-494: an authenticated plaintext data key is dropped un-wiped, while the success path at :497 moves the buffer into PlaintextDataKey)
    and for F3's branch_key_wrap::unwrap buffer (:275, a bare Vec<u8> is returned). The BUG-07(a) caller impact names one caller that the function list above does not:
    branch_key_wrap::wrap (branch_key_wrap.rs:157, aes_encrypt call :199); wrap_data_key (raw_aes_keyring.rs:163) is already in F2. The failure cannot fire today:
    key and IV sizes are fixed by type in wrap, and the raw-AES wrapping-key length is checked at RawAesKeyringBuilder::build (raw_aes_keyring.rs:369-379).
  dependencies: []
```

```yaml
recommendation:
  id: VR-2026-T10
  rank: 12
  priority_score: 2.88
  origin: threat-driven
  target:
    crate: aws-crypto-mpl
    file: mpl/src/aws_kms/branch_key_wrap.rs; mpl/src/aws_kms/hierarchical_keyring.rs
    function: compute_aad (branch_key_wrap.rs:61); uuid_str_to_16_bytes (:92, private); uuid_16_bytes_to_str (hierarchical_keyring.rs:644, private)
  property: >
    compute_aad returns Ok exactly when the version is a 36-char canonical UUID and the EC is
    serializable; the AAD is then "aws-kms-hierarchy" ‖ utf8(bkid) ‖ uuid_bytes(version) ‖ to_bytes(ec).
    For a fixed bkid, (version, ec) ↦ AAD is injective. For every 16-byte b,
    uuid_str_to_16_bytes(uuid_16_bytes_to_str(b)) == Ok(b).
  formal_spec: |
    fn compute_aad(bkid, ver, ec) -> (r) ensures r.is_Ok() <==> canonical_uuid(ver@) && serializable(ec@)
      ensures r matches Ok(a) ==> a@ == "aws-kms-hierarchy"@ + bkid@ + uuid_bytes(ver@) + ser(ec@)
    proof fn aad_injective_fixed_bkid(..) ensures uuid_bytes(v1@) == uuid_bytes(v2@) && e1@ == e2@   // uses T15
    proof fn uuid_round_trip(b: [u8;16]) ensures uuid_str_to_16_bytes(&uuid_16_bytes_to_str(&b), _) == Ok(b)
  tool: Verus
  agent: mpl-verus-header-parsing-proofs
  estimated_effort: 1 week
  threat_references:
    - {id: TM-MPL-013, category: Tampering, description: "Branch-key wrap/unwrap AAD constructed inconsistently"}
  trace_to_spec: "spec/framework/aws-kms/aws-kms-hierarchical-keyring.md#branch-key-wrapping-and-unwrapping-aad"
  coverage_gap: 0.6
  coverage_evidence: "mpl/tests/test_aws_kms_hierarchical_keyring.rs: compute_aad_layout_for_known_inputs (:826) and mismatch/round-trip tests."
  rationale: "Expected: cross-bkid injectivity is false (no length prefix; spec layout), harmless because each AAD is used under its own branch key. Unchanged since a1e23d7."
  scoring:
    severity: 3
    coverage_gap: 0.6
    feasibility: 0.4
    blast_radius: 4
    product: "3 × 0.6 × 0.4 × 4 = 2.88"
  quick_win: false
  proof_status: "None yet"
  dependencies: [VR-2026-T15]
```

```yaml
recommendation:
  id: VR-2026-T11
  rank: 13
  priority_score: 2.88
  origin: threat-driven
  target:
    crate: aws-crypto-mpl
    file: mpl/src/aws_kms/mrk_match.rs; mpl/src/key_store/kms_config.rs
    function: aws_kms_mrk_match_for_decrypt (mrk_match.rs:24); is_multi_region_arn (:52); is_alias_arn (:62); is_arn_compatible (kms_config.rs:86); parse_arn (:31)
  property: >
    True exactly when neither input is an alias ARN and either the inputs are identical, or both are MRK
    ARNs (6 ':'-segments, "arn", service "kms", resource "key/mrk-…") equal on partition, service,
    account, resource type and id, region the only possible difference. Symmetric. is_arn_compatible
    is byte-equality for KmsKeyArn, the MRK match for KmsMrKeyArn, true for Discovery modes.
  formal_spec: |
    fn aws_kms_mrk_match_for_decrypt(a, b) -> (r: bool)
      ensures r <==> !is_alias(a@) && !is_alias(b@) && (a@ == b@ || (is_mrk(a@) && is_mrk(b@) && same_except_region(a@, b@)))
      ensures r == aws_kms_mrk_match_for_decrypt_spec(b@, a@)
  tool: Verus
  agent: mpl-verus-header-parsing-proofs
  estimated_effort: 2 weeks
  threat_references:
    - {id: TM-MPL-004, category: Tampering, description: "ARN/MRK match accepts a non-matching key ARN"}
  trace_to_spec: "spec/framework/aws-kms/aws-kms-mrk-match-for-decrypt.md#implementation; spec/framework/branch-key-store.md#aws-key-arn-compatibility"
  coverage_gap: 0.6
  coverage_evidence: "mpl/tests/test_aws_kms_mrk_match.rs (incl. identical_aliases_return_false :32); mpl/tests/test_key_store_kms_config.rs."
  rationale: "Parser inconsistency to settle: mrk_match uses split(':') (exactly 6) while parse_arn uses splitn(6, ':'). Unchanged logic."
  scoring:
    severity: 3
    coverage_gap: 0.6
    feasibility: 0.4
    blast_radius: 4
    product: "3 × 0.6 × 0.4 × 4 = 2.88"
  quick_win: false
  proof_status: "None yet"
  dependencies: []
```

```yaml
recommendation:
  id: VR-2026-T12
  rank: 14
  priority_score: 2.88
  origin: threat-driven
  target:
    crate: aws-crypto-mpl
    file: mpl/src/cmm/default_cmm.rs
    function: merge_reproduced_encryption_context (:273, private); call in decrypt_materials (:177, call :198)
  property: >
    No reproduced EC → (message EC, ∅). Otherwise Ok exactly when both agree on every shared key; then
    ec = m ∪ r, m ⊆ ec, required keys = dom(r) \ dom(m) ⊆ dom(ec). The EC given to the keyring is
    exactly the merged map.
  formal_spec: |
    fn merge_reproduced_encryption_context(m, r) -> (res)
      ensures r is None ==> res == Ok((*m, empty))
      ensures r matches Some(rr) ==> (res.is_Ok() <==> forall|k| m@.contains_key(k) && rr@.contains_key(k) ==> m@[k] == rr@[k])
      ensures res matches Ok((ec, req)) && r matches Some(rr) ==> ec@ == m@.union_prefer_right(rr@) && req@ == rr@.dom().difference(m@.dom())
  tool: Verus
  agent: mpl-verus-header-parsing-proofs
  estimated_effort: 1 week
  threat_references:
    - {id: TM-MPL-017, category: Tampering, description: "Reproduced-EC merge drops or alters bound context"}
  trace_to_spec: "spec/framework/cmm-interface.md#decrypt-materials; spec/framework/default-cmm.md#decrypt-materials"
  coverage_gap: 0.6
  coverage_evidence: "mpl/tests/test_default_cmm.rs reproduced-EC tests (e.g. test_decrypt_materials_reproduced_ec_mismatched_values_fails :538)."
  rationale: "The transition checks now stop a keyring from altering the EC afterwards (C07), but the merge itself is still the only guard that decrypt AAD equals encrypt AAD."
  scoring:
    severity: 3
    coverage_gap: 0.6
    feasibility: 0.4
    blast_radius: 4
    product: "3 × 0.6 × 0.4 × 4 = 2.88"
  quick_win: false
  proof_status: "None yet"
  dependencies: []
```

```yaml
recommendation:
  id: VR-2026-T09
  rank: 15
  priority_score: 2.56
  origin: threat-driven
  target:
    crate: aws-crypto-mpl
    file: mpl/src/structures/commitment_policy.rs; mpl/src/cmm/default_cmm.rs; mpl/src/structures/materials_checks.rs
    function: >
      CommitmentPolicy::{default_algorithm_suite_id (:43), allows_for_encrypt (:62), allows_for_decrypt (:77)};
      AlgorithmSuiteId::specification / key_commitment; DefaultCmm get_encryption_materials (:85, gate :97) /
      decrypt_materials (:177, gate :184); suite frame enforced by check_encryption_transition (materials_checks.rs:72) /
      check_decryption_transition (:117)
  property: >
    key_commitment() holds exactly for 0x0478 and 0x0578. The allow-tables match commitment-policy.md for
    3 policies × 11 suites, and each policy's default suite is encrypt-allowed (FORBID default is now
    0x0378, a documented deviation from the spec's 0x0014 that is still non-committing).
    get_encryption_materials returns Ok only with an encrypt-allowed suite; decrypt_materials returns Err
    without calling the keyring when the suite is not decrypt-allowed.
  formal_spec: |
    ensures p.allows_for_encrypt(id) <==> match p { Esdk(ForbidEncryptAllowDecrypt) => !committing(id), _ => committing(id) }
    ensures p.allows_for_decrypt(id) <==> match p { Esdk(RequireEncryptRequireDecrypt) => committing(id), _ => true }
    ensures p.allows_for_encrypt(p.default_algorithm_suite_id())
    fn get_encryption_materials(..) -> (r) ensures r matches Ok(o) ==> policy.allows_for_encrypt(o.materials.algorithm_suite_id())
    // keyring frame now a lemma of C07: check_encryption_transition Ok ⇒ suite unchanged
  tool: Verus
  agent: mpl-verus-header-parsing-proofs
  estimated_effort: 1 week
  threat_references:
    - {id: TM-MPL-006, category: Elevation of Privilege, description: "Algorithm-suite downgrade / commitment-policy bypass"}
    - {id: TM-MPL-008, category: Elevation of Privilege, description: "Non-committing suite reuse (Invisible Salamanders) — code-gate slice"}
  trace_to_spec: "spec/framework/commitment-policy.md; spec/framework/default-cmm.md#get-encryption-materials, #decrypt-materials"
  coverage_gap: 0.4
  coverage_evidence: >
    mpl/tests/test_commitment_policy.rs (full policy × suite table); mpl/tests/test_default_cmm.rs
    (e.g. test_decrypt_materials_unsupported_suite_for_policy_fails :382); mpl/tests/test_materials_checks.rs
    on_encrypt_rejects_a_changed_algorithm_suite (:271). The runtime transition check enforces the frame on every send().
  rationale: |
    Rescored (gap 0.5 → 0.4): the "keyring preserves the suite" assumption is now a runtime check on every
    fluent path, so a third-party keyring can no longer break the CMM postcondition through SharedKeyring.
    SharedCmm::send() checks completeness only, not the policy (mpl/src/cmm/fluent_builders.rs:168-171 encrypt,
    :316-319 decrypt, both calling the materials_checks::check_*_materials_complete functions). So a third-party
    CMM behind a SharedCmm is not policy-checked inside the MPL; the proof covers the DefaultCmm gates
    (default_cmm.rs:97, :184) plus the ESDK re-check (esdk/src/materials.rs:130 decrypt, :202 encrypt).
  scoring:
    severity: 4        # TM-MPL-006 Critical
    coverage_gap: 0.4
    feasibility: 0.4
    blast_radius: 4
    product: "4 × 0.4 × 0.4 × 4 = 2.56"
  quick_win: false
  proof_status: "None yet"
  dependencies: [VR-2026-C07]   # soft: frame lemma
```

```yaml
recommendation:
  id: VR-2026-T16
  rank: 16
  priority_score: 2.24
  origin: threat-driven
  target:
    crate: aws-crypto-mpl
    file: >
      mpl/src/aws_kms/branch_key_wrap.rs; mpl/src/aws_kms/hierarchical_keyring.rs; mpl/src/keyring/raw_aes_keyring.rs;
      mpl/src/structures/encryption_context.rs; mpl/src/aws_kms/mrk_match.rs; mpl/src/aws_kms/cache_entry_identifier.rs;
      mpl/src/cmm/default_cmm.rs; mpl/src/key_store/branch_key_store.rs; mpl/src/aws_kms/user_agent.rs
    function: >
      unwrap (guard :236, .expect :249/:252/:256); try_decrypt_edk (guard :879, .expect :892);
      on_decrypt UTF-8 filter (hierarchical :734); raw-AES on_decrypt split_at (:469) / decryptable_edk_iv split_at (:201/:206/:212);
      EncryptionContext::from_bytes (:145, offset arithmetic :166-197); aws_kms_mrk_match_for_decrypt pa[5]/pb[5] (:40-41);
      build_cache_identifier .expect (:64); DefaultCmm .expect (:123) and ecdsa_generate_keypair .expect (:138, BUG-05a);
      version_key `new_decrypt_only_ec[ATTR_TYPE]` (:719); user_agent_override .expect (user_agent.rs:17)
  property: >
    For every input (EDK ciphertext, provider info, serialized EC bytes, ARN strings) these paths return
    and never panic: each slice/index is preceded by a guard implying it is in range, each try_into
    length is exact, offset arithmetic cannot overflow.
  formal_spec: |
    fn unwrap(m, ec, ct) -> (r)          // total; ct.len() >= 60 ⇒ all slices in range
    fn try_decrypt_edk(..)               // ct.len() >= 44 ⇒ [28..44] has len 16
    fn from_bytes(b) -> (r)              // loop inv: offset <= b.len()
    fn aws_kms_mrk_match_for_decrypt(a, b) -> (r)   // is_multi_region_arn(x) ⇒ 6 segments ⇒ index 5 valid
    // EXPECTED-UNPROVABLE (report, do not axiomatize): default_cmm.rs:138 ecdsa_generate_keypair(..).expect (BUG-05a)
  tool: Verus
  agent: mpl-verus-zero-panic
  estimated_effort: 1 week
  threat_references:
    - {id: TM-MPL-023, category: Denial of Service, description: "Malformed EDK/ciphertext triggers panic instead of error"}
  trace_to_spec: "spec/framework/aws-kms/aws-kms-hierarchical-keyring.md#ondecrypt; spec/framework/raw-aes-keyring.md#ondecrypt; spec/framework/structures.md#serialization"
  coverage_gap: 0.7
  coverage_evidence: >
    unwrap_too_short_ciphertext_returns_error (:1187), on_decrypt_skips_edks_with_non_utf8_provider_info (:1841);
    test_raw_aes_keyring.rs negative provider-info tests; test_encryption_context.rs insufficient-bytes tests; test_aws_kms_mrk_match.rs.
  rationale: |
    The old key-store client `.expect` sites are gone (clients are non-Option after build, branch_key_store.rs:101-108).
    The storm-tracking `.expect`s (:199, :213, :227) are test-utils introspection accessors and out of scope.
    BUG-05(b) observation stands: a 44–59-byte EDK costs one cache/key-store lookup before unwrap rejects it.
  scoring:
    severity: 2        # TM-MPL-023 Medium
    coverage_gap: 0.7
    feasibility: 0.4
    blast_radius: 4
    product: "2 × 0.7 × 0.4 × 4 = 2.24"
  quick_win: false
  proof_status: "None yet"
  dependencies: []
```

```yaml
recommendation:
  id: VR-2026-T21
  rank: 17
  priority_score: 2.24
  origin: threat-driven
  target:
    crate: aws-crypto-mpl
    file: mpl/src/cmc/storm_tracking.rs; mpl/src/aws_kms/hierarchical_keyring.rs (call sites that can leave a mark behind)
    function: >
      StormTrackingCmcBuilder::build (:606; checks :613, :616, :619, :622); StormTrackingCmc::{state_locked (:239; skips the caller's own
      key when pruning, :250-255), classify_and_mark (:264; fan-out-full miss returns `Wait { deadline: None }` :313; stale-mark error
      :322-323; `now + in_flight_ttl` :333), wait_for_leader (:360; deadline check :378-382; guard taken :388; leader test :390-394)};
      Cmc::put_cache_entry impl (:710; inner put :721, mark cleared :724-725); Cmc::get_cache_entry impl (:729; guard taken and
      classify called under it :739-740); within_grace_period (:661); within_grace_interval (:675).
      Call sites whose error path leaves a mark behind: HierarchicalKeyring decrypt_edk_at_version (hierarchical_keyring.rs:934-938, the
      `.await?` before the put at :947-953) and on_encrypt (:692-696, before the put at :704-710)
  property: >
    (a) build returns Ok exactly when the spec constraints hold: fan_out ≥ 1, in_flight_ttl > 0, sleep > 0,
    grace_interval ≤ in_flight_ttl, AND grace_interval ≤ grace_period, in_flight_ttl ≤ grace_period, grace
    period and grace interval ≥ the spec minimum. EXPECTED TO FAIL: build no longer checks the
    grace_period orderings or minimums (mitigation regressed). (b) Under the mutex every production state
    step preserves |inflight| ≤ fan_out. (c) A key already in flight yields a new leader only after its grace
    interval. (d) put_cache_entry writes the inner cache before clearing the mark. (e) within_grace_* match
    the spec formulas. (f) A poisoned lock maps to Kind::Internal, never a panic.
    Added in the second pass (TM-MPL-018 findings 1 to 3, static reasoning, not run):
    (g) Stale in-flight mark. A leader that never reaches put_cache_entry (a key-store error at the call
    sites above, or a cancelled caller) leaves its key marked, and nothing on that error path clears it.
    Recovery property: if a key's mark is older than in_flight_ttl, the next get for that same key either
    becomes a leader or removes the stale mark. EXPECTED TO FAIL: state_locked deliberately skips the
    caller's own key (:251), and classify_and_mark returns the in-flight error without changing the state
    (:322-323), so the same key stays wedged until a call for a different key prunes it. The spec requires the
    error but does not say who clears the mark. A leader may retake the slot between the grace interval and
    the TTL (:337), so the wedge needs the next same-key call to arrive after in_flight_ttl with no other key
    in between (a low-traffic, single-key, encrypt-only service).
    (h) Waiter with no deadline. Every Wait decision carries a deadline no later than now + in_flight_ttl, as the
    spec's FanOut text requires (a blocked request gives up when it has been outstanding longer than the
    Inflight TTL). EXPECTED TO FAIL: the fan-out-full miss returns `deadline: None` (:313), and
    wait_for_leader then ends only when a slot frees (a prune after in_flight_ttl, or a put).
    (i) Panic under the state lock. No SystemTime + Duration addition runs while the guard from state_locked
    is held, or the additions cannot panic. EXPECTED TO FAIL with BUG-01 (T06): `now + in_flight_ttl` (:333)
    and `inflight + grace_interval` (:680) run inside classify_and_mark and wait_for_leader under the guard
    (:739-740, :388-394); unwinding poisons the mutex, and every later call on that cache instance returns
    Internal "cache lock poisoned" (:248). Config-driven (an unbounded duration), but the failure is then
    permanent for that instance. (f) is the proof that the poisoned state is an error, not a panic.
  formal_spec: |
    fn build(self) -> (r) ensures r.is_Ok() <==> fo >= 1 && !it.is_zero() && !sl.is_zero() && gi <= it
                                              && gi <= gp && it <= gp && gp >= MIN && gi >= MIN   // FAILS today
    spec fn inv(s, fo) -> bool { s.inflight@.len() <= fo }
    fn classify_and_mark(&self, s, id, cached, now) -> (r) requires inv(*old(s), self.fan_out) ensures inv(*s, self.fan_out)
    fn within_grace_interval(t, now, gi) -> (r) requires st_add_ok(t, gi) ensures r <==> now < t + gi   // see T06
    // (g) recovery: a stale mark is never a fixed point of a same-key get            // FAILS today (:322-323 keeps the mark)
    fn classify_and_mark(&self, s, id, None, now) -> (r)
      requires old(s).inflight@.contains_key(id@) && now - old(s).inflight@[id@] > self.in_flight_ttl
      ensures r is Ok(Ready(None)) || !s.inflight@.contains_key(id@)
    // (h) every wait is bounded                                                      // FAILS today (:313)
    fn classify_and_mark(&self, s, id, None, now) -> (r)
      ensures r matches Ok(Wait { deadline }) ==> deadline is Some(d) && d <= now + self.in_flight_ttl
    // (i) no panic under the lock: classify_and_mark and wait_for_leader are total, or the sums are checked_add
    //     with the failure mapped to Err; requires st_add_ok(now, self.in_flight_ttl) is not assumed
  tool: Verus
  agent: mpl-verus-zero-panic   # sequential slice; cat-4 interleavings → concurrency specialist
  estimated_effort: 1 month
  threat_references:
    - {id: TM-MPL-018, category: Denial of Service, description: "Storm-tracking misconfiguration or logic error; second pass adds the stale-mark wedge, the no-deadline waiter and the poisoned state lock"}
  trace_to_spec: "spec/framework/storm-tracking-cryptographic-materials-cache.md#initialization, #fanout, #inflight-ttl, #in-flight, #putcacheentry, #within-grace-period, #within-grace-interval, #getcacheentry"
  coverage_gap: 0.8
  coverage_evidence: >
    mpl/tests/test_storm_tracking_cmc.rs (33 tests, was 38): test_within_grace_interval_matches_spec_formula (:545),
    test_sub_second_grace_period_is_honored (:283), test_concurrent_gets_on_same_key_coalesce_to_one_refresh (:1295).
    test_durations_are_stored_exactly (:388) asserts grace_period = 0 is accepted, i.e. the tests encode the regressed contract.
    (g): test_get_miss_inflight_exceeds_ttl_fails (:761) pre-marks a key and asserts the error; no test checks recovery
    after a failed refresh. (h): test_get_miss_blocks_when_fanout_saturated_until_key_appears (:699) and
    test_block_miss_not_inflight_prunes_stale_entries_in_loop (:1021) end the wait by a put or a prune, so they pass
    with the missing deadline. (f), (i): no test exercises a poisoned lock or a large Duration (`grep poison` in mpl/tests is empty).
  rationale: |
    Rescored (gap 0.7 to 0.8, score 1.96 to 2.24). The first step (0.6 to 0.7) was the missing spec-ordering tests.
    This step adds three properties of which (g) and (f)/(i) have no test and (h) has tests that cannot detect
    its defect; (b) to (e) keep direct tests including negative cases, so the gap is "some unit tests" (0.8), not 0.9.
    No rating changed (TM-MPL-018 stays Medium), so severity 2 and feasibility 0.7 are unchanged. If a reproducer
    confirms (g), the threat model says severity could rise to High; at Likelihood Low the risk would stay Medium, so
    nothing changes here without one. The attacker-driven side of (g) and (h) is T27 (TM-MPL-025). Excluded: liveness
    under a real scheduler and the Tokio-only runtime; (g) and (h) are stated as properties of the pure classify step
    over an abstract clock, not as scheduler liveness. The concurrency interleavings stay with the specialist.
  scoring:
    severity: 2
    coverage_gap: 0.8
    feasibility: 0.7   # TM-MPL-018 Likelihood Medium
    blast_radius: 2    # storm-tracking cache (now also the DefaultCmc default with rt-tokio)
    product: "2 × 0.8 × 0.7 × 2 = 2.24"
  quick_win: false
  proof_status: "None yet"
  dependencies: [VR-2026-T06]
```

```yaml
recommendation:
  id: VR-2026-T15
  rank: 18
  priority_score: 1.92
  origin: threat-driven
  target:
    crate: aws-crypto-mpl
    file: mpl/src/structures/encryption_context.rs
    function: EncryptionContext::to_bytes (:91); EncryptionContext::from_bytes (:145; duplicate / order checks :198-211); utf8 (:231)
  property: >
    to_bytes returns Ok exactly when |ec| ≤ 65535 and every key and value ≤ 65535 bytes; then it emits the
    sorted spec layout. to_bytes is injective, from_bytes(to_bytes(ec)) == Ok(ec), and (now that BUG-03 is
    fixed) from_bytes(b) == Ok(ec) ⇒ to_bytes(ec) == Ok(b): accepted bytes are canonical.
  formal_spec: |
    fn to_bytes(&self) -> (r) ensures r matches Ok(b) ==> b@ == ser(self@)
    proof fn ser_injective(m1, m2) requires ser(m1) == ser(m2) ensures m1 == m2
    fn from_bytes(b) -> (r) ensures r matches Ok(ec) ==> ser(ec@) == b@      // expected to VERIFY on 620771c
    // open question for the owner, not a proof failure: from_bytes accepts empty keys (test :468)
  tool: Verus
  agent: mpl-verus-header-parsing-proofs
  estimated_effort: 2 weeks
  threat_references:
    - {id: TM-MPL-013, category: Tampering, description: "AAD consistency depends on EC serialization determinism"}
    - {id: TM-MPL-017, category: Tampering, description: "Bound context must survive the round trip"}
  trace_to_spec: "spec/framework/structures.md#serialization"
  coverage_gap: 0.4
  coverage_evidence: >
    mpl/tests/test_encryption_context.rs (45 tests, was 37): test_round_trip_preserves_all_entries (:79),
    test_out_of_order_keys_rejected_on_deserialize (:68), invalid-UTF-8 tests (:502-533),
    test_deserialize_accepts_empty_key_length_currently_unenforced (:468). from_bytes now enforces order, uniqueness and UTF-8 at runtime.
  rationale: "Rescored after BUG-03 fix: the previous expected counterexample no longer exists, so the non-malleability theorem becomes the goal."
  scoring:
    severity: 3        # TM-MPL-013 High
    coverage_gap: 0.4
    feasibility: 0.4
    blast_radius: 4
    product: "3 × 0.4 × 0.4 × 4 = 1.92"
  quick_win: false
  proof_status: "None yet"
  dependencies: []
```

```yaml
recommendation:
  id: VR-2026-T17
  rank: 19
  priority_score: 1.92
  origin: threat-driven
  target:
    crate: aws-crypto-mpl
    file: mpl/src/key_store/kms_ops.rs; mpl/src/key_store/kms_config.rs
    function: resolve_key_store_arn Discovery arm (:96-98) / MrDiscovery arm (:100-102); reject_alias_arn (:118); rewrite_arn_region (:144); parse_arn (kms_config.rs:31)
  property: >
    Discovery: Ok(record ARN) exactly when parse_arn succeeds and resource_type ≠ "alias".
    MrDiscovery: the region is rewritten only for MRK ARNs ("key/mrk-"), per branch-key-store.md#mrdiscovery.
    EXPECTED TO FAIL (BUG-04 open): rewrite_arn_region rewrites every non-alias ARN, including
    single-Region keys; it fails closed at KMS.
  formal_spec: |
    fn resolve_key_store_arn(c, rec, bkid) -> (r)
      ensures c is Discovery ==> (r.is_Ok() <==> parse_arn_spec(rec@) matches Ok(p) && p.resource_type@ != "alias"@)
      ensures c matches MrDiscovery(m) && r matches Ok(k) ==>
                (is_mrk(rec@) ==> parse_arn_spec(k@) == Ok(parse_arn_spec(rec@)->Ok_0.with_region(m.region@)))
             && (!is_mrk(rec@) ==> k@ == rec@)          // FAILS today (BUG-04)
    proof fn parse_format_round_trip(p) requires well_formed(p) ensures parse_arn_spec(format_spec(p)) == Ok(p)
  tool: Verus
  agent: mpl-verus-header-parsing-proofs
  estimated_effort: 1 week
  threat_references:
    - {id: TM-MPL-007, category: Elevation of Privilege, description: "Discovery/MRDiscovery decrypts under an alias or attacker-region key"}
  trace_to_spec: "spec/framework/branch-key-store.md#discovery, #mrdiscovery, #aws-kms-branch-key-decryption"
  coverage_gap: 0.8
  coverage_evidence: >
    test_key_store_kms_config.rs parse_arn tests; test_key_store_branch_key_store.rs new_with_mr_discovery_config_succeeds (:245)
    and discovery create/version rejection tests. reject_alias_arn and rewrite_arn_region are private with no unit test; no non-MRK MRDiscovery test.
  rationale: "BUG-04 confirmed by RECHECK; the proof both documents the deviation and verifies the fix once an `mrk-` check is added."
  scoring:
    severity: 3
    coverage_gap: 0.8
    feasibility: 0.4
    blast_radius: 2    # opt-in Discovery / MRDiscovery
    product: "3 × 0.8 × 0.4 × 2 = 1.92"
  quick_win: false
  proof_status: "None yet"
  dependencies: []
```

```yaml
recommendation:
  id: VR-2026-T18
  rank: 20
  priority_score: 1.92
  origin: threat-driven
  target:
    crate: aws-crypto-mpl
    file: mpl/src/key_store/branch_key_store.rs
    function: >
      <Builtin<DynamoDbKeyStore> as KeyStore>::version_key (:641) — authentication ReEncrypt with old_active_ec
      (:671, :678) and the inline EC derivation (:706-722); conditional writes (:743, :752)
  property: >
    New DECRYPT_ONLY EC = old minus `version`, type = "branch:version:"+v, create-time = ts. New ACTIVE EC =
    DECRYPT_ONLY with version = "branch:version:"+v and type = "branch:ACTIVE". Both preserve branch-key-id,
    kms-arn, hierarchy-version, tablename and every `aws-crypto-ec:` entry, and agree with
    key_store::encryption_context::{decrypt_only,active}_encryption_context for the same inputs.
  formal_spec: |
    fn derive_version_ecs(old, v, ts) -> (r) requires old@["type"@] == "branch:ACTIVE"@
      ensures r.0@ == old@.remove("version"@).insert("type"@, "branch:version:"@ + v@).insert("create-time"@, ts@)
      ensures r.1@ == r.0@.insert("version"@, "branch:version:"@ + v@).insert("type"@, "branch:ACTIVE"@)
  tool: Verus
  agent: mpl-verus-header-parsing-proofs
  estimated_effort: 1 week
  threat_references:
    - {id: TM-MPL-016, category: Tampering, description: "VersionKey optimistic-lock bypass — EC derivation + self-authentication slice"}
  trace_to_spec: "spec/framework/branch-key-store.md#versionkey, #authenticating-a-keystore-item"
  coverage_gap: 0.8
  coverage_evidence: "test_key_store_branch_key_store.rs (version_key dispatch / discovery rejection); live-AWS integ only for the derivation; test_key_store_encryption_context.rs::active_is_decrypt_only_with_type_and_version_overrides (:214) covers the other module."
  rationale: "version_key still builds the new ECs inline. DDB transaction semantics excluded."
  scoring:
    severity: 2
    coverage_gap: 0.8
    feasibility: 0.4
    blast_radius: 3
    product: "2 × 0.8 × 0.4 × 3 = 1.92"
  quick_win: false
  proof_status: "None yet"
  dependencies: [VR-2026-T01]
```

```yaml
recommendation:
  id: VR-2026-T19
  rank: 21
  priority_score: 1.92
  origin: threat-driven
  target:
    crate: aws-crypto-mpl
    file: mpl/src/aws_kms/hierarchical_keyring.rs
    function: >
      resolve_branch_key_id (:831); on_decrypt filter (:734, bkid compare :760); try_decrypt_edk (:867) →
      decrypt_edk_at_version (:901, cache id :908); on_encrypt EDK provider info (:722); BranchKeyIdSupplier trait (:187)
  property: >
    Static id configured ⇒ resolve returns exactly it. on_decrypt attempts an EDK only if provider id ==
    "aws-kms-hierarchy" and utf8(provider info) == resolved bkid. The key-store/cache query uses that bkid and
    the version decoded from ct[28..44]. on_encrypt emits provider info = resolved bkid bytes.
  formal_spec: |
    fn on_decrypt(&self, input) -> (r) ensures forall|e| ghost_attempted.contains(e) ==> e.key_provider_id@ == "aws-kms-hierarchy"@
              && utf8_decode(e.key_provider_info@) == Some(ghost_bkid@)
    fn on_encrypt(&self, input) -> (r) ensures r matches Ok(o) ==> o.materials.edks@.last().key_provider_info@ == ghost_bkid@.as_bytes()
  tool: Verus
  agent: mpl-verus-header-parsing-proofs
  estimated_effort: 1 week
  threat_references:
    - {id: TM-MPL-003, category: Spoofing, description: "Malicious supplier returns attacker-chosen id — the id is bound consistently"}
  trace_to_spec: "spec/framework/aws-kms/aws-kms-hierarchical-keyring.md#onencrypt, #ondecrypt, #branch-key-supplier"
  coverage_gap: 0.6
  coverage_evidence: "on_decrypt_skips_edks_with_wrong_branch_key_id (:1872), ..._non_utf8_provider_info (:1841), on_encrypt/on_decrypt_uses_branch_key_id_supplier_when_configured (:1640, :2161)."
  rationale: "Observation stands: the returned materials' bkid/version are not compared with the request (TB7); decrypt fails closed through the AAD. A supplier returning NUL-containing ids is a BUG-06 path (T13). Scope note (second pass): on decrypt the supplier's input is the message's encryption context (hierarchical_keyring.rs:746-748, :831; with DefaultCmm the merged context, default_cmm.rs:198), which is unauthenticated until a data key is recovered. The filter at :760 compares the EDK's provider info only with the supplier's own result. So the proof shows the id is bound consistently, not that the id is one the application should serve; which tenant ids may be decrypted is the application's job (TM-MPL-003 second-pass residual, rating unchanged). The same input drives T27."
  scoring:
    severity: 2
    coverage_gap: 0.6
    feasibility: 0.4
    blast_radius: 4
    product: "2 × 0.6 × 0.4 × 4 = 1.92"
  quick_win: false
  proof_status: "None yet"
  dependencies: [VR-2026-T13]
```

```yaml
recommendation:
  id: VR-2026-T20
  rank: 22
  priority_score: 1.68
  origin: threat-driven
  target:
    crate: aws-crypto-mpl
    file: mpl/src/keyring/raw_aes_keyring.rs
    function: RawAesKeyring::serialize_provider_info (:129); RawAesKeyring::decryptable_edk_iv (:191)
  property: >
    serialize_provider_info(iv) = key_name ‖ be32(128) ‖ be32(12) ‖ iv. decryptable_edk_iv returns Some(iv)
    exactly when provider id == namespace and info has that shape for a 12-byte iv. Round trip holds. Total.
  formal_spec: |
    fn serialize_provider_info(&self, iv) -> (r) requires iv@.len() == 12 ensures r@ == info(self.key_name@, iv@)
    fn decryptable_edk_iv(&self, e) -> (r) ensures r matches Some(iv) <==> e.key_provider_id@ == self.key_namespace@
              && iv@.len() == 12 && e.key_provider_info@ == info(self.key_name@, iv@)
  tool: Verus
  agent: mpl-verus-header-parsing-proofs
  estimated_effort: 1 week
  threat_references:
    - {id: TM-MPL-023, category: Denial of Service, description: "Malformed provider info rejected, not panic"}
    - {id: TM-MPL-011, category: Elevation of Privilege, description: "Decryptor uses exactly the encryptor's IV"}
    - {id: TM-MPL-001, category: Spoofing, description: "Provider-id filter on decrypt"}
  trace_to_spec: "spec/framework/raw-aes-keyring.md#key-provider-information, #ondecrypt"
  coverage_gap: 0.7
  coverage_evidence: "test_raw_aes_keyring.rs: test_encrypted_data_key_wire_format (:406) and provider-info / short-ciphertext negative tests (:619, :658, :696)."
  rationale: "Small binary codec; parser half of T07. Unchanged."
  scoring:
    severity: 2
    coverage_gap: 0.7
    feasibility: 0.4
    blast_radius: 3
    product: "2 × 0.7 × 0.4 × 3 = 1.68"
  quick_win: false
  proof_status: "None yet"
  dependencies: []
```

```yaml
recommendation:
  id: VR-2026-T22
  rank: 23
  priority_score: 1.60
  origin: threat-driven
  target:
    crate: aws-crypto-mpl + aws-mpl-primitives
    file: mpl/src/structures/{algorithm_suite.rs, branch_key_materials.rs, beacon_key_materials.rs, encrypted_data_key.rs}; mpl/src/keyring/raw_aes_keyring.rs; mpl/src/error/generated.rs; prim/src/ecdsa.rs; prim/src/error.rs
    function: >
      Debug impls: PlaintextDataKey (algorithm_suite.rs:564), SigningKey (:612), SymmetricSigningKey (:696),
      BranchKeyMaterials (branch_key_materials.rs:55) and its builder (:191), BeaconKeyMaterials (beacon_key_materials.rs:57) and
      its builder (:191), RawAesKeyring (raw_aes_keyring.rs:80) and its builder (:241), SignatureKeyPair (prim/src/ecdsa.rs:335);
      derived Debug of materials / CacheEntry; DataKeyInfo (prim/src/error.rs:378) built by `From<&EncryptedDataKey>`
      (encrypted_data_key.rs:147) and attached to errors (Error::with_encrypted_data_keys, error/generated.rs:1064; getter
      encrypted_data_keys() :1591; shown by the NoMatchingDataKey Debug impl, :1596, field at :271); KeyProviderInfo Debug (prim/src/error.rs:410)
  property: >
    Noninterference: each Debug output, and each error's attached DataKeyInfo, depends only on non-secret
    fields and never on secret bytes or EDK ciphertext. Scope note (second pass): `NoMatchingDataKey` keeps
    the message's EDK identities (provider id and provider info), reachable through `Debug` and
    `encrypted_data_keys()`; `KeyProviderInfo`'s Debug prints the info as text when it is UTF-8 and as hex
    otherwise. Provider info is not secret, but it is attacker-controlled text and can carry a KMS key ARN
    with an account id. The property covers secrets and ciphertext only: it does not claim that the provider
    info is safe to log or return to a ciphertext sender (callers should not return MPL errors to the sender,
    TM-MPL-021 and TM-MPL-003). The EDK ciphertext stays excluded from DataKeyInfo.
  formal_spec: |
    proof fn pdk_redacted(k1, k2) requires k1.len() == k2.len() ensures fmt_spec(PlaintextDataKey(k1)) == fmt_spec(PlaintextDataKey(k2))
    proof fn data_key_info_no_ciphertext(e1, e2) requires same_provider(e1, e2) ensures DataKeyInfo::from(e1) == DataKeyInfo::from(e2)
  tool: Verus
  agent: mpl-verus-unsafe-ffi-safety
  estimated_effort: 1 week
  threat_references:
    - {id: TM-MPL-021, category: Information Disclosure, description: "Secret bytes leak via Debug/error/log formatting"}
  trace_to_spec: "baseline assurance, no single clause"
  coverage_gap: 0.5
  coverage_evidence: "test_algorithm_suite.rs::test_plaintext_data_key_debug_redacts (:21) and siblings; test_raw_aes_keyring.rs::test_debug_does_not_leak_the_wrapping_key (:827); prim/tests/test_ecdsa.rs."
  rationale: "Previous residual closed in code; the proof upgrades substring tests to an all-values guarantee and now also covers the new error model."
  scoring:
    severity: 2
    coverage_gap: 0.5
    feasibility: 0.4
    blast_radius: 4
    product: "2 × 0.5 × 0.4 × 4 = 1.60"
  quick_win: false
  proof_status: "None yet"
  dependencies: []
```

```yaml
recommendation:
  id: VR-2026-T25
  rank: 24
  priority_score: 1.44
  origin: threat-driven
  target:
    crate: aws-esdk-cpp shim (esdk/shims/aws-esdk-cpp, outside mpl/ and prim/)
    file: esdk/shims/aws-esdk-cpp/src/lib.rs
    function: >
      require_handle (:715; null check :720; `unsafe { &*ptr }` :728; callers :1287, :1331, :1652, :1942, :1985);
      key-store builder nullable client handles (`unsafe { input.kms_client.as_ref() }` :1570, `ddb_client` :1571; moved from
      :1564-1565 by #188); hierarchical keyring nullable cache handle (`unsafe { input.cache.as_ref() }` :1661; was :1655);
      into_keyring_handle (:2059; `Box::into_raw(Box::new(Keyring { .. })).cast()` :2062-2065), the Rust half of the type-erased
      adopt path; the C++ half is `Keyring::adopt(void*)` (esdk/shims/aws-esdk-cpp/src/EncryptionSDK.cpp:541-547,
      `rust::Box<::ffi::Keyring>::from_raw(static_cast<::ffi::Keyring*>(raw_handle))` :546; declared at
      include/aws/esdk/EncryptionSDK.h:664, contract :656-663)
  property: >
    Borrowed handles. Every raw-handle dereference in the shim is dominated by a null check; a null required
    handle yields a Validation error and never a dereference; a null optional handle yields None (core default); no handle
    is dereferenced after the shim itself frees it. The validity of a NON-null C++-supplied pointer is a
    caller precondition (spec shim.md#handles-and-lifetimes), modeled as a trusted PointsTo permission
    at the FFI boundary — it is not proven.
    Adopted keyring (added in the second pass). Rust-provable part: into_keyring_handle returns a non-null
    pointer to a freshly allocated Box<Keyring> that owns the shared keyring it was given, and it keeps no
    other alias to it (Box::into_raw gives up the Box; Verus support for Box::into_raw is modeled as a TCB
    external spec). Outside the proof: C++ `Keyring::adopt` calls `rust::Box::from_raw` on a `void*` with no
    null check, no type check and no ownership check, so (i) a pointer that did not come from
    into_keyring_handle is type confusion, and (ii) a second adoption of the same handle is a double free.
    The header makes both caller obligations ("any other pointer is undefined behavior", each handle adopted
    at most once), and the shim spec says "the shim does not detect violations"; the annotation records this as an
    exception (lib.rs:2050-2054). No Rust-side proof can discharge (i) or (ii) while the handle is a bare
    pointer. Only a hardening change (a type tag or a generation-checked handle table, with `adopt` going
    through a Rust function that checks it) would make "adopt rejects null, unknown and already-adopted
    handles" a provable Rust property; that is an owner decision and would then be added here.
  formal_spec: |
    fn require_handle<T>(ptr: *const T, name, op) -> (r: Result<&T, String>)
      requires ptr != null ==> ffi_valid(ptr)          // TCB: caller lifetime contract (shim.md#handles-and-lifetimes)
      ensures ptr == null <==> r.is_Err()
      ensures r matches Ok(x) ==> addr_of(x) == ptr
    // each `unsafe` site: ghost proof that the deref is reached only on a non-null pointer, under the same requires
    fn into_keyring_handle(k) -> (p: *mut c_void) ensures p != null && fresh_box_owning(p, k)   // Rust half only; Box::into_raw = TCB
    // NOT PROVEN, caller obligations (no Rust-side check exists): adopt(p) requires came_from(into_keyring_handle, p) && adopted_at_most_once(p)
  tool: Verus
  agent: mpl-verus-unsafe-ffi-safety
  estimated_effort: 1 week
  threat_references:
    - {id: TM-MPL-024, category: Elevation of Privilege / Tampering, description: "C++ shim dereferences or adopts a dangling, forged or double-owned handle to an MPL object"}
  trace_to_spec: "spec/shim/shim.md#handles-and-lifetimes (annotated at lib.rs:718-719); spec/shim/shim.md, section \"Custom implementations of core-library interfaces\" (:180-204; the lib.rs annotation at :2037-2054 names it `#adopting-custom-implementations`); spec/shim/esdk-shim.md#create-hierarchical-keyring"
  coverage_gap: 0.6
  coverage_evidence: >
    esdk/shims/aws-esdk-cpp/src/tests.rs: require_handle_rejects_null_and_borrows_non_null (:715),
    encrypt_rejects_null_keyring (:733), decrypt_rejects_null_keyring (:746),
    create_hierarchical_keyring_rejects_null_key_store (:791); into_keyring_handle_boxes_the_keyring (:1624) checks that
    the handle is non-null and an owned Box<Keyring> (its own `Box::from_raw` at :1634 is test-only). Dangling, forged,
    type-confused and double-adopted handles are not testable from Rust.
  rationale: |
    New threat (e9bde48 retargeted the shim onto the native MPL). It is the only `unsafe` reaching MPL key
    material. The provable slice is small (null-dominance, no self-use-after-free, and the non-null unique Box
    from into_keyring_handle); the dangerous part, a dangling or type-confused non-null pointer from C++ and a
    double adoption, is excluded as a caller obligation. Owner: the shim.
    Second pass: the `unsafe` lines moved by #188 (+6; #189 changed build and link only, no handle or lifetime path)
    and the type-erased `Keyring::adopt` path was added to the scope. Score unchanged (gap 0.6): the added
    scope has no Rust-side check to test, and its provable slice is covered by tests.rs:1624.
    Suggested hardening (owner decision): generation-checked handles instead of raw pointers, and a type tag plus
    a null check in `adopt`.
  scoring:
    severity: 3        # TM-MPL-024 High
    coverage_gap: 0.6
    feasibility: 0.4   # Likelihood Low
    blast_radius: 2    # C++ shim consumers only
    product: "3 × 0.6 × 0.4 × 2 = 1.44"
  quick_win: false
  proof_status: "None yet"
  dependencies: []
```

```yaml
recommendation:
  id: VR-2026-T23
  rank: 25
  priority_score: 1.26
  origin: threat-driven
  target:
    crate: aws-crypto-mpl
    file: mpl/src/cmc/local.rs
    function: LocalCmc::{with_clock (:83), get_fresh (:131), prune_tail (:166; min at :167)}; Cmc impl put_cache_entry (:280), get_cache_entry (:302), delete_cache_entry (:311)
  property: >
    inner is None exactly when entry_capacity == 0, else len ≤ entry_capacity after every operation. get never
    returns an entry with expiry_time ≤ now. prune_tail scans min(tail, len) entries. A poisoned lock is Err.
  formal_spec: |
    spec fn inv(c) -> bool { (c.store is None <==> c.entry_capacity == 0) && (c.store matches Some(l) ==> l@.len() <= c.entry_capacity) }
    fn put_cache_entry(&self, i) -> (r) requires inv(*self) ensures inv(*self)
    fn get_cache_entry(&self, i) -> (r) ensures r matches Ok(o) && o.entry matches Some(e) ==> e.expiry_time() > ghost_now
  tool: Verus
  agent: mpl-verus-zero-panic
  estimated_effort: 2 weeks
  threat_references:
    - {id: TM-MPL-022, category: Denial of Service, description: "Cache exhaustion / eviction thrash — capacity + TTL invariants"}
  trace_to_spec: "spec/framework/local-cryptographic-materials-cache.md#entry-capacity, #put-cache-entry, #get-cache-entry, #pruning"
  coverage_gap: 0.6
  coverage_evidence: "test_local_cmc.rs (20 tests): test_capacity_invariant_holds_after_put_returns (:299), test_pruning_evicts_all_ttl_expired_in_tail (:428). The four new tests are usage-metadata tests (C08)."
  rationale: "Foundation for StormTrackingCmc/DefaultCmc (T21). The default cache is now DefaultCmc over this LRU."
  scoring:
    severity: 1        # TM-MPL-022 Low
    coverage_gap: 0.6
    feasibility: 0.7   # Likelihood Medium
    blast_radius: 3
    product: "1 × 0.6 × 0.7 × 3 = 1.26"
  quick_win: false
  proof_status: "None yet"
  dependencies: []
```

```yaml
recommendation:
  id: VR-2026-T24
  rank: 26
  priority_score: 1.20
  origin: threat-driven
  target:
    crate: aws-crypto-mpl
    file: mpl/src/keyring/raw_aes_keyring.rs
    function: RawAesKeyringBuilder::build (:350; prefix check :360 against RESERVED_KEY_NAMESPACE_PREFIX :52); on_encrypt provider id
  property: "build returns Err for every namespace starting with \"aws-kms\", so no built keyring or emitted EDK has such a provider id."
  formal_spec: |
    fn build(self) -> (r) ensures starts_with(ns@, "aws-kms"@) ==> r.is_Err()
                          ensures r matches Ok(k) ==> !starts_with(k.key_namespace()@, "aws-kms"@)
  tool: Verus
  agent: mpl-verus-header-parsing-proofs
  estimated_effort: 1 day
  threat_references:
    - {id: TM-MPL-001, category: Spoofing, description: "Raw-AES EDK impersonates an AWS KMS keyring"}
  trace_to_spec: "spec/framework/raw-aes-keyring.md#initialization"
  coverage_gap: 0.5
  coverage_evidence: "test_raw_aes_keyring.rs::test_build_rejects_reserved_aws_kms_key_namespace (:769) and siblings."
  rationale: "Trivial, well tested; kept so TM-MPL-001 has a proof-grade closure. The check moved from new() into build()."
  scoring:
    severity: 2
    coverage_gap: 0.5
    feasibility: 0.4
    blast_radius: 3
    product: "2 × 0.5 × 0.4 × 3 = 1.20"
  quick_win: false
  proof_status: "None yet"
  dependencies: []
```

```yaml
recommendation:
  id: VR-2026-T08
  status: Retired
  retired_in: 620771c refresh
  previous_score: 3.84
  origin: threat-driven
  former_target: "PlaintextDataKey::zeroize — the unsafe write_volatile loop (was mpl/src/structures/algorithm_suite.rs:439 at a1e23d7)"
  reason: >
    Code gone. a864ad8 (#131) replaced the hand-written unsafe loop with
    #[derive(Clone, Zeroize, ZeroizeOnDrop)] on PlaintextDataKey (algorithm_suite.rs:505); SigningKey (:571)
    and SymmetricSigningKey (:655) got the same derive. `\bunsafe\b` has no match in mpl/src or prim/src.
    The zeroize crate's own implementation is third-party (TCB).
  successor: VR-2026-T26 (TM-MPL-015 residual: transient and error-path buffers)
  threat_references_at_retirement: [TM-MPL-015]   # threat still active; now mapped to T26
  proof_status: "None (retired)"
```

## 4. Excluded (not Verus-provable, or not present in this repo)

**Fully excluded** = no provable code slice. **Partial** = the slice is a target above; only the listed remainder is excluded.

| Threat | Scope | Excluded part | Reason |
|---|---|---|---|
| TM-MPL-019 | **Fully excluded** | Missing Duvet coverage (1 annotation, no MPL config); spec floats on `master` (#91) | Process / traceability tooling; no code property |
| TM-MPL-020 | **Fully excluded** | No audit binding between MPL operations and KMS/DDB calls | Operational control (CloudTrail; user agent `AwsCryptographicMPL-Rust/<version>` at `aws_kms/user_agent.rs:16-19`) |
| TM-MPL-026 | **Fully excluded** | Unauthenticated loopback test servers use ambient AWS credentials for any local process (`mpl/test-server/src/main.rs:26-27`, `prim/test-server/src/main.rs:23-24`, `esdk/test-server/src/main.rs:26-27`, `esdk/shims/aws-esdk-cpp/test-server/src/main.rs:26-27`; AWS clients built from request data at `mpl/test-server/src/handlers.rs:137-147`, `:425-430`) | Test-only code, not published (`publish = false`, line 6 of each `Cargo.toml`), bound to `127.0.0.1`. Risk Low (Medium × Low). It is an operational control (run the servers only on development hosts without production credentials, `mpl-threat-model.md` recommendations), not a property of the library; no target needed |
| TM-MPL-001 | Partial (→ T24, T20) | Downstream case-insensitive provider-id trust | Other components |
| TM-MPL-002 | Partial (→ T03, T01) | KMS key policy / grants; KMS enforcing EC-as-AAD; Discovery trusting the record ARN | External service; configuration |
| TM-MPL-003 | Partial (→ T19) | Correctness of a caller-supplied `BranchKeyIdSupplier` | Caller code |
| TM-MPL-004 | Partial (→ T11) | KMS guarantee that MRK replicas share key material | External service |
| TM-MPL-005 | Partial (→ T01, T02) | Rollback/replay of an older authentic ACTIVE record (second-pass residual: plain `GetItem` without a consistent-read flag, `branch_key_store.rs:148`, `:155-163`; the keyring does not remember the highest version seen); AEAD integrity; user-supplied `KeyStore` output (TB7) | Storage freshness, no code property separates an authentic old record; crypto hardness; trusted caller code |
| TM-MPL-006 | Partial (→ T09) | Cryptographic security of key commitment; ESDK message-level checks | Crypto hardness; out of MPL scope |
| TM-MPL-007 | Partial (→ T17) | KMS regional availability; KMS rejecting wrong-region ARNs | External service |
| TM-MPL-008 | Partial (→ T09) | Invisible-Salamanders resistance of commit-key suites; future caching CMM (CVE-2026-6550 class) | Crypto hardness; code does not exist |
| TM-MPL-009 | Partial (→ T13) | SHA-384 collision resistance; operators reusing a logical name across stores | Crypto hardness; unenforceable config MUST |
| TM-MPL-010 | Partial (→ T14, T13) | Partition-id randomness; operator choice to share; user `Cmc` returning arbitrary entries or `grace_period() = None` (`cmc/mod.rs`) | Probabilistic; operational; trusted caller code |
| TM-MPL-011 | Partial (→ T07, T20) | CSPRNG quality; 96-bit nonce birthday bound | Probabilistic |
| TM-MPL-012 | Partial (→ T04) | 224-bit salt‖IV collision bound; rotation cadence | Probabilistic + operational |
| TM-MPL-013 | Partial (→ T10, T15) | GCM's cryptographic binding of AAD | Crypto hardness |
| TM-MPL-014 | Partial (→ T05) | HMAC-SHA-256 PRF security; aws-lc-rs KBKDF correctness | Crypto hardness / third-party |
| TM-MPL-015 | Partial (→ T26) | `Vec` reallocation copies; allocator/OS residency (heap, swap, core dumps); aws-lc internal buffers (including the DER buffer `aws-lc-rs` returns to `ecdsa_generate_keypair`); cache holding branch keys for the TTL by design; `zeroize` crate internals | Outside Verus's memory model or by design; third-party TCB |
| TM-MPL-016 | Partial (→ T18) | DynamoDB `TransactWriteItems` atomicity and condition evaluation | External service |
| TM-MPL-017 | Fully targeted (→ T12, T15) | — | — |
| TM-MPL-018 | Partial (→ T21, T06, T27) | Liveness under a real scheduler; Tokio-only runtime; wall clock. The stale mark and the no-deadline waiter are in T21 (g), (h) as properties of the pure classify step; their reproducer is a concurrency test | Deployment constraints |
| TM-MPL-021 | Partial (→ T22) | What applications log; AWS SDK error-cause contents | External code |
| TM-MPL-022 | Partial (→ T23, T06) | KMS throttling under eviction thrash; capacity sizing | Performance / operations |
| TM-MPL-023 | Partial (→ T16, T20, T06) | `ecdsa_generate_keypair(..).expect` success (BUG-05a) | Needs an unjustified "always Ok" axiom; kept in T16 as an expected-unprovable finding |
| TM-MPL-024 | Partial (→ T25) | Validity / lifetime / type of a non-null C++-supplied pointer; C++ `Keyring::adopt(void*)` (`EncryptionSDK.cpp:541-547`: no null, type or ownership check; a wrong pointer is type confusion, a second adoption is a double free); C++ caller code; `cxx` bridge internals | Caller obligation across FFI (header `EncryptionSDK.h:656-663`; shim spec says the shim does not detect violations); third-party TCB |
| TM-MPL-025 | Partial (→ T27) | Wall-clock time per request (each duplicate unknown version waits about one grace interval); DynamoDB read capacity and KMS cost; which bound to add (EDK cap in the MPL, per-decrypt budget, negative cache, de-duplication) | Performance and operations; owner decision. The threat is provisional (static reasoning) and unconfirmed until a reproducer exists |

## 5. Corrections and notes against the threat model

| # | Threat-model text | Reality on 620771c / 9955ecd | Effect |
|---|---|---|---|
| C1 | TM-MPL-023 listed `branch_key_wrap.rs:240` as the 60-byte guard | The guard is at `branch_key_wrap.rs:236` (`if ciphertext.len() < FIXED_OVERHEAD_LEN`); `:240` is inside the error message | T16 cites `:236`. **Resolved** in the verification pass: the threat model now cites `:236` |
| C2 | TM-MPL-015 mitigation lines in `branch_key_materials.rs` / `beacon_key_materials.rs` | Re-checked with `sed -n` in the verification pass: `branch_key_materials.rs:205` is `impl Drop for BranchKeyMaterials`, `beacon_key_materials.rs:221-235` are the `Drop` / `ZeroizeOnDrop` impls. No active target cites them | none |
| C3 | Completeness audit G1 and the work list cite the "MUST fail" clause at `branch-key-store.md:530`, `:552`, `:573`, and the record fields at `:677`, `:688-691` | On HEAD the "response MUST contain the fields" sentences are `:530`, `:552`, `:573` and the "If the record does not contain the defined fields, this operation MUST fail" sentences are `:531`, `:553`, `:574`. "A branch key record MUST include" is `:677`; `create-time` is `:690` and `hierarchy-version` is `:692` (Number type `:693`). The audit's `:530`/`:552`/`:573` are off by one for the MUST-fail sentence | T02 cites the corrected lines. Substance unchanged |
| C4 | `lib.rs:2037-2054` annotates `spec/shim/shim.md#adopting-custom-implementations` | `spec/shim/shim.md` has no heading of that name. The text is under "Custom implementations of core-library interfaces" (`:180-204`; "MUST adopt each at most once; the shim does not detect violations" is `:203-204`) | T25 cites the spec section by its heading and records the annotation's anchor. A Duvet anchor mismatch is a shim owner item, not a target change |
| C5 | TM-MPL-021 second pass cites `prim/src/error.rs:406-409` for the `Debug` of `DataKeyInfo` | `:406-409` is the doc comment and the `struct KeyProviderInfo` line (`:408`); the `Debug` impl is at `:410`, and `DataKeyInfo` is at `:378` | T22 cites the impl lines. Substance unchanged |

New / still-open findings recorded in targets and **not changed** (owner decisions): T06 (BUG-01), T13 (BUG-06), T17 (BUG-04), T16 (BUG-05a/b), T21 (storm-tracking spec ordering regressed; stale in-flight mark; waiter with no deadline; panic under the state lock), T26 (BUG-07a, unwiped decrypt buffers, BUG-10 (raw-AES `on_decrypt` wrong-length path, code reading), expired cache entries resident until read, unwiped ECDSA private-key `Vec` on an error path), T27 (no bound on key-store calls per decrypt; unconfirmed), T02 (G1: `create-time` and `hierarchy-version` not required on read), T25 (no check in C++ `Keyring::adopt`), C01(c) (BUG-08 dead branch).

## 6. Accounting — every threat mapped

| Threat | Severity / Likelihood | Target(s) | Exclusion |
|---|---|---|---|
| TM-MPL-001 | Medium / Low | T24, T20 | Partial |
| TM-MPL-002 | Critical / Low | T03, T01 | Partial |
| TM-MPL-003 | Medium / Low | T19 | Partial |
| TM-MPL-004 | High / Low | T11 | Partial |
| TM-MPL-005 | Critical / Medium | T01, T02 | Partial |
| TM-MPL-006 | Critical / Low | T09 | Partial |
| TM-MPL-007 | High / Low | T17 | Partial |
| TM-MPL-008 | High / Low | T09 | Partial |
| TM-MPL-009 | High / **Medium** | T13 | Partial |
| TM-MPL-010 | High / **Medium** | T14, T13 | Partial |
| TM-MPL-011 | Critical / Low | T07, T20 | Partial |
| TM-MPL-012 | Critical / Low | T04 | Partial |
| TM-MPL-013 | High / Low | T10, T15 | Partial |
| TM-MPL-014 | High / Low | T05 | Partial |
| TM-MPL-015 | **Medium** / Low | **T26** (T08 retired) | Partial |
| TM-MPL-016 | Medium / Low | T18 | Partial |
| TM-MPL-017 | High / Low | T12, T15 | None |
| TM-MPL-018 | Medium / Medium | T21, T06, T27 | Partial |
| TM-MPL-019 | Medium / Medium | — | **Fully excluded** |
| TM-MPL-020 | Low / Low | — | **Fully excluded** |
| TM-MPL-021 | Medium / Low | T22 | Partial |
| TM-MPL-022 | Low / Medium | T23, T06 | Partial |
| TM-MPL-023 | Medium / Low | T16, T20, T06 | Partial |
| TM-MPL-024 | High / Low | T25 (scope extended with `adopt`) | Partial |
| TM-MPL-025 | Medium / Medium (provisional) | **T27** (new) | Partial |
| TM-MPL-026 | Medium / Low | — | **Fully excluded** (test-only) |

Totals: **26 active threat-driven targets** (T01–T07, T09–T27) plus **1 retired** (T08). All 26 threat IDs TM-MPL-001..026 are accounted for: 23 have at least one active target (001..018, 021..025), 3 are fully excluded (019, 020, 026), 1 is fully targeted (017), 22 carry partial exclusions (every targeted threat except 017). No active target cites a retired threat (there are none) or retired code.

## 7. Proof status and bug records added at HEAD b94c871

Added after the `9955ecd` refresh. No score, rank, coverage gap, feasibility, severity or quick-win changed.

- **C03 (in `02-capability-driven.md`).** Partly proved in-crate on branch `Mahnush_Verus` as VR-013 and VR-014 (the shipped prim code; not on this branch): `verification results:: 18 verified, 0 errors` at `8d6381e`. Status string: Partly proved (in-crate, on the shipped prim code, on branch Mahnush_Verus, not on this branch, under trusted aws-lc-rs assumptions A1-A20): 18 verified, 0 errors. This is a different qualifier from the model-level proofs in this file (T02, T03, T05: "model level, not the shipped code"). C03 cites no threat, so no threat row here changed.
- **T01 and T13 (model level).** T01: Proved (model level, not the shipped code, under stated hypotheses): 52 verified, 0 errors. T13: Partly proved (model level, not the shipped code, under stated hypotheses): 42 verified, 1 errors; the one error is the intentional BUG-06 obligation. Neither is a duplicate of anything on `Mahnush_Verus` (duplicate check in `docs/mpl-verification-targets.md`, cross-branch section). T01 reuses the C01 model unchanged and adds the KMS leg, the item and record loops, `VersionKey` and the authenticity theorem. No score, rank, coverage gap or quick-win changed.
- **T04 (model level).** Proved (model level, not the shipped code, under stated hypotheses): 45 verified, 0 errors. The proof covers the structure around the salt and IV draws and the 60 + n layout. It does not prove that the salt or the IV is fresh or unique: that rests on the aws-lc-rs generator, assumed only as A_RNG. Not a duplicate of anything on `Mahnush_Verus` (duplicate check in `docs/mpl-verification-targets.md`, cross-branch section; VR-013(d) and VR-014 there prove prim functions that `wrap` calls, not `wrap`). No score, rank, coverage gap or quick-win changed.
- **C02.** Proved at model level (unchanged); partly superseded by VR-008 (in-crate, `Mahnush_Verus`): the retry bound, termination and guarded copy. It is not a duplicate. Details in `02-capability-driven.md`.
- **BUG-10 -> TM-MPL-015 -> T26.** BUG-10 (Low, code reading, added 2026-11-17) is the bug report for T26's site F1 wrong-length path (`raw_aes_keyring.rs:489-494`) and for F3 (`branch_key_wrap::unwrap`, `:275`). It is recorded in T26's `related_bugs` and `scope_note`. T26's score (3.20), rank, gap and the TM-MPL-015 rating are unchanged, and its proof status is still "None yet". The completeness audit's section 3b predates BUG-10.
- **BUG-07(a) caller impact -> T26 (F2), T07.** The plaintext data key can stay in the caller's buffer after an `aes_encrypt` `Err` at `wrap_data_key` and `branch_key_wrap::wrap`. Code reading; it cannot fire today. The prim-side facts are proved only on `Mahnush_Verus` (C03, VR-014).
- **Open bugs.** BUG-01, 04, 05(a), 05(b), 06, 07(a/b), 08 and 10. Fixed: BUG-02, 03, 09.
