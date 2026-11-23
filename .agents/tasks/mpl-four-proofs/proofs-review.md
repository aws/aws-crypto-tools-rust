# Review of the four model-level Verus proofs (C05, T24, C08, C04)

Branch MPL-Verus, HEAD ad3522b. Reviewed files: `verus-proofs/c05_algorithm_suite_table.rs`, `t24_raw_aes_namespace.rs`,
`c08_cache_usage_counters.rs`, `c04_pdk_length_invariant.rs`, plus the notes, run logs, copy-check outputs and mutation records in
`.agents/tasks/mpl-four-proofs/`. Verus and the mutants were not re-run. Recorded results were checked for consistency:
the run logs (22, 19, 20, 24 verified, 0 errors) are newer than or equal in time to the proof files, the C04 file md5 in the notes
(`5796a0cb...`) equals the current file, and the C05 md5 quoted in the C04 header (`98209a4d...`) equals the current C05 file.

**Verdict: CHANGES_REQUESTED.** One MEDIUM finding (C08). Everything else is LOW and is listed for the same edit pass; none of it blocks.

## Findings that block (MEDIUM)

### F1 (MEDIUM) C08: the model assumes one counter cell per identifier; the code does not, and no hypothesis says so

- Model: `Cache.entries: Map<Id, UM>` (c08 `Cache`, `update_spec`). Each identifier owns its counters.
- Code: the map holds `CacheEntry` handles, `CacheEntry { inner: Arc<CacheEntryInner> }` with `usage_metadata: Mutex<UsageMetadata>`
  (`mpl/src/cmc/entry.rs` :136-146). A clone shares the counters (`entry.rs` doc :132-133, test `test_shared_handles.rs` :167-181).
  `PutCacheEntryInput` is `Clone` and carries a `CacheEntry` by value (`operation.rs` :11-31). `put_cache_entry` stores it under the
  given identifier with `cache.put(identifier, entry)` (`local.rs` :280-300), and `get_cache_entry` returns a clone (`local.rs` :148).
  So a caller can put the same handle under two identifiers using only public API.
- Consequence: with two identifiers A and B sharing one cell, `update_usage_metadata(B)` changes the counters seen through A.
  The following statements in the file are then false for that reachable state:
  - `theorem_update_step`: "no other identifier changes" (the `forall k != call.id` clause).
  - `theorem_cache_refines_entry_run` and `theorem_no_wrap_any_calls`: A's counters are `start + n` and `start + sum` where `n` and `sum`
    count only the calls addressed to A. The real cell also counts B's calls, and A survives while B is evicted by an overflow caused through B.
  What still holds under aliasing is the cell-level safety property: no call wraps a counter, a failing call leaves the cell unchanged,
  and the addressed slot is evicted (R1, R2, `record_use`, R7 are about one cell and are unaffected).
- Why it is not covered now: A_ALL_CALLS says "every change to the counters of the cell goes through `update_usage_metadata`, so `calls`
  lists all of them". With aliasing, `bytes_for(calls, id)` does not list the calls addressed to the other identifier, so the premise does
  not exclude the case, and no other A_* or H_* does. H_ARC_SHARED mentions sharing only for `get_fresh` and for observation O1.
  Task requirement: every hypothesis named. This one is missing, and the headline theorem R5 depends on it.
- Fix (documentation and statement only, no model rewrite needed):
  1. Add to header section 4 of `c08_cache_usage_counters.rs`: `A_NO_ALIAS (ASSUMED, for R3 "no other identifier changes", R4 and R5)`:
     no `CacheEntry` handle, original or clone, is stored under two identifiers, so distinct identifiers have distinct counter cells.
     State that `put_cache_entry` takes a cloneable handle, so this is a premise about callers and the code does not enforce it.
  2. Reword A_ALL_CALLS so it does not claim `calls` lists all changes when handles are shared, or fold it into A_NO_ALIAS.
  3. Add to "WHAT IS NOT PROVED": under aliasing the per-identifier totals of R4 and R5 and the "no other identifier changes" clause do not hold;
     the per-call no-wrap and both-or-neither properties (R1, R2) still do.
  4. Mark the three affected doc comments (`theorem_update_step`, `theorem_cache_refines_entry_run`, `theorem_no_wrap_any_calls`) and the R3, R4, R5 header lines "relative to A_NO_ALIAS".
  5. Add the same hypothesis to `c08-notes.md` section 4 and section 5, and to the suggested wording for the docs step.
  Optional stronger fix: model `Map<Id, CellId>` and `Map<CellId, UM>`. Not required if the hypothesis is stated.
  This does not change the verdict on the no-wrap claim: the code cannot wrap, aliasing or not.

## Non-blocking observations (LOW, fix in the same edit)

1. **C05 comment says five, table has four.** In `theorem_no_symmetric_signing` the doc comment reads "`has_asymmetric_signing` is true exactly for
   the five ECDSA suites". The `ensures` lists four (02 14, 03 46, 03 78, 05 78), the spec has four ECDSA ESDK rows, and the notes say four. Change "five" to "four".
2. **C05 header section 5, sentence about `lemma_spec_table_consistent`.** "Section 4 of the code also holds a spec-only check" is garbled
   (the lemma is in file SECTION 4, "R1"). Reword to "The file also holds a spec-only check (`lemma_spec_table_consistent`)".
3. **C05 `curve_bits` (256, 384) is a typed constant not listed.** It is used in `lemma_field_size_formula`. Add it to A_PRIM_COPY or A_SPEC_COPY
   (it comes from the names P-256 and P-384, not from a source file).
4. **T24 H_CONST says the prefix constant is "used once, at :360".** It is also used in the error message at `raw_aes_keyring.rs` :364
   (`{RESERVED_KEY_NAMESPACE_PREFIX}`). The check is still one use. Say "the only comparison is at :360; :364 formats the message".
   Also the header cites `wrap_data_key` as :146-184 / :179-181 in section 1 and :165-182 / :180 in H_EDK_ID. The code has the fn at :146 and
   `key_provider_id(...)` at :180. Use one form.
5. **C08 F0 and the STATUS paragraph state the code claim flat.** "The code cannot wrap and cannot panic at any legal input" is code reading plus
   the model, not a proved fact about the code (H_STD_CHECKED_ADD, H_NO_PANIC_IN_GUARD, H_ONLY_SITES). Say "code reading finds no input at which the code wraps
   or panics; the model proof is consistent with that". Same wording in `c08-notes.md` F0.

## 1. Faithfulness (model against shipped code)

- **C05.** All 11 rows of `code_row` equal the literals of `specification()` (`algorithm_suite.rs` :144-305): ids, key length, IV, tag, KDF,
  commit KDF, signature fields, format version, suite data length, all `usize`/`u8` as in the code. `ALL_SUITES` order (:94-106), `from_id_bytes`
  (:139-141, first match), `verification_key_length` (:440-446, 33 and 49), `key_commitment` (:410) agree. `get_alg_suite`
  (`esdk/src/message/body/mod.rs` :18-28), `AesGcm::key_length` (`prim/src/lib.rs` :148-154) and `field_size` (`prim/src/ecdsa.rs` :352-357) agree.
  The spec rows agree with `spec/framework/algorithm-suites.md` :183-312 (read directly: ids, bits, IV, tag, KDF, hash, commitment, commit KDF, signatures, versions, data length,
  and the 7 S3EC and DBE ids). The suites.rs map has an extra wildcard arm for future variants that the model omits; harmless and consistent with "total on the two variants".
  The 22 tests claim is right (22 `#[test]` in `test_algorithm_suite_id.rs`). The spec salt column is declared not modeled.
- **T24.** The model matches `build` (`raw_aes_keyring.rs` :351-390): order namespace, name, wrapping key, wrapping algorithm, then the prefix test (:360, `str::starts_with`,
  byte-wise, case-sensitive), then the key length test (:369-379). The constant is "aws-kms" (:52). Only :382 builds `RawAesKeyringInner` (grep). The EDK provider ID is the namespace (:180),
  the decrypt filter is exact equality (:192). The spec sentences S1 (`keyring-interface.md` :83-86) and S2 (`raw-aes-keyring.md` :22, change log) are quoted correctly. The code check is a prefix test
  on the namespace, so it is not narrower than S1 or S2, and the "no gap, no EXPECTED_FAIL" conclusion is right. Case variants and lookalikes are accepted and are stated, with the downstream
  exclusion, as an observation.
- **C08.** `record_use` (`entry.rs` :206-223: two `checked_add` on `u64`, both sums before any store, poison ignored) and `update_usage_metadata` (`local.rs` :326-342:
  poisoned store gives `Err(Internal)`, `peek`, `record_use`, `pop` on false, `Ok`) are modeled with the right widths and order. Only `entry.rs` :213-214 does arithmetic on the counters (grep).
  The one fidelity gap is F1 above. No EXPECTED_FAIL is correct: the code cannot wrap or panic.
- **C04.** The path list matches grep over `mpl/src`, `esdk/src`, `prim/src`: field writes only in `add_data_key` (enc :48-64, dec :45-59) and the two `build` literals (:427, :349); the
  four checks (`encryption_materials.rs` :60 and :365, `decryption_materials.rs` :56 and :303); `PlaintextDataKey::new` only at raw :497 and :544 and hierarchical :767 and :984; no `&mut self`
  on the materials; no `unsafe` in `mpl/src`. `raw_dec` (length test :489 then `add_data_key`), `hier_dec` (no pre-test, `?` at :767), `hier_enc` (`add_data_key` only when generated), the two
  generators (`vec![0u8; encryption_key_length()]`, filled through `&mut [u8]`) and `check_data_key_length` (`!=` on two `usize`) match. The table block (`pub enum Suite` through `code_row`, 112 lines)
  is byte-identical to the C05 block (checked with `diff`). The header says it is a copy of a copy. The spec cites (keyring-interface :144-148, algorithm-suites :95 and :423, structures :225-229 and :321-325)
  are accurate, and A_FIT is stated as an interpretation. No path that builds or accepts a PDK without the check was found.

## 2. Overclaiming and evidence levels

- All four headers open with "model-level proof, not a proof of the shipped code", list what is not proved, and use PROVED / ASSUMED / CODE READING with the A_* and H_* names. None says a threat is mitigated;
  C05 and C04 state they map to no TM-MPL threat, T24 says TM-MPL-001 is not mitigated, C08 says it has no threat reference.
- The trivial-proof requirement is met: C05 says plainly it is a consistency check of two hand-typed tables, names the 22 existing tests, and says it does not show the code is called correctly. C04 says P1 and P2
  restate a one-line comparison and that the value is the path list and the closure. T24 marks `theorem_matches_s1` as true by construction. C08 says the no-wrap part rests on `checked_add`.
- No `assume`, `admit`, `external_body` or `assume_specification` is written in any of the four files (C08 relies on vstd's `u64::checked_add` specification and says so; `checked_add_by_hand` cross-checks it).
- Issues: F1 (missing hypothesis), LOW items 1 to 5.
- No real gap was missed in T24, C08 (per call), C04 or C05, and no finding or EXPECTED_FAIL was invented.

## 3. Style and header conventions (against t04 and t06)

Same layout as t04 and t06: title with the VR id, `Run:` line, "NOT part of any cargo build", section 0 "WHAT THIS FILE IS (read this first)" with the same first sentence, STATUS line with the exact result line,
proved list, not-proved list, source modeled with line numbers, correspondence table, spec-derived against code-derived, hypotheses with evidence levels, `use vstd::prelude::*; verus! { ... } fn main() {}`,
`theorem_`/`lemma_` names. The new files add a "findings" section (all report no gap), which is consistent with t04 section 8. No convention break.

## 4. Mutation sets

- C05: 23 mutants, 21 rejected, 2 survived (m21 the same wrong id typed into both copies; m22 the id comparison removed from `row_refines`). Both are explained and are the limits of a hand-copy comparison and of a weakened relation. The copy-check script (49 of 49) catches m21.
- T24: 18 mutants, 15 rejected, 3 survived (s01 tail typo in a KMS id, s02 `lower` bound, s03 unused key name). Explained: no claim reads those items. m03 (different prefix string) is rejected only by `lemma_reserved_bytes`, which is stated.
- C08: 30 mutants, 28 rejected, 2 survived (s01 `Id` width, s02 redundant assert hint). Explained. The weakness that an edit of exec `record_use` is seen only through its own `ensures` is stated. No mutant models aliasing (F1).
- C04: 34 mutants, 31 rejected, 3 survived (s01 generated path bypasses the check, s06 no-op refactor, s07 consistent copy error in every copy). Explained. Four predictions were wrong and each is explained; the first-run m27 survivor led to `lemma_step_dispatch`, which is disclosed as a definition check.
- The counts in the notes equal the counts in the `*-mutation-run.txt` files. All records say the mutants test the model, not the shipped code.

## 5. Repository state

- `git status --short`: only untracked files (`verus-proofs/{c05,t24,c08,c04}*.rs`, `.agents/tasks/...`). No tracked file is modified or staged.
- `git diff HEAD -- mpl prim esdk docs` is empty, so nothing under `mpl/`, `prim/` or `esdk/` changed, and no doc (including `docs/`, `verus-proofs/README.md`, `dashboard/`) was edited yet.

## Next step

Apply F1 and LOW items 1 to 5 (comment and hypothesis edits only), re-run `~/verus/verus verus-proofs/c08_cache_usage_counters.rs` (the result must stay `20 verified, 0 errors`;
header-only edits do not change the proof) and the other three files after touching them, then update the matching notes. Do not edit docs until the review passes.
