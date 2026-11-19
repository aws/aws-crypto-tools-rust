# T06 mutation check record

Target: `verus-proofs/t06_systemtime_add_overflow.rs` (model level, not the shipped code).
Script: `.agents/tasks/t06-verus-proof/mutate.py`. Raw output of the final run: `mutation-run.txt` (same directory).
Method: each variant copies the proof to `/tmp`, applies one text edit (the script checks the old text occurs exactly once), runs `~/verus/verus` and compares with the baseline.
Baseline: `verification results:: 28 verified, 4 errors`. The four baseline errors are the intentional BUG-01 obligations (`lemma_bug01_site_702_..._EXPECTED_FAIL`, `_945_`, `_333_`, `_680_`).
"Rejected" means: Verus reports at least one NEW failing lemma beyond the four baseline errors. These checks cover edits to the model only, not edits to the shipped code.

Result: 23 variants. 20 rejected as predicted. 1 (M13) behaves as predicted (the four-error baseline drops to three). 2 survive (M19b, M20), both predicted. One prediction was wrong (M19, see below) and the script was corrected to state the real prediction before the final run.

| Id | Edit | Predicted | Result | New failing lemmas (beyond the baseline) |
|---|---|---|---|---|
| M1 | Safe bound off by two seconds (`d.secs <= hi - t.secs + 1`) | reject | 27 verified, 5 errors | `theorem_safe_bound` |
| M2 | std algorithm without the carry overflow check (drop `s0 + 1 > hi`) | reject | 27 verified, 5 errors | `lemma_add_ok_iff` |
| M3 | Wrong site: the `:333` model adds `grace_interval` instead of `in_flight_ttl` | reject | 26 verified, 6 errors | `lemma_bug01_site_333_counterexample`, `theorem_fixed_classify_agrees` |
| M4 | Saturating instead of panicking: `st_add` returns the last instant on overflow | reject | 22 verified, 10 errors | `lemma_bound_is_tight`, `lemma_bug01_keyring_counterexample`, `lemma_bug01_keyring_counterexample_i64_max`, `lemma_bug01_site_333_counterexample`, `lemma_bug01_site_680_counterexample`, `lemma_fix_validate_depends_on_range`, `lemma_st_add_panic_iff`, `lemma_threshold_depends_on_range`, `theorem_fixed_add_agrees`, `theorem_fixed_classify_agrees`. The four EXPECTED_FAIL lemmas now PASS, as they should: with saturation there is no panic |
| M5 | Dropped precondition: `theorem_safe_bound` without the safe-bound premise | reject | 27 verified, 5 errors | `theorem_safe_bound` |
| M6 | Dropped precondition: `lemma_add_ok_iff` without `time_wf` | reject | 27 verified, 5 errors | `lemma_add_ok_iff` |
| M7 | Poison not persistent: a Get on a poisoned lock returns Ok | reject | 27 verified, 5 errors | `lemma_poisoned_call_is_internal` |
| M8 | A panic under the lock does not poison | reject | 25 verified, 7 errors | `lemma_panic_under_lock_poisons`, `theorem_bug01_poisons_storm_cache`, `theorem_bug01b_poisons_storm_cache` |
| M9 | `delete_cache_entry` and `update_usage_metadata` take the state lock | reject | 27 verified, 5 errors | `lemma_other_ops_unaffected` |
| M10 | `fixed_add` returns a value instead of the error on overflow | reject | 25 verified, 7 errors | `theorem_fixed_add_agrees`, `theorem_fixed_classify_agrees`, `theorem_fixed_handles_counterexamples` |
| M11 | Fix B constant too large (`max_d = 9e18` s) | reject | 27 verified, 5 errors | `lemma_fix_validate_depends_on_range` |
| M12 | Shipped classify without the `:322` `in_flight_ttl` check | reject | 27 verified, 5 errors | `theorem_fixed_classify_agrees` |
| M13 | The `:702` obligation gets two added premises: `ttl.secs <= 1000` and `now.secs <= 4e9` (the repair) | 3 errors | 29 verified, 3 errors | none. `lemma_bug01_site_702_..._EXPECTED_FAIL` now verifies. It shows the obligation is repairable by a bound on ttl plus a bound on the clock, and that the failure is not an artifact of the statement |
| M14 | Wrong A_TIME_RANGE: `hi = 1e12` s | reject | 26 verified, 6 errors | `lemma_keyring_1e15_is_fine`, `lemma_threshold_depends_on_range` |
| M15 | Wrong A_TIME_RANGE: `hi = 2^64` | reject | 26 verified, 6 errors | `lemma_bug01_keyring_counterexample`, `lemma_bug01_keyring_counterexample_i64_max` |
| M16 | `Put` on a poisoned lock returns Ok | reject | 27 verified, 5 errors | `lemma_poisoned_call_is_internal` |
| M17 | `within_grace_interval` compares the wrong way (`inflight + gi < now`) | reject | 26 verified, 6 errors | `lemma_bug01_site_333_counterexample`, `theorem_fixed_classify_agrees` |
| M18 | Wrong operand at `:680`: `within_grace_interval` adds to `now` instead of `inflight` | reject | 27 verified, 5 errors | `theorem_fixed_classify_agrees` |
| M19 | `:322` comparison `>` changed to `>=` in the shipped classify only | reject (the script first said "survive"; see below) | 27 verified, 5 errors | `theorem_fixed_classify_agrees` |
| M19b | `:322` comparison `>` changed to `>=` in BOTH the shipped and the fixed classify | survive | 28 verified, 4 errors | none: SURVIVES |
| M20 | Builder accepts a zero `in_flight_ttl` (drop the `:616` check from `s_accepts`) | survive | 28 verified, 4 errors | none: SURVIVES |
| M21 | `k_accepts` also rejects ttl above `1e15` s (a bound the shipped builder does not have) | reject | 25 verified, 7 errors | `lemma_bug01_keyring_counterexample`, `lemma_bug01_keyring_counterexample_i64_max`, `lemma_bug01_keyring_with_storm_cache_accepted`. The `:702` and `:945` obligations still fail: a bound on ttl alone, with the clock only assumed representable, does not make the addition safe |
| M22 | Fix A: `fixed_classify` skips the second addition (`:333`) and returns TakeLeader | reject | 26 verified, 6 errors | `theorem_fixed_classify_agrees`, `theorem_fixed_handles_counterexamples` |

## Survivors and why

- **M19b (`>` to `>=` at the `:322` check, in both models).** No claim of T06 depends on the exact boundary `elapsed == in_flight_ttl`. T06 is about the additions after that check. The edit changes behavior only for that one boundary value. Not a gap in the claims T06 makes. It would matter to a proof of the `:322` check itself (T21).
- **M20 (zero `in_flight_ttl` accepted).** A zero `in_flight_ttl` cannot make an addition overflow, so no obligation uses `!dur_zero(c.in_flight_ttl)`. The check is kept in `s_accepts` so the model follows the builder (`storm_tracking.rs:616-618`). Same for the `fan_out`, `sleep` and `grace_interval <= in_flight_ttl` checks other than the ones the counterexamples need.

## Prediction that was wrong

- **M19 was predicted to survive and was rejected.** The edit changes only the shipped classify. The separately written fix model keeps `>`, so `theorem_fixed_classify_agrees` (the fix agrees with the shipped model wherever that does not panic) fails. M19b, which edits both, survives. The script text for M19 was changed from "survive" to "reject" and a paired M19b was added before the final run. Nothing in the proof file changed.

## What the checks do and do not show

- The shipped-model lemmas alone would not catch M12, M18 and M19. They are caught because the fix model is written separately and a lemma compares the two. A single edit applied to both would pass (as M19b does).
- The four EXPECTED_FAIL lemmas fail for the right reason: M4 (no panic) makes them verify, M13 (premises added) makes the `:702` one verify, and M21 (a bound on ttl only) leaves them failing.
- None of these edits tests the match between model and shipped code (H_MODEL_MATCH is code reading).
