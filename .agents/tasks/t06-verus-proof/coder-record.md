# T06 coder record

Task: write the model-level Verus proof T06 (VR-2026-T06, BUG-01, `SystemTime + Duration` additions) and record its status in the docs.
Repo: esdk-native-mpl, branch MPL-Verus, HEAD 19deef7. Nothing was added, committed or pushed in this step (a later step commits by explicit path).

## 1. Files changed or created

Created:
- `verus-proofs/t06_systemtime_add_overflow.rs` (the proof)
- `.agents/tasks/t06-verus-proof/coder-record.md` (this file)
- `.agents/tasks/t06-verus-proof/mutation-record.md`, `mutate.py`, `mutation-run.txt` (mutation check)
- `.agents/tasks/t06-verus-proof/t06-run.txt` (raw `verus` output of the proof)

Modified (docs only; `git diff --stat`):
```
 .../BUG-01-ttl-duration-overflow-panic.md          |  9 ++++
 .../BUG-10-raw-aes-on-decrypt-unwiped-data-key.md  |  2 +-
 docs/mpl-bug-reports/README.md                     |  1 +
 docs/mpl-completeness-audit.md                     |  5 ++-
 docs/mpl-spec-security-analysis.md                 |  2 +-
 docs/mpl-threat-model.md                           | 13 +++---
 docs/mpl-verification-targets.md                   | 32 ++++++++++----
 docs/mpl-verification-targets/01-threat-driven.md  | 19 ++++++--
 .../02-capability-driven.md                        |  2 +-
 verus-proofs/README.md                             | 51 ++++++++++++++++++++--
 10 files changed, 110 insertions(+), 26 deletions(-)
```
What changed:
- `docs/mpl-verification-targets.md`: "Proofs written" (nine targets, T06 at HEAD 19deef7, new table row, canonical status string, "Scores are unchanged" sentence for T06, C03 "nine above"), cross-branch table row, new subsection "T06 against Mahnush_Verus", six "Findings from the proofs" bullets, ranked row 11 proof status, section 5 "nine targets" and section 6 "nine proofs", the T06 line in the bug list, and an open-findings bullet for T06. Same set of places as T04 in 19deef7. Score, rank, gap and quick-win values are unchanged.
- `docs/mpl-verification-targets/01-threat-driven.md`: header, table row, canonical string, scores sentence, findings bullets, ranked row 7 proof status, YAML `proof_status`, `proof_file` and `proof_note` of VR-2026-T06, summary bullet. YAML `rank`, `priority_score`, `scoring`, `coverage_gap` and `quick_win` are untouched.
- `docs/mpl-verification-targets/02-capability-driven.md`: header sentence only.
- `docs/mpl-threat-model.md`: proof-status sentence at TM-MPL-018 (finding 3), a pointer at TM-MPL-023 (3), "Proof status" section (nine proofs, tenth target C03), new row TM-MPL-018, 022, 023 / T06. Line references into the targets docs (`:212`, `:217`, `:143`, `:691`, `:1583`) were shifted to the new line numbers.
- `docs/mpl-completeness-audit.md`: new row "T06 proof status (added after the audit)" and shifted line numbers in the G1 and G4-1 rows (as 19deef7 did). Lines 30, 39 and 186 also cite old line numbers of the targets docs; 19deef7 did not update them (they refer to the 4807e6a state), so they were left as they were.
- `docs/mpl-spec-security-analysis.md`: one sentence added to the `ttl` row.
- `docs/mpl-bug-reports/BUG-01-ttl-duration-overflow-panic.md`: new section "Formal check (T06)" before "Fix options" (the BUG-08 pattern). Severity, status, confidence and evidence unchanged.
- `docs/mpl-bug-reports/README.md`: one "Formal check (T06)" bullet.
- `docs/mpl-bug-reports/BUG-10-raw-aes-on-decrypt-unwiped-data-key.md`: line reference `01-threat-driven.md:770-773` shifted to `:780-783`.
- `verus-proofs/README.md`: run line, results row, section "T06", TCB rows, mapping row, grep bullet. `README-t03-t05.md` is not changed (it has no T06 text).

## 2. The proof: what it proves and does not prove

Model: `Dur` (u64 secs, u32 nanos), `Time` (int secs and nanos), `Range {lo, hi}` (A_TIME_RANGE). `st_checked_add` copies std's Unix `Timespec::checked_add_duration` step by step. The `+` is `Out::Panic` when that is None (H_STD_ADD). The four sites are spec functions with the same operands as the shipped lines: `site_702`, `site_945`, `site_333`, `site_680` (inside `within_grace_interval`). The miss-and-inflight arm of `classify_and_mark` is `classify_miss_inflight`. Builder checks are `k_accepts` (`hierarchical_keyring.rs:546-552`) and `s_accepts` (`storm_tracking.rs:606-626`).

Proved (relative to the model and hypotheses):
- R1 `lemma_add_ok_iff`: the std two-step algorithm equals `tn(t) + dn(d) <= hi*1e9 + 999999999`.
- R2 (1) `theorem_safe_bound`: if `d.secs + 1 <= hi - t.secs` there is no overflow. Also `lemma_bound_is_tight`, `theorem_sites_safe` at each site, `lemma_threshold_depends_on_range`.
- R3 (2) four counterexamples and four EXPECTED_FAIL obligations (section 4).
- R4 lock consequence: `theorem_poison_is_persistent`, `theorem_bug01_poisons_storm_cache`, `theorem_bug01b_poisons_storm_cache`, `lemma_other_ops_unaffected`. After a panic at `:333` or `:680` the state mutex is poisoned. Every later `get_cache_entry` and `put_cache_entry` that gets past the local-cache step returns Internal, for any call sequence. It is modeled with one boolean, the four Cmc entry points and an abstract body (`Fine`, `Fails`, `Panics`). The body for the miss-inflight path is computed from the modeled additions. It is relative to A_MUTEX (std documentation) and needs unwinding (H_UNWIND).
- R5 (3) Fix A (BUG-01 option 1, checked add as an error): agrees with the shipped model where it does not panic, errors exactly where it panics, cannot poison the lock (`lemma_fixed_never_poisons`, only for the four additions).
- R6 (3) Fix B (BUG-01 option 2, bound in the builders, illustrative 100 years, clock cap year 3000): `theorem_fix_validate_no_overflow`. Sound only relative to A_TIME_RANGE and A_NOW_CAP (`lemma_fix_validate_depends_on_range`).

Not proved: the platform range of `SystemTime` (assumed), the clock value, std behavior on non-Unix targets, panic = unwind, the match between model and code, anything about the shipped code. BUG-01 option 3 (saturate) is not modeled. The grace period (only `checked_sub`, cannot panic) and `sleep` (a tokio sleep, not a `SystemTime` addition) are out of the model, by code reading.

Sites in scope: all four. Each is reachable with a large Duration (H_REACH). `:333` needs an inflight entry, an unelapsed non-zero grace interval and `elapsed <= in_flight_ttl`; the counterexample uses `grace_interval = 1 s`. `:680` needs an inflight entry (all three callers); the counterexample uses `grace_interval = in_flight_ttl = Duration::MAX`. No site was dropped. The only `SystemTime + Duration` additions in `mpl/src`, `prim/src` and `esdk/src` are these four (grep).

## 3. Hypotheses (names as in the file header)

Assumed (A_*): A_TIME_RANGE (representable seconds in `[lo, hi]`; instance `[i64::MIN, i64::MAX]`), A_NOW (the clock reading is representable), A_NOW_CAP (fix B only: the clock reads at most year 3000), A_MUTEX (a panic with the guard alive poisons; `lock()` on a poisoned mutex is Err; an `Err` return does not poison).
Code reading (H_*): H_STD_ADD (std `+` on `SystemTime` is `checked_add().expect("overflow when adding duration to instant")`, read in `library/std/src/time.rs` at rustc 59807616e = 1.95.0, the compiler of the BUG-01 log), H_STD_UNIX (`Timespec::checked_add_duration`, same commit, Unix only), H_STATE_LOCKED_SITES, H_NO_LOCK_KEYRING, H_NO_CLEAR (grep: no `clear_poison` or `into_inner` in `mpl/src`), H_LOCAL_SEPARATE, H_UNWIND (no `panic` key in any Cargo.toml or in `.cargo/config.toml`; no `catch_unwind` in `mpl/src`, `esdk/src`, `esdk/shims`; the C++ host build flags were not examined), H_CLOCK (`StormTrackingCmcBuilder::clock` is `#[cfg(feature = "test-utils")]`), H_REACH, H_MODEL_MATCH.
No `assume`, `admit`, `external_body`, `external`, `assume_specification`, `#[verifier..]` or uninterpreted spec function is in the file (grep, no hits).

## 4. Counterexample (BUG-01), with the legal inputs

Values are in the file (`now0`, `cex_keyring`, `cex_storm_333`, `cex_storm_680`). Clock reading `now0 = 1_700_000_000 s`.
- `:702`, `:945`: `HierarchicalKeyring::builder().ttl(Duration::MAX)`. `k_accepts` holds (non-zero is the only check). `now + Duration::MAX` overflows for every clock reading at or after the Unix epoch (`lemma_bug01_keyring_counterexample`). `ttl = i64::MAX` seconds also panics, and `1e15` seconds does not (`lemma_bug01_keyring_counterexample_i64_max`, `lemma_keyring_1e15_is_fine`), as in the BUG-01 log. The same ttl is accepted with a storm cache that has the default 10 s grace period (`lemma_bug01_keyring_with_storm_cache_accepted`).
- `:333`: `StormTrackingCmc::builder().in_flight_ttl(Duration::MAX).grace_interval(1 s)` (other settings: grace period 10 s, sleep 20 ms, fan-out 1). A second get at the same instant as the inflight mark passes the `:322` check and the grace interval, so `now + Duration::MAX` panics (`lemma_bug01_site_333_counterexample`).
- `:680`: `grace_interval = in_flight_ttl = Duration::MAX`. The second get finds the key inflight and `inflight + Duration::MAX` panics (`lemma_bug01_site_680_counterexample`).

The four EXPECTED_FAIL lemmas state "no panic for every accepted configuration" per site and are left failing: `lemma_bug01_site_702_no_overflow_for_any_accepted_ttl_EXPECTED_FAIL` (`:614`), `lemma_bug01_site_945_..._EXPECTED_FAIL` (`:629`), `lemma_bug01_site_333_..._EXPECTED_FAIL` (`:649`), `lemma_bug01_site_680_..._EXPECTED_FAIL` (`:668`).

## 5. Commands run for the done check, with real output

### 5.1 T06
```
$ ~/verus/verus verus-proofs/t06_systemtime_add_overflow.rs        (exit 1)
error: postcondition not satisfied
   --> verus-proofs/t06_systemtime_add_overflow.rs:614:9
error: postcondition not satisfied
   --> verus-proofs/t06_systemtime_add_overflow.rs:629:9
error: postcondition not satisfied
   --> verus-proofs/t06_systemtime_add_overflow.rs:649:9
error: postcondition not satisfied
   --> verus-proofs/t06_systemtime_add_overflow.rs:668:9
verification results:: 28 verified, 4 errors
error: aborting due to 4 previous errors
```
Only the four intentional BUG-01 obligations fail. Each error line is the `ensures` of one `*_EXPECTED_FAIL` lemma. Full output: `.agents/tasks/t06-verus-proof/t06-run.txt`.

### 5.2 The eight existing proofs (regression)
```
== ~/verus/verus verus-proofs/t04_branch_key_wrap.rs
verification results:: 45 verified, 0 errors
== ~/verus/verus verus-proofs/t01_keystore_auth_ec.rs
verification results:: 52 verified, 0 errors
== ~/verus/verus verus-proofs/t13_cache_identifier.rs
verification results:: 42 verified, 1 errors
== ~/verus/verus verus-proofs/t02_record_reconstruction.rs
verification results:: 21 verified, 1 errors
== ~/verus/verus verus-proofs/c01_ec_roundtrip.rs
verification results:: 40 verified, 0 errors
== ~/verus/verus verus-proofs/c02_sign_fixed_len.rs
verification results:: 21 verified, 0 errors
== ~/verus/verus verus-proofs/t03_resolve_pinned_arn.rs
verification results:: 39 verified, 0 errors
== ~/verus/verus verus-proofs/t05_kbkdf_fixed_info.rs
verification results:: 33 verified, 0 errors
```
Expected: t04 45/0, t01 52/0, t13 42/1 (BUG-06), t02 21/1 (G1), c01 40/0, c02 21/0, t03 39/0, t05 33/0. All match. Exit codes checked: t06 1, t04 0.

### 5.3 Mutation check
See `mutation-record.md`. 23 variants: 20 rejected, M13 as predicted (3 errors), 2 survive (M19b, M20; explained there). Re-run with `python3 .agents/tasks/t06-verus-proof/mutate.py`.

### 5.4 check_scores
```
$ python3 .agents/tasks/docs-sync-9955ecd/check_scores.py | tail -2
  C08: 2 x 0.6 x 0.4 x 2 = 0.96 (doc 0.96)
PROBLEMS: none
```

### 5.5 mpl/, prim/, esdk/ untouched
```
$ git diff --stat -- mpl prim esdk            (prints nothing)
$ git diff -- mpl prim esdk | wc -l
0
```

### 5.6 git status
```
$ git status --short
 M docs/mpl-bug-reports/BUG-01-ttl-duration-overflow-panic.md
 M docs/mpl-bug-reports/BUG-10-raw-aes-on-decrypt-unwiped-data-key.md
 M docs/mpl-bug-reports/README.md
 M docs/mpl-completeness-audit.md
 M docs/mpl-spec-security-analysis.md
 M docs/mpl-threat-model.md
 M docs/mpl-verification-targets.md
 M docs/mpl-verification-targets/01-threat-driven.md
 M docs/mpl-verification-targets/02-capability-driven.md
 M verus-proofs/README.md
?? .agents/tasks/chorus-lookup/chorus-export.md
?? .agents/tasks/chorus-lookup/find-export.txt
?? .agents/tasks/chorus-lookup/read-summary-doc.txt
?? .agents/tasks/t06-verus-proof/
?? verus-proofs/t06_systemtime_add_overflow.rs
```
The three `.agents/tasks/chorus-lookup/` files were untracked before this task and were not touched. Nothing is staged.

## 6. Duplicate check against origin/Mahnush_Verus (read-only: git grep, ls-tree, diff, show)

Result: **T06 does not duplicate anything there.** No Verus in `mpl/`, no `verus-proofs/` directory, no hit for TM-MPL-018, 022, 023, VR-2026-T06, T06 or BUG-01, and `mpl/src` is identical to HEAD (the same four additions). Docs there mention the lock-poisoning `.expect` and the Mutex only as remarks and plans. The result is recorded in `docs/mpl-verification-targets.md`, section "T06 against Mahnush_Verus". Nothing was merged or checked out.
```
$ git rev-parse --short origin/Mahnush_Verus
8d6381e
$ git grep -l 'verus!' origin/Mahnush_Verus -- mpl   (expect: nothing)
exit 1
$ git ls-tree -r --name-only origin/Mahnush_Verus | grep -c '^verus-proofs/'
0
$ git grep -l 'verus!' origin/Mahnush_Verus | top-level directory counts
   8 .kiro
   5 docs
  11 esdk
   6 prim
  12 verification
$ git grep -n -E 'TM-MPL-018|TM-MPL-022|TM-MPL-023|VR-2026-T06|T06|BUG-01' origin/Mahnush_Verus   (expect: nothing)
exit 1
$ git diff HEAD origin/Mahnush_Verus --stat -- mpl/src/cmc/storm_tracking.rs mpl/src/aws_kms/hierarchical_keyring.rs   (expect: empty)
$ git diff HEAD origin/Mahnush_Verus --stat -- mpl/src | tail -2
$ git grep -n 'checked_add' origin/Mahnush_Verus -- mpl/src
origin/Mahnush_Verus:mpl/src/cmc/entry.rs:213:            usage.messages_used.checked_add(1),
origin/Mahnush_Verus:mpl/src/cmc/entry.rs:214:            usage.bytes_used.checked_add(bytes),
$ git grep -n -i -E 'SystemTime|storm_tracking|in_flight|grace_interval|Duration' origin/Mahnush_Verus -- docs verification prim .kiro
origin/Mahnush_Verus:docs/threat-model.md:720:| Data races | Prevented by `Send`/`Sync` traits; the CMC uses a `std::sync::Mutex` (`mpl/src/cmc/storm_tracking.rs`), not lock-free `unsafe` |
origin/Mahnush_Verus:docs/verification-recommendations.md:356:| `mpl/src/cmc/storm_tracking.rs` (~L323+) | `.expect("… lock poisoned")` on `Mutex::lock` | Lock-poisoning propagation |
$ git grep -n -E 'checked_add|SystemTime' origin/Mahnush_Verus -- esdk/shims | head
origin/Mahnush_Verus:esdk/shims/aws-esdk-cpp/src/lib.rs:942:        .checked_add(Duration::from_nanos(u64::from(d.nanos)))
origin/Mahnush_Verus:esdk/shims/aws-esdk-cpp/src/lib.rs:1141:            let Some(expiration) = SystemTime::UNIX_EPOCH.checked_add(since_epoch) else {
```

## 7. Honesty notes and things for the reviewer

- The proof is of a re-typed model. The std `+` and `Mutex` are modeled from a reading of std 1.95.0 (Unix) and the std documentation. Verus has no specification of either. The header says so in section 0 and in the hypotheses.
- The platform range is a parameter (`Range`). The instance `unix64()` is assumed. The BUG-01 log is consistent with it but does not establish it.
- Status string: "Partly proved (model level, not the shipped code, under stated hypotheses): 28 verified, 4 errors", the same form as T02 and T13.
- Prediction M19 in the mutation script was wrong (see `mutation-record.md`).
- Line numbers in docs: only references that 19deef7 also maintained were shifted. Lines 30, 39 and 186 of the audit were left unchanged on purpose.
- `verus-proofs/README.md` names line numbers of the proof file (`:604`, `:614`, `:629`, `:649`, `:668`). They match the final file and `t06-run.txt`.
- No score, rank, gap, quick-win, severity or rating was changed anywhere.
- No independent review pass was run by this step. The workflow's reviewer step does that.

## 8. Fix iteration 2 (review.json verdict CHANGES_REQUESTED)
Finding: `docs/mpl-verification-targets.md:164` and `docs/mpl-verification-targets/01-threat-driven.md:88` cited mutants M13 and M21 as "still failing". Per `mutation-record.md`, only M21 (bound on ttl alone) leaves the obligations failing. M13 (bound on ttl and on the clock) makes the `:702` obligation verify.

Fix: in both files the sentence now reads: "A bound on the builder values alone, without A_NOW_CAP, leaves the expected-FAIL obligations failing (mutant M21). The `:702` obligation verifies once both a bound on ttl and a bound on the clock are added (mutant M13)." It matches `verus-proofs/README.md:332` and `mutation-record.md`. No other occurrence of the wrong citation exists (`grep -rn "M13 and M21" docs verus-proofs` finds none in docs after the edit).

Files changed in this iteration: `docs/mpl-verification-targets.md`, `docs/mpl-verification-targets/01-threat-driven.md`, this record. No `.rs` file changed, so the eight regression results and the T06 mutation record are unchanged.

Commands re-run (docs edit can affect only these):
```
$ python3 .agents/tasks/docs-sync-9955ecd/check_scores.py | tail -1
PROBLEMS: none
$ git diff HEAD --stat -- mpl prim esdk
(empty)
$ ~/verus/verus verus-proofs/t06_systemtime_add_overflow.rs   (sanity)
verification results:: 28 verified, 4 errors      (the four intentional BUG-01 EXPECTED_FAIL errors)
$ git status --short
 M docs/mpl-bug-reports/BUG-01-ttl-duration-overflow-panic.md
 M docs/mpl-bug-reports/BUG-10-raw-aes-on-decrypt-unwiped-data-key.md
 M docs/mpl-bug-reports/README.md
 M docs/mpl-completeness-audit.md
 M docs/mpl-spec-security-analysis.md
 M docs/mpl-threat-model.md
 M docs/mpl-verification-targets.md
 M docs/mpl-verification-targets/01-threat-driven.md
 M docs/mpl-verification-targets/02-capability-driven.md
 M verus-proofs/README.md
?? .agents/tasks/chorus-lookup/ (3 files, not part of this task)
?? .agents/tasks/t06-verus-proof/
?? verus-proofs/t06_systemtime_add_overflow.rs
```
The reviewer's minor wording note ("on a fresh cache" in the comment on `theorem_bug01_poisons_storm_cache`) was not blocking and was left unchanged.
