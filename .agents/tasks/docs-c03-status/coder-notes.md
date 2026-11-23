# Coder notes: C03 / C02 / BUG-10 status record (first iteration, no review.json existed)

Branch `MPL-Verus`, HEAD `b94c8719dc4e9ccd6ad35dc9d6755e23581b5586`. Nothing committed or pushed. Documentation only.

## Sources read
- `.agents/tasks/docs-c03-status/rerun.md` (previous step): re-run at the `origin/Mahnush_Verus` tip `8d6381eb82daee55ecf32911d6ef8b48690d68b9` (`8d6381e`), `cargo verus verify` default features and `--no-default-features --features aws-lc-sys`, both `verification results:: 18 verified, 0 errors` (aws-mpl-primitives); vstd line `1858 verified, 0 errors` not a C03 result; no `prim/` change after `43b9ff7`.
- `.agents/tasks/review-vr013-vr014/report.md` (verdict "Consistent with gaps"; scope table; A1-A20; doc inconsistencies; uncovered items; caller impact; recommended fixes).
- `docs/bug-reports/BUG-07-prim-aes-buffer-handling.md` ("Impact on callers"), `BUG-10-raw-aes-on-decrypt-unwiped-data-key.md`, `README.md` (not edited).
- Read-only against `origin/Mahnush_Verus` at `8d6381e` (`git show`, `git ls-tree`, `git merge-base`, `git diff --stat`; no checkout, no merge, no worktree in this step): `docs/verus-proofs-report.md`, `verification/README.md`, `docs/verification-recommendations.md`; `prim/src/lib.rs`, `prim/src/ecdsa.rs`, `prim/src/aws_lc_specs.rs` (cores present; 20 `assume_specification`).
- The existing docs (targets, threat model, audit, Chorus threat model, 04-validation) and `verus-proofs/README.md` (T1-T6 labels of C02).

## Tip read
`origin/Mahnush_Verus` = `8d6381eb82daee55ecf32911d6ef8b48690d68b9`. VR-013/VR-014 commits `ed4a81e`, `43b9ff7`; `2d22937` and `8d6381e` are docs only. Diverged: merge base `5f2dc72`, 20 commits only on MPL-Verus, 47 only on Mahnush_Verus. `mpl/` identical except two `Cargo.lock` files; `prim/` and `esdk/` differ. Mahnush_Verus has no `verus-proofs/` directory.

## Statuses recorded
- C03: `Partly proved (in-crate, on the shipped prim code, on branch Mahnush_Verus, not on this branch, under trusted aws-lc-rs assumptions A1-A20): 18 verified, 0 errors`. Result line `verification results:: 18 verified, 0 errors`, re-run at `8d6381e`, same as `43b9ff7`. Gaps and trusted base as in the brief (all nine items present in the merged document).
- C02: model-level string unchanged (`Proved (model level, not the shipped code, under stated hypotheses): 21 verified, 0 errors`); relation added as a separate `proof_note`, a separate canonical-list line and a sentence in the ranked cell: partly superseded by VR-008 (in-crate, Mahnush_Verus); not a duplicate, not demoted.
- BUG-10 -> TM-MPL-015 -> T26: T26 YAML `related_bugs` + `scope_note` (01 and merged); T26 score 3.20, rank, gap, `proof_status: "None yet"` unchanged. C03 YAML `related_bugs`: BUG-07(a), BUG-07(b), BUG-10.

## Files changed (docs only)
docs/verification-targets.md, docs/verification-targets/01-threat-driven.md, 02-capability-driven.md, 04-validation.md, docs/threat-model.md, docs/completeness-audit.md, docs/chorus/MPL-Threat-Model.md and .docx. Scripts: `edit_targets.py`, `edit_others.py` (applied once), checkers below.

## Runs and results
- `check_c03_status.py` -> `check_c03_status.out`: `PROBLEMS: none`. Covers canonical strings, ranked-table cells, YAML diff vs HEAD (only C02, C03, T26 changed, only added keys), result-line qualifiers, no "C03 on this branch" claim, C03 facts vs review report and vs origin/Mahnush_Verus (20 assume_specification, nine cores, no verus-proofs/, mpl/src identical, divergence 20/47), no "duplicate" for C02, BUG-10 coverage, cite remapping, forbidden paths, format, 12 new file:line cites.
- `check_scores.py`: PROBLEMS none. `check_extras.py`: none. `check_misc.py`: none. `check_prose_scores.py`: 0 wrong (1 history mention). `check_stride_map.py`: 0 problems. `check_ratings.py`: 0 mismatches. `check_threat_refs.py`: ok. Outputs `check_*.out` here.
- Rank + score diff against HEAD: `rank_score_diff.sh` -> `rank-score.head.txt` and `rank-score.now.txt` (73 ranked rows: rank, ID, score), `rank-score.diff` is empty (exit 0). The ranked rows differ from HEAD only in the last (Proof status) cell: merged C02 and C03, 02 C02 and C03, 01 none.
- YAML: `ruby` parse of all blocks: merged 13 ok, 02 8 ok, 01 26 ok (the retired T08 block does not parse at HEAD either).
- Citations: `check_citations_v3.py` / `check_fn_defs_v2.py` HEAD vs now: 26 new non-OK keys (of 1111) and 15 new DEF-MISMATCH rows, all for the new cites `raw_aes_keyring.rs:163/369-379/471/489-494/497`, `branch_key_wrap.rs:157/199/275`; each verified by pattern on the line (check item 12) and by `sed` (wrap_data_key at :146 with aes_encrypt call :163; wrap :157 / call :199; unwrap :230 / buffer :275; build :350 / check :369-379; on_decrypt :422 / buffer :471 / continue :489-494 / move :497). Mahnush_Verus is cited by function name only.
- Line-number cites into the targets docs (threat model 22, audit section 7 26) re-mapped with the line map: 13 distinct numbers updated. `01-threat-driven.md` lines 747-750 (cited by the BUG-10 report) are identical to HEAD: edits in 01 above line 750 were in place (no new lines).
- `git diff --quiet HEAD -- mpl prim esdk verus-proofs docs/bug-reports docs/spec-security-analysis.md docs/chorus/MPL-Bug-Reports.md docs/chorus/MPL-Bug-Reports.docx`: exit 0. `git status --short`: the eight docs above plus `?? .agents/tasks/docs-c03-status/`.
- pandoc: `/opt/homebrew/bin/pandoc docs/chorus/MPL-Threat-Model.md -o docs/chorus/MPL-Threat-Model.docx` exit 0; file 50794 bytes; `pandoc ... .docx -t plain | head -3` first line `MPL Threat Model: AWS Cryptographic Material Providers Library (native Rust)`.
- Not run in this step: the five model-level proofs (no proof file or code changed; last re-run at `d288750`, check P1), the C03 re-run (done by the previous step, `rerun.md`), FIPS.

## Inconsistencies found
1. The Chorus threat model still said "9 bug reports (BUG-01 to BUG-09)" and "all nine bugs" after BUG-10 was added; fixed (ten bugs, 12 items).
2. The audit's section 7 line cites into the targets docs were stale after the "Proofs written" insertions; remapped. The audit's findings table (line 39: `:1294`) is a record of the audit time and was left alone.
3. The other branch's docs call C03 "in-crate" without "partly" and say the `Ok`-case order is proved (review items B1, B2); this record uses "partly" and "in-body assert".
4. The threat model's TM-MPL-015 rating prints as Medium/Low in places (Severity / Likelihood) and Low as risk elsewhere; left as is, no rating changed.
5. The threat model has no BUG-07 -> TM-MPL-011 link (only via T07), so C03 rows were placed under TM-MPL-015 and TM-MPL-023 (bug links), not TM-MPL-011. The VR-013 no-panic/length results are not attached to a threat (C03 cites none).
6. A20 line numbers disagree across the other branch's notes (review "Inconsistencies" 1); not cited by line here.
