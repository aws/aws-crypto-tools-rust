# Review: proof status in the MPL verification documents

Verdict: APPROVED, after two in-scope fixes made by the reviewer (listed below).

## Per-check results
1. Proof re-runs: PASS. I re-ran all five from the repo root. T02 `21 verified, 1 errors`, C01 `40 verified, 0 errors`, C02 `21 verified, 0 errors`, T03 `39 verified, 0 errors`, T05 `33 verified, 0 errors`. Every place a document states a result line uses these numbers (grep of all added lines).
2. No-score-change: PASS. `check_scores.py` prints `PROBLEMS: none` and its output is identical to the saved HEAD output. `check_citations.py` gives 2091 rows (HEAD 2091). The only differences against HEAD are the two bare table-cell references in `threat-model.md` that moved with the new section, plus one text change in the `spec-security-analysis.md` G1 row. `check_fn_defs.py` gives def-ok=338, def-mismatch=113, as at HEAD. Removed lines in the three targets docs are only prose that said "no proof exists" (replaced), and table rows that gained the Proof status cell. Quick-wins list rows are unchanged. The author's `check_proof_status.py` also prints `PROBLEMS: none`.
3. Cross-document consistency: PASS. Status words, the qualifier, G1 (with `lemma_g1_code_ignores_fields`, `lemma_g1_witness_accepted_without_fields`, `lemma_g1_spec_soundness_FAILS`, "more permissive, never stricter"), O1, O2, F1 and the BUG-08 condition (dead iff A_ITER, live if a key repeats) agree in the targets docs, threat model, audit, spec analysis, BUG-08, bug-reports README, and both Chorus editions. The G1 and F1 lemma names exist in the proof files.
4. No claim that shipped code is verified: PASS after fix 2. Statements such as "Verified is 0" and "No Verus proof of the shipped code exists" were checked.
5. Excluded files: PASS. `git diff --quiet HEAD -- mpl prim esdk verus-proofs docs/bug-reports/RECHECK-main-620771c.md` exits 0. `git status` shows changes only under `docs/` and `.agents/tasks/docs-proof-status/`. Nothing committed or pushed.
6. .docx files: PASS. Both exist, non-empty (49107 and 45368 bytes), and `pandoc -t plain | head` shows the correct titles. They were regenerated after fix 1 and their content matches the Markdown (same structure; only table column widths differ in pandoc's AST).
7. Header and summary claims: PASS. The `04-validation.md` addendum P1 to P9 and the results.md claims match what the files contain. The completeness-audit line "No proof was run" describes the audit's own run and is correctly left.
Format: no HTML, diagrams, footnotes or emoji in changed files. Table column counts are consistent except one pre-existing row at `spec-security-analysis.md:43`, which is not part of this change.

## Inconsistencies found and fixed
1. Chorus tables had a broken header: `docs/chorus/MPL-Threat-Model.md:427` ("Related bugs  Proof status") and `docs/chorus/MPL-Bug-Reports.md:60` ("Related targets (score)  Proof status") were missing the `|` before `Proof status`. Header had one cell fewer than the separator and body rows, so the new column would render without a title. Fixed both, regenerated both `.docx` with pandoc.
2. In the "Proofs written" tables of `verification-targets.md`, `01-threat-driven.md` and `02-capability-driven.md`, the Status cell said only "Proved." / "Partly proved." beside the raw `N verified` result line. Added the qualifier "(model level, not the shipped code, under stated hypotheses)" to each of the five rows, so no row pairs "verified" with a target without it. Re-ran `check_scores.py` (none), `check_citations.py` (2091 rows) and `check_proof_status.py` (none) afterwards.

## Remaining blockers
None.
