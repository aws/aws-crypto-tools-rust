# Validation Report: MPL Verus Verification Targets (HEAD 9955ecd)

> Pipeline artifact. Stage 3, Step 4 of 4 (validation). Re-run for branch `MPL-Verus` at HEAD `9955ecd`. The previous version of this file described the `620771c` run. Extended in the C03 status update (the commit on top of HEAD `b94c871`) with the checks for the C03 status record (section "C03 status checks"); the 18 checks and the proof-status addendum below are kept unchanged.
> Reviewed: `docs/mpl-verification-targets.md`, `docs/mpl-verification-targets/01-threat-driven.md`, `docs/mpl-verification-targets/02-capability-driven.md`, as they stand in the working tree (uncommitted edits on top of HEAD).
> Checked against: `docs/mpl-threat-model.md` (TM-MPL-001..026), `mpl/src`, `prim/src`, `mpl/tests`, `prim/tests`, `esdk/` (shim and `esdk/src`), and the local `spec/` checkout.
> How the checks were run: a shell was available. Checks used `git`, `grep`, `sed -n`, `ctx.py` and Python scripts kept in `.agents/tasks/docs-sync-9955ecd/` (named per check below). For the 18 checks at `9955ecd` nothing was built and no Verus proof was run. The addendum "Proof-status checks (HEAD `d288750`)" below re-ran the five proofs in `verus-proofs/`. No file under `mpl/`, `prim/` or `esdk/` was written.
> Scope of the claims below: 18 checks were run (the 15 rows of the previous report, numbered 1, 1b and 2 to 14, plus 15, 16 and 17). One defect was found and fixed (see "Fixes made"). Limits of the evidence are in "Open items".

## Result: all 18 checks pass after one fix

| # | Check | Result | Short evidence |
|---|---|---|---|
| 1 | file:line existence for every active target | PASS (see open item 1) | Scripts plus 97 manual rows; no wrong citation found |
| 1b | Cited test names exist at the cited line | PASS | 76 of 77 `name :LINE` citations exact; the 77th is a two-number list, both numbers correct |
| 2 | Every threat mapped or justified | PASS after fix | 26 of 26 threats accounted for; TM-MPL-018 mapping corrected |
| 3 | Severity and feasibility consistent with the threat model | PASS | 35 targets, 0 mismatches |
| 4 | Capability targets carry `capability_reference` | PASS | 7 in 02, 4 in the merged doc |
| 5 | Score arithmetic (S x G x F x B) | PASS | 33 active products recomputed |
| 6 | Rank order and tie-breaks | PASS | Merged order, 01 order, 02 order |
| 7 | ID stability | PASS | No ID removed or reused; T27 added |
| 8 | Retired code and threats not cited as active | PASS | No match for `unsafe` in `mpl/src`, `prim/src` |
| 9 | Merged doc has at least 5 detailed YAML blocks, both origins | PASS | 13 blocks: 9 threat-driven, 4 capability-driven |
| 10 | Quick wins = score above 6.0 and effort at most 1 week | PASS | T02, C01, C02 |
| 11 | Bug-status-driven changes applied | PASS | Fixed BUG-02, 03, 09 not cited as failures |
| 12 | Out-of-scope discipline | PASS | No property scopes crypto hardness or external-service semantics |
| 13 | CVE handling | PASS | CVE-2026-6550 described as verified, not applicable |
| 14 | Docs-only rule | PASS | No code diff; nothing committed or pushed |
| 15 | New: every threat reference exists in the threat model; TM-MPL-001..026 all accounted for | PASS after fix | 0 unknown IDs; 23 targeted, 3 fully excluded |
| 16 | New: every file:line citation verified on the current code | PASS (see open item 1) | Scripts, HEAD-versus-working-tree comparison and manual rows |
| 17 | New: scores recomputed; ranked table, YAML, quick wins, gap table and STRIDE table agree | PASS after fix | `check_scores.py` and four further scripts |

## Check details

### 1 and 16. file:line existence and citations on the current code

Method. Two passes, because the shipped scripts mis-resolve many citations.

1. The shipped scripts, run unchanged from `.agents/tasks/docs-sync-9955ecd/`.
2. A comparison of the working-tree docs against the `HEAD` version of the same docs (exported to `/tmp/headdocs`), followed by a manual read of every citation the scripts could not resolve and that is new since HEAD, using `sed -n`, `ctx.py` and `manual_expect.py`.

Commands.

```
python3 check_citations.py > final-citations.txt
python3 check_fn_defs.py > final-fndefs.txt
python3 check_citations_v3.py > final-citations-v3.txt
DOCROOT=/tmp/headdocs python3 check_citations_v3.py > head-citations-v3.txt
DOCROOT=/tmp/headdocs python3 check_fn_defs_v2.py > head-fndefs.txt
python3 check_fn_defs_v2.py > run1-fndefs-v2.txt
python3 manual_expect.py
```

Results.

- `check_citations.py`, 794 tokens in the three docs: 328 OK, 139 NOID (no identifier to compare), 134 ALT, 97 MISS, 76 RANGE, 20 NOFILE. This is not a clean run. The script resolves a bare `lib.rs` to `mpl/src/lib.rs` (the citation is often `prim/src/lib.rs` or the shim `lib.rs`), sends spec line numbers to code files, and has no file for `:LINE` in a table cell.
- `check_citations_v3.py` (derived copy that keeps every candidate file, treats `*.md:N` as a spec citation and maps `module::` to its file): 338 OK, 153 NOID, 126 ALT, 99 MISS, 43 RANGE, 10 NOFILE.
- Against the HEAD version of the docs, v3 reports 167 distinct non-OK keys; the working tree has 278. The 121 new keys were each read against the code. All resolve to the cited construct. The non-OK status came from wrong-file resolution, or from the named identifier not being on the exact cited line (for example the closing line of a call).
- `check_fn_defs.py`: 66 DEF-MISMATCH lines in the three docs (113 in all six docs the script scans). With `check_fn_defs_v2.py` the HEAD docs give 40 and the working tree 66; the 27 new keys were each read. They are Debug impls cited against the type definition (T22), spec line numbers that follow a code word, and call sites cited against a definition. None is a wrong line.
- `manual_expect.py`: 97 (file, line, pattern) rows written from the doc sentence beside each citation. 97 pass, 0 fail. They cover the hierarchical keyring `on_decrypt` chain (`:734`, `:751`, `:764`, `:867`, `:879`, `:889-894`, `:901`, `:908`, `:916-924`, `:934-938`, `:947-953`), the storm-tracking lines (`:199` to `:740`), raw-AES (`:129`, `:191`, `:350`, `:360`, `:471`, `:489`), the shim (`lib.rs:715`, `:720`, `:728`, `:1287`, `:1331`, `:1570-1571`, `:1652`, `:1661`, `:1942`, `:1985`, `:2059`), `esdk` materials, `mpl/src/error/generated.rs` (`:271`, `:1064`, `:1591`, `:1596`), the C++ header (`EncryptionSDK.h:656-663`, `:664`), and test functions.
- Spec citations (`branch-key-store.md:531`, `:553`, `:574`, `:677`, `:690`, `:692`; `aws-kms-hierarchical-keyring.md:236-249`, `:242`; `storm-tracking-cryptographic-materials-cache.md:59`, `:71`, `:92`, `:136-138`; `shim.md:180-204`) were read in the local `spec/` checkout (a separate git repository at `e833453`; `spec/` is ignored by this repository). Each line holds the sentence the doc attributes to it.
- Code changes since the `620771c` validation: `git diff --quiet 620771c HEAD -- mpl prim` exits 0. In `esdk/`, 8 files under `esdk/shims/aws-esdk-cpp/` changed, among them `src/lib.rs` (8 lines near line 1411, shifting every later line). Every shim `lib.rs` citation at line 1411 or later was read and resolves (`:1564-1565` and `:1570-1571` for the client handles, `:1652`, `:1655`, `:1661`, `:1942`, `:1985`, `:2037-2054`, `:2059`, `:2062`).

Result: no citation in the three docs points at a wrong line. See open item 1 for the part of the evidence that is indirect.

### 1b. Cited test names exist

Method. Collect every `fn` defined only under a `tests/` directory or `tests.rs` whose name has at least three underscore-separated words, and compare each `name :LINE` in the docs with the definition line (inline script; output saved as `check_test_names.out`).

Result. 76 citations match the definition line exactly. One does not: `01-threat-driven.md` line 1224 cites `on_encrypt/on_decrypt_uses_branch_key_id_supplier_when_configured (:1640, :2161)`. The tool matched the shared tail of two function names to one name and one number. Both functions exist at those lines in `mpl/tests/test_aws_kms_hierarchical_keyring.rs` (`on_encrypt_...` at `:1640`, `on_decrypt_...` at `:2161`). No change needed. Also read: `into_keyring_handle_boxes_the_keyring` at `esdk/shims/aws-esdk-cpp/src/tests.rs:1624`, its test-only `Box::from_raw` at `:1634`, and the three shim null-handle tests at `:733`, `:746`, `:791`.

### 2 and 15. Threats mapped; threat references exist; all 26 accounted for

Method and command. `python3 check_threat_refs.py`, then `python3 check_stride_map.py`, then a read of 01 section 6, 01 section 4, and merged sections 4 and 6.

Results.

- `docs/mpl-threat-model.md` has 26 distinct IDs, TM-MPL-001 to TM-MPL-026. Distinct TM references: merged 26, 01 26, 02 5. References not found in the threat model: none, in the prose and in every YAML `threat_references`.
- 23 threats have at least one active threat-driven target in 01 (001 to 018 and 021 to 025). Three have none and are listed as fully excluded: TM-MPL-019 and TM-MPL-020 (01 section 4, section 6, merged section 6) and TM-MPL-026 (the same three places, marked test-only). 23 + 3 = 26.
- TM-MPL-017 is the only threat with no exclusion; the other 22 targeted threats carry a partial exclusion. This matches merged section 4.
- Defect found by the cross-check: T27 cites TM-MPL-018 as a secondary threat in its YAML (01 and merged), but the TM-MPL-018 rows in 01 section 6, 01 section 4 and merged section 6 named only T21 and T06. Fixed (see "Fixes made"). After the fix `check_stride_map.py` reports 0 problems: every threat's target list in 01 section 6 equals the set of active YAML blocks that cite it.
- Merged section 4 (STRIDE) was compared with the threat-model appendix: 6 rows, 26 threats, category counts 3, 5, 1, 3, 4, 10; "With target" 3, 5, 0, 3, 4, 8 (total 23); fully excluded 0, 0, 1, 0, 0, 2 (total 3); the "Targets" column of each row equals the YAML-derived set.

### 3. Severity and feasibility consistent with the threat model

Command. `python3 check_ratings.py`.

Result. The appendix table has 26 rows. The 26 rows of 01 section 6 (Severity / Likelihood) equal the appendix. For each of the 35 active threat-driven YAML blocks (26 in 01, 9 in the merged doc), `severity` equals the primary threat's Severity (Critical 4, High 3, Medium 2, Low 1) and `feasibility` equals its Likelihood (Low 0.4, Medium 0.7). 0 mismatches. This includes TM-MPL-009 and TM-MPL-010 (High, Medium), TM-MPL-015 (Medium, Low), TM-MPL-024 (High, Low), TM-MPL-025 (Medium, Medium) and TM-MPL-026 (Medium, Low, no target).

### 4. Capability targets carry `capability_reference`

Command. `python3 check_misc.py`.

Result. C01, C02, C03, C04, C05, C07 and C08 in 02 have `capability_reference`, a `category` and an `invariant`; the four capability blocks in the merged doc (C01, C02, C03, C07) have them too. Categories: C01 1, C02 2, C03 2, C04 1, C05 1, C07 1, C08 2.

### 5 and 17. Score arithmetic and cross-document agreement

Commands.

```
python3 check_scores.py            # PROBLEMS: none
python3 check_extras.py            # PROBLEMS: none
python3 check_prose_scores.py      # 29 mentions, 0 wrong
python3 check_stride_map.py        # 0 problems after the fix
python3 check_ratings.py           # 0 mismatches
```

Results.

- YAML blocks: 01 has 27 (26 active, T08 retired), 02 has 8 (7 active, C06 retired), the merged doc has 13. Active targets: 33 (26 threat-driven, 7 capability-driven).
- All 33 products recomputed from the factors with decimal arithmetic and equal `priority_score` and the `product` string in 01/02 and the merged doc: T01 8.96, T02 6.72, C01 6.72, C02 6.40, C03 5.60, T03 5.12, C07 5.04, T04 4.48, T13 4.41, T05 4.32, T06 4.20, T07 3.84, T14 3.78, T27 3.78, T26 3.20, T10 2.88, T11 2.88, T12 2.88, C04 2.80, T09 2.56, C05 2.40, T16 2.24, T21 2.24, T15 1.92, T17 1.92, T18 1.92, T19 1.92, T20 1.68, T22 1.60, T25 1.44, T23 1.26, T24 1.20, C08 0.96. T21 is 2 x 0.8 x 0.7 x 2 = 2.24 everywhere; the old value 1.96 appears only on history lines.
- Every merged YAML block has the same factors and score as its source block in 01 or 02. Each top-level `coverage_gap` equals `scoring.coverage_gap`.
- Merged section 1 has 35 rows (33 active, 2 retired); each active row score equals the YAML. Merged section 3 has 33 rows and each gap equals the YAML. The `rank` field of each merged YAML block equals its section 1 rank.
- The 26 rows of the 01 ranked table and the 7 rows of the 02 ranked table are in the same relative order as the merged table, with sequential rank columns. 01 says T27 is inserted at rank 10 and its table has T27 at rank 10.
- The rank claims in the merged refresh section hold: T14 13, T27 14, T26 15, T16 22, T21 23, T25 30, C08 33, T02 2.
- The 29 prose mentions of the form `T27 (3.78` agree with the YAML; one history mention (T21 1.96) is an old score and is labeled as such.
- Quick wins (score above 6.0 and effort at most 1 week): computed T02, C01, C02; merged section 5 lists T02, C01, C02; every `quick_win` flag in the YAML equals the rule (T01, 8.96, is 2 weeks and is not a quick win).
- Agent totals computed from the 33 `agent` fields: mpl-verus-header-parsing-proofs 20, mpl-verus-zero-panic 8, mpl-verus-unsafe-ffi-safety 5 (33). The merged refresh section states the same.
- STRIDE summary (merged section 4): the top-priority target per category (Spoofing T01, Tampering T01, Information Disclosure T13, Denial of Service T06, Elevation of Privilege T04) equals the highest-scoring active threat-driven target that cites a threat of that category (computed by script from the YAML).

### 6. Rank order and tie-breaks

Covered by `check_scores.py` and `check_extras.py`. The order is score descending, then severity descending, then T before C, then ID. Examples read: T02 (severity 4) before C01 (severity 3) at 6.72; T10, T11, T12 at 2.88 by ID; T14 (severity 3) before T27 (severity 2) at 3.78; T16 before T21 at 2.24; T15, T17 (severity 3) before T18, T19 (severity 2) at 1.92.

### 7. ID stability

Command. `python3 check_misc.py` (compares the YAML IDs of the working tree with `git show HEAD:`).

Result. IDs removed from 01 or 02 versus HEAD: none. IDs added: T27 only. T08 (01) and C06 (02) are still `status: Retired` blocks with a reason. T21's `file` list gained `mpl/src/aws_kms/hierarchical_keyring.rs`; no other `file` or status field changed.

### 8. Retired code and threats not cited as active

Commands.

```
grep -rnw unsafe mpl/src prim/src                     # 0 lines
grep -n -E 'ValidatedConfig::from_raw|HierarchicalKeyring::new|RawAesKeyring::new|resolve_keystore_arn' <three docs>
```

Result. `unsafe` as a word has no match in `mpl/src` or `prim/src` (the lint name `unsafe_op_in_unsafe_fn` at `prim/src/lib.rs:33` is a single identifier and is described as such in 01). The old names appear only in "renamed from", "was" and retirement text (01 line 56; 02 lines 32, 70, 443, 445). `mpl/src/keystore/` and `BranchKeyStore::` have no match in the three docs; `mpl/src/keystore/` does not exist. No threat is retired, so none can be cited as active.

### 9. Merged doc has at least 5 detailed YAML blocks and both origins

Result. 13 blocks: threat-driven T01, T02, T03, T04, T05, T13, T25, T26, T27; capability-driven C01, C02, C03, C07.

### 10. Quick wins

Covered under check 17. T27 (3.78) and T21 (2.24) are below the threshold; T26 (3.20, 2 weeks) and T25 (1.44) also stay out.

### 11. Bug-status-driven changes

Method. Compared the statuses in `docs/mpl-bug-reports/RECHECK-main-620771c.md` (BUG-02, 03 and 09 fixed on main; BUG-01, 04, 05(a), 05(b), 06, 07, 08 still present) with the three docs by `grep`.

Result. No line cites BUG-02 or BUG-09 as an expected failure. BUG-03 appears with "FAIL" wording only to say the counterexample is gone (01 lines 54, 1103; 02 line 460). The merged and 01 bug lists say: open BUG-01, 04, 05(a), 05(b), 06, 07(a/b), 08; fixed BUG-02, 03, 09. The open bugs are still cited as expected failures in T06, T17, T16, T13, T26, C03, C01.

### 12. Out-of-scope discipline

Method. Searched the `property:` text of every YAML block for crypto-hardness, probabilistic and external-service terms (collision resistance, IND-CPA, birthday, probability, entropy, side channel, KMS or DynamoDB guarantees, allocator, C++ pointer ownership), and read merged section 6 and 01 section 4.

Result. One hit: T05's property names "PRF HMAC-SHA-256" as a parameter of the fixed KDF input, not a hardness claim. No target scopes hardness, KMS or DynamoDB behaviour, probabilistic bounds, allocator or OS memory, or the validity of C++-supplied pointers. T25 and TM-MPL-024 keep the C++ `Keyring::adopt` half as a caller obligation outside the proof.

### 13. CVE handling

Result. CVE-2026-6550 / GHSA-v638-38fc-rhfv appears in merged section 0 (line 38) and in 01 (lines 66, 587 and 1499). It is described as verified in the threat model, not applicable to this repository (no caching CMM exists), and no score depends on it.

### 14. Docs-only rule

Commands and results.

```
git diff --quiet HEAD -- mpl prim esdk            # exit 0 (no uncommitted code change)
git diff --quiet 620771c HEAD -- mpl prim         # exit 0 (mpl and prim identical to origin/main 620771c)
git status --short                                # M docs/mpl-verification-targets.md, 01-threat-driven.md, 02-capability-driven.md;
                                                  # ?? .agents/tasks/docs-sync-9955ecd/ (before this report was rewritten)
git status --short -- docs/mpl-bug-reports docs/mpl-spec-security-analysis.md    # empty
```

This step edited the three targets docs (one fix), rewrote this file, and wrote scratch files under `.agents/tasks/docs-sync-9955ecd/`. Nothing was committed or pushed. `docs/mpl-bug-reports/*` and `docs/mpl-spec-security-analysis.md` were not touched.

Format checks on the three docs and this file: no diagram blocks, no footnote markers, no HTML tags outside code spans and fenced blocks, balanced code fences, no emoji.

## Fixes made

1. TM-MPL-018 mapping (found by checks 2, 15 and 17). T27's YAML cites TM-MPL-018 as a secondary threat, but three places listed only T21 and T06 for it. Changed:
   - `01-threat-driven.md` section 6 row TM-MPL-018: `T21, T06` to `T21, T06, T27`.
   - `01-threat-driven.md` section 4 row TM-MPL-018: `Partial (→ T21, T06)` to `Partial (→ T21, T06, T27)`.
   - `mpl-verification-targets.md` section 6 bullet: `TM-MPL-018 (→ T21, T06)` to `TM-MPL-018 (→ T21, T06, T27)`.
2. Change lists made to match. `mpl-verification-targets.md` line 27 now says that the TM-MPL-018 partial-exclusion line names T27 and that this file was rewritten for `9955ecd` (18 checks, one mapping fix); before, it said this file still described the `620771c` run. `01-threat-driven.md` line 28 now says the TM-MPL-018 rows name T27.

No score, rank, ID or citation changed. After the fix every script above was re-run: `check_scores.py`, `check_extras.py`, `check_misc.py` and `check_ratings.py` report no problem, `check_stride_map.py` reports 0 problems (it reported 1 before), and `manual_expect.py` passes 97 of 97.

## Proof-status checks (HEAD `d288750`)

Added when the proof status of T02, C01, C02, T03 and T05 was recorded in the targets documents, the threat model, the completeness audit, the spec analysis, the BUG-08 report and the Chorus editions. The 18 checks above are unchanged. Scripts and outputs are in `.agents/tasks/docs-proof-status/` (`results.md`, `check_proof_status.py`, and the `docs-sync-9955ecd` checkers `check_scores.py`, `check_citations.py`, `check_fn_defs.py`).

| # | Check | Result | Short evidence |
|---|---|---|---|
| P1 | Each recorded status matches a proof re-run and its log | PASS | Re-ran `~/verus/verus verus-proofs/<file>.rs` for all five: T02 Partly proved (model level, not the shipped code, under stated hypotheses): 21 verified, 1 errors (the one error is the intentional G1 obligation); C01 Proved (model level, not the shipped code, under stated hypotheses): 40 verified, 0 errors; C02 Proved (model level, not the shipped code, under stated hypotheses): 21 verified, 0 errors; T03 Proved (model level, not the shipped code, under stated hypotheses): 39 verified, 0 errors; T05 Proved (model level, not the shipped code, under stated hypotheses): 33 verified, 0 errors. The same result lines are in the five logs under `.agents/tasks/verus-proofs-quickwins/logs/` and `.agents/tasks/verus-proofs-t03-t05/logs/`, and in the two proof READMEs |
| P2 | No score, rank, coverage gap, feasibility, severity or quick-win changed | PASS | `check_scores.py`: PROBLEMS none. Diff against HEAD by script: every changed ranked-table row (35 merged, 27 in 01, 8 in 02) equals its HEAD row plus the added `Proof status` cell; every YAML block (13, 27, 8) equals its HEAD block apart from `proof_status` and `proof_file` lines. The quick-wins table is unchanged (one sentence added below it) |
| P3 | Proof files exist at the cited paths | PASS | All five files exist under `verus-proofs/`; every `verus-proofs/...` path cited in the changed documents resolves |
| P4 | Status wording is identical across documents | PASS | The canonical status string of each target appears the required number of times in the targets documents (YAML field, table cell, list), and in the threat model, the Chorus threat model, the audit, the spec analysis, the BUG-08 report and the Chorus bug reports. Every `N verified, M errors` mention in the changed documents is one of the five real result lines. A result line never appears without the qualifier "model level, not the shipped code" |
| P5 | Findings recorded | PASS | G1, O1, O2, F1, the BUG-08 condition (dead if and only if A_ITER) and the C02 `copy_from_slice` assumption appear in the targets documents; G1, O1, O2, F1 and BUG-08 in the threat model and the Chorus threat model; G1 in the audit; G1, O1, O2 and F1 in the spec analysis; BUG-08 in its report and the Chorus bug reports |
| P6 | Citations | PASS | `check_citations.py` and `check_fn_defs.py` compared with the same run on HEAD: the number of citation rows is equal (2091), no new non-OK row except two table-cell line references in the threat model that moved with the new section (they were already in the unresolved class), and the def-mismatch count is equal (113). Five line references to the targets documents in the threat model Resolution table, and the G1 and G4-1 rows of the audit table, were updated to the new line numbers and checked by a line-map script |
| P7 | Docs-only rule | PASS | `git diff --quiet HEAD -- mpl prim esdk verus-proofs docs/mpl-bug-reports/RECHECK-main-620771c.md` exits 0. `git status --short` shows only files under `docs/` and `.agents/tasks/docs-proof-status/`. Nothing was committed or pushed |
| P8 | Chorus editions regenerated | PASS | `pandoc docs/chorus/MPL-Threat-Model.md -o docs/chorus/MPL-Threat-Model.docx` and the same for `MPL-Bug-Reports`: both exit 0, both files exist and are non-empty, and `pandoc X.docx -t plain \| head` shows the document title |
| P9 | Format | PASS | In the changed Markdown files: no HTML tags outside code, no diagram blocks, no footnote markers, no emoji, balanced code fences |

Limits. The proofs are of re-typed models; these checks show that the documents record the proofs correctly, not that the shipped code has the proved properties. The correspondence between model and code is a human review recorded in each proof file header.

## C03 status checks (C03 status update on top of HEAD `b94c871`)

Added when the status of target C03 (in-crate on branch `Mahnush_Verus`, VR-013 and VR-014), the C02 / VR-008 relation and BUG-10 were recorded in the targets documents, `docs/mpl-threat-model.md`, `docs/mpl-completeness-audit.md` and `docs/chorus/MPL-Threat-Model.{md,docx}`. The 18 checks above and P1 to P9 are unchanged. Scripts and outputs are in `.agents/tasks/docs-c03-status/`: `check_c03_status.py` (output `check_c03_status.out`), `rank_score_diff.sh` (outputs `rank-score.head.txt`, `rank-score.now.txt`, `rank-score.diff`), `rerun.md` and the two `rerun-*.log` files, plus the `docs-sync-9955ecd` checkers.

| # | Check | Result | Short evidence |
|---|---|---|---|
| C1 | Every recorded proof status matches a re-run or a stated source | PASS | C03: `cargo verus verify` in `prim/` at `8d6381e` (detached worktree under `/tmp`, removed afterwards): default features `verification results:: 18 verified, 0 errors` (aws-mpl-primitives), and `--no-default-features --features aws-lc-sys` the same line; the count equals our review at `43b9ff7` (no commit after `43b9ff7` touches `prim/`). The five model-level strings (T02, C01, C02, T03, T05) occur as often as at HEAD in every document; their proofs were not re-run in this step, because no proof file or code changed (re-run at `d288750`: P1) |
| C2 | No score, rank, coverage gap, feasibility, severity or quick-win changed | PASS | `check_scores.py`: PROBLEMS none; `check_extras.py`, `check_misc.py`: PROBLEMS none; `check_prose_scores.py`: 0 wrong; `check_ratings.py`: 0 mismatches; `check_stride_map.py`: 0 problems. `rank_score_diff.sh` diffs the rank, ID and score columns of all 73 ranked rows (merged 38, 01 27, 02 8) against HEAD: the diff is empty. Every ranked row differs from HEAD only in its last cell (merged 2 cells: C02, C03; 02: 2 cells: C02, C03; 01: none). Every YAML block equals its HEAD block apart from the added keys (`proof_*`, `related_bugs`, `scope_note`), and only C02, C03 and T26 changed |
| C3 | The C03 statuses are consistent with the review report and with the other branch | PASS | The canonical C03 string is the same in the YAML field, the ranked table cell and the canonical list of the merged and 02 documents, and in the threat model, the audit and the Chorus threat model. Against `.agents/tasks/review-vr013-vr014/report.md`: verdict "Consistent with gaps", count 18, trusted base A1 to A20, the gaps list (`hkdf` end to end, `DigestContext::digest`, adapters, A12/A13, the in-body `Ok` order and A19, A20 assumption-relative). Read-only against `origin/Mahnush_Verus` (`8d6381eb82daee55ecf32911d6ef8b48690d68b9`): 20 `assume_specification` in `aws_lc_specs.rs`; the nine cores named in the documents exist (`hmac_core`, `digest_core`, `kbkdf_core`, `fill_random_core`, `ct_equal_core`, `aes_encrypt_core`, `aes_decrypt_core`, `digest_finish_core`, `sign_fixed_len_core`); no `verus-proofs/` directory; `mpl/src` identical to this branch; merge base `5f2dc72`, 20 commits only here and 47 only there |
| C4 | No document says the C03 proof is on this branch | PASS | A script checks every line that mentions VR-013, VR-014, "18 verified" or an in-crate proof: its own line, its table header, its YAML block or its subsection lead paragraph names `Mahnush_Verus` or "not on this branch". Lines that combine "C03" with "on this branch" all negate it. The C03 YAML `proof_location` says "NOT on MPL-Verus" |
| C5 | C02 is partly superseded, not a duplicate, and not demoted | PASS | No line with C02 and "duplicate" lacks a negation. C02's canonical model-level string is unchanged (same count as HEAD); the relation is a separate YAML `proof_note`, a separate line in the canonical list and an added sentence in the ranked cell |
| C6 | BUG-10 -> TM-MPL-015 -> T26 recorded consistently | PASS | T26 YAML `related_bugs` and `scope_note` in 01 and the merged document (T26 `proof_status` still "None yet", score 3.20); C03 YAML `related_bugs` names BUG-07(a), BUG-07(b) and BUG-10; the threat model (TM-MPL-015 residual exposures, bug to threat table, proof-status rows), the audit (section 7) and the Chorus threat model (headline counts, TM-MPL-015, cross-reference table, bug table, note 6) name BUG-10. The bug count in the Chorus threat model is now ten (it said nine) |
| C7 | Line numbers cited into the targets documents still resolve | PASS | The targets documents gained lines, so 22 citations in the threat model (resolution table) and 26 in the audit (section 7) were checked with a line map against HEAD (same content at the new line) and the moved ones (13 distinct line numbers) were updated (merged `:104 -> :167`, `:111 -> :174`, `:116 -> :179`, `:183 -> :246`, `:189 -> :252`, `:191 -> :254`, `:490 -> :576`, `:523-537 -> :609-623`, `:561 -> :647`, `:584 -> :670`; 01 `:1551 -> :1560`, `:1617 -> :1626`, `:1619 -> :1628`). Lines 747 to 750 of `01-threat-driven.md` (cited by the BUG-10 report) are identical to HEAD, so that report was not touched |
| C8 | New file:line citations into `mpl/` and `prim/` | PASS | 12 checked by pattern on the line: `raw_aes_keyring.rs` `:163`, `:369`, `:379`, `:471`, `:489`, `:494`, `:497`; `branch_key_wrap.rs` `:157`, `:199`, `:230`, `:275`; `prim/src/lib.rs:215`. The citation scripts of `docs-sync-9955ecd` report new NOID / MISS / ALT rows for these (26 new non-OK keys over 1111 at HEAD) because they resolve a bare function name against another file; each was read. `check_fn_defs_v2.py` adds 15 DEF-MISMATCH rows, all call sites cited against a definition (the class already described under check 1). Nothing on `Mahnush_Verus` is cited by line number; function names are used because the scripts resolve every `file:line` against this tree |
| C9 | Docs-only rule | PASS | `git diff --quiet HEAD -- mpl prim esdk verus-proofs docs/mpl-bug-reports docs/mpl-spec-security-analysis.md docs/chorus/MPL-Bug-Reports.md docs/chorus/MPL-Bug-Reports.docx` exits 0. `git status --short`: modified `docs/mpl-verification-targets.md`, `docs/mpl-verification-targets/` (01, 02, 04), `docs/mpl-threat-model.md`, `docs/mpl-completeness-audit.md`, `docs/chorus/MPL-Threat-Model.{md,docx}`; untracked `.agents/tasks/docs-c03-status/`. Branch `MPL-Verus`, HEAD `b94c871`. `origin/Mahnush_Verus` was only fetched (a new remote-tracking ref); no merge, checkout or modification; the re-run worktree was removed. Nothing committed or pushed |
| C10 | Format and the Chorus edition | PASS | In the changed Markdown files: no HTML outside code, no emoji, no diagram block, no footnote marker, balanced fences, no new table with a wrong column count. `pandoc docs/chorus/MPL-Threat-Model.md -o docs/chorus/MPL-Threat-Model.docx` exits 0; the file is non-empty (50 KB) and `pandoc docs/chorus/MPL-Threat-Model.docx -t plain \| head` shows the title "MPL Threat Model: AWS Cryptographic Material Providers Library (native Rust)" |

Limits. The model-level proofs were not re-run in this step. The C03 re-run was done by the previous workflow step and is recorded in `rerun.md`; the prim tests, clippy and the 1443-line differential run are from our review at `43b9ff7` and were not repeated at `8d6381e`. No FIPS run exists. The check that "partly" is the right word rests on the review report (the gaps), not on a new reading of the proof sources. These checks show that the documents record the proofs and bugs consistently; they do not show that the code on this branch has any of the proved properties.

## Open items

1. Indirect evidence for unchanged citations. The shipped citation scripts leave many citations unresolved (see check 1 and 16). The 121 non-OK citations new since HEAD were each read. The 157 non-OK keys that are identical in the HEAD docs were not re-read one by one. They rely on the fact that `mpl/` and `prim/` are unchanged since the `620771c` run, in which they were read, and on the shim lines being re-read as described. A full reading of every citation in all three docs on the current code was not done.
2. The scripts shipped for this step mis-resolve bare `lib.rs`, spec line numbers and table-cell `:LINE`. The derived `check_citations_v3.py` and `check_fn_defs_v2.py` reduce the noise but do not remove it. They are scratch files and are not committed. The shipped scripts also scan this file, and they mis-resolve the line numbers quoted here in the same way, so their counts for this file are not meaningful.
3. TM-MPL-025 and target T27 are provisional. The threat model derives them by static reasoning; the docs say so, and no reproducer test exists yet. The score 3.78 depends on that threat rating (Medium, provisional) and on a coverage gap of 0.9 that is itself an estimate.
4. `spec/` is a local checkout (separate git repository at `e833453`, ignored by `.gitignore`); the spec revision floats on `master`. Spec line citations were checked only against that checkout.
5. C07's note about fields not constrained by `check_encryption_transition` was not compared with Dafny `Materials.dfy`, which is not in this repository.
6. No Verus proof existed or was run for the 18 checks at `9955ecd`. Five proofs of models now exist (see the addendum), and C03 is partly proved in-crate on branch `Mahnush_Verus`, not on this branch (see "C03 status checks"). "Expected FAIL" and "expected VERIFY" labels for every other target remain predictions from reading the code and tests. For T02, C01, C02, T03 and T05 the proof results are recorded in "Proofs written" in the targets documents; they are model level and do not verify the shipped code.
7. Open code defects recorded in the docs for owner decision (merged section 7): BUG-01, 04, 05(a), 05(b), 06, 07(a/b), 08 and 10 (BUG-10 by code reading); T21 properties (g), (h), (i); the missing `create-time` and `hierarchy-version` read-path check (T02, G1); C++ `Keyring::adopt` has no null, type or ownership check (T25). None is changed by this step.
8. C03 is partly proved on `Mahnush_Verus` only. Whether and how the proof reaches this branch is an owner decision; until then no document may call the code here verified. The wording and test fixes recommended for that branch by our review are not applied here.
9. The BUG-07 and BUG-10 caller findings are code reading (mpl is not Verus-enabled on either branch). The "cannot fire today" statements rest on the wrapping-key length check in `RawAesKeyringBuilder::build` and on key and IV sizes fixed by type; a regression in either would change them.

Note (2026-11-17): the Chorus review edition of the threat model (`docs/chorus/MPL-Threat-Model.md` and `.docx`) and the Word copy of the bug reports (`docs/chorus/MPL-Bug-Reports.docx`) were removed after an internal lookup showed that Chorus takes Markdown natively and has no Word import (see `.agents/tasks/chorus-lookup/cli-output.txt`). The source of truth for the threat model is `docs/mpl-threat-model.md`; `docs/chorus/MPL-Bug-Reports.md` is the only file left in `docs/chorus/`. Rows above that cite the removed files describe the state when each check ran.
