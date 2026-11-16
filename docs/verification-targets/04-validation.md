# Validation Report: MPL Verus Verification Targets (HEAD 9955ecd)

> Pipeline artifact. Stage 3, Step 4 of 4 (validation). Re-run for branch `MPL-Verus` at HEAD `9955ecd`. The previous version of this file described the `620771c` run.
> Reviewed: `docs/verification-targets.md`, `docs/verification-targets/01-threat-driven.md`, `docs/verification-targets/02-capability-driven.md`, as they stand in the working tree (uncommitted edits on top of HEAD).
> Checked against: `docs/threat-model.md` (TM-MPL-001..026), `mpl/src`, `prim/src`, `mpl/tests`, `prim/tests`, `esdk/` (shim and `esdk/src`), and the local `spec/` checkout.
> How the checks were run: a shell was available. Checks used `git`, `grep`, `sed -n`, `ctx.py` and Python scripts kept in `.agents/tasks/docs-sync-9955ecd/` (named per check below). Nothing was built, and no Verus proof was run. No file under `mpl/`, `prim/` or `esdk/` was written.
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

- `docs/threat-model.md` has 26 distinct IDs, TM-MPL-001 to TM-MPL-026. Distinct TM references: merged 26, 01 26, 02 5. References not found in the threat model: none, in the prose and in every YAML `threat_references`.
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
- Agent totals computed from the 33 `agent` fields: verus-header-parsing-proofs 20, verus-zero-panic 8, verus-unsafe-ffi-safety 5 (33). The merged refresh section states the same.
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

Method. Compared the statuses in `docs/bug-reports/RECHECK-main-620771c.md` (BUG-02, 03 and 09 fixed on main; BUG-01, 04, 05(a), 05(b), 06, 07, 08 still present) with the three docs by `grep`.

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
git status --short                                # M docs/verification-targets.md, 01-threat-driven.md, 02-capability-driven.md;
                                                  # ?? .agents/tasks/docs-sync-9955ecd/ (before this report was rewritten)
git status --short -- docs/bug-reports docs/spec-security-analysis.md    # empty
```

This step edited the three targets docs (one fix), rewrote this file, and wrote scratch files under `.agents/tasks/docs-sync-9955ecd/`. Nothing was committed or pushed. `docs/bug-reports/*` and `docs/spec-security-analysis.md` were not touched.

Format checks on the three docs and this file: no diagram blocks, no footnote markers, no HTML tags outside code spans and fenced blocks, balanced code fences, no emoji.

## Fixes made

1. TM-MPL-018 mapping (found by checks 2, 15 and 17). T27's YAML cites TM-MPL-018 as a secondary threat, but three places listed only T21 and T06 for it. Changed:
   - `01-threat-driven.md` section 6 row TM-MPL-018: `T21, T06` to `T21, T06, T27`.
   - `01-threat-driven.md` section 4 row TM-MPL-018: `Partial (→ T21, T06)` to `Partial (→ T21, T06, T27)`.
   - `verification-targets.md` section 6 bullet: `TM-MPL-018 (→ T21, T06)` to `TM-MPL-018 (→ T21, T06, T27)`.
2. Change lists made to match. `verification-targets.md` line 27 now says that the TM-MPL-018 partial-exclusion line names T27 and that this file was rewritten for `9955ecd` (18 checks, one mapping fix); before, it said this file still described the `620771c` run. `01-threat-driven.md` line 28 now says the TM-MPL-018 rows name T27.

No score, rank, ID or citation changed. After the fix every script above was re-run: `check_scores.py`, `check_extras.py`, `check_misc.py` and `check_ratings.py` report no problem, `check_stride_map.py` reports 0 problems (it reported 1 before), and `manual_expect.py` passes 97 of 97.

## Open items

1. Indirect evidence for unchanged citations. The shipped citation scripts leave many citations unresolved (see check 1 and 16). The 121 non-OK citations new since HEAD were each read. The 157 non-OK keys that are identical in the HEAD docs were not re-read one by one. They rely on the fact that `mpl/` and `prim/` are unchanged since the `620771c` run, in which they were read, and on the shim lines being re-read as described. A full reading of every citation in all three docs on the current code was not done.
2. The scripts shipped for this step mis-resolve bare `lib.rs`, spec line numbers and table-cell `:LINE`. The derived `check_citations_v3.py` and `check_fn_defs_v2.py` reduce the noise but do not remove it. They are scratch files and are not committed. The shipped scripts also scan this file, and they mis-resolve the line numbers quoted here in the same way, so their counts for this file are not meaningful.
3. TM-MPL-025 and target T27 are provisional. The threat model derives them by static reasoning; the docs say so, and no reproducer test exists yet. The score 3.78 depends on that threat rating (Medium, provisional) and on a coverage gap of 0.9 that is itself an estimate.
4. `spec/` is a local checkout (separate git repository at `e833453`, ignored by `.gitignore`); the spec revision floats on `master`. Spec line citations were checked only against that checkout.
5. C07's note about fields not constrained by `check_encryption_transition` was not compared with Dafny `Materials.dfy`, which is not in this repository.
6. No Verus proof was written or run. "Expected FAIL" and "expected VERIFY" labels in the docs are predictions from reading the code and tests.
7. Open code defects recorded in the docs for owner decision (merged section 7): BUG-01, 04, 05(a), 05(b), 06, 07(a/b), 08; T21 properties (g), (h), (i); the missing `create-time` and `hierarchy-version` read-path check (T02, G1); C++ `Keyring::adopt` has no null, type or ownership check (T25). None is changed by this step.
