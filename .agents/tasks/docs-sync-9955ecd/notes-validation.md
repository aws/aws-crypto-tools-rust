# Notes: validation step for docs/verification-targets/04-validation.md (HEAD 9955ecd)

Not committed. Working directory: `/Users/mahnush/Desktop/ESDK-Rust-Verus/MPL/esdk-native-mpl`.

## Scripts run (all in this directory)

| Script | Origin | Result |
|---|---|---|
| `check_scores.py` | copied from pipeline-rerun-620771c | `PROBLEMS: none` (yaml blocks 01=27, 02=8, merged=13; 33 active, 2 retired; merged section 1 has 35 rows, section 3 has 33 rows). Output in `final-scores.txt`. |
| `check_citations.py` | copied | 794 in-scope citation tokens: 328 OK, 139 NOID, 134 ALT, 97 MISS, 76 RANGE, 20 NOFILE. Not clean: the script resolves bare `lib.rs` to `mpl/src/lib.rs`, spec line numbers to code files, and `:LINE` in table cells to no file. Output in `final-citations.txt`. |
| `check_fn_defs.py` | copied | 66 DEF-MISMATCH lines in the three in-scope docs (113 over all six docs). Output in `final-fndefs.txt`. |
| `check_citations_v2.py`, `check_citations_v3.py`, `check_fn_defs_v2.py` | derived by this step | v3: keeps every candidate file for a basename, treats `*.md:N` as an external spec citation, maps `module::` to its file, and takes `DOCROOT` so the HEAD version of the docs can be run for comparison. 338 OK, 153 NOID, 126 ALT, 99 MISS, 43 RANGE, 10 NOFILE. |
| `manual_expect.py` | written by this step | 97 (file, line, regex) rows written by reading the doc sentence next to each unresolved citation. 97 pass, 0 fail. |
| `ctx.py`, `manual1.sh` | helpers | print the doc sentence next to the cited code lines |
| `check_threat_refs.py` | new | all TM refs exist; 26 threat-model IDs; 23 have an active 01 target; 019, 020, 026 are fully excluded rows |
| `check_ratings.py` | new | appendix Severity/Likelihood vs 01 section 6 (26 rows) and vs YAML severity/feasibility of 35 threat-driven blocks (26 in 01, 9 in merged): 0 mismatches |
| `check_stride_map.py` | new | 01 section 6 target column and merged section 4 STRIDE table vs YAML `threat_references` and appendix STRIDE letters. First run: 1 difference (TM-MPL-018 omitted T27). After the fix: 0 |
| `check_extras.py` | new | quick-win flags, merged section 5, agent totals, rank claims, relative order of the 01 and 02 ranked tables: 0 problems |
| `check_prose_scores.py` | new | 29 score mentions in prose (`T27 (3.78`): 0 wrong; 1 history line (T21 1.96, an old score) |
| `check_misc.py` | new | capability_reference, ID stability against HEAD, merged YAML count and origins: 0 problems |

## Triage of the citation scripts

1. HEAD version of the three docs exported to `/tmp/headdocs` and run with v3 (`head-citations-v3.txt`): 167 distinct non-OK keys. Working tree: 278. 121 keys are new. Each of the 121 was read against the code (cluster by cluster, with `sed -n`, `ctx.py` and `manual_expect.py`). All resolve to the cited construct; the non-OK status came from wrong-file resolution or from a cited identifier that is not on the exact line (for example a closing brace or the second line of a call).
2. `check_fn_defs_v2.py` on HEAD docs vs working tree: 40 vs 66 DEF-MISMATCH lines, 27 new keys. All 27 read: they are Debug impls cited against the type definition (T22), spec line numbers following a code word (`version :692`), `get_branch_key_version` call sites cited against the definition, and `on_decrypt` chain entries cited at call lines.
3. The 157 non-OK keys that are identical in the HEAD docs were not re-read one by one. Basis: `git diff --quiet 620771c HEAD -- mpl prim` is clean, the `esdk/` changes since 620771c are 8 files under `esdk/shims/aws-esdk-cpp/` (build files, `test-server`, and `src/lib.rs` with 8 changed lines around 1411 that shift everything after it). No doc cites a file other than `src/lib.rs` among them, and every shim `lib.rs` citation at line 1411 or later was read.
4. Spec citations (`branch-key-store.md:531/553/574/677/690/692`, `aws-kms-hierarchical-keyring.md:236-249`, `:242`, `storm-tracking-cryptographic-materials-cache.md:59/71/92/136-138`, `shim.md:180-204`) read in the local `spec/` checkout (a separate git repository at `e833453`; `spec/` is ignored by this repository's `.gitignore`).

## Defect found and fixed

- TM-MPL-018 mapping. T27's YAML `threat_references` cite TM-MPL-025 and TM-MPL-018 (01 and merged). 01 section 6 row TM-MPL-018 listed `T21, T06`; 01 section 4 row and merged section 6 bullet said `Partial (→ T21, T06)`. All three now name T27. Wording added to merged line 27 and 01 line 28 so the change lists describe it.

## Commands

```
git status --short; git log --oneline -1
python3 check_scores.py; python3 check_citations.py; python3 check_fn_defs.py
python3 check_citations_v3.py; DOCROOT=/tmp/headdocs python3 check_citations_v3.py; DOCROOT=/tmp/headdocs python3 check_fn_defs_v2.py
python3 manual_expect.py; python3 check_threat_refs.py; python3 check_ratings.py; python3 check_stride_map.py
python3 check_extras.py; python3 check_prose_scores.py; python3 check_misc.py
git diff --quiet HEAD -- mpl prim esdk           # exit 0
git diff --quiet 620771c HEAD -- mpl prim        # exit 0
git diff --stat 620771c HEAD -- mpl prim esdk    # esdk only: shim, test-server, Makefile, CMake
grep -rnw unsafe mpl/src prim/src                # 0 lines
git status --short -- docs/bug-reports docs/spec-security-analysis.md   # empty
```

No authentication, access or token error occurred.

## Addendum

- Check 1b: inline script, output `check_test_names.out`: 76 test-name citations exact, 1 two-number citation (01 line 1224) correct on both numbers.
- Output written: `docs/verification-targets/04-validation.md` rewritten (18 checks: 1, 1b, 2 to 14, 15 to 17). Three targets docs edited once (TM-MPL-018 rows now name T27; two change-list sentences).
- Format check on 04: no HTML outside code, no footnotes, no diagram blocks, even fences, no emoji.
