# Independent review: docs sync at HEAD 9955ecd

Verdict: APPROVED, after two small direct fixes in `docs/completeness-audit.md` (listed under "Direct fixes").
No authentication or access error occurred. Nothing was committed or pushed. I did not rerun the coder's build or test evidence; there is none for a docs-only change. I reran every check script and added independent checks (`/tmp/rv-added.py`, inline Python, `sed`, `git`).

## Per-check results

| # | Check | Result | Evidence |
|---|---|---|---|
| 1 | Citations | PASS | See below |
| 2 | Scores | PASS | See below |
| 3 | Work list and audit items | PASS | Table below |
| 4 | Headers and refresh sections match bodies | PASS | See below |
| 5 | Ratings, counts, IDs across documents | PASS | See below |
| 6 | Bug documents | PASS | See below |
| 6b | BUG-06 severity everywhere | PASS after fix | See below |
| 7 | Code clean, only expected paths changed | PASS | `git diff --quiet HEAD -- mpl prim esdk` exits 0; `git status --porcelain` lists only `docs/verification-targets*`, `docs/threat-model.md`, `docs/completeness-audit.md`, `docs/chorus/`, `docs/bug-reports/`, `docs/spec-security-analysis.md` and `?? .agents/tasks/docs-sync-9955ecd/`; no other untracked file (ignored: `spec/`, `target/`, `.DS_Store`, `__pycache__`) |
| 8 | No commit, no push | PASS | `git rev-parse --short HEAD` is `9955ecd`; `git reflog` top entry is the `9955ecd` commit; `origin/MPL-Verus..HEAD` shows only the two commits that were already local before this task |
| 9 | Format | PASS | See below |

### 1. Citations

- Ran `check_citations.py` and `check_fn_defs.py` over the six scanned docs (and `check_citations_bugdocs.py` for the bug documents and spec analysis). The scripts are heuristic: they report many MISS, ALT, NOID and DEF-MISMATCH rows that are wrong-file resolution or prose words (the coder's notes explain the classes). I therefore did not rely on the counts.
- Independent mechanical check: extracted every explicit `mpl|prim|esdk/...:LINE` citation in all of `docs/**/*.md` (350). Every one exists and is in range except 15 `mpl/src/keystore/...`, `test_keystore_...` and `attributes.rs` citations. All 15 are labelled `a1e23d7` history (module `keystore/` was renamed `key_store/`), unchanged from HEAD.
- Independent content check: extracted every citation on a line added in the bug reports, README, RECHECK, spec analysis and completeness audit (`/tmp/rv-added.py`, short names resolved to tracked files) and printed the cited source line. All current-code citations hold: `branch_key_store.rs:396-405`, `:322`, `:1114`, `:1118`, `:711`, `:1098`, `:1141-1198`; `default_cmm.rs:123`; `raw_aes_keyring.rs:471`; `branch_key_wrap.rs:275`; `algorithm_suite.rs:505`; `storm_tracking.rs:333`, `:680`; `prim/src/lib.rs:187-194` (key `:187`, nonce `:188-189`, seal `:192-194`); `record.rs:95`; `kms_ops.rs:172`; `encryption_context.rs:67`, `:77`. Citations to `a1e23d7` locations (`:763-771`, `config.rs:28`, `default_cmm.rs:100`, `algorithm_suite.rs:434`, `raw_aes_keyring.rs:309`, `branch_key_wrap.rs:267`, `test_keystore_...:234`) are each marked as `a1e23d7` history with the current location beside them.
- Spot checks with `sed -n` (more than 60 lines). T25: shim `lib.rs:715` (`require_handle`), `:720` (null check), `:728` (`unsafe { &*ptr }`), `:1570`, `:1571`, `:1661` (`as_ref()` on nullable handles), `:2059`, `:2062`, `:2065` (`into_keyring_handle`, `Box::into_raw`, `.cast()`); `EncryptionSDK.cpp:541-547` (`Keyring::adopt`, `from_raw` at `:546`); `EncryptionSDK.h:654-664`. `git diff 620771c HEAD` on the shim shows `ddb_client` gained 6 lines at `:1411`, which explains the move from `:1564-1565`, `:1655` (old values appear only as "was" history). T21: `storm_tracking.rs:239`, `:250-251`, `:264`, `:313` (`Wait { deadline: None }`), `:322-323`, `:333`, `:360`, `:378`, `:388`, `:610-624` (build checks), `:680`, `:724`, `:739-740`; tests `test_storm_tracking_cmc.rs:283`, `:388`, `:699`, `:761` (33 test fns, no `poison` in `mpl/tests`). T26: `cmc/local.rs:69`, `:131`, `:166`; `prim/src/ecdsa.rs:324-326`, `:373`, `:387` (`der.as_ref().to_vec()`), `:391-392` (error return). T02/G1: spec `branch-key-store.md` `:530/:531`, `:552/:553`, `:573/:574`, `:677`, `:690`, `:692` and `record_from_ddb_item` (`:1141-1198`, which reads only `enc`, with `ATTR_CREATE_TIME` and `ATTR_HIERARCHY_VERSION` used only on write paths: `grep` confirms). T14: `hierarchical_keyring.rs:989-994` (`unwrap_or(Duration::ZERO)`, so a future creation time counts as fresh). T27: `hierarchical_keyring.rs:734`, `:751`, `:764`, `:867`, `:879`, `:889`, `:901`, `:934`, `:947`; `test_keyring_memory.rs:100`, `:113`; `esdk/src/config.rs:35`, `:42`; `test_aws_kms_hierarchical_keyring.rs:1998`. Bug reports: `branch-key-store.md:168`, `:204`, `:669` read in the local spec; BUG-08 test removal confirmed with `git log -S` (`538dbd9`, `e9bde48`) and `test_key_store_encryption_context.rs:127`.
- Note on the task text: it gives the G1 spec lines as about `:530/:552/:573` and `:688-691`. The checked lines are `:531/:553/:574` for the MUST-fail sentences and `:677`, `:690`, `:692` for the record fields. The documents state the checked lines and say the audit was one line low. I agree with the documents.

### 2. Scores

`check_scores.py`: `PROBLEMS: none`; 27 + 8 + 13 YAML blocks; 33 active, 2 retired. Hand recomputation from the stated factors:

| Target | Factors (S x G x F x B) | Product | Factor sources |
|---|---|---|---|
| T21 | 2 x 0.8 x 0.7 x 2 | 2.24 | TM-MPL-018 Medium severity, Medium likelihood; gap 0.8 evidenced by tests that encode the regressed contract and no test for (g), (h), (i) |
| T25 | 3 x 0.6 x 0.4 x 2 | 1.44 | TM-MPL-024 High severity, Low likelihood |
| T26 | 2 x 1.0 x 0.4 x 4 | 3.20 | TM-MPL-015 Medium severity, Low likelihood |
| T27 | 2 x 0.9 x 0.7 x 3 | 3.78 | TM-MPL-025 Medium severity, Medium likelihood (provisional) |
| T02 | 4 x 0.6 x 0.7 x 4 | 6.72 | TM-MPL-005 Critical severity, Medium likelihood |

Ranked table order (score, then severity, then T before C, then ID) holds: T14 (sev 3) before T27 (sev 2) at 3.78; T16 before T21 at 2.24; T10/T11/T12 at 2.88; T15, T17, T18, T19 at 1.92. YAML ranks equal the table ranks. Quick wins (score > 6.0, effort <= 1 week): T02, C01, C02 in section 5 and in the `quick_win` flags (T01 at 8.96 needs 2 weeks). Coverage-gap table gaps equal the YAML (T21 0.8, T27 0.9). The STRIDE table sums to 26 threats (3, 5, 1, 3, 4, 10), 23 targeted, 3 excluded.

### 3. Work list and audit items

| Item | Status | Location |
|---|---|---|
| T25 refreshed (shim cites, adopt path, provable vs outside the proof) | Applied | `01-threat-driven.md:18`, T25 block (`:1333`, `:1348`); `verification-targets.md:15`, `:413` |
| T21 refreshed (g), (h), (i), gap 0.7 to 0.8 | Applied | `01-threat-driven.md:17`, `:34`, `:1004-1060`; `verification-targets.md:14`, `:96` row 23 |
| T26 refreshed (F4 `local.rs`, F5 `ecdsa.rs`) | Applied | `01-threat-driven.md:19`, `:707-733`; `verification-targets.md:16`, T26 YAML |
| New T27 for TM-MPL-025, standard formula, unconfirmed | Applied | `01-threat-driven.md:16`, `:96`; `verification-targets.md:13`, `:79`; YAML |
| G1 applied to T02, no new ID | Applied | `01-threat-driven.md:20`, `:88`, `:197-211`; `verification-targets.md:17`, `:145-153` |
| G4-1: range 001..026, TM-MPL-026 out of scope with reason | Applied | `verification-targets.md:4`, `:506`; `01-threat-driven.md:4`, `:1491`; `02-capability-driven.md` inputs |
| Wording notes T06, T14, T19, T22, T09, T01-T03 | Applied (as notes) | `01-threat-driven.md:21-26`; `verification-targets.md:18` |
| Capability-driven sibling decision with evidence | Applied (no sibling; R17) | `02-capability-driven.md` Refresh section and R17; I checked `storm_tracking.rs:613-622`, spec `:59`, `:71`, `:92`, `:136-138`, and 2 x 0.9 x 0.7 x 2 = 2.52 |
| IDs stable; T08 and C06 retired with reasons | Applied | `check_misc.py`: no ID removed, T27 added |
| Ranked table, YAML, quick wins, gap table, STRIDE, out-of-scope agree | Applied | `check_scores.py`, `check_extras.py`, `check_stride_map.py`: no problems |
| Refresh sections at top of the merged doc and 01 with arithmetic | Applied | `verification-targets.md:7-30`; `01-threat-driven.md:8-28` |
| 04-validation rewritten (same checks plus threat refs, file:line, scores by script) | Applied | 18 checks; the previous 15 rows plus 15, 16, 17 |
| `threat-model.md`: only the Impact table update, one-line audit note, replaced closing note | Applied | `git diff`: one reworded row and one reworded sentence (`:39`, `:353`), new "Resolution" table and closing note; the original table rows are kept; no rating, ID or citation changed |
| `completeness-audit.md` "Resolution status" | Applied | Section 7: G1 to T02, G2 to commit `9955ecd`, G4-1, BUG-06 aligned; findings unchanged (one bullet reworded, see fixes) |
| Bug reports: cross-references, drift fixes, Last cross-checked, README column | Applied | `git diff HEAD -U0 -- docs/bug-reports` read in full |
| RECHECK addendum | Applied | `@@ -160,0 +161,66 @@`: 66 added lines, 0 removed |
| `spec-security-analysis.md`: G1 U row, G2, spec revision, audit pointer | Applied | `git diff`: one header bullet, one spec-revision bullet, one MUST-index row; no other change |
| Chorus threat model regenerated, Chorus bug reports updated, both `.docx` | Applied | See checks 5 and 9 |

### 4. Header, summary and refresh claims against bodies

Compared each claimed change in the merged and 01 refresh tables, the 02 refresh table, `threat-model.md` "Resolution (HEAD 9955ecd)", `completeness-audit.md` section 7, the README note and "Last cross-checked" lines, the RECHECK addendum and the spec-analysis additions against the body and `git diff`. Every claim has the matching body text. Line numbers quoted in `completeness-audit.md` section 7 and in the `threat-model.md` Resolution table were each read (`01:20`, `:88`, `:197-199`, `:211`, `:228`, `:235`, `:241`, `:1491`, `:1557`, `:1559`; `verification-targets.md:4`, `:9`, `:13-18`, `:26`, `:67`, `:74`, `:79`, `:145`, `:151`, `:153`, `:435`, `:468`, `:482`, `:506`, `:529`) and are correct. The RECHECK addendum states `git diff --stat 620771c 5f2dc72 -- mpl prim` is empty; I ran it: empty, exit 0. The 8-file stat in the addendum equals my run of `git diff --stat 620771c 5f2dc72` (165 insertions, 37 deletions). `git log 620771c..5f2dc72` shows exactly #188 and #189; `5f2dc72` equals `origin/main` and is an ancestor of HEAD.

### 5. Ratings, counts and IDs

Recounted from the `docs/threat-model.md` appendix (26 rows): High 3 (005, 009, 010), Medium 14, Low 9; severity Critical 5, High 9, Medium 10, Low 2; likelihood Low 19, Medium 7; grid Critical/Low 4, Critical/Medium 1, High/Low 7, High/Medium 2, Medium/Low 7, Medium/Medium 3, Low/Low 1, Low/Medium 1. The Chorus threat model states the same counts and grid, and each of its 26 register rows equals the source (STRIDE, severity, likelihood, risk). Threat to target lists in the Chorus section 7 equal `01-threat-driven.md` section 6 for all 26 threats (my own comparison; the only difference is the retired T08 text in 01 for TM-MPL-015). Scores in the Chorus cross-reference equal the ranked table. Every `TM-MPL-nnn (Rating)` in the bug documents equals the appendix (`check_bug_xrefs.py`: 0 problems; also grep). All 26 threats are accounted for in the targets (23 with a target, 3 fully excluded). CVE-2026-6550 / GHSA-v638-38fc-rhfv is written as verified and scoped to the AWS Encryption SDK for Python caching CMM, not applicable. The Chorus threat model has the same `##` sections as HEAD plus one added "Appendix B" (rating history); I accept that.

### 6. Bug documents

`git diff HEAD -U0` over `BUG-01..09` read line by line: changes are Related IDs lines (threat IDs with current ratings, targets, T27, T21 (i)), a completeness-audit mapping line, a "Last cross-checked" line, line-drift notes (each keeps the `a1e23d7` value and adds the current one), BUG-04's spec-line re-read note, and the BUG-06 severity change. No Summary, Status, Evidence, Confidence or Severity line changed other than BUG-06. README: the Severity, Confidence, Spec conflict and Status columns equal HEAD for all rows except BUG-06's severity; the new columns are "Related threats (rating)" and "Related targets"; the discussion priority order is unchanged and the note explains it (label for BUG-06 changed from "1 – Medium" to "1 – High"). RECHECK: only added lines at the end (`@@ -160,0 +161,66 @@`, 0 removed), so everything above "Addendum (HEAD 9955ecd)" is byte-identical to HEAD; the BUG-06 text in the snapshot never stated a severity.

### 6b. BUG-06 severity

`grep -rn 'BUG-06' docs` plus `grep -n -i` for `Severity review`, `stays Low`, `rated Low`, `1 – Medium`, `severity mismatch`, `Low in the bug report`. Result: High in the BUG-06 report (Severity line and "Severity decision"), README (table cell, intro line, "How to read", priority label "1 – High"), RECHECK addendum, `threat-model.md` (`:39`, `:353`, closing note `:676`), `completeness-audit.md` section 7, the Chorus threat model (bug summary table, `:471`, `:536`, `:570`) and the Chorus bug reports (summary table, cross-reference table, agenda row, BUG-06 attribute table, severity rationale, "Severity decision", appendix C). The targets documents and `spec-security-analysis.md` never state a BUG-06 severity. The only "Low" mentions left are the explicit "raised Low -> High" records and the (now clarified) "Realistic exploitability: low" bullet, which says it is about precondition likelihood and not severity. No "Severity review suggested" or "rates BUG-06 Low while TM-MPL-009/010 are High" note remains. The rationale and preconditions are present and not overstated: shared cache required; NUL-containing partition id, logical key store name or branch key id via a caller-supplied value or a branch key supplier; end-to-end result on main (keyring B served key store A's branch key, key store B called 0 times; I checked these against the RECHECK snapshot lines 97-103); non-injective preimage with NUL (both collisions `true`, control `false`); TM-MPL-009/010 High; "not met by a default configuration"; "owner's decision after the main re-check". BUG-06 is discussion priority 1 in the README and both Chorus editions. No other bug's severity differs from HEAD (README diff and Chorus tables).

### 9. Format

For all 20 changed `.md` files: no HTML tags outside code, no Mermaid, no footnotes, no emoji, even number of code fences. Both `.docx` files exist (47,701 and 44,481 bytes), start with the document title in `pandoc X.docx -t plain`, and their plain text equals a fresh `pandoc` conversion of the current `.md` (checked with `cmp`).

## Direct fixes

1. `docs/completeness-audit.md` section 4 bullet (about line 147): "BUG-06 Low in the bug report vs TM-MPL-009/010 High: explained in the closing note..." still stated a current Low. Reworded to "BUG-06 was rated Low in the bug report when this audit ran, ... resolved, because the owner raised BUG-06 from Low to High after the main re-check (see section 7)".
2. `docs/completeness-audit.md` section 7, "BUG-06 severity" row: the "Where" cell said "the bug report itself is edited in a separate step", which is stale. Replaced with the actual locations (BUG-06 report "Severity decision", README, RECHECK addendum, both Chorus editions). Added one row for TM-MPL-025: the audit's "known item" is now applied as target T27 (3.78, provisional, no rating change).

After the fixes I reran `check_scores.py`, `check_chorus_consistency.py`, `check_bug_xrefs.py`, `check_ratings.py`, `check_stride_map.py`, `check_extras.py`, `check_misc.py`, `check_prose_scores.py` (all clean) and re-checked the code and status commands (check 7, 8). The Chorus files were not edited, so no `.docx` regeneration was needed.

## Remaining notes (not blockers)

- `04-validation.md` open item 1 is honest: 157 non-OK script keys identical to HEAD were not re-read by the author. I covered that gap with the explicit-citation range check over all docs, the new-line content check, and over 60 `sed` reads. `mpl/` and `prim/` are unchanged since the `620771c` run.
- `completeness-audit.md` sections 2, 3b, 3c and the "Done criteria" bullet keep their original wording (they record the audit as run). Section 7 now says what became of each.
- `docs/threat-model.md` still says "TM-MPL-001..024" in the second-pass method and rating-change lines (`:18`, `:24`). The task bars rating, ID and citation changes there, and those lines describe the second pass of the 24 earlier threats, so I left them.
