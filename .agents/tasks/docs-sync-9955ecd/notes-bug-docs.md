# Bug reports, RECHECK addendum and spec analysis: sync at HEAD 9955ecd

Nothing was committed or pushed. No authentication or token error occurred. No fetch was needed (`620771c`, `5f2dc72` and `a1e23d7` are available locally; `5f2dc72` equals `origin/main` and is an ancestor of HEAD).

Files edited (uncommitted): `docs/bug-reports/BUG-01..BUG-09 *.md`, `docs/bug-reports/README.md`, `docs/bug-reports/RECHECK-main-620771c.md`, `docs/spec-security-analysis.md`. Not edited: `docs/threat-model.md`, `docs/completeness-audit.md`, `docs/verification-targets*`, any code.

## What was run, with results

| Command or script | Result |
|---|---|
| `git diff --stat 620771c 5f2dc72 -- mpl prim` | empty (exit 0) |
| `git diff --stat 620771c 5f2dc72` | 8 files, all `esdk/shims/aws-esdk-cpp/` (165 insertions, 37 deletions); commits `41f1d51` (#188), `5f2dc72` (#189) |
| `git diff --stat 620771c HEAD -- mpl prim` | empty |
| `git diff --quiet HEAD -- mpl prim esdk` | succeeds (no code change) |
| `git diff HEAD -U0 -- docs/bug-reports/RECHECK-main-620771c.md` | one hunk `@@ -160,0 +161,N @@`: only added lines at the end, 0 removed lines |
| `check_citations_bugdocs.py` (copy of `check_citations_v3.py` with DOCS = `docs/bug-reports/*.md` + spec analysis) | before 411 non-OK heuristic rows, after 416. The 5 new rows are false positives from the checker's identifier heuristic, each verified by reading the line (see below). No new RANGE, BADFILE or NOFILE row |
| `check_fn_defs_bugdocs.py` (copy of `check_fn_defs_v2.py`, same DOCS) | before 41 DEF-MISMATCH, after 41. All 41 are prose words or call sites (for example `check`, `unwrap`, `get_active_branch_key`), none is a wrong definition line |
| `check_bug_xrefs.py` (new) | 26 risk rows read from `docs/threat-model.md`; every `TM-MPL-NNN (Rating)` in `docs/bug-reports/*.md` and `docs/spec-security-analysis.md` equals the appendix rating; every TM id exists; every target id exists in `docs/verification-targets.md`. Problems: 0 |
| `grep -n '00 14'` in `docs/spec-security-analysis.md`, `docs/threat-model.md`, `docs/bug-reports/*.md` | no match. G2 is fixed: the FORBID default suite is written as `03 78` (code) against `00 78` (spec) in the spec analysis |

The scripts are in this directory. `show.py` and `ends.py` print source lines for manual checks.

## Citations verified by reading the line (current code, HEAD 9955ecd)

All current-code `file:line` citations in BUG-01..09, the README and the RECHECK snapshot were printed and read. Verified, no drift:

- `hierarchical_keyring.rs`: 535, 547, 596, 626, 665, 684, 702, 767, 798, 867, 879, 894, 901, 908, 927, 934, 945, 958, 987-995, code blocks 698-703, 879-881, 931-936.
- `storm_tracking.rs`: 333, 606-626, 680; code blocks 332-334, 675-681.
- `algorithm_suite.rs`: 505, 547-562. `encryption_materials.rs`: 60, 358, 365. `decryption_materials.rs`: 56, 295, 303.
- `structures/encryption_context.rs`: 16, 91, 145, 198-211, 230. `kms_ops.rs`: 88, 96-103, 144-158, 162, 170-172, 179. `branch_key_store.rs`: 112-122, 396-405, 641-644, 663, 801, 839, 874, 1114-1121, 1141-1198.
- `default_cmm.rs`: 85, 123, 137-138. `prim/src/ecdsa.rs`: 373, 375, 380, 386, 391-396. `branch_key_wrap.rs`: 236. `cache_entry_identifier.rs`: 35-66 (code block 42-60).
- `prim/src/lib.rs`: 175, 183-197, 206, 215, 228-229. `mrk_match.rs`: 52. `key_store/mod.rs`: 36. `key_store/encryption_context.rs`: 36, 40, 58-62, 86-104. `attributes.rs`: 11-17, 24.
- The 5 checker rows that are new in "after" are `BUG-07` `raw_aes_keyring.rs:471`, `branch_key_wrap.rs:275` (both `vec![0u8; encrypted_key.len()]`), `BUG-05` `default_cmm.rs:123` (resolved by the checker to a different file), and two RECHECK rows that quote `prim/src/lib.rs:187-192` (the checker resolves them to `branch_key_wrap.rs`).
- Spec analysis: the MUST index table has bare `:N` evidence; every range was printed (first and last line) for `hierarchical_keyring.rs`, `raw_aes_keyring.rs`, `branch_key_wrap.rs`, `default_cmm.rs`, `kms_config.rs`, `branch_key_store.rs`, `kms_ops.rs`, `record.rs`, `local.rs`, `storm_tracking.rs`, `commitment_policy.rs`, `materials_checks.rs`, `mrk_match.rs`. No wrong citation found, so none was changed there.

## Line drift found and fixed

Historical citations (marked `a1e23d7` in the reports) were kept, and the current equivalent was added in brackets:

| Report | Old (a1e23d7) | Current |
|---|---|---|
| BUG-04 | `branch_key_store.rs:763-771` (`region_from_kms_config`) | default clients built `branch_key_store.rs:396-405`; `region_from_kms_config` `:1114`, MrDiscovery arm `:1118` |
| BUG-04 | `KeystoreConfig::kms_client`, `config.rs:28` | `DynamoDbKeyStoreBuilder::kms_client`, `branch_key_store.rs:322` (`KeystoreConfig` no longer exists) |
| BUG-05 (Q2) | `default_cmm.rs:100` | `default_cmm.rs:123` |
| BUG-07 | `raw_aes_keyring.rs:309`, `branch_key_wrap.rs:267` | `raw_aes_keyring.rs:471`, `branch_key_wrap.rs:275` |
| BUG-07 | `PlaintextDataKey::zeroize()` at `algorithm_suite.rs:434` | removed; `PlaintextDataKey` derives `Zeroize, ZeroizeOnDrop` at `algorithm_suite.rs:505` (tracked by T26) |
| BUG-08 | test `distinct_non_utf8_custom_ec_keys_do_not_collapse`, `test_keystore_encryption_context.rs:234` | test no longer exists (removed in `e9bde48`; custom EC is `BTreeMap<String, String>`); file is `test_key_store_encryption_context.rs` |
| RECHECK addendum | BUG-07 `Err` returns `prim/src/lib.rs:187-192` | `:187-194` (key `:187`, nonce `:188-189`, seal `:192-194`); code unchanged |

BUG-04 spec lines 168, 204, 669 were not re-checked in the snapshot. They were read in the local spec (`spec/framework/branch-key-store.md`): 168 and 204 are "Any MRK ARN discovered will be changed to this region before use", 669 is the MRDiscovery `KeyId` sentence. Recorded in BUG-04 and in the addendum.

## BUG-06 severity

Changed Low -> High in `BUG-06-cache-identifier-not-injective-with-nul.md` (Severity line, new "Severity decision" paragraph replacing the old "Severity review suggested" paragraph, one clarifying sentence in the Impact bullet "Realistic exploitability: low") and in the README (table cell, intro line, "How to read" bullet). The README priority label for BUG-06 changed from "1 – Medium" to "1 – High"; the priority order is unchanged and BUG-06 stays at 1. `grep -n -i low docs/bug-reports/BUG-06*.md` shows no remaining severity statement of Low (the matches are the words "Low" in the Severity line's "Low -> High", the TM-MPL-003 rating, and "low" in "Realistic exploitability"). The RECHECK snapshot text never stated the BUG-06 severity, so no snapshot text was touched; the addendum states the decision. No "rates Low while TM-MPL-009/010 are High" note exists in any of these files.

The "Realistic exploitability: low" bullet was kept (technical content). A sentence now says it describes how likely the preconditions are and is not the severity, and that the threat model rates the likelihood of TM-MPL-009 and TM-MPL-010 Medium.

## Spec analysis (docs/spec-security-analysis.md)

- G1: added a U row to the MUST index after the "Branch Key Materials From Authenticated Encryption Context" row, citing T02. Real spec lines: "A branch key record MUST include" `:677`, `create-time` `:690`, `hierarchy-version` `:692`; "response MUST contain" `:530`, `:552`, `:573`; "If the record does not contain the defined fields, this operation MUST fail" `:531`, `:553`, `:574` (the task text had `:530/:552/:573`, `:688-691`; the checked lines are as stated, consistent with `01-threat-driven.md` section 5 C3). Code: `record_from_ddb_item` `branch_key_store.rs:1141-1198` checks only `enc` and attribute types; `record.rs:95`; `kms_ops.rs:172`; `ATTR_CREATE_TIME` and `ATTR_HIERARCHY_VERSION` used only on write paths.
- G2: confirmed already fixed (no `00 14` in the file).
- Spec revision: bullet added. Spec `master` `94c2bfe` (2026-11-12). In the clone `.agents/tasks/pipeline-rerun-620771c/spec-pinned/` (HEAD `877edcc`), `git diff 877edcc 94c2bfe -- framework` is empty (only `client-apis/decrypt.md` changed), and `diff -rq spec/framework` against the clone reports only `transitive-requirements.md`. So the 13 MPL framework specs are unchanged.
- Pointer to `docs/completeness-audit.md` (540 units examined, 429 mapped) added to the header block.
- The file never stated a BUG-06 severity, so there was nothing to align.

## Problems found outside this step's scope (not edited)

1. `docs/completeness-audit.md` section 3c ("025 | none (known item)") and the 3b row for BUG-05(b) ("TM-MPL-025 target is the known item") predate the new target T27 (TM-MPL-025, provisional). Section 7 does not update them. The bug reports now name T27 for TM-MPL-025.
2. `docs/completeness-audit.md` section 7, row "BUG-06 severity": says the bug report "is edited in a separate step". That step is now done, so the phrase is stale. Its "Done criteria" bullet (`git diff --quiet HEAD -- ... docs/bug-reports`) no longer holds by design.
3. No other error found in the threat model, the targets documents or the audit. The bug to threat mapping in `docs/threat-model.md` lists only TM-MPL-013 for BUG-03, TM-MPL-018 and 023 for BUG-01 and TM-MPL-015 or 023 for BUG-07. The reports and README also list TM-MPL-017, TM-MPL-022 and TM-MPL-011 because the targets (T15, T06, T07) reference them; the README says so.
