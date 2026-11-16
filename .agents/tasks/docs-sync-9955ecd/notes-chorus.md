# Chorus review editions: sync at HEAD 9955ecd (first iteration)

Nothing was committed or pushed. No authentication or token error occurred. No code under `mpl/`, `prim/`, `esdk/` was touched. `review.json` did not exist, so this is the first iteration. `docs/bug-reports/*`, `docs/spec-security-analysis.md`, `docs/threat-model.md`, `docs/verification-targets*` and `docs/completeness-audit.md` were only read.

Files edited (uncommitted): `docs/chorus/MPL-Threat-Model.md` (rewritten), `docs/chorus/MPL-Bug-Reports.md` (edited), and both `.docx` files (regenerated).

## Recount from docs/threat-model.md (Appendix: Threat Risk Matrix, 26 rows)

| Dimension | Counts |
|---|---|
| Risk | High 3 (TM-MPL-005, 009, 010), Medium 14 (002, 004, 006, 007, 008, 011, 012, 013, 014, 017, 018, 019, 024, 025), Low 9 (001, 003, 015, 016, 020, 021, 022, 023, 026) |
| Severity | Critical 5, High 9, Medium 10, Low 2 |
| Likelihood | Low 19, Medium 7, High 0 |
| STRIDE (source section 7) | Spoofing 3, Tampering 5, Repudiation 1, Information Disclosure 3, Denial of Service 4, Elevation of Privilege 10 |
| Severity x Likelihood grid | Critical/Low 4, Critical/Medium 1, High/Low 7, High/Medium 2, Medium/Low 7, Medium/Medium 3, Low/Low 1, Low/Medium 1 |

The first edition said 1 High, 15 Medium, 7 Low for 23 threats. The change is TM-MPL-009 and 010 (Medium to High), TM-MPL-015 (Medium to Low), plus new 024 (Medium), 025 (Medium), 026 (Low).

## What changed in each Chorus file

MPL-Threat-Model.md: new title block (code reviewed main 620771c / branch HEAD 9955ecd, earlier a1e23d7; date 2026-11-15; threat IDs 001..026). A "changes since the previous edition" list. Executive summary recounted, risk grid and risk totals. System overview (adds SharedCmm/SharedKeyring `send()` checks, shim, test servers, TB1..TB9), assets A1..A14, actors TA1..TA9. Register of 26 threats with ratings identical to the source (checked by script). Per-threat detail for all 26 including second-pass residuals (TM-002 Discovery on encrypt, TM-003 message-driven supplier, TM-005 rollback, TM-010 same-name and future-time, TM-015 cache residency, TM-018 liveness, TM-025 new, TM-024 adopt, TM-026 new). CVE-2026-6550 / GHSA-v638-38fc-rhfv written as verified, scoped to the AWS Encryption SDK for Python caching CMM, not applicable (under TM-008 and in the references). Section 7 cross-reference threat -> target (with scores) -> bug, using T27, refreshed T21/T25/T26, retired T08/C06 absent, bug status open 01/04/05a/05b/06/07a/b/08, fixed 02/03/09. BUG-06 shown as High in the bug summary table and in the explanatory paragraph. Residual risks, recommendations, open questions and editor's notes rewritten. New Appendix B with the rating rule and per-threat rating history (a1e23d7, 620771c, current).

MPL-Bug-Reports.md: header table (code reviewed, date, how produced), an "Update at HEAD 9955ecd" paragraph in the introduction, a new "Cross-reference to the threat model and verification targets" table (severity, status, threats with risk, targets with score), updated Related IDs rows for BUG-01, 04, 05, 06, 07, 08, current-line notes (BUG-04 spec lines re-read, BUG-05 `default_cmm.rs:123`, BUG-07 `algorithm_suite.rs:505`, `raw_aes_keyring.rs:471`, `branch_key_wrap.rs:275`, BUG-08 test no longer exists), and Appendix C notes. Other bugs' severity, finding, status, evidence and confidence are unchanged.

BUG-06 shown as High in MPL-Bug-Reports.md: summary table (severity column "High (raised from Low on the owner's decision)"), priority label "1 – High", the cross-reference table, the agenda row (still order 1), the BUG-06 attribute table (Severity line), the Severity rationale, a new "Severity decision" paragraph in the BUG-06 Status section (replaces the old "Severity review suggested ... stays Low" paragraph; states the shared cache, NUL-containing partition id / logical key store name / branch key id, caller-supplied value or supplier, end-to-end result on main, non-injective preimage, TM-MPL-009/010 High, preconditions not met by a default configuration, "Severity raised Low -> High on the owner's decision after the main re-check"), the "Realistic exploitability: low" bullet (clarified that it is likelihood of preconditions, not severity), the "How to read" bullet, the introduction and Appendix C. No "rated Low while its threats are High" mismatch note remains (grep `Severity review suggested`, `stays Low`, `revisit`, `1 – Medium`: no match).

## What was run

| Command | Result |
|---|---|
| `python3 check_chorus_consistency.py` (new) | problems: 0. Register (26 rows) and Appendix B (26 rows) equal the source matrix (STRIDE, severity, likelihood, risk). Counts 3/14/9, 5/9/10/2, 19/7/0 present and equal to the recount. STRIDE counts equal source section 7. Every `Txx (score)` equals `docs/verification-targets.md` section 1. Every `TM-MPL-nnn (Rating)` equals the matrix. BUG-06 summary row, attribute row and agenda order checked; no BUG-06 row shows Low. Bug severities equal the README (BUG-06 High). No HTML tag, mermaid, emoji or footnote. One informational note: Appendix A note 8 contains the word "unverified" (it says the CVE was earlier unverified and is now verified) |
| threat -> target comparison (inline script) | The target IDs in all 26 rows of the section 7 table equal `01-threat-driven.md` section 6 (T08 excluded); 26/26, 0 differences |
| `python3 check_citations_chorus.py` (copy of `check_citations_v3.py`, DOCS = the two Chorus docs) | No RANGE, BADFILE or NOFILE row for the Threat Model after fixing 8 bare `:NNN` citations that the checker resolved to the wrong file (each now names its file). The remaining non-OK rows are the same heuristic noise class as in `docs/threat-model.md` (identifier not within +-4 lines, ALT file); the cited line was printed for each and read. Bug-report BADFILE rows (4) are the `a1e23d7` historical locations that the document labels as such (`keystore/` was renamed) |
| `python3 check_fn_defs_chorus.py` (copy of `check_fn_defs_v2.py`) | 15 DEF-MISMATCH rows, all prose words or call sites (`check`, `unwrap`, `version_key`, `decrypt_branch_key`, `allows_for_encrypt`), none is a wrong line. `SymmetricSigningKey :505` is the `derive` on `:505` for `PlaintextDataKey`, and the struct is at `:656` with its derive at `:655`, as in the source |
| `sed -n` on `cmc/local.rs:69,131,166`, `hierarchical_keyring.rs:567,575,584,931,955`, `storm_tracking.rs:115,249,255,310,313,322,606`, `esdk/src/config.rs:35,42`, `raw_aes_keyring.rs:471`, `branch_key_wrap.rs:275`, `algorithm_suite.rs:505`, `default_cmm.rs:123` | Each line holds the construct the text names |
| `sed -n '168p;204p;669p' spec/framework/branch-key-store.md` | 168 and 204: "Any MRK ARN discovered will be changed to this region before use"; 669: the MRDiscovery `KeyId` sentence |
| `/opt/homebrew/bin/pandoc docs/chorus/MPL-Threat-Model.md -o docs/chorus/MPL-Threat-Model.docx` | exit 0; 47,701 bytes; `pandoc ...docx -t plain \| head` starts with "MPL Threat Model: AWS Cryptographic Material Providers Library (native Rust)"; 1856 plain lines; TM-MPL-026 appears |
| `/opt/homebrew/bin/pandoc docs/chorus/MPL-Bug-Reports.md -o docs/chorus/MPL-Bug-Reports.docx` | exit 0; 44,481 bytes; head starts with "MPL Native Rust: Bug Reports for Engineering Discussion"; 1478 plain lines; BUG-06 High text present |
| `git diff --quiet HEAD -- mpl prim esdk` | succeeds (no code change) |
| `git status --short` | only `docs/**` modified and `.agents/` untracked |
