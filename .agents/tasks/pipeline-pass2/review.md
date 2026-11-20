# Independent review: pipeline pass 2, Stages 1 and 2 (documentation only)

Repo `esdk-native-mpl`, HEAD `851977d`. Reviewed `docs/spec-security-analysis.md` and `docs/threat-model.md`.
Outcome: **APPROVED after fixes.** Only the two documents were edited, plus this file. Nothing was committed or pushed.

## Checks

| # | Check | Result |
|---|---|---|
| 1 | `git diff --quiet HEAD -- mpl prim esdk` | Passes. No code changed |
| 2 | `git status --short` | Only `M docs/spec-security-analysis.md`, `M docs/threat-model.md`, `?? .agents/tasks/pipeline-pass2/` (scope, stage1-notes, stage2-notes, this review). No Chorus, bug-report, `verification-targets.md` or Stage 3 file touched |
| 3 | Every `file:line` citation in both documents | Done by script and by hand. About 500 citations in the threat model and about 635 in the spec analysis were extracted, resolved to files, and compared with the cited text. Each hit with no overlap, each range, and each shim, test-server and build-file citation was read in the file. **35 distinct slips fixed** (11 in the threat model, 24 in the spec analysis) (below) |
| 4 | Every rating change in the "Second pass" table has evidence | Pass. The table has 6 rows (025, 026, 018, 024, 009/010, 015), each with a reason and file:line evidence. 025 and 026 are new. The other four are "kept" |
| 5 | No rating changed without being recorded | Pass. I diffed severity, likelihood and the 620771c column of the appendix matrix against `HEAD:docs/threat-model.md`. Identical for TM-MPL-001..024 apart from formatting. The inline "Severity X, Likelihood Y → Z" strings in section 8 also match the matrix |
| 6 | TM-MPL-001..024 present, IDs stable | Pass. Section 7 and section 8 contain 001..026, none renumbered. Re-confirmed (11) plus Extended (13) cover all 24. Retired: none |
| 7 | Risk matrix arithmetic | Pass. Each of the 26 rows was re-derived from the rating rule table. Totals: High 3 (005, 009, 010), Medium 14 (002, 004, 006, 007, 008, 011, 012, 013, 014, 017, 018, 019, 024, 025), Low 9 (001, 003, 015, 016, 020, 021, 022, 023, 026). Section 10 (residual risks) agrees with the matrix |
| 8 | CVE-2026-6550 / GHSA-v638-38fc-rhfv wording | Pass. I fetched `api.github.com/advisories/GHSA-v638-38fc-rhfv`. It is "AWS Encryption SDK for Python: Key commitment policy bypass via shared key cache", medium, pip `aws-encryption-sdk`, fixed in 3.3.1 and 4.0.5, requiring a shared `CachingCryptoMaterialsManager`. The documents call it VERIFIED, scoped to the Python ESDK caching CMM, and not applicable here (no caching CMM in `mpl/src/cmm/`; the hierarchical keyring caches only branch keys). The Stage 1 line (spec doc, CVE context) says the same |
| 9 | "Second pass" sections and "Impact on verification targets" exist | Pass. Threat model: `## Second pass (HEAD 851977d): changes` and `## Impact on verification targets`. Spec analysis: `## Second pass (HEAD 851977d)` |
| 10 | BUG-06 Low vs TM-MPL-009/010 High line | Pass. It is the last line of the threat model |

## Citation fixes (documents only)

Threat model:
- F5 row `storm_tracking.rs:321` → `:320` (`unwrap_or(Duration::ZERO)`; 321 is blank).
- TM-018 finding 1 `:321-323` → `:322-323`.
- TM-025 evidence `:321-337` → `:320-337`.
- `branch_key_wrap.rs:255` → `:254` (`let _version`).
- `user_agent.rs:15-20` → `:15-19` (the file has 19 lines). The "Corrected" row that claimed `:15-19` was wrong and `:15-20` was right is reversed.
- `put_cache_entry` `:710-728` → `:710-727`.
- `hierarchical_keyring.rs:901-960` → `:901-959`.
- `mrk_match.rs:24-28` → `:24-27`.
- `prim/src/ecdsa.rs:282-296` → `:282-293`.
- `encrypted_data_key.rs:148-151` → `:147-152`.
- "Hierarchical default cache" `:567-573` → `:567-574`.
- Added a "Citation slips found in independent review" row to the Corrected table and updated the Summary "Corrected" row.

Spec analysis (Stage 1):
- `kms_config.rs` `validate` `:99` → `:98` in four places, and the C8 row that had "corrected" `:98` to `:99` (wrong) was rewritten. C8 now says four corrections, not five.
- `test_keyring_memory.rs:5` → `:4`.
- `hierarchical_keyring.rs:890-895` → `:889-894` (three places).
- `wire.rs:60-107` → `:60-113` (two places; the twelfth operation is at `:108-113`) and `:124-127` → `:124-126`.
- `user_agent.rs:15-20` → `:15-19` (two places).
- Ranges that ran past a closing brace: `test_storm_tracking_cmc.rs:388-405` → `:388-404`; `local.rs:115-123` → `:115-122`, `:280-301` → `:280-300`, `:166-181` → `:166-182` (it ended one short); `storm_tracking.rs:264-345` → `:264-344`, `:772-775` → `:772-774`; `cmc/mod.rs:111-114` → `:111-113`; `cmc/default.rs:127-130` → `:127-129`; `raw_aes_keyring.rs:191-221` → `:191-219`; `materials_checks.rs:72-114` → `:72-108`, `:157-187` → `:157-186`; `commitment_policy.rs:43-86` → `:43-87`; `kms_config.rs:61-84` → `:61-79`; `kms_ops.rs:144-158` → `:144-157`, `:162-210` → `:162-209`; `hierarchical_keyring.rs:989-996` → `:989-995`; `ecdsa.rs:282-296` → `:282-293`; shim `lib.rs:1057-1073` → `:1057-1071`.
- Added row C10 listing these, and updated the header sentence that counted the first-pass fixes.

## Limits of this review

- Citations are checked for file, line content and function span. Whether a prose claim is true beyond what its cited lines show (for example the static-reasoning findings in TM-018 and TM-025) was not executed. Both documents label those "static reasoning".
- Some spec-analysis ranges deliberately span several functions (`materials_checks.rs:157-186`, `commitment_policy.rs:43-87`, `Drop` plus `ZeroizeOnDrop` impl pairs). I left those.
- The diffs of `41f1d51` and `5f2dc72` were read here for `src/lib.rs` (`git diff 620771c 851977d`: 6 lines added in `ddb_client`, one changed), which matches the documents' claim.
- No tests or builds were run (documentation-only change).
