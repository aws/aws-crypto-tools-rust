# Verification evidence — pipeline re-run for main 620771c

Iteration: **1** (no `review.json` existed when this pass started, so the mechanical checks were run).
Repo: `esdk-native-mpl`, branch `MPL-Verus`, HEAD `eb1ec23`. Docs only; nothing committed or pushed. `docs/chorus/` was not read, edited or checked (user decision: Chorus update skipped).

Documents checked: `docs/spec-security-analysis.md`, `docs/threat-model.md`, `docs/verification-targets.md`, `docs/verification-targets/01-threat-driven.md`, `02-capability-driven.md`, `04-validation.md`.

Helper scripts (kept for reproducibility, under `.agents/` only):
- `check_citations.py`: extracts every `file.rs:N[-M]` and bare `:N` continuation, resolves the file, checks the range, and checks that an identifier written just before the citation occurs within ±4 lines. Falls back to the other tracked files when the context file is ambiguous.
- `check_fn_defs.py`: name-anchored pass. For `name … :N` where `name` is a defined fn/struct/enum/trait/const, checks a definition sits within ±3 lines.
- `check_scores.py`: parses every YAML block and the ranked/gap tables, recomputes the scores, and cross-checks the documents.

## (a) Threat IDs — PASS

- `grep -c "TM-MPL-0NN" docs/threat-model.md` for 001..024: every ID present (3–11 hits each). §7 STRIDE tables list all 24 (S 3, T 5, R 1, I 3, D 3, E 9). Appendix risk matrix has 24 rows.
- `Retired: **none**` (line 48). No ID deleted. The only new ID is TM-MPL-024, contiguous after 023; `TM-MPL-025`..`030` have 0 hits.

## (b) file:line citations — PASS after 7 fixes

`check_citations.py` found 1,304 citation instances. They were triaged as follows:
- 510 OK: identifier matched at the line.
- 213 ALT: matched in another tracked file. These are cases where the doc names the file in another column or the basename is ambiguous (`lib.rs`, `encryption_context.rs`).
- 319 MISS and 183 NOID: the cited line was printed with `sed -n` and read by hand (a transient 499-row listing, all read, then deleted).
- 44 NOFILE and 35 RANGE: the resolver picked the wrong file. Each was re-checked against the intended file.

`check_fn_defs.py`: 284 def-OK, 68 mismatches. All 68 were inspected. They are call sites cited on purpose (e.g. `check_decryption_transition` at `keyring/fluent_builders.rs:163`) or generic words (`check`, `call`, `handle`), so they are not errors.

Genuine errors found and fixed. None changes a threat, target, score or conclusion:

| Doc | Was | Now | Evidence (`sed -n`) |
|---|---|---|---|
| spec-security-analysis.md:18 | `mpl/src/lib.rs:34-44` | `:34-43` | file has 43 lines; `__test_internals` block is 34-43 |
| spec-security-analysis.md:105 | `cmc/default.rs:98-131` | `:98-130` | file has 130 lines; `impl Cmc for Builtin<DefaultCmc>` 98-130 |
| threat-model.md:24 (TM-MPL-010 delta) and :314 | `CachedMaterials::BranchKey` `:701`, `:944` | `:700`, `:943` | 700/943 = `.materials(CachedMaterials::BranchKey(..))`; 701/944 = `.creation_time(now)` |
| threat-model.md:274 (TM-MPL-002) | pinned arms `kms_ops.rs:95-96` | `:94-95` | 94 `KmsKeyArn`, 95 `KmsMrKeyArn`, 96 `Discovery` |
| threat-model.md:377 (TM-MPL-023) | 60-byte guard `branch_key_wrap.rs:240` | `:236` | 236 `if ciphertext.len() < FIXED_OVERHEAD_LEN`; 240 is the message (already flagged in 01 §5 C1) |
| verification-targets.md §2 T26; 01 T26 | raw-AES decrypt buffer `:472`; `wrap_data_key` output Vec `:163` | `:471`; `:162` (01 keeps the `aes_encrypt` call at `:163`) | 471 `let mut plaintext_dk = vec![0u8; ..]`; 472 `aes_decrypt(` call; 162 `let mut ciphertext = Vec::new()` |
| 01 T20 coverage_evidence | provider-info negative tests `:619-:746` | `:619`, `:658`, `:696` | 732/746 are build-time key-length tests, not provider-info |

Follow-on edits: 01 §5 C1 is marked resolved. 01 §5 C2 now records that `branch_key_materials.rs:205` and `beacon_key_materials.rs:221-235` were re-checked. 04-validation gained a "Verification pass with a shell" section. Check 14 now records the git result, and its Known-limitations bullet was updated.

Spot facts re-confirmed: no `\bunsafe\b` in `mpl/src` or `prim/src` (grep exit 1; only the lint name `unsafe_op_in_unsafe_fn` at `prim/src/lib.rs:33`). The only `//=` in mpl/prim src+tests is `mpl/src/cmc/entry.rs:201-203`. The old loop exists at `a1e23d7:mpl/src/structures/algorithm_suite.rs:439` (`git show`). Shim anchors `esdk/shims/aws-esdk-cpp/src/lib.rs:167, 715, 717-719, 720, 728, 1564-1565, 1655, 2054-2057` and shim `tests.rs:715, 733, 746, 791` match. Bug statuses in the docs match `docs/bug-reports/RECHECK-main-620771c.md` (open 01, 04, 05a, 05b, 06, 07a/b, 08; fixed 02, 03, 09).

## (c) Scores — PASS

`check_scores.py` parsed 26 YAML blocks in 01, 8 in 02 and 12 in the merged doc. It recomputed S×G×F×B for the 32 active targets (2-dp, half-up). Every value matched in each of these places:
- `priority_score`, the top-level `coverage_gap`, and the `product` string in 01/02
- merged §2 YAML (factors, score, `rank`)
- merged §1 table (score; rank order = score ↓, severity ↓, T before C, ID)
- 01 §1 and 02 §1 tables
- merged §3 gap table (32 rows)

Result: `PROBLEMS: none`. Values: T01 8.96, T02 6.72, C01 6.72, C02 6.40, C03 5.60, T03 5.12, C07 5.04, T04 4.48, T13 4.41, T05 4.32, T06 4.20, T07 3.84, T14 3.78, T26 3.20, T10/T11/T12 2.88, C04 2.80, T09 2.56, C05 2.40, T16 2.24, T21 1.96, T15/T17/T18/T19 1.92, T20 1.68, T22 1.60, T25 1.44, T23 1.26, T24 1.20, C08 0.96. These match 04-validation check 5.

Severity and Feasibility of each threat-driven target were compared with the primary threat's appendix rating (Critical/High/Medium/Low → 4/3/2/1; Likelihood Low/Medium → 0.4/0.7). All 25 matched, including the changed ratings: T13/T14 F 0.7 (009/010 Medium), T26 S 2 (015 Medium), T25 S 3 / F 0.4 (024 High/Low).

## (d) Target IDs — PASS

- Active: T01–T07, T09–T26 (25) and C01–C05, C07, C08 (7) = 32. Retired: T08, C06.
- Each retired target has a `status: Retired` YAML block with a `reason`, `former_target` and `successor` (T08 → T26; C06 → none). They also appear as struck-through rows in the merged §1 and 01 §1 tables.
- New IDs T25, T26, C07, C08 are present in 01/02, merged §1 and §3, and as YAML in the merged §2.
- No active YAML block cites retired code. A regex scan of active blocks for `write_volatile`, `PlaintextDataKey::zeroize`, `from_raw`, `HierarchicalKeyring::new`, `RawAesKeyring::new`, `resolve_keystore_arn`, `keystore/`, `BranchKeyStore::`, `EncryptionContext::(de)serialize` and "integer division" found nothing. The only `unsafe` hits are the agent name `verus-unsafe-ffi-safety` and the shim derefs of T25. T26 mentions T08 only as "replaces retired T08". No threat is retired, so no Retired threat can be cited.

## (e) Code untouched — PASS

- `git diff --quiet HEAD -- mpl prim esdk` → exit 0 (run before and after the edits).
- `git diff --quiet 620771c HEAD -- mpl prim esdk` → exit 0.
- `git status --short`: only the six in-scope docs (M), `.agents/tasks/pipeline-rerun-620771c/` (untracked) and a pre-existing `docs/.DS_Store`. Nothing under `docs/chorus/` changed.
- Note: the local `origin/main` ref is now `5f2dc72`, two commits past `620771c` (#188, #189). Those commits touch only `esdk/shims/aws-esdk-cpp/` build files and 8 lines of the shim `src/lib.rs`; `mpl/` and `prim/` are unchanged. The analysis baseline stays `620771c`, which HEAD's code equals. T25's shim line numbers are valid on HEAD/620771c and may shift once those commits are merged.
