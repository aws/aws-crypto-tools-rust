# mpl- rename of the MPL documents (branch MPL-Verus, base HEAD bd24f61)

Nothing is committed or pushed. Renames were done with `git mv` (staged); all content edits are unstaged working-tree changes. The orchestrator commits.

Files in this directory:
- `verify.sh`, `verify-output.txt`: the scripted verification and its saved output (re-run with `./verify.sh > verify-output.txt 2>&1`).
- `rewrite_refs.py`: the path rewriter used for the reference updates. `check_links.py`, `check_renames.py`: helpers called by `verify.sh`.
- `rewrite-counts-repo.txt`, `rewrite-counts-scripts.txt`: per-file replacement counts.

## Rename map (19 files, `git mv`)

| Old | New |
|---|---|
| docs/threat-model.md | docs/mpl-threat-model.md |
| docs/spec-security-analysis.md | docs/mpl-spec-security-analysis.md |
| docs/verification-targets.md | docs/mpl-verification-targets.md |
| docs/verification-targets/{01-threat-driven,02-capability-driven,04-validation}.md | docs/mpl-verification-targets/ (same names) |
| docs/completeness-audit.md | docs/mpl-completeness-audit.md |
| docs/bug-reports/{BUG-01..BUG-10 *.md, README.md, RECHECK-main-620771c.md} (12 files) | docs/mpl-bug-reports/ (same names) |

Not renamed: docs/chorus/ (already `MPL-*`), verus-proofs/ and its files, anything under .agents/tasks/.
`ls -R docs` before the rename showed no other file than the ones listed, so nothing was added to the list.

## References updated (replacements of path/link text)

| Area | Count |
|---|---|
| docs/ top-level (mpl-threat-model, mpl-completeness-audit, mpl-spec-security-analysis, mpl-verification-targets.md) | 89 (incl. 40 bare relative names such as `threat-model.md:473`, `verification-targets.md:18`) |
| docs/mpl-bug-reports/ (incl. README, RECHECK; GitHub `blob/MPL-Verus/docs/...` URLs are in chorus) | 48 |
| docs/mpl-verification-targets/ | 34 |
| docs/chorus/MPL-Threat-Model.md and MPL-Bug-Reports.md (incl. `blob/MPL-Verus/docs/bug-reports/...` and `/tree/MPL-Verus/docs/bug-reports` URLs) | 71 |
| verus-proofs/README.md, README-t03-t05.md (`docs/verification-targets*.md` -> `docs/mpl-verification-targets*.md`) | 2 |
| .kiro/agents/verification-recommender.md (both copies) | 2 |
| Total in documents and agents | 246 |
| Checker scripts under .agents/tasks (hard-coded `docs/...` paths) | 106 |

146 lines changed in .md files in total (`check_renames.py`). Prose uses of "verification-targets" as a name for the pipeline (for example "the verification-targets documents", "from the verification-targets pipeline") were left as they are: they are not paths. `.agents/tasks/bug-reports/...` (reproducer and log directory) is a different, unrenamed directory and was deliberately not touched.

Workspace copy `/Users/mahnush/Desktop/ESDK-Rust-Verus/MPL/.kiro/agents/verification-recommender.md` was overwritten with the repo copy; `diff -r` of the two `agents` directories is empty. (The workspace `MPL/.kiro` is not inside a git repo.) No other agent file mentions the renamed docs.

Word files regenerated with `/opt/homebrew/bin/pandoc docs/chorus/MPL-Threat-Model.md -o docs/chorus/MPL-Threat-Model.docx` (50,803 bytes) and `... MPL-Bug-Reports.md -o ... .docx` (50,842 bytes). `pandoc X.docx -t plain | head` shows the titles "MPL Threat Model: AWS Cryptographic Material Providers Library (native Rust)" and "MPL Native Rust: Bug Reports for Engineering Discussion". Neither docx contains an old path.

## Scripts changed

Path-only edit (docs/ prefix -> docs/mpl-):
- .agents/tasks/docs-sync-9955ecd/: check_bug_xrefs, check_chorus_consistency, check_citations, check_citations_bugdocs, check_citations_v2, check_citations_v3, check_extras, check_fn_defs, check_fn_defs_bugdocs, check_fn_defs_v2, check_misc, check_prose_scores, check_ratings, check_scores, check_stride_map, check_threat_refs (check_citations_chorus.py and check_fn_defs_chorus.py only name docs/chorus paths and needed no change).
- .agents/tasks/pipeline-rerun-620771c/: check_citations.py, check_fn_defs.py, check_scores.py.
- .agents/tasks/docs-proof-status/check_proof_status.py.

Small functional edits, needed because the files are renamed and not yet committed:
- check_proof_status.py: `head(p)` falls back to the old HEAD path when the new path is absent at HEAD; the two `git status --short` parses take the part after ` -> ` for rename lines.
- docs-sync-9955ecd/check_misc.py: same HEAD-path fallback (`_show`). Without it the "ID stability vs HEAD" check compares against an empty file until the rename is committed.

Left unchanged on purpose (one-shot edit/run helpers or records of a past run, they still contain old paths): audit-light/sweep2_cov.sh, audit-light/sweep34_targets.py, docs-c03-status/{check_c03_status.py, edit_others.py, edit_targets.py, rank_score_diff.sh}, docs-proof-status/edit_targets.py, docs-sync-9955ecd/manual1.sh. The `edit_*` scripts would rewrite docs from a past state, and `check_c03_status.py` / `rank_score_diff.sh` hard-code that run's HEAD and output directory (`rank_score_diff.sh` overwrites files in its record directory, so it was edited and then reverted). If they are ever reused, apply `rewrite_refs.py` to them first.

Historical run records under .agents/tasks/ (notes, logs, reviews, claims tables, run-log files) were not rewritten and still cite the old paths. That is intended.

## Verification results (details in verify-output.txt)

1. Renames: `git status` shows 19 `R`/`RM` entries; similarity 76% to 99% (the lowest, mpl-completeness-audit.md, has 52 path replacements because it cites `threat-model.md:NNN` and `verification-targets.md:NN` many times). `check_renames.py` over all 24 renamed or modified .md files: 0 violations. Test: the path rewrite applied to the HEAD text equals the new text, and removing the added `mpl-` prefix from the new text gives back the HEAD text exactly. So only path/link text changed; no finding, status, score or evidence text moved.
   RECHECK-main-620771c.md: the line diff shows 2 changed lines (path text only); after undoing the prefix it is identical to HEAD.
2. Link checker (relative Markdown links, anchors, backticked repo paths, backticked bare `*.md` names) over docs/ and verus-proofs/: 83 unresolved now, 85 at HEAD. 0 new. The 83 are pre-existing (listed in verify-output.txt with names mapped to the new ones): backticked `mpl/src/keystore/...` paths that no longer exist (the module is `key_store`), `mpl/tests/zz_bugrepro_*.rs` and `prim/tests/zz_bugrepro_07_aes_buffers.rs` (reproducers live under .agents/tasks/bug-reports/reproducers), spec file names (`branch-key-store.md`, `structures.md`, ... they refer to the spec repo), and `docs/mpl-bug-reports/BUG-01..BUG-09` (a range in prose). The 2 fewer are `.agents/tasks/pipeline-rerun-620771c/spec-pinned`, which exists in the working tree but is untracked, so it is missing from the `git archive HEAD` copy used as baseline. No renamed-path link is broken.
3. Old-path grep over docs/, verus-proofs/*.md, .kiro/, MPL/.kiro/ (both full `docs/<old>` and bare `threat-model.md`, `verification-targets/`, ...): no hits. Chorus docx plain text: 0 old-path lines. Hits remain only in the two .rs files below and in .agents/tasks.
4. Checkers with new paths: `check_scores.py` -> `PROBLEMS: none` (also pipeline-rerun-620771c/check_scores.py). Every docs-sync-9955ecd `check_*.py` and the pipeline-rerun-620771c ones were also run at pristine HEAD (HEAD scripts + HEAD docs, copy in /tmp/mpl-head) and compared with the working tree: 20 give identical output (tab columns 1-4, "mpl-" removed). One differs: check_citations_bugdocs.py, line 64 of BUG-10, one MISS at HEAD became OK now. The check picks identifiers from a text window around the citation, and the 4-character prefix moved that window; it is a heuristic artifact and not a regression. `check_proof_status.py` already reports 73 problem lines on pristine HEAD (it is a one-shot validator that expects its own edit run: "table row changed", "unknown result line '18 verified...'" after the later C03 commit). With the path fixes it reports the same lines on the working tree plus 2 expected ones: `forbidden paths changed` (its diff guard sees the renamed RECHECK and the README edits) and `HTML tag outside code` in BUG-10 (`<u8>` in prose, present at HEAD, found now only because the script format-checks changed files).
   Rank + score columns of the ranked tables (mpl-verification-targets.md cols 2-3; 01 and 02 cols 2-4): 76 rows each, identical to HEAD's docs/verification-targets*.md.
5. `git diff --quiet HEAD -- mpl prim esdk` exit 0; `git diff --quiet HEAD -- 'verus-proofs/*.rs'` exit 0; sha256 of all five .rs proof files equal HEAD. The only verus-proofs changes are the two READMEs (path text).
6. `diff -r` of repo `.kiro/agents` and workspace `MPL/.kiro/agents`: identical.
7. No file at any old path; `find docs -type d -empty` is empty.
8. Collisions with origin/Mahnush_Verus (fetched read-only; the tip fetched now is 8d6381e, the task text mentioned 2d229377): `comm -12` over docs/ paths is empty after the rename. Before the rename it was exactly `docs/threat-model.md`.
9. `git status` shows only: the 19 renames, edits to the moved files, docs/chorus .md/.docx, the two verus-proofs READMEs, .kiro/agents/verification-recommender.md, the checker scripts listed above, and the untracked `.agents/tasks/mpl-rename/`.

## Pre-existing issues found (not fixed, out of scope)

- 83 unresolved backticked/relative references listed above (stale `mpl/src/keystore/` paths, reproducer paths, spec file names).
- `check_proof_status.py` reports problems at HEAD (see 4).

## Stale references in .rs files (left as is, .rs must stay byte-identical)

- verus-proofs/c02_sign_fixed_len.rs:326 `docs/verification-targets/02-capability-driven.md` (comment)
- verus-proofs/t03_resolve_pinned_arn.rs:16 `docs/verification-targets/01-threat-driven.md` (comment)

## Remaining name collisions with Mahnush_Verus (not changed)

Outside docs/, the same path exists on both branches with different content for: `.kiro/agents/*.md` (all 8 agent files, differing already at HEAD, for example verification-recommender.md and spec-analyzer.md) and `.kiro/skills/verus/SKILL.md`; `esdk/src/...`, `esdk/Cargo.*`, `esdk/Makefile`, `esdk/tests/test_custom_keyring.rs`, `prim/src/{lib,ecdsa,hkdf}.rs`, `prim/Cargo.*`, `prim/Makefile`, `prim/tests/test_hkdf.rs` and several `Cargo.lock` files (full list in verify-output.txt, section 8). These are ordinary divergence of a shared code base. The ones that matter for a later merge of the two branches are the `.kiro/agents` and `.kiro/skills` files, because the mpl- docs rename touches `verification-recommender.md` on this side. Nothing there was changed beyond the two path lines in `verification-recommender.md`. The verus-proofs/ file names (c01_..., t02_...) do not exist on Mahnush_Verus.
