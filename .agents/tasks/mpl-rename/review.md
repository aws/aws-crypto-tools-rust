# Review of the mpl- docs rename (branch MPL-Verus, base HEAD bd24f61)

Verdict: **APPROVED**. No blockers. I made no fixes and changed no repo file. I added only review artifacts to this directory (`review.md`, `review.json`, `review-verify-rerun.txt`, `review-normalized-diff.py`/`.out`, `review-spotcheck.py`). I did not commit or push.

## Evidence

I re-ran the coder's `verify.sh` (output: `review-verify-rerun.txt`) and wrote separate checks for the claims where the coder's own script was the only evidence (normalized diff, link resolution, docx). `git status --short` was byte-identical before and after my runs. The re-run output equals the coder's `verify-output.txt` except for dict-key order in one checker line (`check9 merged blocks`).

### The 8 verification items

| # | Result | Evidence |
|---|---|---|
| 1 Renames, path-only | PASS | `git diff --cached` shows 19 `R100` (pure `git mv`). `git diff -M HEAD` shows 19 renames at 76% to 99% similarity. The lowest, `mpl-completeness-audit.md`, has 52 path replacements. Normalized content diff below: empty. |
| 2 Links | PASS | `check_links.py`: 83 unresolved now, 85 at HEAD, **0 new**. The 83 are pre-existing (stale `mpl/src/keystore/`, reproducer paths, spec file names, `BUG-01..BUG-09` ranges). The 2 fewer are an untracked `spec-pinned` directory missing from the `git archive` baseline. My independent sweep of all 246 `mpl-*` reference occurrences in the changed files resolved all but 4. Those 4 are the prose ranges `docs/mpl-bug-reports/BUG-` and `BUG-01..BUG-09` / `BUG-01` to `BUG-09`, which are the same at HEAD with old names. |
| 3 Old-path grep | PASS | `docs/`, `verus-proofs/*.md`, `.kiro/`, `MPL/.kiro/`: no full `docs/<old>` path and no bare old filename. Both docx plain texts: 0 old-path lines, and the docx XML has 0 matches. Hits remain only in `.agents/tasks` and in `verus-proofs/c02_sign_fixed_len.rs:326` and `t03_resolve_pinned_arn.rs:16` (comments). The brief says to leave those. Other `threat-model` / `verification-targets` strings under `.kiro` are agent names or diagram text, not doc paths. |
| 4 Scores | PASS | `check_scores.py` -> `PROBLEMS: none`. `pipeline-rerun-620771c/check_scores.py` -> `PROBLEMS: none`. Other `check_*.py` outputs at pristine HEAD (HEAD scripts + HEAD docs) vs working tree: identical for 20 of 21 scripts. The one difference is `check_citations_bugdocs.py`, BUG-10 line 64, MISS -> OK. It is a text-window heuristic shifted by the 4-character prefix and is not a regression. `check_proof_status.py` has 73 problem lines at pristine HEAD (a one-shot validator) and 75 now. The 2 extra are its "forbidden paths changed" guard seeing the expected rename, and `<u8>` in BUG-10 prose, which is present at HEAD and now format-checked. Rank + score columns of the three ranked tables (76 rows each) are identical to HEAD. |
| 5 No code change | PASS | `git diff HEAD -- mpl prim esdk` empty, `git status -- mpl prim esdk` empty. The 5 `verus-proofs/*.rs` files are unchanged vs HEAD (`git diff --quiet` per file, plus sha256). Only `README.md` and `README-t03-t05.md` changed in `verus-proofs/`. |
| 6 Agent copies | PASS | `diff -r esdk-native-mpl/.kiro/agents MPL/.kiro/agents` is empty. Only 2 lines changed in `verification-recommender.md`, both `docs/threat-model.md` -> `docs/mpl-threat-model.md`. |
| 7 Old paths gone | PASS | No file or directory at any of the six old paths. `find docs -type d -empty` is empty. |
| 8 Mahnush_Verus collisions | PASS | `origin/Mahnush_Verus` tip is `8d6381e`. `comm -12` over `docs/` is empty now. At HEAD it was exactly `docs/threat-model.md`. Collisions outside `docs/` (`.kiro/agents/*.md`, `.kiro/skills/verus/SKILL.md`, `esdk/` and `prim/` files, `Cargo.lock`) are reported in the notes and left unchanged, as the brief requires. |

### Normalized content diff (no finding/status/score text changed)

I wrote a separate normalizer (`review-normalized-diff.py`, not the coder's rule or inverse). For each changed file it reads the HEAD content (at the old path for renames) and the working-tree content. It maps `(mpl-)?(threat-model|spec-security-analysis|verification-targets|completeness-audit|bug-reports)` to the bare old name on both sides and compares. HEAD has no pre-existing `mpl-<name>` strings, so the mapping hides nothing.

Result over all 44 changed files (`review-normalized-diff.out`): **residual diff empty for 42**. This covers all 24 `.md` documents (19 renamed, `docs/chorus/MPL-*.md`, the 2 verus-proofs READMEs, `.kiro` agent) and 18 scripts. The 2 non-empty files are `check_proof_status.py` and `check_misc.py`. I read their diffs. Beyond the path edits they contain only the documented functional edits: a fallback to the old HEAD path when the new path is absent at HEAD, and taking the part after ` -> ` in `git status` rename lines. They change no document content.

`docs/mpl-bug-reports/RECHECK-main-620771c.md`: 2 changed lines (path text only). Removing the `mpl-` prefix gives a file identical to HEAD.

Word files: the plain text of each regenerated docx, with `mpl-` removed from the 5 names, equals the plain text of the HEAD docx (diff empty). Each is non-empty (50,803 and 50,842 bytes). `pandoc X.docx -t plain | head` shows the titles "MPL Threat Model: AWS Cryptographic Material Providers Library (native Rust)" and "MPL Native Rust: Bug Reports for Engineering Discussion". Docx vs md plain text differ only in table rule widths (0 differing lines for Bug-Reports, 8 rule-only lines for Threat-Model).

### 20 random reference spot-checks (seed 20240607, 246 occurrences)

All 20 resolve to an existing file. Run `review-spotcheck.py` to reproduce.

1. `docs/mpl-completeness-audit.md:181` `mpl-threat-model.md` -> `docs/mpl-threat-model.md` OK
2. `docs/mpl-bug-reports/README.md:3` `docs/mpl-verification-targets/01-threat-driven.md` OK
3. `docs/mpl-completeness-audit.md:180` `mpl-spec-security-analysis.md` OK
4. `docs/mpl-completeness-audit.md:114` `mpl-threat-model.md` OK
5. `docs/mpl-completeness-audit.md:30` `mpl-threat-model.md` OK
6. `docs/chorus/MPL-Bug-Reports.md:762` URL `.../blob/MPL-Verus/docs/mpl-bug-reports/BUG-08-build-base-collision-branch-unreachable.md` -> file exists OK
7. `docs/mpl-completeness-audit.md:217` `docs/mpl-verification-targets/01-threat-driven.md` OK
8. `docs/chorus/MPL-Threat-Model.md:568` `docs/mpl-completeness-audit.md` OK
9. `docs/mpl-completeness-audit.md:187` `mpl-threat-model.md` OK
10. `docs/mpl-verification-targets.md:4` `docs/mpl-spec-security-analysis.md` OK
11. `docs/chorus/MPL-Threat-Model.md:567` `docs/mpl-verification-targets.md` OK
12. `docs/chorus/MPL-Threat-Model.md:28` `docs/mpl-threat-model.md` OK
13. `docs/mpl-threat-model.md:663` `mpl-verification-targets.md` OK
14. `docs/mpl-bug-reports/BUG-05-keygen-expect-and-short-edk-keystore-lookup.md:10` `docs/mpl-threat-model.md` OK
15. `docs/chorus/MPL-Bug-Reports.md:764` URL `.../blob/MPL-Verus/docs/mpl-bug-reports/BUG-10-raw-aes-on-decrypt-unwiped-data-key.md` OK
16. `docs/mpl-threat-model.md:660` `mpl-verification-targets.md` OK
17. `docs/chorus/MPL-Threat-Model.md:590` `docs/mpl-threat-model.md` OK
18. `docs/chorus/MPL-Bug-Reports.md:11` `docs/mpl-completeness-audit.md` OK
19. `docs/mpl-verification-targets/04-validation.md:177` `docs/mpl-spec-security-analysis.md` OK
20. `docs/mpl-completeness-audit.md:223` `docs/mpl-threat-model.md` OK

The sample is weighted toward `mpl-completeness-audit.md`, which has the most bare-name references. The full 246-occurrence sweep covers the rest. The 21 GitHub URLs all use `MPL-Verus` as the ref (20 `blob`, 1 `tree`), and none points at another branch or commit, so no wrong-branch URL was rewritten. No changed line points at a Mahnush_Verus doc.

### Excluded paths and repo state

- `mpl/`, `prim/`, `esdk/`: no diff, no untracked files. `verus-proofs/*.rs`: unchanged.
- Mahnush_Verus not merged or touched: no `.git/MERGE_HEAD`, HEAD still `bd24f61`. The reflog shows no new entries. `origin/Mahnush_Verus` exists only as a read-only fetched remote-tracking ref (`8d6381e`).
- Nothing committed (HEAD unchanged). Nothing pushed: `origin/MPL-Verus` is still `851977d` and I ran no push.
- `.agents/tasks/` historical records: the only tracked changes there are 20 `check_*.py` scripts. No notes, logs, reviews or claims were rewritten. The only untracked files are in `tasks/mpl-rename/`.
- `git status` contains only the 19 renames, the edited moved files, docs/chorus `.md`/`.docx`, the two verus-proofs READMEs, `.kiro/agents/verification-recommender.md`, the 20 scripts and the new notes directory.

## Fixes made

None.

## Advisory notes (not blockers)

- Left on the old paths by the coder, with reasons given in `notes.md`: `docs-c03-status/{check_c03_status.py, rank_score_diff.sh, edit_*.py}`, `audit-light/*`, `docs-proof-status/edit_targets.py`, `docs-sync-9955ecd/manual1.sh`. They hard-code a past run's HEAD and output directory, so I judge them records of a past run and not reusable checkers. Anyone reusing them must first apply `rewrite_refs.py`.
- Two `.rs` comments cite old doc paths (`c02_sign_fixed_len.rs:326`, `t03_resolve_pinned_arn.rs:16`). The brief forbids touching `.rs` files, and `notes.md` lists them.
- A third agent copy exists outside the brief at `/Users/mahnush/Desktop/ESDK-Rust-Verus/MPL/.kiro 2/agents/verification-recommender.md`. It still has the old `docs/threat-model.md` path and is not in a repo. Update it by hand if it is used.
- `check_proof_status.py` was already failing on HEAD (73 problems) and still fails (75). This is the pre-existing one-shot validator behavior described above.
