# mpl- rename of the verification agents and the verus skill

Branch `MPL-Verus`, HEAD `9df42d8`. Nothing committed or pushed. `review.json` did not exist, so this is the first pass.
Files in this directory: `rewrite_ids.py` (the reference rewriter), `rewrite-counts-repo.txt` (its per-file counts), `verify.sh` and `verify-output.txt` (verification and its saved output), this note.

## Rename map (done in both `.kiro` copies: `git mv` in the repo copy, `mv` in the workspace copy)

| Old | New |
|---|---|
| `.kiro/agents/ai-verification-pipeline.md` | `.kiro/agents/mpl-ai-verification-pipeline.md` |
| `.kiro/agents/spec-analyzer.md` | `.kiro/agents/mpl-spec-analyzer.md` |
| `.kiro/agents/threat-model-generator.md` | `.kiro/agents/mpl-threat-model-generator.md` |
| `.kiro/agents/verification-recommender.md` | `.kiro/agents/mpl-verification-recommender.md` |
| `.kiro/agents/verus-capabilities.md` | `.kiro/agents/mpl-verus-capabilities.md` |
| `.kiro/agents/verus-header-parsing-proofs.md` | `.kiro/agents/mpl-verus-header-parsing-proofs.md` |
| `.kiro/agents/verus-unsafe-ffi-safety.md` | `.kiro/agents/mpl-verus-unsafe-ffi-safety.md` |
| `.kiro/agents/verus-zero-panic.md` | `.kiro/agents/mpl-verus-zero-panic.md` |
| `.kiro/skills/verus/SKILL.md` | `.kiro/skills/mpl-verus/SKILL.md` |

Frontmatter `name:` equals the file stem in every file (`name: verus` became `name: mpl-verus` for the skill). `tools:` and `description:` lines are unchanged. Git reports 9 renames (similarity 80% to 99%).

Before renaming, the file list (`find .kiro`) was compared with `git ls-tree -r --name-only origin/Mahnush_Verus | grep '^.kiro/'` (fetched read-only, no auth problem). Mahnush_Verus has the same 9 paths plus two files that exist only there: `.kiro/agents/ai-verification-update.md` and `.kiro/steering/verus-verification.md`. No other file here collided, so no extra rename was needed. After the rename `comm -12` of the two lists is empty.

## How identifiers were rewritten

`rewrite_ids.py` replaces each old agent name with `mpl-<name>` when it is not preceded or followed by `[A-Za-z0-9_-]` (so it cannot apply twice and cannot hit a longer name such as `mpl-verus-capabilities`). Skill rules: `` `verus` skill `` (2 places in `mpl-verus-capabilities.md`), `.kiro/skills/verus/` paths, `skill::verus`, and the frontmatter name. `.kiro/agents/<old>.md` paths are covered by the agent rule. Plain `Verus`, `~/verus/verus`, `verus!`, `cargo verus` and the directory `verus-proofs/` are not matched.

## Reference counts per area (replacements made; per-file detail in `rewrite-counts-repo.txt`)

| Area | Replacements |
|---|---|
| `.kiro/agents/*.md` (cross-references, frontmatter names, skill refs) | 81 agent ids + 2 skill refs |
| `.kiro/skills/mpl-verus/SKILL.md` | 4 agent ids (related-agents line) + 1 frontmatter name |
| `docs/mpl-verification-targets.md` | 53 |
| `docs/mpl-verification-targets/01-threat-driven.md` | 55 |
| `docs/mpl-verification-targets/02-capability-driven.md` | 19 |
| `docs/mpl-verification-targets/04-validation.md` | 3 |
| `docs/mpl-threat-model.md` | 2 |
| `docs/mpl-spec-security-analysis.md` | 2 |
| `docs/mpl-completeness-audit.md` | 1 |
| `docs/mpl-bug-reports/*` (incl. RECHECK) | 0 (no agent identifiers in these files) |
| `docs/chorus/*.md` | 0 |
| `verus-proofs/README.md`, `README-t03-t05.md` | 0 |
| workspace `.kiro/` copy | same edits as the repo copy (88 replacements) |
| `.agents/tasks/docs-sync-9955ecd/check_extras.py` | 6 (see checker scripts) |

Total in the repo copy: 223 replacements in the 16 `.kiro` and docs files, plus 6 in the checker script. The 77-match figure in section 7 of the output counts matches at HEAD under `docs/mpl-verification-targets/` (55 + 19 + 3 = 77, same as above).

RECHECK and the bug reports contain no agent identifiers, so they are byte-identical to HEAD (proved with `git diff --quiet`, section 4).

## Word files

`docs/chorus/MPL-Threat-Model.md` and `MPL-Bug-Reports.md` contain no agent identifiers, so their text did not change. Both `.docx` files were regenerated anyway with `/opt/homebrew/bin/pandoc <f>.md -f markdown+smart -t docx -o <f>.docx` (that reader reproduces the committed files: `pandoc old.docx -t plain` equals `pandoc new.docx -t plain` for both; `-f gfm` would have changed curly quotes and the table header). Result: `MPL-Threat-Model.docx` 50803 bytes, `MPL-Bug-Reports.docx` 50842 bytes, both non-empty, plain-text output starts with the document titles. git shows them as modified only because docx files embed a timestamp; the text content is unchanged.

## Verification results (script: `verify.sh`, saved output: `verify-output.txt`, reproduced below)

Summary: both `.kiro` copies byte-identical (`.DS_Store` excluded, it is untracked Finder metadata and differs); 17 of 17 frontmatters parse with name = stem; 9 renames; no old identifier left in `docs/`, `verus-proofs/*.md`, `.kiro/`, workspace `.kiro/`; no `mpl-mpl-`; all 13 `.kiro/...` paths mentioned resolve in both copies; all 46 `agent:` fields in docs resolve to an agent file; the normalized diff (prefix stripped, compared with HEAD) is identical for all 17 changed text files; `check_scores.py` prints `PROBLEMS: none`; rank, id and score columns of the three ranked tables equal HEAD; `git diff --quiet HEAD -- mpl prim esdk 'verus-proofs/*.rs'` exits 0; no `.kiro` path collides with `origin/Mahnush_Verus`.

## Checker scripts under `.agents/tasks/`

- Updated: `docs-sync-9955ecd/check_extras.py` (it hard-codes `verus-header-parsing-proofs`, `verus-zero-panic`, `verus-unsafe-ffi-safety` to total the `agent:` fields and parse the "Agent routing" line). It now prints `PROBLEMS: none` against the renamed docs.
- Not changed on purpose: `docs-c03-status/edit_targets.py` is a one-shot edit script that was already applied (8 old-name table strings in its search/replace pairs); rerunning it would not match anything anyway. `check_scores.py` and the other `check_*.py` scripts do not mention agent names or `.kiro` paths.

## Occurrences left unchanged on purpose

1. Historical run records under `.agents/tasks/` describe what ran at the time under the old names, so they were not rewritten (the user's notes say not to rewrite them): `docs-sync-9955ecd/{notes-targets-threat-driven.md,scores.md}`, `audit-light/{sweep3-bugs.md,sweep4-threat-target.md}`, `docs-c03-status/{edit_targets.py,check_extras.out}`, `docs-proof-status/head/*` (pre-change snapshots of the three targets documents: 53, 49 and 16 matches), `pipeline-rerun-620771c/{stage2-notes.md,stage3-notes.md,verification-evidence.md}`, and the earlier `mpl-rename/` task files (`notes.md`, `review.md`, `verify-output.txt`, `review-verify-rerun.txt`, `rewrite-counts-repo.txt`).
2. `verus-proofs/*.rs`: the brief expected stale agent-name mentions in comments. A grep for all 8 names, `.kiro` and `skill` found none (only two comments naming `.agents/tasks/verus-proofs-*/logs/`), so there is nothing to list. No `.rs` file was touched.
3. Prose in `.kiro/agents/mpl-ai-verification-pipeline.md` lines 82-83: the table cells "Threat model generator" and "Verification recommender" are generic English role names, not identifiers. The brief says to keep 'verification recommender' in prose.
4. Tool names and paths: `~/verus/verus`, `verus!`, `cargo verus`, plain "Verus", the directory `verus-proofs/`, and the skill title "Verus Formal Verification".
5. `duvet/mpl-annotations` (a git branch name in `mpl-ai-verification-pipeline.md`) and `docs/mpl-*.md` path text were already `mpl-`-prefixed and are untouched.
6. User-level agents under `~/.kiro` were not touched. A stray directory `/Users/mahnush/Desktop/ESDK-Rust-Verus/MPL/.kiro 2/` (a duplicate of the old `.kiro` with the old names, outside both `.kiro` folders named in the brief) was also left as is; delete it if it is not needed, otherwise Kiro users may see old names there.
7. `.kiro/.DS_Store` differs between the two copies (untracked, ignored in comparisons).

## Remaining path collisions with Mahnush_Verus

None for `.kiro/` (`comm -12` empty). `docs/` and `verus-proofs/` also have no colliding paths. Files that exist only on Mahnush_Verus under `.kiro/` and do not collide: `.kiro/agents/ai-verification-update.md`, `.kiro/steering/verus-verification.md`. Inspection with `git show` (read-only) found that those two Mahnush_Verus files refer to the old names (`ai-verification-update.md`: `ai-verification-pipeline.md`, `verus-capabilities.md`, the three `verus-*` agents and the `verus` skill; `steering/verus-verification.md`: `.kiro/agents/ai-verification-pipeline.md`). They keep resolving to Mahnush_Verus's own agents at the old paths, so after a merge both sets sit side by side without a path clash. They were not touched.

## Full output of `verify.sh`

```
=== 0. state
MPL-Verus
9df42d8

=== 1. structure
--- .kiro copies byte-identical (workspace vs repo; .DS_Store ignored, it is untracked Finder metadata)
IDENTICAL
--- file lists
./agents/mpl-ai-verification-pipeline.md
./agents/mpl-spec-analyzer.md
./agents/mpl-threat-model-generator.md
./agents/mpl-verification-recommender.md
./agents/mpl-verus-capabilities.md
./agents/mpl-verus-header-parsing-proofs.md
./agents/mpl-verus-unsafe-ffi-safety.md
./agents/mpl-verus-zero-panic.md
./skills/mpl-verus/SKILL.md
--- frontmatter name == file stem (agents) and skill dir == skill name; name/description/tools present
OK  .kiro agents mpl-ai-verification-pipeline | name=mpl-ai-verification-pipeline desc=True tools=True
OK  .kiro agents mpl-spec-analyzer | name=mpl-spec-analyzer desc=True tools=True
OK  .kiro agents mpl-threat-model-generator | name=mpl-threat-model-generator desc=True tools=True
OK  .kiro agents mpl-verification-recommender | name=mpl-verification-recommender desc=True tools=True
OK  .kiro agents mpl-verus-capabilities | name=mpl-verus-capabilities desc=True tools=True
OK  .kiro agents mpl-verus-header-parsing-proofs | name=mpl-verus-header-parsing-proofs desc=True tools=True
OK  .kiro agents mpl-verus-unsafe-ffi-safety | name=mpl-verus-unsafe-ffi-safety desc=True tools=True
OK  .kiro agents mpl-verus-zero-panic | name=mpl-verus-zero-panic desc=True tools=True
OK  .kiro skills mpl-verus | name=mpl-verus desc=True tools=False
OK  esdk-native-mpl/.kiro agents mpl-ai-verification-pipeline | name=mpl-ai-verification-pipeline desc=True tools=True
OK  esdk-native-mpl/.kiro agents mpl-spec-analyzer | name=mpl-spec-analyzer desc=True tools=True
OK  esdk-native-mpl/.kiro agents mpl-threat-model-generator | name=mpl-threat-model-generator desc=True tools=True
OK  esdk-native-mpl/.kiro agents mpl-verification-recommender | name=mpl-verification-recommender desc=True tools=True
OK  esdk-native-mpl/.kiro agents mpl-verus-capabilities | name=mpl-verus-capabilities desc=True tools=True
OK  esdk-native-mpl/.kiro agents mpl-verus-header-parsing-proofs | name=mpl-verus-header-parsing-proofs desc=True tools=True
OK  esdk-native-mpl/.kiro agents mpl-verus-unsafe-ffi-safety | name=mpl-verus-unsafe-ffi-safety desc=True tools=True
OK  esdk-native-mpl/.kiro agents mpl-verus-zero-panic | name=mpl-verus-zero-panic desc=True tools=True
OK  esdk-native-mpl/.kiro skills mpl-verus | name=mpl-verus desc=True tools=False
frontmatter problems: 0
--- no file at any old path (both copies)
(none listed above = pass)
--- git status (R = rename)
 M .agents/tasks/docs-sync-9955ecd/check_extras.py
RM .kiro/agents/ai-verification-pipeline.md -> .kiro/agents/mpl-ai-verification-pipeline.md
RM .kiro/agents/spec-analyzer.md -> .kiro/agents/mpl-spec-analyzer.md
RM .kiro/agents/threat-model-generator.md -> .kiro/agents/mpl-threat-model-generator.md
RM .kiro/agents/verification-recommender.md -> .kiro/agents/mpl-verification-recommender.md
RM .kiro/agents/verus-capabilities.md -> .kiro/agents/mpl-verus-capabilities.md
RM .kiro/agents/verus-header-parsing-proofs.md -> .kiro/agents/mpl-verus-header-parsing-proofs.md
RM .kiro/agents/verus-unsafe-ffi-safety.md -> .kiro/agents/mpl-verus-unsafe-ffi-safety.md
RM .kiro/agents/verus-zero-panic.md -> .kiro/agents/mpl-verus-zero-panic.md
RM .kiro/skills/verus/SKILL.md -> .kiro/skills/mpl-verus/SKILL.md
 M docs/chorus/MPL-Bug-Reports.docx
 M docs/chorus/MPL-Threat-Model.docx
 M docs/mpl-completeness-audit.md
 M docs/mpl-spec-security-analysis.md
 M docs/mpl-threat-model.md
 M docs/mpl-verification-targets.md
 M docs/mpl-verification-targets/01-threat-driven.md
 M docs/mpl-verification-targets/02-capability-driven.md
 M docs/mpl-verification-targets/04-validation.md
?? .agents/tasks/mpl-agent-rename/
--- renames in index+worktree vs HEAD (git diff -M HEAD --summary): 9 (expected 9)
 rename .kiro/agents/{ai-verification-pipeline.md => mpl-ai-verification-pipeline.md} (91%)
 rename .kiro/agents/{spec-analyzer.md => mpl-spec-analyzer.md} (99%)
 rename .kiro/agents/{threat-model-generator.md => mpl-threat-model-generator.md} (99%)
 rename .kiro/agents/{verification-recommender.md => mpl-verification-recommender.md} (80%)
 rename .kiro/agents/{verus-capabilities.md => mpl-verus-capabilities.md} (86%)
 rename .kiro/agents/{verus-header-parsing-proofs.md => mpl-verus-header-parsing-proofs.md} (97%)
 rename .kiro/agents/{verus-unsafe-ffi-safety.md => mpl-verus-unsafe-ffi-safety.md} (97%)
 rename .kiro/agents/{verus-zero-panic.md => mpl-verus-zero-panic.md} (97%)
 rename .kiro/skills/{verus => mpl-verus}/SKILL.md (98%)

=== 2. old identifiers left (must list only deliberate keeps; none expected in these areas)
--- docs/ verus-proofs/*.md .kiro/ and workspace .kiro/
exit 1 (1 = none found)
--- backticked `verus` skill / skill::verus / .kiro/skills/verus/ / name: verus
exit 1 (1 = none found)
--- mpl-mpl- anywhere in changed files / areas
exit 1 (1 = none found)
--- old identifiers in verus-proofs/*.rs (informational; none expected)
exit 1 (1 = none)
--- chorus .docx plain text
docs/chorus/MPL-Bug-Reports.docx: 0 lines with old identifiers; size 50842 bytes
MPL Native Rust: Bug Reports for Engineering Discussion
docs/chorus/MPL-Threat-Model.docx: 0 lines with old identifiers; size 50803 bytes
MPL Threat Model: AWS Cryptographic Material Providers Library (native Rust)

=== 3. every referenced path / agent name resolves
.kiro paths mentioned: 13 unresolved: 0
.kiro/agents/mpl-ai-verification-pipeline.md -> mpl- names mentioned: ['mpl-ai-verification-pipeline', 'mpl-spec-analyzer', 'mpl-threat-model-generator', 'mpl-verification-recommender', 'mpl-verus-capabilities', 'mpl-verus-header-parsing-proofs', 'mpl-verus-unsafe-ffi-safety', 'mpl-verus-zero-panic'] unresolved: []
.kiro/agents/mpl-spec-analyzer.md -> mpl- names mentioned: ['mpl-spec-analyzer'] unresolved: []
.kiro/agents/mpl-threat-model-generator.md -> mpl- names mentioned: ['mpl-threat-model-generator'] unresolved: []
.kiro/agents/mpl-verification-recommender.md -> mpl- names mentioned: ['mpl-spec-analyzer', 'mpl-verification-recommender', 'mpl-verus-header-parsing-proofs', 'mpl-verus-unsafe-ffi-safety', 'mpl-verus-zero-panic'] unresolved: []
.kiro/agents/mpl-verus-capabilities.md -> mpl- names mentioned: ['mpl-verification-recommender', 'mpl-verus', 'mpl-verus-capabilities', 'mpl-verus-header-parsing-proofs', 'mpl-verus-unsafe-ffi-safety', 'mpl-verus-zero-panic'] unresolved: []
.kiro/agents/mpl-verus-header-parsing-proofs.md -> mpl- names mentioned: ['mpl-verus-header-parsing-proofs', 'mpl-verus-unsafe-ffi-safety', 'mpl-verus-zero-panic'] unresolved: []
.kiro/agents/mpl-verus-unsafe-ffi-safety.md -> mpl- names mentioned: ['mpl-verus-header-parsing-proofs', 'mpl-verus-unsafe-ffi-safety', 'mpl-verus-zero-panic'] unresolved: []
.kiro/agents/mpl-verus-zero-panic.md -> mpl- names mentioned: ['mpl-verus-header-parsing-proofs', 'mpl-verus-unsafe-ffi-safety', 'mpl-verus-zero-panic'] unresolved: []
.kiro/skills/mpl-verus/SKILL.md -> mpl- names mentioned: ['mpl-verus', 'mpl-verus-unsafe-ffi-safety'] unresolved: []
agent/skill names in agent bodies unresolved: 0
docs YAML agent: fields: 46 unresolved: 0

=== 4. no content change beyond identifiers
IDENTICAL after undo .agents/tasks/docs-sync-9955ecd/check_extras.py  
IDENTICAL after undo .kiro/agents/ai-verification-pipeline.md -> .kiro/agents/mpl-ai-verification-pipeline.md
IDENTICAL after undo .kiro/agents/spec-analyzer.md -> .kiro/agents/mpl-spec-analyzer.md
IDENTICAL after undo .kiro/agents/threat-model-generator.md -> .kiro/agents/mpl-threat-model-generator.md
IDENTICAL after undo .kiro/agents/verification-recommender.md -> .kiro/agents/mpl-verification-recommender.md
IDENTICAL after undo .kiro/agents/verus-capabilities.md -> .kiro/agents/mpl-verus-capabilities.md
IDENTICAL after undo .kiro/agents/verus-header-parsing-proofs.md -> .kiro/agents/mpl-verus-header-parsing-proofs.md
IDENTICAL after undo .kiro/agents/verus-unsafe-ffi-safety.md -> .kiro/agents/mpl-verus-unsafe-ffi-safety.md
IDENTICAL after undo .kiro/agents/verus-zero-panic.md -> .kiro/agents/mpl-verus-zero-panic.md
IDENTICAL after undo .kiro/skills/verus/SKILL.md -> .kiro/skills/mpl-verus/SKILL.md
skip (binary/other): docs/chorus/MPL-Bug-Reports.docx
skip (binary/other): docs/chorus/MPL-Threat-Model.docx
IDENTICAL after undo docs/mpl-completeness-audit.md  
IDENTICAL after undo docs/mpl-spec-security-analysis.md  
IDENTICAL after undo docs/mpl-threat-model.md  
IDENTICAL after undo docs/mpl-verification-targets.md  
IDENTICAL after undo docs/mpl-verification-targets/01-threat-driven.md  
IDENTICAL after undo docs/mpl-verification-targets/02-capability-driven.md  
IDENTICAL after undo docs/mpl-verification-targets/04-validation.md  
files compared: 17 differing: 0
--- files with zero agent identifiers must be byte-identical to HEAD (bug reports incl. RECHECK, chorus .md, verus-proofs READMEs)
byte-identical to HEAD: yes
--- check_scores.py
  T24: 2 x 0.5 x 0.4 x 3 = 1.20 (doc 1.20)
  C08: 2 x 0.6 x 0.4 x 2 = 0.96 (doc 0.96)
PROBLEMS: none
--- check_extras.py (updated to new agent names)
quick wins computed: ['C01', 'C02', 'T02'] listed in merged s5: ['C01', 'C02', 'T02']
agent totals: {'mpl-verus-header-parsing-proofs': 20, 'mpl-verus-unsafe-ffi-safety': 5, 'mpl-verus-zero-panic': 8} total 33
merged refresh agent claim (20, 8, 5) computed (20, 8, 5)
merged s1 ranks: 33 max 33
01 ranked table rows: 26 order matches merged: True rank col sequential: True
02 ranked table rows: 7 order matches merged: True rank col sequential: True
01 claims T27 at rank 10 table has 10
PROBLEMS: none
--- rank+score columns of the ranked tables vs HEAD
docs/mpl-verification-targets.md rows 36 rank/score/id columns identical to HEAD: True
docs/mpl-verification-targets/01-threat-driven.md rows 26 rank/score/id columns identical to HEAD: True
docs/mpl-verification-targets/02-capability-driven.md rows 7 rank/score/id columns identical to HEAD: True

=== 5. mpl/ prim/ esdk/ and verus-proofs/*.rs untouched
git diff --quiet exit 0: OK
 untracked-or-modified entries there:        0

=== 6. collisions with origin/Mahnush_Verus (.kiro)
origin/Mahnush_Verus .kiro files:       11; ours (tracked):        9
comm -12 (colliding paths; must be empty):
(end)
docs/ and verus-proofs/ colliding paths (informational):
(end)

=== 7. reference counts per area (old identifier occurrences at HEAD that were rewritten)
docs/mpl-verification-targets.md : 53
docs/mpl-verification-targets/ : 77
docs/mpl-threat-model.md : 2
docs/mpl-spec-security-analysis.md : 2
docs/mpl-completeness-audit.md : 1
docs/mpl-bug-reports/ : 0
docs/chorus/ : 0
verus-proofs/*.md : 0
.kiro/ : 87
(counts above are matches at HEAD; the rewrite_ids.py per-file counts are in rewrite-counts-repo.txt)
```
