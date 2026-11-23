# Review: mpl- rename of verification agents and verus skill

Branch `MPL-Verus`, HEAD `9df42d8`, changes uncommitted. Reviewer re-ran all checks with his own commands, not `verify.sh`. Verdict: **APPROVED**. No blockers. No fixes made by the reviewer (no file was edited except this review and `review.json`).

## State
```
$ git rev-parse --short HEAD; git branch --show-current
9df42d8
MPL-Verus
$ git merge-base --is-ancestor origin/Mahnush_Verus HEAD  -> not an ancestor (no merge); git stash list: 0 entries; reflog top is the HEAD commit (no new commit)
```

## Item 1: structure
```
$ diff -rq <workspace>/.kiro esdk-native-mpl/.kiro
Files .../MPL/.kiro/.DS_Store and .kiro/.DS_Store differ        # only difference; untracked Finder metadata, listed in .git/info/exclude
$ per-file shasum of all 9 non-.DS_Store files in both copies, sorted, diffed
SHA-SAME (9 files each)
$ ls .kiro/agents .kiro/skills   (both copies)
mpl-ai-verification-pipeline.md  mpl-spec-analyzer.md  mpl-threat-model-generator.md  mpl-verification-recommender.md
mpl-verus-capabilities.md  mpl-verus-header-parsing-proofs.md  mpl-verus-unsafe-ffi-safety.md  mpl-verus-zero-panic.md
skills/mpl-verus
```
No file at any old path (`ls` above; old `skills/verus` is gone). Frontmatter `name` equals the file stem for all 8 agents and the skill (`name: mpl-verus`, dir `mpl-verus`), in both copies (`name:` values printed by Ruby `YAML.safe_load`, item 7).
```
$ git status --short -M   (9 renames, staged by git mv, plus content modifications)
RM .kiro/agents/ai-verification-pipeline.md -> .kiro/agents/mpl-ai-verification-pipeline.md
RM .kiro/agents/spec-analyzer.md -> .kiro/agents/mpl-spec-analyzer.md
RM .kiro/agents/threat-model-generator.md -> .kiro/agents/mpl-threat-model-generator.md
RM .kiro/agents/verification-recommender.md -> .kiro/agents/mpl-verification-recommender.md
RM .kiro/agents/verus-capabilities.md -> .kiro/agents/mpl-verus-capabilities.md
RM .kiro/agents/verus-header-parsing-proofs.md -> .kiro/agents/mpl-verus-header-parsing-proofs.md
RM .kiro/agents/verus-unsafe-ffi-safety.md -> .kiro/agents/mpl-verus-unsafe-ffi-safety.md
RM .kiro/agents/verus-zero-panic.md -> .kiro/agents/mpl-verus-zero-panic.md
RM .kiro/skills/verus/SKILL.md -> .kiro/skills/mpl-verus/SKILL.md
$ git diff -M HEAD --summary | grep -c rename
9
```
Result: pass. The byte-identical requirement holds for every tracked/meaningful file; `.DS_Store` is not part of the content (see non-blocking note 1).

## Item 2: old identifiers
A Python scan (regex: old name not preceded by `mpl-` and not part of a longer `[A-Za-z0-9_-]` token) over `docs/`, `.kiro/`, workspace `.kiro/`, `verus-proofs/` (all files), the top-level README and `check_extras.py`, plus a skill-form scan (`` `verus` skill``, `skill::verus`, `skills/verus`, `^name: verus$`, `verus skill`, `"verus"`):
```
bare hits 0
(no SKILL lines printed)
$ grep -rn 'mpl-mpl-' docs verus-proofs .kiro <workspace>/.kiro .agents/tasks/docs-sync-9955ecd/check_extras.py
(no output)
$ grep -rIl (old names, any form) repo excluding .git, target, .agents:
docs/mpl-threat-model.md, docs/mpl-completeness-audit.md, docs/mpl-verification-targets/{01,02,04}*.md, docs/mpl-spec-security-analysis.md,
docs/mpl-verification-targets.md, .kiro/agents/mpl-*.md (8), .kiro/skills/mpl-verus/SKILL.md
```
Those files match only because each contains the new `mpl-<name>` form (a file named `mpl-spec-analyzer.md` contains the substring `spec-analyzer`); the bare-name scan shows 0 un-prefixed uses. The workspace root outside `esdk-native-mpl` has no other files mentioning the names (only workspace `.kiro/`).

Deliberately kept (confirmed present, correct to keep):
- `.kiro/agents/mpl-ai-verification-pipeline.md:83`: table cell "Verification recommender" (generic English role name).
- `docs/mpl-bug-reports/*`, `docs/chorus/*.md`, `verus-proofs/README*.md`: contain no agent identifiers (grep for `.kiro` / `agent` in them hits only reproducer/log paths), so they are byte-identical to HEAD (`git diff --quiet HEAD -- docs/mpl-bug-reports docs/chorus/MPL-Bug-Reports.md docs/chorus/MPL-Threat-Model.md verus-proofs` rc=0).
- `.agents/tasks/**` historical records (not touched except the checker script, see non-blocking note 2).
- Tool names (`~/verus/verus`, `verus!`, `cargo verus`, plain "Verus"), `verus-proofs/` directory, `duvet/mpl-annotations` branch name, `docs/mpl-*.md` path text.
- `verus-proofs/*.rs` contain no agent-name mentions, so nothing to list.

## Item 3: references resolve
```
$ every .kiro/agents|skills|steering path mentioned in docs/, .kiro/, verus-proofs/*.md, workspace .kiro (checked in repo and workspace roots)
6 .kiro/agents/mpl-ai-verification-pipeline.md    3 .kiro/agents/mpl-verification-recommender.md
4 .kiro/agents/mpl-verus-capabilities.md          2 .kiro/agents/mpl-verus-header-parsing-proofs.md
2 .kiro/agents/mpl-verus-unsafe-ffi-safety.md     2 .kiro/agents/mpl-verus-zero-panic.md
(no UNRESOLVED lines)
$ mpl-* tokens inside .kiro (counts): ai-verification-pipeline 2, spec-analyzer 4, threat-model-generator 3, verification-recommender 5, mpl-verus 3,
  verus-capabilities 10, verus-header-parsing-proofs 19, verus-unsafe-ffi-safety 15, verus-zero-panic 21
  -> every token is a file stem or the skill name (checked against the file list)
$ docs `agent:` fields: 27 mpl-verus-header-parsing-proofs, 8 mpl-verus-unsafe-ffi-safety, 11 mpl-verus-zero-panic (46 total, all resolve)
$ references to ai-verification-update / steering in .kiro and docs: none
```
Pass.

## Item 4: content unchanged beyond identifiers
Forward check (the opposite direction from the coder's script): apply old->new identifier substitution to the HEAD text of each changed text file (renamed ones against their old path) and compare with the working-tree text.
```
OK  .agents/tasks/docs-sync-9955ecd/check_extras.py lines changed 2 line count same True
OK  .kiro/agents/mpl-ai-verification-pipeline.md 16   OK .kiro/agents/mpl-spec-analyzer.md 1   OK .kiro/agents/mpl-threat-model-generator.md 1
OK  .kiro/agents/mpl-verification-recommender.md 21   OK .kiro/agents/mpl-verus-capabilities.md 22
OK  .kiro/agents/mpl-verus-header-parsing-proofs.md 5   OK .kiro/agents/mpl-verus-unsafe-ffi-safety.md 5   OK .kiro/agents/mpl-verus-zero-panic.md 5
OK  .kiro/skills/mpl-verus/SKILL.md 3
OK  docs/mpl-completeness-audit.md 1   OK docs/mpl-spec-security-analysis.md 2   OK docs/mpl-threat-model.md 2
OK  docs/mpl-verification-targets.md 49   OK docs/mpl-verification-targets/01-threat-driven.md 53
OK  docs/mpl-verification-targets/02-capability-driven.md 16   OK docs/mpl-verification-targets/04-validation.md 1
total changed lines 205  (line counts equal in every file; no line added or removed)
```
```
$ python3 .agents/tasks/docs-sync-9955ecd/check_scores.py | tail -4
  T23: 1 x 0.6 x 0.7 x 3 = 1.26 (doc 1.26)
  T24: 2 x 0.5 x 0.4 x 3 = 1.20 (doc 1.20)
  C08: 2 x 0.6 x 0.4 x 2 = 0.96 (doc 0.96)
PROBLEMS: none
$ python3 .agents/tasks/docs-sync-9955ecd/check_extras.py | tail -8
agent totals: {'mpl-verus-header-parsing-proofs': 20, 'mpl-verus-unsafe-ffi-safety': 5, 'mpl-verus-zero-panic': 8} total 33
merged refresh agent claim (20, 8, 5) computed (20, 8, 5)
... PROBLEMS: none
```
The exact-equality check (not just the rank/score columns) shows the ranked tables in `docs/mpl-verification-targets.md` and the two sub-documents differ from HEAD only in identifier text, so rank and score columns, findings, statuses and evidence text are identical to HEAD. The coder's separate column comparison also reports True for all 3 tables (36, 26, 7 rows).

Frontmatter diff vs HEAD (Python): only the `name:` line changed in each file. The `description:` line changed in `mpl-ai-verification-pipeline.md` and `mpl-verus-capabilities.md` only by identifier text (covered by the equality check above).

## Item 5: protected paths
```
$ git diff --quiet HEAD -- mpl prim esdk 'verus-proofs/*.rs'; echo rc=$?
rc=0
$ git status --short --ignored -- mpl prim esdk verus-proofs
!! mpl/target/
!! prim/target/        # ignored build output, no tracked or untracked change
$ git diff HEAD --stat -- mpl prim esdk verus-proofs     (empty)
$ git diff HEAD --stat -- .agents      only check_extras.py (2+/2-); mpl-agent-rename/ is the new untracked task dir
```
`~/.kiro/agents` holds only unrelated platform JSON agents with mtimes of Nov 11 and Nov 13; no mpl files there. Pass.

## Item 6: collisions with origin/Mahnush_Verus (8d6381eb)
```
$ git ls-tree -r --name-only refs/remotes/origin/Mahnush_Verus | grep '^\.kiro/'   (11 paths: the 9 old paths + .kiro/agents/ai-verification-update.md + .kiro/steering/verus-verification.md)
$ comm -12 <that list> <git ls-files .kiro>        (empty)
$ comm -12 <that list> <files on disk under .kiro>  (empty)
$ docs/ and verus-proofs/ path collisions           (empty)
```
Pass. Branch is not merged and Mahnush_Verus was not touched.

## Item 7: frontmatter parses
Ruby `YAML.safe_load` on both copies' frontmatter (keys, name, tools):
```
agents/mpl-ai-verification-pipeline.md keys=name,description,tools tools=["read", "web"]
agents/mpl-spec-analyzer.md keys=name,description,tools tools=["read", "write", "web"]
agents/mpl-threat-model-generator.md keys=name,description,tools tools=["read", "write", "web"]
agents/mpl-verification-recommender.md keys=name,description,tools tools=["read", "write", "web"]
agents/mpl-verus-capabilities.md keys=name,description,tools tools=["read", "web"]
agents/mpl-verus-header-parsing-proofs.md keys=name,description,tools tools=["read", "write", "shell"]
agents/mpl-verus-unsafe-ffi-safety.md keys=name,description,tools tools=["read", "write", "shell"]
agents/mpl-verus-zero-panic.md keys=name,description,tools tools=["read", "write", "shell"]
mpl-verus/SKILL.md keys=name,description (skills have no tools key at HEAD either) name=mpl-verus
```
No YAML errors in either copy. Pass.

## Word files
```
MPL-Threat-Model.docx  50803 bytes (HEAD 50803), unzip -t OK, title: "MPL Threat Model: AWS Cryptographic Material Providers Library (native Rust)"
MPL-Bug-Reports.docx   50842 bytes (HEAD 50842), unzip -t OK, title: "MPL Native Rust: Bug Reports for Engineering Discussion"
pandoc -t plain of each new docx == pandoc -t plain of the HEAD docx (808 and 851 lines, cmp identical)
```
Git lists both as modified only because the regenerated zip differs in embedded timestamps. Their source `.md` files are unchanged and contain no agent identifiers, so no text change is expected, and none exists.

## 20 spot checks (seeded random sample from the 205 changed lines; old -> new)
1. `.kiro/agents/mpl-verification-recommender.md:184`  `agent: verus-zero-panic` -> `agent: mpl-verus-zero-panic`
2. `docs/mpl-verification-targets/02-capability-driven.md:578`  `Routing: verus-header-parsing-proofs ×4 …, verus-zero-panic ×3` -> both `mpl-` prefixed, counts and IDs unchanged
3. `.kiro/agents/mpl-verus-capabilities.md:21`  `` `verus-unsafe-ffi-safety` `` -> `` `mpl-verus-unsafe-ffi-safety` ``
4. `docs/mpl-verification-targets.md:192`  rank 27 / 1.92 / T19 row, agent cell `verus-header-parsing-proofs` -> `mpl-verus-header-parsing-proofs`; other cells identical
5. `.kiro/agents/mpl-ai-verification-pipeline.md:154`  `` `verus-capabilities` `` -> `` `mpl-verus-capabilities` ``
6. `.kiro/agents/mpl-verus-capabilities.md:127`  table cell `` `verus-header-parsing-proofs` `` -> `` `mpl-verus-header-parsing-proofs` ``
7. `docs/mpl-verification-targets/04-validation.md:117`  agent totals line `verus-header-parsing-proofs 20, verus-zero-panic 8, verus-unsafe-ffi-safety 5 (33)` -> same numbers with `mpl-` names
8. `docs/mpl-verification-targets/01-threat-driven.md:134`  rank 18 / VR-2026-T15 / 1.92 row, agent cell prefixed; rest identical
9. `docs/mpl-verification-targets/01-threat-driven.md:123`  rank 7 / VR-2026-T06 / 4.20 row (expected FAIL, BUG-01), agent cell `verus-zero-panic` -> `mpl-verus-zero-panic`
10. `.kiro/agents/mpl-verus-zero-panic.md:14`  `` `verus-header-parsing-proofs`: stored/serialized bytes … `` -> `` `mpl-verus-header-parsing-proofs` ``
11. `docs/mpl-spec-security-analysis.md:94`  "the spec-analyzer definition expects `mpl/.duvet/config.toml`" -> "the mpl-spec-analyzer definition …" (reference to the agent definition; finding text otherwise identical)
12. `docs/mpl-verification-targets/01-threat-driven.md:360`  `agent: verus-unsafe-ffi-safety` -> `agent: mpl-verus-unsafe-ffi-safety`
13. `docs/mpl-verification-targets.md:180`  rank 15 / 3.20 / T26 row (expected FAIL: BUG-07a …), only agent cell prefixed
14. `docs/mpl-verification-targets/01-threat-driven.md:252`  `agent: verus-header-parsing-proofs` -> `agent: mpl-verus-header-parsing-proofs`
15. `.kiro/agents/mpl-verus-capabilities.md:18`  `` `verification-recommender` — uses this map … `` -> `` `mpl-verification-recommender` — … ``
16. `docs/mpl-verification-targets/02-capability-driven.md:329`  `agent: verus-header-parsing-proofs` -> `agent: mpl-verus-header-parsing-proofs`
17. `docs/mpl-verification-targets/01-threat-driven.md:613`  `agent: verus-header-parsing-proofs` -> `agent: mpl-verus-header-parsing-proofs`
18. `docs/mpl-verification-targets.md:193`  rank 28 / 1.68 / T20 row, agent cell prefixed; TM ids, effort, status cells identical
19. `docs/mpl-verification-targets/01-threat-driven.md:125`  rank 9 / VR-2026-T14 / 3.78 row, agent cell prefixed; rest identical
20. `docs/mpl-verification-targets/02-capability-driven.md:210`  `agent: verus-zero-panic` -> `agent: mpl-verus-zero-panic`

No sampled line has a changed score, status, finding or evidence text.

## Non-blocking notes (no action required)
1. `.kiro/.DS_Store` differs between the workspace and repo copies. It is untracked, git-excluded Finder metadata, not agent/skill content, so it is excluded from the byte-identical requirement.
2. `.agents/tasks/docs-sync-9955ecd/check_extras.py` was edited (2 lines, identifier text only; it regex-matches agent names in the docs and would not match the renamed docs otherwise). It is a checker script, not a historical run record, and the brief says to update every reference, so this is accepted. All other `.agents/tasks/` records are untouched.
3. The duplicate `/Users/mahnush/Desktop/ESDK-Rust-Verus/MPL/.kiro 2/` still holds the old names. It is outside both named `.kiro` folders and not read by Kiro as `.kiro`; the user may delete it.
4. Mahnush_Verus's own `.kiro/agents/ai-verification-update.md` and `.kiro/steering/verus-verification.md` reference the unprefixed names. They resolve to Mahnush_Verus's own agents after a merge, so no clash. They are not on this branch and are out of scope.

## Fixes made by reviewer
None.
