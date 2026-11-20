# Recipe R1: prove one target (feasibility, prove, review, ask before merge)

This file is the authoritative spec of recipe R1. The workflow file `.kiro/workflows/verus-prove-target.workflow.json` is a machine-readable copy of it and is UNVALIDATED (see "Workflow file"). When the two disagree, this file wins.

## Purpose and when to use

Use R1 to take one verification target, new or existing, from a feasibility check to a reviewed local commit, and to stop and ask the user before anything is merged or pushed. Use it when the target touches shipped code. Read-only questions and investigations do not need R1.

## Inputs

| Input | What it is |
|---|---|
| `target_id` | the target id (an existing profile `targets[].id`), or `new` for a target that has no id yet |
| `target_description` | one line: what is to be proven |
| `base_branch` | the branch the work starts from and may later be merged into |
| `base_sha` | the full sha of `base_branch` at the start of the run |
| `profile_path` | absolute path of the library profile |
| `task_dir` | absolute path of the task-notes directory for this run (inside the workspace, never committed) |
| `worktree_path` | absolute path of the worktree to create |

Deviation from the brief: the brief named the first six inputs. `worktree_path` is added because every step prompt must name an absolute worktree path, the workflow templates cannot compute one, and the profile has no worktree field. Convention: `<repo root>/.worktrees/<basename of task_dir>`. The task branch has the same name as the basename of `worktree_path`.

**Library profile.** Everything specific to the library under verification (crates and paths, commands, result-line rule, spec and traceability, trust boundaries and the TCB, gate modules, target ids and done targets, maintained docs, CI checks, environment limits, packaging decisions, domain tables) is in the library profile at `.kiro/verification-profile/verification-profile.yaml`, with prose appendices next to it. Read it first. References below have the form profile `field.path`. This file holds only the generic method.

## Standing rules (every step)

1. **Worktree by default.** All edits happen in `worktree_path` on the task branch. Work in place only if the user decided so, and that decision is in the Decisions file.
2. **No merge and no push without explicit approval.** Gate G3a asks before the merge and gate G3b asks again before any push. A yes to one is not a yes to the other.
3. **Decisions are recorded verbatim.** Every user decision goes word for word, with who relayed it and the date, into the "Decisions (do not re-decide)" block of `{{task_dir}}/decisions.md`. Every later step reads that file first, follows it, and appends to it. No step re-opens a recorded decision.
4. **PR bodies are edited only from the live body.** Fetch the current body, keep the original in `{{task_dir}}`, write the new body next to it, show the diff, and ask before the edit.
5. **Re-ask after a lost connection.** If a step loses its connection while it waits, the user's answer may not have arrived. Ask again; do not assume an answer.
6. **Do not repeat an accepted escalation.** When the user has accepted a known item (for example a known test failure or a documented limit), later steps do not escalate it again unless its root cause changed. If it changed, say how.
7. **Never weaken a proof** and follow every SKILL invariant (`.kiro/skills/verus/SKILL.md`). Counts come only from runs made in this run, never from text.

Source note for rules 5 and 6: they come from the user's Step 5 brief. The lessons audit found no run artifact that shows them, so no run is cited.

## Gates

Gate numbering follows the user's brief. The lessons audit (§5.2) numbered them differently: there G2 was the pre-merge question and G3 the push question.

- **G1 feasibility stop** (step 1). The run stops for the user when the verdict is not `GO, clean`, when the change is intrusive, when it needs a behavior or API change, or when a finding appears.
- **G2 review loop** (step 6). The loop ends only when `{{task_dir}}/verdict.json` has `"verdict": "APPROVED"`.
- **G3a merge** (step 7). Ask before `git merge --ff-only` into `base_branch`.
- **G3b push** (step 8). Ask separately before any push or PR-body edit.

## Steps

Each step names the profile fields it reads, its template, its output and its id in the workflow file. Every step reads `{{task_dir}}/decisions.md` first.

### Step 0: setup (workflow id `setup`)

- Confirm `git rev-parse <base_branch>` equals `base_sha`. If not, stop and report.
- Create the worktree at `worktree_path` on a new task branch from `base_sha`. Record `git rev-parse HEAD` and the branch name.
- Check profile `schema_version` against `schema_version` in `.kiro/verification-toolkit/verification-profile.template.yaml`. If they differ, stop and report.
- Create `task_dir`, `{{task_dir}}/logs/` and `{{task_dir}}/decisions.md` with an empty "Decisions (do not re-decide)" block. If a `verdict.json` from an earlier run exists in `task_dir`, rename it so the review loop cannot stop on a stale verdict.
- Profile fields: `schema_version`.
- Output: `{{task_dir}}/setup.md` (worktree, branch, base sha, schema check), `{{task_dir}}/decisions.md`.

### Step 1: feasibility and gate G1 (workflow id `feasibility`)

- Read-only on the source: no source edits and no commits. Scratch files go outside the repository.
- Fill template T-feasibility (`.kiro/verification-toolkit/templates/T-feasibility.md`). Title with profile `library.short_name`.
- Baseline run today: profile `crates[].cache_bust`, then each profile `crates[].verify_cmd` with each entry of profile `crates[].feature_sets`; read the line named by profile `crates[].result_line`; run profile `models.verify_cmd`.
- Numbering: profile `ids.next_free`, re-checked with profile `ids.next_free_check`; never take or reuse profile `ids.external_ids`; profile `ids.known_gaps` stay gaps; findings use profile `ids.finding_format`. For an existing target, read profile `targets[]` for its parts and levels.
- **G1:** if any G1 trigger holds, record it in the note, do not fix it, and ask the user with numbered options and a recommendation (SKILL "Stop and report findings"). Write the answer verbatim into the Decisions block of `decisions.md` and of the note. If the user says stop, the run ends.
- Output: `{{task_dir}}/feasibility.md`.

### Step 2: prove (workflow id `prove`)

- Follow the proof agent named by profile `targets[].agent` for an existing target. For a new target, use the route that `.kiro/agents/verus-capabilities.md` gives for the property.
- Implement the design in the feasibility note and the Decisions block. Keep every SKILL invariant. Comments say in plain language what is proven and what is trusted.
- A design change that would be a G1 trigger (behavior or API change, a new trusted spec without approval) stops the step and goes to the user.
- Run profile `crates[].cache_bust` and each profile `crates[].verify_cmd` × profile `crates[].feature_sets` once; read profile `crates[].result_line`. Commit locally on the task branch. Fill the "Implementation outcome" section of the feasibility note.
- Output: a local commit; `{{task_dir}}/feasibility.md` "Implementation outcome".

### Step 3: mutations (workflow id `mutations`)

- Fill template T-mutations-log (`.kiro/verification-toolkit/templates/T-mutations-log.md`): baseline after profile `crates[].cache_bust`, each profile `crates[].verify_cmd` × profile `crates[].feature_sets`, line by profile `crates[].result_line`. At least one mutation per new obligation, an outcome class per row, a byte-for-byte revert per row.
- When the expected catcher and the outcome class differ, stop and report it.
- The tree is clean at the end (`git status --short` empty). No commit.
- Output: `{{task_dir}}/logs/mutations.md`.

### Step 4: CI parity (workflow id `ci_parity`)

- Run, on HEAD:
  - profile `crates[].cache_bust`, then every profile `crates[].verify_cmd` × profile `crates[].feature_sets`, reading profile `crates[].result_line`;
  - profile `models.verify_cmd`;
  - profile `crates[].test_cmd`; every failure must be listed in profile `crates[].known_test_failures`, any other failure is reported;
  - every profile `crates[].lint_cmds` entry;
  - every profile `ci.checks[].local_cmd` (named by profile `ci.checks[].name`, enforcing profile `ci.checks[].what`);
  - profile `ci.dependent_lockfiles` are updated together when a manifest changed.
- Check new platform-dependent code against profile `platform_assumptions`.
- List each item of profile `local_env_limits[]` that stops a check from running locally, with its profile `local_env_limits[].consequence`, under "Not run locally". The docs commit repeats this list.
- Fix only what the change itself broke (format, lint), re-run that check and commit; anything else goes to the user.
- Output: `{{task_dir}}/logs/ci-parity.md` (the HEAD sha the checks ran on, after any fix commit; every command, its result line or summary; "Not run locally").

### Step 5: docs (workflow id `docs`)

- Follow `.kiro/agents/ai-verification-update.md` for the doc edits.
- Update every doc in profile `artifacts.maintained` that cites the target, and the status in profile `artifacts.status_oracle`. Counts come from the step 4 runs (profile `artifacts.counts_source`). Update the lines named by profile `artifacts.baseline_markers`. Regenerate each profile `artifacts.maintained[].docx_twin` with profile `artifacts.docx_cmd`.
- Report drift in profile `artifacts.report_only` files; do not edit them.
- Commit locally. The message carries the verification block from `logs/ci-parity.md`, including "Not run locally", and the mutation summary from `logs/mutations.md` (one line per row and the "Claims supported" line). This commit changes docs only.
- Output: a local commit; `{{task_dir}}/logs/docs.md` (docs changed, report-only drift, the docs commit sha).

### Step 6: review loop, gate G2 (workflow id `review_loop`: `fix`, then `review`)

- At most 2 iterations. The loop stops when `{{task_dir}}/verdict.json` has `"verdict": "APPROVED"`, and pauses for the user after the second iteration otherwise.
- `fix` (first in each iteration): on iteration 1 there is no verdict file, so it only confirms the branch state: the tree is clean, HEAD is the docs commit sha in `logs/docs.md`, and `git diff <sha in logs/ci-parity.md>..HEAD` touches only the docs listed in `logs/docs.md`. If not, it re-runs the step 4 checks on HEAD and updates `logs/ci-parity.md`. Later, it fixes every `blocker` and `major` finding from `{{task_dir}}/verdict.json`, and the `minor` findings inside the target's scope, re-runs the step 4 checks the fix affects, updates the logs and commits. A fix that would change behavior goes to the user.
- `review`: the `verus-proof-reviewer` agent (`.kiro/agents/verus-proof-reviewer.md`) runs checklist C1 to C13. It writes template T-review (`.kiro/verification-toolkit/templates/T-review.md`) to `{{task_dir}}/review.md` and the verdict file to `{{task_dir}}/verdict.json` on every iteration:

  ```json
  {"verdict": "APPROVED | CHANGES_REQUESTED", "summary": "<text>", "reviewDoc": "<absolute path of review.md>", "findings": [{"id": "R1", "severity": "blocker | major | minor | info", "file": "<path>", "issue": "<text>", "fix": "<text>"}]}
  ```

  `verdict` is `"APPROVED"` if and only if no finding is `blocker` or `major`. The reviewer signals success whatever the verdict.
- Output: `{{task_dir}}/review.md`, `{{task_dir}}/verdict.json`, fix commits.

### Step 7: gate G3a, merge (workflow id `merge_gate`)

- Show the user: the commits in `<base_sha>..HEAD`, the diff stat, the counts from `logs/ci-parity.md`, "Not run locally", the verdict and its remaining minor or info findings.
- Ask before merging. Merge only after an explicit yes.
- Before merging, confirm `base_branch` still points at `base_sha`. If it moved, do not merge; report and ask.
- Merge with `git merge --ff-only <task branch>` in the checkout that has `base_branch` checked out. If no checkout has it, or that checkout has uncommitted changes, do not merge; report and ask.
- Record the answer in `decisions.md`. A no ends the merge part of the run.
- Output: the merge, or the recorded no.

### Step 8: gate G3b, push (workflow id `push_gate`)

- Ask separately before any push and before any PR-body edit. If the merge was declined, report and end without asking.
- Push only what the user named, to the remote the user named. Never force-push.
- A PR-body edit follows standing rule 4.
- Record the answer in `decisions.md`.
- Output: the push or edit, or the recorded no.

## Workflow file

`.kiro/workflows/verus-prove-target.workflow.json` maps the steps above to workflow steps with ids `setup`, `feasibility`, `prove`, `mutations`, `ci_parity`, `docs`, `review_loop` (`fix`, `review`), `merge_gate` and `push_gate`. Every step except `review` runs as the bundled `wf-coder` agent; `review` runs as `verus-proof-reviewer`. Every prompt names the absolute paths through `{{worktree_path}}`, `{{task_dir}}` and `{{profile_path}}`, the section of this file to follow, the template to fill and the signals to send (success; warning for G1, G3a and G3b; error when the user says stop).

**Validation status: UNVALIDATED.** The workflow schema could not be validated where the file was written. These fields are uncertain:

- the `inputs` type-hint strings (free text is assumed);
- whether `{{...}}` is interpolated inside `stopCondition.fileCheck.path`;
- the `jsonPath` syntax (`"verdict"` as written, not `$.verdict`);
- whether artifacts declared inside a `repeat` are visible to later top-level steps (`merge_gate` uses `{{task_dir}}` paths instead, so nothing depends on it);
- whether a custom agent id resolves from `.kiro/agents/<id>.md`;
- whether Kiro discovers workflows in `.kiro/workflows/` and needs the `.workflow.json` suffix;
- whether the bundled `wf-coder` agent has the shell and git tools the steps need;
- `captureOutput` is left at its default.

## Example from the ESDK profile (VR-016, short walk)

The VR-016 run (task notes `.agents/tasks/sizing-and-sigpresence/`, commit `5443aff1` on base `4db8580e`) mapped onto R1:

- Step 1: `feasibility.md` gave `Item #2: GO, clean` and `Item #3: GO, clean`, with the confirmed base sha, five call sites D1 to D5 and the VR-016 number check. G1 would have passed without a stop.
- Steps 2 to 5: one commit, `feat(esdk): prove decrypt buffer sizing (VR-016) and the signature-presence check (VR-015 (b))`. Its message lists the Verus runs (esdk 81 verified on both feature sets, prim 18, models 78), `cargo test` (392 passed, 6 credential-gated failures), clippy and fmt, the mutations and the docs changed.
- What R1 now requires that the run did not have: a separate `logs/mutations.md` (the mutations were only in the commit message), a `logs/ci-parity.md` with a "Not run locally" list, and a `decisions.md` file.
- Step 6: `review.md` was APPROVED with one non-blocking note. `review.json` had `verdict`, `findings` and `reviewDoc` but no `summary`, which the verdict shape now requires.
