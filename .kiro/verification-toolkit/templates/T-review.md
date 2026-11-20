# Template T-review: review of one proof target

Used by the `verus-proof-reviewer` agent (`.kiro/agents/verus-proof-reviewer.md`) in recipe R1 step 6 (`.kiro/verification-toolkit/recipes/R1-prove-target.md`). The reviewer writes two files every iteration:

- the review prose, in the shape below, to `<task dir>/review.md`;
- the verdict file, in the JSON shape below, to `<task dir>/verdict.json`.

Replace every `<...>`. Keep every section. The checklist items C1 to C13 are defined in the reviewer agent, with the profile fields each one reads. Here each item gets its evidence or `n/a: <reason>`.

---

# Review (<profile `library.short_name`>): <target id> (`<base sha>..<HEAD sha>`)

Branch `<branch>`, worktree `<absolute worktree path>`, base branch `<base branch>` at `<base sha>`.

Verdict: <APPROVED | CHANGES_REQUESTED>, <n> blockers, <n> major.

## Scope and requirements

What the feasibility note and the Decisions block asked for, and whether the diff does exactly that. Name any file the diff touches that the plan did not name. If the range contains commits that are not part of this target (for example an approved rebase base), say which range is under review.

## Checklist

Each item: evidence (file:line, command and output, or the log it was read from) or `n/a: <reason>`. Say for each count or result whether you ran it or read it from a log.

- **C1 Scope and requirements:** <evidence>
- **C2 Soundness grep on added lines:** <the command, every hit by file:line, and for each allowed hit the allowlist rule it meets>
- **C3 Target inside `verus!`, satisfiable `requires`, nothing contradictory, honest `decreases`:** <evidence>
- **C4 Mutation log:** <one row per new obligation, an outcome class per row, byte-for-byte reverts, each ladder claim matches its class>
- **C5 One definition per function and type:** <evidence>
- **C6 Behavior preserved:** <results, error kinds, messages, check order, buffer effects on Ok and Err, public API, streaming; the tests that pin it>
- **C7 Honesty ladder:** <each claim and its level; no overclaiming>
- **C8 TCB:** <new trusted specs, their rows, the approval in Decisions; changes flagged for the TCB owner>
- **C9 Live counts:** <result line per crate and feature set, run now after the cache bust; models; compared with every count in the commit and docs>
- **C10 CI parity:** <tests against known failures, lints, CI checks, dependent lockfiles, what was not run locally and why, platform assumptions>
- **C11 Docs and ids:** <maintained docs updated, baseline markers and twins regenerated, report-only drift reported, ids correct, plain-language comments>
- **C12 Git state:** <base branch unchanged, nothing merged, `git branch -r --contains HEAD` empty, tree clean>
- **C13 Decisions respected:** <each decision and how the diff follows it; user-accepted items not re-raised>

## Findings

`None.`, or one row per finding. Ids are `R1`, `R2`, ... within this review. Severities: `blocker`, `major`, `minor`, `info`.

| Id | Severity | File | Issue | Fix |
|---|---|---|---|---|
| <R1> | <severity> | <path[:line]> | <what is wrong> | <what to change> |

## Decisions (do not re-decide)

Copied forward word for word from `<task dir>/decisions.md` and the feasibility note, each with who relayed it. Do not add, drop or reword a decision.

> <verbatim decision>

## Git state

- Base branch `<base branch>`: `<sha>` (unchanged from the run's base: yes/no).
- Task branch `<branch>`: `<HEAD sha>`; commits in range: `<list>`.
- `git branch -r --contains HEAD`: `<empty | output>`.
- `git status --short`: `<empty | output>`.
- Merged into any branch: no. Pushed: no.

## Verdict file

`<task dir>/verdict.json` has this shape:

```json
{
  "verdict": "APPROVED | CHANGES_REQUESTED",
  "summary": "<plain-language summary of the review>",
  "reviewDoc": "<absolute path of review.md>",
  "findings": [
    {"id": "<R1>", "severity": "blocker | major | minor | info", "file": "<path>", "issue": "<what is wrong>", "fix": "<what to change>"}
  ]
}
```

Rules:

- `verdict` is `"APPROVED"` if and only if no finding has severity `blocker` or `major`. Otherwise it is `"CHANGES_REQUESTED"`.
- `findings` is `[]` when there are none. Minor and info findings may stay in an APPROVED verdict.
- Write the file on every iteration, also when the verdict did not change. The R1 review loop stops when `verdict` is `"APPROVED"`.

---

**Example from the ESDK profile (sources of this template):**

This template was derived from these reviews in the task-notes directory (`.agents/tasks/`):

- `sizing-and-sigpresence/review.md`: header `Review: sizing-and-sigpresence (5443aff1 vs base 4db8580e)`, "Verdict: APPROVED, no blockers", the evidence list (open sites, sizes and behavior, proof integrity, recorded verification, mutations, docs, git) and a "Note (not a blocker)" on module-local construction of `OpenBuffers`.
- `vr001b-vr002-stage2/review.md`: the scope note that the range `8d6381eb...HEAD` also contains the approved rebase base `b0c88c6e`, so the change under review is `b0c88c6e..3195f86f`.
- `verus-prim-t1/review.md`: the soundness gate (blocking), with `external_body` allowed only on the `external_type_specification` wrapper of `ExSignature`, and the fips local-environment limit stated as not run.
- `verus-prim-c03/review.md`: the TCB check (`aws_lc_specs.rs` tags T-ty, T-uf, T-AsRef, A1 to A20; A-OPEN labeled) and the mutation log M1 to M19.
- `coverage-tests/review.md`: `Ghost::assume_new()` in T10, inside a `#[cfg(test)]` module after the file's `} // verus!` closer; `git branch -r --contains coverage-tests` empty.
- `agents-toolkit-split/verdict.json`: the verdict JSON shape (`verdict`, `summary`, `reviewDoc`, `findings` with `id`, `severity`, `file`, `issue`, `fix`).

Filled verdict file (shortened from `agents-toolkit-split/verdict.json`):

```json
{
  "verdict": "APPROVED",
  "summary": "The Step 3 split meets the brief. The template and the ESDK profile have the same 22 keys with a 'what; read by' comment on every key. Nothing was pushed or merged. Four minor findings remain.",
  "reviewDoc": "/Users/mahnush/Desktop/ESDK-Rust-Verus/aws-crypto-tools-rust/.agents/tasks/agents-toolkit-split/2026-11-19-164823-review.md",
  "findings": [
    {"id": "R3", "severity": "minor", "file": ".kiro/verification-profile/verification-profile.yaml", "issue": "crates[aws-mpl-primitives].lint_cmds lists 'make -C prim clippy', which also runs the fips feature and needs cmake and go; test_cmd carries this caveat, lint_cmds does not.", "fix": "Add the same cmake/go note (see local_env_limits) to the prim lint_cmds entry."}
  ]
}
```
