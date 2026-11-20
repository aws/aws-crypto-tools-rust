# Template T-feasibility: feasibility note for one proof target

Used by recipe R1 step 1 (`.kiro/verification-toolkit/recipes/R1-prove-target.md`). Write the note to `<task dir>/feasibility.md`. This step is read-only on the source: no source edits and no commits. Scratch files (for example a standalone Verus file to try a design) go outside the repository.

Replace every `<...>`. Keep every section. If a section does not apply, write `n/a: <reason>`.

---

# Feasibility (<profile `library.short_name`>): <target id>, <one-line target description>

Worktree `<absolute worktree path>`, branch `<branch>`, HEAD = base = `<full base sha>` (`<base branch>`; confirmed with `git rev-parse HEAD` and `git merge-base HEAD <base branch>`). No source edits and no commits in this step.

## Baseline (run today)

Run each command after busting the cache (profile `crates[].cache_bust`), and copy the line that profile `crates[].result_line` names. Do not copy a count from a doc or an earlier note.

| Crate | Feature set (profile `crates[].feature_sets`) | Command (profile `crates[].verify_cmd`) | Result line |
|---|---|---|---|
| <crate> | <feature set> | `<command>` | `verification results:: <N> verified, 0 errors` |

Models (profile `models.verify_cmd`): `<result line>`.

## Verdict

`<GO, clean | FINDING, paused | NO-GO>`

- `GO, clean`: the design proves the target with no behavior change, no public API change and no finding.
- `FINDING, paused`: the code does not match the target (see the SKILL section "Stop and report findings"). Nothing is fixed. The run waits for the user's decision.
- `NO-GO`: the property is not provable here (see `.kiro/agents/verus-capabilities.md`), or the cost is out of proportion.

Gate G1 stops the run for the user when any of these holds: the verdict is not `GO, clean`; the change is intrusive (wide signature changes, restructuring async code, touching many files); the proof needs a behavior or API change (a new check, a changed error, a changed error order, a changed message, a changed buffer effect); or a finding appeared. Record the trigger here. Do not fix it.

## Facts re-confirmed

One bullet per fact the design rests on. Each gives `file:function:line`, says whether the function is sync or async and inside or outside `verus!`, and shows the grep or command that confirmed it.

- `<file>:<function>:<line>` (<sync | async>, <inside | outside> `verus!`): <fact>. Confirmed by `<grep command>`.

## Design

The types, functions and `requires`/`ensures` to add, as a short code sketch. Say where each item lives and why there (for example, a separate module so field privacy limits who can build a token). List every signature that changes, before and after.

## Proven, compiler-enforced, trusted

Label each part with its honesty-ladder level (SKILL "Honesty ladder"). One target can sit on several levels.

- **Verus-proven (level 1, or the gate part of level 2):** <what the `ensures` and type invariants state>.
- **Compiler-enforced (level 2 order or level 3):** <privacy, types, token parameters>.
- **Trusted (levels 6 to 8):** <what stays outside the proof, with its source; any new trusted spec needs a TCB row and the user's approval>.
- **No longer needed:** <earlier trusted items or code-reading arguments the design removes>.

## Behavior

State each item as "unchanged" with the reason, or describe the change (a change is a G1 trigger):

- results on `Ok`:
- error kinds:
- error messages (byte-identical):
- check order and error order:
- buffer effects on `Ok` and on `Err`:
- public API:
- streaming (what is released to the caller, and when):

## Mutations planned

At least one per new `ensures`, `requires`, type invariant, loop invariant and `decreases` (SKILL "Mutation testing"). The run's log uses template T-mutations-log.

| Mutation | Obligation it targets | Expected catcher (Verus, compiler, review only, never) |
|---|---|---|
| <mutation> | <obligation> | <catcher and the expected error> |

## Diff size

Lines per file, as an estimate. New Verus obligations and the expected count after the change, per crate and feature set.

## Numbering

- Id for this target: `<id>`. Next free id per profile `ids.next_free`, re-checked with profile `ids.next_free_check` (show the command and its empty output).
- External ids (profile `ids.external_ids`): not taken, not reused; written in full when cited.
- Known gaps (profile `ids.known_gaps`): <none touched | which one, and that it stays a known gap>.
- Strengthens an existing target instead of taking a new id: <yes, which, and why | no>.
- Finding ids follow profile `ids.finding_format`.

## Findings

`n/a: none`, or one entry per finding: id, exact location, what the spec says, what the code does.

## Options and recommendation

Only when the verdict is not `GO, clean` or there is a choice to make. Number the options. For each: what changes, what the user would notice, diff size. Then the recommendation and why.

## Decisions (do not re-decide)

The user's decisions, copied word for word, each with who relayed it (for example "relayed by the parent session") and the date. Later steps copy this block forward and do not re-open it.

> <verbatim decision>

## Implementation outcome

Filled after the prove step: what was built, how it differs from the design above and why, the commit sha, and where the results are recorded.

---

**Example from the ESDK profile (sources of this template):**

This template was derived from these feasibility notes in the task-notes directory (`.agents/tasks/`):

- `sizing-and-sigpresence/feasibility.md`: header with the confirmed base sha, `Item #2: GO, clean`, "Facts re-confirmed" with five call sites D1 to D5, the proven / compiler-enforced / trusted split, VR-016 numbering with the `grep "VR-01[6-9]\|VR-02"` check, and an "Implementation outcome" section.
- `vr001b-vr002-stage2/feasibility.md`: the baseline run today (esdk `69 verified, 0 errors` on both feature sets), the `file:function:line` and sync/async table, the mutation table with three outcome classes, and §User decision ("Verbatim (relayed by the parent session)").
- `encrypt-signing-key-presence/feasibility.md`: `Verdict: FINDING, paused`, the check works in one direction only, three numbered options with a recommendation, and the decision recorded afterwards (option 1, VR-019, finding F3).
- `signature-release-gate/feasibility.md`: `Verdict: GO, clean` with the spec clause, the VR number check, and a cleanliness checklist.
- `encrypt-limits-and-lengths/feasibility.md`: `#5 GO, #6 GO, both clean` with a code-vs-spec finding (F1, stricter than spec) that does not meet the pause criteria.

Example rows:

| Crate | Feature set | Command | Result line |
|---|---|---|---|
| aws-esdk | default | `cargo verus verify` in `esdk/` | `verification results:: 69 verified, 0 errors` |
| aws-esdk | `--no-default-features --features aws-lc-sys` | `cargo verus verify --no-default-features --features aws-lc-sys` in `esdk/` | `verification results:: 69 verified, 0 errors` |

| Mutation | Obligation it targets | Expected catcher |
|---|---|---|
| `header_auth_gate` returns `Ok` when `open_result` is `Err` | `ensures (r is Ok) <==> (open_result is Ok)` | Verus: postcondition fails |
| Call `step_decrypt_body` before `step_verify_header` | token order | rustc: token not in scope (E0425) |
| Delete the `&HeaderVerified` parameter from `step_decrypt_body` | the guard itself | review only: it compiles and verifies |
