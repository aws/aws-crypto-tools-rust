# Template T-mutations-log: mutation log for one proof target

Used by recipe R1 step 3 (`.kiro/verification-toolkit/recipes/R1-prove-target.md`). Write the log to `<task dir>/logs/mutations.md` and summarize it in the commit message. The method is the SKILL section "Mutation testing" (`.kiro/skills/verus/SKILL.md`): one mutation at a time, cache bust, run, record, revert, compare byte for byte.

Replace every `<...>`.

---

# Mutation log: <target id> (`<HEAD sha before mutating>`)

## Baseline

One line per crate and feature set, run on the unmutated tree after busting the cache (profile `crates[].cache_bust`). Command: profile `crates[].verify_cmd` with each entry of profile `crates[].feature_sets`. Copy the line that profile `crates[].result_line` names.

- <crate>, <feature set>: `verification results:: <N> verified, 0 errors`

Mutations were applied by `<tool or "hand">`. After each revert the file was compared with the saved copy using `<cmp | git diff --exit-code <file>>`.

## Mutations

At least one row per new `ensures`, `requires`, type invariant, loop invariant and `decreases`. Compiler checks and review-only cases get rows too.

| Id | Obligation | Mutation | Expected catcher | Result line or compiler error | Outcome class | Reverted (byte-for-byte) |
|---|---|---|---|---|---|---|
| M1 | <obligation> | <change made> | <Verus, compiler, review only, never> | <`verification results:: ...` and the first error lines, or `error[E....]`, or "compiles and verifies"> | <class> | yes |

## Outcome classes

Use exactly these four names, as the SKILL section "Mutation testing" defines them. Each class supports only the honesty-ladder claim given here (SKILL "Honesty ladder").

| Outcome class | What happened | Ladder claim it supports |
|---|---|---|
| Verus-caught | the result line shows at least one error | level 1 (Verus-proven), or the gate part of level 2 |
| Compiler-caught | `cargo build` fails (for example E0451, E0425, E0616, E0061, E0308) | level 2 (compiler-enforced order) or level 3 (compiler-enforced) |
| Review-only | the mutation compiles and verifies; only code review catches it | no tool claim; the docs say only review catches it |
| Adapter glue, never caught | a change in an unverified adapter outside `verus!`; neither tool sees it | no claim; the docs say the adapter is not covered |

Rules:

- If the expected catcher and the outcome class differ, stop and report it. A Verus obligation that no mutation breaks is a tautology or does not reach the code (SKILL "Mutation testing", tautology check). Do not count it.
- Every row ends with `yes` in the last column. A row without a byte-for-byte revert makes the log invalid.

## Claims supported

One line: which claims this log supports, at which ladder level, and which parts rest on review or are not covered. Example form: "<obligations> are Verus-caught (level 1); <order> is compiler-caught (level 2); <item> is review-only; <adapter> is not covered."

---

**Example from the ESDK profile (sources of this template):**

This template was derived from these files in the task-notes directory (`.agents/tasks/`):

- `verus-prim-c03/logs/mutations.md`: baseline `verification results:: 18 verified, 0 errors`, mutations applied by `/tmp/c03_mutate.py` and compared byte for byte after restore, rows M1 to M19 each with result line, errors and `yes`.
- `vr001b-vr002-stage2/feasibility.md` §3 "Mutation tests to run in Phase 2": the mutation table with three classes (Verus postcondition failure, rustc E0425 and E0451, and "compiles: only review catches it").
- `sizing-and-sigpresence/review.md` "Mutations" bullet: each mutation says whether Verus or the compiler catches it (`open_buffers` +1 fails in Verus; a hand-built `OpenBuffers` fails with E0451; a raw buffer fails with E0061).

Example rows:

| Id | Obligation | Mutation | Expected catcher | Result line or compiler error | Outcome class | Reverted (byte-for-byte) |
|---|---|---|---|---|---|---|
| M1 | VR-013(a) `digest_core` length `ensures` | remove the length guard | Verus | `verification results:: 17 verified, 1 errors`; postcondition not satisfied --> src/lib.rs:262:9 | Verus-caught | yes |
| M2 | VR-002 token order in `decrypt_steps` | call `step_decrypt_body` before `step_verify_header` | compiler | `error[E0425]`: token not in scope | Compiler-caught | yes |
| M3 | VR-002 guard parameter | delete the `&HeaderVerified` parameter from `step_decrypt_body` | review only | compiles and verifies | Review-only | yes |
