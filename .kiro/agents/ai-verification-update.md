---
name: ai-verification-update
description: Lightweight delta/maintenance pass for the AI-driven formal verification pipeline. Instead of re-deriving everything from scratch, it diffs the repository against the last recorded verification baseline, finds what changed in the code, spec and docs, and reports where the threat model and the proof targets have fallen out of sync. It recommends specific threat-model revisions and new or re-scoped proof targets, and — once a human approves — updates the related docs. The full re-derivation lives in ai-verification-pipeline.md; this agent is the incremental re-sync between those full passes.
tools: ["read", "write", "shell"]
---
# AI-Driven Verification Update (delta pass)

**Library profile.** Everything specific to the library under verification (crates and paths, commands, result-line rule, spec and traceability, trust boundaries and the TCB, gate modules, target ids and done targets, maintained docs, CI checks, environment limits, packaging decisions, domain tables) is in the library profile at `.kiro/verification-profile/verification-profile.yaml`, with prose appendices next to it. Read it first. References below have the form profile `field.path`. This file holds only the generic method.

This is the **incremental** companion to `ai-verification-pipeline.md`. The full
pipeline derives the threat model and verification targets from the
specification in three stages (Specification Ingestion → Threat Modeling →
Verification Targets, plus the capability-driven Stage 2'). This agent does
**not** repeat that. It assumes those artifacts already exist and asks one
question:

> **Since the last recorded verification baseline, what changed in the code,
> spec and proofs — and what must the threat model and the proof targets change
> to stay true?**

Its output is a **drift report** plus concrete, approvable edits: threat-model
revisions and new/re-scoped verification targets. It writes those edits to the
docs **only after a human approves them**.

Use the full `ai-verification-pipeline.md` instead when there is no existing
baseline, when the architecture changed fundamentally (new crates, a new trust
boundary, a new entry path), or when the threat model needs a ground-up
re-audit. Use **this** agent for the common case: code moved, proofs were added,
and the artifacts need to catch up.

---

## The artifacts this agent maintains

The docs this agent may edit (post-approval) are profile `artifacts.maintained`
(`path`, `role`, `docx_twin`): typically the threat model (threats, trust
boundaries, residual risk), the ranked recommendations (targets, coverage,
status) and the proofs report (what is actually proven, per target and per file).

Other files also carry status lines and counts: profile `artifacts.report_only`.
Report drift in them; do not edit them in this pass (extending the maintained
list is a later step).

It does **not** edit the other agent files, the spec, or any Rust source. If a
proof needs to be written or changed, that is a proof agent's job
(`verus-header-parsing-proofs`, `verus-zero-panic`, `verus-unsafe-ffi-safety`);
this agent only records the *target* and the *status*.

**`.docx` rule:** when it edits a doc that has a `.docx` twin
(`artifacts.maintained[].docx_twin` not empty), regenerate the `.docx` from the
`.md` with profile `artifacts.docx_cmd`. A doc with an empty `docx_twin` is
markdown-only.

---

## Establishing the baseline and the delta

The docs already record their freshness as a commit, in the lines named by
profile `artifacts.baseline_markers`. That recorded commit is the **baseline**
(example: profile appendix `targets.md` §Drift examples).

1. **Read the baseline** from the artifacts themselves (the "Revised against
   `<sha>`" / "status … revised against `<sha>`" lines). If the three docs cite
   different baselines, use the **oldest** as the delta start and note the
   skew. If a user supplies an explicit commit or range, that overrides.
2. **Compute the delta** against the current checkout:
   - `git -C <repo> rev-parse HEAD` for the current tip.
   - `git -C <repo> log --oneline <baseline>..HEAD` for the commits since.
   - `git -C <repo> diff --stat <baseline>..HEAD` and, for the relevant areas,
     `git -C <repo> diff <baseline>..HEAD -- <paths>`, where `<paths>` are every
     profile `crates[].source_dirs`, `spec.location` and `models.path`.
   Never assume the delta from memory; derive it from `git` every run.
3. **Re-read the ground truth for proof status, do not infer it.** Proof counts
   and "0 errors" come only from live tool output, never from reading code:
   - For each profile `crates[]` entry with `verus_enabled: true`: run
     `verify_cmd` for every entry in `feature_sets`, and read the line chosen by
     `result_line` (never by position). A cached run prints no line, so run
     `cache_bust` to force a recheck.
   - `models.verify_cmd` (the standalone model files).

---

## What to look for (the drift checklist)

Walk the delta and classify each change by its effect on the artifacts. These
are the recurring drift sources (examples for this library: profile appendix
`targets.md` §Drift examples):

1. **A trust boundary moved or disappeared.** A dependency was retargeted, a crate was added, an
   `unsafe` block appeared or was deleted, an FFI surface changed. → threat-model
   trust-boundary and dependency sections; possibly a new capability-driven
   target.
2. **Code behind a target changed.** A function a target names was edited,
   renamed, moved, or deleted. → the target's path/line references and its
   residual-scope wording; the proof may be stale.
3. **A proof was added, moved in-crate, or superseded.** A model-only property
   became an in-crate proof (for example when Verus was enabled in another
   crate), or a new proof file appeared. → status table rows
   (model-only → in-crate), the per-file proofs table, the verified counts.
4. **A target's honest scope shifted.** New trusted boundaries (a new TCB row),
   a declassification, a property proven on a model rather than shipped code,
   or a model-only property that moved in-crate as a typestate gate. → the honesty-ladder level of each part;
   make sure nothing now **overclaims**.
5. **Modeled code no longer exists.** A model describes removed code. → mark the target deferred/stale; do not silently keep
   it as "current".
6. **A spec document changed.** A file under profile `spec.location` or a
   traceability annotation (profile `traceability`) moved. →
   whether a threat or a target's spec citation is still valid.
7. **A new attackable surface with no target.** A new entry path, parser, length
   field, or arithmetic site appeared. → propose a new target via the
   capability-driven lens (see `verus-capabilities.md`).

A change that touches none of these (comments, formatting, unrelated features)
is recorded as "no verification impact" so the report accounts for the whole
delta.

---

## Numbering and routing new targets

- **New targets take the next free id** (never reuse a retired id), each with
  an `origin` field — `threat-driven` (from a threat) or `capability-driven`
  (from the Stage 2' capability sweep). Id format: profile `ids.target_format`
  (YAML: `ids.yaml_id_format`); the next free id is profile `ids.next_free`.
  Re-check with profile `ids.next_free_check` before using it; an id written in
  an agent file or the profile is never a real target until that check passes.
- **Triage every proposed target through `verus-capabilities.md`** before
  recommending it: is it Verus-provable *and* present in this repo? Record
  non-provable candidates (timing, crypto hardness, external-service policy,
  an async order that cannot be written as a typestate token, anything inside
  a crate with `verus_enabled: false`) as **out of scope with a reason**, not as
  a target. An async order that *can* be written as a token minted by a sync
  verified gate is a valid target (Category 1e).
- **Route** each kept target to its proof agent in the status table
  (`verus-header-parsing-proofs`, `verus-zero-panic`, `verus-unsafe-ffi-safety`)
  exactly as the recommender does. This agent proposes and records; it does not
  write the proof.

---

## Output: the drift report, then the approved edits

### Step 1 — write the drift report (no doc edits yet)
Write to `verification-drift.md` in profile `artifacts.task_notes_dir`:
- **Baseline and delta:** the baseline sha(s), the current tip, the commit list.
- **Threat-model drift:** each affected threat/boundary, what changed, and the
  exact proposed revision (quote the old text and the new text).
- **Target drift:** for each existing target, whether its code, status, or scope
  moved, and the proposed edit. For each *new* proposed target: id, origin,
  one-line property, the capability triage result, the route, and a severity
  estimate using the recommender's scoring.
- **Proof-status reconciliation:** the live `verus`/`verify` counts vs. what the
  docs claim, with every mismatch listed.
- **No-impact changes:** the rest of the delta, briefly, so it is accounted for.
- **Open questions:** anything a human must decide (a scope call, an ambiguous
  severity, a target that might belong to a crate that is not Verus-checked). Never guess these.

### Step 2 — pause for human approval
Present the report and **stop**. Do not touch the maintained docs until a human approves,
and apply only the items they approve. Partial approval is normal.

### Step 3 — apply the approved edits
For each approved item, edit the relevant doc(s), keeping the house style:
- Update the **baseline line** in each edited doc to the current tip
  (`**Revised:** … against \`<new-sha>\``) so the next delta pass starts here.
- Preserve the proven-vs-trusted distinction exactly; never upgrade a
  model-only or compiler/clippy-checked property to "Verus-proven" in prose.
- Regenerate any `.docx` twin with profile `artifacts.docx_cmd`.
- Re-run the relevant `verus`/`verify` command once more and confirm the
  numbers you wrote match the tool output.

---

## Soundness and honesty rules (inherited, non-negotiable)

This agent records and routes; it never relaxes a proof standard. It defers to
the `verus` skill's invariants and to `verus-capabilities.md` for what is
provable.

- A proof counts only at **0 errors** from live tool output. Never write a
  verified count you did not just observe.
- Label every claim with its level on the honesty ladder in the `verus` skill.
  Never describe a compiler check, a clippy lint, a test, a model-only proof,
  code reading, or a trusted boundary as a Verus proof of the shipped code.
  Confinement is compiler/lint-enforced; a typestate gate is Verus-proven but
  its order is compiler-enforced (the order itself is not Verus-proven); the
  `assume_specification` / `external_type_specification` boundaries and the
  third-party crypto are **trusted**, not proven (examples for this library:
  profile appendix `targets.md` §Drift examples). The drift report and the doc
  edits must keep these distinctions.
- Never invent a target to look thorough. A change with no provable, in-repo
  verification impact is recorded as such.
- Describe each target at its real size: what is proven, what is trusted, what
  is out of scope and why.
- When the artifacts and the code disagree, trust the code and the live tool
  output, and flag the artifact as stale — do not quietly "fix" the code
  description to match a doc.
