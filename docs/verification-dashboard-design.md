# ESDK Verification Dashboard — Design

**Status:** proposed. A working throwaway prototype exists at
`.agents/tasks/dashboard-proto/` (`gen_dashboard.py`, `verification-status.json`,
`dashboard.html`); this doc describes the production version to build from it.
**Revised:** November 2026: the ladder (§3) now follows the verus skill's nine
levels, and §4.1 defines `verification-status.json` schema v1 (per-feature-set
counts, `parts[]` per target, the drift flag, TCB rows), with counts read
through the library profile (§4.2).

## 1. Purpose

Give ESDK engineers one view of the formal-verification state: the threats, the
verification targets, what is verified, and — critically — **at what level**.
The dashboard answers, at a glance:

- Which threats are backed by a proof, and how strong is it?
- Which targets are proven in shipped code vs on a model vs enforced by the
  compiler/clippy vs merely trusted?
- Which targets came from the threat model vs the capability-driven sweep?
- What are the current `make … verus` / `verify` numbers?

It is a **reporting** surface over existing artifacts, not a new source of
truth and not a verifier. It never runs or re-interprets proofs beyond reading
the tool's pass/fail output.

## 2. Non-goals

- Not a live service. No server, no hosting, no on-demand re-verification.
  (Live status overlaps the still-open "proofs in CI" question, PR #103 Q2, and
  is deliberately out of scope here.)
- Not an editor. It does not modify the threat model, targets, or proofs.
- Not a replacement for `docs/verus-proofs-report.md`, which remains the
  authoritative prose record. The dashboard is a generated view *of* it.
- Does not re-derive targets. That is the pipeline/update agents' job.

## 3. The honesty ladder (the core concept)

Every target part carries a **level**, and the dashboard's one job is to show it
truthfully. The levels are the honesty ladder of the verus skill
(`.kiro/skills/verus/SKILL.md`, "Honesty ladder"), strongest first. The same
labels are used in the library profile (`targets[].parts[].level`):

| # | Level key | Meaning | Example (profile `targets[]`) |
|---|---|---|---|
| 1 | **verus_in_crate** | Verus-proven in shipped `esdk`/`prim` code (0 errors) | VR-003 decoders, VR-006, VR-012, VR-020 core |
| 2 | **verus_gate_compiler_order** | Verus proves the gate that mints a token; the compiler enforces the order | VR-001 (b), VR-002, VR-015, VR-016, VR-019 |
| 3 | **compiler_lint** | Enforced by Rust privacy or clippy, not Verus | VR-011 confinement |
| 4 | **model_only** | Proven on a standalone model in `verification/`, not the shipped path | VR-003 loops, VR-005 `ct ‖ tag` append |
| 5 | **tested** | Tests exercise it; they sample, they do not prove | — (no target part is at this level today) |
| 6 | **code_reading** | Someone read the code; no tool checks it | VR-020 adapter |
| 7 | **trusted** | A TCB assumption with a written-down row | VR-001 (c) constant time, T-cmp |
| 8 | **assumed_labeled** | A trusted assumption about third-party behavior its docs do not fully state | VR-014 BUG-07(b) under A-OPEN |
| 9 | **deferred** / **not_started** | No current evidence | VR-010 (deferred), VR-007 caller-side ordering (not started) |

**Rule the dashboard must obey:** a level is never rendered as an upgrade of the
one below it. Only levels 1 and 2 may be coloured or labelled as Verus-proven,
and level 2 only for its gate part. A single target may split across levels
(VR-001 is level 1 for (a), level 2 for (b), level 7 for (c)); the dashboard
shows every part, it does not collapse a target to its best level.

*History:* an earlier version of this table had six levels (in_crate,
model_only, compiler_lint, trusted, deferred, not_started) and showed VR-001 (b)
and VR-002 as model-only. Both moved to level 2 with the decrypt-order tokens.

## 4. Architecture

A two-stage static pipeline. No runtime component.

```
docs/*.md  +  live `make … verus/verify`
        │  (generator reads + runs)
        ▼
verification-status.json      ← structured intermediate (the "API")
        │  (renderer)
        ▼
verification-dashboard.html   ← self-contained, open in any browser
```

### 4.1 The intermediate: `verification-status.json`

A single structured file, the contract between extraction and rendering. The
dashboard HTML reads **only** this — it never parses prose.

**Schema v1.** Top-level fields:

| Field | What it holds |
|---|---|
| `schema_version` | `1` |
| `generated` | ISO timestamp of the run |
| `toolkit_version` | version of the verification toolkit the generator used |
| `profile` | library name from the profile (`library.short_name`) |
| `repo_sha` | the commit the counts and levels were read on |
| `snapshot_note` | the "this is a snapshot" caveat shown in the header |
| `counts[]` | one entry per crate and feature set: `crate`, `feature_args`, `verified`, `errors`, `cmd`, `cache_busted`, `raw_line` (the matched line), `line_index` (its line number in the raw log). When the toolchain is missing: `available: false` and a `reason`, never old numbers |
| `models` | `verified`, `errors`, `files`, `per_file{}` (file name → verified count) |
| `levels` | the ladder keys of §3 → display labels |
| `targets[]` | per target: `id`, `origin` (`threat` / `capability`), `score` (or `null`), `property`, `agent`, `threats[]`, `spec_refs[]`; `parts[]` with `label`, `level`, `evidence[]`, `trusted[]` (TCB row ids); `findings[]` (`id` as `VR-0NN Fk`, `summary`, `behavior_change`); `mutations` (`count`, `caught_by` with `verus`, `compiler`, `review`); `status_source`, `yaml_status`, `drift` |
| `tcb[]` | per TCB row: `id`, `item`, `kind` (`naming` / `trusted` / `labeled_assumption`), `source` |
| `packaging_decisions[]` | optional; shown in the footer |

Example (abridged; the counts are a snapshot of a live run at `9964b20b`, not
current values):

```json
{
  "schema_version": 1,
  "generated": "2026-11-22T17:00:00",
  "toolkit_version": "<toolkit version>",
  "profile": "ESDK",
  "repo_sha": "9964b20b",
  "snapshot_note": "Counts are a snapshot of one live run; re-run the commands for current numbers.",
  "counts": [
    {"crate": "aws-esdk", "feature_args": "", "verified": 99, "errors": 0,
     "cmd": "make -C esdk verus", "cache_busted": true,
     "raw_line": "verification results:: 99 verified, 0 errors", "line_index": 6},
    {"crate": "aws-esdk", "feature_args": "--no-default-features --features aws-lc-sys",
     "verified": 99, "errors": 0, "cmd": "make -C esdk verus", "cache_busted": true,
     "raw_line": "verification results:: 99 verified, 0 errors", "line_index": 14},
    {"crate": "aws-mpl-primitives", "feature_args": "", "verified": 18, "errors": 0,
     "cmd": "make -C prim verus", "cache_busted": true,
     "raw_line": "verification results:: 18 verified, 0 errors", "line_index": 3}
  ],
  "models": {"verified": 78, "errors": 0, "files": 11,
             "per_file": {"io_stream_aligned.rs": 24, "frame_layout_proofs.rs": 7}},
  "levels": {"verus_in_crate": "Verus-proven in shipped code",
             "verus_gate_compiler_order": "Verus-proven gate, compiler-enforced order",
             "trusted": "Trusted (TCB row)"},
  "targets": [
    {
      "id": "VR-001",
      "origin": "threat",
      "score": 16.0,
      "property": "Key-commitment accept/reject decision and its order",
      "agent": "verus-header-parsing-proofs",
      "threats": ["E3", "T8"],
      "spec_refs": ["spec/client-apis/decrypt.md", "spec/client-apis/key-derivation.md#hkdf-commit-key"],
      "parts": [
        {"label": "a", "level": "verus_in_crate",
         "evidence": ["esdk/src/message/header.rs:suite_data_check"], "trusted": []},
        {"label": "b", "level": "verus_gate_compiler_order",
         "evidence": ["esdk/src/decrypt_gate.rs:CommitmentAccepted"], "trusted": []},
        {"label": "c", "level": "trusted",
         "evidence": ["aws-lc-rs (Verus does not model timing)"], "trusted": []}
      ],
      "findings": [],
      "mutations": {"count": null, "caught_by": {"verus": null, "compiler": null, "review": null}},
      "status_source": "docs/verus-proofs-report.md section 3",
      "yaml_status": "in_crate_a_and_b",
      "drift": false
    }
  ],
  "tcb": [
    {"id": "A20", "item": "LessSafeKey::open_separate_gather", "kind": "labeled_assumption",
     "source": "docs/verus-proofs-report.md, TCB table (trusted specs and laws)"},
    {"id": "T-cmp", "item": "obeys_cmp::<String>()", "kind": "trusted",
     "source": "docs/verus-proofs-report.md, TCB table (trusted specs and laws)"}
  ]
}
```

Unknown values are `null`, not guessed (for example a target with no
`priority_score` in the recommendations YAML, or a mutation count the
generator could not read).

*History:* the first prototype used a flat `counts` object (one number per
crate, no feature sets) and one `level` per target, with the split only in a
`notes` string. Schema v1 replaces both: one count per crate and feature set,
and `parts[]` for every target that splits.

Keeping this as a committed artifact gives three things: the HTML stays dumb,
the data is diffable in review, and other tools (CI badges, future pages) can
consume it.

### 4.2 The generator

A script that produces `verification-status.json` by combining:

1. **Live counts, read through the library profile**
   (`.kiro/verification-profile/verification-profile.yaml`), not hard-coded:
   - for each crate, run profile `crates[].cache_bust` (for example
     `touch esdk/src/lib.rs`), then profile `crates[].verify_cmd` once per
     entry of profile `crates[].feature_sets`; keep the raw log;
   - pick the line with profile `crates[].result_line`: the first
     `verification results::` line after `Checking <crate> v...`, never a line
     by position (vstd and dependency crates print their own lines first only
     when they are not cached);
   - key each count by the crate that printed it: the aws-mpl-primitives line
     inside esdk's run is not the standalone prim count;
   - run profile `models.verify_cmd` and sum the per-file lines;
   - fail the run if any error count is non-zero or an expected line is
     missing. Profile `artifacts.counts_source` names these runs as the only
     source of counts.
2. **Status and levels** — each part's level comes from the status oracle,
   profile `artifacts.status_oracle` (`docs/verus-proofs-report.md` section 3,
   "Target coverage"), with the parts and their labels from profile
   `targets[].parts`. The `status:` fields in the YAML blocks of
   `docs/verification-recommendations.md` are metadata, not status: they are
   known to lag (the pipeline re-derivation once found VR-001 still marked
   `not_started` there).
3. **Metadata** — property, score, agent, `origin`, threat links and spec
   references come from the recommendations YAML (`id`, `origin`,
   `priority_score`, `property`, `agent`, `threat_references`,
   `trace_to_spec`). A field that is missing there is `null`.
4. **TCB rows** — from the TCB table that profile `tcb.doc_section` names.

When the YAML `status` disagrees with the oracle, the generator sets
`drift: true` on that target and shows both, rather than silently picking one
(this is the same drift the `ai-verification-update` agent catches).

Implementation: language and location are open packaging decisions (§7). A
Rust `xtask` subcommand runs in the repo's own toolchain and needs no extra
runtime in CI. A standalone Python script (as the prototype is) is cheaper and
easier to reuse for another library that has no `xtask` crate. A profile field
such as `dashboard_cmd` could name the per-repo entry point; that field is a
proposal and is not in the profile.

### 4.3 The renderer

Emits a **self-contained** `verification-dashboard.html`: inline CSS and JS, no
external assets, no network. Opens by double-click. Contents:

- **Header:** generation timestamp + the snapshot caveat.
- **Count tiles:** esdk / prim / verification-models, each showing `N verified,
  0 errors` and the command that produced it.
- **Level tiles:** how many targets sit at each level.
- **Origin filter:** All / Threat-driven / **Capability-driven** buttons.
- **Target table:** one row per target — id, origin badge, linked threat(s),
  property, one colour-coded **level chip per part** (with the part label and
  its evidence), score, and a drift marker when the YAML status disagrees with
  the oracle.
- **Footer:** restates the ladder and the snapshot caveat.

## 5. Where it lives and how it runs

Where the generator and its output live is an open packaging decision (§7);
record the choice in profile `packaging_decisions` when it is made. The
proposal below is one option, not a decision.

- Output: `docs/verification-dashboard.html` + `docs/verification-status.json`
  (co-located with the other verification docs). A reviewer suggested a page
  on `aws.github.io/aws-crypto-tools-commons/` instead.
- Trigger: `make dashboard` (a new target that runs the generator). Regenerate
  on demand; the HTML and JSON are committed so a reader needs no toolchain.
- Later, optional: hook the generator into the `ai-verification-update` drift
  flow (so a status refresh updates the dashboard) and/or a CI job. The CI hook
  depends on PR #103 Q2 (whether the Verus toolchain runs in CI); until that is
  decided, the dashboard is regenerated locally.

## 6. Honesty and staleness rules

- Every count is from a **live run** at generation time, cited with its command;
  never inferred from code, never hand-edited in the JSON.
- The JSON records `generated` and a snapshot note; the HTML shows both. The
  dashboard never implies the numbers are live.
- If the generator cannot run the `make` targets (no Verus toolchain), it must
  **fail or clearly mark counts as unavailable**, not fall back to stale numbers.
- Level is taken from the report oracle; YAML/report disagreements are surfaced,
  not hidden.
- The dashboard inherits the no-overclaim rule: it must not present a
  model-only, compiler/clippy, or trusted result as a Verus proof of shipped
  code.

## 7. Open questions

1. **Generator language and location (open packaging decision):** Rust `xtask`
   subcommand (fits the repo build, no extra runtime) vs a standalone Python
   script or single binary (cheaper, matches the prototype, reusable for a
   library without `xtask`). Where the output is published (`docs/` or a
   commons page) is part of the same decision. Not decided here; record the
   choice in profile `packaging_decisions`. A profile field `dashboard_cmd` for
   the per-repo entry point is a proposal only.
2. **Commit the generated HTML/JSON, or generate-on-demand only?** Committing
   lets readers open it with no toolchain; it also adds generated files to the
   repo (the same concern as the `.docx` twins, PR #103 Q4). Recommend
   committing both, since a dashboard nobody can open is useless.
3. **CI integration** — tied to PR #103 Q2. Defer until that is answered.
4. **Scope of the target metadata** — schema v1 adds per-part levels, the
   agent, spec references, findings, mutation counts and per-file model
   counts. Which of these the HTML shows by default is still open.

## 8. Build plan

The prototype proves the shape; the production version is a multi-file build
(generator + status schema + HTML renderer + `make dashboard` target) and
warrants the full plan → implement → review loop, run in a worktree (the
standing default for this project). The throwaway prototype in
`.agents/tasks/dashboard-proto/` is the reference for the rendered layout and
the JSON schema, and is discarded once the production version lands.
