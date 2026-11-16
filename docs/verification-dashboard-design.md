# ESDK Verification Dashboard — Design

**Status:** proposed. A working throwaway prototype exists at
`.agents/tasks/dashboard-proto/` (`gen_dashboard.py`, `verification-status.json`,
`dashboard.html`); this doc describes the production version to build from it.

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

Every target carries a **level**, and the dashboard's one job is to show it
truthfully. The levels, strongest first, mirror the project-wide ladder in
`docs/verus-proofs-report.md` and the developer guide:

| Level | Meaning | Example |
|---|---|---|
| **in_crate** | Verus-proven in shipped `esdk`/`prim` code (0 errors) | VR-003, VR-006, VR-012 |
| **model_only** | Proven on a standalone model in `verification/`, not the shipped path | VR-001 (b), VR-002 |
| **compiler_lint** | Enforced by Rust privacy + clippy, not Verus | VR-011 confinement |
| **trusted** | A TCB assumption (aws-lc-rs crypto, constant-time, C++ pointer validity) | VR-001 (c) |
| **deferred** | Target exists but not currently proven | VR-010 (models removed code) |
| **not_started** | Recommended, no proof yet | — |

**Rule the dashboard must obey:** a level is never rendered as an upgrade of the
one below it. A `compiler_lint` or `model_only` or `trusted` cell must never be
coloured or labelled as if it were a Verus proof of shipped code. A single
target may split across levels (VR-001 is in_crate for (a), model_only for (b),
trusted for (c)); the dashboard shows the split, it does not collapse it to the
best level.

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
dashboard HTML reads **only** this — it never parses prose. Shape (from the
prototype):

```json
{
  "generated": "<iso timestamp>",
  "snapshot_note": "Counts are a snapshot; re-read from make … verus/verify.",
  "counts": {
    "esdk":   {"verified": 69, "errors": 0, "cmd": "make -C esdk verus"},
    "prim":   {"verified": 10, "errors": 0, "cmd": "make -C prim verus"},
    "verification_models": {"verified": 78, "errors": 0, "files": 11,
                            "cmd": "make -C verification verify"}
  },
  "levels": { "in_crate": "In-crate proof", "model_only": "Model-only", … },
  "targets": [
    {
      "id": "VR-001",
      "origin": "threat",          // "threat" | "capability"
      "level": "in_crate",         // the honesty-ladder key
      "score": 16.0,
      "property": "…",
      "evidence": "esdk/src/message/header.rs (suite_data_check)",
      "threats": "T8/E3 commitment; Invisible Salamanders",
      "notes": "(a) decision in-crate; (b) ordering MODEL-ONLY …; (c) constant-time TRUSTED"
    }
  ]
}
```

Keeping this as a committed artifact gives three things: the HTML stays dumb,
the data is diffable in review, and other tools (CI badges, future pages) can
consume it.

### 4.2 The generator

A script that produces `verification-status.json` by combining:

1. **Live counts** — run `make -C esdk verus` (default, then
   `--no-default-features --features aws-lc-sys`), `make -C prim verus` (both
   feature sets), `make -C verification verify`; parse the `verification
   results:: N verified, M errors` lines. `touch esdk/src/lib.rs` /
   `prim/src/lib.rs` first to defeat the cache. These are the tile numbers and
   the proof of "0 errors."
2. **Targets + levels** — the per-target status is taken from
   `docs/verus-proofs-report.md` (the authoritative current table), **not** the
   `status:` fields in the YAML blocks of `docs/verification-recommendations.md`,
   which are known to lag (the pipeline re-derivation found VR-001 still marked
   `not_started` there). Property, score, agent, `origin`, and threat links come
   from the recommendations YAML (`id`, `origin`, `priority_score`, `property`,
   `agent`, `scoring`, `threat_references`).
3. **Threat links** — the threat ids each target traces to, from the
   recommendations `threat_references` / the threat model.

Because the YAML `status` is unreliable, the generator treats
`verus-proofs-report.md` as the status oracle and the YAML as the metadata
source, and it **flags any target whose YAML status disagrees with the report**
rather than silently picking one (this is the same drift the
`ai-verification-update` agent catches).

Implementation: a Rust `xtask` subcommand (the repo already has an `xtask`
crate) is the best fit — it runs in the repo's own toolchain, can shell out to
the `make` targets, and needs no extra language runtime in CI. A standalone
Python script (as the prototype is) is the cheaper alternative if `xtask`
integration is not wanted.

### 4.3 The renderer

Emits a **self-contained** `verification-dashboard.html`: inline CSS and JS, no
external assets, no network. Opens by double-click. Contents:

- **Header:** generation timestamp + the snapshot caveat.
- **Count tiles:** esdk / prim / verification-models, each showing `N verified,
  0 errors` and the command that produced it.
- **Level tiles:** how many targets sit at each level.
- **Origin filter:** All / Threat-driven / **Capability-driven** buttons.
- **Target table:** one row per target — id, origin badge, linked threat(s),
  property, colour-coded **level chip**, evidence file, score, honest notes
  (where a target splits across levels, the split is spelled out here).
- **Footer:** restates the ladder and the snapshot caveat.

## 5. Where it lives and how it runs

- Output: `docs/verification-dashboard.html` + `docs/verification-status.json`
  (co-located with the other verification docs).
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

1. **Generator language:** Rust `xtask` subcommand (fits the repo build, no
   extra runtime) vs a standalone Python script (cheaper, matches the
   prototype). Recommend `xtask` for the production version.
2. **Commit the generated HTML/JSON, or generate-on-demand only?** Committing
   lets readers open it with no toolchain; it also adds generated files to the
   repo (the same concern as the `.docx` twins, PR #103 Q4). Recommend
   committing both, since a dashboard nobody can open is useless.
3. **CI integration** — tied to PR #103 Q2. Defer until that is answered.
4. **Scope of the target metadata** — is the current column set (origin,
   threats, property, level, evidence, score, notes) sufficient, or should it
   also show per-file verified counts, the responsible agent, or the Duvet/spec
   reference?

## 8. Build plan

The prototype proves the shape; the production version is a multi-file build
(generator + status schema + HTML renderer + `make dashboard` target) and
warrants the full plan → implement → review loop, run in a worktree (the
standing default for this project). The throwaway prototype in
`.agents/tasks/dashboard-proto/` is the reference for the rendered layout and
the JSON schema, and is discarded once the production version lands.
