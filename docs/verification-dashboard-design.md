# ESDK Verification Dashboard — Design

**Status:** built. `cargo xtask verification-status` writes
`docs/verification-status.json`, and the Verification page of the Crypto Tools
dashboard (`dashboard/verification/` in `aws/aws-crypto-tools-commons`) shows it.

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
        │  (cargo xtask verification-status)
        ▼
docs/verification-status.json      ← structured intermediate (the "API")
        │  (fetched by the browser)
        ▼
Crypto Tools dashboard, Verification page (aws-crypto-tools-commons)
```

### 4.1 The intermediate: `verification-status.json`

A single structured file, the contract between extraction and rendering. The
dashboard page reads **only** this — it never parses prose. Shape:

```json
{
  "generated": "2026-11-17T20:45:49Z",
  "commit": "<HEAD when generated>",
  "verus": "0.2026.07.12.0b42f4c",
  "snapshot_note": "Counts come from one Verus run at generation time. …",
  "levels": { "in_crate": "Verus proof of shipped code", … },
  "counts": [
    { "name": "esdk", "cmd": "make -C esdk verus", "unavailable": null,
      "runs": [ { "label": "default features", "verified": 69, "errors": 0 }, … ] },
    { "name": "verification_models", "cmd": "make -C verification verify",
      "unavailable": null,
      "runs": [ { "label": "body_aad_proofs.rs", "verified": 4, "errors": 0 }, … ] }
  ],
  "targets": [
    {
      "id": "VR-001",
      "title": "key commitment verification",
      "origin": "threat",
      "score": 16.0,
      "property": "…",
      "agent": "verus-header-parsing-proofs",
      "files": ["esdk/src/message/header.rs"],
      "threats": [ { "id": "E3", "category": "Elevation of Privilege", "description": "…" } ],
      "parts": [
        { "level": "in_crate", "what": "decision (a)" },
        { "level": "model_only", "what": "ordering (b)" },
        { "level": "trusted", "what": "constant time (c)" }
      ],
      "status": "<the report's Status cell>",
      "residual": "<the report's Residual cell>",
      "yaml_status": "not_started",
      "drift": "verification-recommendations.md says `not_started`, but the report gives in_crate, model_only, trusted."
    }
  ]
}
```

A count with `runs: null` could not be read, and `unavailable` says why.

Keeping this as a committed artifact gives three things: the page stays dumb,
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
2. **Targets + levels** — the per-target levels are taken from the Levels
   column of the target table in `docs/verus-proofs-report.md` (the
   authoritative current table), **not** the
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

Implementation: the `verification-status` subcommand of the repo's `xtask`
crate. It runs in the repo's own toolchain and shells out to the `make` targets.

### 4.3 The renderer

The Verification page of the Crypto Tools dashboard
(`dashboard/verification/index.html` in `aws/aws-crypto-tools-commons`). Like
the dashboard's other pages, it reads `docs/verification-status.json` from this
repo through the GitHub API in the browser, from `main` or from a pasted PR.
Contents:

- **Header:** generation time, commit, Verus version and the snapshot caveat.
- **Count cards:** esdk / prim / verification models, each showing `N verified,
  M errors`, the command that produced it, and each run.
- **Level legend:** how many targets have a part at each level.
- **Origin filter:** All / Threat-driven / Capability-driven.
- **Target matrix:** one row per target, one column per level. A cell names the
  part of the target proven at that level, so a split target shows its split.
- **By file:** for each `.rs` file under `esdk/src` and `prim/src`, how many
  fn lines Verus checks. `xtask/src/proof_coverage.rs` reads which code is
  inside `verus!` and sorts each line into proven (has `requires`/`ensures`),
  no panic only, spec and proof, trusted (`external_body`,
  `assume_specification`) or not checked. Click a file to see its source with
  each line colored. This is read from the source, not from running tests.
- **Detail pane:** property, status, residual scope, files, threats and any
  YAML drift note for the clicked target.

## 5. Where it lives and how it runs

- Output: `docs/verification-status.json`, committed so the dashboard can read
  it with no toolchain.
- Trigger: `cargo xtask verification-status`, run locally with Verus installed
  at `~/verus` (the version the report names).
- Later, optional: a CI job. It depends on PR #103 Q2 (whether the Verus
  toolchain runs in CI); until that is decided, the JSON is regenerated locally.

## 6. Honesty and staleness rules

- Every count is from a **live run** at generation time, cited with its command;
  never inferred from code, never hand-edited in the JSON.
- The JSON records `generated` and a snapshot note; the page shows both. The
  dashboard never implies the numbers are live.
- If the generator cannot run the `make` targets (no Verus toolchain), it must
  **fail or clearly mark counts as unavailable**, not fall back to stale numbers.
- Level is taken from the report oracle; YAML/report disagreements are surfaced,
  not hidden.
- The dashboard inherits the no-overclaim rule: it must not present a
  model-only, compiler/clippy, or trusted result as a Verus proof of shipped
  code.

## 7. Open questions

1. **CI integration** — tied to PR #103 Q2. Defer until that is answered.
2. **Scope of the target metadata** — is the current column set (origin,
   threats, property, level, evidence, score, notes) sufficient, or should it
   also show per-file verified counts, the responsible agent, or the Duvet/spec
   reference?
