---
inclusion: fileMatch
fileMatchPattern: 'verification/**'
---

# Verus verification: where the rules and the library facts live

**Library profile.** Everything specific to the library under verification (crates and paths, commands, result-line rule, spec and traceability, trust boundaries and the TCB, gate modules, target ids and done targets, maintained docs, CI checks, environment limits, packaging decisions, domain tables) is in the library profile at `.kiro/verification-profile/verification-profile.yaml`, with prose appendices next to it. Read it first. References below have the form profile `field.path`. This file holds only the generic method.

- Rules (invariants, honesty ladder, mutation testing, trusted boundary, stop and report), idioms and patterns: the `verus` skill.
- Library idioms (helper names, lint settings, per-crate decisions): profile appendix `idioms.md`.
- Commands, result line, cache bust: profile `crates[]`; standalone models: profile `models`.
- Targets and their status: profile `targets` and `artifacts.status_oracle`.
