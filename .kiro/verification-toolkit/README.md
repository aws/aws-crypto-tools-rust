# Verus verification toolkit

A set of Kiro agents, one skill and one steering file that take a Rust library from its specification to a threat model, ranked verification targets and Verus proofs. The toolkit holds only the generic method. Everything about one library lives in that library's profile.

## Contents

| Part | Path |
|---|---|
| 9 agents | `.kiro/agents/*.md` |
| Skill | `.kiro/skills/verus/SKILL.md` |
| Steering pointer | `.kiro/steering/verus-verification.md` |
| This README | `.kiro/verification-toolkit/README.md` |
| Profile schema | `.kiro/verification-toolkit/verification-profile.template.yaml` |

The library profile is not part of the toolkit: `.kiro/verification-profile/verification-profile.yaml` plus the appendices `domain.md`, `idioms.md` and `targets.md` in the same directory.

## Layout and copy-out rule

Kiro finds agents only in `.kiro/agents/`, skills in `.kiro/skills/` and steering in `.kiro/steering/`, so the generic files stay there. To move the toolkit to another repository, copy `.kiro/agents/`, `.kiro/skills/verus/`, `.kiro/steering/verus-verification.md` and `.kiro/verification-toolkit/`. Leave `.kiro/verification-profile/` behind: it belongs to the library.

## How agents find the profile

At a fixed path from the repository root: `.kiro/verification-profile/verification-profile.yaml`. Agent markdown has no variables, so every generic file carries a short "Library profile" paragraph that names this path and says to read it first.

## Adopting the toolkit for a new library

1. Copy the toolkit files listed above into the new repository's `.kiro/`.
2. Copy the template to `.kiro/verification-profile/verification-profile.yaml`. Fill every field from the repository with grep, `ls` and the build files, never from memory. Keep the comments. If a value cannot be checked, write the closest checked statement and say so.
3. Write `domain.md` (format constants, spec topics, threat-model context), `idioms.md` (library-specific Verus idioms) and `targets.md` (one section per target, done lists, panic surface, trusted boundary, drift examples) next to the profile.
4. Set `fileMatchPattern` in the frontmatter of `.kiro/steering/verus-verification.md` to the library's proof directory. It is the one per-library value outside the profile, because Kiro frontmatter cannot read the profile.
5. Run the checks: the template and the profile have the same key set; every path in the profile and appendices exists (paths under a spec directory that is fetched on demand are listed as such); the target ids in the profile match the library's status doc.

## What the profile must contain

The template is the schema: same keys, empty values, one comment per key naming what it is and which agents read it. The top-level fields:

| Field | What it holds |
|---|---|
| `schema_version` | schema version |
| `library` | name and kind of system |
| `crates` | each crate: path, role, Verus on/off, verify command, feature sets, result-line rule, cache bust, tests, lints, unsafe |
| `models` | standalone models: path, command, status file, per-file status |
| `toolchain` | Verus, Rust and vstd pins |
| `spec` | spec location, resolver, tracked documents, standards, per-agent documents |
| `traceability` | annotation tool, config, markers, ladder level per annotation type |
| `scope` | in and out of scope, threat mindset, literature, sibling libraries |
| `components` | architecture inventory |
| `trust_boundaries` | each boundary and what it is trusted for |
| `unsafe_surface` | where `unsafe` is and the command that confirms it |
| `tcb` | trusted-spec list: owner, modules, doc section, rows, labeled assumptions, per-crate rules |
| `typestate_gates` | gate modules, tokens, targets |
| `platform_assumptions` | platform facts the proofs or tests rely on |
| `ids` | id formats, next free id and how to check it |
| `targets` | every target with the ladder level of each part |
| `do_not_redo` | proven cores per agent area |
| `artifacts` | maintained docs, status oracle, counts source, baseline lines, docx command |
| `ci` | CI checks with local commands, lockfiles that move together |
| `local_env_limits` | what cannot run locally and what follows |
| `packaging_decisions` | build and packaging choices that must stay explicit |
| `appendices` | paths of the three appendices |

Counts ("N verified") never go in the profile. The profile names the commands and the rule for reading the result line; dated numbers live only in the library's proofs report.

## Reference syntax

Generic files point at the profile as profile `crates[].verify_cmd` (dotted path; `[]` means each list entry) and at an appendix as profile appendix `targets.md` §<heading>.

## Example rule

A library literal (a crate path, a target id, a format constant) may appear in a generic file only inside a block introduced by a line that contains exactly `Example from the ESDK profile`, for example `**Example from the ESDK profile (historical):**`. Everything else library-specific goes in the profile or an appendix.
