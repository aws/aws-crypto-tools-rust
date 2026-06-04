# Annotation Accuracy Review: commitment-policy

**Round:** 2 (fix verification)
**Spec:** `spec/framework/commitment-policy.md`
**Files reviewed:** `mpl/src/commitment_policy.rs`, `mpl/src/client.rs`, `mpl/src/error.rs`, `mpl/src/lib.rs`, `mpl/tests/test_mpl_client.rs`

## Quote Accuracy: PASS

All `//# ` lines match the compliance TOML `quote` fields character-for-character. Verified:
- 2 implementation annotations (supported-format-commitment-policy-enum, supported-commitment-policy-enum)
- 2 test annotations (same requirements)
- 12 todo annotations (behavioral MUSTs across 4 policy sections)

## Paths: PASS

All annotations use `spec/framework/commitment-policy.md#<section>` — matches the `.duvet/config.toml` registered spec path. No `specification/` or `aws-encryption-sdk-specification/` prefixes found. No explicit `type=implementation` written (correctly omitted as default).

## Placement — Error Conditions: PASS

No error-condition annotations in scope (the validation in `build()` is not annotated with a spec requirement — it's application-level logic, not spec-mandated).

## Placement — Positive Behavior: PASS

- `supported-format-commitment-policy-enum` annotation at line 7 is directly above the `EsdkCommitmentPolicy` enum definition — the enum IS the "provision" of the ENUM. ✅
- `supported-commitment-policy-enum` annotation at line 32 is directly above the `CommitmentPolicy` union enum definition. ✅

## Placement — General Behavior: PASS

Both implemented annotations are "general behavior" type (defining/providing an enum). Both are correctly placed at the top of their respective enum definitions.

## Placement — Sub-Items: PASS

N/A — the two implemented requirements don't have sub-item lists.

## Placement — Ordered Structures: PASS

N/A — no "MUST consist of, in order" requirements in this spec section.

## Placement — Module-Level Cross-Refs: PASS

No `type=implication` annotations found. The two implementation annotations are module-level above enum definitions — appropriate for "MUST provide an ENUM" requirements where the definition IS the implementation.

## Placement — Context-Reset: PASS

Context-reset evaluation for each annotation:
1. Line 7-9 → next code: `#[derive(...)] pub enum EsdkCommitmentPolicy { ... }` — immediately obvious this IS providing the ESDK commitment policy enum. ✅
2. Line 32-35 → next code: `#[derive(...)] pub enum CommitmentPolicy { Esdk(...), Dbe(...) }` — immediately obvious this IS providing the union enum. ✅
3. Test annotations → followed by code instantiating all enum variants and asserting distinctness. Connection is self-evident. ✅

## Cross-References: 0/0

The two implemented requirement quotes contain no markdown links. The 12 todo requirement quotes contain links to `cmm-interface.md` and `algorithm-suites.md` which are unimplemented specs — cross-refs not applicable for todo items.

## Formatting: PASS

- Blank lines separate unrelated annotation blocks ✅
- Todo annotations separated by blank lines from each other ✅
- No `//= reason=` lines present (none needed) ✅
- No ambiguous references ("this operation", "the above") in quoted text ✅

## Impl vs Test Count: impl=2 test=2 — PASS

Source annotations (excluding todo/tracking-issue metadata lines):
- 2 implementation annotations (default type)
- 12 todo annotations (out-of-scope behavioral MUSTs)

Test annotations:
- 2 `type=test` annotations

Balance: 2 impl, 2 test — equal coverage for in-scope requirements.

## Implication Checks: PASS

No `type=implication` annotations found in any reviewed file.

## Duvet Query: PASS

`duvet report` succeeded. Snapshot confirms:
- `supported-format-commitment-policy-enum`: `implementation,test` ✅
- `supported-commitment-policy-enum`: `implementation,test` ✅
- 1 MAY requirement uncovered (acceptable — MAY level)
- 12 behavioral MUSTs marked `todo` (intentionally out of scope this round)

## Todo Annotations: Well-formed

All 12 behavioral MUSTs are correctly structured:
- `//= spec/framework/commitment-policy.md#<correct-section>`
- `//= type=todo`
- `//= tracking-issue=commitment-policy-behavior`
- `//# <exact quote from TOML>`

Duvet recognizes all 12 (visible in snapshot as `todo` status).

## Duplicate Annotations: PASS

The `duvet_duplicates.py` script flagged 4 items as "CLEANUP NEEDED," but these are false positives. The flagged annotations have the same quote text (e.g., "MUST only support algorithm suites...") but cite DIFFERENT spec section anchors (`esdk-require-encrypt-allow-decrypt` vs `esdk-require-encrypt-require-decrypt` vs `dbe-require-encrypt-require-decrypt`). Each is a distinct requirement from a different section — not a duplicate.

## Orphaned Annotations: PASS

The 12 `type=todo` annotations at module level (end of file) have no trailing executable code, but duvet's scanner still matches them (confirmed in snapshot). This is the expected pattern for `type=todo` — they mark unimplemented requirements and don't require executable code to follow.

## Annotation Completeness: PASS

For the two in-scope MUST requirements:
- `supported-format-commitment-policy-enum` [[spec]] MUST → impl ✅ + test ✅
- `supported-commitment-policy-enum` [[spec]] MUST → impl ✅ + test ✅

The `supported-commitment-policy-enum` TOML also has a MAY requirement ("different formats MAY have duplicate...") that is uncovered. MAY-level requirements are not blocking.

## Issues

| # | Severity | Category | Description |
|---|----------|----------|-------------|
| — | — | — | No issues found |

## Result: PASS
