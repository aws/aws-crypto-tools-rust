# Sweep 4: threat → target and target → threat cross-check

Repo `esdk-native-mpl`, branch `MPL-Verus`, HEAD `4807e6a`. Documentation only; nothing edited outside this folder, nothing committed.

## Result

One candidate gap: **TM-MPL-026 has no target and no out-of-scope row** in `docs/verification-targets.md` §6 (or in `01-threat-driven.md` §4 / §6). Every other threat has a target or an explicit exclusion, apart from the known TM-MPL-025 item. No dangling references: every threat ID and capability category cited by the 32 active targets exists, and no active target depends on retired T08 or C06.

## Counts

| Check | Examined | Mapped | Unmapped |
|---|---|---|---|
| (a) Threats TM-MPL-001..026 → target or §6 exclusion | 26 | 24 (22 with an active target, 2 fully excluded: 019, 020) | 2: TM-MPL-025 (known, not reported) and **TM-MPL-026 (candidate gap)** |
| (b) Active targets → existing threat or capability reference | 32 (25 T, 7 C) | 32 | 0 dangling |
| (b) References to retired targets (T08, C06) from active targets | 32 | n/a | 0 |

## Method

- Threat IDs: `grep -o 'TM-MPL-0[0-9][0-9]'` per document. `threat-model.md` defines 001..026 (STRIDE tables `:261-309`). `verification-targets.md` and `01-threat-driven.md` mention only 001..024; `02-capability-driven.md` mentions only 010 (inside retired C06).
- Targets: `sweep34_targets.py` (this folder) splits `01-threat-driven.md` and `02-capability-driven.md` into per-target YAML blocks and extracts `threat_references` IDs, `capability_reference`, bug mentions and `VR-2026-*` dependencies.
- Capability categories checked against `.kiro/agents/verus-capabilities.md` headings (1a-1d `:41-57`, 2a-2d `:68-80`, 3a-3c, 4a-4b).
- Exclusions read from `verification-targets.md` §6 (points to 01 §4) and `01-threat-driven.md:1225-1294` (§4 exclusions, §6 accounting).

## (a) Threat → target matrix

| Threat | Rating (TM §7) | Active target(s) (from YAML threat_references) | §6 / 01 §4 exclusion | Status |
|---|---|---|---|---|
| TM-MPL-001 | Low | T20, T24 | Partial | OK |
| TM-MPL-002 | Medium | T01, T03 | Partial | OK |
| TM-MPL-003 | Low | T19 | Partial | OK |
| TM-MPL-004 | Medium | T11 | Partial | OK |
| TM-MPL-005 | High | T01, T02 | Partial | OK |
| TM-MPL-006 | Medium | T09 | Partial | OK |
| TM-MPL-007 | Medium | T17 | Partial | OK |
| TM-MPL-008 | Medium | T09 | Partial | OK |
| TM-MPL-009 | High | T13 | Partial | OK |
| TM-MPL-010 | High | T13, T14 | Partial | OK |
| TM-MPL-011 | Medium | T07, T20 | Partial | OK |
| TM-MPL-012 | Medium | T04 | Partial | OK |
| TM-MPL-013 | Medium | T10, T15 | Partial | OK |
| TM-MPL-014 | Medium | T05 | Partial | OK |
| TM-MPL-015 | Low | T26 | Partial | OK (T26 staleness is known) |
| TM-MPL-016 | Low | T18 | Partial | OK |
| TM-MPL-017 | Medium | T12, T15 | None (fully targeted) | OK |
| TM-MPL-018 | Medium | T06, T21 | Partial | OK (T21 staleness is known) |
| TM-MPL-019 | Medium | — | Fully excluded (process/Duvet) | OK |
| TM-MPL-020 | Low | — | Fully excluded (operational) | OK |
| TM-MPL-021 | Low | T22 | Partial | OK |
| TM-MPL-022 | Low | T06, T23 | Partial | OK |
| TM-MPL-023 | Low | T06, T16, T20 | Partial | OK |
| TM-MPL-024 | Medium | T25 | Partial | OK (T25 staleness is known) |
| TM-MPL-025 | Medium (provisional) | — | — | Known item, not reported |
| TM-MPL-026 | Low | — | — | **Candidate gap** |

## (b) Target → reference check

| Target | Reference(s) | Exists? |
|---|---|---|
| T01 | TM-MPL-002, 005 | yes |
| T02 | TM-MPL-005 | yes |
| T03 | TM-MPL-002 (dep T11) | yes |
| T04 | TM-MPL-012 (deps T05, T10) | yes |
| T05 | TM-MPL-014 | yes |
| T06 | TM-MPL-018, 022, 023 | yes |
| T07 | TM-MPL-011 (mentions T20) | yes |
| T09 | TM-MPL-006, 008 (mentions C07) | yes |
| T10 | TM-MPL-013 (mentions T15) | yes |
| T11 | TM-MPL-004 | yes |
| T12 | TM-MPL-017 | yes |
| T13 | TM-MPL-009, 010 | yes |
| T14 | TM-MPL-010 (mentions T13) | yes |
| T15 | TM-MPL-013, 017 | yes |
| T16 | TM-MPL-023 | yes |
| T17 | TM-MPL-007 | yes |
| T18 | TM-MPL-016 (mentions T01) | yes |
| T19 | TM-MPL-003 (mentions T13) | yes |
| T20 | TM-MPL-001, 011, 023 | yes |
| T21 | TM-MPL-018 (mentions T06) | yes |
| T22 | TM-MPL-021 | yes |
| T23 | TM-MPL-022 | yes |
| T24 | TM-MPL-001 | yes |
| T25 | TM-MPL-024 | yes |
| T26 | TM-MPL-015 | yes |
| C01 | cap 1 (1c, 1b) (dep T02) | yes |
| C02 | cap 2 (2d) | yes |
| C03 | cap 2 (2a, 2d) | yes |
| C04 | cap 1 (1a) | yes |
| C05 | cap 1 | yes |
| C07 | cap 1 (1a, 1b) | yes |
| C08 | cap 2 (2b) | yes |

Retired-target references: `T08` and `C06` appear only in retirement rows and in their own retired blocks (`verification-targets.md:13`, `:24-27`, `:74-77`; `01-threat-driven.md:12-13`, `:76`, `:564`, `:1210`, `:1283`, `:1294`; `02-capability-driven.md:13`, `:51`, `:419`, `:486`). T26 says it "replaces T08", which is a history note, not a dependency. No active target lists T08 or C06 in `dependencies`.

## Candidate gaps

### G4-1: TM-MPL-026 has no target and no out-of-scope reason in the verification-targets documents

- Type: missed target / missing exclusion (threat with neither).
- Severity guess: Low (threat is rated Low, test-only; doc gap only).
- Evidence:
  - The threat exists: `threat-model.md:36` (new, Low), `:309` (EoP table: "Unauthenticated loopback test server exercises ambient AWS credentials for any local process"), `:469`, `:542`, `:628`.
  - `grep TM-MPL-026` in `docs/verification-targets.md` and `docs/verification-targets/*.md`: no match. `verification-targets.md` header says its input is "TM-MPL-001..024"; §6 names only TM-MPL-019 and 020 as fully excluded; `01-threat-driven.md:1294` accounts for "All 24 threat IDs TM-MPL-001..024".
  - The threat model itself says no target is needed (`threat-model.md:651`: "TM-MPL-026 (test-only; no target needed)"), but that reason is not carried into verification-targets §6.
  - Code check: `mpl/test-server/src/main.rs:24-25` binds `127.0.0.1` with no auth layer, consistent with the threat text.
- Verus-provable? No. Per `verus-capabilities.md` "Provable vs. Not-Here", authentication policy, ambient credentials and which hosts run the server are deployment/operational, not a code invariant. "Bind address is loopback" is a trivially checkable constant and not worth a target.
- Suggested resolution (not applied): add a "Fully excluded" row for TM-MPL-026 to `01-threat-driven.md` §4 / §6 and `verification-targets.md` §4 / §6 (reason: test-only, operational; mitigation is running on hosts without production credentials, `threat-model.md:555`), and update the "001..024" totals. This sits next to the known TM-MPL-025 item and can be done in the same refresh.

## Items judged NOT a gap

- TM-MPL-025 with no target: known item.
- T21, T25, T26 citing TM-MPL-018 / 024 / 015 with stale scope (missing second-pass sub-surfaces from `threat-model.md:645-651`): known items. Their threat IDs still exist, so they are not dangling.
- TM-MPL-019 and 020: fully excluded with reasons in `01-threat-driven.md:1231-1232`, referenced from `verification-targets.md` §6.
- Capability targets (C01-C05, C07, C08) with empty `threat_references`: by design (`02-capability-driven.md:6`); each has a `capability_reference` category that exists in `verus-capabilities.md`.
- C06's block mentions TM-MPL-010: the target is retired, and the ID exists anyway.
- `verification-targets.md` §4 STRIDE table counts 24 threats: stale in the same way as the known TM-MPL-025 item and G4-1; not a separate gap.
