# Sweep 3: bug → threat / target cross-check

Repo `esdk-native-mpl`, branch `MPL-Verus`, HEAD `4807e6a`. Documentation only; nothing edited outside this folder, nothing committed.

## Result

**No gap found.** Every bug in `docs/bug-reports/` (BUG-01..BUG-09, with 05 and 07 split into a/b) maps to at least one threat in `docs/threat-model.md` and to at least one target (threat-driven or capability-driven) whose YAML block names the bug. The only bug-related hole is BUG-05(b) → TM-MPL-025 having no target, which is the known "missing target for TM-MPL-025" item and is not reported again.

## Counts

| | Count |
|---|---|
| Bug reports found in `docs/bug-reports/` | 9 files (BUG-01..BUG-09); README lists the same 9, no extra files |
| Bug items examined (05 and 07 split) | 11 (01, 02, 03, 04, 05a, 05b, 06, 07a, 07b, 08, 09) |
| Open on main 620771c | 8 (01, 04, 05a, 05b, 06, 07a, 07b, 08) |
| Fixed on main | 3 (02, 03, 09) |
| Mapped to a threat | 11 / 11 |
| Mapped to a target | 11 / 11 |
| Unmapped (no threat or no target) | 0 |

## Method

1. Listed `docs/bug-reports/` (9 BUG files + README + RECHECK). No BUG file exists that README omits.
2. Threat mapping taken from the "Bug → threat mapping" table in `docs/threat-model.md:80-94` (authoritative), compared with the TM IDs each bug report cites (`grep -o TM-MPL-0..`).
3. Target mapping: `sweep34_targets.py` (this folder) splits `01-threat-driven.md` and `02-capability-driven.md` into per-target YAML blocks and lists the `threat_references`, `capability_reference` and every `BUG-0x` string in each block. Cross-checked with `docs/verification-targets.md` §7.
4. Spot-checked the current code line each mapping relies on with `sed -n` (all matched): `hierarchical_keyring.rs:702`, `:945` (`now + self.inner.ttl`), `storm_tracking.rs:333`, `:680`; `kms_ops.rs:100-103` (MrDiscovery → `rewrite_arn_region`); `default_cmm.rs:137-138` (`.expect`); `hierarchical_keyring.rs:879` (44-byte check); `cache_entry_identifier.rs:35`; `prim/src/lib.rs:175`, `:185`, `:215`; `key_store/encryption_context.rs:95-101`; `algorithm_suite.rs:547`; `structures/encryption_context.rs:205`; `hierarchical_keyring.rs:989-995` (`elapsed <= ttl`).
5. "Verus-provable?" per `.kiro/agents/verus-capabilities.md` decision aid (categories 1a-1d, 2a-2d, 3, 4).

## Matrix

| Bug | Status | Threat(s) (threat-model.md:80-94) | Target(s) naming the bug | Verus-provable? | Evidence (target block) |
|---|---|---|---|---|---|
| BUG-01 TTL/grace/inflight overflow panic | Open | TM-MPL-018, 023 | T06 (refs 018, 022, 023) | Yes, cat 2b; expected FAIL | 01-threat-driven.md:396, :417 |
| BUG-02 PDK length not enforced | Fixed | TM-MPL-006, 023 | C04 (cat 1a) | Yes; expected VERIFY | 02-capability-driven.md:297, :319 |
| BUG-03 EC decode accepts unsorted | Fixed | TM-MPL-013 | T15 (refs 013, 017) | Yes, cat 1c | 01-threat-driven.md:860, :879 |
| BUG-04 MRDiscovery rewrites non-MRK region | Open | TM-MPL-007 | T17 (ref 007) | Yes, cat 1a; expected FAIL | 01-threat-driven.md:903, :910, :922 |
| BUG-05(a) `.expect` on ECDSA keygen | Open | TM-MPL-023 | T16 (ref 023), expected-unprovable; also 01 §4 exclusion row | Partly: "never Err" needs an unjustified axiom, so it is reported, not proved | 01-threat-driven.md:763, :774, :1253 |
| BUG-05(b) 44-59-byte EDK reaches key store | Open (likely not a bug) | TM-MPL-023, 025 | T16 (ref 023) | Yes for the length guard (cat 1a) | 01-threat-driven.md:788. TM-MPL-025 side: known missing target |
| BUG-06 cache id not injective with NUL | Open | TM-MPL-009, 010, 003 | T13 (refs 009, 010), T19 (ref 003) | Yes, cat 1a/1c; expected counterexample | 01-threat-driven.md:297, :306, :321 |
| BUG-07(a) `aes_encrypt` leaves plaintext on Err | Open | TM-MPL-015 | T26 (ref 015); also noted in T07 | Yes as buffer post-condition (`ct@ == old(ct)@` on Err); expected FAIL | 01-threat-driven.md:542, :550, :464 |
| BUG-07(b) `aes_decrypt` guard weaker than callee | Open | TM-MPL-023 | C03 (cat 2a/2d) | Yes | 02-capability-driven.md:202, :480 |
| BUG-08 dead collision branch in `build_base` | Open (informational) | TM-MPL-005 | C01(c) (cat 1c) | Yes (unreachability) | 02-capability-driven.md:80, :479 |
| BUG-09 TTL admits ttl + 1 s | Fixed | TM-MPL-010 | T14 (ref 010) | Yes, cat 1a | 01-threat-driven.md:506, :509 |

## Candidate gaps

None.

## Items judged NOT a gap

- BUG-05(b) → TM-MPL-025 has no target: this is the known "missing target for TM-MPL-025" item. BUG-05(b) itself is covered by T16 via TM-MPL-023.
- BUG-07(a) is mapped to T26, which is a known stale target. The mapping exists; T26's staleness is the known item, not a new finding.
- BUG-02, BUG-07(b), BUG-08 map only to capability-driven targets (C04, C03, C01) that carry `capability_reference` instead of `threat_references`. The threat link still exists in `threat-model.md:80-94`, and capability targets are allowed to omit threat refs by design (02-capability-driven.md:6).
- BUG-02, BUG-03, BUG-09 are fixed on main. Each keeps a target as a regression proof (C04 expected VERIFY, T15, T14), so no unmapped regression risk.
- Bug-report files cite threat IDs that differ from the threat-model map: BUG-07 report cites TM-MPL-011 (threat model: 015, 023); BUG-03 report cites 013, 017 (threat model: 013); BUG-01 report adds 022; BUG-02 and BUG-08 reports cite no TM ID. These are cross-reference inconsistencies in old reports (written at `a1e23d7`), not coverage gaps: every cited ID exists, and the threat-model table is the current mapping. Optional doc tidy-up only.
- BUG-06 severity Low in the bug report vs TM-MPL-009/010 High: already explained in the note at `threat-model.md:653`.
