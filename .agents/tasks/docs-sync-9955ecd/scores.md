# Stage 3 threat-driven refresh: scores and changes (HEAD 9955ecd)

Source: `docs/verification-targets/01-threat-driven.md` (edited, not committed). Formula: `Severity × Coverage_Gap × Feasibility × Blast_Radius`, conventions of that doc's section 1. No threat rating changed; `mpl/`, `prim/` are unchanged from main `620771c`; `esdk/` differs only by #188 and #189.

## 1. Targets whose score, text or status changed in 01

| ID | Threat refs | Severity | Coverage gap | Feasibility | Blast radius | Score | Change |
|---|---|---|---|---|---|---|---|
| T27 (new) | TM-MPL-025 (+ TM-MPL-018 link) | 2 | 0.9 | 0.7 | 3 | **3.78** (2 × 0.9 × 0.7 × 3) | New target: key-store calls and loop iterations per decrypt are bounded by the EDK list (verifies); no constant bound exists (expected FAIL). Agent verus-zero-panic, 1 week. Provisional: TM-MPL-025 is unconfirmed until a reproducer exists |
| T21 | TM-MPL-018 | 2 | 0.7 → **0.8** | 0.7 | 2 | 1.96 → **2.24** (2 × 0.8 × 0.7 × 2) | Properties (g) stale in-flight mark never cleared, (h) fan-out-full waiter has no deadline, (i) panic under the state lock poisons it added; all expected FAIL. Gap recomputed from the test list (see 01, Refresh section) |
| T25 | TM-MPL-024 | 3 | 0.6 | 0.4 | 2 | 1.44 (3 × 0.6 × 0.4 × 2), unchanged | Citations moved by #188 (`lib.rs:1564-1565` → `:1570-1571`, `:1655` → `:1661`, `into_keyring_handle` `:2054` → `:2059`). Scope adds the type-erased `Keyring::adopt` path. Rust-provable: non-null unique `Box` from `into_keyring_handle`. Outside the proof: C++ `from_raw` with no null, type or ownership check (type confusion, double free) |
| T26 | TM-MPL-015 | 2 | 1.0 | 0.4 | 4 | 3.20 (2 × 1.0 × 0.4 × 4), unchanged | Adds F4 (expired `LocalCmc` entries resident until read: `cmc/local.rs:69`, `:131`, `:166`) and F5 (`ecdsa_generate_keypair` leaves the private-key `Vec` un-wiped on the error return: `prim/src/ecdsa.rs:387`, `:391-392`). Rank 10 → 11 |
| T02 | TM-MPL-005 | 4 | 0.6 | 0.7 | 4 | 6.72 (4 × 0.6 × 0.7 × 4), unchanged | G1: spec clause "record MUST include `create-time` and `hierarchy-version`; otherwise MUST fail" added to property, formal spec and trace (expected FAIL). No new target. Still the only quick win |
| T06 | TM-MPL-018, 022, 023 | 2 | 1.0 | 0.7 | 3 | 4.20, unchanged | Text only: after a panic under the storm-tracking lock the consequence is a persistent `Internal` error |
| T14 | TM-MPL-010 | 3 | 0.6 | 0.7 | 3 | 3.78, unchanged | Text only: a creation time in the future counts as fresh (`hierarchical_keyring.rs:991-994`) |
| T19 | TM-MPL-003 | 2 | 0.6 | 0.4 | 4 | 1.92, unchanged | Text only: supplier input on decrypt is the unauthenticated message EC |
| T22 | TM-MPL-021 | 2 | 0.5 | 0.4 | 4 | 1.60, unchanged | Text only: `NoMatchingDataKey` exposes provider info via `Debug` and `encrypted_data_keys()`; ciphertext excluded; `Debug` citations moved to impl lines |
| T09 | TM-MPL-006, 008 | 4 | 0.4 | 0.4 | 4 | 2.56, unchanged | Text only: `SharedCmm::send()` checks completeness only (`cmm/fluent_builders.rs:168-171`, `:316-319`) |
| T01, T03 | TM-MPL-005, 002 | 4, 4 | 0.8, 0.8 | 0.7, 0.4 | 4, 4 | 8.96, 5.12, unchanged | Text only: rollback of an authentic record is a non-goal (T01, T02); T03 notes that Discovery on the encrypt path is out of its pinned-mode scope |

Ranks after the refresh (26 active, T08 retired): T01 8.96, T02 6.72, T03 5.12, T04 4.48, T13 4.41, T05 4.32, T06 4.20, T07 3.84, T14 3.78, **T27 3.78 (rank 10)**, T26 3.20 (11), T10 2.88, T11 2.88, T12 2.88, T09 2.56, T16 2.24, **T21 2.24 (17)**, T15 1.92, T17 1.92, T18 1.92, T19 1.92, T20 1.68, T22 1.60, T25 1.44, T23 1.26, T24 1.20. Ties are broken by higher severity, then ID (T14 before T27; T16 before T21). Quick win (score > 6.0 and effort ≤ 1 week): T02 only.

## 2. Out-of-scope rows added or changed (01, section 4 and section 6)

| Threat | Row | Change |
|---|---|---|
| TM-MPL-026 | **Fully excluded** (added) | Loopback test servers (four crates, `127.0.0.1`, no auth, ambient AWS credentials; `mpl/test-server/src/main.rs:26-27`, `handlers.rs:137-147`, `:425-430`). Reason: test-only, `publish = false`, operational control; Risk Low. Section 6 row added |
| TM-MPL-025 | Partial (→ T27) (added) | Excluded: wall-clock time per request, DynamoDB capacity and KMS cost, the choice of bound. Reason: performance and operations, owner decision; threat unconfirmed |
| TM-MPL-024 | Partial (→ T25) (changed) | Adds C++ `Keyring::adopt` (`EncryptionSDK.cpp:541-547`) to the excluded part; header contract `EncryptionSDK.h:656-663` |
| TM-MPL-005 | Partial (→ T01, T02) (changed) | Rollback of an older authentic ACTIVE record made specific (plain `GetItem`, no consistent read, no highest-version memory) |
| TM-MPL-015 | Partial (→ T26) (changed) | Adds the `aws-lc-rs` DER buffer to the excluded third-party internals |
| TM-MPL-018 | Partial (→ T21, T06) (changed) | Notes that (g), (h) are stated over the pure classify step; their reproducer is a concurrency test |

"TM-MPL-001..024" now reads "001..026" everywhere in 01. Section 6 totals: 26 threats; 23 with an active target, 3 fully excluded (019, 020, 026), 1 fully targeted (017), 22 partial.

## 3. Corrections found while citing (01, section 5, C3 to C5)

- C3: the audit's `branch-key-store.md:530`, `:552`, `:573` are the "MUST contain the fields" sentences; the "MUST fail" sentences are `:531`, `:553`, `:574`. Record Format: `:677`, `create-time` `:690`, `hierarchy-version` `:692`.
- C4: `lib.rs:2037-2054` annotates `shim.md#adopting-custom-implementations`, but `spec/shim/shim.md` has no such heading (the text is under "Custom implementations of core-library interfaces", `:180-204`).
- C5: the threat model's `prim/src/error.rs:406-409` is the doc comment and struct line; the `Debug` impl is `:410`.

## 4. Recommendation: capability-driven sibling for the storm-tracking builder

Question: does `StormTrackingCmcBuilder::build` no longer enforcing the spec's Inflight TTL ≤ Grace Period, Grace Interval ≤ Grace Period and "at least 1" bounds justify a capability-driven (C) sibling of T21?

**Recommendation: no. Keep it as T21 (a).** Evidence:

1. The property is already a target. T21 (a) states the exact `build` Ok/Err characterization including the missing constraints, marked expected FAIL. `02-capability-driven.md:445` already lists "`StormTrackingCmcBuilder::build` constraints; grace formulas" as fully overlapped by T21, and 02's rule is that candidates already scoped by Step 1 are listed, not re-issued. A sibling would restate the same pure function, spec text and agent.
2. Code against spec. The spec requires Grace Interval ≤ Grace Period and Inflight TTL ≤ Grace Period (`storm-tracking-cryptographic-materials-cache.md:136-137`) and at least 1 for each (`:59`, `:71`, `:92`). `build` enforces only fan_out ≥ 1 (`storm_tracking.rs:613`), in_flight_ttl > 0 (`:616`), sleep > 0 (`:619`) and Grace Interval ≤ Inflight TTL (`:622`, spec `:138`). `test_durations_are_stored_exactly` (`test_storm_tracking_cmc.rs:388`) accepts `grace_period = 0`.
3. The bound is not yet well defined. The spec's own defaults break its ordering (Inflight TTL 20 s > Grace Period 10 s); the code uses 10 s on purpose (`storm_tracking.rs:117-119`). "At least 1" is in the configured Time Unit (Seconds or Milliseconds, spec `:114-122`), while the code takes a `Duration` and tests accept sub-second values (`test_sub_second_grace_period_is_honored` :283). A proof needs the owner to choose the minimum first; T21 (a) keeps `MIN` symbolic.
4. A sibling would not change the order of work. Under the 02 conventions it would score 2 × 0.9 × 0.7 × 2 = 2.52 (gap 0.9 because the tests encode the regressed contract), far below the 6.0 quick-win threshold, and it would not address BUG-01, which needs upper bounds (T06), not lower bounds.

What is worth doing instead (no new ID): the 02 overlap row for `StormTrackingCmcBuilder::build` can add that (a) is expected FAIL and is a cheap slice (about a day) of the one-month T21. That edit belongs to the step that refreshes 02.

## 5. Open items for later steps (not done here)

- `docs/verification-targets.md` (merged): `check_scores.py` reports 4 problems, all caused by this refresh: active T27 missing from §1 and §3, T21 score 1.96 ≠ 2.24 and gap 0.7 ≠ 0.8. Ranks of T26 and below shift by one. Header line 4 says "T01..T26" and "001..024"; the §4 STRIDE table counts 24 threats (audit G4-1).
- `docs/verification-targets/02-capability-driven.md`: overlap rows for T21, T26 and T25 (and a possible row for T27) should follow 01.
- `docs/spec-security-analysis.md` ("MUST index by spec section", `:327`): add the G1 clause as a "U" row. Not edited here (rule).
- Pre-existing, not changed: the T08 YAML block in 01 does not parse (an unquoted colon in `former_target`); the other 26 blocks parse.
