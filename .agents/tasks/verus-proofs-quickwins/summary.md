# Verus quick wins: update note

Repo `esdk-native-mpl`, HEAD `66aba1c`. Verus 0.2026.07.12.0b42f4c. Full write-up: `verus-proofs/README.md`.

## What was done
Three Verus proofs were written and documented. Each is a proof about a hand-written model of the shipped Rust, not about the shipped code. Nothing under `mpl/`, `prim/`, `esdk/` or `docs/` was changed. Nothing was committed or pushed. `git status` shows only the untracked `verus-proofs/` and `.agents/tasks/verus-proofs-quickwins/`.

## Status per target

| ID | Target | File | Result line | Status |
|---|---|---|---|---|
| T02 | VR-2026-T02 / TM-MPL-005 | `verus-proofs/t02_record_reconstruction.rs` | `verification results:: 21 verified, 1 errors` | Partly proved |
| C01 | VR-2026-C01 / capability 1c | `verus-proofs/c01_ec_roundtrip.rs` | `verification results:: 40 verified, 0 errors` | Proved (model level, under hypotheses A_ITER, and A_DDB/A_NAME for `theorem_prod_*`) |
| C02 | VR-2026-C02 / capability 2d | `verus-proofs/c02_sign_fixed_len.rs` | `verification results:: 21 verified, 0 errors` | Proved (model level) |

Logs: `.agents/tasks/verus-proofs-quickwins/logs/`. I re-ran all three files on writing the README and got the same result lines.

## Findings
- **G1 confirmed.** The record reconstruction does not enforce `create-time` or `hierarchy-version`. The one failing obligation in T02, `lemma_g1_spec_soundness_FAILS`, states the spec property and was left unweakened. Shipped builders always write both fields, so honest writers are unaffected. Impact is low.
- **BUG-08 is dead code, harmless.** The collision branch fires only if `custom.iter()` repeats a key, which a `BTreeMap` never does. That last step is an assumption (A_ITER), not proved.
- **Empty `branch-key-id`.** Rejected by the builder and required by the spec, but missing from the T02 YAML property.
- **Version not checked as UUID v4.** The spec requires it. The code accepts any non-empty string.
- **No defect in `sign_fixed_len`.** At most 128 calls, no partial write. It has no internal length check, but both callers run one first.

## Open items
1. Review the correspondence tables in the three file headers. They are the only link between model and code.
2. Decide G1: enforce in `record.rs` or in `record_from_ddb_item`. Then T02 can move to Proved.
3. Add non-empty `branch-key-id` to the T02 YAML `formal_spec`.
4. Decide on the UUID v4 check for the branch key version.
5. C01's production-pair theorems rely on A_DDB and A_NAME (DynamoDB returns what was written; same logical name). These are not checkable from this crate.
6. The orchestrator records proof status in `docs/verification-targets*.md` after review. I did not edit those files.
7. Closing the model-to-code gap needs code changes or vstd specs. See the README, per target. C02 is the cheapest to close.
