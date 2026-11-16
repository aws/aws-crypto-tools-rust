# Notes: Stage 3 threat-driven refresh (01), HEAD 9955ecd

Nothing was committed or pushed. Only `docs/verification-targets/01-threat-driven.md` was modified (`git status`: ` M` for that file and `??` for this notes directory). The check `git diff --quiet HEAD -- mpl prim esdk docs/threat-model.md docs/spec-security-analysis.md docs/bug-reports docs/completeness-audit.md docs/verification-targets.md docs/verification-targets/02-capability-driven.md docs/verification-targets/04-validation.md` succeeded (no change to code or to any protected or other-step document).

## What was read

`docs/threat-model.md` (section "Impact on verification targets", TM-MPL-015, 018, 024, 025, 026 and the appendix matrix), `docs/completeness-audit.md` (G1, G2, G4-1), `docs/verification-targets/01-threat-driven.md` (whole), the scoring and routing sections of `.kiro/agents/verification-recommender.md`, `verus-capabilities.md`, the three `verus-*` agent descriptions, `02-capability-driven.md` sections 0 to 1 and 4 (for the sibling recommendation), and the spec files `branch-key-store.md`, `storm-tracking-cryptographic-materials-cache.md`, `aws-kms-hierarchical-keyring.md#ondecrypt`, `cryptographic-materials-cache.md#background-processing`, `spec/shim/shim.md`.

## Line numbers verified on HEAD (sed / grep / awk with NR)

Shim (`esdk/shims/aws-esdk-cpp/src/lib.rs`): `require_handle` :715, null check :720, `unsafe { &*ptr }` :728; `unsafe` greps: only :728, :1570, :1571, :1661. `kms_client.as_ref()` :1570, `ddb_client.as_ref()` :1571, `cache.as_ref()` :1661. `into_keyring_handle` :2059, `Box::into_raw` :2062, `.cast()` :2065. Spec annotation :2037-2054 (exception at :2050-2054). `require_handle` callers :1287, :1331, :1652, :1942, :1985. `tests.rs`: :715, :733, :746, :791, `into_keyring_handle_boxes_the_keyring` :1624 (test-only `unsafe` :1634). C++: `Keyring::adopt` `EncryptionSDK.cpp:541-547` (`from_raw` :546); header `EncryptionSDK.h:656-664`. `git diff --stat 620771c HEAD -- esdk` shows `src/lib.rs` (8 lines) as the only file under the shim's `src/` that changed; the other changes are build files and `test-server`.

Storm tracking (`mpl/src/cmc/storm_tracking.rs`): `state_locked` :239 (prune :250-255, own key skipped :251), `classify_and_mark` :264, fan-out-full `Wait { deadline: None }` :313, new-key mark :315, stale-mark error :322-323, `now + in_flight_ttl` :333, leader retake :337, `wait_for_leader` :360 (deadline check :378-382, guard :388, leader test :390-394), `within_grace_interval` :675 (`+` at :680), `put_cache_entry` :710 (inner put :721, clear :724-725), `get_cache_entry` :729 (guard and classify :739-740), builder :606 (checks :613, :616, :619, :622), defaults :115-119. Hierarchical keyring: `on_decrypt` :734, supplier call :746-748, loop :751-772, filter :752-762, attempt :764, `resolve_branch_key_id` :831, `try_decrypt_edk` :867 (guard :879, version bytes :889-894), `decrypt_edk_at_version` :901 (cache id :908, lookup :916-924, key-store read :934-938, put :947-953), `on_encrypt` read :692-696 and put :704-710, `cache_entry_within_limits` :989 (:991-994), creation time writes :701 and :944, `DefaultCmc` default :567-574.

Secrets: `local.rs` :69, :131, :166; `prim/src/ecdsa.rs` :324-326, :335, :373, :387, :391-392; `default_cmm.rs` :137-139, :148. Debug impls: `algorithm_suite.rs` :564, :612, :696; `branch_key_materials.rs` :55, :191; `beacon_key_materials.rs` :57, :191; `raw_aes_keyring.rs` :80, :241; `prim/src/error.rs` :378 (`DataKeyInfo`), :408 (struct), :410 (impl); `encrypted_data_key.rs` :147; `error/generated.rs` :271, :1064, :1591, :1596. `SharedCmm::send` `cmm/fluent_builders.rs` :168-171, :316-319; ESDK re-check `esdk/src/materials.rs` :130, :202.

G1: spec `branch-key-store.md` :530/:531, :552/:553, :573/:574, :677, :690, :692 (the audit's cites are off by one for the MUST-fail sentence, recorded as C3); code `record_from_ddb_item` :1141, `record.rs` :95, :164, `kms_ops.rs` :162, :172, `ATTR_CREATE_TIME` / `ATTR_HIERARCHY_VERSION` only at `branch_key_store.rs:711`, `:1098` and `encryption_context.rs:67`, `:77`.

TM-MPL-025: `test_keyring_memory.rs` :4, :100, :113; `esdk/src/config.rs` :35, :42; spec `aws-kms-hierarchical-keyring.md` :236-249 ("one at a time" :242); test fixtures `test_aws_kms_hierarchical_keyring.rs` :1306, :1764, :1998, :2192.

TM-MPL-026: four `main.rs` bind lines, `Cargo.toml:6` `publish = false` in all four, `handlers.rs:137-147`, `:425-430`.

## Scoring evidence

- T21 gap: grep over `mpl/src` and `mpl/tests` and `esdk/tests` for `poison` found only lock-error messages in `mpl/src` (`local.rs`, `storm_tracking.rs`, `error/generated.rs`); no test. `test_storm_tracking_cmc.rs` has 33 `async fn`/`fn test_*` items; the tests named in the doc were read (:699-742, :1021-1040). Decision 0.7 → 0.8 recorded in the doc with the reasoning. The result equals an earlier draft's value (2.24) but was derived from the test list.
- T27: gap 0.9 (tests exist but cannot detect), feasibility 0.7 and severity 2 from the TM-MPL-025 rating (Medium, Medium), blast radius 3 with reasoning in the doc; 3.78 equals the earlier draft, again derived from evidence. Agent verus-zero-panic (loop-bound and termination slice; routing per `verus-capabilities.md` category 2).
- T25, T26, T02: gap kept (reasons in the doc, Refresh section).

## Checker runs (scripts in this directory)

- `python3 check_scores.py`: all 01 blocks recompute (`T27 2 x 0.9 x 0.7 x 3 = 3.78`, `T21 2 x 0.8 x 0.7 x 2 = 2.24`); the only PROBLEMS are in the merged doc (T27 missing in §1 and §3; T21 1.96 vs 2.24 and gap 0.7 vs 0.8), which a later step must fix.
- `python3 check_citations.py` (saved as `baseline-citations.txt` before editing and `after-citations.txt` after): the non-OK counts rise because the new text has many bare `:LINE` continuations that the script resolves against the wrong file (for example `lib.rs` to `mpl/src/lib.rs`). I did not rely on it for the new lines. Instead a second script extracted every explicit `path:line` citation on the added lines (`added-lines.txt`, 355 lines from `git diff -U0`) and printed the source line; every line was read and matched, and the bare continuations were checked with `awk 'NR==..'` as listed above.
- `python3 check_fn_defs.py` (`baseline-fndefs.txt`, `after-fndefs.txt`): the new DEF-MISMATCH lines are intended (T22's Debug impl lines versus the type definitions, the history cite `into_keyring_handle :2054` in the change table, and prose words such as `check` or `call`). No new mismatch for a real function name.
- YAML: every block in 01 parsed with Ruby `YAML.safe_load`: 26 of 27 parse. The T08 block failed to parse before my edit (unquoted colon in `former_target`), unchanged.
- `grep` for `001..024`, `25 active`, `24 threat` in 01: only the intentional "now says" sentence remains.
- Format check: no HTML, Mermaid, emoji or footnotes were added; GitHub-flavored tables and fenced YAML only.

## Deviations from the instructions and open points

- The brief says to add G1 "to any MUST index in the doc". 01 has no MUST index; it lives in `docs/spec-security-analysis.md:327`, which is protected. Listed in `scores.md` section 5.
- The brief's spec cites for G1 (`~:530, :552, :573`) are off by one for the MUST-fail sentence; both sets are in the doc (C3).
- T02's G1 clause is stated as part of the Ok/Err iff with a "FAILS today" marker, and the doc says the check could live in `record_from_ddb_item` instead; this is an owner decision.
- The T21 and T27 numbers, T27's blast radius of 3 and the T21 gap are judgments; the evidence is in the doc so a reviewer can change them.
- No authentication or access errors occurred.
