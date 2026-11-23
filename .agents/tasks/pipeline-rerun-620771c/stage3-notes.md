# Stage 3 working notes — verification-target refresh for main 620771c

Step: Stage 3 (verification-recommender) of the pipeline re-run. Previous run analyzed a1e23d7.
Rules followed: docs only; nothing under `mpl/`, `prim/`, `esdk/` written; nothing committed or pushed.
Tooling: no shell in this step. All `grep -n` / `sed -n` equivalents were done with the IDE text search (line-numbered hits) and offset file reads. `git diff --quiet` could not be re-run here (scope.md recorded exit 0 at the end of the scoping step).

## Inputs read

- `.agents/tasks/pipeline-rerun-620771c/scope.md` (path map, bug status, test deltas, CVE).
- `docs/threat-model.md` (TM-MPL-001..024; 009/010 Likelihood → Medium; 015 Severity → Medium; new 024; none retired).
- `docs/spec-security-analysis.md` (searched for target-relevant notes: storm-tracking `from_raw` contract change, secret-lifetime residuals, remaining panics).
- Previous `docs/verification-targets.md`, `01-threat-driven.md`, `02-capability-driven.md`, `04-validation.md`.
- Methodology files in `.kiro/agents/` were already summarized in the step prompt; scoring rules taken from `verification-recommender.md` as embedded in the agent instructions.

## Code facts verified on HEAD (this step)

- `\bunsafe\b` in `mpl/src/**`, `prim/src/**`: no match. Old zeroize loop gone; `PlaintextDataKey` `#[derive(Clone, Zeroize, ZeroizeOnDrop)]` at `algorithm_suite.rs:505`.
- `//=` in `mpl`/`prim` src+tests: only `mpl/src/cmc/entry.rs:201-203` (+ `//#` :205).
- Hierarchical keyring: builder `build` :535, `ttl.is_zero()` :547, grace check `grace_period >= ttl` :585 (Duration; integer division gone → C06 retired), partition id :595-599, `generate_partition_id` :626, `on_encrypt` :654, cache id :665, `now + self.inner.ttl` :702 / :945, `on_decrypt` :734, `add_data_key(PlaintextDataKey::new(..))` :767 (BUG-02 fix path), `try_decrypt_edk` :867 → `decrypt_edk_at_version` :901, `cache_entry_within_limits` :989 (`elapsed <= ttl` :994, BUG-09 fixed), `as_branch_key_materials` :1000.
- `branch_key_wrap.rs`: `compute_aad` :61, `uuid_str_to_16_bytes` :92, `derive_branch_key` :122 (Zeroizing :125/:135), `wrap` :157, `unwrap` :230, 60-byte guard :236 (threat model says :240 — discrepancy noted in 01 §5).
- `kms_ops.rs`: `resolve_key_store_arn` :88, Discovery :96-98, MrDiscovery :100-102 (BUG-04: no `mrk-` check), compat :105, error kind `Kind::Validation`, `reject_alias_arn` :118, `rewrite_arn_region` :144, `decrypt_branch_key` :162 (auth EC :170, resolve :179, key_id :183).
- `branch_key_store.rs`: impl `KeyStore for Builtin<DynamoDbKeyStore>` :432; `build_auth_ec` :132; `create_key` :539; `version_key` :641 (inline EC derivation :706-722; index `new_decrypt_only_ec[ATTR_TYPE]` :719; conditions :743, :752); `get_active_branch_key` :792; `get_branch_key_version` :827; `get_beacon_key` :868; `item_from_ec_and_enc` :1089; `record_from_ddb_item` :1141. Client `.expect`s removed (:101-108 return refs).
- `record.rs`: `encryption_context_from_item` :37 and `to_attribute_map` :61 are now `#[cfg(feature = "test-utils")]`; reconstruction :95, Zeroizing :100/:173.
- `storm_tracking.rs`: `StormTrackingCmcBuilder::build` :606 checks only fan_out :613, in_flight_ttl :616, sleep :619, grace_interval ≤ in_flight_ttl :622 (spec ordering vs grace_period gone); `now + in_flight_ttl` :333; `within_grace_interval` :675/:680.
- `entry.rs`: `record_use` :206 with `checked_add` :213-214 → counter arithmetic now exists (old R1 withdrawn → C08).
- `materials_checks.rs`: :18, :37, :72, :117, :157, :177; wired at `keyring/fluent_builders.rs:82`, `:163`, `cmm/fluent_builders.rs:171`, `:319`. `check_encryption_transition` does not compare symmetric signing keys (read :72-106).
- `encryption_context.rs`: `to_bytes` :91, `from_bytes` :145, duplicate/order checks :198-211 (BUG-03 fixed).
- Raw AES: build :350, reserved prefix check :360, `wrap_data_key` :146, decrypt buffer :472 (plain `Vec`), length check :489, aggregate EDK list :517.
- prim: `aes_encrypt` :175 (copy :185 before key/nonce Err :188 → BUG-07a), `aes_decrypt` :206 guard :215, `hmac` :241, `digest` :272, `kbkdf_ctr_hmac` :313; ecdsa `sign_fixed_len` :180, `check_sig_len` :200, `ecdsa_generate_keypair` :373; hkdf :46, :76, :84, :101.
- Shim: `require_handle` :715 (null :720, deref :728), nullable clients :1564-1565, cache :1655, `into_keyring_handle` :2054; tests `src/tests.rs` :715, :733, :746, :791.

## Decisions

- Retire **T08** (code gone) → successor **T26** for TM-MPL-015 residual (transient/error-path buffers; expected FAIL incl. BUG-07a). Kept T08 ID as a Retired block.
- Retire **C06** (integer-division conversion gone; single Duration compare left).
- New **T25** for TM-MPL-024 (shim). Blast 2 (shim consumers only). Non-null pointer validity = trusted caller precondition.
- New **C07** (materials checks) and **C08** (usage counters).
- New gap level 0.4 = near-exhaustive tests + runtime check enforcing the same property (T09, T15).
- Rescores: T13 2.52→4.41, T14 2.52→3.78, T09 3.20→2.56, T15 2.40→1.92, T21 1.68→1.96, C04 5.60→2.80. Others unchanged (locations only).
- T23 kept at gap 0.6: the four new `test_local_cmc.rs` tests are usage-metadata tests (counted for C08), not capacity/TTL.

## Arithmetic (double-checked)

T01 4×.8×.7×4=8.96 · T02 4×.6×.7×4=6.72 · T03 4×.8×.4×4=5.12 · T04 4×.7×.4×4=4.48 · T05 3×.9×.4×4=4.32 · T06 2×1×.7×3=4.20 · T07 4×.8×.4×3=3.84 · T09 4×.4×.4×4=2.56 · T10/T11/T12 3×.6×.4×4=2.88 · T13 3×.7×.7×3=4.41 · T14 3×.6×.7×3=3.78 · T15 3×.4×.4×4=1.92 · T16 2×.7×.4×4=2.24 · T17 3×.8×.4×2=1.92 · T18 2×.8×.4×3=1.92 · T19 2×.6×.4×4=1.92 · T20 2×.7×.4×3=1.68 · T21 2×.7×.7×2=1.96 · T22 2×.5×.4×4=1.60 · T23 1×.6×.7×3=1.26 · T24 2×.5×.4×3=1.20 · T25 3×.6×.4×2=1.44 · T26 2×1×.4×4=3.20 · C01 3×.8×.7×4=6.72 · C02 2×.8×1×4=6.40 · C03 2×.7×1×4=5.60 · C04 2×.5×.7×4=2.80 · C05 3×.5×.4×4=2.40 · C07 3×.6×.7×4=5.04 · C08 2×.6×.4×2=0.96.

## Final combined top 10

1 T01 8.96 · 2 T02 6.72 · 3 C01 6.72 · 4 C02 6.40 · 5 C03 5.60 · 6 T03 5.12 · 7 C07 5.04 · 8 T04 4.48 · 9 T13 4.41 · 10 T05 4.32.

## Files written

- `docs/verification-targets/01-threat-driven.md` (rewritten in place)
- `docs/verification-targets/02-capability-driven.md` (rewritten in place)
- `docs/verification-targets.md` (rewritten in place)
- `docs/verification-targets/04-validation.md` (re-run)
- this file
