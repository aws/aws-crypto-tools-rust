# Stage 1 working notes: spec analysis re-run at 620771c

Output: `docs/spec-security-analysis.md`, rewritten in place.
Inputs: `scope.md` (this folder), current `mpl/src`, `prim/src`, the MPL-facing parts of `esdk/`, and local `spec/framework` (`e8334535`).
Rules followed: only `docs/` and `.agents/` were written. `mpl/`, `prim/` and `esdk/` were not touched. Nothing was committed or pushed.

## Spec source decision
- Used the local `spec/` at `e8334535`. Per scope.md, every MPL framework file is byte-identical to `master` `877edcc` (`spec-pinned/`). Only `transitive-requirements.md` differs, and it is ESDK HKDF text.
- Re-read directly for this stage: `commitment-policy.md`, `storm-tracking-cryptographic-materials-cache.md`, and `aws-kms/aws-kms-hierarchical-keyring.md` (Initialization through OnEncrypt).
- Limitation: `scripts/spec-source.json` floats on `master`.
- Tooling note: `grep_search` skips `spec/` because it is git-ignored, so spec files were read with read_file.

## Duvet
- No `mpl/.duvet/config.toml`. The agent definition says there is one; there is not. The only configs are `esdk/.duvet/config.toml` and `esdk/shims/aws-esdk-cpp/.duvet/config.toml`.
- One annotation block in mpl/prim: `mpl/src/cmc/entry.rs:201-205` (type=implication). Re-verified with grep `^\s*//= `.

## New findings beyond scope.md (verified in code)
1. **Storm-tracking config regression.** `StormTrackingCmcBuilder::build` (`cmc/storm_tracking.rs:606-628`) enforces only fan_out ≥ 1, in_flight_ttl > 0, sleep > 0 and grace_interval ≤ in_flight_ttl (`:622`). The spec Consistency section has three MUSTs: GI ≤ GP, IFTTL ≤ GP, GI ≤ IFTTL. It also requires GP and GI ≥ 1. The first two MUSTs and the ≥ 1 bounds are missing. `mpl/tests/test_storm_tracking_cmc.rs:388` (`test_durations_are_stored_exactly`) accepts GP = 0 with IFTTL = 30 s. The previous docs (threat-model TM-MPL-018, verification-targets/01 ~L397, L1301, L1336, chorus MPL-Threat-Model.md L279) all say `grace_interval ≤ inflight_ttl ≤ grace_period` is enforced, and the test names they cite (`test_inflight_ttl_must_not_exceed_grace_period`, etc.) no longer exist. Impact: availability and caching efficiency, not confidentiality. Stage 2 and verification targets need updating.
2. **Pluggable KeyStore / Cmc / BranchKeyIdSupplier** are public traits. `SharedKeyStore` `send()` (`key_store/client_impl.rs:117-424`) does not validate output. The hierarchical keyring does not compare returned `bkm.branch_key_id()`/`branch_key_version()` with the request. The cache-id `logical_key_store_name` comes from `key_store.get_key_store_info()` (`hierarchical_keyring.rs:600-605`). New trust boundary.
3. **EDK provider info** is the resolved bkid (`hierarchical_keyring.rs:722`). The spec says "the UTF8 Encoded AWS DDB response `branch-key-id`". They are equal for `DynamoDbKeyStore`. This is a partial deviation that only matters for user key stores.
4. **FORBID default suite** is `03 78` (`commitment_policy.rs:43-58`, comment `:46-48`). The spec says `00 14`. Documented deviation, and stronger.
5. **Default cache** is `DefaultCmc` = storm-tracking (capacity 1000, GP 10 s). Combined with the grace < TTL check (`hierarchical_keyring.rs:585`), any TTL ≤ 10 s fails `build()` when no cache is given.
6. **Materials-check bypass is narrower than scope.md item 1 suggests.** `Builtin<T>` is `pub(crate)` (`shared.rs:110`), and the handle's inner `Arc` is private. DefaultCmm calls the keyring through fluent `send()` (`default_cmm.rs:166-171`, `:243-249`). The ESDK calls the CMM through fluent `send()` (`esdk/src/materials.rs:99`, `:166`). A bypass is possible only when a user calls their own trait impl directly.
7. **Zeroization now covers** `PlaintextDataKey`/`SigningKey`/`SymmetricSigningKey` (derive), `BranchKeyMaterials` + builder, `BeaconKeyMaterials` + builder, the RawAes wrapping key (inner + builder), the derived branch key, and the decrypted branch key in `record.rs`. Still not covered: `unwrap()`'s returned Vec, the raw AES decrypt buffer on the error and wrong-length paths (`raw_aes_keyring.rs:471`, `:489`), and the KMS SDK `Blob` (`kms_ops.rs:199-208`).
8. `DataKeyInfo` excludes ciphertext (`structures/encrypted_data_key.rs:147-150`), so T22 redaction holds for the new error EDK info.
9. Raw AES namespace and key-length checks are in `build()` (`raw_aes_keyring.rs:360`, `:370`), not in the setters. scope.md's `:302`/`:324` point at setters.

## Line corrections vs scope.md
- `mpl/src/lib.rs` `__test_internals`: `:34-44` (scope said `:36-41`).
- `prim/src/lib.rs` BUG-07a: copy `:185`, `cipher_slice` `:186`, key Err `:187` (matches scope).
- Note on the grep tool: in its output the `N:` prefix is the match line, and context lines can look off by one.

## Citation verification
Every file:line in the new doc was checked with grep_search line output or read_file offsets on HEAD. Main batches:
- `hierarchical_keyring.rs`: 354, 547, 554, 567, 575, 585, 600-605, 626, 654, 665, 692, 702, 722, 734, 752-763, 784, 798, 867, 879, 892, 908, 934, 945, 975, 989, 1000
- `branch_key_wrap.rs`: 61, 66, 79, 92, 122, 135, 143, 157, 217, 230, 236
- `raw_aes_keyring.rs`: 72-78, 129, 146, 191, 234-239, 350, 360, 370, 399, 403, 422, 427, 436, 441, 460, 471, 489, 517, 526-527, 535
- `branch_key_store.rs`: 112, 132, 148, 373, 381, 385-388, 396, 415, 539, 556-557, 569, 641, 703, 752, 792, 814, 827, 852, 868, 1089, 1127, 1140-1141
- `kms_ops.rs`: 49, 88, 96, 100, 105, 118, 144, 162, 185, 199-208, 222, 260
- `storm_tracking.rs`: 109-121, 239, 264, 333, 360, 606-622, 661, 675, 680, 710
- `materials_checks.rs`: 5, 18, 37, 52, 72, 91, 100, 117, 157, 177, 207
- `default_cmm.rs`: 85, 97, 113, 123, 137-138, 166-171, 177, 184, 198, 224, 243-249, 273, 281, 303
- `commitment_policy.rs`: 43, 46-49, 62, 77
- `keyring/fluent_builders.rs`: 82, 163, 170-195. `cmm/fluent_builders.rs`: 171, 319
- `shared.rs`: 12, 62, 104, 110. `keyring/mod.rs`: 150, 176-185. `key_store/mod.rs`: 26-46, 64, 172. `cmc/mod.rs`: 46. `cmc/default.rs`: 98-131. `cmc/local.rs`: 166, 280. `cmc/entry.rs`: 24-33, 201-206
- `algorithm_suite.rs`: 505, 541, 547, 571, 607, 655, 691. `branch_key_materials.rs`: 206-219. `beacon_key_materials.rs`: 211-235. `encryption_materials.rs`: 60, 365, 368-377. `decryption_materials.rs`: 56, 303, 306-315. `encryption_context.rs`: 145, 205. `encrypted_data_key.rs`: 147-150. `record.rs`: 95, 99-100
- `prim/src/lib.rs`: 33, 128, 175, 185-187, 206, 215, 228-229, 241, 272, 291, 313. `ecdsa.rs`: 180, 200, 224, 253, 282, 373. `hkdf.rs`: 46, 76, 89, 101
- `esdk/src/materials.rs`: 99, 166. `esdk/Cargo.toml`: 19-20. Shim `lib.rs`: 167, 728, 1564-1565, 1655
- `mpl/tests/test_storm_tracking_cmc.rs`: 362, 388. `test_keyring_memory.rs`: 100, 113
- Taken from scope.md without re-reading: `key_store/encryption_context.rs:91`, `:95`; `test_encryption_context.rs:468`; shim null check `:720`.

## Hand-off to Stage 2 (threat model)
- Update TM-MPL-018 (storm-tracking config) to say the enforcement regressed.
- Add a threat for user-supplied KeyStore/Cmc/Supplier: cache-id separation and materials binding are not checked.
- Update the secret-lifetime threat: mostly mitigated now; list the remaining buffers.
- Materials-transition checks are a new mitigation for keyring tampering and suite/EC alteration.
- Keep the CVE-2026-6550 note as a future-caching-CMM constraint.
- Open bugs: 01, 04, 05a, 05b, 06, 07, 08. Fixed: 02, 03, 09.
