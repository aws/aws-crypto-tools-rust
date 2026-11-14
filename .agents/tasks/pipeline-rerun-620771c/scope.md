# Scope: pipeline re-run on MPL native Rust at main 620771c

- Repo: `esdk-native-mpl`, branch `MPL-Verus`, HEAD `eb1ec23`. Code under `mpl/`, `prim/`, `esdk/` is identical to `origin/main` `620771c` (merged in `c256243`).
- Previous analysis commit: `a1e23d7` (not an ancestor of `620771c`; "since a1e23d7" = `git log a1e23d7..HEAD`).
- Every current `file:line` below was checked with `grep -n` or `sed -n` on HEAD during this step.
- Rule followed: no change under `mpl/`, `prim/`, `esdk/`; nothing committed or pushed.

## Commit scope

`git log --oneline a1e23d7..HEAD -- mpl prim` lists 20 commits:

| Commit | PR | Subject | Security relevance |
|---|---|---|---|
| 620771c | #186 | raw AES keyring memory use for messages with many keys | `with_encrypted_data_keys` moved from each per-EDK error to the final aggregate error (`mpl/src/keyring/raw_aes_keyring.rs:517`). DoS / memory amplification fix |
| 04f4dcf | #176 | test: SDK-style error `find_source` | tests only |
| acb7e50 | #168 | static keyring in MPL TestServer | test server only |
| 9646828 | #167 | check keyring and CMM materials by default | new `mpl/src/structures/materials_checks.rs`; transition checks in fluent `send()` |
| bec2cfe | #163 | conform public types to Smithy model | API reshape, `types::` module |
| 28eed5b | #169 | `RequiredEncryptionContextKeys` type | new `mpl/src/structures/required_encryption_context_keys.rs` |
| 05cd29d | #166 | move MPL/Primitives test servers under `mpl/`, `prim/` | test servers |
| daac26c | #158 | zeroize the derived branch wrapping key | key hygiene (T08-adjacent) |
| 72dfdc7 | #153 | default FORBID_ENCRYPT_ALLOW_DECRYPT suite to HKDF_SHA384_ECDSA_P384 | T09 commitment policy / CMM gate |
| 918e6f9 | #132 | SDK-style append-one setters, `Option` builder getters | builders everywhere |
| bd80b4a | #142 | Plaintext/Ciphertext types from encrypt/decrypt | ESDK API |
| a864ad8 | #131 | zeroize secrets on drop, compare in constant time | T08, T22: `PlaintextDataKey` now `#[derive(Zeroize, ZeroizeOnDrop)]` (`mpl/src/structures/algorithm_suite.rs:505-506`), `ct_eq` at `:541`, `:607`, `:691` |
| e8d79b8 | #146 | CI restructure | none |
| e2fc729 | #138 | crate metadata | none |
| f8abe78 | #87 | cargo-deny, license headers | supply chain |
| 21a785c | #137 | one method per operation on handles and built-in components | `Shared*` handles, fluent builders |
| 18873bc | #136 | KMS and DynamoDB SDK deps as optional features | feature-gated code paths |
| e9bde48 | #98 | retarget ESDK and C++ shim onto native MPL | huge diff; fixed BUG-02/03/09; `keystore/` → `key_store/` |
| 71cd6cb | #64 | primitives test server | test server |
| bf03949 | #100 | MPL in KMS client user agent | new `mpl/src/aws_kms/user_agent.rs` |

Related commits outside `mpl/ prim`: `cdd5980` (#107) deleted `unsafe-unreviewed-mpl/` entirely (old Dafny-generated wrapper crate gone). `0a5ef5b` (#184) ESDK decrypt grows `enc_content`/`result` as bytes arrive (`read_into_vec`, `esdk/src/message/serialize_functions.rs`), test `esdk/tests/test_body_allocation.rs`. `6ef7d80` (#91) spec resolved from `scripts/spec-source.json` instead of a submodule.

`git diff --stat a1e23d7 HEAD -- mpl prim`: 141 files, +32298 / −8753. Large chunks are generated error code (`mpl/src/error/generated.rs` +4245, `prim/src/error/generated.rs` +1071), test servers, and tests.

Source file changes in `mpl/src` (`--name-status -M`):
- Added: `aws_kms/user_agent.rs`, `builder.rs`, `cmc/default.rs`, `cmc/fluent_builders.rs`, `cmc/operation.rs`, `cmm/fluent_builders.rs`, `cmm/types.rs`, `error.rs`, `error/generated.rs`, `key_store/{branch_key_store,client_impl,config,mod,shapes}.rs`, `keyring/fluent_builders.rs`, `keyring/types.rs`, `shared.rs`, `structures/aes_wrapping_alg.rs`, `structures/materials_checks.rs`, `structures/required_encryption_context_keys.rs`, `types.rs`.
- Renamed: `keystore/{attributes(100%),encryption_context(72%),kms_config(68%),kms_ops(61%),record(58%)}.rs` → `key_store/…`.
- Deleted: `client.rs`, `cmc/cache_config.rs`, `cmm/request.rs`, `keystore/{branch_key_store,config,error,mod}.rs`, `structures/error.rs`.
- Modified: everything else (hierarchical keyring +1038 lines, storm tracking, local CMC, entry, default CMM, all `structures/*`).
- `prim/src`: `lib.rs`, `ecdsa.rs`, `hkdf.rs` modified (error messages, length guards); `error.rs`, `error/generated.rs` added.

## Module/path map (old cite → current file:line)

Old citations were taken from the previous docs (`spec-security-analysis.md`, `threat-model.md`, `verification-targets.md`, `verification-targets/01,02,04`). Old line content was read with `git show a1e23d7:<file> | sed -n`.

### Directory / module renames

| Old path (a1e23d7) | Current path |
|---|---|
| `mpl/src/keystore/` | `mpl/src/key_store/` |
| `mpl/src/keystore/branch_key_store.rs` | `mpl/src/key_store/branch_key_store.rs` (rewritten; git sees delete + add) |
| `mpl/src/keystore/{record,kms_ops,kms_config,encryption_context,attributes}.rs` | `mpl/src/key_store/<same name>.rs` |
| `mpl/src/keystore/error.rs`, `mpl/src/structures/error.rs`, `cmc` errors | single `mpl/src/error.rs` + `mpl/src/error/generated.rs` (`Error` + `Kind`) |
| `mpl/src/keystore/config.rs` | `mpl/src/key_store/config.rs` (new) |
| `mpl/src/cmc/cache_config.rs` | removed; config lives in builders (`StormTrackingCmcBuilder` in `cmc/storm_tracking.rs`, `cmc/default.rs`) |
| `mpl/src/cmm/request.rs` | removed → `mpl/src/cmm/types.rs` (Input/Output shapes) |
| `mpl/src/client.rs` | removed |
| public `structures::*` | `structures` is private (`mpl/src/lib.rs` `mod structures;`); public re-exports in `mpl/src/types.rs` |
| `aws_kms::__test_internals` | `aws_crypto_mpl::__test_internals::aws_kms` (`mpl/src/lib.rs:36-41`, feature `test-utils`); key store internals at `mpl/src/key_store/mod.rs:286-291` |
| `unsafe-unreviewed-mpl/` | deleted (`cdd5980`) |
| tests `mpl/tests/test_keystore_*.rs` | `mpl/tests/test_key_store_*.rs`; `test_materials_error.rs`, `test_cmc_error.rs`, `test_mpl_client.rs` deleted (replaced by `test_error.rs`, `test_materials_checks.rs`) |

### Line-level citations

| Old cite (a1e23d7) | What it was | Current location | Note |
|---|---|---|---|
| `keystore/branch_key_store.rs:172` | `kms_client()` `.expect("kms_client is resolved during construction")` | `mpl/src/key_store/branch_key_store.rs:101-102` (`fn kms_client` returns `&self.inner.kms_client`) | `.expect` removed; client is non-`Option` after build (`:75`) |
| `keystore/branch_key_store.rs:367` | `decrypt_only_encryption_context` in `version_key`/`create_key` | `mpl/src/key_store/branch_key_store.rs:569` (in `create_key` `:539`); `version_key` at `:641` | |
| `keystore/branch_key_store.rs:566` | `branch_key_materials_from_authenticated_encryption_context` | `mpl/src/key_store/branch_key_store.rs:814` (`get_active_branch_key` `:792`), `:852` (`get_branch_key_version` `:827`); fn at `mpl/src/key_store/record.rs:95` | |
| `record_from_ddb_item`, `item_from_ec_and_enc` | DDB item codec | `mpl/src/key_store/branch_key_store.rs:1141`, `:1089` | |
| `keystore/record.rs` `to_attribute_map` | | `mpl/src/key_store/record.rs:61` | |
| `keystore/encryption_context.rs:111` | `build_base` collision branch (BUG-08) | `mpl/src/key_store/encryption_context.rs:40` (`build_base`), dead branch `:91`/`:95` | logic unchanged |
| `keystore/kms_ops.rs` `resolve_keystore_arn` | ARN resolution (T03/T17, BUG-04) | `mpl/src/key_store/kms_ops.rs:88` `resolve_key_store_arn`; MrDiscovery arm `:100`; `reject_alias_arn` `:118`; `rewrite_arn_region` `:144`; call in `decrypt_branch_key` (`:162`) at `:179` | renamed, logic unchanged |
| `kms_ops::build_authenticated_encryption_context` | | `mpl/src/key_store/kms_ops.rs:49` | |
| `keystore/kms_config.rs` `parse_arn`, `is_arn_compatible` | | `mpl/src/key_store/kms_config.rs:31`, `:86` | |
| `aws_kms/cache_entry_identifier.rs:64` | `.expect` on SHA-384 output | `mpl/src/aws_kms/cache_entry_identifier.rs:64` | file unchanged since a1e23d7 (`git diff --quiet` succeeded); `build_cache_identifier` `:35`, NUL join `:49` |
| `aws_kms/hierarchical_keyring.rs:342` | `now + Duration::from_secs(ttl_seconds)` (BUG-01) | `mpl/src/aws_kms/hierarchical_keyring.rs:702` (`on_encrypt` `:654`) and `:945` | TTL is now `Duration`; only `is_zero` check `:547` |
| `aws_kms/hierarchical_keyring.rs:607` | `generate_random_data_key` | `mpl/src/aws_kms/hierarchical_keyring.rs:975` | |
| `try_decrypt_edk` | EDK parse / 44-byte check | `mpl/src/aws_kms/hierarchical_keyring.rs:867`; check `:879`; key store call `:934` | |
| `cache_entry_within_limits` | TTL check (BUG-09) | `mpl/src/aws_kms/hierarchical_keyring.rs:989` | fixed (`Duration` compare) |
| `as_branch_key_materials` | cache-kind check (T14) | `mpl/src/aws_kms/hierarchical_keyring.rs:1000` | |
| `generate_partition_id` | | `mpl/src/aws_kms/hierarchical_keyring.rs:626` | |
| grace-vs-TTL check (C06) | | `mpl/src/aws_kms/hierarchical_keyring.rs:585` (`grace_period >= ttl`) | |
| hierarchical `on_decrypt` | | `mpl/src/aws_kms/hierarchical_keyring.rs:734`; `add_data_key` `:767`; `all_failed` `:798` | |
| `branch_key_wrap::{compute_aad, derive_branch_key, wrap, unwrap}` | T04/T05/T10 | `mpl/src/aws_kms/branch_key_wrap.rs:61`, `:122`, `:157`, `:230`; 60-byte check `:236`; `try_into().expect` `:249`, `:252`, `:256` | |
| `aws_kms/mrk_match.rs` | T11 | `aws_kms_mrk_match_for_decrypt` `mpl/src/aws_kms/mrk_match.rs:24`; `is_multi_region_arn` `:52` | |
| `cmc/storm_tracking.rs:323` | `lock().expect("StormTrackingCmc lock poisoned")` in `get` | `mpl/src/cmc/storm_tracking.rs:248` `state_locked` returns `Kind::Internal` error | panic removed from hot path; `.expect` remains only in test-helper accessors `:199`, `:213`, `:227` |
| `cmc/storm_tracking.rs:446` | `deadline: Some(now + self.inflight_ttl)` (BUG-01c) | `mpl/src/cmc/storm_tracking.rs:333` | unchanged arithmetic |
| `cmc/storm_tracking.rs:536` | `now < inflight + grace_interval` (BUG-01b) | `mpl/src/cmc/storm_tracking.rs:680` (`within_grace_interval` `:675`; `within_grace_period` `:661`) | unchanged |
| `cmc/storm_tracking.rs:541` | `put_cache_entry` | `mpl/src/cmc/storm_tracking.rs:710` | |
| `StormTrackingCmc::from_raw` | config validation | `StormTrackingCmcBuilder::build` `mpl/src/cmc/storm_tracking.rs:606` | |
| `wait_for_leader` | | `mpl/src/cmc/storm_tracking.rs:360` | |
| `cmc/local.rs` `prune_tail` | T23 | `mpl/src/cmc/local.rs:166`; `put_cache_entry` `:280` | |
| `cmc/entry.rs` usage metadata | | `record_use` `mpl/src/cmc/entry.rs:206` (Duvet annotation `:201-204`) | |
| `cmm/default_cmm.rs:100` | `asymmetric_signature_algorithm().expect(...)` | `mpl/src/cmm/default_cmm.rs:123` | |
| `cmm/default_cmm.rs:115` | `ecdsa_generate_keypair(..).expect(...)` (BUG-05a) | `mpl/src/cmm/default_cmm.rs:137-138` | unchanged |
| `default_cmm::merge_reproduced_encryption_context` | T12 | `mpl/src/cmm/default_cmm.rs:273`; `get_encryption_materials` `:85`; `decrypt_materials` `:177` | |
| `keyring/raw_aes_keyring.rs:326` | `plaintext_dk.len() != expected_dk_len` | `mpl/src/keyring/raw_aes_keyring.rs:489` (`expected_dk_len` `:441`; `on_decrypt` `:422`) | |
| `keyring/raw_aes_keyring.rs:382` | `generate_random_data_key` | `mpl/src/keyring/raw_aes_keyring.rs:535` | |
| raw AES provider-info codec (T20) | | `serialize_provider_info` `mpl/src/keyring/raw_aes_keyring.rs:129`; `wrap_data_key` `:146`; `on_encrypt` `:399` | |
| `structures/algorithm_suite.rs:439` | `unsafe { ptr::write_volatile }` zeroize loop (T08) | `mpl/src/structures/algorithm_suite.rs:505-506` `#[derive(Clone, Zeroize, ZeroizeOnDrop)] pub struct PlaintextDataKey` | `unsafe` removed; `grep unsafe mpl/src` finds no `unsafe` block |
| `check_data_key_length` (new, BUG-02 fix) | | `mpl/src/structures/algorithm_suite.rs:547`; callers `encryption_materials.rs:60,365`, `decryption_materials.rs:56,303` | |
| `structures/encryption_context.rs` `deserialize` (T15, BUG-03) | | `from_bytes` `mpl/src/structures/encryption_context.rs:145`; order check `:205` | fixed |
| `prim/src/lib.rs:30` | `unsafe_op_in_unsafe_fn` lint | `prim/src/lib.rs:33` | lint list only; `prim/src` has no `unsafe` |
| `prim/src/lib.rs:208` | `cipher_slice = &mut cipher_text[old_size..]` | `prim/src/lib.rs:186` (`aes_encrypt` `:175`; plaintext copy `:185`; key `Err` `:187`) | BUG-07a unchanged |
| `prim/src/lib.rs:236` | `aes_decrypt` guard | `prim/src/lib.rs:215` (`aes_decrypt` `:206`; callee `:228`; error mapping `:229`) | BUG-07b unchanged |
| `prim/src/lib.rs:261`, `:280` | `hmac`, `copy_from_slice` | `prim/src/lib.rs:241`, `:260` (length guard comment `:246`) | |
| `prim` `digest` | | `prim/src/lib.rs:272`, copy `:285` | |
| `prim` `generate_random_bytes`, `constant_time_equal`, `kbkdf_ctr_hmac` | | `prim/src/lib.rs:128`, `:291`, `:313` | |
| `prim/src/ecdsa.rs:79`, `:87` | `finish`, `copy_from_slice` | `prim/src/ecdsa.rs:82`, `:90` | |
| `prim/src/ecdsa.rs:177`, `:185` | `sign_fixed_len`, copy (C02) | `prim/src/ecdsa.rs:180`, `:188`; `check_sig_len` `:200`; `ecdsa_sign` `:224`; `ecdsa_sign_digest` `:253`; `ecdsa_generate_keypair` `:373` | `sign_once` is a closure parameter (`:182`), not a fn |
| `prim/src/hkdf.rs:43`, `:79` | `hkdf`, `hkdf_no_salt` salt slice | `prim/src/hkdf.rs:46`, `:84` | |
| `esdk/src/key_derivation.rs:87` | ESDK PDK length check | `esdk/src/key_derivation.rs:79` | |

## New attack surface candidates

1. Materials checks only on the fluent `Shared*` path. `check_encryption_transition` / `check_decryption_transition` run in `SharedKeyring` fluent `send()` (`mpl/src/keyring/fluent_builders.rs:82`, `:163`); `check_encryption_materials_complete` / `check_decryption_materials_complete` in `SharedCmm` (`mpl/src/cmm/fluent_builders.rs:171`, `:319`). Checks defined in `mpl/src/structures/materials_checks.rs:18,37,72,117,157,177`. A caller using the `Keyring`/`Cmm` trait directly bypasses them. Candidate target: "a keyring's transition is accepted by `send()` iff it only adds PDK/EDKs" (refines C04, T09).
2. Builders (#132, #137, #163). Every component is now built through `*Builder::build()` with `required()` (`mpl/src/builder.rs:7`). Validation now lives in `build()`: `HierarchicalKeyringBuilder` (`ttl` zero check `mpl/src/aws_kms/hierarchical_keyring.rs:547`, grace-vs-TTL `:585`), `StormTrackingCmcBuilder::build` (`mpl/src/cmc/storm_tracking.rs:606`), raw AES key length / reserved namespace (setters `mpl/src/keyring/raw_aes_keyring.rs:302`, `:324`). No upper bound on any `Duration` (BUG-01). `test_builder_getters.rs` (`every_builder_getter_tracks_its_setter`, line 166) only checks getter/setter consistency.
3. Optional features (#136). `mpl/Cargo.toml` features `kms`, `ddb`, `default-aws-sdk-clients`, `rt-tokio`, `test-utils`, `aws-lc-sys`, `fips`. Without `rt-tokio`, `StormTrackingCmc`/`DefaultCmc` are unavailable and the hierarchical keyring needs an explicit `cache`. Without `default-aws-sdk-clients` the key store must be given both clients. ESDK depends on MPL with `default-features = false` (`esdk/Cargo.toml:19-20`). Risk: feature-combination-dependent code paths; verification should name the feature set.
4. C++ shim / FFI (e9bde48). `esdk/shims/aws-esdk-cpp/src/lib.rs` (2063 lines, `#[cxx::bridge]` at `:167`) has 4 `unsafe` uses: `require_handle` `&*ptr` (`:728`, null-checked at `:720`), nullable `as_ref()` for KMS/DDB clients (`:1564`, `:1565`) and cache (`:1655`). Outside `mpl/`/`prim/` but it is the only remaining `unsafe` reachable from MPL users. Shim has its own Duvet config (`esdk/shims/aws-esdk-cpp/.duvet/config.toml`) and spec `spec/shim/*.md`.
5. Decrypt buffer growth (#184, ESDK). `read_into_vec` in `esdk/src/message/serialize_functions.rs` grows buffers as bytes arrive, so header-declared frame length no longer drives allocation. Tests `esdk/tests/test_body_allocation.rs:56,74,97`. ESDK-side; relevant to the MPL threat model only as a caller.
6. Raw AES keyring memory (#186). Per-EDK `NoMatchingDataKey` errors no longer carry the whole EDK list; the list is attached once to the aggregate error (`mpl/src/keyring/raw_aes_keyring.rs:517`). Was O(n²) memory in EDK count (attacker controls EDK count in a message). Hierarchical keyring attaches it once (`mpl/src/aws_kms/hierarchical_keyring.rs:784`). Test `mpl/tests/test_keyring_memory.rs:100`, `:113`.
7. Unsafe inventory. `grep -rn unsafe mpl/src prim/src` (excluding generated) finds only the lint name `prim/src/lib.rs:33`. The old `write_volatile` zeroize loop is gone (now `zeroize` crate). `unsafe-unreviewed-mpl/` deleted. No new `unsafe` in `mpl`/`prim`. Test-only `unsafe` in custom allocators: `mpl/tests/test_keyring_memory.rs:30,40`, `esdk/tests/test_body_allocation.rs:32,38`.
8. Remaining panics in `mpl/src` non-test code (`grep expect(`): `default_cmm.rs:123`, `:138` (BUG-05a); `aws_kms/user_agent.rs:17` (static metadata); `branch_key_wrap.rs:249,252,256` and `hierarchical_keyring.rs:892` (fixed-size `try_into`); `cache_entry_identifier.rs:64`; `storm_tracking.rs:199,213,227` (introspection accessors). `error.rs:471` `.unwrap()` is inside `#[cfg(all(test, feature = "kms"))]`. Plus unchecked `SystemTime + Duration` (BUG-01).
9. New public types: `RequiredEncryptionContextKeys` (`mpl/src/structures/required_encryption_context_keys.rs`), `AesWrappingAlg` (`structures/aes_wrapping_alg.rs`), `CachedMaterials` enum with 4 kinds (`mpl/src/cmc/entry.rs:24-33`), `DefaultCmc` (`cmc/default.rs`, `put_cache_entry` `:99`), user-agent (`aws_kms/user_agent.rs`).
10. Error type carries data: `Error::with_encrypted_data_keys` (`mpl/src/error/generated.rs:1064`) puts EDK info on errors. Check T22 redaction covers `DataKeyInfo` (only key provider id/info, not ciphertext, should be confirmed by the threat-model step).
11. Test servers (`mpl/test-server`, `prim/test-server`): new HTTP servers (`src/main.rs`, `handlers.rs`). Test infrastructure, not shipped in the crate; out of MPL scope but they listen on sockets (flag only).

## Spec revision & Duvet config

- Since #91 the spec is not a submodule. `scripts/spec-source.json` sets `url = https://github.com/awslabs/aws-encryption-sdk-specification.git`, `ref = "master"`. `scripts/resolve-spec.sh` does `fetch --depth 1 origin <ref>` + `checkout --detach FETCH_HEAD` into `<repo>/spec` on each `make duvet`. So main does not pin a revision; it floats on `master`. `/spec/` is git-ignored (`.gitignore:12`).
- Local `spec/` is at `e8334535` ("feat(shim): make key store KMS and DynamoDB clients optional", branch `origin/aws-crypto-rust/cpp-shim-spec-integration`), clean.
- Fetched current `master` read-only: `git clone --depth 1 --branch master` into `.agents/tasks/pipeline-rerun-620771c/spec-pinned/` → `877edcc` (2026-11-02, "feat: add key-derivation spec and specify shim streaming, errors, and adoption (#324)"). No tracked file changed.
- `diff -r spec/framework spec-pinned/framework`: only `framework/transitive-requirements.md` differs. Keyrings (`raw-aes-keyring.md`, `aws-kms/*`), CMM (`cmm-interface.md`, `default-cmm.md`, `caching-cmm.md`, `required-encryption-context-cmm.md`), key store (`branch-key-store.md`), caching (`cryptographic-materials-cache.md`, `local-…`, `storm-tracking-…`, `synchronized-…`), `structures.md`, `algorithm-suites.md`, `commitment-policy.md` are byte-identical.
- `transitive-requirements.md` diff (HKDF sections, ESDK-level): wording rewrite, plus two substantive points. Commit-key salt is now "salt length specified by the suite's commit key derivation settings" (was fixed "256 bits"), and commit-key OKM length is "key derivation output length of the commit key derivation settings" (was "algorithm suite data length"). Encryption-key salt for no-salt suites now says "salt length of 0 → all 0x00 bytes of hash length". Relevant to ESDK `key_derivation.rs`, not to MPL modules in scope.
- Other repo-wide diffs (non-framework): `client-apis/encrypt.md`, `shim/esdk-shim.md`, `shim/shim.md`, `s3-encryption/materials/s3-kms-keyring.md`; local has `client-apis/key-derivation.md`, master has `s3-encryption/key-derivation.md`.
- Duvet configs: `esdk/.duvet/config.toml` (sources `./src/**/*.rs`, `./tests/**/*.rs`; specs `data-format/*`, `client-apis/{client,decrypt,encrypt,streaming}.md`, `framework/transitive-requirements.md`) and `esdk/shims/aws-esdk-cpp/.duvet/config.toml`. There is no `mpl/.duvet` and no duvet config covering any MPL framework spec.
- Decision for this run: use the local `spec/` copy (`e8334535`). For every MPL-relevant framework section it is identical to current `master` `877edcc`. Limitation: `master` floats, so this equivalence is only as of 2026-11-02 / this fetch.

## Duvet annotations

- `grep -rn '//=' mpl/src mpl/tests prim/src prim/tests`: 4 hits.
  - One real annotation block: `mpl/src/cmc/entry.rs:201-204`: `spec/framework/cryptographic-materials-cache.md#usage-metadata`, `type=implication`, `reason=both counters change under one lock`, `//# Updating usage metadata SHOULD be atomic.` (on `record_use`, `:206`).
  - One comment mentioning `//= type=test`: `mpl/tests/test_local_cmc.rs:364` (not an annotation).
  - `prim`: 0.
- No duvet config includes `mpl/` sources, so even the one MPL annotation is not checked by CI.
- ESDK, for contrast: 2100 `//=` lines across 51 files in `esdk/src` + `esdk/tests`, covering `client-apis/{client,decrypt,encrypt,streaming}.md`, `data-format/*`, `framework/transitive-requirements.md`.
- Conclusion: the "no Duvet traceability for MPL" gap from the previous run is essentially unchanged (1 annotation, 1 section).

## Bug status

From `docs/bug-reports/RECHECK-main-620771c.md` and `docs/bug-reports/README.md`; locations re-verified on HEAD.

| Bug | Status | Current file:line |
|---|---|---|
| BUG-01 TTL / grace / inflight `SystemTime + Duration` overflow panic | Still present | `mpl/src/aws_kms/hierarchical_keyring.rs:702`, `:945` (only zero-check `:547`); `mpl/src/cmc/storm_tracking.rs:333`, `:680`; no bound in `build` `:606` |
| BUG-02 PDK length not enforced | Fixed (e9bde48) | `check_data_key_length` `mpl/src/structures/algorithm_suite.rs:547`; callers `encryption_materials.rs:60,365`, `decryption_materials.rs:56,303`; keyring `hierarchical_keyring.rs:767` |
| BUG-03 EC deserialize accepts unsorted | Fixed (e9bde48) | `mpl/src/structures/encryption_context.rs:145` (`from_bytes`), order check `:205` |
| BUG-04 MRDiscovery rewrites non-MRK ARN region | Still present | `mpl/src/key_store/kms_ops.rs:100` (MrDiscovery arm), `:144` (`rewrite_arn_region`, no `mrk-` check), used `:179`; `is_multi_region_arn` only at `mpl/src/aws_kms/mrk_match.rs:52` |
| BUG-05(a) Default CMM `.expect` on ECDSA keygen | Still present | `mpl/src/cmm/default_cmm.rs:137-138`; `prim/src/ecdsa.rs:373` returns `Result` |
| BUG-05(b) 44–59-byte hierarchical EDK reaches key store | Still present (likely not a bug) | `mpl/src/aws_kms/hierarchical_keyring.rs:879` (44-byte check), `:934` (key store call); 60-byte check `mpl/src/aws_kms/branch_key_wrap.rs:236` |
| BUG-06 Cache identifier not injective with NUL | Still present (discussion priority 1) | `mpl/src/aws_kms/cache_entry_identifier.rs:35`, NUL-joined fields from `:49`; file unchanged since a1e23d7 |
| BUG-07(a) `aes_encrypt` leaves plaintext on `Err` | Still present | `prim/src/lib.rs:175`, copy `:185`, `Err` after copy `:187` |
| BUG-07(b) `aes_decrypt` guard weaker than callee | Still present (error text now "authentication tag did not match") | `prim/src/lib.rs:206`, guard `:215`, callee `:228`, mapping `:229` |
| BUG-08 `build_base` collision `Err` dead code | Still present | `mpl/src/key_store/encryption_context.rs:40`, branch `:91`, `Err` `:95` |
| BUG-09 TTL check admits up to ttl + 1 s | Fixed (e9bde48) | `mpl/src/aws_kms/hierarchical_keyring.rs:989` (`cache_entry_within_limits`, full `Duration` compare) |

Open: BUG-01, 04, 05a, 05b, 06, 07, 08. Fixed: 02, 03, 09.

## New tests vs targets

Test counts are `#[test]`/`#[tokio::test]` attributes, HEAD vs `a1e23d7` (renamed files compared to their old names).

| File | Now | Old | Targets touched |
|---|---|---|---|
| `mpl/tests/test_materials_checks.rs` | 27 | new | C04, T09 (transition checks; e.g. `on_encrypt_rejects_a_changed_algorithm_suite` `:271`, `..._changed_encryption_context` `:281`) |
| `mpl/tests/test_encryption_materials.rs` | 25 | 18 | C04 (`test_add_data_key_rejects_wrong_length` `:429`, `test_build_rejects_wrong_length_plaintext_data_key` `:456`), T08 (`test_plaintext_data_key_zeroize` `:248`), T22 |
| `mpl/tests/test_decryption_materials.rs` | 24 | 17 | C04 (`:401`, `:413`), T08 (`:228`), constant-time compare `test_secret_keys_compare_with_ct_eq` `:236` |
| `mpl/tests/test_encryption_context.rs` | 45 | 37 | T15 (`test_out_of_order_keys_rejected_on_deserialize` `:68`, invalid-UTF-8 `:502`, `:509`, `:516`, `:533`); `test_deserialize_accepts_empty_key_length_currently_unenforced` `:468` documents an open gap |
| `mpl/tests/test_aws_kms_hierarchical_keyring.rs` | 58 | 53 | T06/C06 sub-second TTL and grace (`:225`, `:244`, `:607`), BUG-09 regression `on_encrypt_ttl_compares_the_full_duration` `:1547`, T16 `on_decrypt_skips_edks_with_non_utf8_provider_info` `:1841`, T13 cache id (`:647`, `:680`, `:708`, `:736`, `:770`, still no NUL case), T04 (`:939`, `:1026`, `:1168`, `:1187`) |
| `mpl/tests/test_keyring_memory.rs` | 3 | new | T16 / DoS: EDK-count memory growth (`:100` raw AES, `:113` hierarchical) |
| `mpl/tests/test_key_store_branch_key_store.rs` | 28 | 26 | T18, T17 (`new_with_mr_discovery_config_succeeds` `:245`, `create_key_with_discovery_config_fails` `:378`, `version_key_with_discovery_config_fails` `:411`) |
| `mpl/tests/test_key_store_kms_config.rs` | 22 | 21 | T03/T11/T17 (`:65`, `:122`, `:131`); still no direct test of `rewrite_arn_region` / `reject_alias_arn` (private) |
| `mpl/tests/test_key_store_encryption_context.rs`, `test_key_store_record.rs` | 17, 23 | 20, 23 | T01/T02/C01 (`materials_branch_key_rejects_wrong_length` `test_key_store_record.rs:169`) |
| `mpl/tests/test_local_cmc.rs` | 20 | 16 | T23 (`test_update_usage_metadata_deletes_entry_on_overflow` `:729`, `test_pruning_evicts_all_ttl_expired_in_tail` `:428`) |
| `mpl/tests/test_storm_tracking_cmc.rs` | 33 | 38 | T21, C06 (`test_within_grace_interval_matches_spec_formula` `:545`, `test_sub_second_grace_period_is_honored` `:283`); count dropped (some config-bound tests moved into builders) |
| `mpl/tests/test_raw_aes_keyring.rs` | 25 | 23 | T07/T20/T24 (`:619`, `:658`, `:696`, `:732`, `:746`, reserved namespace `:769`, redaction `:827`) |
| `mpl/tests/test_algorithm_suite_id.rs` | 22 | 20 | C05 (`:189`, `:227`, `:234`, `:519`) |
| `mpl/tests/test_error.rs` | 20 | new | error model (not a previous target) |
| `mpl/tests/test_shared_handles.rs`, `test_builder_getters.rs`, `test_default_cmc.rs`, `test_aws_kms_user_agent.rs` | 8, 1, 2, 2 | new | API plumbing; no previous target |
| `prim/tests/*` | unchanged counts except `test_error.rs` 17 (was 5) | | C02/C03 gaps unchanged (no wrong-length `finish` buffer, no retry-exhaustion test) |
| `mpl/test-server/tests/*`, `prim/test-server/tests/*` | 21, 9 | new | cross-runtime round trips (raw AES, hierarchical, static keyring; AES, ECDSA, HKDF/digest) |

Gaps that remain: no large-`Duration` test (T06/BUG-01; grep for `u64::MAX`/`Duration::MAX` in the hierarchical and storm-tracking tests finds none), no NUL-in-field cache-id test (T13/BUG-06), no non-MRK MRDiscovery test (T17/BUG-04), no two-call raw-AES IV-distinctness test (T07), prim C02/C03 gaps. Coverage gains: C04 now directly tested, T15 ordering and UTF-8, T08 zeroize-on-drop + `ct_eq`, materials transition checks, EDK-count memory.

## CVE lookup

Web lookup done (2026-11-10). CVE-2026-6550 / GHSA-v638-38fc-rhfv is VERIFIED to exist:
- GitHub advisory: [GHSA-v638-38fc-rhfv in aws/aws-encryption-sdk-python](https://github.com/aws/aws-encryption-sdk-python/security/advisories/GHSA-v638-38fc-rhfv). Title "Key commitment policy bypass via shared key cache in AWS Encryption SDK for Python".
- NVD: [CVE-2026-6550](https://nvd.nist.gov/vuln/detail/CVE-2026-6550). AWS bulletin: [2026-017-aws](https://aws.amazon.com/security/security-bulletins/2026-017-aws/).
- Summary (paraphrased): in the ESDK for Python, two clients with different commitment policies that share one `CachingCryptoMaterialsManager` can get cached non-committing encryption materials. This happens when the weaker-policy client encrypts first, the encryption contexts match, and both use the default suite. The result is encryption without key commitment ("Invisible Salamanders"). Affected 2.0–2.5.1, 3.0–3.3.0, 4.0–4.0.4; fixed in 3.3.1 and 4.0.5. Workaround: don't share a key cache across differing commitment policies.
- Relevance to this repo: the native Rust MPL has no caching CMM (`mpl/src/cmm/` has only `default_cmm.rs`, `fluent_builders.rs`, `mod.rs`, `types.rs`). `CachedMaterials::Encryption` / `::Decryption` exist (`mpl/src/cmc/entry.rs:26`, `:28`) "for a caching CMM", so the risk would come back if a caching CMM is added. Its cache key must then bind the commitment policy (or algorithm suite). The hierarchical keyring caches only branch-key materials, which do not depend on commitment policy. Suggested as a threat-model note / future target, not a current finding.

Content was rephrased for compliance with licensing restrictions.

## Verification

- `git -C <repo> diff --quiet HEAD -- mpl prim esdk` → exit 0 (run at the end of this step).
- Files written by this step: this file, and the read-only spec clone `spec-pinned/` (untracked, under `.agents/`).
