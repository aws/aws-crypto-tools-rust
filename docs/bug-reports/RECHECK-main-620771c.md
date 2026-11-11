# Re-check of BUG-01 .. BUG-09 against main 620771c

- What was re-checked: the nine findings in `docs/bug-reports/BUG-01..BUG-09` (summary in `docs/bug-reports/README.md`).
- Old code: `a1e23d7` (where the bugs were found and reproduced; branch `aws-crypto-rust/esdk-native-mpl`).
- Current code: `c256243` on branch `MPL-Verus` (merge of main). Its code is identical to `origin/main` `620771c`.
- Note: `a1e23d7` is not an ancestor of `620771c`. "Commits since a1e23d7" below means `git log a1e23d7..HEAD -- <file>`, which lists the main commits not in `a1e23d7`.
- Date: 2026-11-10. Toolchain: rustc 1.95.0 / cargo 1.95.0.
- Method: each original reproducer (`.agents/tasks/bug-reports/reproducers/zz_bugrepro_NN_*.rs`) was copied into its crate's `tests/` directory and run with `cargo test --test <name> -- --nocapture`. If it did not compile against the current API, the test (and only the test) was adapted to the current API. The adapted test keeps the same inputs and checks the same property, and no assertion was weakened. BUG-04 is an in-crate test, so it was run in a throwaway `/tmp` copy of `mpl/` + `prim/`, as in the original run (the copy was deleted afterwards). Code-reading findings (BUG-05(a), BUG-08) were re-read in the current source.
- Rule followed: no codebase change. Nothing under `mpl/src`, `prim/src`, `esdk/src`, any `Cargo.toml` or `Cargo.lock`, or any other tracked non-doc file was edited. All `zz_bugrepro_*` files were deleted from `mpl/tests` and `prim/tests` afterwards. Nothing was committed or pushed.
- Artifacts: logs are in `.agents/tasks/bug-recheck/logs/recheckNN.log`. Each log has the ORIGINAL test's output (a compile failure where one occurred), then the ADAPTED run. Adapted tests are in `.agents/tasks/bug-recheck/reproducers/`.

How to read the results: the reproducers were written to pass when the bug is present. Most of them print `REPRO ...` observations instead of asserting. A few assert the buggy behavior through `unwrap()` or an expected panic. So the status below comes from the printed observations plus pass/fail, not from pass/fail alone. For example, BUG-02 F1 "passes" but now prints `Err`.

## Summary

| Bug ID | Title | Previous confidence | Status on main | Evidence | Test changed? | Current location (file:line) |
|---|---|---|---|---|---|---|
| BUG-01 | Large TTL / grace / inflight values overflow `SystemTime + Duration` and panic | Confirmed by test | Still present | Adapted test 5 passed / 0 failed; all 4 panics observed (`overflow when adding duration to instant`) | yes (API only) | `mpl/src/aws_kms/hierarchical_keyring.rs:702`, `:945` (validation `:547`); `mpl/src/cmc/storm_tracking.rs:333`, `:680` (validation `:606-626`) |
| BUG-02 | Plaintext data key length not enforced (hierarchical OnDecrypt, materials constructors) | Confirmed by test | Fixed on main (F1 and F2) | Adapted test: F1 prints `on_decrypt Err: InvalidMaterials: plaintext data key is N bytes, expected 32` for N=5/0/64; F2 constructors return `Err`, so the test FAILS at `em.unwrap()` | yes (API only) | `mpl/src/structures/algorithm_suite.rs:547` (`check_data_key_length`), called from `encryption_materials.rs:60,365`, `decryption_materials.rs:56,303`; keyring path `hierarchical_keyring.rs:767` |
| BUG-03 | `EncryptionContext::deserialize` accepts entries not sorted by key | Confirmed by test | Fixed on main | Adapted test FAILS: `from_bytes(unsorted)` → `Err(Validation: encryption context keys are not in ascending order)`. Related non-UTF-8 observation now `is_ok = false` | yes (API only) | `mpl/src/structures/encryption_context.rs:145` (`from_bytes`), order check `:205` |
| BUG-04 | MRDiscovery rewrites the region of single-Region (non-MRK) KMS key ARNs | Confirmed by test (resolver) | Still present | Adapted in-crate test 1 passed; SRK `us-east-1` ARN → `us-west-2` ARN; `SRK ARN changed by MRDiscovery: true` | yes (API only) | `mpl/src/key_store/kms_ops.rs:100-103` (MrDiscovery arm), `:144-158` (`rewrite_arn_region`), used at `:179` |
| BUG-05 (a) | Default CMM `.expect` on ECDSA key generation | Confirmed by code reading | Still present | Code reading: `.expect(...)` unchanged; `ecdsa_generate_keypair` still has 4 `Err` paths | n/a | `mpl/src/cmm/default_cmm.rs:137-138`; `prim/src/ecdsa.rs:373` (Err at `:375`, `:380`, `:386`, `:392`) |
| BUG-05 (b) | 44–59-byte hierarchical EDK reaches the key store | Confirmed by test, likely not a bug | Still present | Adapted test 1 passed; len 43 → 0 key store calls; len 44/50/59 → 1 call, then `ciphertext too short: N < 60` | yes (API only) | `mpl/src/aws_kms/hierarchical_keyring.rs:879` (44-byte check), `:934` (key store call), `mpl/src/aws_kms/branch_key_wrap.rs:236` (60-byte check) |
| BUG-06 | Cache-identifier preimage not injective when fields contain NUL | Confirmed by test | Still present | Adapted test 2 passed; both collisions `true`, control `false`; end-to-end: keyring B served keystore A's branch key | yes (API only) | `mpl/src/aws_kms/cache_entry_identifier.rs:35-59` (file unchanged since a1e23d7) |
| BUG-07 | `prim::aes_encrypt` leaves plaintext in buffer on `Err`; `aes_decrypt` guard weaker than callee | Confirmed by test | Still present (both a and b) | Original test, unchanged, 2 passed; buffer after `Err` = `"HDR:SECRET-PLAINTEXT"`; ct+1 / ct+16 buffers pass guard, rejected by callee | no | `prim/src/lib.rs:175` (`aes_encrypt`; copy `:185`, Err returns `:187-192`); `prim/src/lib.rs:206` (`aes_decrypt`; guard `:215`, callee `:228-229`) |
| BUG-08 | Custom-EC collision `Err` in `build_base` is dead code | Confirmed by code reading (+ test for named inputs) | Still present | Code reading + adapted test 1 passed; 10 custom entries in, 10 prefixed out, no `Err` | yes (API only) | `mpl/src/key_store/encryption_context.rs:40` (`build_base`), dead branch `:91-102` |
| BUG-09 | `cache_entry_within_limits` admits entries up to `ttl + 1 s` | Confirmed by test, likely not a bug | Fixed on main | Adapted test passes but output changed: with ttl = 1 s, ages 1500/1950 ms now "treated as expired" (were "USED"); shared-cache 1.5 s case now refetches | yes (API only) | `mpl/src/aws_kms/hierarchical_keyring.rs:989-995` (`elapsed <= ttl`, `Duration` compare) |

Totals: Still present: BUG-01, BUG-04, BUG-05(a), BUG-05(b), BUG-06, BUG-07, BUG-08. Fixed on main: BUG-02, BUG-03, BUG-09. All three fixes are in `e9bde48 feat(esdk): retarget the ESDK and C++ shim onto the native Rust MPL (#98)`. No bug was "Partially fixed" or "Cannot determine".

## Common test adaptation (applies to every "Test changed? = yes")

Main reshaped the MPL public API (`21a785c` #137 "one method per operation on handles and built-in components", `918e6f9` #132 SDK-style builders, `bec2cfe` #163 "conform public types to Smithy model", `18873bc` #136 optional SDK features). None of the original `mpl` reproducers compile. Their original compile errors are kept at the top of each log, for example `unresolved import aws_crypto_mpl::keystore`, `module structures is private`, `module aws_kms is private`. The same mechanical changes were made everywhere:

- `aws_crypto_mpl::structures::*` / crate-root re-exports → `aws_crypto_mpl::types::*`, `aws_crypto_mpl::keyring::*`, `aws_crypto_mpl::cmc::*`.
- `aws_kms::__test_internals::{wrap, unwrap, build_cache_identifier}` → `aws_crypto_mpl::__test_internals::aws_kms::*` (the `test-utils` feature, which dev-dependencies turn on). `SCOPE_ID_ENCRYPT/DECRYPT` are re-exported there.
- `Keystore` trait (positional args, `KeystoreError`) → `key_store::KeyStore` trait with `*Input` / `*Output` shapes and `Error`. The fake returns the same canned materials, logical name and Discovery config, and keeps the same call counters.
- Positional constructors → builders, with the same values: `HierarchicalKeyring::new(ks, ttl_s, Some(bkid), None, cache, Some(p))` → `.builder().key_store().ttl(Duration::from_secs(ttl_s)).branch_key_id().cache()/default.partition_id().build().await`. The same applies to `EncryptionMaterials`, `DecryptionMaterials`, `BranchKeyMaterials`, `EncryptedDataKey`, `LocalCmc(capacity, tail)`, `StormTrackingCmc(...)` and `RawAesKeyring`.
- `keyring.on_encrypt(m)` / `on_decrypt(m, &edks)` → `SharedKeyring::new(k).on_encrypt().materials(m).send()` / `.on_decrypt().materials(m).set_encrypted_data_keys(Some(edks)).send()`.
- `CacheType::Shared(Arc<dyn Cmc>)` → `.cache(SharedCmc)`.
- `e.message` / `e.collected_errors()[0].message` → `Display` plus the `source()` chain. With one candidate EDK, the keyring now returns that candidate's error itself (`Error::all_failed`, `hierarchical_keyring.rs:798`).

Bug-specific changes are listed per bug.

## BUG-01: TTL / grace / inflight overflow panics: Still present

- Run: `cd mpl && cargo test --test zz_bugrepro_01_ttl_overflow -- --nocapture` → `logs/recheck01.log`. Original: 6 compile errors. Adapted: `test result: ok. 5 passed; 0 failed`.
- Result excerpt:
  - `REPRO BUG-01a HierarchicalKeyring::new(ttl_seconds = u64::MAX) is_ok = true` → `REPRO BUG-01a on_encrypt PANICKED: overflow when adding duration to instant`
  - `REPRO BUG-01d on_decrypt PANICKED: overflow when adding duration to instant`
  - `REPRO BUG-01b StormTrackingCmc::new(grace_interval = u64::MAX s) is_ok = true` → `REPRO BUG-01b second get PANICKED: overflow when adding duration to instant`
  - `REPRO BUG-01c StormTrackingCmc::new(inflight_ttl = u64::MAX s) is_ok = true` → `REPRO BUG-01c second get PANICKED: overflow when adding duration to instant`
  - `panicked at .../library/std/src/time.rs:746:31`; `now+u64::MAX s checked_add = None`
- Interpretation: same as at a1e23d7. The TTL is now a `Duration`, but `build()` only rejects zero (`hierarchical_keyring.rs:547`). `on_encrypt` / `on_decrypt` still compute `now + self.inner.ttl` unchecked (`:702`, `:945`). `StormTrackingCmcBuilder::build` (`storm_tracking.rs:606-626`) has no upper bound. The waiter deadline `now + self.inner.in_flight_ttl` (`:333`) and `within_grace_interval`'s `now < inflight + grace_interval` (`:680`) still panic.
- Commits since a1e23d7 touching the code: `hierarchical_keyring.rs`: bec2cfe, 918e6f9, bd80b4a, 21a785c, 18873bc, e9bde48. `storm_tracking.rs`: bec2cfe, 21a785c, e9bde48. None of them adds an overflow check.
- Bug-specific adaptation: `ttl_seconds: u64` → `Duration::from_secs(u64::MAX)`. The StormTracking positional args `(1000, 1, gp, gi, 1, ttl, 1 ms, Seconds)` map to the builder setters with the same values. The pass condition (each call must panic) is unchanged.

## BUG-02: PDK length not enforced: Fixed on main

- Run: `cd mpl && cargo test --test zz_bugrepro_02_pdk_length -- --nocapture` → `logs/recheck02.log`. Original: 5 compile errors. Adapted: `1 passed; 1 failed`.
- Result excerpt:
  - F1: `REPRO BUG-02 F1 edk_ciphertext_len=65 -> on_decrypt Err: InvalidMaterials: plaintext data key is 5 bytes, expected 32 for the algorithm suite`. The 60 (0 bytes) and 124 (64 bytes) cases fail the same way. At a1e23d7 these were `on_decrypt Ok, plaintext_data_key len = 5/0/64`.
  - F2: `EncryptionMaterials::new(5-byte PDK, suite needs 32) is_ok = false` and `DecryptionMaterials::new(...) is_ok = false`, both `InvalidMaterials: plaintext data key is 5 bytes, expected 32 ...`. The test then panics at `em.unwrap()` (line 143). That is the original test's own unwrap, which assumed the constructor accepts the key.
- Interpretation: both sub-findings are fixed. `check_data_key_length` (`mpl/src/structures/algorithm_suite.rs:547-562`) runs in both builders (`encryption_materials.rs:365`, `decryption_materials.rs:303`) and in `add_data_key` (`encryption_materials.rs:60`, `decryption_materials.rs:56`). The hierarchical keyring's OnDecrypt now goes through `materials.add_data_key(...)` (`hierarchical_keyring.rs:767`), so a wrong-length unwrapped key is rejected. F1 "passed" only because it prints instead of asserting; its output is the fixed behavior. Because F2's constructors now reject the key, the rest of F2 (hierarchical and raw-AES `on_encrypt` pass-through) cannot be reached that way. With the length check on `add_data_key`, a keyring has no path left to hand back a wrong-length key.
- Fixing commit: `e9bde48` (#98) introduced `check_data_key_length` (`git log -S check_data_key_length`). Other commits on the materials files: bec2cfe, 28eed5b, 918e6f9, a864ad8. `9646828` (#167, "check keyring and CMM materials by default") adds further transition checks.
- Bug-specific adaptation: suite `AlgAes256GcmIv12Tag16NoKdf` → `AlgorithmSuiteId::Esdk(EsdkAlgorithmSuiteId::AlgAes256GcmIv12Tag16NoKdf)`; `AesGcm::Aes256Gcm` → `AesWrappingAlg::AlgAes256GcmIv12Tag16`. Added prints of the constructor `Err` text before the original `unwrap()`. Nothing was removed.

## BUG-03: `deserialize` accepts unsorted entries: Fixed on main

- Run: `cd mpl && cargo test --test zz_bugrepro_03_ec_unsorted -- --nocapture` → `logs/recheck03.log`. Original: 1 compile error (`structures` private). Adapted: `1 passed; 1 failed`.
- Result excerpt: `REPRO BUG-03 deserialize(unsorted) is_ok = false`, `Err = Validation: encryption context keys are not in ascending order`, then a panic at the original `unwrap()`. Related observation: `deserialize(non-UTF-8 key) is_ok = false` (was `true`).
- Interpretation: fixed. `EncryptionContext::from_bytes` (`mpl/src/structures/encryption_context.rs:145`) rejects a key that is not greater than the previous one (duplicate check `:199`, order check `:205-210`). It also rejects non-UTF-8 keys and values (`utf8`, `:230`).
- Fixing commit: `e9bde48` (#98) (`git log -S "not in ascending order"`). Also touched by bec2cfe.
- Bug-specific adaptation: `deserialize` → `from_bytes`, `serialize` → `to_bytes`. Same byte strings. Added a print of the `Err` before the original `unwrap()`.

## BUG-04: MRDiscovery rewrites non-MRK ARN region: Still present

- Run: throwaway copy `/tmp/bugrecheck04/{mpl,prim}`, test module added as `mpl/src/key_store/zz_bugrepro_04.rs` and wired with `#[cfg(test)] #[path] mod` appended to the copy's `kms_ops.rs`. Command: `cargo test --lib zz_bugrepro_04 -- --nocapture` → `logs/recheck04.log`. Original module: 2 compile errors (`unresolved import super::resolve_keystore_arn`, `crate::keystore`). Adapted: `1 passed; 0 failed`. The copy was deleted.
- Result excerpt:
  - `MRDiscovery(us-west-2), record SRK  arn:aws:kms:us-east-1:...:key/1234abcd-... -> Ok("arn:aws:kms:us-west-2:...:key/1234abcd-...")`
  - control MRK → rewritten to us-west-2 (expected); control Discovery → unchanged
  - `REPRO BUG-04 SRK ARN changed by MRDiscovery: true`
- Interpretation: unchanged. `resolve_key_store_arn` (`mpl/src/key_store/kms_ops.rs:88`) MrDiscovery arm (`:100-103`) calls `rewrite_arn_region` (`:144-158`) with no `mrk-` check. `decrypt_branch_key` uses it at `:179`. `is_multi_region_arn` is still only in `mpl/src/aws_kms/mrk_match.rs:52`. The KMS-side failure needs AWS and was not run, as before.
- Commits since a1e23d7: `mpl/src/keystore/` was renamed to `mpl/src/key_store/` in e9bde48 (#98), and bec2cfe touched it. The logic is unchanged.
- Bug-specific adaptation: `resolve_keystore_arn(cfg, arn)` → `resolve_key_store_arn(cfg, arn, "bk")` (the new `branch_key_id` argument is used only for error messages). `KmsConfiguration::MrDiscovery { region }` → `MrDiscovery(MrDiscovery::builder().region(..).build())`; `Discovery` → `Discovery(Discovery::builder().build())`.

## BUG-05: (a) keygen `.expect`; (b) short EDK reaches the key store: (a) Still present, (b) Still present

- (a) Code reading: `mpl/src/cmm/default_cmm.rs:137-138` still has `ecdsa_generate_keypair(alg).expect("ECDSA keypair generation cannot fail for fixed P-256/P-384 algorithms")`. `prim/src/ecdsa.rs:373` still returns `Result`, with `Err` from key generation (`:375`), public-key compression (`:380`), DER encoding (`:386`) and the explicit length check (`:392`). A failure there still panics the caller. Commits on these files: 28eed5b, 918e6f9, 21a785c, e9bde48 (default_cmm); e8d79b8, f8abe78, e9bde48 (ecdsa). None changed this call.
- (b) Run: `cd mpl && cargo test --test zz_bugrepro_05_short_edk_lookup -- --nocapture` → `logs/recheck05.log`. Original: 4 compile errors. Adapted: `1 passed; 0 failed`.
  - `ciphertext_len=43: ... calls=0 inner_error=Some("Cryptographic: encrypted data key ciphertext too short to contain the branch key version: 43 bytes (need at least 44)")`
  - `ciphertext_len=44: ... calls=1 inner_error=Some("Cryptographic: ciphertext too short: 44 < 60")`; 50 and 59 give the same result
  - `ciphertext_len=60: ... calls=1 ... AES-256-GCM decrypt failed <- authentication tag did not match` (control)
- Interpretation (b): behavior unchanged; only the message text changed. `try_decrypt_edk` checks only `>= 44` (`hierarchical_keyring.rs:879`) before `decrypt_edk_at_version` calls the key store (`:934`). The 60-byte minimum is enforced later in `branch_key_wrap::unwrap` (`branch_key_wrap.rs:236`).
- Bug-specific adaptation (b): error text is read through `Display` plus the source chain instead of `collected_errors()[0].message`, because a single failed candidate is now returned directly. The fake counts `get_branch_key_version` calls as before.

## BUG-06: cache-identifier not injective with NUL: Still present

- Run: `cd mpl && cargo test --test zz_bugrepro_06_cache_id_nul -- --nocapture` → `logs/recheck06.log`. Original: 7 compile errors. Adapted: `2 passed; 0 failed`.
- Result excerpt: `encrypt-scope ids equal ... : true`, `decrypt-scope ids equal ... : true`, `control ... : false`. End to end: `keystore A get_active calls = 1, keystore B get_active calls = 0` and `keyring B's EDK unwraps with keystore A's branch key: true; with keystore B's own branch key: false`.
- Interpretation: unchanged. `build_cache_identifier` (`mpl/src/aws_kms/cache_entry_identifier.rs:35`) still joins the fields with a single `NULL_BYTE` (`:49-59`), with no length prefix and no NUL rejection. `HierarchicalKeyringBuilder::build` does not reject NUL in the partition id, and the key store info's logical name is used as returned.
- Commits since a1e23d7: none on `cache_entry_identifier.rs` (`git diff a1e23d7 HEAD` on it is empty).
- Bug-specific adaptation: `LocalCmc::new(1000, 1)` → `LocalCmc::builder().entry_capacity(1000).entry_pruning_tail_size(1)`, shared through `SharedCmc`.

## BUG-07: prim AES buffer handling: Still present (07a and 07b)

- Run: `cd prim && cargo test --test zz_bugrepro_07_aes_buffers -- --nocapture` → `logs/recheck07.log`. The original test compiled and ran unchanged: `2 passed; 0 failed`.
- Result excerpt:
  - `REPRO BUG-07a bad key: is_err=true err=Some("Cryptographic(CryptographicError { message: \"invalid AES-GCM key\" })")`
  - `REPRO BUG-07a buffer after Err = "HDR:SECRET-PLAINTEXT"`; `bad iv: is_err=true buffer after Err = "SECRET-PLAINTEXT"`
  - `REPRO BUG-07b plain_text len = ct len + 1: Err("... authentication tag did not match ...")`, and the same for `+ 16`
  - `REPRO BUG-07b plain_text len = ct len - 1: Err("... plaintext buffer of 15 bytes is shorter than the 16 byte ciphertext ...")`
- Interpretation: 07a is unchanged. `aes_encrypt` (`prim/src/lib.rs:175`) still appends the plaintext (`:185`) before the key and nonce checks that can return `Err` (`:187-192`), and it does not truncate on error. 07b is unchanged in behavior: the guard (`:215`) still allows a longer buffer, which the callee (`:228`) rejects. The error text has changed: a longer buffer is now reported as `authentication tag did not match` (`:229`, which maps every callee error to that message), where it used to be `gather Unspecified`. That message is now more misleading than before, because the tag is fine and the problem is the buffer length.
- Commits since a1e23d7: bec2cfe, f8abe78, e9bde48. They changed the error messages only.

## BUG-08: dead collision branch in `build_base`: Still present

- Code reading: `build_base` (`mpl/src/key_store/encryption_context.rs:40`) inserts six base keys (`:60-79`), none starting with `aws-crypto-ec:`. It then inserts `format!("{CUSTOM_EC_PREFIX}{key}")` for each custom key (`:91-93`). The custom context is a `BTreeMap<String, String>` with unique keys, so `insert(..).is_some()` can never be true and the `Err` at `:95-101` is unreachable. The comment at `:89-90` still names inputs that do not collide.
- Run: `cd mpl && cargo test --test zz_bugrepro_08_build_base_dead_branch -- --nocapture` → `logs/recheck08.log`. Original: 2 compile errors. Adapted: `1 passed; 0 failed`. Output: `active is_ok = true, decrypt_only is_ok = true`; `10 custom entries in, 10 prefixed entries out: ["aws-crypto-ec:a", "aws-crypto-ec:aws-crypto-ec:a", ...]`. This is identical to a1e23d7.
- Commits since a1e23d7: e9bde48 (#98) moved the file from `keystore/` to `key_store/`. The logic is unchanged.
- Bug-specific adaptation: the module path is now `aws_crypto_mpl::key_store::__test_internals::encryption_context`. `EncryptionContext::insert` takes strings instead of `Vec<u8>`. Same keys and values.

## BUG-09: TTL check admits up to ttl + 1 s: Fixed on main

- Run: `cd mpl && cargo test --test zz_bugrepro_09_ttl_truncation -- --nocapture` → `logs/recheck09.log`. Original: 5 compile errors. Adapted: `2 passed; 0 failed`. The test prints instead of asserting, so the output is the evidence.
- Result excerpt (ttl = 1 s):

  | entry age | a1e23d7 | main |
  |---|---|---|
  | 900 ms | cache entry USED | cache entry USED |
  | 1500 ms | cache entry USED | treated as expired |
  | 1950 ms | cache entry USED | treated as expired |
  | 2050 ms | treated as expired | treated as expired |

  Shared LocalCmc: `ttl=1 keyring at ~1.5 s: keystore calls = 2` (was 1, meaning the stale entry was used); at ~2.2 s: 2.
- Interpretation: fixed. `cache_entry_within_limits` (`mpl/src/aws_kms/hierarchical_keyring.rs:989-995`) now compares full `Duration`s (`elapsed <= ttl`) instead of `elapsed.as_secs() <= ttl_seconds`. Main also added its own regression test, `on_encrypt_ttl_compares_the_full_duration` (`mpl/tests/test_aws_kms_hierarchical_keyring.rs`).
- Fixing commit: `e9bde48` (#98). Its diff replaces `elapsed.as_secs() <= ttl_seconds` with `elapsed <= ttl`.
- Bug-specific adaptation: the custom `BackdatedCmc` implements the new `Cmc` trait (`*Input` → `*Output`, plus the new `update_usage_metadata`). `CacheEntry::new(...)` → `CacheEntry::builder()` with the same creation and expiry times.

## Line-number drift (a1e23d7 → main 620771c)

| Bug | Old location (a1e23d7) | New location (620771c) |
|---|---|---|
| BUG-01 | `mpl/src/aws_kms/hierarchical_keyring.rs:342`, `:585` | `mpl/src/aws_kms/hierarchical_keyring.rs:702`, `:945` |
| BUG-01 | `mpl/src/cmc/storm_tracking.rs:446` (`now + self.inflight_ttl`) | `mpl/src/cmc/storm_tracking.rs:333` (`now + self.inner.in_flight_ttl`) |
| BUG-01 | `mpl/src/cmc/storm_tracking.rs:536` (`inflight + grace_interval`) | `mpl/src/cmc/storm_tracking.rs:680` |
| BUG-01 | `StormTrackingCmc::from_raw` `storm_tracking.rs:91` | `StormTrackingCmcBuilder::build` `storm_tracking.rs:606` |
| BUG-02 | `hierarchical_keyring.rs:420` (OnDecrypt `PlaintextDataKey::new`, unchecked) | `hierarchical_keyring.rs:767` (`add_data_key`, checked) |
| BUG-02 | `EncryptionMaterials::new` `encryption_materials.rs:30`; `DecryptionMaterials::new` `decryption_materials.rs:28` | builders `encryption_materials.rs:358/365`, `decryption_materials.rs:295/303`; check `algorithm_suite.rs:547` |
| BUG-03 | `mpl/src/structures/encryption_context.rs:109` (`deserialize`) | `mpl/src/structures/encryption_context.rs:145` (`from_bytes`), order check `:205` |
| BUG-04 | `mpl/src/keystore/kms_ops.rs:84` (`resolve_keystore_arn`), `:104-107`, `:132-149` | `mpl/src/key_store/kms_ops.rs:88` (`resolve_key_store_arn`), `:100-103`, `:144-158`, call `:179` |
| BUG-04 | `mpl/src/keystore/mod.rs:21` (`pub(crate) mod kms_ops`) | `mpl/src/key_store/mod.rs:36` (`mod kms_ops`) |
| BUG-05(a) | `mpl/src/cmm/default_cmm.rs:114-116`; `prim/src/ecdsa.rs:370` (Err `:372`, `:377`, `:383`, `:389`) | `mpl/src/cmm/default_cmm.rs:137-138`; `prim/src/ecdsa.rs:373` (Err `:375`, `:380`, `:386`, `:392`) |
| BUG-05(b) | `hierarchical_keyring.rs:536` (44-byte check), `:572` (key store call) | `hierarchical_keyring.rs:879`, `:934`; 60-byte check `branch_key_wrap.rs:236` |
| BUG-06 | `mpl/src/aws_kms/cache_entry_identifier.rs:35` | unchanged: `mpl/src/aws_kms/cache_entry_identifier.rs:35` |
| BUG-07 | `prim/src/lib.rs:197` (`aes_encrypt`), `:227` / `:236` (`aes_decrypt` / guard) | `prim/src/lib.rs:175`, `:206` / `:215` |
| BUG-08 | `mpl/src/keystore/encryption_context.rs:110-123` | `mpl/src/key_store/encryption_context.rs:86-102` (dead `Err` `:95-101`) |
| BUG-09 | `hierarchical_keyring.rs:620-626` | `hierarchical_keyring.rs:989-995` (fixed) |

Spec references in the original reports (for example `spec/framework/branch-key-store.md:168/204/669` for BUG-04) were not re-checked here. Main removed the spec submodule (`6ef7d80` #91, "resolve the duvet spec from a config, not a submodule").
