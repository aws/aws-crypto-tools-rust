# Reproduction evidence for BUG-01 .. BUG-09

Repo: `esdk-native-mpl` (branch `aws-crypto-rust/esdk-native-mpl`), working tree unchanged under `mpl/src`, `prim/src`, `esdk/src`.
Reproducers are untracked integration tests (`zz_bugrepro_*.rs`); backup copies in `.agents/tasks/bug-reports/reproducers/` are byte-identical to the repo copies (checked with `cmp`).
Every reproducer prints `REPRO ...` lines describing the observed behavior; the tests *pass* when the defective behavior is observed (they assert/record the bug, not the fix).
All runs: `cargo test --test <name> -- --nocapture` from the crate dir; full output in `logs/bugreproNN.log`.

Review result: all 8 existing reproducers were re-read against the current source and demonstrate the stated finding. No test file needed changes.

## Summary

| Bug | Finding | Reproducer | Result | Confidence |
|---|---|---|---|---|
| BUG-01 | T06 SystemTime + Duration overflow panic | `mpl/tests/zz_bugrepro_01_ttl_overflow.rs` | 5 passed / 0 failed; panics observed | Confirmed by test |
| BUG-02 | C04-F1/F2 PDK length not enforced | `mpl/tests/zz_bugrepro_02_pdk_length.rs` | 2 passed / 0 failed | Confirmed by test |
| BUG-03 | T15 EC deserialize accepts unsorted entries | `mpl/tests/zz_bugrepro_03_ec_unsorted.rs` | 2 passed / 0 failed | Confirmed by test |
| BUG-04 | T17 MRDiscovery rewrites non-MRK ARNs | `reproducers/zz_bugrepro_04_mrdiscovery_non_mrk.rs` (in-crate test, run in a /tmp copy) | 1 passed / 0 failed | Confirmed by test (resolver output); KMS-side failure not run |
| BUG-05 | T16 (a) keygen `.expect`; (b) 44–59 B EDK triggers keystore lookup | `mpl/tests/zz_bugrepro_05_short_edk_lookup.rs` (part b only) | 1 passed / 0 failed | (b) Confirmed by test; (a) Confirmed by code reading |
| BUG-06 | T13 cache-id preimage not injective with NUL | `mpl/tests/zz_bugrepro_06_cache_id_nul.rs` | 2 passed / 0 failed | Confirmed by test |
| BUG-07 | T07/C03 aes_encrypt leaves plaintext on Err; aes_decrypt guard weaker than callee | `prim/tests/zz_bugrepro_07_aes_buffers.rs` | 2 passed / 0 failed | Confirmed by test |
| BUG-08 | C01(c) collision Err in `build_base` is dead | `mpl/tests/zz_bugrepro_08_build_base_dead_branch.rs` | 1 passed / 0 failed | Confirmed by test (inputs named by the comment) + code reading (unreachability) |
| BUG-09 | T14 TTL check admits up to ttl + 1 s | `mpl/tests/zz_bugrepro_09_ttl_truncation.rs` | 2 passed / 0 failed | Confirmed by test |

None of the reproducers showed a finding to be wrong. Severity caveats are noted per bug (BUG-07b and BUG-08 are robustness/code-quality issues; both fail closed).

---

## BUG-01 — T06: TTL / grace / inflight overflow panics

- Code: `mpl/src/aws_kms/hierarchical_keyring.rs:342` and `:585` (`now + Duration::from_secs(self.ttl_seconds)`); `mpl/src/cmc/storm_tracking.rs:446` (`now + self.inflight_ttl`) and `:536` (`inflight + grace_interval` in `within_grace_interval`).
- Command: `cd mpl && cargo test --test zz_bugrepro_01_ttl_overflow -- --nocapture` → `logs/bugrepro01.log` (re-run in this step).
- Result: `test result: ok. 5 passed; 0 failed`.
- Key output:
  - `REPRO BUG-01a HierarchicalKeyring::new(ttl_seconds = u64::MAX) is_ok = true`
  - `REPRO BUG-01a on_encrypt PANICKED: overflow when adding duration to instant`
  - `REPRO BUG-01d on_decrypt PANICKED: overflow when adding duration to instant`
  - `REPRO BUG-01b StormTrackingCmc::new(grace_interval = u64::MAX s) is_ok = true` → `REPRO BUG-01b second get PANICKED: overflow when adding duration to instant`
  - `REPRO BUG-01c StormTrackingCmc::new(inflight_ttl = u64::MAX s) is_ok = true` → `REPRO BUG-01c second get PANICKED: overflow when adding duration to instant`
  - `panicked at .../library/std/src/time.rs:746:31`
  - `REPRO BUG-01 now+u64::MAX s checked_add = None`, `now+i64::MAX s checked_add = None`, `now+1e15 s checked_add is_some = true`
- Confidence: **Confirmed by test**.

## BUG-02 — C04-F1 / C04-F2: plaintext data key length not enforced

- Code: `HierarchicalKeyring::on_decrypt` (`mpl/src/aws_kms/hierarchical_keyring.rs`, unwrap path returns `PlaintextDataKey::new(bytes)` with no length check, ~line 615); `EncryptionMaterials::new` / `DecryptionMaterials::new` accept any PDK length. `RawAesKeyring::on_decrypt` does check (used as control).
- Command: `cd mpl && cargo test --test zz_bugrepro_02_pdk_length -- --nocapture` → `logs/bugrepro02.log`.
- Result: `2 passed; 0 failed`.
- Key output:
  - `REPRO BUG-02 F1 suite AlgAes256GcmIv12Tag16NoKdf encryption_key_length = 32`
  - `REPRO BUG-02 F1 edk_ciphertext_len=65 -> on_decrypt Ok, plaintext_data_key len = 5`
  - `REPRO BUG-02 F1 edk_ciphertext_len=60 -> on_decrypt Ok, plaintext_data_key len = 0`
  - `REPRO BUG-02 F1 edk_ciphertext_len=124 -> on_decrypt Ok, plaintext_data_key len = 64`
  - `REPRO BUG-02 F2 EncryptionMaterials::new(5-byte PDK, suite needs 32) is_ok = true`
  - `REPRO BUG-02 F2 DecryptionMaterials::new(5-byte PDK, suite needs 32) is_ok = true`
  - `REPRO BUG-02 F2 HierarchicalKeyring::on_encrypt Ok: pdk len = 5, edk ciphertext len = 65`
  - Control: `RawAesKeyring::on_decrypt Err: ... first nested: Some("EncryptedDataKey 0: decrypted data key is 5 bytes, expected 32 for the algorithm suite")`
- Confidence: **Confirmed by test**. (The wrong-length EDKs are produced with the crate's own `wrap()`, i.e. by any holder of the branch key.)

## BUG-03 — T15: EncryptionContext::deserialize accepts unsorted entries

- Code: `mpl/src/structures/encryption_context.rs:109` (`deserialize`), spec `structures.md#serialization` (entries MUST be sorted ascending by key).
- Command: `cd mpl && cargo test --test zz_bugrepro_03_ec_unsorted -- --nocapture` → `logs/bugrepro03.log`.
- Result: `2 passed; 0 failed`.
- Key output:
  - `REPRO BUG-03 deserialize(unsorted) is_ok = true`
  - `REPRO BUG-03 deserialize(unsorted) == deserialize(sorted): true`
  - `REPRO BUG-03 input     = [00, 02, 00, 01, 62, 00, 01, 31, 00, 01, 61, 00, 01, 32]`
  - `REPRO BUG-03 serialize = [00, 02, 00, 01, 61, 00, 01, 32, 00, 01, 62, 00, 01, 31]`
  - `REPRO BUG-03 serialize(deserialize(b)) == b: false` (two distinct byte strings decode to the same context; round trip not identity)
  - Related (not part of the finding, for the engineer's awareness): `deserialize(non-UTF-8 key) is_ok = true`.
- Confidence: **Confirmed by test**.

## BUG-04 — T17: MRDiscovery rewrites the region of non-MRK ARNs

- Reproducer: **none**. `resolve_keystore_arn` and `rewrite_arn_region` live in `mpl/src/keystore/kms_ops.rs`, which is `pub(crate) mod kms_ops` (`mpl/src/keystore/mod.rs:22`); both functions are private / `pub(crate)` and not re-exported via any `__test_internals`. The only public path is `BranchKeyStore` → `decrypt_branch_key`, which needs a DynamoDB record and a real KMS `Decrypt` call (or local HTTP stubs for both SDK clients). That cannot run offline without changing `src` or standing up local listeners, so per instructions no reproducer was written.
- Code path (read in this step):
  - `kms_ops.rs:104-107`:
    ```rust
    KmsConfiguration::MrDiscovery { region } => {
        reject_alias_arn(record_kms_arn)?;
        rewrite_arn_region(record_kms_arn, region)
    }
    ```
  - `kms_ops.rs:132-149` `rewrite_arn_region` unconditionally rebuilds `arn:{partition}:{service}:{new_region}:{account}:{resource_type}/{resource}`; there is no `mrk-` check (contrast `is_multi_region_arn` in `mpl/src/aws_kms/mrk_match.rs:52`, which the keystore path does not call).
  - Called from `decrypt_branch_key` (`kms_ops.rs:~173`) to compute `KeyId` for KMS `Decrypt` (and the same resolver feeds ReEncrypt per the doc comment at `kms_ops.rs:73-84`).
  - Effect: a record whose `kms-arn` is a single-Region key `arn:aws:kms:us-east-1:...:key/1234...` is sent to KMS as `arn:aws:kms:<configured-region>:...:key/1234...`, a key that does not exist; the request fails rather than using the real key.
- Spec: `spec/framework/branch-key-store.md:169` and `:205`: "Any MRK ARN discovered will be changed to this region before use." Note for the engineer: `branch-key-store.md:669` states the KeyId MUST be the `kms-arn` "with the region replaced by the configured region" without the MRK qualifier, so the spec is internally inconsistent; the fix decision depends on which text is authoritative.
- Confidence: **Confirmed by code reading**.
- UPDATE (bug-report writing step): reproduced as an in-crate unit test in a throwaway `/tmp` copy of the crate (only change: a `#[cfg(test)] #[path] mod` line appended to the copy's `kms_ops.rs`; copy deleted). Log: `logs/bugrepro04.log` — `MRDiscovery(us-west-2)` turns the single-Region `arn:aws:kms:us-east-1:...:key/1234abcd-...` into `arn:aws:kms:us-west-2:...`; `1 passed; 0 failed`. Spec line numbers corrected: 168 / 204 / 669. Dafny `replaceRegion` (KMSKeystoreOperations.dfy) leaves non-MRK ARNs unchanged. Confidence now **Confirmed by test** (resolver); the KMS-side failure needs AWS.

## BUG-05 — T16: (a) keygen `.expect`; (b) short hierarchical EDK reaches the keystore

- (a) Code: `mpl/src/cmm/default_cmm.rs:114-116`:
  `ecdsa_generate_keypair(alg) ... .expect("ECDSA keypair generation cannot fail for fixed P-256/P-384 algorithms")`.
  `prim/src/ecdsa.rs:370` `ecdsa_generate_keypair` returns `Result` with four distinct `Err` paths (keygen at :372, public-key compression at :377, DER encoding at :383, and an explicit `return err(...)` at :389). A failure there aborts the caller instead of returning an error. Not reproducible without forcing an AWS-LC failure. Confidence (a): **Confirmed by code reading**.
- (b) Code: `hierarchical_keyring.rs` ~536-545 only checks `ciphertext.len() >= CIPHERTEXT_VERSION_OFFSET + CIPHERTEXT_VERSION_LEN` (44) before calling `get_branch_key_version`; the full 60-byte minimum is enforced later in `unwrap`.
- Command: `cd mpl && cargo test --test zz_bugrepro_05_short_edk_lookup -- --nocapture` → `logs/bugrepro05.log`.
- Result: `1 passed; 0 failed`.
- Key output:
  - `ciphertext_len=43: ... keystore get_branch_key_version calls=0 inner_error=Some("HierarchicalKeyring::on_decrypt: EDK ciphertext too short to contain branch-key version: 43 bytes (need at least 44)")`
  - `ciphertext_len=44: ... calls=1 inner_error=Some("Branch key unwrap: ciphertext too short: 44 < 60")`
  - `ciphertext_len=50: ... calls=1 inner_error=Some("Branch key unwrap: ciphertext too short: 50 < 60")`
  - `ciphertext_len=59: ... calls=1 inner_error=Some("Branch key unwrap: ciphertext too short: 59 < 60")`
  - `ciphertext_len=60: ... calls=1 inner_error=Some("Branch key unwrap: AES-256-GCM decrypt failed")` (control)
- Confidence (b): **Confirmed by test**. Impact is a wasted keystore (DynamoDB + KMS) round trip per malformed EDK; decryption still fails closed.

## BUG-06 — T13: cache-identifier preimage not injective with NUL bytes

- Code: `mpl/src/aws_kms/cache_entry_identifier.rs:35` `build_cache_identifier` concatenates `partition_id`, `logical_key_store_name`, `branch_key_id`, `version` separated by a single `NULL_BYTE` with no length prefix or NUL rejection (layout is spec-mandated).
- Command: `cd mpl && cargo test --test zz_bugrepro_06_cache_id_nul -- --nocapture` → `logs/bugrepro06.log`.
- Result: `2 passed; 0 failed`.
- Key output:
  - `REPRO BUG-06 encrypt-scope ids equal for (p="tenant\0x", n="L") vs (p="tenant", n="x\0L"): true`
  - `REPRO BUG-06 decrypt-scope ids equal for (n="L", bkid="bk\0x") vs (n="L\0bk", bkid="x"): true`
  - `REPRO BUG-06 control (no NUL, p="tenantx") equal to first: false`
  - End to end with a shared `LocalCmc`: `keystore A get_active calls = 1, keystore B get_active calls = 0` and `keyring B's EDK unwraps with keystore A's branch key: true; with keystore B's own branch key: false` (keyring B encrypted under keystore A's branch key).
- Confidence: **Confirmed by test**. Requires attacker/config influence over partition id or logical keystore name containing NUL and a shared cache.

## BUG-07 — T07 / C03: AES buffer handling in `prim`

- Code: `prim/src/lib.rs:197` `aes_encrypt` (appends plaintext to the output buffer, then seals in place; on error the plaintext stays); `prim/src/lib.rs:236` `aes_decrypt` guard `if plain_text.len() < cipher_text.len()` while the AWS-LC callee requires equal length.
- Command: `cd prim && cargo test --test zz_bugrepro_07_aes_buffers -- --nocapture` → `logs/bugrepro07.log`.
- Result: `2 passed; 0 failed`.
- Key output:
  - `REPRO BUG-07a bad key: is_err=true err=Some("Error { message: \"new Unspecified\", ... }")`
  - `REPRO BUG-07a buffer after Err = "HDR:SECRET-PLAINTEXT"`
  - `REPRO BUG-07a bad iv: is_err=true buffer after Err = "SECRET-PLAINTEXT"`
  - `REPRO BUG-07b plain_text len = ct len + 0: Ok(())`
  - `REPRO BUG-07b plain_text len = ct len + 1: Err("Error { message: \"gather Unspecified\", ... }")` (passes the guard, rejected by callee)
  - `REPRO BUG-07b plain_text len = ct len + 16: Err("... gather Unspecified ...")`
  - `REPRO BUG-07b plain_text len = ct len - 1: Err("... aes_decrypt : Plain text buffer length of 15 is less than cipher text length of 16. ...")`
- Confidence: **Confirmed by test**. 07a is a real secret-hygiene issue (plaintext left in caller buffer after `Err`). 07b fails closed: the effect is an opaque AWS-LC error instead of the guard's descriptive one, so it is a robustness/contract issue, not a security bug.

## BUG-08 — C01(c): collision `Err` in `build_base` is dead code

- Code: `mpl/src/keystore/encryption_context.rs:110-123`. Base keys (`branch-key-id`, `type`, `create-time`, `tablename`, `kms-arn`, `hierarchy-version`) never start with `aws-crypto-ec:`, and the custom EC is a map with unique keys, so `format!("{CUSTOM_EC_PREFIX}{key}")` can never hit an existing entry; `insert(..).is_some()` is unreachable. The comment's example ("a custom key that already carries the prefix") becomes `aws-crypto-ec:aws-crypto-ec:a` and does not collide.
- Command: `cd mpl && cargo test --test zz_bugrepro_08_build_base_dead_branch -- --nocapture` → `logs/bugrepro08.log`.
- Result: `1 passed; 0 failed`.
- Key output:
  - `REPRO BUG-08 active is_ok = true, decrypt_only is_ok = true`
  - `REPRO BUG-08 10 custom entries in, 10 prefixed entries out: ["aws-crypto-ec:a", "aws-crypto-ec:aws-crypto-ec:a", "aws-crypto-ec:branch-key-id", "aws-crypto-ec:create-time", "aws-crypto-ec:enc", "aws-crypto-ec:hierarchy-version", "aws-crypto-ec:kms-arn", "aws-crypto-ec:tablename", "aws-crypto-ec:type", "aws-crypto-ec:version"]`
- Confidence: **Confirmed by test** for the inputs the comment names (they do not reach the branch); unreachability for all inputs follows from code reading. Code-quality issue (misleading comment/dead branch), no behavioral defect. Note: a custom key `enc` becomes `aws-crypto-ec:enc`, which is fine.

## BUG-09 — T14: TTL check admits entries up to ttl + 1 s

- Code: `mpl/src/aws_kms/hierarchical_keyring.rs:620-626` `cache_entry_within_limits`: `elapsed.as_secs() <= ttl_seconds` truncates sub-second elapsed time, so an entry is accepted while `elapsed < ttl + 1 s`.
- Command: `cd mpl && cargo test --test zz_bugrepro_09_ttl_truncation -- --nocapture` → `logs/bugrepro09.log`.
- Result: `2 passed; 0 failed`.
- Key output (ttl_seconds = 1):
  - `entry age=900 ms -> cache entry USED (keystore calls=0)`
  - `entry age=1500 ms -> cache entry USED (keystore calls=0)`
  - `entry age=1950 ms -> cache entry USED (keystore calls=0)`
  - `entry age=2050 ms -> treated as expired (keystore calls=1)`
  - Shared `LocalCmc`, ttl=100 keyring populates, ttl=1 keyring reads: `at ~1.5 s: keystore calls = 1 (1 = cache entry used)`; `at ~2.2 s: keystore calls = 2 (2 = treated as expired)`.
- Confidence: **Confirmed by test**. Observable only with `CacheType::Shared` where the entry's own expiry is longer than this keyring's TTL (a backdated custom `Cmc`, or a shared `LocalCmc` populated by a keyring with a longer TTL). Overshoot bounded by < 1 s.
