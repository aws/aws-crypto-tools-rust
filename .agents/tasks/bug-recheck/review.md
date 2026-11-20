# Independent review of RECHECK-main-620771c.md

Verdict: APPROVED (no blockers). All 10 status claims hold. I fixed 9 small factual errors in the RECHECK doc: 7 compile-error counts and 3 line numbers. No status changed.

## Check 1: status claims vs logs and current code

- BUG-01 Still present. recheck01.log: 5 passed; all four `PANICKED: overflow when adding duration to instant`. Current code: `hierarchical_keyring.rs:547` only rejects zero; `:702` and `:945` have an unchecked `now + self.inner.ttl`; `storm_tracking.rs:333` has `now + self.inner.in_flight_ttl`; `:680` has `now < inflight + grace_interval`; `build` (`:606-626`) has no upper bound. The only check it adds is `grace_interval <= in_flight_ttl`, and the test satisfies it.
- BUG-02 Fixed on main. recheck02.log: F1 prints `Err: InvalidMaterials: plaintext data key is 5/0/64 bytes`; F2 constructors give `is_ok = false`, then the test panics at its own `em.unwrap()` (line 143). Code: `check_data_key_length` is at `algorithm_suite.rs:547`, called from `encryption_materials.rs:60` (add_data_key) and `:365` (build), and from `decryption_materials.rs:56` and `:303`. The hierarchical OnDecrypt calls `add_data_key` at `hierarchical_keyring.rs:767`. The builders' `plaintext_data_key` setters (`encryption_materials.rs:282/289`, `decryption_materials.rs:221/228`) are checked at build, so there is no unchecked path. Commit: `git log -S check_data_key_length a1e23d7..HEAD` gives only e9bde48 (#98). `git show e9bde48` replaces `Some(PlaintextDataKey::new(..))` with `materials.add_data_key(..)`.
- BUG-03 Fixed on main. recheck03.log: `is_ok = false`, `Err = Validation: encryption context keys are not in ascending order`; non-UTF-8 `is_ok = false`. Code: `from_bytes` is at `encryption_context.rs:145`, the duplicate check at `:199`, the order check at `:205-210`, and `utf8` at `:230`. Commit: `git log -S "not in ascending order"` gives e9bde48, and its diff adds that error.
- BUG-04 Still present. recheck04.log: SRK us-east-1 becomes us-west-2, `changed: true`, 1 passed. Code: the MrDiscovery arm at `kms_ops.rs:100-103` calls `rewrite_arn_region` (`:144-158`) with no mrk check; it is used at `:179`.
- BUG-05(b) Still present. recheck05.log: 43 gives calls=0; 44, 50 and 59 give calls=1 with `too short N < 60`. Code: `hierarchical_keyring.rs:879` (>= 44), key store call `:934`, `branch_key_wrap.rs:236` (60).
- BUG-06 Still present. recheck06.log: collisions true/true, control false, cross-keystore unwrap true. `cache_entry_identifier.rs` has no commits in a1e23d7..HEAD; it is NUL-joined at `:42-59`.
- BUG-07 Still present (a and b). recheck07.log shows the original test ran unchanged: buffer after Err is `"HDR:SECRET-PLAINTEXT"`, and ct+1 / ct+16 fail with `authentication tag did not match`. Code: `prim/src/lib.rs:185` extends before the key and nonce checks (`:187-189`); guard `:215`; callee `:228`; error mapping `:229`.
- BUG-09 Fixed on main. recheck09.log: 1500 and 1950 ms are now "treated as expired" (originally USED in bugrepro09.log); shared case at 1.5 s gives calls = 2 (originally 1). Code: `hierarchical_keyring.rs:989-995` has `elapsed <= ttl` (Duration). `git show e9bde48` has `- elapsed.as_secs() <= ttl_seconds` / `+ elapsed <= ttl`. Regression test `on_encrypt_ttl_compares_the_full_duration` is at `mpl/tests/test_aws_kms_hierarchical_keyring.rs:1547`.
- Ancestry note: `a1e23d7` is not an ancestor of `620771c` (correct as stated), but it is an ancestor of HEAD `c256243` through MPL-Verus. `git diff --quiet 620771c HEAD -- mpl prim esdk` succeeds.

## Check 2: code-reading verdicts

- BUG-05(a): `default_cmm.rs:137-138` still has `ecdsa_generate_keypair(alg).expect(...)`. `prim/src/ecdsa.rs:373` returns `Result`, with Err paths at `:375`, `:380`, `:386` and `:392`. Confirmed.
- BUG-08: `build_base` is at `key_store/encryption_context.rs:40`. Its six base keys (`branch-key-id`, `type`, `create-time`, `tablename`, `kms-arn`, `hierarchy-version`; `attributes.rs:11-17`) do not start with `aws-crypto-ec:` (`CUSTOM_EC_PREFIX`, `attributes.rs:24`). `custom_ec` is a `structures::EncryptionContext(BTreeMap<String,String>)` (`:36`, `structures/encryption_context.rs:16`), so the keys are unique and the `Err` at `:95-101` is unreachable. Confirmed.

## Check 3: file:line accuracy

I checked every current and old (a1e23d7, via `git show`) location in the table, the per-bug sections and the drift table. Corrections made:
- BUG-03 duplicate check `:200` → `:199`.
- BUG-08 dead `Err` `:94-101` → `:95-101`, in both the BUG-08 section and the drift table. Line 94 is the `{`. The summary-table range `:91-102` (the whole if-block) is accurate and kept.
- Drift table, old `mpl/src/keystore/mod.rs:22` → `:21`. At a1e23d7, line 22 is `pub mod record;` and `pub(crate) mod kms_ops;` is line 21. The original BUG-04 report already says `:21`.
- Original compile-error counts, corrected to the `due to N previous errors` lines in the logs: BUG-02 6→5, BUG-03 2→1, BUG-05 5→4, BUG-06 8→7, BUG-08 3→2, BUG-09 6→5. BUG-01 (6) and BUG-04 (2) were already correct.

All other locations match.

## Check 4: test adaptations

I diffed all 8 adapted tests against their originals. The changes are only imports, builders in place of positional constructors, the KeyStore and Cmc trait shapes, the SharedKeyring fluent calls, and Display/source-chain error text. Inputs are the same:
- BUG-01: u64::MAX TTL; storm (gp, gi, ttl) = (MAX, MAX, MAX) and (MAX, 1, MAX); fan_out 1; sleep 1 ms (original `sleep_milli = 1`).
- BUG-02: 5, 0 and 64-byte keys under a 32-byte suite.
- BUG-03: same byte strings.
- BUG-04: same ARNs and region.
- BUG-05: lengths 43, 44, 50, 59 and 60.
- BUG-06: identical `build_cache_identifier` arguments, partitions and logical names.
- BUG-08: same keys.
- BUG-09: ages 900, 1500, 1950 and 2050 ms; TTLs 1 and 100.

Neither the original nor the adapted tests (except BUG-01) contain `assert!`. The BUG-01 expected-panic `panic!` arms are preserved, and the original `unwrap()`s are kept. The only additions are prints of `Err` text placed before those unwraps. No assertion was weakened. BUG-07 ran unchanged.

## Check 5: codebase unchanged

- `git diff --quiet HEAD -- mpl prim esdk` gives OK.
- `git status --porcelain` shows only `?? .agents/tasks/bug-recheck/`, `?? docs/bug-reports/RECHECK-main-620771c.md` and `?? docs/chorus/`.
- There are no `zz_bugrepro_*` files in `mpl/tests` or `prim/tests`.
- I re-ran nothing, because all logs were present and unambiguous.
