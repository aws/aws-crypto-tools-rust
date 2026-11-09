# Review: docs/bug-reports (BUG-01 .. BUG-09 + README)

Verdict: APPROVED. The errors found were document-only (line numbers, and wording about reproducer files). I fixed them directly in `docs/bug-reports/`. No blockers remain.

## Method

- Checked every file:line and code excerpt against the tree at `HEAD a1e23d7` (`aws-crypto-rust/esdk-native-mpl`), using `grep -n` and `awk 'NR..'` line pinning.
- Checked every spec quote against `spec/framework/*.md` with grep, and checked that each heading anchor exists, including the `-1`/`-2` suffixed ones.
- Compared each inline reproducer with `.agents/tasks/bug-reports/reproducers/zz_bugrepro_NN_*.rs`. All 9 are identical apart from blank lines.
- Compared each quoted output block with `logs/bugreproNN.log`. All match: blank lines are dropped, and BUG-01's elisions are marked `...` and stated in the text.
- Did not re-run any suites. The only extra check was reading the aws-lc-rs 1.17.1 registry source for BUG-07's callee claim (`src/aead/unbound_key.rs:140`, confirmed).
- External Dafny/GitHub quotes were not verified, since that needs network access. Each report labels them as read on `main`.

## Repository state (g)

`git status --porcelain -uall` shows only untracked files under `docs/`: the 10 bug-report files plus the pre-existing analysis docs. No source file is modified. No `zz_bugrepro_*` file is tracked or untracked in `mpl/tests` or `prim/tests`. Leftover build artifacts named `zz_bugrepro_07_aes_buffers-*` exist under `prim/target/debug/` (git-ignored). That's harmless, but they can be removed with `cargo clean -p` or by deleting them if wanted.

## Per-report findings

### All reports except BUG-04: reproducer path wording (fixed)
- Error: each said "Reproducer: `mpl/tests/zz_bugrepro_NN_*.rs` (untracked; backup in ...)". That reads as if the file is still in the tree. It isn't: `mpl/tests/zz_bugrepro_*` and `prim/tests/zz_bugrepro_*` don't exist.
- Fix: now reads "(a temporary untracked test, removed from the tree after the run; full source below, copy in `.agents/tasks/bug-reports/reproducers/`)". BUG-04 already described its /tmp copy correctly.

### BUG-01
- No errors found.
- Lines checked: 338-344 / 342 / 585 (`hierarchical_keyring.rs`); 150 (`ttl_seconds == 0`); 177-190 (grace check `>= ttl_seconds`); `storm_tracking.rs` 446 / 531-537 / 107-143.
- Spec quotes checked: `aws-kms-hierarchical-keyring.md:82`; `storm-tracking...md#consistency` (124).
- The log matches. `catch_unwind` is absent from `mpl/src`, `esdk/src` and `esdk/shims` (grep).

### BUG-02
- Error (fixed): the raw AES control excerpt was labeled 327-329 and the text cited `327-331`. The correct lines are 326-330 (`raw_aes_keyring.rs:326`: `if plaintext_dk.len() != expected_dk_len {`).
- Error (fixed): the V2 length check was cited as `key_derivation.rs:191-195`. The `if` is at line 190, so the range is now 190-195.
- Everything else verified:
  - `hierarchical_keyring.rs:414-420`, `:601`, `:608`.
  - `branch_key_wrap.rs:225-236`.
  - The constructor ranges.
  - `key_derivation.rs:83-93`, `105-132`, `286` (`debug_assert_eq!`).
  - Spec quotes: `structures.md:227-230`, `323-326`; `cmm-interface.md:138`; `keyring-interface.md:147`.
- The log matches. The ESDK V1-HKDF claim is labeled as code reading. I checked that `encrypt.rs:699` checks the derived key, not the PDK, so the claim stands.

### BUG-03
- Error (fixed): `serialize` was cited as "line 68". It is at `encryption_context.rs:69`.
- Everything else verified: `deserialize` at 109, `BTreeMap::new()` at 125, the 155-165 excerpt, and the zero-count / trailing-byte rejections. `deserialize(` has no callers in `mpl/src`, `esdk/src` or `prim/src`. The spec quote at `structures.md:155-160` and the "UTF-8 encoded bytes" at 168/170 match. The log matches.

### BUG-04
- No errors found.
- Code checked:
  - `kms_ops.rs:104-107`, `132-148`, `169`.
  - `keystore/mod.rs:21`. The report is correct here; evidence.md's ":22" was stale.
  - `mrk_match.rs:52`.
  - `branch_key_store.rs:190`, `421`, `442`, `555/577/599`, `763-771`.
  - `config.rs:28`.
  - The integration test at 815-866.
- Spec quotes checked: `branch-key-store.md:168`, `:204`, `:669` are verbatim, under `#aws-kms-configuration` / `#mrdiscovery` / `#aws-kms-branch-key-decryption`.
- The log matches.

### BUG-05
- No errors found.
- Code checked: `default_cmm.rs:114-115`; `prim/src/ecdsa.rs:370`, with `Err` paths at 372, 377, 383 and 388; `hierarchical_keyring.rs:536-542`, `570-572`; `branch_key_wrap.rs:231-236`.
- Spec quote checked: `default-cmm.md:87`.
- Question 2's references (`default_cmm.rs:100`, `cache_entry_identifier.rs:64`) match `01-threat-driven.md` C8. The log matches.

### BUG-06
- Error (fixed): the partition-ID `s.into_bytes()` was cited as `hierarchical_keyring.rs:195`. It is at line 196.
- Everything else verified:
  - `cache_entry_identifier.rs:35-66` and the 42-60 excerpt.
  - Constants 0x02 / 0x01 / 0x02, which give the stated preimage.
  - Call sites 306/550, `generate_partition_id` at 269, `resolve_branch_key_id` at 299/398.
  - Spec quotes: lines 422/472, 526-528, 542-543, 547, 524.
  - Anchors: `#partition-id-2` (heading at 532) and `#logical-key-store-name` (545).
  - The ~6% NUL probability: 1−(255/256)^16 = 6.06%.
- The log matches.

### BUG-07
- No errors found.
- Code checked: `prim/src/lib.rs:189`, `197-218`, `206-215`, `224`, `236-238`, `249` (`gather`).
- Callers checked: `raw_aes_keyring.rs:225`, `branch_key_wrap.rs:192`, `body_encrypt.rs:239`, `encrypt.rs:715`.
- Exact-size decrypt buffers checked at 309 and 267. `frame_buf` is local at `body_encrypt.rs:295`.
- `algorithm_suite.rs:434` checked.
- Cargo.lock versions checked: prim 1.17.1; mpl and esdk 1.17.0.
- `prim/Cargo.toml` "Not intended for public consumption" checked.
- The log matches.

### BUG-08
- No errors found.
- Code checked: `encryption_context.rs:109-119`, `59-78`, `93-98`, `145-149`; `attributes.rs:11-18`; `structures/encryption_context.rs:13`.
- Test checked: `test_keystore_encryption_context.rs:234`.
- Spec quote checked: `branch-key-store.md:634-635`, under `#custom-encryption-context`.
- The doc comment that Question 1 refers to exists (`EncryptionContextInput::custom_ec`). The log matches.

### BUG-09
- No errors found.
- Code checked: `hierarchical_keyring.rs:618-626`, `322`, `566`; `local.rs:179`. `get_cache_entry` evicts expired entries.
- Spec quote checked: lines 164-167 under `#onencrypt` and 256-259 under `#ondecrypt`.
- The log matches.

## README (f)

- Severity, Confidence and Spec-conflict cells match every report header.
- Discussion priorities are unique, 1-9.
- The ID-to-finding mapping matches `verification-targets.md` §7.
- The `HEAD a1e23d7` claim matches `git log -1`.

## Sections and tone (d, e)

- All 9 reports have:
  - a summary;
  - a severity, confidence, spec-conflict and related-IDs block;
  - Location, Expected, Actual, Impact and Reproduction sections;
  - 2-3 fix options per part, with a recommendation;
  - 3-4 questions.
- Impact statements carry their preconditions and fail-closed caveats, and untested inferences are labeled (BUG-01 Windows, BUG-02 ESDK V1, BUG-04 KMS side). The tone stays neutral: findings and options, with no accusations.
