# BUG-05: (a) Default CMM panics if ECDSA key generation fails; (b) a 44–59-byte hierarchical EDK reaches the keystore before rejection

Summary: (a) `DefaultCmm::get_encryption_materials` calls `.expect` on the `Result` from `ecdsa_generate_keypair`, so a key-generation failure panics instead of returning `MaterialsError`. (b) `HierarchicalKeyring` fetches the branch key (from the keystore on a cache miss) for an EDK of 44–59 bytes before rejecting it as too short.

- Confidence: (a) Confirmed by code reading; (b) Confirmed by test for the behavior. Part (b) is likely not a bug: it matches the Dafny MPL and adds no amplification beyond what any EDK of 60 bytes or more already causes.
- Spec conflict: no
- Severity: Low.
  - (a) is a latent panic on a path that should be unreachable unless AWS-LC fails (RNG or self-test failure, allocation failure).
  - (b) costs one keystore round trip per malformed EDK, then fails closed.
- Related IDs: VR-2026-T16; TM-MPL-023

## Status on main (620771c)

- Status: (a) Still present. (b) Still present, and still likely not a bug.
- Re-checked: 2026-11-10, against `c256243` on `MPL-Verus` (code identical to `main` `620771c`). Details: [RECHECK-main-620771c.md](RECHECK-main-620771c.md), section BUG-05.
- Evidence (a), by code reading: `.expect(..)` on `ecdsa_generate_keypair` is unchanged, and the callee still has four `Err` paths.
- Evidence (b): the test, adapted for API changes only, gives 1 passed. A 43-byte EDK makes 0 key store calls. EDKs of 44, 50 and 59 bytes each make 1 call, then fail with `ciphertext too short: N < 60` (`.agents/tasks/bug-recheck/logs/recheck05.log`). Only the error text changed.

Line numbers outside the Status and Location sections refer to `a1e23d7`, where the bug was first found, and are kept as history.

## Location

Current code (`main` `620771c`):

(a) `mpl/src/cmm/default_cmm.rs:137-138`:

```rust
137             let keys = ecdsa_generate_keypair(alg)
138                 .expect("ECDSA keypair generation cannot fail for fixed P-256/P-384 algorithms");
```

`prim/src/ecdsa.rs:373` (`ecdsa_generate_keypair`) returns `Result<SignatureKeyPair, Error>` and has four `Err` paths: key generation (`:375`), public-key compression (`:380`), DER encoding (`:386`), and the verification-key length check (`:391-396`). The enclosing `get_encryption_materials` (`default_cmm.rs:85`) already returns a `Result`.

(b) `mpl/src/aws_kms/hierarchical_keyring.rs:879` (in `try_decrypt_edk`, `:867`) checks only for at least 44 bytes (salt 16 + IV 12 + version 16). The key store lookup in `decrypt_edk_at_version` (`:901`) follows at `:934`. The full 60-byte minimum is enforced afterwards in `branch_key_wrap::unwrap` (`mpl/src/aws_kms/branch_key_wrap.rs:236`), called at `hierarchical_keyring.rs:958`:

```rust
879         if ciphertext.len() < CIPHERTEXT_VERSION_OFFSET + CIPHERTEXT_VERSION_LEN {
880             return Err(Error::new(
881                 Kind::Cryptographic,
...
931                 let bkm = self
932                     .inner
933                     .key_store
934                     .get_branch_key_version()
935                     .branch_key_id(branch_key_id)
936                     .branch_key_version(branch_key_version)
```

Originally reported at `a1e23d7`: (a) `default_cmm.rs:114-115`; `prim/src/ecdsa.rs:370-400`, with `Err` at `:372`, `:377`, `:383` and `:388-393`. (b) `hierarchical_keyring.rs:536-542` (44-byte check) and `:570-572` (key store call); `branch_key_wrap.rs:231-236` (60-byte check), called at `hierarchical_keyring.rs:601`.

## Expected behavior

There's no spec requirement for either part; this is robustness / defense-in-depth.

(a) `spec/framework/default-cmm.md#get-encryption-materials` says "the default CMM MUST Generate a [signing key](structures.md#signing-key)" but says nothing about how a generation failure is reported. The Dafny Default CMM propagates it as an error: `var pair :- maybeECDSAPair.MapFailure(e => Types.AwsCryptographyPrimitives(e));` ([DefaultCMM.dfy](https://github.com/aws/aws-cryptographic-material-providers-library/blob/main/AwsCryptographicMaterialProviders/dafny/AwsCryptographicMaterialProviders/src/CMMs/DefaultCMM.dfy), `main`, read while writing this report).

(b) `spec/framework/aws-kms/aws-kms-hierarchical-keyring.md#ondecrypt` orders the steps as: find branch key materials from the cache, using the version from the EDK, and fall back to the keystore; then unwrap. It doesn't require a full-length check first. The Dafny keyring does the same as Rust: `Need(|providerWrappedMaterial| >= EDK_CIPHERTEXT_VERSION_INDEX, ...)` (44 bytes), then `GetHierarchicalMaterialsVersion` (cache/keystore), then the exact-length check `== EXPECTED_EDK_CIPHERTEXT_OVERHEAD + KeyLength` in `KmsHierarchyUnwrapKeyMaterial.Invoke` ([AwsKmsHierarchicalKeyring.dfy](https://github.com/aws/aws-cryptographic-material-providers-library/blob/main/AwsCryptographicMaterialProviders/dafny/AwsCryptographicMaterialProviders/src/Keyrings/AwsKms/AwsKmsHierarchicalKeyring.dfy)).

## Actual behavior

(a), by code reading:

1. A signing suite is selected (for example the default committing suite with ECDSA P-384).
2. `ecdsa_generate_keypair` returns `Err`.
3. `.expect` panics, and the caller sees a panic, not `MaterialsError`.

(b), by test:

1. An EDK with provider id `aws-kms-hierarchy`, a matching branch key id, and a 44–59-byte ciphertext is passed to `on_decrypt`.
2. The version is parsed from bytes 28..44, the cache misses, and `get_branch_key_version` is called once.
3. `unwrap` then rejects it: "ciphertext too short: N < 60".
4. At 43 bytes, it's rejected before the keystore (0 calls).

## Impact

(a):

- Precondition: AWS-LC key generation, compression or encoding fails. In practice that means an entropy source failure, a FIPS self-test failure, or allocation failure. It can't be triggered by message data.
- Effect: a panic instead of an error on the encrypt path. Under Tokio that kills the task. With `panic = "abort"`, or across FFI, it ends the process.
- The `expect` message's claim ("cannot fail") isn't something the type system or the callee guarantees. The verification-targets analysis records this as an unprovable obligation, not a proven-unreachable one.

(b):

- Precondition: an attacker can get a crafted EDK into a message that a victim decrypts with a hierarchical keyring, and knows or matches the branch key id.
- Effect: one cache lookup, and on a miss one keystore call (DynamoDB `GetItem` + KMS `Decrypt` with a real `BranchKeyStore`), before failing.
- The same attacker can get exactly the same effect with a garbage EDK of 60 bytes or more, which passes both length checks and fails only at AES-GCM authentication (the 60-byte row in the log shows this). Rejecting 44–59 earlier therefore removes no attack capability; it only saves a round trip on one class of malformed input.
- On a cache hit (the version was already cached), there's no keystore call at all.

## Reproduction / evidence

(a) wasn't reproduced. It needs a forced AWS-LC failure, which can't be injected without changing `prim/src`. This part is code reading only, re-read in the current source on `main`.

(b) Re-check on `main` `620771c` (2026-11-10). The original reproducer no longer compiles against the current API (4 compile errors, kept at the top of the log). It was adapted for API changes only. The fake implements the `KeyStore` trait with `*Input` / `*Output` shapes and counts `get_branch_key_version` calls as before. The keyring and materials are built with builders. The error text is read through `Display` plus the `source()` chain instead of `collected_errors()[0].message`, because with one candidate EDK the keyring now returns that candidate's error itself (`Error::all_failed`, `hierarchical_keyring.rs:798`). The EDK lengths are the same (43, 44, 50, 59 and 60).

- Adapted reproducer: [`zz_bugrepro_05_short_edk_lookup.rs`](../../.agents/tasks/bug-recheck/reproducers/zz_bugrepro_05_short_edk_lookup.rs) (115 lines, not inlined here).
- Original reproducer (`a1e23d7` API): `.agents/tasks/bug-reports/reproducers/zz_bugrepro_05_short_edk_lookup.rs`.
- Command: `cd mpl && cargo test --test zz_bugrepro_05_short_edk_lookup -- --nocapture`. The test was copied into `mpl/tests/` for the run and deleted afterwards.

Observed output on `main` (`.agents/tasks/bug-recheck/logs/recheck05.log`):

```text
running 1 test
REPRO BUG-05b ciphertext_len=43: on_decrypt is_err=true keystore get_branch_key_version calls=0 inner_error=Some("Cryptographic: encrypted data key ciphertext too short to contain the branch key version: 43 bytes (need at least 44)")
REPRO BUG-05b ciphertext_len=44: on_decrypt is_err=true keystore get_branch_key_version calls=1 inner_error=Some("Cryptographic: ciphertext too short: 44 < 60")
REPRO BUG-05b ciphertext_len=50: on_decrypt is_err=true keystore get_branch_key_version calls=1 inner_error=Some("Cryptographic: ciphertext too short: 50 < 60")
REPRO BUG-05b ciphertext_len=59: on_decrypt is_err=true keystore get_branch_key_version calls=1 inner_error=Some("Cryptographic: ciphertext too short: 59 < 60")
REPRO BUG-05b ciphertext_len=60: on_decrypt is_err=true keystore get_branch_key_version calls=1 inner_error=Some("Cryptographic: AES-256-GCM decrypt failed <- Cryptographic: authentication tag did not match")
test short_edk_reaches_keystore_before_rejection ... ok
test result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.00s
```

The call counts are the same as in the original run at `a1e23d7` (`.agents/tasks/bug-reports/logs/bugrepro05.log`). Only the message text differs.

## Fix options

These options were written against `a1e23d7` and still apply on `main`, with one change for (b). BUG-02 has since been fixed on `main` (`e9bde48`, #98). That fix checks the key length in `add_data_key`, after the key store lookup and the AES-GCM open. It does not add an exact-length check before the lookup, so it does not resolve (b), as the re-check confirms. "Fold it into the BUG-02 fix" below would now mean adding that pre-lookup check as a separate change. The error type is now `aws_crypto_mpl::Error` instead of `MaterialsError`.

(a) keygen `.expect`:

1. Propagate the error, for example `.map_err(|e| MaterialsError::new_with_cause("DefaultCmm: ECDSA signing key generation failed", e))?`.
   - Pros: matches the Dafny Default CMM and needs no API change, since the function already returns `Result`.
   - Cons: none significant. Negligible cost.
2. Keep the `.expect`, but document and prove the invariant: treat a keygen failure as fatal, by design, like an RNG failure.
   - Pros: no code change.
   - Cons: diverges from Dafny, and leaves a panic on a library path that a C++ caller can reach.

Recommendation for (a): option 1.

(b) short EDK:

1. Check the exact length before the lookup. In `try_decrypt_edk`, require `ciphertext.len() == 60 + suite.encryption_key_length()` before the cache/keystore step.
   - Pros: rejects all wrong-length EDKs with no I/O, and also fixes BUG-02 C04-F1 on the hierarchical path.
   - Cons: diverges in ordering from Dafny, though not in outcome (both reject). Error text changes for 44–59-byte inputs.
2. Raise the pre-lookup minimum from 44 to 60 (`FIXED_OVERHEAD_LEN`).
   - Pros: the smallest change.
   - Cons: only addresses 44–59; wrong lengths of 60 or more still reach the keystore.
3. No change. Document that the ordering matches Dafny and that a full-length garbage EDK has the same cost.

Recommendation for (b): fold it into the BUG-02 fix (option 1 here). Otherwise option 3 is acceptable; this part on its own isn't worth a dedicated change.

## Questions for the engineers

1. Is a panic acceptable anywhere on the `DefaultCmm` encrypt path (for example by a policy treating entropy failure as fatal), or should all primitive failures surface as `MaterialsError` as in Dafny?
2. Are there other `.expect` calls on primitive `Result`s that the team considers "cannot fail"? The verification analysis lists `default_cmm.rs:100` (provably unreachable) and `cache_entry_identifier.rs:64`.
3. For (b), is matching Dafny's step order a goal, or is rejecting before I/O preferred when the outcome is the same?
4. If the BUG-02 exact-length check is adopted, should it run before the cache/keystore lookup (which would resolve this item) or inside `unwrap`?
