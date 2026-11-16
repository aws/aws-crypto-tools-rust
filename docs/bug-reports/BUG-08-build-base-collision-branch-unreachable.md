# BUG-08: The custom encryption context "collision" error in `build_base` is dead code

Summary: `keystore::encryption_context::build_base` returns `Err` when inserting a prefixed custom encryption context key would overwrite an existing entry. Given how the map is built, that insert can never find an existing key, so the error branch is unreachable, and the comment describing when it fires is inaccurate. This is a code-quality finding, not a behavioral defect.

- Confidence: Confirmed by code reading
- Spec conflict: no
- Severity: Informational. Behavior is correct for all inputs. The cost is a misleading comment and an untestable branch, which also makes the C01 round-trip proof slightly harder to state.
- Related IDs: VR-2026-C01 (property (c)); cap:cat1 (1c); TM-MPL-005 (High). `docs/threat-model.md` records BUG-08 as informational with no effect on the TM-MPL-005 rating. Ratings are from `docs/threat-model.md` (HEAD 9955ecd); targets are from `docs/verification-targets.md`.
- Completeness audit mapping (`docs/completeness-audit.md` section 3b): BUG-08 -> TM-MPL-005 -> C01 (c).
- Last cross-checked: HEAD 9955ecd (code == main 620771c for mpl/ and prim/)

## Status on main (620771c)

- Status: Still present.
- Re-checked: 2026-11-10, against `c256243` on `MPL-Verus` (code identical to `main` `620771c`). Details: [RECHECK-main-620771c.md](RECHECK-main-620771c.md), section BUG-08.
- Evidence: code reading, plus the test adapted for API changes only (1 passed). 10 custom entries go in and 10 prefixed entries come out, with no `Err`, the same as at `a1e23d7` (`.agents/tasks/bug-recheck/logs/recheck08.log`).
- The file moved from `mpl/src/keystore/` to `mpl/src/key_store/` in `e9bde48` (#98). The logic is unchanged. The custom EC is now a `BTreeMap<String, String>`, so its keys are distinct strings by type. The UTF-8 decoding step in the original argument (step 3 below) is no longer needed.

Line numbers outside the Status and Location sections refer to `a1e23d7`, where the bug was first found, and are kept as history.

## Location

Current code (`main` `620771c`): `build_base` (`mpl/src/key_store/encryption_context.rs:40`), custom-EC loop `:86-104`, dead `Err` `:95-101`:

```rust
89             // A custom key that already carries the prefix, or a duplicate
90             // after prefixing, would otherwise overwrite a previous entry.
91             if ec
92                 .insert(format!("{CUSTOM_EC_PREFIX}{key_str}"), val_str.to_string())
93                 .is_some()
94             {
95                 return Err(Error::new(
96                     Kind::Validation,
97                     format!(
98                         "custom encryption context key '{key_str}' collides with an existing \
99                          encryption context entry after prefixing with '{CUSTOM_EC_PREFIX}'"
```

Why the insert at `:92` still can never return `Some`, on current code:

- Before the loop, `ec` holds exactly six base keys, inserted at `:60-79`: `branch-key-id`, `type`, `create-time`, `tablename`, `kms-arn` and `hierarchy-version` (constants in `mpl/src/key_store/attributes.rs:11-17`). None of them starts with `aws-crypto-ec:` (`CUSTOM_EC_PREFIX`, `attributes.rs:24`).
- `custom_ec` (`encryption_context.rs:36`) is a `structures::EncryptionContext(BTreeMap<String, String>)` (`mpl/src/structures/encryption_context.rs:16`), so its keys are distinct, and prepending a fixed prefix keeps them distinct.

Originally reported at `a1e23d7`: `mpl/src/keystore/encryption_context.rs:109-122`; base keys at `:59-78`; constants in `mpl/src/keystore/attributes.rs:11-18`; custom EC as `EncryptionContext(BTreeMap<Vec<u8>, Vec<u8>>)` (`mpl/src/structures/encryption_context.rs:13`), decoded as strict UTF-8 at `:93-98`.

## Expected behavior

`spec/framework/branch-key-store.md#custom-encryption-context`:

> To avoid name collisions each added attribute from the custom [encryption context](./structures.md#encryption-context-3)
> MUST be prefixed with `aws-crypto-ec:`.

The code meets this. Nothing in the spec requires the collision error. The finding is only that the branch can't be reached.

## Actual behavior

Why the insert at line 112 can never return `Some`:
1. Before the loop, `ec` holds exactly six keys (lines 59-78): `branch-key-id`, `type`, `create-time`, `tablename`, `kms-arn` and `hierarchy-version` (constants in `mpl/src/keystore/attributes.rs:11-18`). None of them starts with `aws-crypto-ec:`, so no prefixed key can equal a base key.
2. At `a1e23d7` the custom EC was an `EncryptionContext(BTreeMap<Vec<u8>, Vec<u8>>)` (`mpl/src/structures/encryption_context.rs:13`), so its keys were distinct byte strings. On `main` it is a `BTreeMap<String, String>` (see Location).
3. Strict UTF-8 decoding (lines 93-98, which reject invalid input) and prepending a fixed prefix are both injective. So distinct custom keys produce distinct prefixed keys, and no prefixed key collides with an earlier one.
4. The comment's first example, a custom key that already carries the prefix such as `aws-crypto-ec:a`, becomes `aws-crypto-ec:aws-crypto-ec:a`. That doesn't collide with the prefixed form of `a`.
5. The later inserts in `active_encryption_context` (`type`, `version`, lines 145-149) use unprefixed names, so they can't overwrite custom entries either.

## Impact

None on behavior. Every accepted custom EC is copied without loss. The effects are:
- The comment points readers to a failure mode that doesn't exist.
- The branch can't be covered by tests, and any error-handling expectations built around it are untested.
- A proof of C01 (c) has to establish the unreachability argument above. That's straightforward, but it's extra proof work for a branch with no purpose.

An existing test, `distinct_non_utf8_custom_ec_keys_do_not_collapse` (`mpl/tests/test_keystore_encryption_context.rs:234` at `a1e23d7`), shows why the strict UTF-8 check matters: lossy decoding would make step 3 non-injective. With the current strict check, that case is rejected before the insert. On current code this test no longer exists (`git log -S` finds it only in `538dbd9` and `e9bde48`), because the custom EC is a `BTreeMap<String, String>` and the byte-level case cannot occur. The file is now `mpl/tests/test_key_store_encryption_context.rs`, which covers the prefixing (`custom_ec_keys_are_prefixed_with_aws_crypto_ec`, `:127`) but has no test for the collision `Err`.

## Reproduction / evidence

Re-check on `main` `620771c` (2026-11-10). The original reproducer no longer compiles against the current API (2 compile errors, kept at the top of the log). It was adapted for API changes only. The module path is now `aws_crypto_mpl::key_store::__test_internals::encryption_context`, and `EncryptionContext::insert` takes strings instead of `Vec<u8>`. The keys and values are the same. The test feeds in the inputs the comment names (an already-prefixed key next to its unprefixed form) plus every base and reserved attribute name, and shows all of them are accepted with no entry lost. A test can't prove unreachability for all inputs; that rests on the code reading above.

Adapted reproducer: [`zz_bugrepro_08_build_base_dead_branch.rs`](../../.agents/tasks/bug-recheck/reproducers/zz_bugrepro_08_build_base_dead_branch.rs). Command: `cd mpl && cargo test --test zz_bugrepro_08_build_base_dead_branch -- --nocapture`. The test was copied into `mpl/tests/` for the run and deleted afterwards.

```rust
use aws_crypto_mpl::key_store::__test_internals::encryption_context::{
    EncryptionContextInput, active_encryption_context, decrypt_only_encryption_context,
};
use aws_crypto_mpl::types::EncryptionContext;

#[test]
fn inputs_named_by_the_comment_do_not_reach_the_collision_branch() {
    let mut custom = EncryptionContext::new();
    // "A custom key that already carries the prefix":
    custom.insert("aws-crypto-ec:a", "1");
    custom.insert("a", "2");
    // Custom keys equal to every base key name:
    for k in ["branch-key-id", "type", "create-time", "tablename", "kms-arn", "hierarchy-version", "version", "enc"] {
        custom.insert(k, "x");
    }
    let input = EncryptionContextInput {
        branch_key_id: "bk",
        create_time: "2024-01-01T00:00:00Z",
        logical_key_store_name: "L",
        kms_arn: "arn:aws:kms:us-west-2:111122223333:key/k",
        hierarchy_version: 1,
        custom_ec: Some(&custom),
    };
    let act = active_encryption_context(&input, "11111111-2222-4333-8444-555555555555");
    let dec = decrypt_only_encryption_context(&input, "11111111-2222-4333-8444-555555555555");
    println!("REPRO BUG-08 active is_ok = {}, decrypt_only is_ok = {}", act.is_ok(), dec.is_ok());
    let act = act.unwrap();
    let custom_keys: Vec<&String> = act.keys().filter(|k| k.starts_with("aws-crypto-ec:")).collect();
    println!("REPRO BUG-08 {} custom entries in, {} prefixed entries out: {custom_keys:?}", custom.len(), custom_keys.len());
}
```

The header comment of the adapted file is omitted above. It records the same API changes.

Observed output on `main` (`.agents/tasks/bug-recheck/logs/recheck08.log`):

```text
running 1 test
REPRO BUG-08 active is_ok = true, decrypt_only is_ok = true
REPRO BUG-08 10 custom entries in, 10 prefixed entries out: ["aws-crypto-ec:a", "aws-crypto-ec:aws-crypto-ec:a", "aws-crypto-ec:branch-key-id", "aws-crypto-ec:create-time", "aws-crypto-ec:enc", "aws-crypto-ec:hierarchy-version", "aws-crypto-ec:kms-arn", "aws-crypto-ec:tablename", "aws-crypto-ec:type", "aws-crypto-ec:version"]
test inputs_named_by_the_comment_do_not_reach_the_collision_branch ... ok
test result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.00s
```

The output is identical to the original run at `a1e23d7`.

## Fix options

1. Keep the check as defense-in-depth and fix the comment. State that the branch is unreachable by construction and guards against future changes (for example, a base key that starts with the prefix, or a switch back to lossy decoding).
   - Pros: no behavior change, and the code stays robust against future edits.
   - Cons: the branch stays untestable.
2. Replace the runtime `Err` with `debug_assert!(prev.is_none(), ...)` and a corrected comment.
   - Pros: the invariant is documented and checked in debug and test builds, and there's no dead error path.
   - Cons: release builds would silently overwrite if a future change made a collision possible.
3. Leave the code as it is and discharge the branch with the Verus C01 (c) proof.
   - Pros: the property becomes machine-checked.
   - Cons: the misleading comment stays unless it's also edited.

Recommendation: option 1 (comment fix only). If the C01 proof is pursued, option 3 can follow without further code change.

## Questions for the engineers

1. Was the branch meant to guard against a specific input I haven't considered, such as keys from a stored record, which the input's doc comment says take a different path?
2. Do you prefer to keep an unreachable runtime check as defense-in-depth, or replace it with a debug assertion?
3. Should the base attribute names be asserted (at compile time or in a test) never to start with `aws-crypto-ec:`, so the argument in step 1 stays true?
