# BUG-08: The custom encryption context "collision" error in `build_base` is dead code

Summary: `keystore::encryption_context::build_base` returns `Err` when inserting a prefixed custom encryption context key would overwrite an existing entry. Given how the map is built, that insert can never find an existing key, so the error branch is unreachable, and the comment describing when it fires is inaccurate. This is a code-quality finding, not a behavioral defect.

- Confidence: Confirmed by code reading
- Spec conflict: no
- Severity: Informational. Behavior is correct for all inputs. The cost is a misleading comment and an untestable branch, which also makes the C01 round-trip proof slightly harder to state.
- Related IDs: VR-2026-C01 (property (c)); cap:cat1 (1c)

## Location

Verified against `HEAD a1e23d7`. `mpl/src/keystore/encryption_context.rs:109-122`:

```rust
109            // A custom key that already carries the prefix, or a duplicate
110            // after prefixing, would otherwise overwrite a previous entry.
111            if ec
112                .insert(format!("{CUSTOM_EC_PREFIX}{key_str}"), val_str.to_string())
113                .is_some()
114            {
115                return Err(KeystoreError::new(
116                    KeystoreErrorKind::Configuration,
117                    format!(
118                        "custom encryption context key '{key_str}' collides with an existing \
119                         encryption context entry after prefixing with '{CUSTOM_EC_PREFIX}'"
```

## Expected behavior

`spec/framework/branch-key-store.md#custom-encryption-context`:

> To avoid name collisions each added attribute from the custom [encryption context](./structures.md#encryption-context-3)
> MUST be prefixed with `aws-crypto-ec:`.

The code meets this. Nothing in the spec requires the collision error. The finding is only that the branch can't be reached.

## Actual behavior

Why the insert at line 112 can never return `Some`:
1. Before the loop, `ec` holds exactly six keys (lines 59-78): `branch-key-id`, `type`, `create-time`, `tablename`, `kms-arn` and `hierarchy-version` (constants in `mpl/src/keystore/attributes.rs:11-18`). None of them starts with `aws-crypto-ec:`, so no prefixed key can equal a base key.
2. The custom EC is an `EncryptionContext(BTreeMap<Vec<u8>, Vec<u8>>)` (`mpl/src/structures/encryption_context.rs:13`), so its keys are distinct byte strings.
3. Strict UTF-8 decoding (lines 93-98, which reject invalid input) and prepending a fixed prefix are both injective. So distinct custom keys produce distinct prefixed keys, and no prefixed key collides with an earlier one.
4. The comment's first example, a custom key that already carries the prefix such as `aws-crypto-ec:a`, becomes `aws-crypto-ec:aws-crypto-ec:a`. That doesn't collide with the prefixed form of `a`.
5. The later inserts in `active_encryption_context` (`type`, `version`, lines 145-149) use unprefixed names, so they can't overwrite custom entries either.

## Impact

None on behavior. Every accepted custom EC is copied without loss. The effects are:
- The comment points readers to a failure mode that doesn't exist.
- The branch can't be covered by tests, and any error-handling expectations built around it are untested.
- A proof of C01 (c) has to establish the unreachability argument above. That's straightforward, but it's extra proof work for a branch with no purpose.

An existing test, `distinct_non_utf8_custom_ec_keys_do_not_collapse` (`mpl/tests/test_keystore_encryption_context.rs:234`), shows why the strict UTF-8 check matters: lossy decoding would make step 3 non-injective. With the current strict check, that case is rejected before the insert.

## Reproduction / evidence

Reproducer: `mpl/tests/zz_bugrepro_08_build_base_dead_branch.rs` (a temporary untracked test, removed from the tree after the run; full source below, copy in `.agents/tasks/bug-reports/reproducers/`). Command: `cd mpl && cargo test --test zz_bugrepro_08_build_base_dead_branch -- --nocapture`. The test feeds in the inputs the comment names (an already-prefixed key next to its unprefixed form) plus every base and reserved attribute name, and shows all of them are accepted with no entry lost. A test can't prove unreachability for all inputs; that rests on the code reading above.

```rust
// TEMPORARY reproducer for BUG-08 (C01(c)). Delete after running.
use aws_crypto_mpl::keystore::encryption_context::{
    EncryptionContextInput, active_encryption_context, decrypt_only_encryption_context,
};
use aws_crypto_mpl::structures::EncryptionContext;
#[test]
fn inputs_named_by_the_comment_do_not_reach_the_collision_branch() {
    let mut custom = EncryptionContext::new();
    // "A custom key that already carries the prefix":
    custom.insert(b"aws-crypto-ec:a".to_vec(), b"1".to_vec());
    custom.insert(b"a".to_vec(), b"2".to_vec());
    // Custom keys equal to every base key name:
    for k in ["branch-key-id", "type", "create-time", "tablename", "kms-arn", "hierarchy-version", "version", "enc"] {
        custom.insert(k.as_bytes().to_vec(), b"x".to_vec());
    }
    let input = EncryptionContextInput {
        branch_key_id: "bk",
        create_time: "2024-01-01T00:00:00Z",
        logical_keystore_name: "L",
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

Observed output (`.agents/tasks/bug-reports/logs/bugrepro08.log`):

```text
running 1 test
REPRO BUG-08 active is_ok = true, decrypt_only is_ok = true
REPRO BUG-08 10 custom entries in, 10 prefixed entries out: ["aws-crypto-ec:a", "aws-crypto-ec:aws-crypto-ec:a", "aws-crypto-ec:branch-key-id", "aws-crypto-ec:create-time", "aws-crypto-ec:enc", "aws-crypto-ec:hierarchy-version", "aws-crypto-ec:kms-arn", "aws-crypto-ec:tablename", "aws-crypto-ec:type", "aws-crypto-ec:version"]
test inputs_named_by_the_comment_do_not_reach_the_collision_branch ... ok
test result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.00s
```

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
