# BUG-03: `EncryptionContext::deserialize` accepts entries that are not sorted by key

Status: Fixed on main in `e9bde48` (#98). See "Status on main (620771c)" below.

Summary (as found at `a1e23d7`): `mpl::structures::EncryptionContext::deserialize` accepted key-value entries in any order and canonicalized them into a `BTreeMap`. Two different byte strings therefore decoded to the same context, and `serialize(deserialize(b)) != b` for non-canonical input, while the spec says the entries MUST be sorted.

- Confidence: Confirmed by test
- Spec conflict: yes. The spec's MUST describes the serialized form; whether a decoder must reject non-conforming input is an interpretation (see Expected behavior).
- Severity: Low. No production caller of this function exists in this repository: the ESDK header path uses its own parser, `esdk/src/message/encryption_context.rs::read_canonical_ec`. The function is public API, though, so external callers may rely on it.
- Related IDs: VR-2026-T15; TM-MPL-013, TM-MPL-017

## Status on main (620771c)

- Status: Fixed on main.
- Re-checked: 2026-11-10, against `c256243` on `MPL-Verus` (code identical to `main` `620771c`). Details: [RECHECK-main-620771c.md](RECHECK-main-620771c.md), section BUG-03.
- Evidence: with the reproducer adapted for API changes only, `from_bytes(unsorted)` returns `Err(Validation: encryption context keys are not in ascending order)`, so the test fails at its original `unwrap()`. The related non-UTF-8 observation is now `is_ok = false` (`.agents/tasks/bug-recheck/logs/recheck03.log`).
- Fixing commit: `e9bde48` "feat(esdk): retarget the ESDK and C++ shim onto the native Rust MPL (#98)" (found with `git log -S "not in ascending order"`).
- Where the fix lives: `EncryptionContext::from_bytes` (`mpl/src/structures/encryption_context.rs:145`, the renamed `deserialize`). It rejects a duplicate key (`:199`) and a key lower than the previous one (`:205-210`). It also rejects non-UTF-8 keys and values (`utf8`, `:230`).

The sections after Location are the original analysis at `a1e23d7`, kept as history. Their line numbers refer to `a1e23d7`.

## Location

Current code (`main` `620771c`), `mpl/src/structures/encryption_context.rs:198-211`:

```rust
198             if let Some((previous, _)) = map.last_key_value() {
199                 if key == *previous {
200                     return Err(Error::new(
201                         Kind::Validation,
202                         format!("duplicate key in encryption context: {key:?}"),
203                     ));
204                 }
205                 if key < *previous {
206                     return Err(Error::new(
207                         Kind::Validation,
208                         "encryption context keys are not in ascending order",
209                     ));
210                 }
211             }
```

The type is now exported as `aws_crypto_mpl::types::EncryptionContext`, with `from_bytes` / `to_bytes` in place of `deserialize` / `serialize`.

Originally reported at `a1e23d7`: `mpl/src/structures/encryption_context.rs:109` (`deserialize`). Entries were inserted into a `BTreeMap` with a duplicate check only (`:155-165`), and there was no comparison with the previous key. `serialize` (`:69`) always emitted ascending order.

## Original analysis at a1e23d7 (history)

The rest of this report describes the behavior at `a1e23d7`, before the fix.

### Expected behavior

`spec/framework/structures.md#key-value-pair-entries` (under `#serialization`):

> A sequence of one or more key-value pair entries.
> This sequence MUST NOT contain duplicate entries.
> These entries MUST be sorted, by key,
> in ascending order according to the UTF-8 encoded binary value.

The duplicate rule is enforced on decode. The sorting rule isn't. A strict reading treats both as validity conditions of the encoding, so a conforming decoder rejects input that violates either one. A lenient reading only constrains producers. The implementation already rejects duplicates, a zero count and trailing bytes on decode, which suggests the strict reading was intended.

The spec table also says keys and values are "UTF-8 encoded bytes". The reproducer shows `deserialize` accepts a non-UTF-8 key too. That's noted as related, not part of this finding.

### Actual behavior

1. The input is count = 2, then `("b" → "1")`, then `("a" → "2")`, in descending key order.
2. `deserialize` returns `Ok`.
3. The result equals `deserialize` of the sorted encoding.
4. `serialize` of the result emits the sorted bytes, which differ from the input, so the round trip isn't the identity.

### Impact

- No production path in this repo calls `EncryptionContext::deserialize`. I searched `mpl/src`, `esdk/src` and `prim/src`, and the only hit is the definition. The ESDK header parser `read_canonical_ec` keeps pairs in wire order as a `Vec` and doesn't use this function. That parser's own sorting behavior is out of scope for this finding and wasn't checked.
- If an external caller used `deserialize` to recover an EC and then re-serialized it to rebuild an AAD or signature input, the re-serialized bytes would differ from the original bytes. Authentication would then fail closed. It wouldn't cause a forgery: AES-GCM and signature checks still bind the exact bytes used.
- The main practical consequence is non-injectivity. Distinct encodings map to one value, which blocks proving `deserialize ∘ serialize = id` together with uniqueness of encodings (the T15 verification target). This is a correctness/canonicalization issue, not an exploitable vulnerability as far as I can tell.

### Reproduction / evidence

Reproducer: `mpl/tests/zz_bugrepro_03_ec_unsorted.rs` (a temporary untracked test, removed from the tree after the run; full source below, copy in `.agents/tasks/bug-reports/reproducers/`). Command: `cd mpl && cargo test --test zz_bugrepro_03_ec_unsorted -- --nocapture`.

```rust
// TEMPORARY reproducer for BUG-03 (T15). Delete after running.
use aws_crypto_mpl::structures::EncryptionContext;
#[test]
fn deserialize_accepts_unsorted_entries() {
    // count = 2, then ("b" -> "1"), ("a" -> "2"): keys in DESCENDING order.
    let unsorted: Vec<u8> = vec![0x00, 0x02, 0x00, 0x01, b'b', 0x00, 0x01, b'1', 0x00, 0x01, b'a', 0x00, 0x01, b'2'];
    // Same pairs, ascending order (the only spec-conformant encoding).
    let sorted: Vec<u8> = vec![0x00, 0x02, 0x00, 0x01, b'a', 0x00, 0x01, b'2', 0x00, 0x01, b'b', 0x00, 0x01, b'1'];
    let ec_u = EncryptionContext::deserialize(&unsorted);
    println!("REPRO BUG-03 deserialize(unsorted) is_ok = {}", ec_u.is_ok());
    let ec_u = ec_u.unwrap();
    let ec_s = EncryptionContext::deserialize(&sorted).unwrap();
    println!("REPRO BUG-03 deserialize(unsorted) == deserialize(sorted): {}", ec_u == ec_s);
    let re = ec_u.serialize().unwrap();
    println!("REPRO BUG-03 input     = {unsorted:02x?}");
    println!("REPRO BUG-03 serialize = {re:02x?}");
    println!("REPRO BUG-03 serialize(deserialize(b)) == b: {}", re == unsorted);
}
#[test]
fn related_deserialize_accepts_non_utf8() {
    // count = 1, key = [0xFF] (not UTF-8), value = "v".
    let b: Vec<u8> = vec![0x00, 0x01, 0x00, 0x01, 0xFF, 0x00, 0x01, b'v'];
    println!("REPRO BUG-03 (related) deserialize(non-UTF-8 key) is_ok = {}", EncryptionContext::deserialize(&b).is_ok());
}
```

Observed output (`.agents/tasks/bug-reports/logs/bugrepro03.log`):

```text
running 2 tests
REPRO BUG-03 (related) deserialize(non-UTF-8 key) is_ok = true
REPRO BUG-03 deserialize(unsorted) is_ok = true
REPRO BUG-03 deserialize(unsorted) == deserialize(sorted): true
REPRO BUG-03 input     = [00, 02, 00, 01, 62, 00, 01, 31, 00, 01, 61, 00, 01, 32]
REPRO BUG-03 serialize = [00, 02, 00, 01, 61, 00, 01, 32, 00, 01, 62, 00, 01, 31]
REPRO BUG-03 serialize(deserialize(b)) == b: false
test related_deserialize_accepts_non_utf8 ... ok
test deserialize_accepts_unsorted_entries ... ok
test result: ok. 2 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.00s
```

### Re-check on main (620771c)

The reproducer was adapted for API renames only: `structures::EncryptionContext` became `types::EncryptionContext`, `deserialize` became `from_bytes`, and `serialize` became `to_bytes`. It also prints the `Err` text before the original `unwrap()`. The byte strings are the same. Adapted reproducer: [`zz_bugrepro_03_ec_unsorted.rs`](../../.agents/tasks/bug-recheck/reproducers/zz_bugrepro_03_ec_unsorted.rs). Same command as above.

Observed output on `main` (`.agents/tasks/bug-recheck/logs/recheck03.log`, trimmed):

```text
running 2 tests
REPRO BUG-03 deserialize(unsorted) is_ok = false
REPRO BUG-03 deserialize(unsorted) Err = Validation: encryption context keys are not in ascending order
thread 'deserialize_accepts_unsorted_entries' (6401694) panicked at tests/zz_bugrepro_03_ec_unsorted.rs:18:21:
called `Result::unwrap()` on an `Err` value: Validation(ValidationError { message: "encryption context keys are not in ascending order" })
REPRO BUG-03 (related) deserialize(non-UTF-8 key) is_ok = false
test deserialize_accepts_unsorted_entries ... FAILED
test related_deserialize_accepts_non_utf8 ... ok
test result: FAILED. 1 passed; 1 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.00s
```

The test was written to pass while the bug is present, so the failure at the original `unwrap()` is the evidence that the decoder now rejects unsorted input.

## Resolved

Fixed on `main` in `e9bde48` (#98), as described in the Status section. The decoder now follows the strict reading of the spec. Out-of-order and duplicate keys are rejected, and so are non-UTF-8 keys and values. This is fix option 3 from the original report (option 1 plus UTF-8 validation). The original fix options are no longer needed and were removed from this report. They remain in the git history of this file.

Questions that may still be relevant:

1. How do the Dafny MPL / ESDK and other runtimes treat an unsorted or non-UTF-8 EC on read? This was not checked. The answer shows whether the new strict decoder removes a cross-runtime difference or creates one.
2. Do any consumers outside this repository depend on the old lenient decoding, or on the old `deserialize` name?
