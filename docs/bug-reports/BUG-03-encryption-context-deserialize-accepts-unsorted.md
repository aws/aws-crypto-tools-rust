# BUG-03: `EncryptionContext::deserialize` accepts entries that are not sorted by key

Summary: `mpl::structures::EncryptionContext::deserialize` accepts key-value entries in any order and canonicalizes them into a `BTreeMap`. Two different byte strings therefore decode to the same context, and `serialize(deserialize(b)) != b` for non-canonical input, while the spec says the entries MUST be sorted.

- Confidence: Confirmed by test
- Spec conflict: yes. The spec's MUST describes the serialized form; whether a decoder must reject non-conforming input is an interpretation (see Expected behavior).
- Severity: Low. No production caller of this function exists in this repository: the ESDK header path uses its own parser, `esdk/src/message/encryption_context.rs::read_canonical_ec`. The function is public API, though, so external callers may rely on it.
- Related IDs: VR-2026-T15; TM-MPL-013, TM-MPL-017

## Location

Verified against `HEAD a1e23d7`. `mpl/src/structures/encryption_context.rs:109` (`deserialize`). Entries are inserted into a `BTreeMap` with a duplicate check only, and there's no comparison with the previous key:

```rust
125        let mut map = BTreeMap::new();
...
155            match map.entry(key) {
156                Entry::Occupied(occupied) => {
157                    return Err(MaterialsError::new(format!(
158                        "Duplicate key in encryption context: {:?}",
159                        occupied.key()
160                    )));
161                }
162                Entry::Vacant(vacant) => {
163                    vacant.insert(value);
164                }
165            }
```

`serialize` (line 69) iterates the `BTreeMap`, so it always emits ascending byte order. The defect is confined to the decoder.

## Expected behavior

`spec/framework/structures.md#key-value-pair-entries` (under `#serialization`):

> A sequence of one or more key-value pair entries.
> This sequence MUST NOT contain duplicate entries.
> These entries MUST be sorted, by key,
> in ascending order according to the UTF-8 encoded binary value.

The duplicate rule is enforced on decode. The sorting rule isn't. A strict reading treats both as validity conditions of the encoding, so a conforming decoder rejects input that violates either one. A lenient reading only constrains producers. The implementation already rejects duplicates, a zero count and trailing bytes on decode, which suggests the strict reading was intended.

The spec table also says keys and values are "UTF-8 encoded bytes". The reproducer shows `deserialize` accepts a non-UTF-8 key too. That's noted as related, not part of this finding.

## Actual behavior

1. The input is count = 2, then `("b" → "1")`, then `("a" → "2")`, in descending key order.
2. `deserialize` returns `Ok`.
3. The result equals `deserialize` of the sorted encoding.
4. `serialize` of the result emits the sorted bytes, which differ from the input, so the round trip isn't the identity.

## Impact

- No production path in this repo calls `EncryptionContext::deserialize`. I searched `mpl/src`, `esdk/src` and `prim/src`, and the only hit is the definition. The ESDK header parser `read_canonical_ec` keeps pairs in wire order as a `Vec` and doesn't use this function. That parser's own sorting behavior is out of scope for this finding and wasn't checked.
- If an external caller used `deserialize` to recover an EC and then re-serialized it to rebuild an AAD or signature input, the re-serialized bytes would differ from the original bytes. Authentication would then fail closed. It wouldn't cause a forgery: AES-GCM and signature checks still bind the exact bytes used.
- The main practical consequence is non-injectivity. Distinct encodings map to one value, which blocks proving `deserialize ∘ serialize = id` together with uniqueness of encodings (the T15 verification target). This is a correctness/canonicalization issue, not an exploitable vulnerability as far as I can tell.

## Reproduction / evidence

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

## Fix options

1. Reject out-of-order keys. Track the previous key and return `Err` unless `key > prev`. Strictly greater also subsumes the duplicate check.
   - Pros: the implementation matches the strict reading of the spec, and `deserialize` becomes the exact inverse of `serialize`.
   - Cons: a behavior change for any external caller that feeds non-canonical bytes. Cost is one byte-slice comparison per entry.
2. Keep accepting, but document it as lenient. State in the doc comment that `deserialize` canonicalizes, and add a separate `deserialize_strict` (or a `strict: bool` flag) for callers who need canonical input.
   - Pros: no behavior change.
   - Cons: the default stays non-conforming under the strict reading, and the API surface grows.
3. Option 1 plus UTF-8 validation of keys and values (the related observation).
   - Pros: fully aligned with the spec table.
   - Cons: a larger behavior change. It needs a decision on whether non-UTF-8 ECs should be representable at all in `mpl::EncryptionContext`, which stores `Vec<u8>`.

Recommendation: option 1, provided the team confirms the strict reading and no external caller depends on lenient decoding. Treat UTF-8 validation as a separate decision.

## Questions for the engineers

1. Is the spec's "MUST be sorted" intended to bind decoders (reject on read) or only encoders?
2. Do any consumers outside this repository (for example the DB-ESDK, or other crates) call `EncryptionContext::deserialize` on untrusted bytes?
3. How do the Dafny MPL / ESDK and other runtimes treat an unsorted EC on read? I didn't verify this, and the answer decides whether strict rejection here creates or removes a cross-runtime difference.
4. Should `mpl::EncryptionContext` keep allowing non-UTF-8 keys and values?
