# BUG-10: `RawAesKeyring::on_decrypt` drops an authenticated plaintext data key without wiping it when its length is wrong

Summary: in the raw AES keyring's EDK loop, the decrypt buffer is a plain `Vec<u8>`. When `aes_decrypt` succeeds but the recovered key has the wrong length for the algorithm suite, the loop `continue`s and the authenticated plaintext data key is dropped without being zeroized. On the success path the same buffer moves into `PlaintextDataKey`, which is `ZeroizeOnDrop`.

- Source: found on the `Mahnush_Verus` branch (aws/aws-crypto-tools-rust, tip `2d229377`, PR #103) while reviewing the mpl decrypt sites for BUG-07 (Finding 2 there). It is a separate zeroization issue and not part of [BUG-07](BUG-07-prim-aes-buffer-handling.md). Quoted text is the other branch's wording; every location below was re-found by function name on `MPL-Verus`.
- Confidence: Confirmed by code reading. No reproducer was run, and there is no proof: mpl is not Verus-enabled on either branch.
- Spec conflict: no
- Severity: Low (confidentiality). A decrypted data key can stay in freed heap memory. Reading it needs access to the process memory, and mpl otherwise zeroizes key material.
- Related IDs: VR-2026-T26; TM-MPL-015 (Low). Ratings are from `docs/mpl-threat-model.md`; targets are from `docs/mpl-verification-targets.md`. Both documents already list this site as a known residual (see "Relation to TM-MPL-015 and T26" below); neither was edited for this report.
- Completeness audit mapping: not listed in `docs/mpl-completeness-audit.md` section 3b, which predates this report. By content: BUG-10 -> TM-MPL-015 -> T26.
- Last cross-checked: HEAD e3abf2d (code == main 620771c for mpl/ and prim/)

## Status on main (620771c)

- Status: Still present.
- Checked: 2026-11-17, by code reading on `MPL-Verus` HEAD `e3abf2d`. `git diff --stat 620771c HEAD -- mpl prim` is empty, so this is the code on `main`. `mpl/src/keyring/raw_aes_keyring.rs` and `mpl/src/aws_kms/branch_key_wrap.rs` are also identical on `Mahnush_Verus` `2d229377`, so the line numbers in the original finding (~:471-496, ~:275) match ours.
- Evidence: code reading only. Per-claim check: `.agents/tasks/bug-docs-from-mahnush/claims.md` (rows F2.1-F2.7).

## Location

`RawAesKeyring::on_decrypt` (`mpl/src/keyring/raw_aes_keyring.rs:422`), EDK loop. Buffer at `:471`, wrong-length `continue` at `:489-494`, success move at `:497`:

```rust
471             let mut plaintext_dk = vec![0u8; encrypted_key.len()];
472             if let Err(e) = aes_decrypt(
...
489             if plaintext_dk.len() != expected_dk_len {
490                 collected_errors.push(Error::new(Kind::Cryptographic, format!(
491                     "encrypted data key {index}: decrypted data key is {} bytes, expected {expected_dk_len} for the algorithm suite",
492                     plaintext_dk.len(),
493                 )));
494                 continue;
495             }
496
497             let materials = materials.add_data_key(PlaintextDataKey::new(plaintext_dk))?;
```

`expected_dk_len` comes from the materials' algorithm suite (`:441`). `PlaintextDataKey` derives `Zeroize, ZeroizeOnDrop` and `new` moves the `Vec` without copying (`mpl/src/structures/algorithm_suite.rs:505-506`, `:517-519`). The file already imports `zeroize::Zeroizing` (`:15`).

Related site: `branch_key_wrap::unwrap` (`mpl/src/aws_kms/branch_key_wrap.rs:230`) also holds its decrypt buffer as a plain `Vec<u8>` (`:275`) and returns a bare `Vec<u8>` (`:234`, `:290`). The hierarchical keyring wraps it in `PlaintextDataKey` (`mpl/src/aws_kms/hierarchical_keyring.rs:767`, after the call at `:958`).

## Expected behavior

No spec requirement; this is defense-in-depth. The mpl convention is that key material is zeroized: `PlaintextDataKey`, the wrapping key, branch key materials and the derived branch key all zeroize on drop (TM-MPL-015 mitigations in `docs/mpl-threat-model.md`). T26 states the property: "Every buffer that held key plaintext is wiped or moved into a ZeroizeOnDrop owner on every exit path."

## Actual behavior

1. An EDK passes the provider filter, and `aes_decrypt` authenticates it and writes the key into `plaintext_dk` (`:471-487`).
2. The key length differs from `expected_dk_len`, so the loop records an error and `continue`s (`:489-494`).
3. `plaintext_dk` goes out of scope as a plain `Vec<u8>`. Its heap allocation is freed with the authenticated key bytes still in it.

For `unwrap` the effect is narrower on our code. Its result is moved, not copied, into `PlaintextDataKey` at `hierarchical_keyring.rs:767`. A wrong-length key is rejected afterwards by `add_data_key` (`mpl/src/structures/decryption_materials.rs:56`, `check_data_key_length` at `algorithm_suite.rs:547`), when it is already inside `PlaintextDataKey`, so it is wiped on drop. What remains there is the bare `Vec` between `unwrap` and the wrapper, which is a type-level gap rather than an un-wiped drop.

Not checked: whether aws-lc-rs leaves decrypted bytes in the output buffer when `open_separate_gather` fails. That decides whether the `aes_decrypt` `Err` path (`:472-487`, also a `continue`) leaves data in `plaintext_dk`. TM-MPL-015 lists that path as a residual too.

## Impact and preconditions

- Precondition: an EDK for this keyring that authenticates under the wrapping key and the encryption context, but decrypts to a key whose length does not match the suite. Producing such an EDK needs the wrapping key, or a message whose algorithm suite no longer matches the key that was wrapped. By code reading, the raw AES AAD is the serialized encryption context only (`:436-439`), so the EDK does not bind the suite. Whether the ESDK passes such a header to the keyring (for example under a commitment policy that allows non-committing suites) was not traced.
- Effect: one un-wiped copy of a data key in freed heap memory per such EDK. Decryption of that EDK fails; the loop goes on to the next EDK.
- Exploitation needs a way to read process memory (core dump, swap, a memory-disclosure bug elsewhere). The threat model treats this as an attacker already inside the process, which is why TM-MPL-015 is Low.

## Relation to TM-MPL-015 and T26

This site is already in scope. `docs/mpl-threat-model.md` lists under TM-MPL-015's residual exposures "the raw-AES decrypt buffer on the AES-error and wrong-length paths (`raw_aes_keyring.rs:471`, `:489`)" and "the `Vec` returned by `branch_key_wrap::unwrap` before it is wrapped in `PlaintextDataKey`". T26's target lists "raw-AES on_decrypt buffer (:471, :489)" and `branch_key_wrap::unwrap`, and its property expects to fail on "(F1) raw-AES on_decrypt drops `plaintext_dk` unwiped on the aes_decrypt-Err and wrong-length paths" and "(F3) unwrap's returned Vec ... plain Vec<u8> between producer and wrapper" (`docs/mpl-verification-targets/01-threat-driven.md:826-829`). No bug report existed for it before this one. T26's proof status is "None yet".

## Evidence

Code reading only, on `MPL-Verus` HEAD `e3abf2d`. The finding on `Mahnush_Verus` is also code reading ("no proof (mpl is not Verus-enabled)"). No test in `mpl/tests` reaches the wrong-length path of the raw AES keyring with a check on memory contents; a test could not observe freed memory directly in any case.

## Fix options

1. Hold the decrypt buffer in `on_decrypt` as `Zeroizing<Vec<u8>>`, and move the bytes out into `PlaintextDataKey` on success (for example with `std::mem::take`). Do the same for `unwrap`'s buffer. This is the Mahnush_Verus recommendation.
   - Pros: every exit path (wrong length, `aes_decrypt` `Err`, success) is covered; no change in behavior or errors.
   - Cons: a small edit at two sites.
2. In addition, have `unwrap` return `PlaintextDataKey` instead of a bare `Vec<u8>` (the optional part of the recommendation).
   - Pros: the type carries the zeroization from the producer; closes T26 F3 for this site.
   - Cons: changes the signature of a crate-internal function that the `test-utils` feature re-exports to integration tests (`mpl/src/aws_kms/mod.rs:25`).
3. Zeroize `plaintext_dk` explicitly before each `continue`.
   - Pros: smallest diff.
   - Cons: easy to miss on a future exit path.

Recommendation: option 1, with option 2 if the test-utils signature change is acceptable. Neither is implemented.

## Questions for the engineers

1. Should wrong-length rejection move before the decrypt (an exact-length check on the EDK ciphertext), so no wrong-length key is ever produced? The same question is open for the hierarchical keyring under BUG-02.
2. Is the raw AES keyring meant to bind the algorithm suite, or is suite binding left to the ESDK header authentication? This decides how reachable the wrong-length path is.
3. Should T26's expected-FAIL list cite this report as the bug for F1?
