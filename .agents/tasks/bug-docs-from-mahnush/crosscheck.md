# Cross-check: what Mahnush_Verus 2d229377 proves for BUG-07(a)

Fetch (read-only): `git -c credential.helper= -c credential.helper='!gh auth git-credential' fetch https://github.com/aws/aws-crypto-tools-rust.git +refs/heads/Mahnush_Verus:refs/remotes/origin/Mahnush_Verus` -> `43b9ff7..8d6381e`. `2d229377` is an ancestor of the new tip `8d6381e`; the one commit after it is docs-only (`docs/verus-proofs-report.md`). `git diff --stat 43b9ff7 2d229377 -- prim` is empty, so `prim/src/lib.rs` at 2d229377 is the code our review at 43b9ff7 read.

Read with `git show 2d229377:prim/src/lib.rs` (lines 380-439, 441-501) and `git show 2d229377:prim/src/aws_lc_specs.rs` (lines 366-404).

## `aes_encrypt_core` `ensures` at 2d229377 (prim/src/lib.rs:397, `ensures` at :405-416)

```rust
    ensures
        (r matches Err(AesEncryptCoreError::InvalidKey) || r matches Err(
            AesEncryptCoreError::InvalidNonce,
        )) ==> final(cipher_text)@ == old(cipher_text)@ + message@,
        r matches Err(AesEncryptCoreError::SealFailed) ==> final(cipher_text)@.len() == old(
            cipher_text,
        )@.len() + message@.len() && final(cipher_text)@.subrange(0, old(cipher_text)@.len() as int)
            == old(cipher_text)@,
        r is Ok ==> final(cipher_text)@.len() == old(cipher_text)@.len() + message@.len() + 16
            && final(cipher_text)@.subrange(0, old(cipher_text)@.len() as int) == old(
            cipher_text,
        )@,
```

In-body, after the tag is appended (`:437`):

```rust
    // The tag is appended after the ciphertext.
    assert(cipher_text@ =~= o + ct + tag_bytes@);
```

Doc comment (`:387-396`), Mahnush_Verus's own wording: "seal failed: length `|o| + |m|`, prefix `o` unchanged (the tail bytes are whatever the seal left; A18 says nothing about them)"; "`Ok`: length `|o| + |m| + 16`, prefix `o` unchanged, and the tag is appended after the ciphertext (the `+ 16` rests on A19)"; "No crypto property is proven."

Trusted assumptions used (`prim/src/aws_lc_specs.rs`):
- A18 (`:366-376`): `seal_in_place_separate_tag` keeps `in_out` length. "Nothing about the bytes written."
- A19 (`:378-385`): `Tag::as_ref` has length 16, labeled "TRUSTED length".
- A20 = A-OPEN (`:387-404`): `open_separate_gather` `Ok ==> |in_ciphertext| == |out_plaintext|`; labeled "LABELED ASSUMPTION A-OPEN, not proven".

## Result per sub-claim of Finding 1 "BUG-07(a): PROVED"

| Sub-claim | Exported `ensures`? | Status at 2d229377 |
|---|---|---|
| Key or nonce Err: buffer is exactly `old ++ message` | Yes (clause 1) | Proved (relative to A14-A17 no-panic specs; no length/byte assumption needed) |
| Seal Err: length `old + |message|`, prefix `old` | Yes (clause 2) | Proved, relying on A18 for the length. Tail contents are not described (doc comment says so) |
| Ok: buffer is `old ++ ciphertext ++ 16-byte tag` | Only length `old+|m|+16` and prefix `old` are exported (clause 3) | The "ciphertext then tag" order is an in-body `assert` (`:437`), checked by Verus inside the function but not part of the contract callers see. `ct` is the ghost value of the slice after the seal, whose bytes A18 leaves unconstrained. The `+16` rests on trusted A19 |

Unchanged since our review at 43b9ff7 (`.agents/tasks/review-vr013-vr014/report.md`, item 6a). A Reviewer note is warranted, because "Ok: the buffer is `old ++ ciphertext ++ 16-byte tag`" under "PROVED" is stronger than the exported postcondition. The key/nonce and seal-Err statements match the `ensures` exactly.

## BUG-07(b) / A-OPEN line numbers

Finding 1 cites aws-lc-rs 1.18.1 `src/aead/unbound_key.rs:139-142`. Mahnush_Verus's comments (`aws_lc_specs.rs:387-391`, `lib.rs:458-461` region, `docs/verus-proofs-report.md:593`) cite `:136-139`. In the local registry copy (`~/.cargo/registry/src/index.crates.io-*/aws-lc-rs-1.18.1/src/aead/unbound_key.rs`) the comment is at `:139`, `if in_ciphertext_len != out_plaintext_len {` at `:140`, `return Err(Unspecified);` at `:141`, `}` at `:142` (reviewer-corrected; the finding's `:139-142` is exact). Mahnush_Verus's own `:136-139` is a few lines off. The BUG-07 section quotes the finding's citation and gives the local line numbers.
