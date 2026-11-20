# Review notes 4: behavior preservation and test file (VR-013 / VR-014)

Branch Mahnush_Verus, tip 43b9ff7 (ed4a81e code, 43b9ff7 docs) vs base 6b51de8. Read-only review; no tracked file, branch or worktree was modified (`git status` clean in both worktrees, HEAD unchanged).

## Item 5: behavior preservation

### Method
1. Read `git -C /tmp/review-mahnush-verus diff 6b51de8 HEAD -- prim/src prim/Cargo.toml` function by function (touched: lib.rs, ecdsa.rs, new aws_lc_specs.rs, Cargo.toml lint entry).
2. Differential harness at `/tmp/review-vr013-harness/`:
   - `src/main.rs` = one transcript program; `base/` and `tip/` are two cargo projects (identical main.rs, same Cargo.lock) that depend on the base / tip `prim` by path.
   - aws-lc-rs 1.19.0, aws-lc-sys 0.47.0, vstd 0.0.0-2026-06-14-0213 in both builds. Release profile.
   - Output: `out-base.txt`, `out-tip.txt` (1443 lines each, 1359 of them Err lines). Each line holds Ok/Err, `Display` text, `Debug` text, output buffer bytes and length.
3. Commands:
```
export CARGO_TARGET_DIR=/tmp/review-vr013-harness/target
cd /tmp/review-vr013-harness/base && cargo build --release
cp base/Cargo.lock tip/Cargo.lock; sed -i '' 's/harness-base/harness-tip/' tip/Cargo.lock
cd tip && cargo build --release --locked
cd .. && target/release/harness-base > out-base.txt; target/release/harness-tip > out-tip.txt
diff out-base.txt out-tip.txt      # empty
```
Result: `diff` is empty; sha256 of both transcripts `b1d771fe...890c1`. The two binaries differ (d23684f8... vs 79560a0a...), so the tip code was really exercised.

### Cases covered
- aes_encrypt: Aes128/192/256, initial Vec empty and `HDR:`, message len 0/4/100: success; bad key length (0,15,17,31,33 where not the valid one); bad nonce length (0,11,13,16); bad key and bad nonce together (precedence). Compared Ok/Err, texts, final Vec bytes and length.
- aes_decrypt: three algs, ct 0/4/100 bytes, plaintext buffer lengths ct-1, ct, ct+1, ct+16, buffer pre-filled 0x00 and 0xAA; good inputs, flipped tag, wrong AAD, bad key length, bad nonce length, 8-byte tag. Buffer bytes after the call compared.
- hmac (key "key"/msg "msg" and empty/empty), digest, DigestContext::finish (also `output_len()`): all of Sha256/384/512, out length 0..=80, buffer pre-filled 0xEE (checks "unchanged on Err").
- kbkdf_ctr_hmac: Sha256/384/512, okm length 0,1,16,32,64,100,1000,8160,100000, and empty ikm; Ok/Err, text, length, hash of okm bytes.
- generate_random_bytes: lengths 0,1,32,1000,2^20 (Ok + length).
- constant_time_equal: equal, empty/empty, unequal, both length mismatch directions, empty vs non-empty.

### Per-function verdicts (all identical in the transcript and by reading the diff)
| Function | Verdict | Notes from the diff |
|---|---|---|
| aes_encrypt | identical | Same order: extend plaintext, then key, nonce, LessSafeKey, Aad, seal, then tag append. Messages "invalid AES-GCM key" / "invalid AES-GCM nonce" / "AES-GCM encryption failed" unchanged (`serr` via map_err). BUG-07(a) preserved: on bad key / bad nonce the Vec is `old ++ plaintext` (e.g. `HDR:asdf`, len 8). Success appends ciphertext then 16-byte tag. Seal-failure path not reachable from the public API; identical by inspection. |
| aes_decrypt | identical | Guard `aes_decrypt_len_ok` still first. Error texts the same ("plaintext buffer of N bytes is shorter than the M byte ciphertext", key, nonce, "authentication tag did not match"). `err(..)` is `Err(serr(..))`, so mapping is the same. `get_aes_alg` now runs before the guard; it is a pure const fn. BUG-07(b) preserved: pt = ct+1 and ct+16 pass the guard and fail in the callee with the tag-mismatch text; buffer left all zeros. |
| hmac | identical (one assumption) | Guard length now `hmac_alg.tag_len()` instead of `get_digest_alg(alg).output_len()`. In aws-lc-rs 1.18.1 and 1.19.0 source `tag_len()` is `digest_algorithm().output_len`, and HMAC_SHA256/384/512 wrap digest::SHA256/384/512, so the value is equal. Message uses the same `want_len` and `{alg:?}`. Guard now runs after the alg match (no side effect). If a future aws-lc-rs made tag_len differ, behavior would change; the Cargo requirement `1.18.1` allows newer versions. |
| digest | identical | Guard + copy moved into `digest_core`; same `output_len()`, same message built from `e.want_len`; `out` untouched on Err. |
| DigestContext::finish | identical | `want_len` = `context.algorithm().output_len()`, which is what `self.output_len()` returned. Same message; context dropped without finalizing on Err, copy only after the guard. |
| kbkdf_ctr_hmac | identical | Lookup `None` -> "KBKDF-CTR-HMAC-{alg:?} algorithm is unavailable"; derivation Err -> "KBKDF-CTR-HMAC derivation failed". The unavailable branch cannot be reached through the public API (only 3 algs, all provided), so it is checked by inspection only. |
| generate_random_bytes | identical | `rand::fill` wrapped by `fill_random_core`; same message with `bytes.len()`. |
| constant_time_equal | identical | `ct_equal_core` returns `verify_slices_are_equal(a,b).is_ok()`. |
| Cargo.toml / lib.rs attrs / aws_lc_specs.rs | no runtime effect | `[lints.rust] unexpected_cfgs` entry (appended without a blank line before the table), `cfg_attr(verus_keep_ghost, feature(sized_hierarchy))`, and a new module that is only specs / `assume_specification` / external_body ghost items. `cargo build` of the tip gives 0 warnings. |

Error values carry no source location (`#[track_caller]` on `serr` only; Error holds message + lazy backtrace), so moving the construction site changes nothing observable.

No change to behavior, error text or the BUG-07 buffer behavior was found.

### BUG-07 status
Preserved as-is and not fixed: (a) plaintext stays appended on any Err after the extend; (b) the guard `plain.len() < ct.len()` is weaker than the callee's check, and longer buffers fail with "authentication tag did not match". VR-014's formal statements about (b) rest on assumption A20 (open_separate_gather returns Ok only when lengths are equal) and the `+16` tag length on A19; the harness confirms both empirically for the tested inputs, but they are assumed, not proved.

## Item 6: test file `prim/tests/test_wrapper_contracts.rs`
7 tests, no env vars, credentials, network, AWS SDK or files (grep found none); deterministic fixed keys/IVs.

| Test | Checks | Assessment |
|---|---|---|
| digest_exact_length_only | all algs, out = n-1 and n+1: Err with exact message, buffer unchanged; out = n Ok | Pins the length contract and message. Ok case only unwraps (digest value checked in test_digest.rs). |
| hmac_exact_length_only | same for hmac | Same. |
| digest_context_finish_exact_length_only | n-1, n+1 Err with message, `output_len()==n`, buffer unchanged; Ok output equals `digest()` | Good. Equality against `digest` is a consistency check, not an independent known-answer. |
| aes_encrypt_err_leaves_plaintext_appended | Aes256 only, initial `HDR:`; bad key (15 bytes) and bad nonce (11 bytes): Err text and buffer == `HDR:asdf` | Pins BUG-07(a) precisely (contents, not just length). Comment says to update when owners fix it. Does not cover seal failure or an empty initial Vec. |
| aes_encrypt_ok_appends_ciphertext_then_tag | length old+4+16, prefix kept, tail equals a fresh encryption | Good; deterministic because key/IV fixed. |
| aes_decrypt_buffer_length_cases | ct+1 and ct+16 -> "authentication tag did not match"; ct-1 -> "shorter than" message with numbers; ct -> Ok and plaintext equals | Pins BUG-07(b): inputs are valid, so the only reason for failure is the length, and the different message shows the guard was passed. Does not assert the buffer is untouched on those Err cases. |
| kbkdf_empty_okm_is_derivation_failure | empty okm -> "derivation failed" for 3 algs | Narrow. No valid-derivation test here (test_kbkdf_ctr_hmac.rs covers that) and the Unavailable branch is unreachable. |

Gaps: no tests for generate_random_bytes / constant_time_equal in this file (existing test_generate_random_bytes.rs and test_constant_time.rs cover them; they pass); AES-128/192 and the seal-failure path are not exercised; assertions use `Debug` substring matching (fine, but looser than exact equality). No tautological assertions found.

### Run results
- Tip copy (`/tmp/review-tip-copy/prim`, `cargo test`): all suites pass, including 7/7 in this file (full prim run: 2+12+7+6+17+17+1+12+7+4+7 tests and 8 doctests, 0 failures).
- Base copy (`/tmp/review-base-copy/prim`, base sources + this test file copied in, separate target dir): 7/7 pass. So the tests are behavior-pinning, as intended; they would not catch a regression in verification, only in behavior.
- Copies were made with `rsync --exclude .git` from the worktrees; Cargo.lock copied from the harness.
