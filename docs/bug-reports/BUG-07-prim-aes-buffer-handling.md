# BUG-07: `prim::aes_encrypt` leaves plaintext in the caller's buffer on `Err`; `prim::aes_decrypt`'s length guard is weaker than its callee's check

Summary: (a) `aes_encrypt` appends the plaintext to the caller's output `Vec` before validating the key and IV. On any `Err`, the plaintext stays in that buffer. (b) `aes_decrypt` only rejects `plain_text.len() < cipher_text.len()`, but aws-lc-rs requires the lengths to be equal. A longer buffer gets past the guard and fails inside aws-lc-rs with an opaque `Unspecified` error. On `main`, prim reports that error as `authentication tag did not match`.

- Confidence: Confirmed by test
- Spec conflict: no
- Severity: Low. (a) is a secret-hygiene issue in a crate-level API. Every in-repo caller validates key and IV lengths first and drops the buffer on `Err`, so I found no path where the residue is returned or written out. (b) fails closed, and the only effect is a less useful error message.
- Related IDs: (a) VR-2026-T26, VR-2026-T07 (property (e)); TM-MPL-015 (Low). (b) VR-2026-C03; TM-MPL-023 (Low). TM-MPL-011 (Medium) stays listed through T07. Ratings are from `docs/threat-model.md` (HEAD 9955ecd), where (a) is counted in the Low residual of TM-MPL-015; targets are from `docs/verification-targets.md`.
- Completeness audit mapping (`docs/completeness-audit.md` section 3b): BUG-07(a) -> TM-MPL-015 -> T26, T07; BUG-07(b) -> TM-MPL-023 -> C03.
- Last cross-checked: HEAD 9955ecd (code == main 620771c for mpl/ and prim/)

## Status on main (620771c)

- Status: Still present (both 07a and 07b).
- Re-checked: 2026-11-10, against `c256243` on `MPL-Verus` (code identical to `main` `620771c`). Details: [RECHECK-main-620771c.md](RECHECK-main-620771c.md), section BUG-07.
- Evidence: the original test compiled and ran unchanged (2 passed). After `Err`, the buffer still holds `"HDR:SECRET-PLAINTEXT"`. Buffers of ct + 1 and ct + 16 bytes still pass the guard and are rejected by the callee (`.agents/tasks/bug-recheck/logs/recheck07.log`).
- What changed: only the error text (commits bec2cfe, f8abe78, e9bde48). A longer decrypt buffer is now reported as `authentication tag did not match` instead of `gather Unspecified`. Every callee error maps to that message (`prim/src/lib.rs:229`). The new text is more misleading than before, because the tag is fine and the problem is the buffer length.

Line numbers outside the Status and Location sections refer to `a1e23d7`, where the bug was first found, and are kept as history.

## Location

Current code (`main` `620771c`): `prim/src/lib.rs:175-197` (`aes_encrypt`). The plaintext is appended at `:185`, before the key and nonce checks that can return `Err` (`:187-189`) and the seal (`:192-194`):

```rust
184     let old_size = cipher_text.len();
185     cipher_text.extend_from_slice(message);
186     let cipher_slice = &mut cipher_text[old_size..];
187     let key = UnboundKey::new(alg, key).map_err(|_| serr("invalid AES-GCM key".to_owned()))?;
188     let nonce = Nonce::try_assume_unique_for_key(iv)
189         .map_err(|_| serr("invalid AES-GCM nonce".to_owned()))?;
190     let key = LessSafeKey::new(key);
191     let aad = Aad::from(aad);
192     let tag = key
193         .seal_in_place_separate_tag(nonce, aad, cipher_slice)
194         .map_err(|_| serr("AES-GCM encryption failed".to_owned()))?;
```

`prim/src/lib.rs:206` (`aes_decrypt`), guard at `:215` and callee at `:228-229`:

```rust
215     if plain_text.len() < cipher_text.len() {
216         return err(format!(
217             "plaintext buffer of {} bytes is shorter than the {} byte ciphertext",
...
228     key.open_separate_gather(nonce, aad, cipher_text, auth_tag, plain_text)
229         .map_err(|_| serr("authentication tag did not match".to_owned()))?;
```

The callee is aws-lc-rs. All three lock files (`prim/`, `mpl/`, `esdk/`) now resolve 1.18.1. The callee source was not re-read at 1.18.1, but the re-check output shows it still rejects a buffer longer than the ciphertext.

In-repo callers of `aes_encrypt`: `mpl/src/keyring/raw_aes_keyring.rs:163`, `mpl/src/aws_kms/branch_key_wrap.rs:199`, `esdk/src/message/body/body_encrypt.rs:244`, `esdk/src/encrypt.rs:776`.

Originally reported at `a1e23d7`: `prim/src/lib.rs:197-218` (`aes_encrypt`, append at `:207`, checks at `:209-210`) and `:227` / `:236` (`aes_decrypt` / guard). Callee was aws-lc-rs 1.17.1 (`src/aead/unbound_key.rs:140`). Callers were at `raw_aes_keyring.rs:225`, `branch_key_wrap.rs:192`, `body_encrypt.rs:239` and `encrypt.rs:715`.

## Expected behavior

No spec requirement; this is robustness / defense-in-depth. The rustdoc for `aes_encrypt` says "On success, `cipher_text` is extended with the ciphertext followed by the authentication tag". It says nothing about the buffer's state on error. The rustdoc for `aes_decrypt` lists "if `plain_text` is shorter than `cipher_text`" as an error, which matches the guard but not the effective contract (lengths must be equal).

## Actual behavior

(a)
1. The caller passes `cipher_text = b"HDR:"` and a 5-byte key for AES-256-GCM.
2. Line 207 appends the plaintext, then line 209 fails on the key length and returns `Err`.
3. The caller's buffer now holds `"HDR:SECRET-PLAINTEXT"`. The same happens with an 11-byte IV (line 210). A seal failure at line 214 would leave the plaintext there too.

(b)
1. The caller passes a `plain_text` buffer that's 1 or 16 bytes longer than the ciphertext.
2. The guard at line 236 doesn't fire. aws-lc-rs returns `Unspecified`, and prim maps it to `"gather Unspecified"`, which is the same error text as an authentication failure.
3. A buffer 1 byte shorter is rejected by the guard with the descriptive message.

## Impact

- (a) The plaintext copy only matters if a caller keeps or exposes the buffer after `Err`. By code reading:
  - The MPL callers (raw AES keyring, branch key wrap) return through `?` and drop their local buffer. Both pass key and IV lengths that are already validated (raw AES checks the key length in `new` and uses a fresh 12-byte IV; branch key wrap uses a derived 32-byte key and a 12-byte IV), so the `Err` path is practically unreachable for them.
  - The ESDK frame path writes into a local `frame_buf` that's dropped on `Err`. The plaintext there is message plaintext the caller already holds.
  - Residual concern: the plaintext data key copy in a dropped `Vec` isn't wiped, while `PlaintextDataKey` itself offers `zeroize()` (`mpl/src/structures/algorithm_suite.rs:434` at `a1e23d7`). That's a memory-hygiene gap, not a disclosure path. On current code the manual `zeroize` loop is gone: `PlaintextDataKey` derives `Zeroize` and `ZeroizeOnDrop` (`algorithm_suite.rs:505`), and the un-wiped transient copies of this kind are tracked by VR-2026-T26 under TM-MPL-015.
  - An external caller of `aws-mpl-primitives` that reuses or logs the buffer after `Err` would expose plaintext. The crate describes itself as "Not intended for public consumption" (`prim/Cargo.toml`).
- (b) No security impact. All callers I checked size the buffer exactly (`raw_aes_keyring.rs:309`, `branch_key_wrap.rs:267` at `a1e23d7`; now `raw_aes_keyring.rs:471` and `branch_key_wrap.rs:275`, each `vec![0u8; encrypted_key.len()]`). A mis-sized buffer just produces an error that looks like an authentication failure, which costs debugging time.
- The Dafny primitives (AtomicPrimitives `AESEncrypt` / `AESDecrypt`) return fresh output values instead of writing into a caller buffer, so this class of issue doesn't come up there (judged by API shape; I didn't check that implementation further).

## Reproduction / evidence

Reproducer: `prim/tests/zz_bugrepro_07_aes_buffers.rs`, a temporary untracked test, copied into the tree for each run and removed afterwards (full source below; copy in `.agents/tasks/bug-reports/reproducers/`). Command: `cd prim && cargo test --test zz_bugrepro_07_aes_buffers -- --nocapture`. The `prim` API did not change, so the re-check on `main` ran this test unchanged.

```rust
// TEMPORARY reproducer for BUG-07 (T07 / C03). Delete after running.
use aws_mpl_primitives::{AesGcm, aes_decrypt, aes_encrypt};
#[test]
fn aes_encrypt_leaves_plaintext_in_buffer_on_err() {
    let msg = b"SECRET-PLAINTEXT";
    // Bad key length (5 bytes for AES-256).
    let mut out = b"HDR:".to_vec();
    let r = aes_encrypt(AesGcm::Aes256Gcm, &[0u8; 12], &[0u8; 5], msg, b"", &mut out);
    println!("REPRO BUG-07a bad key: is_err={} err={:?}", r.is_err(), r.err().map(|e| format!("{e:?}")));
    println!("REPRO BUG-07a buffer after Err = {:?}", String::from_utf8_lossy(&out));
    // Bad IV length (11 bytes).
    let mut out2 = Vec::new();
    let r2 = aes_encrypt(AesGcm::Aes256Gcm, &[0u8; 11], &[0u8; 32], msg, b"", &mut out2);
    println!("REPRO BUG-07a bad iv: is_err={} buffer after Err = {:?}", r2.is_err(), String::from_utf8_lossy(&out2));
}
#[test]
fn aes_decrypt_longer_buffer_rejected_by_callee_not_guard() {
    let key = [3u8; 32];
    let iv = [4u8; 12];
    let mut ct = Vec::new();
    aes_encrypt(AesGcm::Aes256Gcm, &iv, &key, b"0123456789abcdef", b"aad", &mut ct).unwrap();
    let (body, tag) = ct.split_at(ct.len() - 16);
    for extra in [0usize, 1, 16] {
        let mut pt = vec![0u8; body.len() + extra];
        let r = aes_decrypt(AesGcm::Aes256Gcm, &key, body, tag, &iv, b"aad", &mut pt);
        println!("REPRO BUG-07b plain_text len = ct len + {extra}: {:?}", r.map_err(|e| format!("{e:?}")));
    }
    let mut short = vec![0u8; body.len() - 1];
    let r = aes_decrypt(AesGcm::Aes256Gcm, &key, body, tag, &iv, b"aad", &mut short);
    println!("REPRO BUG-07b plain_text len = ct len - 1: {:?}", r.map_err(|e| format!("{e:?}")));
}
```

Observed output on `main` (`.agents/tasks/bug-recheck/logs/recheck07.log`):

```text
running 2 tests
REPRO BUG-07a bad key: is_err=true err=Some("Cryptographic(CryptographicError { message: \"invalid AES-GCM key\" })")
REPRO BUG-07a buffer after Err = "HDR:SECRET-PLAINTEXT"
REPRO BUG-07a bad iv: is_err=true buffer after Err = "SECRET-PLAINTEXT"
REPRO BUG-07b plain_text len = ct len + 0: Ok(())
REPRO BUG-07b plain_text len = ct len + 1: Err("Cryptographic(CryptographicError { message: \"authentication tag did not match\" })")
REPRO BUG-07b plain_text len = ct len + 16: Err("Cryptographic(CryptographicError { message: \"authentication tag did not match\" })")
test aes_encrypt_leaves_plaintext_in_buffer_on_err ... ok
REPRO BUG-07b plain_text len = ct len - 1: Err("Cryptographic(CryptographicError { message: \"plaintext buffer of 15 bytes is shorter than the 16 byte ciphertext\" })")
test aes_decrypt_longer_buffer_rejected_by_callee_not_guard ... ok
test result: ok. 2 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.00s
```

At `a1e23d7` (`.agents/tasks/bug-reports/logs/bugrepro07.log`), the same calls gave the same results with different error text: `new Unspecified` for the bad key, and `gather Unspecified` for the longer buffers.

## Fix options

These options were written against `a1e23d7` and still apply on `main` (`aes_encrypt` at `prim/src/lib.rs:175`, `aes_decrypt` guard at `:215`). For (b), a descriptive guard message would now also replace the misleading `authentication tag did not match` text for a longer buffer.

(a) `aes_encrypt`
1. Build `UnboundKey` and `Nonce` before extending the buffer. Then, if sealing fails, zero the appended region and `truncate(old_size)`.
   - Pros: the buffer is unchanged on every `Err`. In-repo callers see no difference because they drop it anyway. The cost is negligible (a zeroing pass only on the error path).
   - Cons: a small change to a function that every encrypt path uses, so it needs careful review.
2. Encrypt into a separate scratch `Vec` and append only on success.
   - Pros: simple to reason about.
   - Cons: an extra allocation and copy on every call, including every ESDK frame.
3. Document the current behavior ("on `Err`, `cipher_text` contents are unspecified and may contain plaintext") and keep the T07 (e) proof obligation on callers.
   - Pros: no code change.
   - Cons: the burden stays on every caller.

(b) `aes_decrypt`
1. Change the guard to `plain_text.len() != cipher_text.len()` with a descriptive message, and update the rustdoc.
   - Pros: no change in which inputs succeed, since aws-lc-rs already rejects the mismatch. Only the error text gets better, and prim's own contract becomes provable without depending on the callee.
   - Cons: none significant.
2. Keep the guard and document that the lengths must be equal.

Recommendation: (a) option 1 and (b) option 1. Neither changes the observable success behavior of any in-repo caller.

## Questions for the engineers

1. Is `aws-mpl-primitives` considered internal-only (so a documented caller obligation is enough), or should its functions keep the caller's buffer unchanged on error?
2. Should plaintext copies left in prim scratch buffers be wiped (for example with `zeroize`), consistent with `PlaintextDataKey::zeroize`?
3. Is anything relying on `aes_decrypt` accepting an oversized buffer with the result then failing in aws-lc-rs? I found nothing in-repo.
