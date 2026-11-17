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

## Impact on callers (from Mahnush_Verus)

Source: Finding 1 from the `Mahnush_Verus` branch (aws/aws-crypto-tools-rust, tip `2d229377`, PR #103), copied here as text. Nothing was merged. This section does not change this report's severity, status, confidence or evidence. Quoted text is the other branch's wording. Every file:line below was re-found by function name on `MPL-Verus` (HEAD `e3abf2d`; `mpl/` and `prim/` identical to `main` `620771c`). The four mpl files involved are identical on both branches; the esdk files and `prim/src/lib.rs` differ. Per-claim check: `.agents/tasks/bug-docs-from-mahnush/claims.md`.

### What Mahnush_Verus states as proved (VR-014, in-crate Verus in its `prim/src/lib.rs`)

- BUG-07(a): "PROVED". Reported: on a key or nonce `Err` the buffer is exactly `old ++ message`; on a seal `Err` its length is `old + |message|` with prefix `old`; on `Ok` it is "`old ++ ciphertext ++ 16-byte tag`".
- BUG-07(b): "RECORDED, not proved". The guard `plain_text.len() < cipher_text.len()` is weaker than the equality check in aws-lc-rs `open_separate_gather`. This is stated relative to the labeled assumption A-OPEN, which the finding says matches aws-lc-rs 1.18.1 `src/aead/unbound_key.rs:139-142`. In the local aws-lc-rs 1.18.1 source the check is `if in_ciphertext_len != out_plaintext_len` at `:140`, returning `Err` at `:141`; the cited range `:139-142` covers the comment through the closing brace.

This proof exists only on `Mahnush_Verus`. `prim` on `MPL-Verus` has no Verus annotations, and mpl is not Verus-enabled on either branch.

Cross-check at `2d229377` (`git show 2d229377:prim/src/lib.rs`; details in `.agents/tasks/bug-docs-from-mahnush/crosscheck.md`). `prim/src` did not change between `43b9ff7`, which our earlier review read, and `2d229377`. The `ensures` of `aes_encrypt_core` (`prim/src/lib.rs:405-416` there) are:

```rust
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

- Key or nonce `Err`: exported postcondition, as stated.
- Seal `Err`: exported postcondition, as stated (length and prefix only). The length relies on trusted assumption A18. The doc comment says the tail bytes "are whatever the seal left".
- `Ok`: the exported postcondition gives the length `old + |message| + 16` and the prefix `old`. The "ciphertext, then tag" order is an in-body `assert(cipher_text@ =~= o + ct + tag_bytes@)` (`:437`), which is not part of the contract. The `+ 16` rests on trusted assumption A19 ("TRUSTED length").

Reviewer note: for the `Ok` case, "PROVED" is stronger than the exported postcondition. Callers can rely on the length and the prefix. The tag order is checked only inside the function, under A18 and A19. The two `Err` statements match the postconditions, and they are the ones that matter for BUG-07(a).

### ESDK impact (code reading over VR-014)

Paths: 2 encrypt and 5 decrypt sites. On `Mahnush_Verus` they go through `secret::seal` and `secret::open` (`esdk/src/secret.rs`). `MPL-Verus` has no such module, and the same seven sites call `aes_encrypt` / `aes_decrypt` directly:

- Encrypt: `construct_frame` (`esdk/src/message/body/body_encrypt.rs:31`, call at `:244`) and `build_header_auth_tag` (`esdk/src/encrypt.rs:750`, call at `:776`).
- Decrypt: `step_verify_header` (`esdk/src/decrypt.rs:554`), `read_and_decrypt_framed_message_body` (`esdk/src/message/body/body_decrypt.rs:279`, `:300`, `:469`) and `read_and_decrypt_non_framed_message_body` (`:652`).

Reported, and confirmed on our code:

- (a) "Harmless today; latent hazard." In `construct_frame` the seal's `?` returns before the Sink write (`write_to_sink`, `:268`) and the signature-digest write (`:277`). The scratch `frame_buf` is local to `encrypt_and_serialize_body` (`:302`) and is dropped when the error propagates. The header-tag seal uses an empty plaintext (`&[]`, `encrypt.rs:786`). The plaintext is user data, not key material. Reported severity: confidentiality, Informational/Low; likelihood negligible. This rests on the seal-before-write order in `construct_frame`.
- (b) "Unreachable." All five decrypt sites size the output exactly: two pass an empty ciphertext and `&mut []` (`decrypt.rs:586`, `body_decrypt.rs:289`), and the others use `result.resize(enc_content.len(), 0)` (`:296`), `result.resize(frame_length_usize, 0)` after reading `frame_length_usize` bytes (`:391-392`), and `enc_content.clone()` (`:647`).

### MPL impact (code reading over VR-014; no mpl-side proof)

Four sites, each handling a plaintext data key:

- Encrypt: `RawAesKeyring::wrap_data_key` (`mpl/src/keyring/raw_aes_keyring.rs:146`, call at `:163`) and `branch_key_wrap::wrap` (`mpl/src/aws_kms/branch_key_wrap.rs:157`, call at `:199`).
- Decrypt: `RawAesKeyring::on_decrypt` (`raw_aes_keyring.rs:422`, call at `:472`) and `branch_key_wrap::unwrap` (`branch_key_wrap.rs:230`, call at `:276`).

Reported, and confirmed on our code:

- (a) "Harmless today (no API escape); latent hazard."
  - Both encrypt sites return with `?` before the encrypted data key is built (`raw_aes_keyring.rs:171-177`, EDK built from `:179`; `branch_key_wrap.rs:207`), and the buffer is dropped. The data key cannot reach an EDK, a returned value or an error message: the error wraps only prim's fixed error text.
  - The buffer is a plain `Vec<u8>` and is not zeroized (`raw_aes_keyring.rs:162`; `branch_key_wrap.rs:192-196`, which already holds salt, IV and version). If a key or nonce error fired, an un-wiped copy of the plaintext data key would remain in freed heap memory.
  - Today the failure cannot fire. `wrap` fixes the key at 32 bytes and the IV at 12 bytes by type (`Zeroizing<[u8; DERIVED_KEY_LEN]>`, `:125`, `DERIVED_KEY_LEN = 32` at `:36`; `[0u8; IV_LEN]`, `:169`, `IV_LEN = 12` at `:24`). The raw AES keyring relies on the wrapping-key length check in `RawAesKeyringBuilder::build` (`raw_aes_keyring.rs:350`, check at `:369-379`), which is pinned by `test_build_rejects_wrapping_key_length_mismatch` (`mpl/tests/test_raw_aes_keyring.rs:732`). Its IV is `vec![0u8; IV_LENGTH]` with `IV_LENGTH = 12` (`:151`, `:31`), so it is fixed by construction rather than by type. "The 'no key residue in practice' conclusion depends on that check. The no-API-escape conclusion does not."
  - Reported severity: confidentiality, Low ("higher than esdk because the residue is key material"). Likelihood negligible.
- (b) "Unreachable." Both decrypt sites size the buffer exactly from the same ciphertext slice (`raw_aes_keyring.rs:467-471`; `branch_key_wrap.rs:259`, `:275`).

A separate zeroization issue found at the `on_decrypt` site is not part of BUG-07. It is recorded as [BUG-10](BUG-10-raw-aes-on-decrypt-unwiped-data-key.md).

### Tests

Reported: no esdk or mpl test exercises the `aes_encrypt` error path after the extend, or a wrong-size decrypt buffer; only the prim tests cover BUG-07 behavior. On `MPL-Verus`: confirmed for mpl and esdk. The only esdk test call (`esdk/tests/test_custom_keyring.rs:47`, `:108`) is a success path with an exact-size buffer. The prim tests that pin the buffer contents (`prim/tests/test_wrapper_contracts.rs`) exist only on `Mahnush_Verus`. Our `prim/tests/test_aes.rs` reaches the bad-key, bad-IV and too-short Err paths (`:154`, `:170`, `:138`) but checks only the error kind. The BUG-07 reproducer above was a temporary, untracked test.

### Recommendations from Mahnush_Verus (not implemented)

prim:

1. Build the `UnboundKey` and `Nonce` before the extend, so key and nonce errors leave the buffer unchanged. This removes the data-key copy at both mpl encrypt sites, and the finding calls it "the fix that matters most".
2. On seal `Err`, `truncate(old_size)`, optionally zeroizing the tail first. Every `Err` then leaves the buffer unchanged, which gives `aes_encrypt` a contract Verus can prove.
3. Tighten the decrypt guard to `plain_text.len() != cipher_text.len()` with a descriptive error, so a sizing bug no longer reports "authentication tag did not match".

Items 1 and 2 together are fix option (a) 1 above; item 3 is fix option (b) 1.

mpl (defense in depth):

1. Hold the encrypt buffers in `wrap_data_key` and `wrap` as `Zeroizing<Vec<u8>>`, or zeroize them on the `Err` arm. Both files already import `zeroize::Zeroizing` (`raw_aes_keyring.rs:15`, `branch_key_wrap.rs:16`).
2. Treat the `RawAesKeyringBuilder::build` wrapping-key length check as security-relevant, and add a comment saying it also keeps prim's post-extend error path unreachable.

esdk (optional): document the "write only after `seal` returns `Ok`" rule at the `construct_frame` Sink write (`body_encrypt.rs:268` on `MPL-Verus`).

Last cross-checked (this section): `MPL-Verus` HEAD `e3abf2d` against `Mahnush_Verus` `2d229377`.
