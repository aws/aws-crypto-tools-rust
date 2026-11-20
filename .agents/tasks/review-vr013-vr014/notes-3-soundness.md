# Review notes 3: soundness and honesty (checklist item 4)

Branch `Mahnush_Verus`, tip `43b9ff7` (commits `ed4a81e`, `43b9ff7`), base `6b51de8`.
Read-only review. Worktrees: `/tmp/review-mahnush-verus` (tip), `/tmp/review-mahnush-verus-base`.
Nothing tracked was modified (`git status --short` clean in both worktrees; the only change in
`esdk-native-mpl` is this untracked notes directory). All experiments ran in scratch copies under `/tmp/n3-*`.

aws-lc-rs checked: **1.18.1** (`prim/Cargo.lock:36-39`), source `~/.cargo/registry/src/*/aws-lc-rs-1.18.1/`.
aws-lc-sys **0.45.0** (`prim/Cargo.lock:47-50`) for C-side tag length. `aws-lc-fips-sys` was NOT read (see UNCHECKED).

## 1. Inventory (grep of the whole diff outside comments)

Command: `git diff 6b51de8 HEAD -- prim/src prim/tests | grep '^+' | grep -vE '^\+\s*//' | grep -nE 'assume\s*\(|admit\s*\(|external_body|external_fn_specification|external_type_specification|external_trait_specification|#\[verifier::external\]|axiom|broadcast|uninterp|assume_specification|unsafe|requires'`

| Construct | Count | Where |
|---|---|---|
| `assume(` / `admit(` | **0** | whole of `prim/src` (also 0 pre-existing) |
| `axiom` / `broadcast` / `#[verifier::external]` fn / `external_fn_specification` / `unsafe` | **0** | |
| `requires` added | **0** (the only `requires` in prim is the pre-existing `copy_from_slice` spec, `ecdsa.rs:179-183`) | |
| `external_type_specification` + `external_body` | 15 (on opaque *types*, never on fns) | `aws_lc_specs.rs:34,41,48,122,129,136,198,209,218,287,294,301,308,336,343` |
| `external_trait_specification` | 1 (`ExAsRef`, `#[cfg(verus_keep_ghost)]`) | `aws_lc_specs.rs:318-319` |
| `uninterp spec fn` | 8 | `aws_lc_specs.rs:53,58,63,141,146,151,223,265` |
| `assume_specification` | 20 (A1 to A20) | `aws_lc_specs.rs:67,77,87,95,106,154,162,172,182,228,237,253,270,346,352,357,362,368,380,393` |

The module doc comment (`aws_lc_specs.rs:12-13`) says "None of the specifications below has a `requires`". True:
no `assume_specification` has one, so each listed call is assumed not to panic for all inputs.

## 2. Trusted-assumption table

"Docs?" = listed in the TCB table `docs/verus-proofs-report.md` ("VR-013 / VR-014 TCB", line 638 onward). All 20 A-ids,
T-ty, T-AsRef and T-uf appear there; `verification/README.md` (VR-013/014 paragraph) and
`docs/verification-recommendations.md` (rows 13, 14, tcb lists at ~114 and ~151) point to the same list.
`docs/esdk-verification-developers-guide.md` only gets the "18 verified" line (not a TCB list, which is fine).

Real-source checks are in aws-lc-rs 1.18.1 `src/` unless stated.

| Id | Name / item | File:line | What is assumed | Docs? | Judgment | Evidence (source file:line) |
|---|---|---|---|---|---|---|
| T-ty (x15) | opaque types `digest::{Algorithm,Digest,Context}`, `hmac::{Algorithm,Key,Tag}`, `error::Unspecified`, `kdf::{KbkdfCtrHmacAlgorithm,KbkdfCtrHmacAlgorithmId}`, `aead::{Algorithm,UnboundKey,Nonce,LessSafeKey,Aad<A>,Tag}` | `aws_lc_specs.rs:34..343` | nothing beyond the Rust signature | yes (T-ty) | TRUE (no claim) | `external_body` on types only; no field or invariant is exposed |
| T-AsRef | `ExAsRef` proxy for `core::convert::AsRef` | `aws_lc_specs.rs:318-327` | signature only, so Verus can name `Aad<A: AsRef<[u8]>>` | yes | TRUE (no claim) | no method gets a spec; gated `cfg(verus_keep_ghost)` so no exec code is affected; `lib.rs` adds `cfg_attr(verus_keep_ghost, feature(sized_hierarchy))` |
| T-uf (x8) | `spec_digest_output_len`, `spec_digest_len`, `spec_context_output_len`, `spec_hmac_tag_len`, `spec_hmac_key_alg`, `spec_hmac_tag_bytes_len`, `spec_kbkdf_available`, `spec_slices_equal_ok` | `aws_lc_specs.rs:53,58,63,141,146,151,223,265` | uninterpreted, constrained only through A1 to A13 | yes | TRUE (no claim alone) | no axiom pins a numeric value for any of them (only A19 pins `16`, on a slice length) |
| A1 | `digest::Algorithm::output_len` | `:67` | `n == spec_digest_output_len(a)` | yes | TRUE (definitional) | `digest.rs:299-301` returns `self.output_len` |
| A2 | `digest::digest` | `:77` | digest length `== alg output length`; no panic | yes (TRUSTED length) | TRUE | `digest.rs:194-202` (`len: algorithm.output_len`); one-shot hashes are plain FFI, `digest/sha.rs:200-228`, no `unwrap`/`assert` |
| A3 | `<Digest as AsRef<[u8]>>::as_ref` | `:87` | byte view has `spec_digest_len` bytes | yes (labelled naming) | TRUE | `digest.rs:251-255` `&self.message[..self.len]`, `len <= MAX_OUTPUT_LEN` |
| A4 | `Context::algorithm` | `:95` | `output_len(result) == spec_context_output_len(c)` | yes (labelled naming) | TRUE | `digest.rs:162-166` returns `self.algorithm` |
| A5 | `Context::finish` | `:106` | digest length `== context output length`; **no panic** | yes (TRUSTED length + no-panic; F4) | TRUE for length; no-panic TRUE except documented C failure (see Section 3) | `digest.rs:136-138` `expect("EVP_DigestFinal failed")`; `digest.rs:151-158` `len: self.algorithm.output_len` |
| A6 | `hmac::Algorithm::tag_len` | `:154` | `n == spec_hmac_tag_len(*a)` | yes (naming) | TRUE | `hmac.rs:137-139` |
| A7 | `hmac::Key::new` | `:162` | `spec_hmac_key_alg(&k) == algorithm`; no panic | yes (labelled naming) | TRUE | `hmac.rs:297-299`; `try_new` stores `algorithm` at `hmac.rs:315-318`. Panic: `expect("Unable to create HmacContext")` |
| A8 | `hmac::sign` | `:172` | tag length `== tag_len of the key's algorithm`; no panic | yes (TRUSTED length) | TRUE (length); no-panic modulo C failure | `hmac.rs:446-469` returns `output[0..tag_len]`, `Tag.msg_len = result.len()` at `hmac.rs:431-438`; `sign` -> `Context::with_key` -> `Key::clone` -> `LcHmacCtx::clone` `expect` at `hmac.rs:205`; `update` expect `hmac.rs:391`; `sign` expect `hmac.rs:425` |
| A9 | `<hmac::Tag as AsRef<[u8]>>::as_ref` | `:182` | byte view length `== spec_hmac_tag_bytes_len` | yes (naming) | TRUE | `hmac.rs:166-171` |
| A10 | `kdf::get_kbkdf_ctr_hmac_algorithm` | `:228` | `Some <==> spec_kbkdf_available(id)`; no claim it is always `Some` | yes (naming, F3) | TRUE | `kdf/kbkdf.rs:38-49` always `Some` in 1.18.1; no `cfg` in the file, so also true under `fips`. A weaker spec than reality, so safe |
| A11 | `kdf::kbkdf_ctr_hmac` | `:237` | `output` length unchanged; no panic | yes (Rust type fact) | TRUE | `kdf/kbkdf.rs:103-145` one FFI call, returns `Err` on bad input (empty output/secret, counter overflow), no panic path |
| A12 | `rand::fill` | `:253` | `dest` length unchanged; no panic | yes (Rust type fact) | TRUE | `rand.rs:205-210` one `RAND_bytes` call, `Err` on failure |
| A13 | `constant_time::verify_slices_are_equal` | `:270` | `Ok` iff `spec_slices_equal_ok(a@, b@)` (a function of the bytes only); no panic | yes (TRUSTED determinism) | TRUE | `constant_time.rs:15-26`: length check, then `CRYPTO_memcmp`, pure function of contents; no panic |
| A14 | `aead::UnboundKey::new` | `:346` | no panic (no ensures) | yes | TRUE | `aead/unbound_key.rs:36-42` returns `Err` for bad key length; `aead/aead_ctx.rs`, `aead/aes_gcm.rs` have no `unwrap`/`expect`/`assert` |
| A15 | `Nonce::try_assume_unique_for_key` | `:352` | no panic | yes | TRUE | `aead/nonce.rs:26-28`, `iv.rs:73-76` `try_into()?` |
| A16 | `LessSafeKey::new` | `:357` | no panic | yes | TRUE | `aead.rs:709-712` plain struct build |
| A17 | `Aad::<A>::from` | `:362` | no panic | yes | TRUE | `aead.rs:661-666` |
| A18 | `LessSafeKey::seal_in_place_separate_tag` | `:368` | `in_out` length unchanged; no panic | yes (Rust type fact) | TRUE | `aead.rs:890-902` -> `unbound_key.rs:502-536` (`check_per_nonce_max_bytes` returns `Err`, then one FFI call). `debug_assert_eq!` at `unbound_key.rs:513` is debug-only and the nonce is always 12 bytes |
| A19 | `<aead::Tag as AsRef<[u8]>>::as_ref` | `:380` | length is **16** for every `aead::Tag` | yes (TRUSTED, AEAD-TAG-16) | TRUE for the AES-GCM tags prim produces (and for every tag construction path in 1.18.1) | `aead.rs:1032-1034` `tag_len() == TAG_LEN`, `aead.rs:1086` `TAG_LEN = 16`; `Tag(tag, out_tag_len)` at `unbound_key.rs:535`, `unbound_key.rs:582` (`tag_len` = algorithm tag length); C side `aws-lc-sys-0.45.0/aws-lc/crypto/fipsmodule/cipher/e_aes.c:1024-1025,1116` default tag length 16, `*out_tag_len = tag_len + extra_in_len` with no extra input. `as_ref` slices `[..self.1]`, so it cannot panic while `self.1 <= 16` |
| A20 = A-OPEN | `LessSafeKey::open_separate_gather` | `:393` | `Ok ==> in_ciphertext.len() == out_plaintext.len()`; `out_plaintext` length unchanged; no panic | yes (labelled assumption) | TRUE | `aead.rs:805` doc line; enforced at `aead/unbound_key.rs:139-141` (`if in_ciphertext_len != out_plaintext_len { return Err }`) before the FFI call, so `Ok` implies equal lengths. (The notes cite `unbound_key.rs:136-139`; actual lines are 139-141, a three-line citation drift) |
| (pre-existing) | `copy_from_slice` spec (VR-008) | `ecdsa.rs:179-183` | `requires dst.len == src.len`, `ensures dst == src` | yes (VR-008) | TRUE | matches `core` semantics (panics iff lengths differ); unchanged by this branch |

Unqualified result: all 20 assumptions are true statements about aws-lc-rs 1.18.1 on the default `aws-lc-sys` backend.

## 3. Panic / no-panic scope (the implicit assumption behind "no `requires`")

Every `assume_specification` is requires-free, so Verus treats each call as panic-free. In 1.18.1 these calls contain
`expect` that can fire only if the C library reports failure:

| Call | Panic site | Reachable when |
|---|---|---|
| `Context::finish` | `digest.rs:136-138` `expect("EVP_DigestFinal failed")` | `EVP_DigestFinal` returns != 1 (allocation / internal failure) |
| `hmac::Key::new` | `hmac.rs:297-299` `expect("Unable to create HmacContext")` | `HMAC_Init_ex` fails (allocation / internal failure) |
| `hmac::sign` | `hmac.rs:205` (clone), `hmac.rs:391` (update), `hmac.rs:425` (final) | `HMAC_CTX_copy_ex`, `HMAC_Update`, `HMAC_Final` fail |
| `digest::digest` | none (plain FFI, no `expect`) | n/a |
| kbkdf / rand / constant_time / aead calls | none (`Result` or plain) | n/a |

Honesty judgment:
- Docs state the general rule plainly: "No entry has a `requires`, so every listed call is trusted not to panic.
  Allocation failure / OOM ... is out of scope" (`docs/verus-proofs-report.md`, TCB intro) and "that the aws-lc-rs calls do
  not panic (trusted, see TCB)" under "What is NOT proven". `verification-recommendations.md` repeats it in `out_of_scope`.
- Docs name only one concrete panic site, F4 (`Context::finish`). The three hmac panic sites above
  (`hmac::Key::new`, `Context::with_key` clone, `sign`) are covered by the blanket statement but not enumerated.
  Low severity, but a one-line F4-style note for hmac would make the scope complete.
- Conditionality is stated for `finish` (F4) and for BUG-07(b) (A-OPEN). It is not repeated per proof row for `hmac`
  or `digest` (but A8/A2 rows say "TRUSTED length", and the blanket no-panic sentence applies).

## 4. Does the proof "prove" what is assumed?

Mostly honest; the docs say so.
- `aes_decrypt_core` `ensures` (`lib.rs`, VR-014(b)): `Ok ==> |plain| == |cipher|` is A20 restated; the "longer buffer
  never yields `Ok`" line is A20 + the VR-006 guard. Doc comment says "assumed, not proved"; report says "recorded under
  A-OPEN" (`verus-proofs-report.md` rows ~580, 726; README row ~110). Honest. The real aws-lc-rs behaviour matches
  (`unbound_key.rs:139-141`), so the recorded fact is true, but it is not evidence derived by Verus.
- `ct_equal_core` `ensures r == spec_slices_equal_ok(a@, b@)` is A13 restated; the real content is totality
  (no panic), and the docs say exactly that.
- `fill_random_core`, `kbkdf_core` length clause: Rust type fact (A11/A12). The report states these "carry no independent
  evidence beyond that" (TCB table footnote). Honest.
- `digest_core`, `digest_finish_core`, `hmac_core`: the guard-before-copy property and `Ok <==>` / `out` unchanged on `Err`
  are genuinely proved from the code; the in-bounds copy additionally rests on A2/A3/A5/A8/A9 (trusted lengths), listed as such.
- `aes_encrypt_core` prefix/`o ++ m` facts are derived from Verus `&mut` borrow semantics and the extend core (not assumed);
  the `+16` rests on A18 + A19, listed.

Labelling nit: A4 and A7 are tagged "naming" but are real (true) link facts (algorithm of a context; algorithm of a key),
and A3/A9 are definitional only because `spec_digest_len` / `spec_hmac_tag_bytes_len` are uninterpreted. The combined
chains (A2+A3, A5+A4+A1, A8+A7+A6+A9) are the real trusted claims, and each chain is TRUE.

## 5. Satisfiability and vacuity

Static argument. No `requires` anywhere in the new specs or cores, so no precondition can fail to hold or conflict.
The uninterpreted functions are shared only across consistent clauses: `spec_digest_output_len` (A1, A2, A4), `spec_digest_len`
(A2, A3, A5), `spec_context_output_len` (A4, A5), `spec_hmac_*` (A6 to A9). The real library is a model of all 20
simultaneously (each is TRUE per Section 2), so the set is satisfiable. A19 (`== 16`) is the only numeric constraint and
touches only `aead::Tag`, on which nothing else speaks. `ExAsRef` has no method spec, so there is nothing to contradict vstd
(Verus reports a duplicate-spec error, not silence, if vstd ever adds one).

Concrete check, in scratch copy `/tmp/n3-scratch` only (worktrees untouched):
1. Baseline `PATH="$HOME/verus:$PATH" cargo verus verify --offline`:
   `verification results:: 18 verified, 0 errors` (matches the docs; vstd line was `1858 verified, 0 errors`).
2. Inserted `assert(false);` at every path end in the new cores (before each `return Err(...)`, before each final `Ok(())`, in the
   `kbkdf`/`rand`/`aes_decrypt` match arms, before `ct_equal_core`'s result) and ran
   `cargo verus verify --offline -- --multiple-errors 20`. Result: `10 verified, 9 errors`; the `assertion failed` errors are
   at `ecdsa.rs:207,212` and `lib.rs:269,274,299,305,335,339,340,360,361,374,430,434,440,448,498,502,506,512,513`.
   Every such path is reachable (no `assert(false)` was provable), for `digest_core`, `digest_finish_core`, `hmac_core`,
   `kbkdf_core` (both arms), `fill_random_core` (both arms), `ct_equal_core`, `aes_encrypt_core` (key, nonce, seal-fail, Ok),
   `aes_decrypt_core` (guard, key, nonce, `Ok`, `Open`).
3. Added `vac_all`, one function that calls A1 to A19 together on one path (digest, Context finish, hmac, kbkdf, rand, ct, aead
   seal), then asserts the combined length facts (`ds@.len() == n`, `fds@.len() == cn`, `ts@.len() == tl`, `tgs@.len() == 16`;
   all proved, no error at those lines) followed by `assert(false)` at `lib.rs:556`, which **failed** as required. So the
   combined spec set is not contradictory on a path that uses all of them.

Not done: asserting that an uninterpreted function is NOT provably a specific value (e.g. `spec_digest_output_len == 32`);
argued statically instead.

## 6. `prim/Cargo.toml` / `Cargo.lock` verdict: no effect on ordinary builds

- `git diff 6b51de8 HEAD -- prim/Cargo.toml prim/Cargo.lock`: only `+[lints.rust] unexpected_cfgs = { level = "warn", check-cfg = ['cfg(verus_keep_ghost)'] }`
  (6 lines including comment). **`Cargo.lock` is not in the diff.** No new dependency, no version bump, no feature change.
  `vstd = "=0.0.0-2026-06-14-0213"` and `[package.metadata.verus]` pre-date this branch (commit `8289070`).
- `cargo tree --locked --offline -e features,normal` in base vs tip: identical except the crate path line.
- Stable `cargo build --offline` on scratch copies of base and tip: both exit 0, **0 warnings** (so the check-cfg declaration
  is silent and no new `unexpected_cfgs` noise).
- `#![cfg_attr(verus_keep_ghost, feature(sized_hierarchy))]` (`lib.rs`) and the `ExAsRef` proxy are inert unless `verus_keep_ghost`
  is set (only by cargo-verus). They do matter for the Verus toolchain and for the planned vstd feature-gating (documented
  in `verus-proofs-report.md` and `verification/README.md`).
- Not checked: `--no-default-features --features fips` build (needs `aws-lc-fips-sys` compile); the Cargo.toml change is
  feature-neutral so I expect no difference, but it is UNCHECKED.

## 7. UNCHECKED / residual items

1. `fips` backend: Rust-layer source is identical (same aws-lc-rs 1.18.1), but the `aws-lc-fips-sys` 0.14.2 C code was not read,
   so A19's C-side 16-byte tag and A2/A8 lengths are TRUE by the Rust layer only for the FIPS backend. UNCHECKED, low risk.
2. The C functions' failure conditions (what makes `EVP_DigestFinal`, `HMAC_Init_ex`, `HMAC_Final` fail): not read. The docs'
   "OOM out of scope" is the right frame, but I did not prove those are the only failure causes.
3. `Context::update` and `DigestContext::new` panics (`digest.rs:99`, `digest.rs:87`) are not on the proved paths and not specified.
4. Citation drift: A20 cites `unbound_key.rs:136-139` (actual 139-141); `hmac.rs:131-153` is approximate. Cosmetic.

## 8. Item 4 summary

No `assume`/`admit`/`external_body` fn/axiom; 20 `assume_specification`s, 8 uninterpreted fns, 15 opaque types, 1 trait proxy; all are in the
documented TCB; all 20 are TRUE of aws-lc-rs 1.18.1 (default backend); no vacuity found (22 reachable-path probes + 1 combined probe all fail
`assert(false)` as they should); the Cargo change is a lints-only addition with an unchanged dependency graph. Findings are
documentation-completeness nits (hmac panic sites not enumerated, A4/A7 labelled "naming", one citation off by 3 lines), not soundness defects.
