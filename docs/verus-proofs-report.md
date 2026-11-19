# Verus Proofs — Work Report

**Repository:** `aws-crypto-tools-rust` (AWS Encryption SDK for Rust)
**Code baseline:** commit `d8c1c3d` for the standalone models; the "In-crate proofs" section and the status tables are current at `2fb844fa`
**Date:** September 2026 (models); November 2026 (in-crate)
**Verus:** `0.2026.07.12.0b42f4c`, toolchain `1.96.0` (binary at `~/verus/verus`)
**Pipeline / targets:** `.kiro/agents/ai-verification-pipeline.md`, `docs/verification-recommendations.md`

---

## 1. Summary

Introduced formal Verus verification to the ESDK, starting from the prioritized
targets in the verification-recommendations doc. The standalone `verification/`
directory then held ten proof files — **71 obligations verified, 0 errors** in
total — and an
`SafeRead`/`SafeWrite` abstraction was prototyped and aligned to the real reader
signatures to unblock loop-level proofs.

As of `2fb844fa` the `verification/` directory holds eleven proof files —
**78 obligations verified, 0 errors** (§3) — after the VR-001 (b) commitment
ordering model (`commitment_ordering_proofs.rs`) was added.

The standalone models are **additive and non-breaking**: they live in a
standalone `verification/` directory referenced by no `Cargo.toml`, and adding
them modified no shipped source. (The later in-crate work, below, does modify
`esdk`.)

Run everything with:
```bash
make -C verification verify
```

> **Update (2026-11-12, branch `verus-in-crate-esdk`):** shipped `esdk` code is
> now verified in place (Option A in `docs/verus-in-crate-migration-design.md`).
> See "In-crate proofs (shipped `esdk` code)" below. The rest of this report
> describes the standalone models in `verification/`, which are kept; their
> current status is in `verification/README.md`.
>
> **Update (branch `verus-in-crate-rest`):** the body AAD and IV layout, the
> frame prefix layout, the final-frame sequence check, the frames-start-at-1
> lemmas and the 0x41 Base64 hint moved in-crate too (40 verified, 0 errors).
> The properties that stay model-only, and why, are listed under "In-crate
> proofs".
>
> **Update (branch `verus-vr009-key-derivation`):** the esdk half of VR-009 is
> verified in-crate: the key-length checks in `esdk/src/key_derivation.rs`
> (`identity_kdf_key_len_ok`, `check_v2_key_lengths`; 45 verified, 0 errors).
> The prim half (`prim/src/hkdf.rs`) is now also in-crate — see the
> `verus-prim-t3` update below; the aws-lc-rs HKDF crypto stays trusted.
>
> **Update (branch `vr011-confinement`):** VR-011 plan steps 2–6. The plaintext
> data key and the derived message key are confined to `esdk/src/secret.rs`.
> That is checked by the Rust compiler and clippy, **not by Verus**. Verus
> covers only the secret types' accessors and the commitment-value
> declassification (57 verified, 0 errors). See "VR-011" under "In-crate
> proofs".
>
> **Update (branch `verus-prim-t1`):** Verus is now enabled in the
> `aws-mpl-primitives` crate (`prim/Cargo.toml` sets
> `[package.metadata.verus] verify = true` and depends on the same
> `vstd = "=0.0.0-2026-06-14-0213"` pin as esdk; `make -C prim verus` runs
> `cargo verus verify` on default features and again with
> `--no-default-features --features aws-lc-sys`). The first in-crate prim
> target is VR-008 (T1) in `prim/src/ecdsa.rs`: **3 verified, 0 errors** on
> both feature sets. The real `sign_fixed_len` retry loop is inside `verus!`,
> with a genuine `decreases MAX_SIGN_ATTEMPTS - attempt` for termination and
> the guarded `copy_from_slice` proven in bounds — see "VR-008" under
> "In-crate proofs". VR-006 (AES-GCM, `prim/src/lib.rs`) and the prim half of
> VR-009 (`prim/src/hkdf.rs`) stay model-only; enabling Verus for them is
> planned.
>
> **Update (branch `verus-prim-t2`):** VR-006 (T2, AES-GCM buffer safety) is
> now in-crate in `prim/src/lib.rs`: **5 verified, 0 errors** on both feature
> sets (3 from VR-008 plus 2 new T2 cores). Two cores inside `verus!` carry
> the obligations — `aes_encrypt_extend_core` (the `aes_encrypt` slice bounds:
> the `split_at_mut(old_size)` index is proven in range by the
> `extend_from_slice` length fact, so `cipher_text[old_size..]` cannot panic)
> and `aes_decrypt_len_ok` (the `aes_decrypt` plaintext-vs-ciphertext length
> precondition). **Not proven:** the AES-GCM key length (16/24/32) and the IV
> validity — those are enforced inside `aws-lc-rs`, a trusted boundary, not by
> Rust-side branches in `prim`; and no crypto correctness. The prim half of
> VR-009 (`prim/src/hkdf.rs`) stays model-only; enabling Verus for it is
> planned. See "VR-006" under "In-crate proofs".
>
> **Update (branch `verus-prim-t3`):** the prim half of VR-009 (T3, HKDF
> key-length and no-salt slice safety) is now in-crate in `prim/src/hkdf.rs`:
> **10 verified, 0 errors** on both feature sets. Three cores inside `verus!`
> carry the obligations — `hkdf_key_len_ok` (the `{16, 24, 32}` HKDF
> key-length decision, proven total and correct against the real `okm.len()`:
> `Ok` for exactly those three lengths, each mapped to its AES size, and `Err`
> for every other length); `salt_size_core` (the per-digest default salt
> length, proven `<= MAX_SALT_SIZE`); and `no_salt_slice_core` (the
> `&salt[0..sz]` subrange on the 64-byte zero buffer, proven in bounds so
> `hkdf_no_salt` cannot panic on the slice). The verified count reflects real
> obligations: each was mutation-tested (wrong mapping, accepting an extra
> length, wrong salt value, an over-long salt, and dropping the buffer-length
> precondition each produce a Verus error). **Not proven:** the HKDF crypto
> itself, the derived key bytes, and the `aws-lc-rs` extract/expand/fill
> results (including their `Err` cases) — those are the trusted boundary. With
> T3, VR-009 is verified on **both** halves (esdk in
> `esdk/src/key_derivation.rs`, prim in `prim/src/hkdf.rs`), each with its own
> trusted boundary; and all three prim panic-point targets (VR-006, VR-008,
> VR-009 prim half) are now in-crate. See "VR-009" under "In-crate proofs".
>
> **Update (branch `verus-prim-c03`):** pipeline target VR-2026-C03 ("prim
> wrappers never panic and keep exact length contracts", from `origin/MPL-Verus`
> `docs/verification-targets/02-capability-driven.md`) is in-crate as
> **VR-013** (`digest`, `DigestContext::finish`, `kbkdf_ctr_hmac`,
> `generate_random_bytes`, `constant_time_equal`, `hmac`) and **VR-014**
> (`aes_encrypt` / `aes_decrypt` buffer facts from BUG-07, `origin/MPL-Verus`
> `docs/bug-reports/BUG-07-prim-aes-buffer-handling.md`):
> **18 verified, 0 errors** on both feature sets (10 before, +8 cores). The
> aws-lc-rs calls now sit inside the verified cores behind explicit
> `assume_specification`s in a new TCB module, `prim/src/aws_lc_specs.rs` (the
> TCB list is under "VR-013 / VR-014 TCB"). **New build attributes for PR #103
> reviewers:** `#![cfg_attr(verus_keep_ghost, feature(sized_hierarchy))]` in
> `prim/src/lib.rs` (a nightly-only feature, enabled only in Verus builds) and a
> `[lints.rust] unexpected_cfgs = { level = "warn", check-cfg =
> ['cfg(verus_keep_ghost)'] }` entry in `prim/Cargo.toml`. They exist for one
> ghost-only `#[cfg(verus_keep_ghost)]` `AsRef` trait proxy, without which
> Verus cannot name `aws_lc_rs::aead::Aad<A: AsRef<[u8]>>`. See "VR-014
> in-crate". Nothing here duplicates VR-006, VR-008 or VR-009.

> **Update (branch `verus-vr001`):** VR-001 (key commitment) is now **partly
> in-crate**. The accept/reject *decision* of `validate_suite_data`
> (`esdk/src/message/header.rs`) is verified by a `verus!` core,
> `suite_data_check`: **59 verified, 0 errors** on both feature sets (up from
> 57; +2 real, mutation-tested obligations). **Proven (property a):** the
> decision accepts **iff** the header suite data equals the derived (expected)
> suite data **and** the suite's committed length agrees with the expected
> length, and otherwise rejects commitment-first. **Not proven, trusted by
> design:** the *constant-time* property of the comparison (property c) rests on
> the `aws_lc_rs::constant_time::verify_slices_are_equal` API contract — Verus
> does not model timing; and the *ordering* (validation before frame
> decryption, property b) is now proven **model only**
> (`verification/commitment_ordering_proofs.rs`, branch `verus-vr001-ordering`)
> on a model of the decrypt pipeline — the same status as VR-002. This is **not**
> a proof about the shipped async `decrypt_steps` (which runs over `dyn Source`
> with `.await`): what stays trusted is that `decrypt_steps` is the real pipeline
> and that the async frame loop runs after the synchronous commitment step
> returns. An in-place / typestate (Stage 2) proof over the shipped path was
> deliberately not taken. See "VR-001" under "In-crate proofs" and the per-target
> status table. (Property (b) has since moved in-crate; see the
> `vr001b-vr002-stage2` update below.)
>
> **Out of scope for VR-001:** the commitment-*policy* checks
> (`CommitmentPolicy::allows_for_encrypt` / `_decrypt`, in
> `mpl/src/structures/commitment_policy.rs`, called from `esdk/src/encrypt.rs`,
> `decrypt.rs`, `materials.rs` and `mpl/src/cmm/default_cmm.rs`) are a *distinct*
> control: policy decides whether committing suites are required or allowed at
> all, whereas `validate_suite_data` checks that the commitment *value* matches.
> They are deliberately not part of VR-001 — they live partly in `mpl`, which is
> not Verus-enabled — and remain tracked separately as **implemented but
> unproven** (see the per-target status table and `verification-recommendations.md`).
>
> **Update (branch `verus-vr012`):** VR-012 (big-endian codec round-trip,
> capability-driven, category 1c) is now in-crate. Two proof lemmas in
> `esdk/src/message/serialize_functions.rs` — `lemma_u32_round_trip` and
> `lemma_u64_round_trip` — prove the verified big-endian encoders and decoders
> are **exact inverses** for `u32` and `u64`: for every `x`, decoding the bytes
> `u32_to_be(x)` / `u64_to_be(x)` produce recovers `x`
> (`spec_be_u32(b) == x` when `b@ == spec_u32_to_be(x)`, and the `u64` analogue).
> This couples the two spec fns that were each previously verified only against
> their own side, bridging the `[u8; N]`-vs-`Seq<u8>` mismatch via the
> hypothesis `b@ == spec_uN_to_be(x)`. **69 verified, 0 errors** on both feature
> sets (up from 59; +10 obligations — the two lemmas plus the staged
> `by (nonlinear_arith)` sub-obligations in the `u64` proof; mutation-tested).
> No `rlimit` bump, `assume`, `admit` or `external_body`. This is a
> functional-correctness lemma about the codec only — it says nothing about the
> async readers/writers. `u16` has a decoder (`be_u16`) but no encoder, so there
> is no `u16` round-trip. See "VR-012" under "In-crate proofs".
>
> **Update (branch `vr001b-vr002-stage2`):** VR-001 property (b) (the key
> commitment is accepted before any frame is decrypted) and VR-002 (the header
> authentication tag is verified before any frame is decrypted) are now
> in-crate, using two tokens in a new module, `esdk/src/decrypt_gate.rs`.
> **73 verified, 0 errors** on both feature sets (up from 69; +4 obligations).
> `CommitmentAccepted` is created only by `commitment_not_required` (a suite
> without key commitment) or `commitment_gate` (which wraps `suite_data_check`
> and returns a token only on `Ok`). `HeaderVerified` is created only by
> `header_auth_gate`, which uses up a `CommitmentAccepted` and returns a token
> only when `secret::open` on the header tag returned `Ok`.
> `step_decrypt_body` takes a `&HeaderVerified`. What is **Verus-proven**: each
> token is created only when its check passed, and every `CommitmentAccepted`
> for a committing suite records matching suite data and length. What the
> **compiler enforces**: the token fields are private to `decrypt_gate`, so no
> other code can build a token, and `step_decrypt_body` cannot be called
> without one. So frame decryption cannot start until both checks have
> passed; this does not depend on how the async runtime schedules the steps.
> What stays **trusted**: the unverified callers in `decrypt.rs` and
> `header.rs` pass the real values (the `verify_slices_are_equal` result,
> `has_commitment` for the suite actually used, the real header `open`
> result); aws-lc-rs AES-GCM accepts only a valid tag and compares in constant
> time; frames are decrypted only through `step_decrypt_body` (checked by
> grep, not by the compiler); a token is not tied to one particular message.
> The standalone models `verification/commitment_ordering_proofs.rs` and
> `verification/header_auth_ordering_proofs.rs` are now **superseded**: these
> two properties no longer depend on them. The model files are kept as
> history. See "VR-001 (b) and VR-002" under "In-crate proofs".
>
> **Update (branch `signature-release-gate`):** VR-015 (the final plaintext is
> held until the signature verifies, threat R3) is now in-crate, in the same
> module and with the same token pattern. **77 verified, 0 errors** on both
> feature sets (up from 73; +4 obligations). `SignatureVerified` is created
> only by `signature_not_required` (no verification key, so an unsigned suite)
> or `signature_gate` (which returns a token only when the aws-lc-rs signature
> check returned `true`). `step_decrypt_body` now returns the final plaintext
> as a `HeldFinalPlaintext`, whose bytes can only be read through `release`,
> which takes a `&SignatureVerified`. **Verus-proven:** the token is created
> only when the signature check returned `true` or there is no verification
> key, and `release` returns exactly the held bytes. **Compiler-enforced:**
> only `decrypt_gate` can build a `SignatureVerified` or read a
> `HeldFinalPlaintext`, so the final plaintext cannot be written to the caller
> before the signature step passes. **Trusted:** aws-lc-rs
> `ecdsa_verify_context` returns `true` only for a valid signature; the callers
> pass the real `valid` value and the real "verification key present" flag;
> "no verification key" means "unsigned suite" (the existing runtime check in
> `decrypt_steps`); the final plaintext reaches the caller only through the
> gated write (the body readers return it instead of writing it themselves).
> Regular frames before the final one are still released early, as the spec
> allows. See "VR-015" under "In-crate proofs".
>
> **Update (branch `sizing-and-sigpresence`):** two more in-crate results,
> **81 verified, 0 errors** on both feature sets (up from 77; +4
> obligations).
>
> - **VR-016 (new): every esdk AES-GCM decryption gets a plaintext buffer as
>   long as its ciphertext.** `secret::open` now takes an `OpenBuffers`,
>   which only the verified `secret::open_buffers` can build. Its type
>   invariant says the plaintext buffer length equals the ciphertext length.
>   All 5 open sites go through it. This makes BUG-07(b) **unreachable from
>   esdk, Verus-proven at every esdk open site** (before: code reading). What
>   aws-lc-rs would do with a mismatched buffer is still only known under
>   A-OPEN, but esdk no longer passes one.
> - **VR-015 (b): the signature-presence check is now a verified token.**
>   `signature_presence_gate` returns a `SignaturePresence` only when the
>   suite has a signature algorithm exactly when the materials have a
>   verification key. Step 5 needs that token: `signature_not_required` gives
>   the "no signature to check" token only for an unsigned suite with no key,
>   and otherwise a `SignatureRequired` (signed suite, key present), which
>   `signature_gate` needs. So a CMM that drops the verification key for a
>   signed suite cannot make decrypt skip the signature check. "No
>   verification key means unsigned suite" is **no longer trusted**; what
>   remains trusted is that `decrypt_steps` passes the real suite flag and the
>   real key-present flag, and that `dec_mat` is not changed between the
>   check and step 5.
>
> Same errors, messages and order as before; no public API or streaming
> change. See "VR-016" and "VR-015" under "In-crate proofs".
>
> **Update (branch `verus-encrypt-limits-and-lengths`):** two encrypt-side
> results, **94 verified, 0 errors** on both feature sets (up from 81; +13
> obligations).
>
> - **VR-017 (new): encrypt body limits** (`body/body_encrypt.rs`). The
>   running plaintext total is a `PlaintextBudget`, whose type invariant says
>   it never exceeds `MAX_DATA` (2^36 - 32); `add` rejects exactly when the
>   new total would exceed `MAX_DATA` (then the Plaintext Length Bound), with
>   overflow-free arithmetic for every input. Frame numbers come from an
>   `EncryptFrameSeq`: it starts at 1, `take_regular` hands out the current
>   number and adds exactly 1, refuses when the number would be `u32::MAX`
>   (so it never wraps), and `final_seq` gives the final frame the regular
>   count + 1. A lemma proves MAX_DATA alone stops the message first only
>   for frame lengths of 17 bytes or more; for 1 to 16 bytes the frame-count
>   guard is needed, and it is there.
> - **VR-018 (new): encrypt header length checks** (`esdk/src/encrypt.rs`).
>   `check_v2_suite_data` (present, and exactly
>   `algorithm_suite_data_length()` bytes) and `data_key_len_ok` (the derived
>   key is exactly the suite key length) accept iff the lengths are equal.
>
> Same errors, messages and order as before; no public API or streaming
> change. The async body loop and the header builders are unverified
> adapters. See "VR-017 and VR-018" under "In-crate proofs".

### Adherence to the Verus skill invariants (esdk)
- No proof was weakened: **no** `assume(...)`, `admit()`, or `#[verifier::external]` anywhere in esdk. In esdk there is exactly **one** `#[verifier::external_body]` — the `utf8_check` wrapper around `std::str::from_utf8` in the AAD sub-parser — used per Verus skill invariant #11 for a std call Verus cannot evaluate (the same role `tag_ok` plays for the AES-GCM check). Its `ensures` is a **trusted boundary, not a proof**: the UTF-8-validation correctness is delegated to the std library; everything around it (that the parser rejects non-UTF-8 with `Err`, never panics) is proven. This is called out explicitly in §5.
- Every "verified" claim is backed by actual `0 errors` tool output.
- Preconditions are satisfiable by real callers (not over-constrained).
- No `ensures` was changed to match buggy behavior.
- Load-bearing proofs were **mutation-tested** to confirm they are not vacuous.

---

## In-crate proofs (shipped `esdk` code)

`esdk/Cargo.toml` sets `[package.metadata.verus] verify = true` and depends on
`vstd = "=0.0.0-2026-06-14-0213"`. `cargo-verus` builds the dependencies
(`aws-lc-rs`, `tokio`, `aws-sdk-*`, `mpl`, `prim`) with plain rustc and verifies
the `verus!` blocks in `esdk`. The in-crate code uses no `assume`, `admit`,
`external_body` or `external`, and no `#[cfg(not(verus_keep_ghost))]`; each
type has one definition (the header enums moved into `verus!` unchanged).

Run from the repo root:

```bash
make -C esdk verus
```

Output (the `aws-esdk` line; `vstd` is verified first with
`1858 verified, 0 errors` and cached afterwards). Default features, then
`--no-default-features --features aws-lc-sys`:

```
verification results:: 94 verified, 0 errors
verification results:: 94 verified, 0 errors
```

The count is Verus's obligation count, not a function count; the checked
fns are 52 exec fns (13 before the in-crate work, 22 before VR-009, 24 before
VR-011, 34 before VR-001, 35 before VR-012, 36 before the VR-001 (b) / VR-002
tokens, 39 before VR-015, 43 before VR-016 and VR-015 (b), 45 before VR-017 /
VR-018) and 10 proof fns (3 before VR-012; the two VR-012 round-trip lemmas bring
it to 5, `lemma_commitment_accepted` to 6, `lemma_open_buffers_sized`
and `lemma_signature_required` to 8, and the two VR-017 lemmas to 10). The count rose from 59 to 69 at
VR-012: the two lemmas plus the staged `by (nonlinear_arith)` sub-obligations in
the `u64` proof each count. It rose from 69 to 73 with the decrypt tokens: the
three token-creating fns and the lemma. It rose from 73 to 77 with VR-015:
`signature_not_required`, `signature_gate`, `hold_final_plaintext` and
`release`. It rose from 77 to 81 with VR-016 (`open_buffers`,
`lemma_open_buffers_sized`) and VR-015 (b) (`signature_presence_gate`,
`lemma_signature_required`); `signature_not_required` and `signature_gate`
were strengthened in place. It rose from 81 to 94 with VR-017
(`PlaintextBudget::new` / `add`, `EncryptFrameSeq::start` / `take_regular` /
`final_seq`, the two lemmas and the staged `nonlinear_arith` step) and VR-018
(`check_v2_suite_data`, `data_key_len_ok`). Files are under `esdk/src/message/`
unless the path starts with `esdk/src/`.

| Fn | File | Ensures | Target |
|----|------|---------|--------|
| `DataKeyRef::len`, `MessageKey::len`, `PublicBytes::len` | `esdk/src/secret.rs` | `n == self.view().len()` | VR-011 |
| `MessageKey::zeroed`, `CommitmentValue::zeroed`, private `zero_vec` | `esdk/src/secret.rs` | the view is `len` zero bytes | VR-011 |
| `CommitmentValue::as_suite_data` | `esdk/src/secret.rs` | `s@ == self.view()` (decrypt-side declassification) | VR-011 |
| `PublicBytes::from_commitment`, private `copy_vec` | `esdk/src/secret.rs` | `p.view() == c.view()`, `p.is_public()` (encrypt-side declassification); `copy_vec`: `v@ == src@` | VR-011 |
| `PublicBytes::into_vec`; type invariant `PublicBytes::inv` | `esdk/src/secret.rs` | `v@ == self.view()`; every `PublicBytes` has `lab@ == Label::Public` | VR-011 |
| `open_buffers`; type invariant `OpenBuffers::inv` | `esdk/src/secret.rs` | `r.cipher() == cipher_text@`, `r.plain_len() == cipher_text@.len()`; every `OpenBuffers` has `plain_len() == cipher().len()` | VR-016 |
| proof fn `lemma_open_buffers_sized` | `esdk/src/secret.rs` | every `OpenBuffers` has a plaintext buffer exactly as long as its ciphertext | VR-016 |
| `identity_kdf_key_len_ok` | `esdk/src/key_derivation.rs` | `ok` iff `plaintext_key_len == encrypt_key_len` | VR-009 |
| `check_v2_key_lengths` | `esdk/src/key_derivation.rs` | `Ok` iff `!identity_kdf && message_id_len == MESSAGE_ID_LEN_V2 && plaintext_key_len == suite_key_len`; `Ok(n) ==> n == suite_key_len && n == plaintext_key_len`; `Err(IdentityKdf)` iff `identity_kdf`; `Err(MessageIdLen)` iff not identity and the message ID length is wrong; `Err(PlaintextKeyLen)` iff both earlier checks pass and the key length is wrong | VR-009 |
| `be_u16` | `serialize_functions.rs` | `r as int == spec_be_u16(b)` | VR-003 |
| `be_u32` | `serialize_functions.rs` | `r as int == spec_be_u32(b)` | VR-003 |
| `be_u64` | `serialize_functions.rs` | `r as int == spec_be_u64(b)` | VR-003 |
| `lemma_u32_round_trip` (proof fn) | `serialize_functions.rs` | `b@ == spec_u32_to_be(x) ==> spec_be_u32(b) == x as int` (decode-after-encode is the identity for `u32`) | VR-012 |
| `lemma_u64_round_trip` (proof fn) | `serialize_functions.rs` | `b@ == spec_u64_to_be(x) ==> spec_be_u64(b) == x as int` (decode-after-encode is the identity for `u64`) | VR-012 |
| `next_chunk_end` | `serialize_functions.rs` | requires `start < length`; `start < end <= length`, `end - start <= READ_CHUNK` (1 MiB) | VR-003 (bounded allocation per read) |
| `bounded_len_u32` | `serialize_functions.rs` | `OverBound` iff `len > bound`; `Ok` iff `len <= bound` and fits in `usize`; `TooLargeForPlatform` iff `len <= bound` and does not fit; `Ok(n) ==> n == len` | VR-003 |
| `bounded_len_u64` | `serialize_functions.rs` | same as `bounded_len_u32`, for `u64` | VR-003 |
| `msg_format_version_from_u8` | `header_types.rs` | `Some(V1)` iff `b == 1`; `Some(V2)` iff `b == 2`; `None` iff neither | VR-003 |
| `msg_type_from_u8` | `header_types.rs` | `Some(TypeCustomerAed)` iff `b == 0x80`; `None` otherwise | VR-003 |
| `content_type_from_u8` | `header_types.rs` | `Some(NonFramed)` iff `b == 1`; `Some(Framed)` iff `b == 2`; `None` iff neither | VR-003 |
| `reserved_bytes_ok` | `v1_header_body.rs` | `ok` iff all four bytes are 0 | VR-003 |
| `iv_len_matches` | `v1_header_body.rs` | `ok` iff `iv_len == expected` | VR-003 |
| `edk_count_check` | `header.rs` | `Empty` iff `count == 0`; `OverMax` iff `count > 0` and `max` is `Some(m)` with `count > m`; `Ok` otherwise | VR-007 |
| `suite_data_check` | `header.rs` | with `requires bytes_equal <==> header@ == expected@`: `Ok` iff `header@ == expected@` and `commit_len == expected@.len()`; `Err(CommitmentMismatch)` iff `header@ != expected@` (checked first); `Err(LengthMismatch)` iff `header@ == expected@` but `commit_len != expected@.len()` | VR-001 (property a) |
| `commitment_not_required` | `esdk/src/decrypt_gate.rs` | returns a token iff `!suite_commits`; that token has `!committing()` | VR-001 (property b) |
| `commitment_gate` | `esdk/src/decrypt_gate.rs` | same `requires` and same three iff conditions as `suite_data_check`; an `Ok` token has `committing()` and records `header@`, `expected@` and `commit_len` | VR-001 (property b) |
| proof fn `lemma_commitment_accepted`; type invariant `CommitmentAccepted::inv` | `esdk/src/decrypt_gate.rs` | every `CommitmentAccepted` with `committing()` has `header() == expected()` and `commit_len() == expected().len()` | VR-001 (property b) |
| `header_auth_gate` | `esdk/src/decrypt_gate.rs` | `Ok` iff `open_result` is `Ok`; an `Ok` token holds the given `CommitmentAccepted`; on `Err` returns the same error value | VR-002, VR-001 (property b) |
| `signature_presence_gate`; type invariant `SignaturePresence::inv` | `esdk/src/decrypt_gate.rs` | returns a token iff `suite_has_signature == has_verification_key`; the token records both flags; every `SignaturePresence` has `signed() == has_key()` | VR-015 (b) |
| `signature_not_required` | `esdk/src/decrypt_gate.rs` | uses up a `SignaturePresence`; `Ok` iff `!signed() && !has_key()`, and that token has `!signed()`; `Err(q)` holds the same presence token, with `signed() && has_key()` | VR-015, VR-015 (b) |
| proof fn `lemma_signature_required`; type invariant `SignatureRequired::inv` | `esdk/src/decrypt_gate.rs` | every `SignatureRequired` is for a signed suite with a verification key | VR-015 (b) |
| `signature_gate` | `esdk/src/decrypt_gate.rs` | uses up a `SignatureRequired`; returns a token iff `valid`; that token has `signed()`, and the used-up token was for a signed suite with a key | VR-015, VR-015 (b) |
| `hold_final_plaintext` | `esdk/src/decrypt_gate.rs` | `r.bytes() == bytes@` | VR-015 |
| `release` | `esdk/src/decrypt_gate.rs` | takes a `&SignatureVerified`; `r@ == held.bytes()` | VR-015 |
| `next_expected_frame` | `body/body_decrypt.rs` | `Some` iff `seq_num == expected && expected < u32::MAX`; `Some(n) ==> n == expected + 1`; `r == spec_next_expected_frame(seq_num, expected)` | VR-004 |
| `final_frame_seq_ok` | `body/body_decrypt.rs` | `ok` iff `seq_num == expected` | VR-004 |
| proof fn `lemma_accepts_run` | `body/body_decrypt.rs` | requires `accepts_run(seqs, expected)`; `seqs[i] == expected + i` for every `i`; `run_end(seqs, expected) == expected + seqs.len()` | VR-004 |
| proof fn `lemma_frames_start_at_1` | `body/body_decrypt.rs` | from `START_SEQUENCE_NUMBER`: `seqs[i] == i + 1`; the accepted final sequence number `== seqs.len() + 1` (the total frame count) | VR-004 |
| `classify_version_byte` | `header_types.rs` | `Supported(V1)` iff `b == 1`; `Supported(V2)` iff `b == 2`; `Base64Hint` iff `b == 0x41`; `Unsupported` iff none of these | VR-003 |
| `u32_to_be`, `u64_to_be`, `low_byte` | `serialize_functions.rs` | `r@ == spec_u32_to_be(x)` / `spec_u64_to_be(x)` (big-endian); `low_byte`: requires `v < 256`, `b == v` | VR-005 |
| `body_aad_content_type_string` | `body/body_aad.rs` | the bytes of `r` are `spec_body_aad_content(bc)` (the bytes of the matching const) | VR-005 |
| `iv_seq_core` | `body/body_aad.rs` | requires `len >= 4`; result `== old.subrange(0, len - 4) + spec_u32_to_be(seq)` | VR-005 |
| `body_aad_core` | `body/body_aad.rs` | result `== message_id@ + spec_body_aad_content(bc) + spec_u32_to_be(seq) + spec_u64_to_be(length)` | VR-005 |
| `write_frame_prefix` | `body/body_encrypt.rs` | appends exactly `spec_frame_prefix(seq, iv@, final_content_len)`: regular `seq ‖ iv`; final `spec_u32_to_be(ENDFRAME) ‖ seq ‖ iv ‖ len` | VR-005 |
| proof fn `lemma_endframe_bytes` | `body/body_encrypt.rs` | `spec_u32_to_be(ENDFRAME_SEQUENCE_NUMBER) == [FF, FF, FF, FF]` | VR-005 |
| `PlaintextBudget::new`; type invariant `PlaintextBudget::inv` | `body/body_encrypt.rs` | `total() == 0`; every `PlaintextBudget` has `total <= MAX_DATA` | VR-017 |
| `PlaintextBudget::add` | `body/body_encrypt.rs` | no `requires`; `Err(TooLarge)` iff `old.total + chunk > MAX_DATA`; `Err(OverBound)` iff not `TooLarge` and `bound` is `Some(b)` with `old.total + chunk > b`; `Ok ==> total == old.total + chunk`; `Err ==> total` unchanged; always `total <= MAX_DATA` | VR-017 |
| `EncryptFrameSeq::start`; type invariant `EncryptFrameSeq::inv` | `body/body_encrypt.rs` | `next() == START_SEQUENCE_NUMBER` (1), `frames() == 0`; every `EncryptFrameSeq` has `next == frames + 1` | VR-017 |
| `EncryptFrameSeq::take_regular` | `body/body_encrypt.rs` | no `requires`; `None` iff `old.next == ENDFRAME_SEQUENCE_NUMBER` (`u32::MAX`), state unchanged; `Some(n) ==> n == old.next && n < u32::MAX && next == n + 1 && frames == old.frames + 1` | VR-017 |
| `EncryptFrameSeq::final_seq` | `body/body_encrypt.rs` | `n == next()`, `n == frames() + 1` (the total frame count), `n >= 1` | VR-017 |
| proof fn `lemma_max_data_bounds_frames` | `body/body_encrypt.rs` | `frame_length >= 17 && k * frame_length <= MAX_DATA ==> k + 1 < ENDFRAME_SEQUENCE_NUMBER` | VR-017 |
| proof fn `lemma_frame_guard_needed_at_16` | `body/body_encrypt.rs` | `(ENDFRAME_SEQUENCE_NUMBER - 1) * 16 == MAX_DATA` | VR-017 |
| `check_v2_suite_data` | `esdk/src/encrypt.rs` | `Err(Missing)` iff no suite data; `Err(LengthMismatch)` iff present with `len != expected_len`; `Ok(sd) ==> sd` is the given suite data with `len == expected_len` | VR-018 |
| `data_key_len_ok` | `esdk/src/encrypt.rs` | `ok` iff `data_key@.len() == expected_len` | VR-018 |

Spec fns `spec_be_u16`/`spec_be_u32`/`spec_be_u64`, the `READ_CHUNK` const and
the `LenCheck`, `EdkCount`, `MessageFormatVersion`, `MessageType`,
`ContentType`, `VersionByte`, `BodyAADContent`, `V2KeyLenError`, `BudgetError`
and `SuiteDataLenError` enums, the `MAX_DATA` const (now a `u64`, same value), the
three body AAD content strings, `START_SEQUENCE_NUMBER` /
`ENDFRAME_SEQUENCE_NUMBER` and `MESSAGE_ID_LEN_V1` / `MESSAGE_ID_LEN_V2` are
also inside `verus!`. The shipped callers use these
cores: `derive_key_v1` calls `identity_kdf_key_len_ok`, `derive_key_v2`
matches on `check_v2_key_lengths` and sizes the derived encryption key with its
`Ok(n)`, `derive_keys` dispatches on `msg_format_version_from_u8`, `read_u16/u32/u64` call `be_uN`, `read_into_vec` calls `next_chunk_end`,
`read_seq_u32/u64_bounded` match on `bounded_len_*`, the header readers call the
`*_from_u8` / `reserved_bytes_ok` / `iv_len_matches` cores,
`validate_max_encrypted_data_keys` and `read_edks` call `edk_count_check`,
the framed-decrypt loop calls `next_expected_frame` and `final_frame_seq_ok`,
`read_msg_format_version` matches on `classify_version_byte`, `iv_seq` and
`body_aad` call `iv_seq_core` and `body_aad_core` after their `debug_assert!`s,
`construct_frame` writes the frame fields with `write_frame_prefix`,
`encrypt_and_serialize_body` counts plaintext with `PlaintextBudget::add` and
numbers frames with `EncryptFrameSeq`, `build_v2_header_body` matches on
`check_v2_suite_data`, and `build_header_auth_tag` calls `data_key_len_ok`.

**Unverified / trusted boundaries:**
- **The async `Source`/`Tee` adapters** are unverified glue. The readers are
  `async fn`s over `&mut dyn Source` (tokio `AsyncRead`, `esdk/src/shapes.rs`)
  that mirror the bytes they read into `&mut Tee` (`dyn Write + Send`). Verus
  cannot verify async code or trait objects, so the adapters read the bytes,
  call a verified core, and build the `Error` (`ser_err` / `err` / `val_err`).
  That they pass the right bytes to the core and keep the `Tee` mirror exact is
  checked by tests, not by Verus.
- **Frame-sequence loop threading.** Both sequence checks and the
  start-at-1 lemmas are in-crate, but the async loop in
  `read_and_decrypt_framed_message_body` that sets `expected_frame =
  START_SEQUENCE_NUMBER` and feeds each `next_expected_frame` result to the
  next iteration is unverified glue; the lemmas describe what it does.
  The encrypt side is the same (VR-017): that `encrypt_and_serialize_body`
  creates one budget and one counter, calls `take_regular` and
  `add(frame_length)` once per regular frame and `add(in_size)` and
  `final_seq` for the final frame, and passes the returned number to
  `construct_frame` is unverified glue.
- **`u32_to_be` / `u64_to_be` vs `to_be_bytes`.** vstd does not model
  `to_be_bytes`, so the cores use verified encoders; that they equal
  `to_be_bytes()` is checked by unit tests. The body AAD content strings are
  proved to be the bytes of the shipped consts, not checked byte by byte
  against the spec text (tests do that).
- **`next_chunk_end`** is proved to stay in bounds, not to equal
  `start + min(READ_CHUNK, length - start)`; that equivalence is checked by a
  differential unit test.
- **The aws-lc-rs FFI** (AES-GCM, ECDSA, HKDF, digests) is out of Verus scope.
- **VR-009, prim half and key-derivation adapters.** `prim/src/hkdf.rs` now
  carries a `verus!` block (VR-009 prim half, T3): the `{16, 24, 32}` HKDF
  key-length decision (`hkdf_key_len_ok`) and the no-salt slice bound
  (`salt_size_core`, `no_salt_slice_core`) are proven in-crate, alongside
  VR-008 (`prim/src/ecdsa.rs`) and VR-006 (`prim/src/lib.rs`). Still a trust
  boundary: the aws-lc-rs HKDF crypto itself and the extract / expand / fill
  results, reached only through the thin adapters outside `verus!`. In esdk,
  `derive_key_v1` / `derive_key_v2` / `derive_keys`
  are unverified adapters. Not proven there: the V1 output length and the V2
  commit-key length, which are MPL getters (`encryption_key_length()`,
  `algorithm_suite_data_length()`) passed straight to `MessageKey::zeroed(n)` /
  `CommitmentValue::zeroed(n)` (Verus proves only the `n` zero bytes, not `n`); the V1
  salt length table `digest_length`, which matches on the `prim` enum
  `DigestAlg` that Verus does not see (modelling it would need an external
  type specification, a trusted assumption); and the debug-only
  `debug_assert!`s on the caller's inputs.
- **`std::str::from_utf8`** is not evaluated by Verus; no in-crate core depends
  on it.
- **MPL `EncryptionContext::from_bytes`** now does the encryption-context
  parsing; it lives in `mpl` and is out of scope here.
- **VR-011 (data-key non-disclosure): not Verus-proven.** See the VR-011
  section below.

**VR-011: what each mechanism checks.** Property (decision D0): during
encrypt and decrypt, the plaintext data key and the derived message encryption
key are never written directly to the output or returned to the caller; they
reach the output only through AES-GCM or, for the data key, as an EDK from the
keyring. The V2 commitment value is public by spec (header suite data) and is
declassified.

- **Compiler-checked (Rust privacy):** outside `esdk/src/secret.rs`, esdk code
  cannot read the bytes of a `DataKeyRef` or `MessageKey`. The fields are
  private, and the types derive no `Clone`, `PartialEq` or `Debug`.
  `PublicBytes`, the header suite-data type, can only be built from a
  `CommitmentValue`. Without the `test-internals` feature,
  `__test_internals` has no key-returning items.
- **Lint-checked (clippy, `esdk/clippy.toml`):** esdk calls
  `PlaintextDataKey::as_bytes`, the materials' `plaintext_data_key` and the
  builders' `get_plaintext_data_key` only in the two ingress adapters, which
  carry `#[expect(clippy::disallowed_methods)]`. CI runs
  `cargo clippy --all-targets -- -D warnings`.
- **Grep-checked only:** prim AES-GCM and HKDF are imported only in
  `secret.rs`, and `key_derivation.rs` passes the HKDF PRK (returned by
  `secret::hkdf_v2_extract`) only to the two `secret.rs` expand adapters.
  No tool enforces either.
- **Verus-proven:** only the `secret.rs` rows in the table above (accessor
  `ensures` against the closed `view()`, and the `PublicBytes` label
  invariant). Verus does not check that a function is absent, and the
  encrypt/decrypt flow is not under Verus (plan step 7, not done).
- **Trusted (TB-A, unverified adapters outside `verus!` in `secret.rs`):**
  `data_key_from_encryption_materials`, `data_key_from_decryption_materials`,
  `identity_copy`, `hkdf_v1`, `hkdf_v2_extract`, `hkdf_v2_expand_key`,
  `hkdf_v2_expand_commitment`, `seal`, `open`. Also trusted: aws-lc-rs
  (through `aws-mpl-primitives`), keyrings and CMMs, and the mpl key types
  and materials (D1).
- **Out of scope:** the mpl accessors themselves (D2), the ECDSA signing key
  (D6), the `test-internals` feature (D3), and memory-level leaks (VR-010).
  Error and `Debug` paths are covered structurally, plus the empirical
  `esdk/tests/test_error_secrets.rs` (D5).

### VR-001 (b) and VR-002 in-crate (`esdk/src/decrypt_gate.rs`)

The two decrypt order properties are:
- **VR-001 (b):** the key commitment check has run and passed before any
  frame is decrypted.
- **VR-002:** the header authentication tag has been verified before any
  frame is decrypted.

Both now hold for the shipped decrypt path, by a mix of a Verus proof and a
compiler check.

**How it works.** `esdk/src/decrypt_gate.rs` defines two tokens. They are
zero-sized at runtime, have private fields, and are neither `Clone` nor
`Copy`. The module is separate from `decrypt.rs` because Rust field privacy is
per module.
- `CommitmentAccepted` says the commitment check passed, or the suite does
  not use key commitment. In `step_get_decryption_materials`, a suite without
  commitment gets one from `commitment_not_required`. A committing suite gets
  one only from `header::validate_suite_data`, which calls `commitment_gate`.
  `commitment_gate` runs `suite_data_check` and returns a token only on `Ok`.
- `HeaderVerified` says the header tag verified. `step_verify_header` gets one
  from `header_auth_gate`, which uses up the `CommitmentAccepted` and returns a
  token only when `secret::open` on the header tag returned `Ok`. Holding a
  `HeaderVerified` therefore means both checks passed.
- `step_decrypt_body` takes a `&HeaderVerified`.

**Verus-proven:** each token-creating function returns a token only when its
check passed (`ensures` in the table above), and every `CommitmentAccepted`
for a committing suite records equal suite data and a matching length (type
invariant, `lemma_commitment_accepted`).

**Compiler-enforced:** no code outside `decrypt_gate` can build a token
(private fields), and `step_decrypt_body` cannot be called without a
`&HeaderVerified`. The token is an argument to the call, so the call cannot
start before both checks have passed. This does not rely on the async runtime
running the awaits in order.

**Trusted, not proven:**
- The unverified callers pass the real values: the
  `verify_slices_are_equal` result (in `validate_suite_data`), `has_commitment`
  for the suite actually used, and the real header `secret::open` result.
- aws-lc-rs: AES-GCM accepts only a valid tag, and the commitment comparison
  runs in constant time (VR-001 (c)).
- Frames are decrypted only through `step_decrypt_body`. This was checked by
  grep; the compiler does not enforce it.
- A token is not tied to one particular message.
- `esdk/src` has no `unsafe` code, so a token cannot be forged that way. The
  crate does not forbid `unsafe`, though.
- Deleting the token parameter from `step_decrypt_body` (and the argument)
  still compiles. Only code review catches that.

Behavior is unchanged: the same checks run in the same order with the same
error kinds and messages. `DecryptState` is unchanged; the tokens are passed
next to it.

The standalone models `verification/commitment_ordering_proofs.rs` (VR-001
(b)) and `verification/header_auth_ordering_proofs.rs` (VR-002) are now
**superseded**. These two properties no longer depend on them. The files are
kept as history.

### VR-015 in-crate (`esdk/src/decrypt_gate.rs`)

The property is the spec rule in
`spec/client-apis/decrypt.md#decrypt-the-message-body`: plaintext decrypted
from non-framed data or from a final frame must not be released until
signature verification succeeds (threat-model R3). It now holds for the
shipped decrypt path, by a Verus proof plus a compiler check.

**Where plaintext reaches the caller.** All of it goes through
`serialize_functions::write_to_sink` on the caller's sink, in two places:

| Path | Covered by the rule? | Where it is released |
|---|---|---|
| Framed, regular (non-final) frames, streaming | No. The spec allows releasing these once their tag verifies. For signed messages `SignedStreaming::RejectMultiFrame` fails instead | `release_previous_frame` in `body_decrypt.rs`, before the signature. Not changed |
| Framed, final frame with content | Yes | `decrypt_steps`, through `release`, after the signature step |
| Framed, empty final frame | Yes. The code also holds back the last full frame in this case, which is stricter than the spec asks | `decrypt_steps`, through `release` |
| Non-framed body | Yes | `decrypt_steps`, through `release` |
| Non-streaming `decrypt` (buffers into a `Vec`) | Covered by the stronger rule that no output is released before all steps complete | The caller only gets the `Vec` from `Ok(DecryptOutput)`. Protected by `Result`, not by the token |

No path broke the rule before this change. The change turns the three "Yes"
rows into a compiler-checked guarantee.

**How it works.**

- `SignatureVerified` says the signature verified, or the suite is unsigned
  and there is no verification key. `step_verify_signature` takes the
  `SignaturePresence` token from the presence check (VR-015 (b), below) and
  passes it to `signature_not_required`. That returns `Ok` with a token for
  an unsigned suite with no key. Otherwise it returns `Err` with a
  `SignatureRequired`, and `verify_signature` passes that to `signature_gate`
  with the `bool` returned by `ecdsa_verify_context`. `signature_gate`
  returns `None` when the check failed, and the caller turns that into the
  same `Cryptographic` "signature verification failed" error as before.
- `HeldFinalPlaintext` holds the final plaintext. `step_decrypt_body` returns
  one (made by `hold_final_plaintext`) instead of a `Vec<u8>`. Its field is
  private, so the only way to read the bytes is `release`, which takes a
  `&SignatureVerified`.
- `decrypt_steps` writes `release(&last_frame, &signature_verified)`.

**Verus-proven:** `signature_not_required` returns a token only for an
unsigned suite with no verification key, `signature_gate` returns a token
only when `valid` is `true` (and only from a `SignatureRequired`), and
`release` returns exactly the bytes that were held.

**Compiler-enforced:** no code outside `decrypt_gate` can build a
`SignatureVerified` or read the bytes of a `HeldFinalPlaintext` (private
fields). So the final plaintext cannot be written to the caller without a
token, and a token exists only after the signature step returned `Ok`. This
does not rely on the async runtime running the awaits in order.

**Trusted, not proven:**

- aws-lc-rs `ecdsa_verify_context` returns `true` only for a valid signature
  over the digest.
- The unverified callers pass the real `valid` value, and `decrypt_steps`
  passes the real suite flag (`state.header.suite`, which step 2 checked
  equals the materials' suite) and the real "verification key present" flag
  to `signature_presence_gate`.
- `dec_mat` is not changed between the presence check and step 5, and
  `verify_signature` uses the key from that same `dec_mat` (code reading:
  `step_decrypt_body` only reads it).
- (Removed by VR-015 (b): "no verification key means unsigned suite" is no
  longer trusted. It is now Verus-proven through the `SignaturePresence`
  token; see below.)
- The final plaintext reaches the caller only through the gated write. The
  body readers return it and never write it to the sink themselves: the
  non-framed reader has no sink, and the framed reader writes only through
  `release_previous_frame`. Checked by reading the code; the compiler does not
  enforce it.
- A token is not tied to one particular message.

**Mutation tests.** (1) Making `signature_gate` return a token even when
`valid` is `false`: Verus fails the postcondition (`76 verified, 1 errors`).
(2) Writing the final plaintext without the token: reading `last_frame.bytes`
directly is rejected by the compiler (`E0616`, private field), and calling
`release` without the token is rejected (`E0061`). Both mutations were
reverted.

Behavior is unchanged: the same checks run in the same order with the same
error kinds and messages, and regular frames are released as before. No
public API changed.

#### VR-015 (b): the signature-presence check (branch `sizing-and-sigpresence`)

Before this change, `decrypt_steps` checked that the materials have a
verification key exactly when the suite has a signature algorithm, in
unverified code, and step 5 then chose between skipping and checking the
signature by re-reading `verification_key().is_some()`. So VR-015 trusted
"no key means unsigned suite". Now:

- `signature_presence_gate(suite_has_signature, has_verification_key)`
  replaces the `if` in `decrypt_steps`, at the same place. It returns a
  `SignaturePresence` only when the two flags agree. On a mismatch the
  caller returns the same `InvalidMaterials` error with the same message.
- `step_verify_signature` takes that token instead of re-reading the key.
  `signature_not_required(presence)` returns `Ok(SignatureVerified)` only
  for an unsigned suite with no key, and otherwise `Err(SignatureRequired)`.
- `signature_gate(required, valid)` needs the `SignatureRequired`.

The token is minted at the existing check because that is where the
decision is made today, and used up at step 5 where the two paths split.
It is not passed to `step_decrypt_body`: `fail_if_multi_frame` there reads
key presence for the `RejectSignedMultiFrame` streaming option, which is a
different property.

**Verus-proven:** a `SignaturePresence` exists only when "suite signed"
equals "key present" (type invariant); the "no signature to check" token is
made only when the suite is unsigned and there is no key; a
`SignatureRequired` exists only for a signed suite with a key present (type
invariant); `signature_gate` makes a signed token only from a
`SignatureRequired` and only when `valid`.

**Compiler-enforced:** only `decrypt_gate` can build these tokens (private
fields); `step_verify_signature` cannot run without a `SignaturePresence`,
and `signature_gate` cannot run without a `SignatureRequired`. None of the
tokens is `Clone` or `Copy`. `SignaturePresence` carries one runtime `bool`
(step 5 branches on it), so it is not zero-sized.

**Trusted, not proven (what remains):** `decrypt_steps` passes the real
suite flag and the real key-present flag; `dec_mat` is not changed between
the check and step 5. The `verification_key().ok_or_else(InvalidMaterials,
..)` inside `verify_signature` is kept, so behavior does not change; it is
now unreachable.

**Mutation tests** (default features; each reverted):

| Mutation | Caught by | Result |
|---|---|---|
| `signature_not_required`: swap the two branches (not-required token for a signed suite, `SignatureRequired` for an unsigned one) | Verus | `80 verified, 1 errors`: postcondition not satisfied; type invariant |
| `signature_not_required`: return the not-required token for a signed suite | Verus | `80 verified, 1 errors`: postcondition not satisfied |
| `signature_presence_gate`: mint a presence token on a mismatch (`if true`), so a key present with an unsigned suite or no key with a signed one gets a token | Verus | `80 verified, 1 errors`: type invariant |
| `signature_not_required`: build a `SignatureRequired` on the unsigned / no-key branch | Verus | `80 verified, 1 errors`: type invariant |
| `step_verify_signature`: call `signature_not_required(verification_key().is_some())` (the old re-read) | compiler | `E0308` mismatched types |
| `verify_signature`: call `signature_gate(valid)` without the `SignatureRequired` | compiler | `E0061` |

### VR-016 in-crate: decrypt buffer sizing (`esdk/src/secret.rs`)

The property: every time esdk calls `aes_decrypt`, the plaintext buffer is
exactly as long as the ciphertext. That is what makes BUG-07(b) (prim's
guard `plain_text.len() < cipher_text.len()` is weaker than aws-lc-rs's
equality check, VR-014) unreachable from esdk. Before, that was code reading
over the 5 open sites. Now it is a Verus proof plus a compiler check.

**How it works.**

- `OpenBuffers` holds the ciphertext slice and the plaintext `Vec`. Its
  type invariant says their lengths are equal. Its fields are private to
  `secret.rs`.
- `open_buffers(cipher_text, plain_text)` (verified) resizes the given `Vec`
  to `cipher_text.len()` and returns an `OpenBuffers`. It reuses the `Vec`,
  so no new allocation is needed.
- `secret::open` takes an `OpenBuffers` instead of a ciphertext slice and a
  `&mut [u8]`, passes the two fields to `aes_decrypt` unchanged, and returns
  the plaintext `Vec`.

The 5 sites (`grep -rn "secret::open(" esdk/src`):

| Site | Before | After |
|---|---|---|
| D1 `decrypt.rs` `step_verify_header` (header tag) | `&[]`, `&mut []` | `open_buffers(&[], Vec::new())`; the result is mapped back to `Result<(), _>` for `header_auth_gate`, which is unchanged |
| D2 `body_decrypt.rs`, empty final frame | `&enc_content` (empty), `&mut []` | `open_buffers(&enc_content, Vec::new())` |
| D3 `body_decrypt.rs`, non-empty final frame | `result.resize(enc_content.len(), 0)`, then `&mut result` | `result = open(.., open_buffers(&enc_content, take(&mut result)), ..)?` |
| D4 `body_decrypt.rs`, regular frame | `result.resize(frame_length_usize, 0)` after `read_into_vec`, then `&mut result` | same as D3. The resize now happens after the tag read and `body_aad`, and to `enc_content.len()`; `read_into_vec` makes that equal to `frame_length_usize`, so the size is the same |
| D5 `body_decrypt.rs`, non-framed body | `result = enc_content.clone()`, then `result.as_mut()` | `open_buffers(&enc_content, enc_content.clone())`; the starting bytes are the same and the resize does nothing |

Behavior is unchanged: every site already sized exactly, so only where the
resize happens moved, and `result` is local (on `Err` the function returns
and drops it). Errors, their order, messages and streaming are unchanged.
Everything touched is `pub(crate)`.

**Verus-proven:** every `OpenBuffers` has `plain_len() == cipher().len()`;
`open_buffers` returns one for the given ciphertext.

**Compiler-enforced:** only `open_buffers` can build an `OpenBuffers`
(private fields); `secret::open` accepts only an `OpenBuffers`; and
`secret::open` is the only esdk path to `aes_decrypt` under a message key,
because `MessageKey.bytes` is private to `secret.rs`. Together these cover
all 5 sites and any future one. The per-site sizing arguments, including
D4's reliance on `read_into_vec`, are no longer needed: the size comes from
the ciphertext slice that is actually passed to `aes_decrypt`.

**Trusted, not proven:** the body of `secret::open` (TB-A, outside
`verus!`) passes the two fields to `aes_decrypt` unchanged. It is three
lines. What aws-lc-rs would do with a mismatched buffer stays under A-OPEN,
but esdk never passes one.

**Numbering.** A new number, VR-016, rather than a change to VR-014: VR-014
is a prim proof about what prim does with a given buffer, and this is an
esdk proof about which buffers esdk passes, with its own target, mutations
and trusted split. VR-014(b)'s row and the "ESDK impact of BUG-07" section
point here.

**Mutation tests** (default features; each reverted):

| Mutation | Caught by | Result |
|---|---|---|
| `open_buffers` resizes to `cipher_text.len() + 1` | Verus | `80 verified, 1 errors`: type invariant; possible arithmetic overflow |
| D3 builds `OpenBuffers { cipher_text: &enc_content, plain_text: vec![0; len + 1] }` by hand | compiler | `E0451` private fields |
| D5 passes `&enc_content, &mut vec![0; len + 1][..]` the old way | compiler | `E0061` wrong argument count |
| D5 passes a `len + 1` `Vec` into `open_buffers` | no error (`81 verified, 0 errors`) | expected: `open_buffers` resizes it back, so the buffer at `aes_decrypt` is still exact. A site cannot mis-size through `open_buffers` |

### VR-017 and VR-018 in-crate: encrypt-side limits and length checks

Branch `verus-encrypt-limits-and-lengths`. Two numbers because they sit in
different files and guard different things. VR-017 is the encrypt
counterpart of VR-004; VR-018 is the encrypt counterpart of the VR-009 length
checks. Neither changes VR-004, VR-005, VR-009 or VR-016.

**VR-017: encrypt body limits (`body/body_encrypt.rs`).** Origin: the
sequence part is threat-driven (Attack Tree 1, "implementation wraps 32-bit
sequence number", which means GCM nonce reuse); the MAX_DATA part is
capability-driven (no threat entry).

- `PlaintextBudget` replaces the `total_data_size: usize` counter. Its type
  invariant is `total <= MAX_DATA`. `add(chunk, bound)` tests
  `chunk > MAX_DATA - total` (the same test as today's
  `total + chunk > MAX_DATA`, but it cannot overflow), then the Plaintext
  Length Bound, in today's order. It has no `requires`, because its caller
  is unverified async code. On a rejection the total is unchanged; the
  caller returns the error at once, so this is unobservable.
- `EncryptFrameSeq` replaces `sequence_number: u32`. `take_regular` makes
  today's `== ENDFRAME_SEQUENCE_NUMBER` check, returns the current number
  and adds 1. The `+= 1` moved from after `construct_frame` into
  `take_regular`, before it. That is unobservable: if `construct_frame`
  fails, the function returns `Err` and drops the counter.
- `MAX_DATA` moved into `verus!` as `u64` `0x000F_FFFF_FFE0` (same value).
  Verus rejects 2^36 as a `usize` without a `global size_of usize == 8`
  directive, whose cargo expansion trips `unused_braces` under clippy; a
  `u64` budget avoids both, and `usize as u64` is lossless.
- `lemma_max_data_bounds_frames` and `lemma_frame_guard_needed_at_16` state
  how the two limits relate. The guard fires after `2^32 - 2` regular
  frames. Those frames hold more than MAX_DATA iff the frame length is at
  least 17, so for 1 to 16 bytes the frame-count guard, not MAX_DATA, stops
  the counter. The code has the guard, so it does not rely on MAX_DATA.

**VR-018: encrypt header length checks (`esdk/src/encrypt.rs`).** Origin:
capability-driven (no threat entry; T8 is the decrypt-side commitment check,
VR-001).

- `check_v2_suite_data(suite_data, expected_len)` takes the
  `Option<PublicBytes>` and returns it on success, so the presence check and
  the length check both live in the core, in today's order.
- `data_key_len_ok(data_key, expected_len)` reads the length through the
  verified `MessageKey::len`. The adapter keeps the `format!` message.
- For keys from `derive_keys` this check never fails (VR-009 already proves
  the derived key length for V2). We prove the check, not that it is
  unreachable.

**Verus-proven:** the start value 1, +1 per regular frame, no wrap, refusal
of the regular frame that would be numbered `u32::MAX`, the final frame
number = regular frames + 1; the total stays `<= MAX_DATA`, `TooLarge` iff
`total + chunk > MAX_DATA`, `OverBound` iff not `TooLarge` and over the
bound, no overflow; the frame-length relationship above; the suite-data
and data-key accept-iff-equal decisions with their variant order.

**Unverified glue / trusted:** the async loop threading (above);
`read_up_to_peek` returning `in_size <= frame_length` (trusted, as today,
`debug_assert!`); the `usize::try_from` conversions of the frame length and
bound; the mapping of each variant to today's `val_err` / `err(Kind::Internal,
..)` messages; `algorithm_suite_data_length()` (MPL) and
`get_encrypt_key_length` (a const table outside `verus!`), which supply the
expected lengths.

**Findings (no behavior change):**
- F1: encrypt refuses framed messages over 2^36 - 32 bytes, but no Duvet
  annotation is attached to that check. The only 2^36 - 32 requirement in the
  annotations is for non-framed content (`message-body.md#nonframed-data-encrypted-content-length`),
  which the Rust ESDK never encrypts. Framed decrypt applies no total limit,
  so this ESDK decrypts framed messages over 64 GiB but will not produce them.
  Stricter than the spec, not a safety issue; a question for the spec owners.
- F2: the bound error differs between regular frames ("configured") and the
  final frame ("specified"). Kept verbatim.

**Mutation tests** (default features; each reverted; all caught by Verus):

| Mutation | Result |
|---|---|
| M1 `chunk > MAX_DATA - total` → `>=` (off by one) | `93 verified, 1 errors`: postcondition |
| M2 overflow-prone form `total + chunk > MAX_DATA` | `93 verified, 1 errors`: possible arithmetic overflow |
| M3 drop the `== ENDFRAME_SEQUENCE_NUMBER` guard | `93 verified, 1 errors`: possible arithmetic overflow |
| M4 drop the guard and use `wrapping_add(1)` (let it wrap) | `93 verified, 1 errors`: type invariant |
| M5 `start()` with `next: 0` | `93 verified, 1 errors`: type invariant |
| M6 suite data accepts `expected_len + 1` | `93 verified, 1 errors`: postcondition |
| M7 data key accepts `expected_len + 1` | `93 verified, 1 errors`: postcondition |
| M8 guard at `ENDFRAME_SEQUENCE_NUMBER - 1` (off by one) | `93 verified, 1 errors`: postcondition, overflow |

Adapter mutations (for example passing a stale number to `construct_frame`)
are glue and are not caught.

### VR-008 in-crate (`aws-mpl-primitives`, `prim/src/ecdsa.rs`)

`prim/Cargo.toml` sets `[package.metadata.verus] verify = true` and depends on
`vstd = "=0.0.0-2026-06-14-0213"`. `cargo-verus` builds the crate's one
dependency (`aws-lc-rs`) with plain rustc and verifies the `verus!` block in
`prim/src/ecdsa.rs`. No `assume`, `admit`, and no
`#[cfg(not(verus_keep_ghost))]`. The only trusted declarations are the FFI/std
boundary: an `external_type_specification` naming `aws-lc-rs`'s opaque
`Signature`, and two `assume_specification`s for std-library methods Verus does
not otherwise model in this toolchain (`Signature::as_ref` and
`<[u8]>::copy_from_slice`, the latter restated verbatim from vstd with its
equal-length precondition). These model external contracts; they do not relax
any obligation on the crate's own loop or copy.

Run from the repo root:

```bash
make -C prim verus
```

Output (default features, then `--no-default-features --features aws-lc-sys`):

```
verification results:: 3 verified, 0 errors
verification results:: 3 verified, 0 errors
```

| Fn | File | What Verus checks | Target |
|----|------|-------------------|--------|
| `sign_fixed_len_core` | `prim/src/ecdsa.rs` | the `while` loop terminates (`decreases MAX_SIGN_ATTEMPTS - attempt`); the guarded `copy_from_slice` is in bounds | VR-008 |

The real retry loop is **inside** `verus!`. `sign_fixed_len_core` is the
verified core: it counts `attempt` from 0 to `MAX_SIGN_ATTEMPTS`, calls the
`sign_once` closure each iteration, and on a length match writes the candidate
with `copy_from_slice`. A thin `sign_fixed_len` adapter outside `verus!` builds
the crate `Error` strings (`format!`) and maps the signing closure's errors —
the pieces Verus does not model — onto a `verus!`-internal `SignCoreError`, so
the `Error` type never enters the verified region. `MAX_SIGN_ATTEMPTS` and the
loop both live inside `verus!`.

**What is proven:** the bounded retry terminates — the loop invariant
`attempt <= MAX_SIGN_ATTEMPTS` with `decreases MAX_SIGN_ATTEMPTS - attempt` is
what Verus checks on the actual `while` loop, so it runs at most
`MAX_SIGN_ATTEMPTS` times. And `copy_from_slice` runs only inside the
`candidate.len() == want_len` guard; the invariant carries
`want_len == signature.len()`, so the two slice lengths are equal and
`copy_from_slice`'s equal-length precondition holds — the write can never be
out of bounds. `check_sig_len` has already pinned `signature.len()` to
`signature_len(alg)` before signing begins.

**What is not proven:** nothing about the cryptography. The `sign_once` closure
runs the `aws-lc-rs` signing operation and its result (including the candidate
length) is trusted; the proof never assumes anything about it. Only the loop
bound and the in-bounds copy are machine-checked.

### VR-006 in-crate (`aws-mpl-primitives`, `prim/src/lib.rs`)

The AES-GCM buffer-safety cores are now inside a `verus!` block in
`prim/src/lib.rs`, checked by the same `make -C prim verus`. No `assume`,
`admit`, `external_body`, `external`, or `#[cfg(not(verus_keep_ghost))]`; the
cores reason against vstd's own specifications for `Vec::extend_from_slice`,
`Vec::as_mut_slice` and `<[T]>::split_at_mut` (vstd registers these for the
downstream crate, so — unlike T1's `copy_from_slice` — none had to be
restated). The `aws-lc-rs` calls and the crate `Error` stay in the thin
`aes_encrypt`/`aes_decrypt` adapters outside `verus!`, exactly as T1 keeps them
out of `sign_fixed_len_core`.

Output (default features, then `--no-default-features --features aws-lc-sys`),
the `aws-mpl-primitives` line, now covering both VR-008 and VR-006:

```
verification results:: 5 verified, 0 errors
verification results:: 5 verified, 0 errors
```

| Fn | File | What Verus checks | Target |
|----|------|-------------------|--------|
| `aes_encrypt_extend_core` | `prim/src/lib.rs` | after `extend_from_slice(message)`, `old_size` is in range for `split_at_mut`, so the appended tail slice (`cipher_text[old_size..]`) is in bounds and exactly `message.len()` bytes | VR-006 |
| `aes_decrypt_len_ok` | `prim/src/lib.rs` | `Ok` iff `plain_text.len() >= cipher_text.len()`; `Err` iff `plain_text.len() < cipher_text.len()` (the guard before the gather) | VR-006 |

The shipped `aes_encrypt` calls `aes_encrypt_extend_core` to obtain the
in-bounds ciphertext region it hands to the `aws-lc-rs` seal; the shipped
`aes_decrypt` returns `Err` when `aes_decrypt_len_ok` rejects an under-sized
plaintext buffer, before the `open_separate_gather` call. There is one
definition of each function — the proved core is the shipped core. Both cores
were mutation-tested: moving the split index to `old_size + 1` fails the
`split_at_mut` precondition, and making `aes_decrypt_len_ok` always return `Ok`
fails its postcondition, so neither obligation is a tautology.

**What is proven (VR-006):** only the Rust-side buffer safety / no-panic.
(a) `aes_decrypt` rejects a plaintext buffer shorter than the ciphertext before
the `aws-lc-rs` gather; (b) `aes_encrypt`'s `cipher_text[old_size..]` slice is
always in bounds with length `message.len()`, so it cannot panic.

**What is NOT proven (VR-006):** the AES-GCM key length (16/24/32) and the IV
validity. These are enforced *inside* `aws-lc-rs` — `UnboundKey::new` returns
`Err` on a bad key length and `Nonce::try_assume_unique_for_key` returns `Err`
on a bad IV — not by Rust-side branches in `prim`, so Verus cannot see them;
they are a trusted boundary. No crypto correctness is proven either (the
`seal`/`open` and tag verification are `aws-lc-rs`).

### VR-009 prim half in-crate (`aws-mpl-primitives`, `prim/src/hkdf.rs`)

The HKDF key-length decision and the no-salt slice are now inside a `verus!`
block in `prim/src/hkdf.rs`, checked by the same `make -C prim verus`. No
`assume`, `admit`, `external_body`, `external`, or
`#[cfg(not(verus_keep_ghost))]`. The crate `Error`, the `DigestAlg` enum and
the external `aws-lc-rs` `aead::Algorithm` stay in thin adapters outside
`verus!` (`get_len`, `digest_to_hkdf`, `hkdf_no_salt`), exactly as T1 keeps the
`Error` out of `sign_fixed_len_core` and T2 keeps it out of the AES cores. The
cores reason over plain `usize` and a `verus!`-internal `HkdfDigest` enum (a
mirror of `DigestAlg`), so no crate type Verus cannot model enters the proof.

Output (default features, then `--no-default-features --features aws-lc-sys`),
the `aws-mpl-primitives` line, now covering VR-008, VR-006 and VR-009 prim
half:

```
verification results:: 10 verified, 0 errors
verification results:: 10 verified, 0 errors
```

| Fn | File | What Verus checks | Target |
|----|------|-------------------|--------|
| `hkdf_key_len_ok` | `prim/src/hkdf.rs` | `Ok` iff `len ∈ {16, 24, 32}` and `Err` otherwise (decision is total); each `Ok` variant pinned to its length (`Aes128 ⟺ 16`, `Aes192 ⟺ 24`, `Aes256 ⟺ 32`) | VR-009 prim half |
| `salt_size_core` | `prim/src/hkdf.rs` | the default salt length per digest (`Sha256⇒32`, `Sha384⇒48`, `Sha512⇒64`) and `sz <= MAX_SALT_SIZE` (64) | VR-009 prim half |
| `no_salt_slice_core` | `prim/src/hkdf.rs` | given a `MAX_SALT_SIZE`-byte buffer, the subrange `salt[0..sz]` is in bounds (so `hkdf_no_salt` cannot panic on the slice) and its length is the digest's salt size | VR-009 prim half |

The shipped `get_len` dispatches on `hkdf_key_len_ok`'s verified decision and
maps each variant to the matching `aws-lc-rs` algorithm; the shipped
`hkdf_no_salt` builds the `[0u8; MAX_SALT_SIZE]` buffer and takes its salt
slice through `no_salt_slice_core`. There is one definition of each function —
the proved core is the shipped core. Each obligation was mutation-tested: a
wrong key-length mapping, accepting an extra length, a wrong salt value, a
salt length of `MAX_SALT_SIZE + 1`, and dropping the buffer-length `requires`
each produce a Verus error (`postcondition not satisfied` / `precondition not
satisfied`), so none of the obligations is a tautology.

**What is proven (VR-009 prim half):** only the Rust-side decision and
no-panic. (a) The HKDF key-length decision over the real `okm.len()` is total
and correct — `Ok` for exactly `{16, 24, 32}` and `Err` for every other
length, the same `{16, 24, 32}` shape the esdk half keys off; (b) the no-salt
slice `&salt[0..sz]` is always in bounds, so `hkdf_no_salt` cannot panic on it.

**What is NOT proven (VR-009 prim half):** the HKDF crypto itself, the derived
key bytes, and the `aws-lc-rs` extract / expand / fill results (including their
`Err` cases) — these are the trusted `aws-lc-rs` boundary, reached only through
the thin adapters outside `verus!`.

**VR-009 is now verified on both halves.** The esdk half
(`esdk/src/key_derivation.rs`: `identity_kdf_key_len_ok`, `check_v2_key_lengths`)
and the prim half (`prim/src/hkdf.rs`: `hkdf_key_len_ok`, `salt_size_core`,
`no_salt_slice_core`) are each in-crate, each with its own trusted boundary
(the esdk MPL getters / the aws-lc-rs HKDF). With T3, all three prim
panic-point targets — VR-006, VR-008 and the VR-009 prim half — are in-crate.

### VR-013 in-crate (`aws-mpl-primitives`, `prim/src/lib.rs`, `prim/src/ecdsa.rs`)

Pipeline target **VR-2026-C03** (prim wrappers never panic and keep exact
length contracts), non-AES part. Six verified cores inside `verus!`, each the
single definition the shipped wrapper calls; each public fn is a thin adapter
outside `verus!` that owns the `DigestAlg` dispatch, `format!` and the crate
`Error`. No `assume`, `admit`, `external_body` on exec/proof fns, `external`,
or `#[cfg(not(verus_keep_ghost))]`. The error types the cores return
(`OutLenMismatch`, `KbkdfCoreError`, `RandFillError`) are declared inside
`verus!`. Runtime behavior is unchanged: same accepted lengths, same error
order, byte-identical messages (pinned by `prim/tests/test_wrapper_contracts.rs`,
which passed on the unchanged code before the refactor).

Output (default features, then `--no-default-features --features aws-lc-sys`),
the `aws-mpl-primitives` line, covering VR-006, VR-008, VR-009 prim half,
VR-013 and VR-014:

```
verification results:: 18 verified, 0 errors
verification results:: 18 verified, 0 errors
```

| Fn | File | What Verus checks | Target |
|----|------|-------------------|--------|
| `digest_core` | `prim/src/lib.rs` | `Ok` iff `out.len() == output_len(alg)`; on `Err`, `want_len` is that length and `out` is unchanged; the `copy_from_slice` runs only after the guard and is proven in bounds (A2) | VR-013(a) |
| `digest_finish_core` | `prim/src/ecdsa.rs` | same three facts against the context's output length; copy in bounds (A5) | VR-013(b) |
| `kbkdf_core` | `prim/src/lib.rs` | `Err(Unavailable)` iff the lookup returns `None`; `Ok` only when available; a derivation failure maps to `DerivationFailed`; `okm` keeps its length; no panic path | VR-013(c) |
| `fill_random_core` | `prim/src/lib.rs` | totality (no `requires`, Verus's panic check covers every input); `bytes` keeps its length | VR-013(d) |
| `ct_equal_core` | `prim/src/lib.rs` | totality; the result is exactly the `Ok`-ness of `verify_slices_are_equal` (A13) | VR-013(e) |
| `hmac_core` | `prim/src/lib.rs` | `Ok` iff `out.len() == tag_len(hmac_alg)`; on `Err`, `want_len` is that length and `out` is unchanged; copy in bounds (A8) | VR-013(f) |

**Value source in `hmac`.** The old code took `want_len` from
`get_digest_alg(alg).output_len()` and relied on `hmac::sign` producing that
many bytes, a link the model cannot see. `hmac_core` takes it from
`hmac_alg.tag_len()`, the tag length of the algorithm that signs. In
aws-lc-rs 1.18.1 these are the same value (`HMAC_SHA256 =
Algorithm(&digest::SHA256)`, `tag_len()` returns `digest_algorithm().output_len`,
`hmac.rs:131-153`), so accepted lengths and messages are unchanged.

**What is proven (VR-013):** the guards, the error mapping, and panic freedom
of the wrapper logic, given the TCB below; the exact-length contracts of
`digest`, `DigestContext::finish` and `hmac` (`Ok` iff the buffer has the
algorithm's length, `out` untouched on `Err`, copy in bounds).

**What is NOT proven (VR-013):** the digest, HMAC, KBKDF and RNG output bytes;
that `constant_time_equal` returning `true` means the slices are equal, and its
timing (third-party semantics; A13 only says the result is a function of the
two byte sequences); that the aws-lc-rs calls do not panic (trusted, see TCB).
`generate_random_bytes` is totality only.

**Findings (VR-013):**

- **F3:** the `Unavailable` branch of `kbkdf_ctr_hmac` is dead with aws-lc-rs
  1.18.1 (`kdf/kbkdf.rs:38-49` always returns `Some`). It is not encoded in
  the spec (A10 makes no such claim), so the proof stays valid if a later
  aws-lc-rs returns `None`.
- **F4:** `DigestContext::finish`'s wrapper has no panic path, but panic
  freedom is still conditional on A5: aws-lc-rs documents that
  `Context::finish` panics if the digest cannot be finalized
  (`expect("EVP_DigestFinal failed")`, `digest.rs:131-137`).

### VR-014 in-crate (`aws-mpl-primitives`, `prim/src/lib.rs`)

Pipeline target **VR-2026-C03**, AES part, and **BUG-07** (MPL-Verus
`docs/bug-reports/BUG-07-prim-aes-buffer-handling.md`). These are new results
next to VR-006, not a re-proof of it: VR-006's `aes_encrypt_extend_core` slice
fact and `aes_decrypt_len_ok` iff are unchanged; the extend core gains two
labeled conjuncts, and two new cores, `aes_encrypt_core` and
`aes_decrypt_core`, call the VR-006 cores first. BUG-07 is **not fixed**; the
plaintext residue stays exactly as shipped.

| Fn | File | What Verus checks | Target |
|----|------|-------------------|--------|
| `aes_encrypt_extend_core` (two new conjuncts) | `prim/src/lib.rs` | the returned tail holds the plaintext (`slice@ == message@`), and `final(cipher_text)@ == old(cipher_text)@ + final(slice)@` | VR-014(a) |
| `aes_encrypt_core` | `prim/src/lib.rs` | with `o` = old buffer, `m` = message: key or nonce rejected ⇒ buffer is exactly `o ++ m`; seal failed ⇒ length `|o| + |m|`, prefix `o`; `Ok` ⇒ length `|o| + |m| + 16`, prefix `o`, and (in-body assert) `buffer == o ++ ct ++ tag`, the tag appended after the ciphertext | VR-014(a), BUG-07(a) **proved** |
| `aes_decrypt_core` | `prim/src/lib.rs` | relative to **A-OPEN**: `Ok` ⇒ `|plain_text| == |cipher_text|`; `|plain_text| > |cipher_text|` ⇒ `Err` and never `PlainTooShort`; on every path `plain_text` keeps its length | VR-014(b), BUG-07(b) **recorded under A-OPEN** |

**What is proven (VR-014):** (a) the exact `Vec` effects of `aes_encrypt` on
every path, in the shipped order (extend first, then key, nonce, seal, tag
append). (b) Under the labeled assumption A-OPEN, that a decrypt buffer longer
than the ciphertext passes the prim guard and can only end in a callee-side
`Err`.

**What is NOT proven (VR-014):** the AES-GCM crypto, the ciphertext and tag
bytes, the tail bytes after a seal failure (A18 leaves them unspecified), and
the aws-lc-rs `open_separate_gather` contract itself. A-OPEN is an
**assumption** taken from the aws-lc-rs 1.18.1 doc ("The `out_plaintext`
length must match the provided `in_ciphertext`", `aead.rs:~806`) and
`unbound_key.rs:136-139`; the callee's behavior is assumed, not proved.

**Findings (VR-014):**

- **F1 (BUG-07(a), proved):** when the key or nonce check fails, the caller's
  `cipher_text` is exactly `old ++ message`, i.e. the plaintext stays appended
  (`len = old_len + message.len()`). When the seal fails, the length is
  `old_len + message.len()` and the prefix is unchanged.
- **F2 (BUG-07(b), recorded under A-OPEN):** the prim guard
  `plain_text.len() < cipher_text.len()` is weaker than the callee's check. A
  buffer of `ct + 1` or `ct + 16` bytes passes the guard and is then rejected by
  aws-lc-rs; the wrapper reports it as "authentication tag did not match"
  (pinned by `aes_decrypt_buffer_length_cases`). Under A-OPEN, the VR-006 guard
  is not what makes `Ok` imply equal lengths.

**ESDK impact of BUG-07 (reviewed at `43b9ff77`; code reading over VR-014.
(b) is now Verus-proven at the call sites by VR-016, branch
`sizing-and-sigpresence`.)** esdk reaches prim AES only through
`secret::seal` / `secret::open` (`esdk/src/secret.rs`), from 2 seal and 5 open
call sites.

- **BUG-07(a): harmless in esdk today; latent hazard only.**
  - Frame seal (`body_encrypt.rs` `construct_frame`): the seal's `?` returns
    before `write_to_sink` and before the signature-digest write, and the
    scratch `frame_buf` is dropped. It is also cleared at the start of each
    frame. Nothing from a failed frame reaches the output, the digest, the
    return value or the error text.
  - Header-tag seal (`encrypt.rs` `build_header_auth_tag`): seals an empty
    plaintext, so nothing is appended.
  - Streaming encrypt writes a frame only after its seal returns `Ok`.
  - The failure paths are also unreachable given esdk's inputs (key length
    and IV length come from the suite that selects the AES variant;
    `check_v2_key_lengths`, `identity_kdf_key_len_ok` and `iv_seq_core` are
    Verus-proven; the suite-table/aws-lc-rs length match is not). That is an
    argument, not a proof. The no-escape conclusion does **not** depend on it:
    it depends on the seal-before-write order in `construct_frame`. A refactor
    that writes or reuses `frame_buf` on an error path would make (a) real.
  - Severity: confidentiality, Informational/Low; likelihood negligible.
- **BUG-07(b): unreachable from esdk (Verus-proven at every esdk open site,
  VR-016; was code reading).** All 5 open sites now build their buffers with
  the verified `secret::open_buffers`, whose `OpenBuffers` type invariant
  says the plaintext buffer is exactly as long as the ciphertext, and
  `secret::open` accepts nothing else. Only the three-line TB-A body of
  `secret::open` (it passes the two fields to `aes_decrypt` unchanged) is
  code reading. This is still relative to A-OPEN for what aws-lc-rs would do
  with a mismatch: a mis-sized buffer would fail closed with a misleading
  "authentication tag did not match" message (availability only). The
  earlier code reading (header-auth and empty final frame 0/0; non-empty
  final frame and non-framed body equal by construction; regular frames
  `frame_length_usize` on both sides via `read_into_vec`) found every site
  exactly sized, and the proof agrees.
- **Tests:** no esdk test exercises either error path; the BUG-07 behavior is
  covered only by the prim tests.
- **Recommendations (not implemented).** For prim owners: build the key and
  nonce before the extend; `truncate(old_size)` on seal `Err` so every `Err`
  leaves the buffer unchanged (a provable contract); tighten the decrypt guard
  to `plain_text.len() != cipher_text.len()`. For esdk (optional, defense in
  depth): document the "write only after `seal` returns `Ok`" invariant at the
  `construct_frame` Sink write, optionally clear `frame_buf` on the seal `Err`
  arm. (The third esdk recommendation, a verified sizing core for the open
  sites, is done: VR-016.)

**MPL impact of BUG-07 (reviewed at `2d229377`; code reading over VR-014 —
mpl is not Verus-enabled, so no mpl-side proof).** mpl calls prim AES at 4
sites: encrypt at `raw_aes_keyring.rs` `wrap_data_key` and
`branch_key_wrap.rs` `wrap`; decrypt at `raw_aes_keyring.rs` `on_decrypt` and
`branch_key_wrap.rs` `unwrap`. At every site the plaintext is a **data key**.

- **BUG-07(a): harmless today (no API escape); latent hazard.**
  - Both encrypt sites return with `?` before the encrypted data key is built,
    and the buffer is dropped. The data key cannot reach an EDK, a returned
    value or an error message.
  - The buffer is a plain `Vec<u8>`, **not zeroized**. If a key/nonce error
    fired, an un-wiped copy of the plaintext data key would remain in freed
    heap memory. mpl otherwise wipes keys, so this rates higher than in esdk.
  - Today the failure cannot fire: `wrap` fixes the key (32 bytes) and IV
    (12 bytes) by type; the raw AES keyring relies on the wrapping-key length
    check in `RawAesKeyringBuilder::build` (`raw_aes_keyring.rs:369-378`,
    pinned by a test). **The "no key residue in practice" conclusion depends on
    that check**; the no-API-escape conclusion does not.
  - Severity: confidentiality, Low; likelihood negligible.
- **BUG-07(b): unreachable from mpl.** Both decrypt sites size the plaintext
  buffer exactly from the same ciphertext slice (relative to A-OPEN).
- **Tests:** no mpl test exercises either error path.
- **Recommendations (not implemented).** prim: build the key and nonce before
  the extend (removes the data-key copy at both mpl encrypt sites), truncate and
  optionally zeroize on seal `Err`. mpl (defense in depth): hold the encrypt
  buffers as `Zeroizing<Vec<u8>>`; treat the `build` length check as
  security-relevant and comment it.
- **Separate finding, outside BUG-07:** in `raw_aes_keyring.rs` `on_decrypt`,
  when a successfully decrypted key has the wrong length, the loop `continue`s
  and drops that **authenticated plaintext data key without wiping it**. Both
  decrypt buffers (`raw_aes_keyring.rs:471`, `branch_key_wrap.rs:275`) are plain
  `Vec<u8>`. Recommendation: hold them as `Zeroizing<Vec<u8>>` (and optionally
  have `unwrap` return `PlaintextDataKey`).

**New build attributes (for PR #103 reviewers).** Verus cannot name
`aws_lc_rs::aead::Aad<A: AsRef<[u8]>>`, which the seal and open specs (A17,
A18, A20) need. The errors, in order: "`aws_lc_rs::aead::Aad` is not
supported"; with a type spec, "cannot find trait `T34_AsRef`"; with a plain
`AsRef` trait spec, "external_trait_specification trait bound mismatch",
fixable only with the unstable `core::marker::PointeeSized`. The boundary,
approved by the user, is the smallest that works:

- a ghost-only `ExAsRef` trait proxy in `prim/src/aws_lc_specs.rs`, under
  `#[cfg(verus_keep_ghost)]` (mirrors how vstd gates its `std_specs`);
- `#![cfg_attr(verus_keep_ghost, feature(sized_hierarchy))]` in
  `prim/src/lib.rs`, a nightly-only feature enabled only when cargo-verus sets
  `verus_keep_ghost`;
- `[lints.rust] unexpected_cfgs = { level = "warn", check-cfg =
  ['cfg(verus_keep_ghost)'] }` in `prim/Cargo.toml`, so rustc's cfg check
  accepts the name.

No exec code is gated, hidden or altered by the cfg. The stable
`cargo build -v` of prim passes only `--check-cfg 'cfg(verus_keep_ghost)'`,
never `--cfg verus_keep_ghost`, so `sized_hierarchy` is not enabled there;
`cargo build`, `cargo test` and `cargo clippy` stay on stable. This interacts
with the future vstd feature-gating work (PR #103 open question 1, approach B):
if vstd and the `verus!` items become feature-gated, this cfg_attr and the
proxy must be gated the same way.

### VR-013 / VR-014 TCB (`prim/src/aws_lc_specs.rs`)

Naming-only entries introduce a symbol and claim nothing. TRUSTED entries are
real assumptions about aws-lc-rs 1.18.1. No entry has a `requires`, so **every
listed call is trusted not to panic**. Allocation failure / OOM
(`extend_from_slice`, `Vec` growth) is out of scope. Reused unchanged from
VR-008 (`prim/src/ecdsa.rs`): `ExSignature`, `Signature::as_ref`,
`<[T]>::copy_from_slice` (vstd spec restated verbatim).

| Id | Item | `ensures` | Kind / source |
|---|---|---|---|
| T-ty | opaque types: `digest::{Algorithm, Digest, Context}`, `hmac::{Algorithm, Key, Tag}`, `kdf::{KbkdfCtrHmacAlgorithm, KbkdfCtrHmacAlgorithmId}`, `error::Unspecified`, `aead::{Algorithm, UnboundKey, Nonce, LessSafeKey, Aad<A>, Tag}` | (none) | naming |
| T-AsRef | `ExAsRef`, an `external_trait_specification` for `core::convert::AsRef`, under `#[cfg(verus_keep_ghost)]` | (none; signature only) | naming. Exists only so Verus can name `Aad<A: AsRef<[u8]>>`; needs `feature(sized_hierarchy)` in Verus builds |
| T-uf | `uninterp spec fn`s: `spec_digest_output_len`, `spec_digest_len`, `spec_context_output_len`, `spec_hmac_tag_len`, `spec_hmac_key_alg`, `spec_hmac_tag_bytes_len`, `spec_kbkdf_available`, `spec_slices_equal_ok` | — | naming |
| A1 | `digest::Algorithm::output_len` | `n == spec_digest_output_len(a)` | naming |
| A2 | `digest::digest(alg, data)` | `spec_digest_len(&d) == spec_digest_output_len(alg)` | **TRUSTED length** (`digest.rs:194-201`) |
| A3 | `<Digest as AsRef<[u8]>>::as_ref` | `s@.len() == spec_digest_len(d)` | naming |
| A4 | `digest::Context::algorithm` | `spec_digest_output_len(r) == spec_context_output_len(c)` | naming |
| A5 | `digest::Context::finish` | `spec_digest_len(&d) == spec_context_output_len(&c)` | **TRUSTED length + TRUSTED no-panic** (`digest.rs:131-137`, documented `expect`) |
| A6 | `hmac::Algorithm::tag_len` | `n == spec_hmac_tag_len(*a)` | naming |
| A7 | `hmac::Key::new(alg, key)` | `spec_hmac_key_alg(&k) == alg` | naming |
| A8 | `hmac::sign(key, data)` | `spec_hmac_tag_bytes_len(&t) == spec_hmac_tag_len(spec_hmac_key_alg(key))` | **TRUSTED length** (tag length == algorithm tag length) |
| A9 | `<hmac::Tag as AsRef<[u8]>>::as_ref` | `s@.len() == spec_hmac_tag_bytes_len(t)` | naming |
| A10 | `kdf::get_kbkdf_ctr_hmac_algorithm(id)` | `(r is Some) <==> spec_kbkdf_available(id)` | naming (no claim it is always `Some`; F3) |
| A11 | `kdf::kbkdf_ctr_hmac(alg, secret, info, output)` | `final(output)@.len() == old(output)@.len()` | Rust type fact |
| A12 | `rand::fill(dest)` | `final(dest)@.len() == old(dest)@.len()` | Rust type fact |
| A13 | `constant_time::verify_slices_are_equal(a, b)` | `(r is Ok) == spec_slices_equal_ok(a@, b@)` | **TRUSTED determinism only** (no claim `Ok` means equal; nothing about timing) |
| A14–A17 | `UnboundKey::new`, `Nonce::try_assume_unique_for_key`, `LessSafeKey::new`, `Aad::<A>::from` | (none) | no-panic only |
| A18 | `LessSafeKey::seal_in_place_separate_tag::<A>` | `final(in_out)@.len() == old(in_out)@.len()` | Rust type fact (nothing about the bytes) |
| A19 | `<aead::Tag as AsRef<[u8]>>::as_ref` | `s@.len() == 16` | **TRUSTED length (AEAD-TAG-16)** (`aead.rs:1069-1074`) |
| A20 | `LessSafeKey::open_separate_gather::<A>` | `(r is Ok) ==> in_ciphertext@.len() == old(out_plaintext)@.len()`; `final(out_plaintext)@.len() == old(out_plaintext)@.len()` | **LABELED ASSUMPTION A-OPEN** (`aead.rs:~806`, `unbound_key.rs:136-139`). Not proven |

The length-preservation clauses (A11, A12, A18, A20 second clause) restate a
Rust type fact (a `&mut [u8]` cannot change length); the core `ensures` that
repeat them (`okm`, `bytes`, `plain_text` keep their length) carry no
independent evidence beyond that.


**Properties that stay model-only, and why:**

| Property | Model | Why it is not in-crate |
|---|---|---|
| Header-auth ordering (verify before decrypt) — VR-002 | `header_auth_ordering_proofs.rs` (superseded) | **Now in-crate** with the `HeaderVerified` token (see "VR-001 (b) and VR-002 in-crate"). The model is kept only as history; VR-002 no longer depends on it. |
| Key-commitment ordering (commitment validate before frame decrypt) — VR-001 (b) | `commitment_ordering_proofs.rs` (superseded) | **Now in-crate** with the `CommitmentAccepted` token (see "VR-001 (b) and VR-002 in-crate"). The model is kept only as history; VR-001 (b) no longer depends on it. Property (c) (constant time) and the signature-release clause are separate and out of scope. |
| EDK list loop | `io_stream_aligned.rs` (`read_edks`) | The count decision is in-crate (`edk_count_check`). What is left is a `for` loop of `.await?` reads over `dyn Source` plus the MPL `EncryptedDataKey` builder; no sync decision logic is left to extract. |
| Encryption-context (AAD) parser | `io_stream_aligned.rs` (`read_canonical_ec` etc.) | Obsolete: parsing moved to MPL (`EncryptionContext::from_bytes`), outside this ESDK scope; esdk only reads a `u16` length and the bytes. |
| Frame ciphertext ‖ tag | `frame_layout_proofs.rs` | `aes_encrypt` (`aws-mpl-primitives`, aws-lc-rs FFI) appends them, and the frame is released through `dyn Sink` / `DigestWriter`. |
| AES-GCM buffer bounds | `aes_gcm_bounds_proofs.rs` (superseded) | **Now in-crate (VR-006, T2):** `prim/src/lib.rs` has a `verus!` block with `aes_encrypt_extend_core` and `aes_decrypt_len_ok`; the standalone model is kept only as the historical model. The AES-GCM key/IV checks and crypto itself remain trusted (`aws-lc-rs`). |
| Zeroization | `zeroize_proofs.rs` | Unchanged, deferred; out of scope for this work. The model describes a hand-written `write_volatile` loop in `PlaintextDataKey::zeroize` that no longer exists (removed in `a864ad87`, #131; the key types now `#[derive(Zeroize, ZeroizeOnDrop)]`), so it does not describe current code. |

---

## 2. Proofs, by file

| File | Verified | Target | What is proven |
|------|----------|--------|----------------|
| `body_aad_proofs.rs` | 4 | VR-005 | `iv_seq`: no panic given `iv.len() >= 4`, last 4 bytes = big-endian sequence number, prefix unchanged. `body_aad`: output = `message_id ‖ content ‖ seq_be(4) ‖ len_be(8)`, length exact. Plus `u32_be`/`u64_be` helpers. |
| `edk_count_proofs.rs` | 4 | VR-007 | `validate_max_encrypted_data_keys`: returns `Ok` **iff** EDK count `> 0` and (if a max is set) `<= max`; empty and over-max rejected; no panic. Three boundary lemmas. |
| `zeroize_proofs.rs` | 4 | VR-010 | `PlaintextDataKey::zeroize` as it was (the loop was removed in `a864ad87`; model deferred): no panic; buffer **fully zeroed** on return (no key bytes remain). Modeled via safe indexed writes (see caveats). |
| `frame_layout_proofs.rs` | 7 | VR-005 | `construct_frame` frame assembly: no panic; `frame_buf` = exact spec layout for regular (`seq ‖ iv ‖ ct‖tag`) and final (`FFFFFFFF ‖ seq ‖ iv ‖ ecl ‖ ct‖tag`) frames. Length + final-frame-sentinel lemmas. |
| `header_parse_proofs.rs` | 7 | VR-003 | Version / content-type / message-type parse: total (no panic), accept **iff** spec-supported, correct variant, Base64 `0x41` hint exact. Bounded readers reject over-limit lengths before use. |
| `frame_sequence_proofs.rs` | 5 | VR-004 | Frame sequence state machine: accept **iff** sequential from 1 (no gaps/repeats/reordering); `expected += 1` **overflow-free**; total. First-frame-must-be-1 and out-of-order-rejected lemmas. |
| `io_stream_model.rs` | 8 | infra | Prototype `SafeRead`/`SafeWrite` abstraction: `ByteReader` (cursor + type invariant), total EOF-safe `read_exact`/`read_u32`, `write_all`; **end-to-end read loop** `read_and_validate_seq_run` (reads sequence numbers from the stream, enforces sequential-from-1, panic-free). |
| `io_stream_aligned.rs` | 24 | infra + VR-003/004/005 | The abstraction reshaped to the **exact `serialize_functions` signatures**: `read_vec`/`read_u8`/`read_u16`/`read_u32`/`read_opt_u8`/`read_seq_u32_bounded` returning `Result<T, SerErr>` (EOF → `Err`; `read_opt_u8` → `Ok(None)`), each mirroring consumed bytes into `raw` (`raw' == raw ++ consumed`); bounded reader rejects over-limit length before reading; end-to-end `read_seq_u16`. **Plus four end-to-end loops:** (a) V1 header tail parse (`read_v1_header_tail`) — total, rejects malformed input, each field spec-valid; (b) framed-decrypt body loop (`read_and_decrypt_framed_body`) — total, strictly sequential from 1, overflow-free, terminating; (c) **EDK list sub-parser** (`read_edks`) — total, rejects `count == 0` and `count > max` before iterating, entry loop terminates; (d) **AAD/encryption-context sub-parser** (`read_canonical_ec`/`read_str_u16`/`read_ec_pairs`) — total, empty-EC short-circuit, non-UTF-8 rejected, pair loop terminates. |
| `header_auth_ordering_proofs.rs` | 5 | VR-002 | Models the `internal_decrypt` 5-step control flow as a phase state machine. Proves the **ordering** invariant: `step_decrypt_body` requires `phase == HeaderVerified`, and the only producer of that phase is a successful `step_verify_header` (which requires `tag_ok`). Therefore **no frame is decrypted unless the header auth tag verified first**; if the tag check fails, the body is never decrypted (the operation halts). **Superseded:** VR-002 is now in-crate (`esdk/src/decrypt_gate.rs`); the model is kept as history. |
| `commitment_ordering_proofs.rs` | 7 | VR-001 (b) | Models the committing-suite portion of `decrypt_steps` as a `HeaderState { Unverified, Verified }` state machine. The modeled commitment decision mirrors `suite_data_check`'s shape (accept iff header suite data == expected **and** committed length agrees). The `verify` transition reaches `Verified` **iff** the commitment accepts; `decrypt_frame` carries `requires state == Verified`. Proves **no frame is decrypted unless the key-commitment check accepted first** (and if it rejects, no frame is ever decrypted). Both obligations mutation-tested (weakening the `verify` accept coupling, and a forbidden `decrypt_frame(Unverified)` call with the guard removed, each make Verus error). **Standalone model, not a proof about `esdk/src/decrypt.rs`.** **Superseded:** VR-001 (b) is now in-crate (`esdk/src/decrypt_gate.rs`); the model is kept as history. |
| `aes_gcm_bounds_proofs.rs` | 3 | VR-006 (partial) | The **non-FFI** buffer bookkeeping of `aes_encrypt`/`aes_decrypt` (`prim/src/lib.rs`). Proves the `aes_encrypt` `cipher_text[old_size..]` slice is always in bounds (never panics) with exact length tracking, and the `aes_decrypt` length guard always rejects an under-sized output buffer before the FFI gather. The AES-GCM crypto itself (aws-lc-rs `seal`/`open`) is out of Verus scope. **Superseded:** this is now proven in-crate (VR-006, T2 — see "VR-006 in-crate"); the standalone model is kept as history. |
| **Total** | **78** | | **0 errors** |

---

## 3. Target coverage (per `docs/verification-recommendations.md`)

| Target | Status | Residual (honestly scoped) |
|--------|--------|-----------------------------|
| VR-001 key commitment verification | **in-crate for (a) and (b)**. Property (a), the accept/reject **decision** (`esdk/src/message/header.rs`, `suite_data_check`), is verified in-crate — `validate_suite_data` accepts **iff** the header suite data equals the derived commit key **and** the committed length agrees, rejecting commitment-first otherwise; obligation mutation-tested. Property (b), the **ordering** (commitment accepted before frame decryption), is in-crate with the `CommitmentAccepted` token (`esdk/src/decrypt_gate.rs`): Verus proves the token is created only when the check passed (or the suite does not commit); the compiler enforces that `step_decrypt_body` cannot run without a `HeaderVerified`, which can only be made from a `CommitmentAccepted`. The model `commitment_ordering_proofs.rs` is superseded | **not Verus-proven, trusted by design**: (c) *constant time* — the timing of `aws_lc_rs::constant_time::verify_slices_are_equal` is an aws-lc-rs API contract (Verus does not model timing). For (b): that the unverified callers pass the real comparison result and the real `has_commitment` value, that frames are decrypted only through `step_decrypt_body` (grep-checked), and that a token is not tied to one message. The derived commit key bytes and the comparison FFI stay at the trusted boundary |
| VR-003 header parsing safety | **in-crate**: big-endian decoding, bounded readers, header-field decisions, the 0x41 Base64 hint (`classify_version_byte`), reserved bytes, IV length, EDK count. **Model only**: the fixed-field header loop and EDK list loop (`io_stream_aligned.rs`) | the async readers over `dyn Source` (unverified glue); the EC sub-parser model is obsolete (parsing is in MPL) |
| VR-004 frame sequence validation | **in-crate**: regular-frame step (`next_expected_frame`), final-frame check (`final_frame_seq_ok`), sequential-run and start-at-1 lemmas | the async loop that threads `expected_frame` (unverified glue) |
| VR-005 frame construction/serialization | **in-crate**: body AAD layout (`body_aad_core`), IV (`iv_seq_core`), frame prefix layout (`write_frame_prefix`). **Model only**: the `ct ‖ tag` append (`frame_layout_proofs.rs`) | `aes_encrypt` (FFI) output and the `dyn Sink` / `DigestWriter` release |
| VR-002 header auth tag ordering | **in-crate** with the `HeaderVerified` token (`esdk/src/decrypt_gate.rs`): Verus proves `header_auth_gate` returns a token only when the header `open` returned `Ok`; the compiler enforces that `step_decrypt_body` cannot run without that token. The model `header_auth_ordering_proofs.rs` is superseded | trusted: that `step_verify_header` passes the real `secret::open` result, that aws-lc-rs AES-GCM accepts only a valid tag, that frames are decrypted only through `step_decrypt_body` (grep-checked), and that a token is not tied to one message |
| VR-015 final plaintext held until the signature verifies (threat R3) | **in-crate** with the `SignatureVerified` token and `HeldFinalPlaintext` (`esdk/src/decrypt_gate.rs`): Verus proves the token is created only when `ecdsa_verify_context` returned `true` (from a `SignatureRequired`: signed suite, key present) or the suite is unsigned and there is no verification key (VR-015 (b), through the `SignaturePresence` token minted by the verified presence check), and `release` returns exactly the held bytes; the compiler enforces that the final plaintext (final frame, last full frame before an empty final frame, or non-framed body) can only be written through `release`, which needs the token, and that step 5 cannot choose its path without the presence token. Regular non-final frames are released early, as the spec allows | trusted: aws-lc-rs signature verification; that the callers pass the real `valid` value, the real suite flag and the real key-present flag; that `dec_mat` is not changed between the presence check and step 5; that the final plaintext reaches the caller only through the gated write; a token is not tied to one message. The `Vec` API is protected by `Result`, not by the token |
| VR-006 AES-GCM panic freedom | **in-crate** (`prim/src/lib.rs`, T2): `aes_encrypt_extend_core` proves the encrypt slice (`cipher_text[old_size..]`) is always in bounds and exactly `message.len()` bytes; `aes_decrypt_len_ok` proves the decrypt plaintext-vs-ciphertext length precondition that rejects an under-sized output buffer before the gather | **not** Verus-proven: the AES-GCM key length (16/24/32) and the IV validity — enforced inside `aws-lc-rs` (`UnboundKey::new` / `Nonce::try_assume_unique_for_key` return `Err`), a trusted boundary; and the crypto itself (aws-lc-rs `seal`/`open`, FFI) |
| VR-008 ECDSA fixed-length signing | **in-crate** (`prim/src/ecdsa.rs`, `sign_fixed_len_core` inside `verus!`): the bounded `MAX_SIGN_ATTEMPTS` retry loop terminates (`decreases MAX_SIGN_ATTEMPTS - attempt`) and the guarded `copy_from_slice` is proven in bounds (tied to `check_sig_len`) | the `aws-lc-rs` signing closure and `Signature` type are the trusted boundary; the thin `sign_fixed_len` adapter builds the `Error`; no crypto property is proven |
| VR-007 EDK count validation | **in-crate**: count-check logic (`edk_count_check`) | the "before any KMS call" ordering (caller-side in `decrypt.rs`) |
| VR-009 HKDF / key-derivation lengths | **both halves in-crate**. esdk half (`esdk/src/key_derivation.rs`): the V1 identity-KDF key-length check (`identity_kdf_key_len_ok`) and the V2 KDF / message-ID / key-length checks that size the derived encryption key (`check_v2_key_lengths`), total and accept iff the checks pass; `derive_keys` dispatches on the verified `msg_format_version_from_u8`. prim half (`prim/src/hkdf.rs`, T3): the `{16, 24, 32}` key-length decision (`hkdf_key_len_ok`), total and correct against `okm.len()`, and the no-salt slice bound (`salt_size_core` `<= MAX_SALT_SIZE`, `no_salt_slice_core` in bounds) | **prim half trust boundary**: the aws-lc-rs HKDF crypto and the extract/expand/fill results (incl. their `Err`), reached through the adapters outside `verus!`. In esdk, unverified: buffer sizes read directly from MPL getters (V1 output, V2 commit key), the V1 salt table `digest_length`, the `debug_assert!`s |
| VR-011 data-key non-disclosure | **confinement** to `esdk/src/secret.rs`, compiler- and clippy-checked (not Verus); **Verus**: the secret types' accessors and the commitment-value declassification | not Verus-proven overall: the encrypt/decrypt flow (plan step 7), the TB-A adapters, aws-lc-rs, keyrings/CMMs and mpl key types are trusted; the PRK hand-off in `key_derivation.rs` is grep-checked only |
| VR-010 key-material zeroization | model only; unchanged, deferred (out of scope for this work) | the modeled `write_volatile` loop was removed in `a864ad87`; current zeroization (`#[derive(Zeroize, ZeroizeOnDrop)]`) is not verified |
| VR-012 big-endian codec round-trip | **in-crate** (`esdk/src/message/serialize_functions.rs`): `lemma_u32_round_trip` and `lemma_u64_round_trip` prove the verified big-endian encoders and decoders are **exact inverses** for `u32` and `u64` — `spec_be_u32(b) == x` when `b@ == spec_u32_to_be(x)`, and the `u64` analogue; mutation-tested. Capability-driven (category 1c), couples the two spec fns each previously verified only against their own side | a functional-correctness lemma about the **codec** only; it says nothing about the async readers/writers (`read_*`/`write_*`) that call the exec helpers. No `u16` round-trip: `u16` has a decoder (`be_u16`) but no encoder. That the exec fns equal std's `from_be_bytes`/`to_be_bytes` rests on their own ensures and the in-module tests, not on these lemmas |
| VR-013 prim wrapper length contracts (pipeline target VR-2026-C03) | **in-crate** (`prim/src/lib.rs`, `prim/src/ecdsa.rs`): `digest`, `DigestContext::finish` and `hmac` return `Err` unless the buffer has the algorithm's exact length, leave `out` unchanged on `Err`, and copy only after the guard (proven in bounds); `kbkdf_ctr_hmac`'s lookup / error mapping has no panic path; `generate_random_bytes` and `constant_time_equal` are total | **trusted (TCB A1–A13):** the aws-lc-rs output lengths (A2, A5, A8), no-panic of every listed call (incl. the documented `Context::finish` `expect`, F4), and A13 determinism. Not proven: output bytes, constant-time equality semantics and timing. F3: the `Unavailable` branch is dead with aws-lc-rs 1.18.1 |
| VR-014 AES buffer effects (pipeline target VR-2026-C03, BUG-07) | **in-crate** (`prim/src/lib.rs`): BUG-07(a) **proved** — `aes_encrypt` leaves exactly `old ++ message` on a key/nonce `Err`, `old_len + |message|` with prefix unchanged on a seal `Err`, and `old ++ ct ++ tag` (+16) on `Ok`. BUG-07(b) **recorded under A-OPEN** — a decrypt buffer longer than the ciphertext passes the guard and can only end in a callee-side `Err` | **assumed, not proven:** A-OPEN (A20), the 16-byte tag (A19), no-panic of the AES calls. Not proven: crypto, ciphertext/tag bytes, tail bytes after a seal failure. FOLLOW-UP: what the `aes_*` callers do with the buffer after an `Err` (mpl 2 + 2, esdk 2 + 5). BUG-07 itself is not fixed. In esdk, (b) is unreachable by VR-016 |
| VR-017 encrypt body limits (MAX_DATA, frame sequence) | **in-crate** (`body/body_encrypt.rs`): `PlaintextBudget` (total never exceeds MAX_DATA; rejects iff the next chunk would; then the Plaintext Length Bound; overflow-free) and `EncryptFrameSeq` (starts at 1, +1 per regular frame, never wraps, final frame = regular count + 1); lemma: MAX_DATA stops the counter first only for frame length >= 17 | the async loop threading in `encrypt_and_serialize_body` (unverified glue); `read_up_to_peek` (`in_size <= frame_length`); the `usize::try_from` conversions; the error mapping |
| VR-018 encrypt header length checks | **in-crate** (`esdk/src/encrypt.rs`): `check_v2_suite_data` (present and exactly `algorithm_suite_data_length()` bytes, in that order) and `data_key_len_ok` (accept iff equal) | the expected lengths come from MPL (`algorithm_suite_data_length`) and the const table `get_encrypt_key_length`; the adapters map variants to today's errors |
| VR-016 decrypt buffer sizing (BUG-07(b) in esdk) | **in-crate** (`esdk/src/secret.rs`): `secret::open` takes only an `OpenBuffers`, built only by the verified `open_buffers`; its type invariant says the plaintext buffer is as long as the ciphertext. All 5 esdk open sites go through it, so BUG-07(b) is unreachable from esdk, Verus-proven | trusted: the TB-A body of `secret::open` passes the two fields to `aes_decrypt` unchanged; what aws-lc-rs does with a mismatch stays under A-OPEN |
| Infra: I/O seam | `esdk` is Verus-buildable; sync `verus!` cores are verified in-crate behind the async `Source`/`Tee` adapters (see "In-crate proofs") | the async adapters themselves stay unverified glue |

---

## 4. Genuineness (mutation testing)

Load-bearing proofs were checked by mutating the code and confirming Verus
*fails* — proving the postconditions actually constrain the implementation:

- **frame layout:** swapping the write order (IV before sequence number) → verification fails.
- **frame sequence:** removing the `expected < 0xFFFFFFFF` guard → Verus reports possible arithmetic overflow.
- **header parse:** accepting `0x03` as version V1 → the accept-iff postconditions fail.
- **zeroize:** writing `1` instead of `0` → the `all_zero` postcondition fails.
- **io stream (model):** weakening the `read_exact` bound so it reads past EOF → out-of-bounds error.
- **io stream (aligned):** dropping the `read_opt_u8` cursor advance → the cursor postcondition fails.
- **header parse loop:** making `read_content_type` accept any byte → the `content_type_ok` postcondition fails.
- **framed-decrypt body loop:** removing the frame-payload cursor-monotonicity guarantee → the loop's `decreases` (termination) proof fails.
- **header auth ordering:** skipping header verification and jumping to `step_decrypt_body` from `MaterialsReady` → its `requires phase == HeaderVerified` precondition fails (body decryption without a verified tag is rejected).
- **EDK sub-parser:** recursing the entry loop without decrementing the count → the `decreases` (termination) proof fails (an unbounded loop reading off an untrusted count is rejected).
- **AAD sub-parser:** recursing the (key, value) pair loop without decrementing → the `decreases` (termination) proof fails.
- **AES-GCM decrypt guard:** making the guard always proceed (ignoring the buffer-size check) → the `proceed <==> (plain_text_len >= cipher_text_len)` postcondition fails.
- **HKDF key-length decision (`hkdf_key_len_ok`, T3):** mapping length 16 to `Aes192` → the `Ok(Aes128) <==> len == 16` and `Ok(Aes192) <==> len == 24` postconditions fail; accepting an extra length (`20 => Ok(...)`) → the `Ok <==> {16,24,32}` and `Err <==>` postconditions fail.
- **HKDF salt size (`salt_size_core`, T3):** returning 40 for SHA-256 → the `Sha256 ==> sz == 32` postcondition fails; returning `MAX_SALT_SIZE + 1` for SHA-512 → the `sz <= MAX_SALT_SIZE` and `Sha512 ==> sz == 64` postconditions fail.
- **HKDF no-salt slice (`no_salt_slice_core`, T3):** dropping the `requires salt.len() == MAX_SALT_SIZE` precondition → the `&salt[0..sz]` subrange reports `precondition not satisfied` (the slice is no longer provably in bounds).
- **key-commitment decision (`suite_data_check`, VR-001 property a):** dropping the committed-length check (accepting whenever the bytes match) → the `Ok <==> (… && commit_len == expected@.len())` and `Err(LengthMismatch) <==>` postconditions fail; inverting the commitment branch (accepting when the bytes differ) → the `Ok`, `Err(CommitmentMismatch)` and `Err(LengthMismatch)` postconditions fail. Both confirm the decision is genuinely constrained, not tautological.
- **key-commitment ordering (`commitment_ordering_proofs.rs`, VR-001 property b):** letting `verify` reach `Verified` without the accept condition (returning `Verified` unconditionally) → the `verify` `(next == Verified) <==> commitment_accepts(…)` and `(next == Unverified) <==> !commitment_accepts(…)` postconditions fail; and, with a forbidden `decrypt_frame(HeaderState::Unverified)` call added, removing the `requires state == Verified` guard flips that call from *precondition not satisfied* to passing — so with the guard in place the forbidden call is rejected. Both confirm the ordering is genuinely constrained, not tautological.
- **decrypt tokens (`esdk/src/decrypt_gate.rs`, VR-001 (b) and VR-002):** creating a token on a failure path makes **Verus** fail each time (`72 verified, 1 errors`, then reverted): in `commitment_gate`, returning a committing token on `Err` → *constructed value may fail to meet its declared type invariant*; in `commitment_not_required`, returning a token for a committing suite → *postcondition not satisfied*; in `header_auth_gate`, returning a token when `open` failed → *postcondition not satisfied*. The order is caught by the **compiler**: calling `step_decrypt_body` without running `step_verify_header` → `E0425` (`header_verified` not in scope); building a `HeaderVerified` in `decrypt.rs` → `E0451` (private field); building a `CommitmentAccepted` in `decrypt.rs` → `E0451` (private fields). Deleting the `&HeaderVerified` parameter and its argument still **compiles** (`cargo build` only warns that `header_verified` is unused; `cargo clippy -- -D warnings` rejects that warning, but deleting the binding too would pass), so only review catches that change.
- **signature presence (VR-015 (b)) and decrypt buffer sizing (VR-016), branch `sizing-and-sigpresence`:** minting the not-required token for a signed suite, swapping the `signature_not_required` branches, minting a presence token on a mismatch, or building a `SignatureRequired` with no key → **Verus** fails each (`80 verified, 1 errors`: postcondition or type invariant); `open_buffers` resizing to `len + 1` → **Verus** fails (type invariant, overflow). Re-reading the key in step 5, calling `signature_gate` without a `SignatureRequired`, hand-building an `OpenBuffers` at an open site, or passing a raw `&mut [u8]` to `secret::open` → the **compiler** rejects it (`E0308`, `E0061`, `E0451`, `E0061`). Details in the VR-015 (b) and VR-016 sections.
- **encrypt limits and length checks (VR-017, VR-018), branch `verus-encrypt-limits-and-lengths`:** an off-by-one in the MAX_DATA check, the overflow-prone `total + chunk` form, dropping the frame-count guard, letting the counter wrap, starting at 0, an off-by-one guard, and accepting a suite-data or data-key length one too long → **Verus** fails each (`93 verified, 1 errors`). Details in the VR-017 and VR-018 section.
- **big-endian codec round-trip (`lemma_u32_round_trip` / `lemma_u64_round_trip`, VR-012):** mutating the decoder `spec_be_u32` (changing the `b[3]` term to `b[3] * 2`) → `lemma_u32_round_trip`'s `spec_be_u32(b) == x as int` postcondition fails (67 verified, 2 errors; the other error is `be_u32`'s own ensures, also tied to the decoder spec); mutating `spec_be_u64` (adding `+ 1` to the `b[7]` term) → `lemma_u64_round_trip`'s postcondition fails (67 verified, 2 errors), then reverted. Both confirm the lemmas genuinely couple the encoder and decoder spec fns and are not a restatement of one side against itself.
- **prim wrapper length contracts (VR-013, pipeline target VR-2026-C03):** removing the length guard in `digest_core`, `digest_finish_core` or `hmac_core` → `precondition not satisfied` on `copy_from_slice` plus the `Ok <==>` / `Err` postconditions fail; changing `!=` to `<` in the `digest_core` / `digest_finish_core` guard → the `Ok <==>` postcondition and the copy precondition fail; reporting `want_len: 0` → the `e.want_len` postcondition fails; taking `hmac`'s `want_len` from a constant `32` → the postconditions and the copy precondition fail; swapping `Unavailable` / `DerivationFailed` in `kbkdf_core` → its postconditions fail; injecting `let _x = bytes[0];` into `fill_random_core` → `index in bounds` precondition not met (the panic check covers the core); `.is_ok()` → `.is_err()` in `ct_equal_core` → the postcondition fails. Each run: `17 verified, 1 errors`, then reverted.
- **AES buffer effects (VR-014, BUG-07):** moving `aes_encrypt_extend_core` after the nonce check (the BUG-07 fix option 1 shape) → the key/nonce `== o + m` postcondition fails; appending `message` instead of the tag → the "tag after ciphertext" assert fails; clearing the buffer on seal failure → the seal-failure postcondition fails; dropping either new extend-core conjunct → the `aes_encrypt_core` postconditions fail; pushing a byte before `old_size` or flipping the first tail byte in the extend core → the matching new conjunct fails; replacing the decrypt guard with `plain_text.len() != cipher_text.len()` (the BUG-07 fix shape) → the observation postcondition fails; dropping A-OPEN's `Ok ==>` ensures from A20 → both decrypt postconditions fail, which shows the BUG-07(b) result rests only on A-OPEN. Each run: `17 verified, 1 errors`, then reverted. Full log: `.agents/tasks/verus-prim-c03/logs/mutations.md` (M1–M19).

---

## 5. Fidelity caveats (what is and isn't machine-checked)

This section covers the standalone models in `verification/` (the in-crate
boundaries are listed under "In-crate proofs" above). The models were written
when `esdk`'s readers took `SafeRead`/`SafeWrite` trait objects; each is a
**faithful, self-contained model** of a specific function as it was then — the
executable body plus `requires`/`ensures`. Honest limits, all documented in the
proof files and `verification/README.md`:

- **Models, not in-crate `verus!` blocks.** If the source functions change, the models must be updated in lockstep. Most of what they cover is now also verified in-crate (see "In-crate proofs"); the rest is model-only for the reasons listed there.
- **`to_be_bytes` / `copy_from_slice` equivalence** (in `body_aad_proofs.rs`): the model uses the equivalent primitive; the one-line equivalence to std is documented, not machine-checked. (The in-crate `iv_seq` / `body_aad` now use the verified `u32_to_be` / `u64_to_be`, checked against `to_be_bytes` by unit tests.)
- **`zeroize` unsafe form** (history; the loop was removed in `a864ad87`): Verus's `Vec` model doesn't expose the raw-pointer `PointsTo` permissions, so the proof covers the equivalent safe indexed-write loop; the `volatile` qualifier and `ptr.add(i)`-in-bounds equivalence were argued informally.
- **`construct_frame` FFI + trait I/O**: `aes_encrypt` (aws-lc-rs) is modeled by its length contract with the FFI output as a real `&[u8]`; the `dyn SafeWrite` release and the ciphertext byte *values* are out of scope.
- **Parser/sequence trait-object reads**: the proofs cover the decision/state-machine given the read value; the trait-object read itself is out of scope (this is exactly what the `io_stream_*` abstraction is designed to close).

- **UTF-8 validation (AAD sub-parser)**: the encryption-context key/value strings are validated with `std::str::from_utf8`, which Verus cannot evaluate. This is wrapped in the single `#[verifier::external_body]` in the project (`utf8_check`), whose `ensures ok == utf8_valid(bytes@)` is a **trusted boundary**: we assert the std check agrees with an abstract `utf8_valid` predicate. What is proven is that the parser branches on the result and rejects non-UTF-8 with `Err(Utf8)`, never panicking. The correctness of UTF-8 validation itself is delegated to std.

The `aws-lc-rs` FFI calls themselves (AES-GCM seal/open, ECDSA sign, HKDF
extract/expand/fill) are **deliberately not** targeted directly — proving them
would require hiding the real work behind `external_body` (beyond the single,
documented std-`from_utf8` boundary above), which the invariants forbid. What
*is* proven in-crate for these functions is the Rust-side decision and
buffer/slice safety around the FFI call: VR-006 (AES-GCM buffer bounds),
VR-008 (the ECDSA retry loop and copy) and VR-009 prim half (the HKDF
`{16, 24, 32}` key-length decision and the no-salt slice bound), plus VR-013
(the digest / HMAC / KBKDF / RNG / constant-time wrapper guards) and VR-014
(the AES `Vec` effects, BUG-07). VR-013/VR-014 call the FFI from inside
`verus!` through `assume_specification`s, never `external_body`; their
trusted facts are listed in "VR-013 / VR-014 TCB". The crypto and the FFI
results stay the trusted boundary.

---

## 6. The I/O seam: `Source`/`Tee` (current) and the `ByteReader` models

`SafeRead`/`SafeWrite` no longer exist. The shipped readers in
`esdk/src/message/serialize_functions.rs` are `async fn`s over
`&mut dyn Source`, where `Source` is tokio `AsyncRead + Unpin + Send`
(`esdk/src/shapes.rs`), and they mirror every byte they read into
`raw: &mut Tee`, where `Tee` is `dyn std::io::Write + Send`, so the header can
be re-authenticated. `read_into_vec` grows its buffer in chunks of at most
`READ_CHUNK` (1 MiB). Verus cannot verify async code or trait objects, so the
in-crate proofs keep these adapters unverified and verify the synchronous cores
they call (see "In-crate proofs" above).

The `ByteReader` in `io_stream_model.rs` / `io_stream_aligned.rs` modeled the
old synchronous `SafeRead`/`SafeWrite` contract (a byte `Seq<u8>` plus a cursor
with a type invariant, `Result` returns, the `raw` mirror). Its bounded-reader,
big-endian, header-field and EDK-count parts, and the regular-frame step of its
frame-sequence loop (regular and final frame, start at 1), are superseded by
the in-crate cores. Its EDK list loop stays model-only (an async loop over
`dyn Source`); its EC sub-parser is obsolete, since EC parsing has moved to MPL
(`EncryptionContext::from_bytes`); its other read loops are possibly stale
against the async readers. The models are kept.

---

## 7. Files

**Created (all under `verification/`, plus this report):**
- `verification/body_aad_proofs.rs`
- `verification/edk_count_proofs.rs`
- `verification/zeroize_proofs.rs`
- `verification/frame_layout_proofs.rs`
- `verification/header_parse_proofs.rs`
- `verification/frame_sequence_proofs.rs`
- `verification/io_stream_model.rs`
- `verification/io_stream_aligned.rs`
- `verification/Makefile`, `verification/README.md`
- `.kiro/steering/verus-verification.md`
- `docs/verus-proofs-report.md` (this file)

**Not modified by the standalone models:** any file under `esdk/`, `prim/`, `mpl/` (or `unsafe-unreviewed-mpl/`, which existed then and was removed upstream in `cdd5980`, #107).

**In-crate proofs (branch `verus-in-crate-esdk`):** `esdk/Cargo.toml`,
`esdk/Cargo.lock`, `esdk/Makefile`, `esdk/src/message/serialize_functions.rs`,
`header_types.rs`, `v1_header_body.rs`, `header.rs`, `encrypted_data_keys.rs`,
`body/body_decrypt.rs`.

**In-crate proofs (branch `verus-in-crate-rest`):**
`esdk/src/message/serialize_functions.rs`, `header.rs`, `header_types.rs`,
`body/body_aad.rs`, `body/body_decrypt.rs`, `body/body_encrypt.rs`.

**In-crate proofs (branch `verus-vr009-key-derivation`):**
`esdk/src/key_derivation.rs`, `esdk/src/message/header_types.rs` (the message
ID length consts moved into `verus!`).

**VR-011 confinement (branch `vr011-confinement`):** `esdk/src/secret.rs`
(new), `esdk/clippy.toml` (new), `esdk/Cargo.toml`, `esdk/Cargo.lock`,
`esdk/src/lib.rs`, `esdk/src/key_derivation.rs`, `esdk/src/encrypt.rs`,
`esdk/src/decrypt.rs`, `esdk/src/message/body/body_encrypt.rs`,
`esdk/src/message/body/body_decrypt.rs`, `esdk/tests/test_custom_keyring.rs`.
**VR-001 (b) and VR-002 tokens (branch `vr001b-vr002-stage2`):**
`esdk/src/decrypt_gate.rs` (new), `esdk/src/lib.rs`, `esdk/src/decrypt.rs`,
`esdk/src/message/header.rs`.

**VR-017 and VR-018 (branch `verus-encrypt-limits-and-lengths`):**
`esdk/src/message/body/body_encrypt.rs`, `esdk/src/encrypt.rs`.
