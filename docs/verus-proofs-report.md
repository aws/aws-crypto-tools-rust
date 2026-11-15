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
> status table.
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
verification results:: 69 verified, 0 errors
verification results:: 69 verified, 0 errors
```

The count is Verus's obligation count, not a function count; the checked
fns are 36 exec fns (13 before the in-crate work, 22 before VR-009, 24 before
VR-011, 34 before VR-001, 35 before VR-012) and 5 proof fns (3 before VR-012; the
two VR-012 round-trip lemmas bring it to 5). The count rose from 59 to 69 at
VR-012: the two lemmas plus the staged `by (nonlinear_arith)` sub-obligations in
the `u64` proof each count. Files are under `esdk/src/message/` unless the path
starts with `esdk/src/`.

| Fn | File | Ensures | Target |
|----|------|---------|--------|
| `DataKeyRef::len`, `MessageKey::len`, `PublicBytes::len` | `esdk/src/secret.rs` | `n == self.view().len()` | VR-011 |
| `MessageKey::zeroed`, `CommitmentValue::zeroed`, private `zero_vec` | `esdk/src/secret.rs` | the view is `len` zero bytes | VR-011 |
| `CommitmentValue::as_suite_data` | `esdk/src/secret.rs` | `s@ == self.view()` (decrypt-side declassification) | VR-011 |
| `PublicBytes::from_commitment`, private `copy_vec` | `esdk/src/secret.rs` | `p.view() == c.view()`, `p.is_public()` (encrypt-side declassification); `copy_vec`: `v@ == src@` | VR-011 |
| `PublicBytes::into_vec`; type invariant `PublicBytes::inv` | `esdk/src/secret.rs` | `v@ == self.view()`; every `PublicBytes` has `lab@ == Label::Public` | VR-011 |
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

Spec fns `spec_be_u16`/`spec_be_u32`/`spec_be_u64`, the `READ_CHUNK` const and
the `LenCheck`, `EdkCount`, `MessageFormatVersion`, `MessageType`,
`ContentType`, `VersionByte`, `BodyAADContent` and `V2KeyLenError` enums, the
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
and `construct_frame` writes the frame fields with `write_frame_prefix`.

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

**Properties that stay model-only, and why:**

| Property | Model | Why it is not in-crate |
|---|---|---|
| Header-auth ordering (verify before decrypt) | `header_auth_ordering_proofs.rs` | The order is the sequence of `.await?` calls in the async `decrypt_steps` (`esdk/src/decrypt.rs`), and "verified" is the `Result` of the aws-lc-rs tag check. Verus cannot verify async fns; a sync core would only prove `Ok ⇒ Ok`. Re-audited: the current order (parse → materials → verify header → decrypt body → verify signature → release last frame) matches the model. |
| Key-commitment ordering (commitment validate before frame decrypt) — VR-001 (b) | `commitment_ordering_proofs.rs` | Same reason as header-auth ordering: the order lives in the async `decrypt_steps`. The commitment check (`validate_suite_data` → `suite_data_check`) runs in the synchronous, `?`-chained step 2 (`step_get_decryption_materials`) and completes before the async frame loop (step 4, `step_decrypt_body`); a sync core would only prove `Ok ⇒ Ok`. This is a **standalone model** of the pipeline, **not** a proof about `esdk/src/decrypt.rs`. Trusted: that `decrypt_steps` is the real pipeline and that the async body runs after the commitment step returns. An in-place / typestate (Stage 2) proof was deliberately not taken. Property (a) (the decision) stays in-crate; property (c) (constant time) and the signature-release clause are separate and out of scope. |
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
| `header_auth_ordering_proofs.rs` | 5 | VR-002 | Models the `internal_decrypt` 5-step control flow as a phase state machine. Proves the **ordering** invariant: `step_decrypt_body` requires `phase == HeaderVerified`, and the only producer of that phase is a successful `step_verify_header` (which requires `tag_ok`). Therefore **no frame is decrypted unless the header auth tag verified first**; if the tag check fails, the body is never decrypted (the operation halts). |
| `commitment_ordering_proofs.rs` | 7 | VR-001 (b) | Models the committing-suite portion of `decrypt_steps` as a `HeaderState { Unverified, Verified }` state machine. The modeled commitment decision mirrors `suite_data_check`'s shape (accept iff header suite data == expected **and** committed length agrees). The `verify` transition reaches `Verified` **iff** the commitment accepts; `decrypt_frame` carries `requires state == Verified`. Proves **no frame is decrypted unless the key-commitment check accepted first** (and if it rejects, no frame is ever decrypted). Both obligations mutation-tested (weakening the `verify` accept coupling, and a forbidden `decrypt_frame(Unverified)` call with the guard removed, each make Verus error). **Standalone model, not a proof about `esdk/src/decrypt.rs`.** |
| `aes_gcm_bounds_proofs.rs` | 3 | VR-006 (partial) | The **non-FFI** buffer bookkeeping of `aes_encrypt`/`aes_decrypt` (`prim/src/lib.rs`). Proves the `aes_encrypt` `cipher_text[old_size..]` slice is always in bounds (never panics) with exact length tracking, and the `aes_decrypt` length guard always rejects an under-sized output buffer before the FFI gather. The AES-GCM crypto itself (aws-lc-rs `seal`/`open`) is out of Verus scope. **Superseded:** this is now proven in-crate (VR-006, T2 — see "VR-006 in-crate"); the standalone model is kept as history. |
| **Total** | **78** | | **0 errors** |

---

## 3. Target coverage (per `docs/verification-recommendations.md`)

| Target | Status | Residual (honestly scoped) |
|--------|--------|-----------------------------|
| VR-001 key commitment verification | **partly in-crate + model only**. Property (a), the accept/reject **decision** (`esdk/src/message/header.rs`, `suite_data_check`), is verified in-crate — `validate_suite_data` accepts **iff** the header suite data equals the derived commit key **and** the committed length agrees, rejecting commitment-first otherwise; obligation mutation-tested. Property (b), the **ordering** (commitment validation before frame decryption), is now proven **model only** (`verification/commitment_ordering_proofs.rs`) on a model of the decrypt pipeline — same status as VR-002 | **not Verus-proven, trusted by design**: (c) *constant time* — the timing of `aws_lc_rs::constant_time::verify_slices_are_equal` is an aws-lc-rs API contract (Verus does not model timing). For (b): the model is **not** a proof about the shipped async `decrypt_steps`; what stays trusted is that `decrypt_steps` is the real pipeline and that the async frame loop runs after the synchronous commitment step returns (an in-place / typestate Stage 2 proof over the shipped path was deliberately not taken). The derived commit key bytes and the comparison FFI stay at the trusted boundary |
| VR-003 header parsing safety | **in-crate**: big-endian decoding, bounded readers, header-field decisions, the 0x41 Base64 hint (`classify_version_byte`), reserved bytes, IV length, EDK count. **Model only**: the fixed-field header loop and EDK list loop (`io_stream_aligned.rs`) | the async readers over `dyn Source` (unverified glue); the EC sub-parser model is obsolete (parsing is in MPL) |
| VR-004 frame sequence validation | **in-crate**: regular-frame step (`next_expected_frame`), final-frame check (`final_frame_seq_ok`), sequential-run and start-at-1 lemmas | the async loop that threads `expected_frame` (unverified glue) |
| VR-005 frame construction/serialization | **in-crate**: body AAD layout (`body_aad_core`), IV (`iv_seq_core`), frame prefix layout (`write_frame_prefix`). **Model only**: the `ct ‖ tag` append (`frame_layout_proofs.rs`) | `aes_encrypt` (FFI) output and the `dyn Sink` / `DigestWriter` release |
| VR-002 header auth tag ordering | **model only** (`header_auth_ordering_proofs.rs`, re-audited against `decrypt_steps`): body decrypt unreachable without a verified header tag | not in-crate: the order is in an async fn and the tag check is aws-lc-rs FFI |
| VR-006 AES-GCM panic freedom | **in-crate** (`prim/src/lib.rs`, T2): `aes_encrypt_extend_core` proves the encrypt slice (`cipher_text[old_size..]`) is always in bounds and exactly `message.len()` bytes; `aes_decrypt_len_ok` proves the decrypt plaintext-vs-ciphertext length precondition that rejects an under-sized output buffer before the gather | **not** Verus-proven: the AES-GCM key length (16/24/32) and the IV validity — enforced inside `aws-lc-rs` (`UnboundKey::new` / `Nonce::try_assume_unique_for_key` return `Err`), a trusted boundary; and the crypto itself (aws-lc-rs `seal`/`open`, FFI) |
| VR-008 ECDSA fixed-length signing | **in-crate** (`prim/src/ecdsa.rs`, `sign_fixed_len_core` inside `verus!`): the bounded `MAX_SIGN_ATTEMPTS` retry loop terminates (`decreases MAX_SIGN_ATTEMPTS - attempt`) and the guarded `copy_from_slice` is proven in bounds (tied to `check_sig_len`) | the `aws-lc-rs` signing closure and `Signature` type are the trusted boundary; the thin `sign_fixed_len` adapter builds the `Error`; no crypto property is proven |
| VR-007 EDK count validation | **in-crate**: count-check logic (`edk_count_check`) | the "before any KMS call" ordering (caller-side in `decrypt.rs`) |
| VR-009 HKDF / key-derivation lengths | **both halves in-crate**. esdk half (`esdk/src/key_derivation.rs`): the V1 identity-KDF key-length check (`identity_kdf_key_len_ok`) and the V2 KDF / message-ID / key-length checks that size the derived encryption key (`check_v2_key_lengths`), total and accept iff the checks pass; `derive_keys` dispatches on the verified `msg_format_version_from_u8`. prim half (`prim/src/hkdf.rs`, T3): the `{16, 24, 32}` key-length decision (`hkdf_key_len_ok`), total and correct against `okm.len()`, and the no-salt slice bound (`salt_size_core` `<= MAX_SALT_SIZE`, `no_salt_slice_core` in bounds) | **prim half trust boundary**: the aws-lc-rs HKDF crypto and the extract/expand/fill results (incl. their `Err`), reached through the adapters outside `verus!`. In esdk, unverified: buffer sizes read directly from MPL getters (V1 output, V2 commit key), the V1 salt table `digest_length`, the `debug_assert!`s |
| VR-011 data-key non-disclosure | **confinement** to `esdk/src/secret.rs`, compiler- and clippy-checked (not Verus); **Verus**: the secret types' accessors and the commitment-value declassification | not Verus-proven overall: the encrypt/decrypt flow (plan step 7), the TB-A adapters, aws-lc-rs, keyrings/CMMs and mpl key types are trusted; the PRK hand-off in `key_derivation.rs` is grep-checked only |
| VR-010 key-material zeroization | model only; unchanged, deferred (out of scope for this work) | the modeled `write_volatile` loop was removed in `a864ad87`; current zeroization (`#[derive(Zeroize, ZeroizeOnDrop)]`) is not verified |
| VR-012 big-endian codec round-trip | **in-crate** (`esdk/src/message/serialize_functions.rs`): `lemma_u32_round_trip` and `lemma_u64_round_trip` prove the verified big-endian encoders and decoders are **exact inverses** for `u32` and `u64` — `spec_be_u32(b) == x` when `b@ == spec_u32_to_be(x)`, and the `u64` analogue; mutation-tested. Capability-driven (category 1c), couples the two spec fns each previously verified only against their own side | a functional-correctness lemma about the **codec** only; it says nothing about the async readers/writers (`read_*`/`write_*`) that call the exec helpers. No `u16` round-trip: `u16` has a decoder (`be_u16`) but no encoder. That the exec fns equal std's `from_be_bytes`/`to_be_bytes` rests on their own ensures and the in-module tests, not on these lemmas |
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
- **big-endian codec round-trip (`lemma_u32_round_trip` / `lemma_u64_round_trip`, VR-012):** mutating the decoder `spec_be_u32` (changing the `b[3]` term to `b[3] * 2`) → `lemma_u32_round_trip`'s `spec_be_u32(b) == x as int` postcondition fails (67 verified, 2 errors; the other error is `be_u32`'s own ensures, also tied to the decoder spec); mutating `spec_be_u64` (adding `+ 1` to the `b[7]` term) → `lemma_u64_round_trip`'s postcondition fails (67 verified, 2 errors), then reverted. Both confirm the lemmas genuinely couple the encoder and decoder spec fns and are not a restatement of one side against itself.

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
`{16, 24, 32}` key-length decision and the no-salt slice bound). The crypto
and the FFI results stay the trusted boundary.

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
