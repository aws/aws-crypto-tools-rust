# Verus Proofs — Work Report

**Repository:** `aws-crypto-tools-rust` (AWS Encryption SDK for Rust)
**Code baseline:** commit `d8c1c3d` for the standalone models; the "In-crate proofs" section and the status tables are current at `5ea2a804`
**Date:** September 2026 (models); November 2026 (in-crate)
**Verus:** `0.2026.07.12.0b42f4c`, toolchain `1.96.0` (binary at `~/verus/verus`)
**Pipeline / targets:** `.kiro/agents/ai-verification-pipeline.md`, `docs/verification-recommendations.md`

---

## 1. Summary

Introduced formal Verus verification to the ESDK, starting from the prioritized
targets in the verification-recommendations doc. The standalone `verification/`
directory now holds ten proof files — **71 obligations verified, 0 errors** in
total (§3) — and an
`SafeRead`/`SafeWrite` abstraction was prototyped and aligned to the real reader
signatures to unblock loop-level proofs.

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
> The prim half (`prim/src/hkdf.rs`, aws-lc-rs HKDF) is not proven.
>
> **Update (branch `vr011-confinement`):** VR-011 plan steps 2–6. The plaintext
> data key and the derived message key are confined to `esdk/src/secret.rs`.
> That is checked by the Rust compiler and clippy, **not by Verus**. Verus
> covers only the secret types' accessors and the commitment-value
> declassification (57 verified, 0 errors). See "VR-011" under "In-crate
> proofs".

### Adherence to the Verus skill invariants
- No proof was weakened: **no** `assume(...)`, `admit()`, or `#[verifier::external]` anywhere. There is exactly **one** `#[verifier::external_body]` — the `utf8_check` wrapper around `std::str::from_utf8` in the AAD sub-parser — used per Verus skill invariant #11 for a std call Verus cannot evaluate (the same role `tag_ok` plays for the AES-GCM check). Its `ensures` is a **trusted boundary, not a proof**: the UTF-8-validation correctness is delegated to the std library; everything around it (that the parser rejects non-UTF-8 with `Err`, never panics) is proven. This is called out explicitly in §5.
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
verification results:: 57 verified, 0 errors
verification results:: 57 verified, 0 errors
```

The count is Verus's obligation count, not a function count; the checked
fns are 34 exec fns (13 before the in-crate work, 22 before VR-009, 24 before
VR-011) and 3 proof fns. Files are under `esdk/src/message/` unless the path
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
| `next_chunk_end` | `serialize_functions.rs` | requires `start < length`; `start < end <= length`, `end - start <= READ_CHUNK` (1 MiB) | VR-003 (bounded allocation per read) |
| `bounded_len_u32` | `serialize_functions.rs` | `OverBound` iff `len > bound`; `Ok` iff `len <= bound` and fits in `usize`; `TooLargeForPlatform` iff `len <= bound` and does not fit; `Ok(n) ==> n == len` | VR-003 |
| `bounded_len_u64` | `serialize_functions.rs` | same as `bounded_len_u32`, for `u64` | VR-003 |
| `msg_format_version_from_u8` | `header_types.rs` | `Some(V1)` iff `b == 1`; `Some(V2)` iff `b == 2`; `None` iff neither | VR-003 |
| `msg_type_from_u8` | `header_types.rs` | `Some(TypeCustomerAed)` iff `b == 0x80`; `None` otherwise | VR-003 |
| `content_type_from_u8` | `header_types.rs` | `Some(NonFramed)` iff `b == 1`; `Some(Framed)` iff `b == 2`; `None` iff neither | VR-003 |
| `reserved_bytes_ok` | `v1_header_body.rs` | `ok` iff all four bytes are 0 | VR-003 |
| `iv_len_matches` | `v1_header_body.rs` | `ok` iff `iv_len == expected` | VR-003 |
| `edk_count_check` | `header.rs` | `Empty` iff `count == 0`; `OverMax` iff `count > 0` and `max` is `Some(m)` with `count > m`; `Ok` otherwise | VR-007 |
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
- **VR-009, prim half and key-derivation adapters.** `prim/src/hkdf.rs`
  (including `get_len`) and the aws-lc-rs HKDF calls are not proven: Verus is
  not enabled in `prim`, by decision, so HKDF and its output-length limit are a
  trust boundary. In esdk, `derive_key_v1` / `derive_key_v2` / `derive_keys`
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

**Properties that stay model-only, and why:**

| Property | Model | Why it is not in-crate |
|---|---|---|
| Header-auth ordering (verify before decrypt) | `header_auth_ordering_proofs.rs` | The order is the sequence of `.await?` calls in the async `decrypt_steps` (`esdk/src/decrypt.rs`), and "verified" is the `Result` of the aws-lc-rs tag check. Verus cannot verify async fns; a sync core would only prove `Ok ⇒ Ok`. Re-audited: the current order (parse → materials → verify header → decrypt body → verify signature → release last frame) matches the model. |
| EDK list loop | `io_stream_aligned.rs` (`read_edks`) | The count decision is in-crate (`edk_count_check`). What is left is a `for` loop of `.await?` reads over `dyn Source` plus the MPL `EncryptedDataKey` builder; no sync decision logic is left to extract. |
| Encryption-context (AAD) parser | `io_stream_aligned.rs` (`read_canonical_ec` etc.) | Obsolete: parsing moved to MPL (`EncryptionContext::from_bytes`), outside this ESDK scope; esdk only reads a `u16` length and the bytes. |
| Frame ciphertext ‖ tag | `frame_layout_proofs.rs` | `aes_encrypt` (`aws-mpl-primitives`, aws-lc-rs FFI) appends them, and the frame is released through `dyn Sink` / `DigestWriter`. |
| AES-GCM buffer bounds | `aes_gcm_bounds_proofs.rs` | The code is in `prim`, which `make -C esdk verus` builds with plain rustc. Verifying it in place would add `vstd` and Verus metadata to the published `aws-mpl-primitives` crate, which this work does not do. Re-audited against `prim/src/lib.rs`: the model matches. |
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
| `aes_gcm_bounds_proofs.rs` | 3 | VR-006 (partial) | The **non-FFI** buffer bookkeeping of `aes_encrypt`/`aes_decrypt` (`prim/src/lib.rs`). Proves the `aes_encrypt` `cipher_text[old_size..]` slice is always in bounds (never panics) with exact length tracking, and the `aes_decrypt` length guard always rejects an under-sized output buffer before the FFI gather. The AES-GCM crypto itself (aws-lc-rs `seal`/`open`) is out of Verus scope. |
| **Total** | **71** | | **0 errors** |

---

## 3. Target coverage (per `docs/verification-recommendations.md`)

| Target | Status | Residual (honestly scoped) |
|--------|--------|-----------------------------|
| VR-003 header parsing safety | **in-crate**: big-endian decoding, bounded readers, header-field decisions, the 0x41 Base64 hint (`classify_version_byte`), reserved bytes, IV length, EDK count. **Model only**: the fixed-field header loop and EDK list loop (`io_stream_aligned.rs`) | the async readers over `dyn Source` (unverified glue); the EC sub-parser model is obsolete (parsing is in MPL) |
| VR-004 frame sequence validation | **in-crate**: regular-frame step (`next_expected_frame`), final-frame check (`final_frame_seq_ok`), sequential-run and start-at-1 lemmas | the async loop that threads `expected_frame` (unverified glue) |
| VR-005 frame construction/serialization | **in-crate**: body AAD layout (`body_aad_core`), IV (`iv_seq_core`), frame prefix layout (`write_frame_prefix`). **Model only**: the `ct ‖ tag` append (`frame_layout_proofs.rs`) | `aes_encrypt` (FFI) output and the `dyn Sink` / `DigestWriter` release |
| VR-002 header auth tag ordering | **model only** (`header_auth_ordering_proofs.rs`, re-audited against `decrypt_steps`): body decrypt unreachable without a verified header tag | not in-crate: the order is in an async fn and the tag check is aws-lc-rs FFI |
| VR-006 AES-GCM panic freedom | **model only** (`aes_gcm_bounds_proofs.rs`, re-audited against `prim/src/lib.rs`): encrypt slice always in-bounds, decrypt rejects under-sized output buffer | not in-crate: `prim` is not Verus-checked; the AES-GCM crypto itself (aws-lc-rs `seal`/`open`, FFI) is out of scope |
| VR-007 EDK count validation | **in-crate**: count-check logic (`edk_count_check`) | the "before any KMS call" ordering (caller-side in `decrypt.rs`) |
| VR-009 HKDF / key-derivation lengths | **esdk half in-crate**: the V1 identity-KDF key-length check (`identity_kdf_key_len_ok`) and the V2 KDF / message-ID / key-length checks that size the derived encryption key (`check_v2_key_lengths`), total and accept iff the checks pass; `derive_keys` dispatches on the verified `msg_format_version_from_u8` | **prim half not proven**: `prim/src/hkdf.rs` (incl. `get_len`) and aws-lc-rs HKDF (trust boundary; Verus not enabled in `prim`). In esdk, unverified: buffer sizes read directly from MPL getters (V1 output, V2 commit key), the V1 salt table `digest_length`, the `debug_assert!`s |
| VR-011 data-key non-disclosure | **confinement** to `esdk/src/secret.rs`, compiler- and clippy-checked (not Verus); **Verus**: the secret types' accessors and the commitment-value declassification | not Verus-proven overall: the encrypt/decrypt flow (plan step 7), the TB-A adapters, aws-lc-rs, keyrings/CMMs and mpl key types are trusted; the PRK hand-off in `key_derivation.rs` is grep-checked only |
| VR-010 key-material zeroization | model only; unchanged, deferred (out of scope for this work) | the modeled `write_volatile` loop was removed in `a864ad87`; current zeroization (`#[derive(Zeroize, ZeroizeOnDrop)]`) is not verified |
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

Functions whose core is an `aws-lc-rs` FFI call (AES-GCM, ECDSA, HKDF) were
**deliberately not** targeted directly — proving them would require hiding the
real work behind `external_body` (beyond the single, documented std-`from_utf8`
boundary above), which the invariants forbid.

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
