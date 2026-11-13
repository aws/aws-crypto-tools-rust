# Verus Proofs — Work Report

**Repository:** `aws-crypto-tools-rust` (AWS Encryption SDK for Rust)
**Code baseline:** commit `d8c1c3d`
**Date:** September 2026
**Verus:** `0.2026.07.12.0b42f4c`, toolchain `1.96.0` (binary at `~/verus/verus`)
**Pipeline / targets:** `.kiro/agents/ai-verification-pipeline.md`, `docs/verification-recommendations.md`

---

## 1. Summary

Introduced formal Verus verification to the ESDK, starting from the prioritized
targets in the verification-recommendations doc. Eight proof files were written
and verified — **48 obligations verified, 0 errors** in total — and an
`SafeRead`/`SafeWrite` abstraction was prototyped and aligned to the real reader
signatures to unblock loop-level proofs.

All work is **additive and non-breaking**: proofs live in a standalone
`verification/` directory referenced by no `Cargo.toml`; `cargo check` on the
`esdk` crate is unaffected; no shipped source was modified.

Run everything with:
```bash
make -C verification verify
```

> **Update (2026-11-12, branch `verus-in-crate-esdk`):** shipped `esdk` code is
> now verified in place (Option A in `docs/verus-in-crate-migration-design.md`).
> See "In-crate proofs (shipped `esdk` code)" below. The rest of this report
> describes the standalone models in `verification/`, which are kept; their
> current status is in `verification/README.md`.

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
verification results:: 19 verified, 0 errors
verification results:: 19 verified, 0 errors
```

| Fn | File (`esdk/src/message/`) | Ensures | Target |
|----|----------------------------|---------|--------|
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
| `next_expected_frame` | `body/body_decrypt.rs` | `Some` iff `seq_num == expected && expected < u32::MAX`; `Some(n) ==> n == expected + 1` | VR-004 |

Spec fns `spec_be_u16`/`spec_be_u32`/`spec_be_u64`, the `READ_CHUNK` const and
the `LenCheck`, `EdkCount`, `MessageFormatVersion`, `MessageType` and
`ContentType` enums are also inside `verus!`. The shipped callers use these
cores: `read_u16/u32/u64` call `be_uN`, `read_into_vec` calls `next_chunk_end`,
`read_seq_u32/u64_bounded` match on `bounded_len_*`, the header readers call the
`*_from_u8` / `reserved_bytes_ok` / `iv_len_matches` cores,
`validate_max_encrypted_data_keys` and `read_edks` call `edk_count_check`, and
the framed-decrypt loop calls `next_expected_frame`.

**Unverified / trusted boundaries:**
- **The async `Source`/`Tee` adapters** are unverified glue. The readers are
  `async fn`s over `&mut dyn Source` (tokio `AsyncRead`, `esdk/src/shapes.rs`)
  that mirror the bytes they read into `&mut Tee` (`dyn Write + Send`). Verus
  cannot verify async code or trait objects, so the adapters read the bytes,
  call a verified core, and build the `Error` (`ser_err` / `err` / `val_err`).
  That they pass the right bytes to the core and keep the `Tee` mirror exact is
  checked by tests, not by Verus.
- **The final-frame sequence check** in `read_and_decrypt_framed_message_body`
  (`body/body_decrypt.rs`) stays an inline `!=` in the async adapter. Only the
  regular-frame step (`next_expected_frame`) is verified in-crate; the
  final-frame check and the start-at-1 property are proved only by the
  standalone `verification/frame_sequence_proofs.rs` model.
- **`next_chunk_end`** is proved to stay in bounds, not to equal
  `start + min(READ_CHUNK, length - start)`; that equivalence is checked by a
  differential unit test.
- **The aws-lc-rs FFI** (AES-GCM, ECDSA, HKDF, digests) is out of Verus scope.
- **`std::str::from_utf8`** is not evaluated by Verus; no in-crate core depends
  on it.
- **MPL `EncryptionContext::from_bytes`** now does the encryption-context
  parsing; it lives in `mpl` and is out of scope here.

---

## 2. Proofs, by file

| File | Verified | Target | What is proven |
|------|----------|--------|----------------|
| `body_aad_proofs.rs` | 4 | VR-005 | `iv_seq`: no panic given `iv.len() >= 4`, last 4 bytes = big-endian sequence number, prefix unchanged. `body_aad`: output = `message_id ‖ content ‖ seq_be(4) ‖ len_be(8)`, length exact. Plus `u32_be`/`u64_be` helpers. |
| `edk_count_proofs.rs` | 4 | VR-007 | `validate_max_encrypted_data_keys`: returns `Ok` **iff** EDK count `> 0` and (if a max is set) `<= max`; empty and over-max rejected; no panic. Three boundary lemmas. |
| `zeroize_proofs.rs` | 4 | VR-010 | `PlaintextDataKey::zeroize`: no panic; buffer **fully zeroed** on return (no key bytes remain). Modeled via safe indexed writes (see caveats). |
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
| VR-003 header parsing safety | **fully verified in the model**: decisions + fixed-field header loop + EDK sub-parser + AAD/encryption-context sub-parser | binding to the in-crate readers (the migration) |
| VR-004 frame sequence validation | state machine **+ end-to-end framed-decrypt body loop** verified (in the model) | binding to the in-crate `body_decrypt` |
| VR-005 frame construction/serialization | byte layout **+ end-to-end read loop** verified (in the model) | write-side trait-object release + FFI ciphertext values |
| VR-002 header auth tag ordering | **control-flow ordering verified** (in the model): body decrypt unreachable without a verified header tag | the AES-GCM tag check itself (aws-lc-rs FFI); binding to in-crate `internal_decrypt` |
| VR-006 AES-GCM panic freedom | **buffer bookkeeping / length guard verified** (in the model): encrypt slice always in-bounds, decrypt rejects under-sized output buffer | the AES-GCM crypto itself (aws-lc-rs `seal`/`open`, FFI) — inherently out of scope |
| VR-007 EDK count validation | count-check logic verified | the "before any KMS call" ordering (caller-side in `decrypt.rs`) |
| VR-010 key-material zeroization | computation verified | the `unsafe write_volatile` form + volatile/`ptr.add` equivalence |
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

- **Models, not in-crate `verus!` blocks.** If the source functions change, the models must be updated in lockstep. The intended end state is to migrate them in-crate so proofs bind to the shipped code.
- **`to_be_bytes` / `copy_from_slice` equivalence** (in `body_aad_proofs.rs`): the model uses the equivalent primitive; the one-line equivalence to std is documented, not machine-checked.
- **`zeroize` unsafe form**: Verus's `Vec` model doesn't expose the raw-pointer `PointsTo` permissions, so the proof covers the equivalent safe indexed-write loop; the `volatile` qualifier and `ptr.add(i)`-in-bounds equivalence are argued informally.
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
frame-sequence loop, are superseded by the in-crate cores. The final-frame
sequence check and the start-at-1 invariant remain model-only (possibly stale);
its read loops and EC sub-parser are possibly stale against
the async readers, and EC parsing has moved to MPL
(`EncryptionContext::from_bytes`). The models are kept for now.

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

**Not modified by the standalone models:** any file under `esdk/`, `prim/`, `mpl/`, `unsafe-unreviewed-mpl/`.

**In-crate proofs (branch `verus-in-crate-esdk`):** `esdk/Cargo.toml`,
`esdk/Cargo.lock`, `esdk/Makefile`, `esdk/src/message/serialize_functions.rs`,
`header_types.rs`, `v1_header_body.rs`, `header.rs`, `encrypted_data_keys.rs`,
`body/body_decrypt.rs`.
