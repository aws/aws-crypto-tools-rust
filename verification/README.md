# Verus Formal Verification for the AWS ESDK (Rust)

This directory holds [Verus](https://github.com/verus-lang/verus) proofs for the
AWS Encryption SDK Rust implementation, following the pipeline in
`.kiro/agents/ai-verification-pipeline.md` and the target prioritization in
`docs/verification-recommendations.md`.

## Why a separate directory (not `verus!` inside `esdk/`)

The `esdk` crate depends on `aws-lc-rs`, `tokio`, `aws-sdk-kms`, and trait
objects (`SafeRead`/`SafeWrite`) that Verus cannot currently build or model.
Running Verus over the whole crate is therefore not yet possible.

Instead, each proof file here is a **faithful, self-contained Verus model** of a
specific pure function in the ESDK, carrying the *exact same executable body*
as the source, plus `requires`/`ensures` contracts. The proof establishes
panic-freedom and functional correctness for that body. Where a function's real
signature uses a helper Verus cannot see (e.g. `<[u8]>::copy_from_slice`,
`u32::to_be_bytes`), the model uses the equivalent primitive operation and the
file documents the one-line equivalence to the std API.

This is the honest, incremental approach: it does not weaken any proof, and it
does not hide any executable logic from the verifier (Verus skill invariants
#1, #10, #11). As the ESDK grows Verus-friendly seams, these models can be
migrated to `verus!` blocks in-crate.

## What is proven today

| File | Source function | Property proven |
|------|-----------------|-----------------|
| `body_aad_proofs.rs` | `iv_seq` (`esdk/src/message/body/body_aad.rs`) | No panic given `iv.len() >= 4`; last 4 bytes are the big-endian sequence number; prefix unchanged. |
| `body_aad_proofs.rs` | `body_aad` byte layout (`esdk/src/message/body/body_aad.rs`) | No panic; output is exactly `message_id ‖ content_str ‖ seq_be(4) ‖ len_be(8)`; length is `message_id.len() + content_str.len() + 12`. |
| `edk_count_proofs.rs` | `validate_max_encrypted_data_keys` (`esdk/src/message/header.rs`) | No panic; returns `Ok` **iff** the EDK count is `> 0` and (if a maximum is configured) `<= max`. Rejects empty lists and over-max counts. |
| `zeroize_proofs.rs` | `PlaintextDataKey::zeroize` (`mpl/src/structures/algorithm_suite.rs`) | No panic (all writes in bounds, length unchanged) and, on return, the buffer is **fully zeroed** — no key bytes remain. Modeled as safe indexed writes; see the scope note below. |
| `frame_layout_proofs.rs` | `construct_frame` frame assembly (`esdk/src/message/body/body_encrypt.rs`) | No panic; the `frame_buf` is assembled with exactly the spec fields in order — regular: `seq(4) ‖ iv ‖ ct‖tag`; final: `FFFFFFFF(4) ‖ seq(4) ‖ iv ‖ enc_content_len(4) ‖ ct‖tag`. Completes VR-005 for the byte-layout seam; see the scope note below. |
| `header_parse_proofs.rs` | Header-field decisions: `read_msg_format_version`, `read_content_type`, `read_msg_type` (`esdk/src/message/header_types.rs`); bounded readers `read_seq_u32/u64_bounded` (`esdk/src/message/serialize_functions.rs`) | Total (no panic) parse decisions: a byte is accepted **iff** it is a spec-supported version / content-type / message-type, with the correct variant; over-limit length fields are rejected before they size any read/allocation. Covers VR-003 for the pure decision logic; see the scope note below. |
| `frame_sequence_proofs.rs` | Frame sequence-number validation in `read_and_decrypt_framed_message_body` (`esdk/src/message/body/body_decrypt.rs`) | Regular/final frames accepted **iff** the sequence number equals the running `expected` (strictly sequential, starting at 1, no gaps/repeats/reordering); the `expected += 1` increment never overflows; total (no panic). Covers VR-004 for the sequence state machine; see the scope note below. |
| `io_stream_model.rs` | **Prototype** Verus abstraction for `SafeRead`/`SafeWrite` (`esdk/src/types.rs`) + the field readers built on it | A `ByteReader` (byte sequence + cursor, with a type invariant) whose `read_exact`/`read_u32` are total (EOF → `None`, never panic), advance the cursor exactly, and return spec-correct values; a `write_all` append contract; and — the payoff — a **read loop** (`read_and_validate_seq_run`) verified **end-to-end** that reads sequence numbers *from the stream* and enforces strict sequential ordering. Unblocks loop-level VR-003/004/005 and eventually VR-001/002. See the section below. |
| `io_stream_aligned.rs` | **Prototype (aligned)** — the `ByteReader` reshaped to the *exact* `serialize_functions` reader signatures, **plus the end-to-end V1 header parse loop** | The full reader family — `read_vec` / `read_u8` / `read_u16` / `read_u32` / `read_opt_u8` / `read_seq_u32_bounded` — returning `Result<T, SerErr>` (EOF → `Err`, matching the real readers; `read_opt_u8` → `Ok(None)`), each mirroring consumed bytes into a `raw: &mut Vec<u8>` (proven `raw' == raw ++ consumed`), plus four end-to-end loops: `read_v1_header_tail` (Content Type ‖ Reserved ‖ IV Length ‖ Frame Length) — **total**, **rejects malformed input** with `Err`, `raw` mirror exact (VR-003) — `read_and_decrypt_framed_body`, the framed-decrypt body loop, proven **total, strictly sequential from 1, overflow-free, and terminating** (VR-004/VR-005) — the **EDK list sub-parser** (`read_edks`) proven **total, rejecting `count == 0`/`count > max` before iterating, terminating** (VR-003) — and the **AAD/encryption-context sub-parser** (`read_canonical_ec`/`read_str_u16`/`read_ec_pairs`) proven **total, empty-EC short-circuit, non-UTF-8 rejected, pair loop terminating** (VR-003, the last variable-length header sub-parser). This is also the drop-in contract for an in-crate migration. See the section below. |
| `header_auth_ordering_proofs.rs` | The `internal_decrypt` control flow (`esdk/src/decrypt.rs`) | Models the 5-step decrypt pipeline as a phase state machine and proves the **ordering** property (VR-002): `step_decrypt_body` requires `phase == HeaderVerified`, whose only producer is a successful header-tag verification — so **no frame is decrypted unless the header auth tag verified first**, and a tag failure halts before body decryption. Control-flow proof (independent of the AES-GCM check itself, which is aws-lc-rs). |
| `aes_gcm_bounds_proofs.rs` | The buffer bookkeeping of `aes_encrypt`/`aes_decrypt` (`prim/src/lib.rs`) | Proves the **non-FFI** panic-freedom (VR-006 partial): the `aes_encrypt` `cipher_text[old_size..]` slice is always in bounds (never panics), length effects tracked exactly; the `aes_decrypt` length guard always rejects an under-sized output buffer before the aws-lc-rs gather. The AES-GCM crypto itself (`seal_in_place_separate_tag`/`open_separate_gather`) is FFI and out of Verus scope. |

Traces to threat-model threats T2/T3 (frame reordering/splicing via AAD),
D1/D2/D3 (framing bounds and excessive-EDK DoS), I1/I5 (key material leaked /
persisting in memory), and verification-recommendations targets VR-005, VR-007,
and VR-010.

### Scope note for `zeroize_proofs.rs` (unsafe `write_volatile`)

The source `zeroize` writes each byte with
`core::ptr::write_volatile(ptr.add(i), 0)` inside `unsafe`. The `volatile`
qualifier is an *operational* guard against dead-store elimination (the Vec is
about to drop), not a functional or memory-safety property. Verus's raw-pointer
model needs `PointsTo` permission tokens that a normally-constructed `Vec<u8>`
does not expose, so the `unsafe` form is not tractable to verify here without
reconstructing the allocation-permission story. Rather than fake it with
`assume`/`external_body` (forbidden), the proof establishes the loop's
*computational* content — every access in bounds, and all bytes zero on return —
via the equivalent **safe** indexed-write loop over the same `Vec<u8>`. The one
remaining informal (not machine-checked) step is that `ptr.add(i)` for
`i in 0..len` is in bounds, which holds because `len == self.0.len()` is the
loop bound. This is stated explicitly in the file header.

### Scope note for `frame_layout_proofs.rs` (trait-object I/O + FFI)

`construct_frame`'s real body writes into a `frame_buf: &mut Vec<u8>` **and** a
`dyn SafeWrite` (`std::io::Write`) trait object, and calls `aes_encrypt` (an
`aws-lc-rs` FFI). Verus cannot model `dyn SafeWrite`/`std::io::Write` or the
FFI. The proof therefore verifies the part `construct_frame` controls — the
**byte layout assembled into `frame_buf`**: the `write_u32`/`write_bytes` field
serialization is modeled as the `Vec` extends they are, and `aes_encrypt`'s
effect is modeled by its documented **length contract** (it appends
`ciphertext ‖ tag`, `ciphertext.len() == plaintext.len()`, fixed `tag_len`) with
the FFI output bytes supplied as a real `&[u8]` argument — no `external_body`,
no `assume`. What is proven: correct fields, correct order, correct sizes, no
panic, for both regular and final frames (verified genuine via a field-order
mutation test). What is out of Verus scope here: the trait-object release
(`write_bytes(ciphertext, …)` / `sig_digest`) and the ciphertext byte *values*
(FFI). Documented in the file header.

### Scope note for `header_parse_proofs.rs` (trait-object read seam)

The real `read_*` header parsers do `let x = read_u8(r, raw)?;` from a
`dyn SafeRead` (`std::io::Read`) trait object, then `match` on `x`. Verus cannot
model the trait-object read, so the proofs model the **decision** part: given
the byte/length value that was read, they prove the accept/reject outcome
matches the spec exactly (accept **iff** supported, correct variant, total — no
panic), and that the bounded readers reject an over-limit length before it sizes
any read or allocation. The trait-object read itself is out of Verus scope, as
for the other files. Genuineness was checked with a mutation test (accepting a
wrong byte as V1 fails verification).

### Scope note for `frame_sequence_proofs.rs` (trait-object read seam)

The real framed-decrypt loop reads each 4-byte sequence number from a
`dyn SafeRead` (`std::io::Read`) trait object, then compares it to a running
`expected_frame: u32` (initialized to `1`) and increments it. Verus cannot model
the trait-object read, so the proof models the **state machine** over
`expected_frame`: given the sequence number that was read, it proves the
accept/reject decision (strictly sequential, starting at 1, no gaps/repeats/
reordering), that the `+= 1` increment never overflows (the final-frame marker
`0xFFFFFFFF` terminates the loop before `expected` can reach `u32::MAX` — this
is the modeled precondition), and that the final-frame check enforces the same
ordering. The trait-object read is out of Verus scope. Genuineness confirmed via
a mutation test (removing the overflow-guard precondition makes Verus report a
possible-overflow error on the increment).

## The `io_stream_model.rs` prototype (enabling infrastructure)

The proofs above verify *decisions* (accept/reject a value) and *layouts*, but
each one stops at the `dyn SafeRead`/`dyn SafeWrite` trait-object boundary: the
read/write **loops** that drive those decisions were out of scope. This
prototype removes that boundary.

**The insight:** the ESDK only ever uses two operations on those traits —
`read_exact(buf)` (fill fully or EOF-error) and `write_all(data)` (append). So
we model the *stream contract*, not `std::io`:

- `ByteReader` — a byte `Seq<u8>` plus a cursor, with a `#[verifier::type_invariant]`
  (`cursor <= len`) that ties the exec state to the spec state. `read_exact(n)`
  succeeds **iff** `cursor + n <= len`, returns the next `n` bytes, and advances
  the cursor; on EOF it returns `None` with the cursor unchanged. It is **total**
  — never panics. `read_u32` is built on it and proven to return the big-endian
  value and advance by 4.
- `write_all` — the append contract (`Vec<u8>` already models a writer in Verus).

**The payoff** is `read_and_validate_seq_run`: a real read-and-validate **loop**
that reads sequence numbers *from the stream* and enforces strict sequential
ordering from 1, proven panic-free with an overflow-guarded counter — i.e. VR-004
verified end-to-end, composing the I/O seam with the sequence check that
`frame_sequence_proofs.rs` could only prove in isolation.

**Why this is a faithful contract, not a fake:** `read_exact` on a real
`std::io::Read` either fills the buffer (`Ok`) or fails with `UnexpectedEof` —
exactly the `cursor + n <= len` dichotomy modeled here. Nothing uses `assume` /
`external_body` / `admit`. When the ESDK read/write functions are migrated
in-crate, `ByteReader`/`write_all` are the abstraction their `requires`/`ensures`
would be written against. Genuineness was checked with a mutation test
(weakening the `read_exact` bound check so it could read past EOF makes Verus
report an out-of-bounds error).

**Status:** prototype, in two stages.

- `io_stream_model.rs` — the minimal proof of the idea (`Option`-returning `read_exact`, the end-to-end loop payoff).
- `io_stream_aligned.rs` — **DONE:** the `ByteReader` contract reshaped to the *exact* `serialize_functions` reader shape: readers return `Result<T, SerErr>` (EOF → `Err`, as the real code does), each takes a `raw: &mut Vec<u8>` mirror that receives the consumed bytes (the real `raw: &mut dyn SafeWrite` used to reconstruct the authenticated header), and the bounded reader rejects an over-limit length *before* reading the payload. `read_u16`/`read_u32` are proven to equal the big-endian byte assembly (`u16/u32::from_be_bytes`). The end-to-end `read_seq_u16` proves a length-prefixed field read keeps the `raw` mirror exact.

**Remaining (the actual in-crate migration — a larger, source-touching change):**
replace the bodies of `serialize_functions::{read_bytes,read_vec,read_u8,read_u16,
read_u32,read_u64,read_opt_u8,read_seq_*}` with a `verus!`-wrapped `ByteReader`
implementation carrying these `requires`/`ensures`, so the proofs bind to the
shipped readers instead of a mirror. That step needs the `esdk` crate to become
Verus-buildable at the `serialize_functions` seam (isolating it from the
`aws-lc-rs`/`tokio`/trait-object dependencies), which is why it is tracked
separately from these additive proof files.

## Running the proofs

Requires Verus installed at `~/verus/verus` (see the `verus` skill).

```bash
# From the repo root:
make -C verification verify
# or directly:
~/verus/verus verification/body_aad_proofs.rs
```

Success prints `verification results:: N verified, 0 errors`.
