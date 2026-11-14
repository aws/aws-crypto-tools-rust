# Verus Formal Verification for the AWS ESDK (Rust)

This directory holds [Verus](https://github.com/verus-lang/verus) proofs for the
AWS Encryption SDK Rust implementation, following the pipeline in
`.kiro/agents/ai-verification-pipeline.md` and the target prioritization in
`docs/verification-recommendations.md`.

## In-crate proofs (shipped `esdk` code)

Shipped `esdk` code is now verified in place with `cargo-verus`. Pure
synchronous cores sit inside `verus! { }` blocks in `esdk/src/`, and the async
readers (over `&mut dyn Source`, mirroring into `&mut Tee`) are thin
**unverified** adapters that call them. `cargo-verus` builds the dependencies
with plain rustc and verifies only `esdk`. Run from the repo root:

```bash
make -C esdk verus
```

It verifies `vstd` first (`1858 verified, 0 errors`, cached after the first
run); the `aws-esdk` result is the second `verification results::` line.
Current output for both runs (default, and
`--no-default-features --features aws-lc-sys`):

```
verification results:: 57 verified, 0 errors
verification results:: 57 verified, 0 errors
```

The count is Verus's obligation count, not a function count; the checked
fns are 34 exec fns (13 before the in-crate work, 22 before VR-009, 24 before
VR-011) and 3 proof fns. The verified fns (each inside a `verus!` block; paths
are under `esdk/src/message/` unless they start with `esdk/src/`):

| File | Fn | Property proven |
|---|---|---|
| `esdk/src/secret.rs` | `DataKeyRef::len`, `MessageKey::len`, `PublicBytes::len` | `n == self.view().len()` (key lengths are public). VR-011. |
| `esdk/src/secret.rs` | `MessageKey::zeroed`, `CommitmentValue::zeroed` (and private `zero_vec`) | The view is `len` zero bytes; the key derivation adapters then fill it. VR-011. |
| `esdk/src/secret.rs` | `CommitmentValue::as_suite_data` | Declassification (decrypt side): `s@ == self.view()`. VR-011. |
| `esdk/src/secret.rs` | `PublicBytes::from_commitment` (and private `copy_vec`) | Declassification (encrypt side): `p.view() == c.view()` and `p.is_public()`. VR-011. |
| `esdk/src/secret.rs` | `PublicBytes::into_vec`; type invariant `PublicBytes::inv` | `v@ == self.view()`; every `PublicBytes` is labelled `Label::Public`. VR-011. |
| `esdk/src/key_derivation.rs` | `identity_kdf_key_len_ok` (called by `derive_key_v1`) | True iff the identity-KDF plaintext data key length equals the suite encryption key length. VR-009. |
| `esdk/src/key_derivation.rs` | `check_v2_key_lengths` (called by `derive_key_v2`) | `Ok` iff the KDF is not the identity KDF, the message ID is `MESSAGE_ID_LEN_V2` (32) bytes and the plaintext key length equals the suite key length; `Ok(n)` has `n` equal to both (it sizes the derived encryption key); each `Err` variant fires exactly when its check is the first to fail (identity KDF, then message ID, then key length). VR-009. |
| `serialize_functions.rs` | `be_u16`, `be_u32`, `be_u64` | Result equals the big-endian value of the bytes (`spec_be_u16/u32/u64`). |
| `serialize_functions.rs` | `next_chunk_end` | Given `start < length`: `start < end <= length` and `end - start <= READ_CHUNK` (1 MiB). |
| `serialize_functions.rs` | `bounded_len_u32`, `bounded_len_u64` | `OverBound` iff `len > bound`; `Ok(n)` iff within bound and fits in `usize`, with `n == len`; `TooLargeForPlatform` otherwise. |
| `header_types.rs` | `msg_format_version_from_u8`, `msg_type_from_u8`, `content_type_from_u8` | `Some(variant)` iff the byte is the spec value for that variant; `None` for every other byte. |
| `v1_header_body.rs` | `reserved_bytes_ok` | True iff all four reserved bytes are 0. |
| `v1_header_body.rs` | `iv_len_matches` | True iff the header IV length equals the suite's IV length. |
| `header.rs` | `edk_count_check` | `Empty` iff count is 0; `OverMax` iff count > 0 and above a configured max; `Ok` otherwise. |
| `body/body_decrypt.rs` | `next_expected_frame` | `Some` iff `seq_num == expected` and `expected < u32::MAX`; then the value is `expected + 1`; `r == spec_next_expected_frame(seq_num, expected)`. |
| `serialize_functions.rs` | `u32_to_be`, `u64_to_be` (and private `low_byte`) | Result is the big-endian encoding `spec_u32_to_be` / `spec_u64_to_be` (equal to `to_be_bytes()`, which vstd does not model; a unit test checks the equality). |
| `body/body_aad.rs` | `body_aad_content_type_string` | Its bytes are `spec_body_aad_content(bc)`: the bytes of the const for `bc`. |
| `body/body_aad.rs` | `iv_seq_core` (called by `iv_seq`) | Given `len >= 4`: the last 4 bytes become `spec_u32_to_be(sequence_number)`; the bytes before them are unchanged. |
| `body/body_aad.rs` | `body_aad_core` (called by `body_aad`) | Result is exactly `message_id ‖ content bytes ‖ spec_u32_to_be(seq) ‖ spec_u64_to_be(length)`. |
| `body/body_decrypt.rs` | `final_frame_seq_ok` | True iff the final frame's sequence number equals the expected one. Used by the final-frame check. |
| `body/body_decrypt.rs` | proof fn `lemma_accepts_run` | A run of regular frames that `next_expected_frame` accepts from `expected` is numbered `expected, expected + 1, …`, and the next expected number is `expected` plus the run length. |
| `body/body_decrypt.rs` | proof fn `lemma_frames_start_at_1` | From `START_SEQUENCE_NUMBER` (1): regular frame `i` (0-based) has number `i + 1`, and the accepted final frame number equals the total frame count. |
| `header_types.rs` | `classify_version_byte` (called by `read_msg_format_version`) | `Supported(V1)` iff `b == 1`; `Supported(V2)` iff `b == 2`; `Base64Hint` iff `b == 0x41`; `Unsupported` otherwise. |
| `body/body_encrypt.rs` | `write_frame_prefix` (called by `construct_frame`) | Appends exactly `spec_frame_prefix`: regular `seq ‖ iv`; final `FFFFFFFF ‖ seq ‖ iv ‖ enc_content_len`. |
| `body/body_encrypt.rs` | proof fn `lemma_endframe_bytes` | `spec_u32_to_be(ENDFRAME_SEQUENCE_NUMBER)` is the bytes `FF FF FF FF`. |

`START_SEQUENCE_NUMBER`, `ENDFRAME_SEQUENCE_NUMBER` (`header.rs`),
`BodyAADContent` with its three content strings (`body_aad.rs`),
`MESSAGE_ID_LEN_V1` / `MESSAGE_ID_LEN_V2` (`header_types.rs`) and
`V2KeyLenError` (`key_derivation.rs`), and the ghost `Label` enum with the
`DataKeyRef`, `MessageKey`, `CommitmentValue` and `PublicBytes` types
(`esdk/src/secret.rs`) are also inside `verus!`, so the proofs use the shipped
definitions. `derive_keys` dispatches on the verified
`msg_format_version_from_u8` (V1 iff the suite's version byte is 1, V2 iff 2,
an error otherwise).

### VR-009 (HKDF / key-derivation lengths): esdk half proven, prim half not

Proven in-crate: the length checks in `esdk/src/key_derivation.rs` listed
above. They are total (no panic; they do no arithmetic, so no overflow), and
their `ensures` state exactly which inputs are accepted and, for V2, which
check rejects, in the order the code runs them. `derive_key_v1`,
`derive_key_v2` and `derive_keys` are the unverified adapters: they read the
lengths from the MPL `AlgorithmSuite` and the slices, call the cores, build the
`Error`s (same kinds and messages as before), allocate the buffers and call
HKDF. Not proven:

- **The prim side** (`prim/src/hkdf.rs`, including `get_len`, and the
  aws-lc-rs `hkdf` / `hkdf_extract` / `hkdf_expand`). Verus is not enabled in
  `prim`, by decision. The HKDF primitive, including its output-length limit,
  is a trust boundary.
- **Buffer sizes read straight from the suite.** The V1 output length
  (`encryption_key_length()`) and the V2 commit-key length
  (`algorithm_suite_data_length()`) are MPL getters used directly by
  `MessageKey::zeroed(n)` / `CommitmentValue::zeroed(n)` in the adapters
  (Verus proves only that these return `n` zero bytes, not that `n` is right);
  `mpl` is not Verus-checked. Only the V2
  encryption-key buffer goes through a verified core (`check_v2_key_lengths`'s
  `Ok(n)`).
- **The V1 HKDF salt length** (`digest_length`: SHA-256/384/512 → 32/48/64).
  It matches on `aws_mpl_primitives::DigestAlg`, a `prim` enum Verus does not
  see; modelling it would need an external type specification (a trusted
  assumption), so the table is left unverified and covered by the existing
  key-derivation tests.
- **The `debug_assert!`s** in `derive_keys`, `derive_key_v1` and
  `derive_key_v2` (non-empty message ID, key length equals the suite length,
  message version) are debug-build-only caller checks outside `verus!`; they do
  not run in release builds.

### VR-011 (data-key non-disclosure): confinement, not a Verus proof

VR-011 is **not Verus-proven**. The guarantee on branch `vr011-confinement` is
confinement: esdk code outside `esdk/src/secret.rs` cannot read the bytes of
the plaintext data key (`DataKeyRef`) or of the derived message key
(`MessageKey`). That is checked by the Rust compiler (private fields; no
`Clone`, `PartialEq` or `Debug` on the secret types) and by clippy
(`esdk/clippy.toml` bans esdk's calls to the mpl data-key accessors outside
the two ingress adapters). Verus checks only the `secret.rs` rows in the table
above: each accessor's `ensures` against the closed `view()`, and the
`PublicBytes` label invariant. The V2 commitment value is public by spec (it
is the header suite data); `as_suite_data` and `from_commitment` are its two
declassification points.

Trusted, unverified (TB-A, outside `verus!` in `secret.rs`):
`data_key_from_encryption_materials`, `data_key_from_decryption_materials`,
`identity_copy`, `hkdf_v1`, `hkdf_v2_extract`, `hkdf_v2_expand_key`,
`hkdf_v2_expand_commitment`, `seal`, `open`. Also trusted: aws-lc-rs (through
`aws-mpl-primitives`), keyrings and CMMs, and the mpl key types. Not checked by
any tool: that `key_derivation.rs` passes the HKDF PRK only to the `secret.rs`
expand adapters (grep only). Not done: a verified encrypt/decrypt flow (plan
step 7). Full record: VR-2026-011 in `docs/verification-recommendations.md`.

### Properties that stay model-only, and why

- **Loop threading for the frame sequence.** The lemmas above describe the
  framed-decrypt loop, but `read_and_decrypt_framed_message_body` is an async
  fn over `dyn Source`: that it starts `expected_frame` at
  `START_SEQUENCE_NUMBER` and feeds each `next_expected_frame` result into the
  next iteration is unverified glue, checked by tests.
- **Header-auth ordering (verify before decrypt),**
  `header_auth_ordering_proofs.rs`. The order is the sequence of `.await?`
  calls in the async `decrypt_steps` (`esdk/src/decrypt.rs`), and "verified" is
  the `Result` of the aws-lc-rs tag check. Verus cannot verify async fns, and a
  sync core would only prove `Ok ⇒ Ok`. The model was re-audited against the
  current order (parse → materials → verify header → decrypt body → verify
  signature → release last frame) and matches.
- **EDK list loop,** `io_stream_aligned.rs::read_edks`. The count decision is
  in-crate (`edk_count_check`); what is left is a `for` loop of `.await?` reads
  over `dyn Source` and the MPL `EncryptedDataKey` builder. No sync decision
  logic is left to extract.
- **Encryption-context (AAD) parser,** `io_stream_aligned.rs`. Obsolete: the
  parsing moved to MPL (`EncryptionContext::from_bytes`), outside this ESDK
  scope; esdk only reads a `u16` length and the bytes.
- **Frame ciphertext ‖ tag,** `frame_layout_proofs.rs`. `aes_encrypt`
  (`aws-mpl-primitives`, aws-lc-rs FFI) appends them, and the frame is released
  through `dyn Sink` / `DigestWriter`; neither is verifiable from esdk.
- **AES-GCM buffer bounds,** `aes_gcm_bounds_proofs.rs`. The code is in `prim`,
  which `make -C esdk verus` builds with plain rustc. Verifying it in place
  would add `vstd` and Verus metadata to the published `aws-mpl-primitives`
  crate, which this work does not do. The model was re-audited against
  `prim/src/lib.rs` and matches.
- **Zeroization,** `zeroize_proofs.rs`: unchanged, deferred; out of scope for
  this work. It models a `write_volatile` loop that was removed in `a864ad87`;
  the current `zeroize`-crate derive is not verified.

There is no standalone model for VR-009; it was done in-crate directly.

The full list, VR targets and trusted boundaries are in
`docs/verus-proofs-report.md` ("In-crate proofs").

## The standalone models in this directory

Each proof file here is a **faithful, self-contained Verus model** of a
specific function in the ESDK, carrying the executable body as it was when the
model was written, plus `requires`/`ensures` contracts. They were written
before the in-crate seam existed. They import nothing from `esdk`, so they can
drift from the shipped code. **All 10 models are kept** (none removed), and
`make -C verification verify` still checks them.

| File | Status |
|------|--------|
| `body_aad_proofs.rs` | Superseded in-crate by `iv_seq_core` / `body_aad_core` (`body/body_aad.rs`). |
| `edk_count_proofs.rs` | Superseded in-crate by `edk_count_check` (`header.rs`). |
| `zeroize_proofs.rs` | Unchanged, deferred; out of scope for this work. It models code that no longer exists: the hand-written `write_volatile` loop in `PlaintextDataKey::zeroize` was removed in `a864ad87` (#131), and `PlaintextDataKey`, `SigningKey` and `SymmetricSigningKey` now `#[derive(Zeroize, ZeroizeOnDrop)]`. The current zeroization is not verified. |
| `frame_layout_proofs.rs` | Superseded in-crate for the prefix layout by `write_frame_prefix` (`body/body_encrypt.rs`); the `ct ‖ tag` append (by `aes_encrypt`) remains model-only. |
| `header_parse_proofs.rs` | Superseded in-crate: header-field decisions (`*_from_u8`), the 0x41 Base64 hint (`classify_version_byte`) and bounded readers (`bounded_len_u32/u64`). |
| `frame_sequence_proofs.rs` | Superseded in-crate: the regular-frame step (`next_expected_frame`), the final-frame check (`final_frame_seq_ok`) and the start-at-1 / sequential-run lemmas (`lemma_frames_start_at_1`, `lemma_accepts_run`), all in `body_decrypt.rs`. The async loop that threads `expected_frame` is unverified glue. |
| `io_stream_model.rs` | Possibly stale: the readers are now async over `dyn Source`, `read_into_vec` reads in chunks, and EC parsing moved to MPL. |
| `io_stream_aligned.rs` | Superseded in-crate: bounded readers, big-endian decoding, header-field and EDK-count checks, the regular- and final-frame sequence checks and start-at-1. Model-only: the EDK list loop (`read_edks`; an async loop over `dyn Source`). Obsolete: the EC sub-parser (parsing is now in MPL). The `ByteReader` loops are possibly stale for the same reasons as `io_stream_model.rs`. |
| `header_auth_ordering_proofs.rs` | Model-only, re-audited against the current `decrypt_steps` (`esdk/src/decrypt.rs`): the ordering lives in an async fn and the tag check is aws-lc-rs. |
| `aes_gcm_bounds_proofs.rs` | Model-only, re-audited against `prim/src/lib.rs`: the code is in `prim`, which is not Verus-checked. |

"Possibly stale" means the model still verifies but its body was not
re-checked against the current source. The historical notes below describe the
models as written and still refer to the old `SafeRead`/`SafeWrite` traits.

## What the models prove (as written)

| File | Source function | Property proven |
|------|-----------------|-----------------|
| `body_aad_proofs.rs` | `iv_seq` (`esdk/src/message/body/body_aad.rs`) | No panic given `iv.len() >= 4`; last 4 bytes are the big-endian sequence number; prefix unchanged. |
| `body_aad_proofs.rs` | `body_aad` byte layout (`esdk/src/message/body/body_aad.rs`) | No panic; output is exactly `message_id ‖ content_str ‖ seq_be(4) ‖ len_be(8)`; length is `message_id.len() + content_str.len() + 12`. |
| `edk_count_proofs.rs` | `validate_max_encrypted_data_keys` (`esdk/src/message/header.rs`) | No panic; returns `Ok` **iff** the EDK count is `> 0` and (if a maximum is configured) `<= max`. Rejects empty lists and over-max counts. |
| `zeroize_proofs.rs` | `PlaintextDataKey::zeroize` (`mpl/src/structures/algorithm_suite.rs`; the hand-written loop was removed in `a864ad87`) | No panic (all writes in bounds, length unchanged) and, on return, the buffer is **fully zeroed** — no key bytes remain. Modeled as safe indexed writes; see the scope note below. |
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

*History: this note describes the source as it was when the model was written.
The loop was removed in `a864ad87` (#131); the model is deferred and unchanged.*

The source `zeroize` wrote each byte with
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

**Remaining, as planned then (history):** *the in-crate migration was done
differently: the readers became async over `dyn Source`, and the decision cores
were verified in-crate instead (see "In-crate proofs" above). The original plan
follows.* Replace the bodies of `serialize_functions::{read_bytes,read_vec,read_u8,read_u16,
read_u32,read_u64,read_opt_u8,read_seq_*}` with a `verus!`-wrapped `ByteReader`
implementation carrying these `requires`/`ensures`, so the proofs bind to the
shipped readers instead of a mirror. That step needs the `esdk` crate to become
Verus-buildable at the `serialize_functions` seam (isolating it from the
`aws-lc-rs`/`tokio`/trait-object dependencies), which is why it is tracked
separately from these additive proof files.

## Running the proofs

Requires Verus installed at `~/verus/verus` and `cargo-verus` at
`~/verus/cargo-verus` (see the `verus` skill).

```bash
# From the repo root. In-crate proofs (shipped esdk code):
make -C esdk verus
# Standalone models:
make -C verification verify
# or directly:
~/verus/verus verification/body_aad_proofs.rs
```

Success prints `verification results:: N verified, 0 errors`.
