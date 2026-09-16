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

### Adherence to the Verus skill invariants
- No proof was weakened: **no** `assume(...)`, `admit()`, or `#[verifier::external]` anywhere. There is exactly **one** `#[verifier::external_body]` — the `utf8_check` wrapper around `std::str::from_utf8` in the AAD sub-parser — used per Verus skill invariant #11 for a std call Verus cannot evaluate (the same role `tag_ok` plays for the AES-GCM check). Its `ensures` is a **trusted boundary, not a proof**: the UTF-8-validation correctness is delegated to the std library; everything around it (that the parser rejects non-UTF-8 with `Err`, never panics) is proven. This is called out explicitly in §5.
- Every "verified" claim is backed by actual `0 errors` tool output.
- Preconditions are satisfiable by real callers (not over-constrained).
- No `ensures` was changed to match buggy behavior.
- Load-bearing proofs were **mutation-tested** to confirm they are not vacuous.

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
| Infra: `SafeRead`/`SafeWrite` seam | prototyped + aligned | the in-crate migration (source-touching, needs a Verus-buildable seam) |

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

Because the `esdk` crate pulls in `aws-lc-rs`, `tokio`, and `SafeRead`/`SafeWrite`
trait objects that Verus cannot build, each proof is a **faithful, self-contained
model** of a specific function — the exact executable body plus `requires`/`ensures`.
Honest limits, all documented in the proof files and `verification/README.md`:

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

## 6. The `SafeRead`/`SafeWrite` abstraction (infrastructure)

The single most reusable result. The other proofs each stop at the trait-object
I/O boundary; this abstraction removes it. The ESDK only uses two operations on
those traits — `read_exact` (fill-or-EOF) and `write_all` (append) — so the
`ByteReader` models the **stream contract** (a byte `Seq<u8>` + cursor with a
type invariant), not `std::io`. `io_stream_aligned.rs` then matches the exact
`serialize_functions` reader signatures (`Result` returns, the `raw` byte
mirror, big-endian correctness, over-limit rejection), making it a **drop-in
contract**.

**Remaining in-crate migration** (a separate, source-touching effort): replace
the bodies of `serialize_functions::{read_bytes,read_vec,read_u8,read_u16,
read_u32,read_u64,read_opt_u8,read_seq_*}` with a `verus!`-wrapped `ByteReader`
implementation carrying these contracts, after isolating that module from the
`aws-lc-rs`/`tokio`/trait-object dependencies so Verus can build it. That binds
the proofs to the shipped readers and unblocks end-to-end VR-003/004/005 and,
ultimately, the highest-value VR-001 (key commitment) and VR-002 (header auth
ordering).

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

**Not modified:** any file under `esdk/`, `prim/`, `mpl/`, `unsafe-unreviewed-mpl/`.
