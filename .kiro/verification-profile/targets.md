# ESDK profile appendix: targets

Per-target detail, done lists, decision-aid rows, panic surface, the trusted aws-lc-rs boundary, do-not-redo lists and drift examples for the ESDK. Read with `.kiro/verification-profile/verification-profile.yaml` (`targets`, `do_not_redo`, `tcb`, `typestate_gates`). The live status of each target is in `docs/verus-proofs-report.md` §3 (profile `artifacts.status_oracle`); if this file and the report disagree, the report wins. Text under "Source:" lines is copied verbatim from the files at `4054fd89`. Bare file names in copied text are relative to `esdk/src/message/` or `prim/src/`, as the surrounding text says.

Counts are not kept here. Read them from the live output of each profile `crates[].verify_cmd` and `models.verify_cmd`.

## VR-001

Key commitment verification. (a) The accept/reject decision (`suite_data_check`, called from `validate_suite_data` in `esdk/src/message/header.rs`) is Verus-proven in-crate. (b) The order (commitment accepted before any frame is decrypted) is a Verus-proven gate with a compiler-enforced order (`CommitmentAccepted` in `esdk/src/decrypt_gate.rs`). (c) Constant time is trusted (aws-lc-rs). Status and residual: `docs/verus-proofs-report.md` §3.

## VR-002

Header auth tag ordering. `header_auth_gate` in `esdk/src/decrypt_gate.rs` returns a `HeaderVerified` token only when the header `open` returned `Ok`; the compiler enforces that the body cannot be decrypted without it. The adapter wiring is trusted; `verification/header_auth_ordering_proofs.rs` is superseded. Status and residual: `docs/verus-proofs-report.md` §3.

## VR-003

Header parsing safety. In-crate: big-endian decoding, bounded readers, header-field decisions, the 0x41 Base64 hint, reserved bytes, IV length. Model-only: the fixed-field header loop and the EDK list loop (`verification/io_stream_aligned.rs`). Status and residual: `docs/verus-proofs-report.md` §3.

## VR-004

Frame sequence validation. In-crate in `esdk/src/message/body/body_decrypt.rs`: `next_expected_frame`, `final_frame_seq_ok`, the start-at-1 and sequential-run lemmas. The async loop that threads `expected_frame` is unverified glue. Status and residual: `docs/verus-proofs-report.md` §3.

## VR-005

Frame construction and serialization. In-crate: body AAD layout (`body_aad_core`), IV (`iv_seq_core`), frame prefix (`write_frame_prefix`). Model-only: the `ct ‖ tag` append (`verification/frame_layout_proofs.rs`). Status and residual: `docs/verus-proofs-report.md` §3.

## VR-006

AES-GCM panic freedom in `prim/src/lib.rs`: `aes_encrypt_extend_core` (encrypt slice in bounds) and `aes_decrypt_len_ok` (decrypt length guard). The AES key length and IV validity are enforced inside aws-lc-rs (trusted). Status and residual: `docs/verus-proofs-report.md` §3.

## VR-007

EDK count validation. The count decision (`edk_count_check`, `esdk/src/message/header.rs`) is in-crate. The "before any KMS call" ordering is caller-side in `esdk/src/decrypt.rs` and is residual. Status and residual: `docs/verus-proofs-report.md` §3.

## VR-008

ECDSA fixed-length signing in `prim/src/ecdsa.rs`. `sign_fixed_len_core` holds the bounded retry loop inside `verus!` (`decreases MAX_SIGN_ATTEMPTS - attempt`) and the guarded `copy_from_slice` is proven in bounds. The signing closure and `Signature` type are trusted. Status and residual: `docs/verus-proofs-report.md` §3.

## VR-009

HKDF and key-derivation lengths, both halves in-crate. esdk half: `identity_kdf_key_len_ok`, `check_v2_key_lengths` (`esdk/src/key_derivation.rs`). prim half: `hkdf_key_len_ok`, `salt_size_core`, `no_salt_slice_core` (`prim/src/hkdf.rs`). The HKDF crypto is trusted. Status and residual: `docs/verus-proofs-report.md` §3.

## VR-010

Key-material zeroization. Deferred: `verification/zeroize_proofs.rs` models the hand-written `write_volatile` loop removed in `a864ad87`. Current zeroization is `#[derive(Zeroize, ZeroizeOnDrop)]` (trusted). Status and residual: `docs/verus-proofs-report.md` §3.

## VR-011

Data-key non-disclosure. Confinement to `esdk/src/secret.rs` is compiler- and clippy-checked, not Verus. Verus covers only the secret types' accessors and the commitment-value declassification. Status and residual: `docs/verus-proofs-report.md` §3.

## VR-012

Big-endian codec round-trip. `lemma_u32_round_trip` and `lemma_u64_round_trip` in `esdk/src/message/serialize_functions.rs` prove the verified encoders and decoders are exact inverses for `u32` and `u64`; u16 is decoder-only (see §Category 1c). Status and residual: `docs/verus-proofs-report.md` §3.

## VR-013

prim wrapper length contracts (implements pipeline target VR-2026-C03), in `prim/src/lib.rs` and `prim/src/ecdsa.rs`, against the trusted rows A1–A13 in `prim/src/aws_lc_specs.rs`. Status and residual: `docs/verus-proofs-report.md` §3.

## VR-014

AES buffer effects in `prim/src/lib.rs` (`aes_encrypt_core`, `aes_decrypt_core`). BUG-07(a) is proved; BUG-07(b) is recorded under the labeled assumption A-OPEN (A20), not fixed. Status and residual: `docs/verus-proofs-report.md` §3.

## VR-015

Final plaintext held until the signature verifies (threat R3): `SignatureVerified` and `HeldFinalPlaintext` in `esdk/src/decrypt_gate.rs`. VR-015 (b), signature presence matches the suite, uses `SignaturePresence` and `SignatureRequired`. Gates are Verus-proven; the order is compiler-enforced. Status and residual: `docs/verus-proofs-report.md` §3.

## VR-016

Decrypt buffer sizing (BUG-07(b) in esdk). `secret::open` takes only an `OpenBuffers`, built only by the verified `open_buffers` (`esdk/src/secret.rs`). The TB-A body of `secret::open` is trusted. Status and residual: `docs/verus-proofs-report.md` §3.

## VR-017

Encrypt body limits in `esdk/src/message/body/body_encrypt.rs`: `PlaintextBudget` (MAX_DATA) and `EncryptFrameSeq` (starts at 1, +1 per regular frame, never wraps). The async loop threading is unverified glue. Status and residual: `docs/verus-proofs-report.md` §3.

## VR-018

Encrypt header length checks in `esdk/src/encrypt.rs`: `check_v2_suite_data` and `data_key_len_ok`. The expected lengths come from MPL and a const table. Status and residual: `docs/verus-proofs-report.md` §3.

## VR-019

Encrypt signing-key check, one direction only: `signing_key_gate` and `SigningKeyPresent` in `esdk/src/encrypt_gate.rs`. Finding VR-019 F1: esdk rejects a missing key only in step 4. Status and residual: `docs/verus-proofs-report.md` §3.

## Repository grounding

Source: `.kiro/agents/verus-capabilities.md` §Repository grounding.

| Crate / item | Path | Verus status |
|--------------|------|--------------|
| `aws-esdk` | `esdk/src/` | **Verus-checked.** `[package.metadata.verus] verify = true`; only code inside `verus! { }` is verified. The typestate gate modules are `esdk/src/decrypt_gate.rs` (VR-001 (b), VR-002, VR-015) and `esdk/src/encrypt_gate.rs` (VR-019); `esdk/src/secret.rs` holds `OpenBuffers` (VR-016). |
| `aws-crypto-mpl` | `mpl/src/` | Dependency. Built by `cargo-verus` with plain rustc; not verified. Keyrings, CMMs, material types (`PlaintextDataKey`, `AlgorithmSuite`). |
| `aws-mpl-primitives` | `prim/src/` | **Verus-checked.** `[package.metadata.verus] verify = true`, `make -C prim verus`. `prim/src/ecdsa.rs` (VR-008: the `sign_fixed_len` retry loop with `decreases` and a bounds-proven copy; VR-013 `digest_finish_core`), `prim/src/lib.rs` (VR-006 buffer cores; VR-013 `digest_core`, `hmac_core` and the other wrapper cores; VR-014 `aes_encrypt_core` / `aes_decrypt_core`, which now make the aws-lc-rs AES calls inside `verus!`), `prim/src/hkdf.rs` (VR-009 prim half: `hkdf_key_len_ok`, `salt_size_core`, `no_salt_slice_core`). The trusted specs for aws-lc-rs are in `prim/src/aws_lc_specs.rs` (TCB rows T-ty, T-AsRef, T-uf, A1–A20; A20 is the labeled assumption A-OPEN). The `ExAsRef` trait spec there needs `#![cfg_attr(verus_keep_ghost, feature(sized_hierarchy))]` in `prim/src/lib.rs`. The crypto itself stays trusted. |
| C++ shim | `esdk/shims/aws-esdk-cpp/` | Not Verus-checked. Holds the only shipped-path `unsafe`. |
| Standalone models | `verification/` | Verus-checked models (`make -C verification verify`). |
| Spec | `spec/` at the repo root | Resolved by `scripts/resolve-spec.sh`; not a submodule and may be absent locally. The tracked documents are listed in `esdk/.duvet/config.toml` (`spec/data-format/*`, `spec/client-apis/*`, …). |
| Duvet annotations | `//=` / `//#` comments in `esdk/src` and `esdk/tests` | Requirement-to-code map. `type=test` means tested, not proven. |

Source: `.kiro/agents/verus-capabilities.md` §Repository grounding, "Reality check for this repo".

- **No `unsafe` in `esdk/src`, `mpl/src` or `prim/src`.** The only shipped-path `unsafe` is 4 expressions in `esdk/shims/aws-esdk-cpp/src/lib.rs` (`&*ptr` / `as_ref()` on C++-supplied handles). There are no raw `aws-lc-sys` calls, no `from_raw_parts`, no `set_len`.
- **Zeroization** comes from `#[derive(Zeroize, ZeroizeOnDrop)]` (the `zeroize` crate is trusted). The hand-written `write_volatile` loop was removed in `a864ad87`; the VR-010 model (`verification/zeroize_proofs.rs`) describes removed code and is deferred.
- The crypto boundary is aws-lc-rs's **safe** API, reached through `aws-mpl-primitives`.

## Category 1a

Source: `.kiro/agents/verus-capabilities.md` §1a. Pre-/postcondition adherence.

- **Done in-crate:** header-field decision cores (`msg_format_version_from_u8`, `msg_type_from_u8`, `content_type_from_u8`, `classify_version_byte`, `reserved_bytes_ok`, `iv_len_matches`; VR-003); `edk_count_check` (VR-007); `identity_kdf_key_len_ok`, `check_v2_key_lengths` (VR-009 esdk half); `hkdf_key_len_ok`, `salt_size_core`, `no_salt_slice_core` (VR-009 prim half, T3); the VR-008 (`prim/src/ecdsa.rs`) and VR-006 (`prim/src/lib.rs`) prim cores; the VR-013 prim wrapper length contracts (`digest_core`, `digest_finish_core`, `hmac_core`); the VR-014 AES buffer effects (`aes_encrypt_core`, `aes_decrypt_core`; BUG-07(a) proved, BUG-07(b) recorded under A-OPEN, not fixed); the VR-018 encrypt header length checks (`check_v2_suite_data`, `data_key_len_ok` in `esdk/src/encrypt.rs`).
- **Done in-crate (VR-001 (a)):** the key-commitment accept/reject decision (`suite_data_check`, called from `validate_suite_data` in `esdk/src/message/header.rs`). VR-001 (b), the order, is Category 1e. VR-001 (c), constant time, is trusted (aws-lc-rs); Verus does not model timing.

## Category 1b

Source: `.kiro/agents/verus-capabilities.md` §1b. Abstract behavioural refinement.

- **Done in-crate:** body AAD is exactly `message_id ‖ content ‖ seq_be(4) ‖ len_be(8)` (`body_aad_core`, `iv_seq_core`; VR-005); the `secret.rs` accessors against their closed `view()` and the `PublicBytes` label invariant (VR-011 Verus layer only).

## Category 1c

Source: `.kiro/agents/verus-capabilities.md` §1c. Round-trip parsing and serialization.

- **Done in-crate (VR-012):** `lemma_u32_round_trip` and `lemma_u64_round_trip` in `esdk/src/message/serialize_functions.rs` prove the verified big-endian encoders and decoders are exact inverses for `u32` and `u64`.
- **Encoder/decoder asymmetry — by design, not a bug.** The decoders exist for u16/u32/u64 (`spec_be_u16/32/64`, `be_u16/32/64`) but the hand-written big-endian *encoders* exist only for u32/u64 (`spec_u32_to_be`/`spec_u64_to_be`). This is deliberate, not a missing function: u16 values *are* written and read at runtime (`write_u16`/`read_u16`), but `write_u16`/`write_u32`/`write_u8` call `to_be_bytes()` directly and do not use the hand-written encoders. The `*_to_be` encoders were added only where a *proof* needed to reason about the bytes of a field — so far the body AAD's u32 sequence number and u64 content length (`body_aad.rs`), hence u32 and u64 only. No proof has needed to reason about the bytes of a written u16, so no `u16_to_be` was written. Consequence: the VR-012 round-trip lemma covers the u32 and u64 pairs that exist; u16 is decoder-only. Adding a `u16_to_be` + round-trip later would be a proof-coverage *completeness* improvement, not a bug fix.
- **Blocked:** a full header serialize/parse round-trip. It is a Vest-shaped property, but the parser and serializer are async over `dyn Source` / `dyn Sink`, so only sync sub-pieces are provable.

## Category 1d

Source: `.kiro/agents/verus-capabilities.md` §1d. State machine / algorithmic equivalence.

- **Done in-crate:** frame-sequence checks and lemmas (`next_expected_frame`, `final_frame_seq_ok`, `lemma_accepts_run`, `lemma_frames_start_at_1`; VR-004). The async loop that threads `expected_frame` is unverified glue.
- **Done in-crate (VR-017):** the encrypt-side frame counter `EncryptFrameSeq` in `esdk/src/message/body/body_encrypt.rs` (starts at 1, +1 per regular frame, never wraps).
- Header-auth ordering (VR-002) and commitment ordering (VR-001 (b)) used to be model-only here. They are now covered in shipped code by typestate tokens (Category 1e). The models `verification/header_auth_ordering_proofs.rs` and `verification/commitment_ordering_proofs.rs` are kept as history.

## Category 1e

Source: `.kiro/agents/verus-capabilities.md` §1e. Ordering via typestate tokens. The gate modules are also in profile `typestate_gates`.

- **Done in-crate:** `CommitmentAccepted` and `HeaderVerified` (VR-001 (b), VR-002), `SignaturePresence`, `SignatureRequired`, `SignatureVerified` and `HeldFinalPlaintext` (VR-015, VR-015 (b)) in `esdk/src/decrypt_gate.rs`; `OpenBuffers` (VR-016, the same token shape used for buffer sizing: `secret::open` takes only an `OpenBuffers`, built only by the verified `open_buffers`) in `esdk/src/secret.rs`; `SigningKeyPresent` (VR-019, one direction only; finding VR-019 F1) in `esdk/src/encrypt_gate.rs`.

Source: `.kiro/skills/verus/SKILL.md` §This repo (ESDK).

- Type-invariant chain example: `CommitmentAccepted` with `lemma_commitment_accepted`.

## Category 2

Source: `.kiro/agents/verus-capabilities.md` §2a. Slice and buffer bounds / 2b. arithmetic / 2c. division.

- **Done in-crate:** `bounded_len_u32`, `bounded_len_u64`, `next_chunk_end` (VR-003), `write_frame_prefix` (VR-005), the overflow-free increment in `next_expected_frame` (VR-004), the encrypt MAX_DATA budget `PlaintextBudget` and frame counter `EncryptFrameSeq` (VR-017, `esdk/src/message/body/body_encrypt.rs`).
- **Open surface:** `esdk/src/lib.rs` leaves `clippy::indexing_slicing` and `clippy::panic` off, so slice indexing outside `verus!` is an allowed, unproven panic surface. A sweep of indexing/arithmetic sites in `esdk/src` is a capability-driven source of targets (only sync, `verus!`-extractable sites qualify).

## Category 2d

Source: `.kiro/agents/verus-capabilities.md` §2d. Total error handling (the `.expect` inventory and the prim cores).

- Known `.expect` sites (re-check before scoping): `esdk/src/shapes.rs` has a `const DEFAULT_FRAME_LENGTH: NonZeroU32 = NonZeroU32::new(4096).expect(...)`, a compile-time constant over a non-zero literal that cannot panic at runtime (not a target). The old `esdk/src/encrypt.rs` HKDF output-length `.expect` no longer exists: that derivation moved behind `esdk/src/secret.rs` with VR-011. (This supersedes the `d8c1c3d` panic inventory in `docs/verification-recommendations.md`.)
- **In-crate (VR-008):** `sign_fixed_len_core` in `prim/src/ecdsa.rs` — the real retry loop is inside `verus!` with `decreases MAX_SIGN_ATTEMPTS - attempt` (termination) and the guarded `copy_from_slice` proven in bounds. The `aws-lc-rs` `Signature` / signing closure is the trusted boundary (`external_type_specification` + `assume_specification`); the thin `sign_fixed_len` adapter builds the `Error`; no crypto property is proven.
- **In-crate (VR-006):** `aes_encrypt_extend_core` and `aes_decrypt_len_ok` in `prim/src/lib.rs` — both inside `verus!`. `aes_encrypt_extend_core` extends `cipher_text` with `message` and returns the appended tail as a slice of exactly `message.len()` bytes; the `split_at_mut(old_size)` index is proven in bounds by the `extend_from_slice` length fact, so `cipher_text[old_size..]` can never panic. `aes_decrypt_len_ok` is the decision core proving `Ok` iff `plain_text.len() >= cipher_text.len()` — the guard that makes the `aws-lc-rs` gather buffer-safe. Since VR-014 the aws-lc-rs calls (`UnboundKey::new`, the seal and the open) sit inside `aes_encrypt_core` / `aes_decrypt_core` in the `verus!` block, against the trusted specs in `prim/src/aws_lc_specs.rs` (A14–A20). The thin `aes_encrypt`/`aes_decrypt` adapters outside `verus!` only build the `Error`. **Not proven:** the AES-GCM key length (16/24/32) and the IV validity — those are enforced inside `aws-lc-rs` (`UnboundKey::new` / `Nonce::try_assume_unique_for_key` return `Err`), a trusted boundary Verus cannot see into; and no crypto property.
- **In-crate (T3):** `prim/src/hkdf.rs` (VR-009 prim half) carries a `verus!` block — the `{16, 24, 32}` HKDF key-length decision and the no-salt slice bound are verified in place; the aws-lc-rs HKDF crypto stays trusted.
- **In-crate (VR-013, VR-014):** the prim wrapper length contracts and the AES buffer effects (see 1a). Every aws-lc-rs call they make is trusted not to panic, because no TCB row has a `requires`.

## Category 3

Source: `.kiro/agents/verus-capabilities.md` §Category 3: Safety of low-level and `unsafe` code.

- **No in-crate surface.** `esdk/src`, `mpl/src` and `prim/src` contain no `unsafe`.
- **The C++ shim** (`esdk/shims/aws-esdk-cpp/src/lib.rs`, 4 `unsafe` expressions): the validity of C++-supplied pointers is not Verus-provable (it is a property of the C++ caller; trusted). Treat any shim concern as threat-driven, not a Verus target, unless a Rust-side null/ownership decision can be extracted into a sync core.
- **The trusted aws-lc-rs boundary** is the TCB list in `prim/src/aws_lc_specs.rs`, owned by `verus-unsafe-ffi-safety`. Its format and rules are in "Trusted boundary" in the `verus` skill.
- **Safe-wrapper preconditions** (AES key length 16/24/32, IV 12, tag 16): these are enforced inside `aws-lc-rs` (its key/nonce constructors return `Err`), not by Rust-side branches in `prim`, so Verus cannot prove them — they are a trusted boundary. What *is* in-crate for AES-GCM (VR-006, `prim/src/lib.rs`) is the Rust-side buffer safety only: the `aes_encrypt` slice bounds and the `aes_decrypt` plaintext-vs-ciphertext length precondition. The ECDSA length gate is in-crate too (VR-008, `prim/src/ecdsa.rs`).
- **Zeroization:** `zeroize` derive, trusted. VR-010 model is deferred (removed code).

## Category 4

Source: `.kiro/agents/verus-capabilities.md` §Category 4: Concurrency and linear ghost permissions.

- **Not applicable in `esdk`.** The concurrent paths are async/tokio, which Verus cannot verify, and `esdk` has no hand-written lock protocol. The MPL storm-tracking cache is outside ESDK scope. The order of sequential async steps is a different question; see Category 1e.

## Decision aid rows

The ESDK rows of the decision aid. The generic rows stay in `.kiro/agents/verus-capabilities.md`.

Source: `.kiro/agents/verus-capabilities.md` §Provable vs. not-here: decision aid.

| Property | Verus-provable? | Here, in place? | Route to |
|----------|-----------------|-----------------|----------|
| Header-field / EDK-count / key-length decision returns the spec result | Yes | Yes (done: VR-003, VR-007, VR-009 esdk half) | `verus-header-parsing-proofs` |
| Key-commitment accept iff derived commit key == header suite data | Yes (the decision) | Yes (done: VR-001 (a)) | `verus-header-parsing-proofs` |
| Body AAD / IV / frame-prefix layout equals the spec bytes | Yes | Yes (done: VR-005) | `verus-header-parsing-proofs` |
| Frame sequence accepted iff sequential from 1 | Yes | Yes for the checks (VR-004); the async loop is glue | `verus-header-parsing-proofs` |
| `spec_be_uN ∘ spec_uN_to_be` identity lemma | Yes | Yes (done: VR-012, u32 and u64) | `verus-header-parsing-proofs` |
| Sync indexing / arithmetic cores in `esdk/src` never panic | Yes | Yes, if extractable into `verus!` | `verus-zero-panic` |
| Header-auth tag verified, and commitment accepted, before any frame (shipped order) | The gate, yes; the order is compiler-enforced (Category 1e) | **Yes, in place** (done: VR-002, VR-001 (b); Verus-proven gate, compiler-enforced order) | `verus-header-parsing-proofs` |
| Final plaintext held until the signature verifies; signature/key presence matches the suite | The gate, yes; the order is compiler-enforced (Category 1e) | **Yes, in place** (done: VR-015, VR-015 (b); VR-019 one direction, finding VR-019 F1) | `verus-header-parsing-proofs` |
| `prim` ECDSA `sign_fixed_len` terminates / no OOB copy | Yes | **Yes, in place** (done: VR-008, `prim/src/ecdsa.rs`) | `verus-zero-panic` |
| `prim` AES-GCM / HKDF Rust-side buffer & decision safety | Yes | Yes (done: VR-006 in `prim/src/lib.rs`, VR-009 prim half in `prim/src/hkdf.rs`) | `verus-zero-panic` |
| `prim` wrapper output lengths and AES buffer effects, against trusted aws-lc-rs specs | Yes, relative to the TCB rows | Yes (done: VR-013, VR-014) | `verus-zero-panic`; TCB rows owned by `verus-unsafe-ffi-safety` |
| Anything inside `mpl` in place | Yes in kind | **No**: `mpl` not Verus-checked | out of scope here |
| Confinement, or absence of a function (e.g. VR-011 "no code outside `secret.rs` reads key bytes") | **No**: Verus does not check that a function is absent | Checked by compiler privacy + clippy `disallowed-methods` | not a Verus target; never describe as Verus-proven |
| Async ordering in shipped code | **Yes**, if the order can be expressed as a data dependency on a token minted by a sync verified gate (Category 1e). Verus proves the gate; the compiler enforces the order | Yes (VR-001 (b), VR-002, VR-015, VR-019) | `verus-header-parsing-proofs` |

Source: `.kiro/agents/verification-recommender.md` §Agent Assignment Rules (the row with an ESDK fact).

| Property Category | Assigned Agent | When to Use |
|------------------|----------------|-------------|
| FFI memory safety (unsafe blocks) | `verus-unsafe-ffi-safety` | Proving pointer validity across C boundary (no in-crate `unsafe` today) |

## Zero-panic (prim panic points)

Source: `.kiro/agents/verus-zero-panic.md` §Real prim panic points (VR-008, VR-006 and VR-009 prim half all in-crate). Counts in the copied scope note are a dated snapshot; read live counts from profile `artifacts.counts_source`.

> **Scope note.** `prim` is Verus-enabled (`[package.metadata.verus] verify = true`, `make -C prim verus`). `prim/src/ecdsa.rs` carries a `verus!` block (VR-008, T1), `prim/src/lib.rs` carries one (VR-006, T2) and `prim/src/hkdf.rs` carries one (VR-009 prim half, T3). All three prim panic-point targets are in-crate, verified in place in the shipped files the same way `esdk` is. Later prim targets VR-013 (wrapper length contracts) and VR-014 (AES buffer effects) are in-crate too. Counts: see `docs/verus-proofs-report.md` and re-read them from the live make output (dated snapshot at `578b1faa`: prim 18 verified / 0 errors on both feature sets).

- `aes_encrypt` / `aes_decrypt` (`prim/src/lib.rs`): **in-crate (VR-006, T2).** The Rust-side buffer safety is proven by two cores inside `verus!`. `aes_encrypt_extend_core` extends `cipher_text` with `message` and returns the appended tail as a slice of exactly `message.len()` bytes; the `split_at_mut(old_size)` index is proven in bounds by the `extend_from_slice` length fact, so the shipped `cipher_text[old_size..]` region can never be out of bounds. `aes_decrypt_len_ok` proves `Ok` iff `plain_text.len() >= cipher_text.len()` — the guard that makes the downstream `open_separate_gather` buffer-safe. Since VR-014 the `aws-lc-rs` calls (`UnboundKey::new`, the seal and the open) sit inside `aes_encrypt_core` / `aes_decrypt_core` in the `verus!` block, against the trusted specs in `prim/src/aws_lc_specs.rs` (A14–A20; A20 is the labeled assumption A-OPEN). The thin `aes_encrypt`/`aes_decrypt` adapters outside `verus!` only build the `Error`. **Not proven:** the key length (16/24/32) and the IV validity — those are enforced *inside* `aws-lc-rs` (`UnboundKey::new` / `Nonce::try_assume_unique_for_key` return `Err` on a bad key or nonce), not by Rust-side branches in `prim`, so Verus cannot see them; they are a trusted boundary. No crypto property is proven.
- `sign_fixed_len` / `check_sig_len` (`prim/src/ecdsa.rs`): **in-crate (VR-008)**. `check_sig_len` rejects a wrong-sized `signature` buffer before signing, and the retry copies a candidate only when its length equals `signature.len()`. The real retry loop is inside `verus!` as `sign_fixed_len_core`: the `while` loop carries `decreases MAX_SIGN_ATTEMPTS - attempt` (termination) and the loop invariant `want_len == signature.len()`, so the `copy_from_slice` under the `candidate.len() == want_len` guard has equal lengths and is proven in bounds. `MAX_SIGN_ATTEMPTS` lives inside `verus!`. The thin `sign_fixed_len` adapter outside `verus!` owns only the `Error`/`format!` strings and maps the closure's signing errors onto a `verus!`-internal `SignCoreError`. The only trusted boundary inside `verus!` is the FFI/std surface: `aws-lc-rs`'s opaque `Signature` (`external_type_specification`), `Signature::as_ref` and `<[u8]>::copy_from_slice` (`assume_specification`s). Proven: the bounded `MAX_SIGN_ATTEMPTS` retry terminates, and no copy runs out of bounds. **Not** proven: the crypto — the signing closure's result (including the candidate length) is trusted.
- `get_len` / `hkdf_no_salt` (`prim/src/hkdf.rs`): **in-crate (VR-009 prim half, T3)**. Three cores inside `verus!`. `hkdf_key_len_ok` proves the `{16, 24, 32}` HKDF key-length decision over the real `okm.len()` is total and correct — `Ok` for exactly those three lengths (each mapped to its AES size) and `Err` otherwise — the same `{16, 24, 32}` shape the esdk half (`identity_kdf_key_len_ok` / `check_v2_key_lengths`) keys off, so VR-009 is now verified on both halves. `salt_size_core` proves the per-digest default salt length is `<= MAX_SALT_SIZE` (64), and `no_salt_slice_core` proves the `&salt[0..sz]` subrange on the 64-byte zero buffer is in bounds, so `hkdf_no_salt` cannot panic on the slice. The crate `Error`, the `DigestAlg` enum and the `aws-lc-rs` `aead::Algorithm` stay in the thin `get_len` / `digest_to_hkdf` / `hkdf_no_salt` adapters outside `verus!`, as T1/T2 keep them out. **Not proven:** the HKDF crypto itself, the derived key bytes, and the `aws-lc-rs` extract/expand/fill results (incl. their `Err`) — the trusted boundary.

All three prim panic-point targets (VR-008, VR-006, VR-009 prim half) are in-crate, verified in place in the shipped files.

Also done in this agent's area (details in `docs/verus-proofs-report.md` §3): VR-013 (prim wrapper length contracts: `digest_core`, `digest_finish_core`, `hmac_core`, `kbkdf_core`, `fill_random_core`, `ct_equal_core`), VR-014 (AES buffer effects; BUG-07(a) proved, BUG-07(b) recorded under A-OPEN, not fixed), VR-017 (encrypt limits: `PlaintextBudget`, `EncryptFrameSeq` in `esdk/src/message/body/body_encrypt.rs`) and VR-018 (encrypt header length checks: `check_v2_suite_data`, `data_key_len_ok` in `esdk/src/encrypt.rs`).

Source: `.kiro/agents/verus-zero-panic.md` §In-Crate Constraints (the concrete prim example).

> Concrete prim example (VR-008): `sign_fixed_len_core` holds the real retry loop inside `verus!` — `MAX_SIGN_ATTEMPTS` moved inside, the `aws-lc-rs` `Signature` modeled by an `external_type_specification`, its `as_ref` and `<[u8]>::copy_from_slice` by `assume_specification` — while the crate `Error` is kept out of `verus!` entirely via a `verus!`-internal `SignCoreError` and a thin `sign_fixed_len` adapter that builds the `Error`.

Source: `.kiro/agents/verus-zero-panic.md` §Process, step 6 (Prove Composability), the ESDK item.

> - `construct_frame()` calls `prim::aes_encrypt()`. This call crosses into `prim`, whose `verus!` cores are not visible across the crate boundary from `esdk`, so keep it in the unverified esdk adapter. Inside `prim` itself the AES-GCM buffer safety is now proven in place (VR-006, T2: `aes_encrypt_extend_core`, `aes_decrypt_len_ok`; VR-014: `aes_encrypt_core`, `aes_decrypt_core`); the key length and IV validity are enforced inside `aws-lc-rs` (trusted), not Verus-proven.

## Open panic surface

Source: `.kiro/agents/verus-zero-panic.md` §Open Panic Surface (not yet closed).

The in-crate zero-panic story is partial. These panic sources are known and left open; a target that closes one is in scope (triage it through `.kiro/agents/verus-capabilities.md` first):

- `esdk/src/lib.rs` leaves `clippy::indexing_slicing` and `clippy::panic` **off** (they are listed in the lint policy as deliberately not enabled, because indexing is too noisy in serialization code and `panic!()` is forced by `#[non_exhaustive]` MPL enums). So raw indexing and `panic!()` are not lint-blocked; Verus bounds proofs are what actually rule them out where they run.
- `.expect(...)` sites in `esdk/src`. Verify each site still exists before citing it specifically; if unsure, describe them generally rather than naming a line. One that exists today is the default frame length in `esdk/src/shapes.rs` (`NonZeroU32::new(4096).expect(...)`), which is a compile-time constant and cannot fail. Prove any input-dependent `.expect` either cannot be reached or is replaced by total error handling.

## FFI scope facts

Source: `.kiro/agents/verus-unsafe-ffi-safety.md` §Important scope correction for this repository.

This repository does **not** call a C crypto backend through raw FFI, and it has **no in-crate `unsafe`**. Do not model raw `aws-lc-sys` `EC_POINT` / ECDH calls, ghost memory regions, or `*mut u8` handed to C: that code does not exist here. The verified facts (re-check each with a search before relying on it):

1. **No `unsafe` in `esdk/src`, `mpl/src` or `prim/src`.** There are no raw `aws-lc-sys` calls, no `from_raw_parts`, no `set_len`, no `EC_POINT` / `EC_GROUP`. The crypto boundary is aws-lc-rs's **safe** Rust API (`UnboundKey`, `LessSafeKey`, `Nonce`, `hmac`, `digest`, `EcdsaKeyPair`, `hkdf`), reached through `aws-mpl-primitives` (`prim/`).

2. **The only shipped-path `unsafe` is in the C++ shim** `esdk/shims/aws-esdk-cpp/src/lib.rs`: four expressions that dereference or borrow raw pointers supplied by C++ callers — `unsafe { &*ptr }` (returning a borrowed handle) and `unsafe { input.<field>.as_ref() }` on optional client/cache handles (`kms_client`, `ddb_client`, `cache`). Confirm the exact locations with a search before citing line numbers; at the time of writing they are near lines 728, 1570, 1571 and 1661. The **validity of those C++-supplied pointers is part of the trusted computing base (TCB)**: it is a property of the C++ caller, not of Rust, and Verus cannot prove it. The only thing that could ever be a Rust-side Verus target here is a null / ownership decision extracted into a synchronous core — and today there is none, because the shim simply maps `as_ref()` over the optional handle. Treat the shim as a threat-driven review item, not a Verus target.

3. **Zeroization is `#[derive(Zeroize, ZeroizeOnDrop)]`, not a hand-written loop.** The `zeroize` crate is part of the TCB. The old hand-written `write_volatile` zeroing loop was removed (commit `a864ad87`); the VR-010 zeroize model (`verification/zeroize_proofs.rs`) describes that **removed** code and is deferred. Do not treat a `write_volatile` loop as a current proof target — there is none.

4. **VR-011 data-key confinement is not a Verus proof.** "No code outside `secret.rs` reads the key bytes" is enforced by the **Rust compiler's privacy rules and clippy `disallowed-methods`**, not by Verus. Verus does not prove the absence of a code path. What Verus covers for VR-011 is only the `esdk/src/secret.rs` accessor contracts against their closed `view()` and the `PublicBytes` label invariant. Never describe the confinement itself as Verus-proven.

## Trusted boundary

Source: `.kiro/agents/verus-unsafe-ffi-safety.md` §The trusted aws-lc-rs boundary (and how the verified prim proofs exercise it).

The cryptographic primitives live in `prim/` and wrap aws-lc-rs's safe API. aws-lc-rs itself is **trusted**: its types are opaque to Verus and its functions cannot be modeled from their Rust source. The verified `prim` cores reason about aws-lc-rs through trusted specs. Those specs are the boundary:

- **`prim/src/aws_lc_specs.rs` (VR-013, VR-014):** the main TCB module. It gives the aws-lc-rs digest, HMAC, KBKDF, RNG, constant-time and AEAD types and calls their specs: T-ty (opaque types), T-AsRef (`ExAsRef`, an `external_trait_specification` for `AsRef`), T-uf (uninterpreted spec fns) and A1–A20. A20 is the labeled assumption A-OPEN about `open_separate_gather` (not proven). `ExAsRef` needs `#![cfg_attr(verus_keep_ghost, feature(sized_hierarchy))]` in `prim/src/lib.rs`, in Verus builds only; whether to keep that line is an open packaging question.
- **`prim/src/ecdsa.rs` (VR-008):** the real `sign_fixed_len` retry loop is verified in `verus!` with `decreases MAX_SIGN_ATTEMPTS - attempt` (termination) and a guarded `copy_from_slice` proven in bounds (no out-of-bounds copy). The aws-lc-rs `Signature` type is given a spec at the boundary with `#[verifier::external_type_specification]` (`ExSignature`), and `<Signature as AsRef<[u8]>>::as_ref` and `<[T]>::copy_from_slice` are given specs with `assume_specification`. VR-013 reuses these unchanged.
- **`prim/src/lib.rs` (VR-006, VR-014):** the AES-GCM buffer-safety cores are in `verus!`. Since VR-014 the aws-lc-rs AES calls (`UnboundKey::new`, the seal and the open) sit inside `aes_encrypt_core` / `aes_decrypt_core` in the `verus!` block, against A14–A20. The thin `aes_encrypt` / `aes_decrypt` adapters outside `verus!` only build the `Error`.
- **`prim/src/hkdf.rs` (VR-009 prim half):** the `{16, 24, 32}` HKDF key-length decision and the no-salt slice bound are verified in place. The aws-lc-rs HKDF calls stay in adapters outside `verus!`; no spec was needed (VR-006 needed none either).

Source: `.kiro/agents/verus-unsafe-ffi-safety.md` §The TCB list (owned by this agent), "Where the list lives in this repo".

> Where the list lives in this repo: the code in `prim/src/aws_lc_specs.rs` (and the VR-008 specs in `prim/src/ecdsa.rs`), and the table in the "VR-013 / VR-014 TCB" section of `docs/verus-proofs-report.md`. When a row is added, changed or removed, update both and check they agree.

Source: `.kiro/agents/verus-unsafe-ffi-safety.md` §The TCB list, "What the boundary does **not** prove".

> What the boundary does **not** prove: no cryptographic property (AES-GCM / ECDSA / HKDF security), and not the AES key length (16/24/32) or IV validity — those are enforced *inside* aws-lc-rs (`UnboundKey::new` / `Nonce::try_assume_unique_for_key` return `Err`), a trusted boundary Verus cannot see into. The in-crate proofs cover only the **Rust-side buffer and decision safety** around the call.

Source: `.kiro/steering/verus-verification.md` §Targets (the crypto-call note).

> For a function whose core is an `aws-lc-rs` call (AES-GCM, ECDSA, HKDF),
> Verus cannot see the crypto. Only the Rust-side logic around the call is
> provable, against trusted specs of the calls (`prim/src/aws_lc_specs.rs`).

## Do not redo

Also in profile `do_not_redo`.

Source: `.kiro/agents/verus-header-parsing-proofs.md` §Process, step 1.

> - **Do not redo work that is already proven.** Among others, the header-field decision cores (VR-003), the `edk_count_check` core (VR-007), the key-commitment decision (VR-001 (a)), the codec round-trip lemmas (VR-012) and the decrypt-order tokens (VR-001 (b), VR-002, VR-015) are already in-crate. Read the target table in `docs/verus-proofs-report.md` §3 and `.kiro/agents/verus-capabilities.md` first and build on these cores rather than re-proving them.

Source: `.kiro/agents/verus-header-parsing-proofs.md` §Process, step 1 (the file list).

> - `esdk/src/message/header.rs`, `header_types.rs`, `v1_header_body.rs`, `v2_header_body.rs`, `encrypted_data_keys.rs`, `serialize_functions.rs`, `header_auth.rs` — native Rust header parsing (async readers over `dyn Source`, with synchronous decision cores inside `verus!`)
> - `prim/src/lib.rs` — AES-GCM wrappers `aes_encrypt` / `aes_decrypt` (shared with verus-zero-panic; Verus-checked in place, VR-006 and VR-014)
> - `esdk/src/decrypt_gate.rs` and `esdk/src/encrypt_gate.rs` — the typestate tokens for ordering targets (Category 1e)

Source: `.kiro/agents/verus-zero-panic.md` §Process, step 1.

> **Do not redo work that is already proven.** The following zero-panic cores are already verified **in-crate** inside `verus! { }` in the shipped `esdk/src/message/` files — build on them rather than re-proving:
> - VR-005: body AAD as a `Seq` concatenation (`body_aad_core`, `iv_seq_core`, `body_aad_content_type_string`, `write_frame_prefix` in `body/body_aad.rs` and `body/body_encrypt.rs`).
> - `bounded_len_u32` / `bounded_len_u64` and `next_chunk_end` (`serialize_functions.rs`, VR-003), and `next_expected_frame` (`body/body_decrypt.rs`, VR-004).

Source: `.kiro/agents/verus-zero-panic.md` §Process, step 1 (the file lists).

> **In-crate (the default — shipped `esdk`, checked by `make -C esdk verus`):**
> - `esdk/src/message/body/body_encrypt.rs` (`construct_frame`, `write_frame_prefix`), `esdk/src/message/body/body_aad.rs`, `esdk/src/message/body/body_decrypt.rs` — frame construction, body AAD, and decryption. Put the synchronous decision core inside the `verus! { }` block in the real file; leave the async writer/reader as an unverified adapter around it.
> - `esdk/src/encrypt.rs`, `esdk/src/key_derivation.rs` — encrypt orchestration and key derivation.

The same step lists the prim files under "In-crate in `prim` (checked by `make -C prim verus`)": `prim/src/ecdsa.rs` (VR-008), `prim/src/lib.rs` (VR-006, VR-014) and `prim/src/hkdf.rs` (VR-009 prim half), each marked "Already proven; build on it, don't re-prove." The per-file detail of those bullets matches §Zero-panic (prim panic points) and is not repeated here (summary, not a verbatim copy).

Source: `.kiro/agents/verus-zero-panic.md` §Rules (the ESDK-target bullet).

> - VR-008 (ECDSA, `prim/src/ecdsa.rs`), VR-006 (AES-GCM, `prim/src/lib.rs`) and VR-009 prim half (HKDF, `prim/src/hkdf.rs`) are all in-crate, as are VR-013 and VR-014 (`prim`) and VR-017 and VR-018 (`esdk` encrypt). None of these is model-only

## Drift examples

ESDK examples for the drift checklist in `.kiro/agents/ai-verification-update.md`. The generic item text stays in the agent.

Source: `.kiro/agents/ai-verification-update.md` §What to look for (the drift checklist).

- Item 1 (a trust boundary moved or disappeared): "A dependency was retargeted (e.g. the `unsafe-unreviewed-mpl` / Dafny shim removal)".
- Item 3 (a proof was added, moved in-crate, or superseded): "A model-only property became an in-crate proof (as VR-006/008/009-prim-half did when Verus was enabled in `prim`)".
- Item 4 (a target's honest scope shifted): "a model-only property that moved in-crate as a typestate gate (as VR-001 (b) and VR-002 did at `3195f86f`)".
- Item 5 (modeled code no longer exists): "A model describes removed code (the VR-010 `write_volatile` loop)".

Source: `.kiro/agents/ai-verification-update.md` §Establishing the baseline and the delta.

> The docs already record their freshness as a commit, e.g. the threat model's
> `**Revised:** … against \`5ea2a804\``. That recorded commit is the **baseline**.

Source: `.kiro/agents/ai-verification-update.md` §Soundness and honesty rules.

> Examples at `578b1faa`: VR-011 confinement is compiler/clippy-enforced;
> VR-001 (b), VR-002, VR-015 and VR-019 are Verus-proven gates whose order is
> compiler-enforced (the order itself is not Verus-proven); the
> `assume_specification` / `external_type_specification` boundaries and the
> aws-lc-rs crypto are **trusted**, not proven.

## Mutation log example

Source: `.kiro/skills/verus/SKILL.md` §This repo (ESDK).

- Mutation log example: `.agents/tasks/verus-prim-c03/logs/mutations.md` (M1–M19). This is a task-notes path in the main checkout (outside the worktree, never committed); it is a historical log.
