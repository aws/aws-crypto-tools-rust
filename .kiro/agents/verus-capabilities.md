---
name: verus-capabilities
description: Reference guide to what Verus can and cannot prove, mapped onto the native-Rust AWS Encryption SDK (`aws-esdk`, `esdk/`) in this repository. Defines the four proof categories (functional correctness against mathematical specs, zero-panic guarantees, safety of low-level/unsafe code, concurrency with ghost permissions) and points each at concrete `esdk` and `prim` code and the VR-001…VR-019 targets (including ordering via typestate tokens, Category 1e). Use it to decide whether a proposed property is Verus-provable here, to pick the proof category and executing agent, and as the provability gate the verification-recommender applies to every candidate. Not an executable proof-writer; it feeds the verification-recommender and the three verus-* proof agents.
tools: ["read", "web"]
---

# What Verus Can Prove: Reference for the ESDK

Verus proves that Rust code meets a mathematical specification and is free of runtime failures, statically, for **all** inputs, using the Z3 SMT solver. A unit test samples some inputs; a Verus proof is a statement over the whole input space.

This document is the shared capability map for the verification pipeline. It answers three questions before any proof is written:

1. **Is this property Verus-provable at all?** (vs. a test, a compiler/lint check, a review comment or an operational control)
2. **Which of the four proof categories does it fall into?**
3. **Which agent writes it, and against which `esdk` code?**

It is upstream of:
- `verification-recommender`: uses this map (a) as the Stage 2' map of where to look for capability-driven targets and (b) as the "can Verus prove this, here?" gate for every candidate, threat-driven or capability-driven
- `verus-header-parsing-proofs`: functional correctness of message header / body parsing and layout
- `verus-zero-panic`: absence of runtime panics
- `verus-unsafe-ffi-safety`: `unsafe` and FFI-boundary safety (little surface here, see Category 3)

The non-negotiable soundness rules are in the `verus` skill and `.kiro/steering/verus-verification.md`: never use `assume`, `admit`, `#[verifier::external_body]` or `#[verifier::external]` to force a pass; a proof counts only when the tool prints `0 errors`. Every claim in this file uses the levels of the **honesty ladder** in the `verus` skill (`.kiro/skills/verus/SKILL.md`, "Honesty ladder"). This agent scopes work. It does not relax proof standards.

## Toolchain and how to run

- Verus `0.2026.07.12.0b42f4c`, Rust toolchain `1.96.0`, binary `~/verus/verus`. `esdk` depends on `vstd = "=0.0.0-2026-06-14-0213"`.
- **In-crate (shipped code):** `make -C esdk verus` (from the repo root). It runs `cargo verus verify` twice: default features, then `--no-default-features --features aws-lc-sys`. `vstd` is verified first (`1858 verified, 0 errors`); the `aws-esdk` result is the **second** `verification results::` line. A cached run prints no results line; `touch esdk/src/lib.rs` forces a re-check.
- **In-crate (`prim`):** `make -C prim verus`, same two feature sets. Read the `aws-mpl-primitives` results line; `touch prim/src/lib.rs` forces a re-check.
- **Standalone models:** `make -C verification verify` (or `~/verus/verus verification/<file>.rs`). These import nothing from the crates and can drift from the code; see `verification/README.md` for which are superseded, stale or model-only.

## Current verified state

Counts: see `docs/verus-proofs-report.md` and re-read them from the live make output. Do not copy a count from this file. Dated snapshot at `578b1faa`, for orientation only: esdk 97 verified / 0 errors on both feature sets, prim 18 / 0 on both, verification 78 / 0 over 11 files.

Never claim a property is verified from reading code.

## Repository grounding

| Crate / item | Path | Verus status |
|--------------|------|--------------|
| `aws-esdk` | `esdk/src/` | **Verus-checked.** `[package.metadata.verus] verify = true`; only code inside `verus! { }` is verified. The typestate gate modules are `esdk/src/decrypt_gate.rs` (VR-001 (b), VR-002, VR-015) and `esdk/src/encrypt_gate.rs` (VR-019); `esdk/src/secret.rs` holds `OpenBuffers` (VR-016). |
| `aws-crypto-mpl` | `mpl/src/` | Dependency. Built by `cargo-verus` with plain rustc; not verified. Keyrings, CMMs, material types (`PlaintextDataKey`, `AlgorithmSuite`). |
| `aws-mpl-primitives` | `prim/src/` | **Verus-checked.** `[package.metadata.verus] verify = true`, `make -C prim verus`. `prim/src/ecdsa.rs` (VR-008: the `sign_fixed_len` retry loop with `decreases` and a bounds-proven copy; VR-013 `digest_finish_core`), `prim/src/lib.rs` (VR-006 buffer cores; VR-013 `digest_core`, `hmac_core` and the other wrapper cores; VR-014 `aes_encrypt_core` / `aes_decrypt_core`, which now make the aws-lc-rs AES calls inside `verus!`), `prim/src/hkdf.rs` (VR-009 prim half: `hkdf_key_len_ok`, `salt_size_core`, `no_salt_slice_core`). The trusted specs for aws-lc-rs are in `prim/src/aws_lc_specs.rs` (TCB rows T-ty, T-AsRef, T-uf, A1–A20; A20 is the labeled assumption A-OPEN). The `ExAsRef` trait spec there needs `#![cfg_attr(verus_keep_ghost, feature(sized_hierarchy))]` in `prim/src/lib.rs`. The crypto itself stays trusted. |
| C++ shim | `esdk/shims/aws-esdk-cpp/` | Not Verus-checked. Holds the only shipped-path `unsafe`. |
| Standalone models | `verification/` | Verus-checked models (`make -C verification verify`). |
| Spec | `spec/` at the repo root | Resolved by `scripts/resolve-spec.sh`; not a submodule and may be absent locally. The tracked documents are listed in `esdk/.duvet/config.toml` (`spec/data-format/*`, `spec/client-apis/*`, …). |
| Duvet annotations | `//=` / `//#` comments in `esdk/src` and `esdk/tests` | Requirement-to-code map. `type=test` means tested, not proven. |

Reality check for this repo:
- **No `unsafe` in `esdk/src`, `mpl/src` or `prim/src`.** The only shipped-path `unsafe` is 4 expressions in `esdk/shims/aws-esdk-cpp/src/lib.rs` (`&*ptr` / `as_ref()` on C++-supplied handles). There are no raw `aws-lc-sys` calls, no `from_raw_parts`, no `set_len`.
- **Zeroization** comes from `#[derive(Zeroize, ZeroizeOnDrop)]` (the `zeroize` crate is trusted). The hand-written `write_volatile` loop was removed in `a864ad87`; the VR-010 model (`verification/zeroize_proofs.rs`) describes removed code and is deferred.
- The crypto boundary is aws-lc-rs's **safe** API, reached through `aws-mpl-primitives`.

## In-crate constraints (decide what is provable *here*)

From the steering file and the proofs report:
- Verus cannot verify `async fn` or `dyn` trait objects. Decision logic goes in synchronous cores inside `verus!`; the async readers over `&mut dyn Source` / `&mut Tee` and the `dyn Sink` writers stay as thin **unverified** adapters.
- A verified fn cannot call or name items declared outside `verus!` (mpl types, the esdk `Error`, prim fns) unless they get a spec at the trusted boundary ("Trusted boundary" in the `verus` skill; `prim` does this for aws-lc-rs). Otherwise those calls stay in unverified adapters, listed by name as the trusted base.
- Verus cannot check the order of `.await` steps directly. An order can still be covered when it is expressed as a data dependency on a token (Category 1e).
- A trait declared in `verus!` but implemented outside it has its `ensures` trusted silently. Give such traits `requires` only.
- `to_be_bytes` is not modeled by vstd. Use `u32_to_be` / `u64_to_be` (`esdk/src/message/serialize_functions.rs`).
- Never hide exec code behind `#[cfg(not(verus_keep_ghost))]`. Keep one definition per type.
- A property whose only proof would be `Ok ⇒ Ok` over an aws-lc-rs result is not worth an in-crate proof.

---

## Category 1: Functional correctness against mathematical specs

### 1a. Pre-/postcondition adherence (`requires` / `ensures`)
- **Done in-crate:** header-field decision cores (`msg_format_version_from_u8`, `msg_type_from_u8`, `content_type_from_u8`, `classify_version_byte`, `reserved_bytes_ok`, `iv_len_matches`; VR-003); `edk_count_check` (VR-007); `identity_kdf_key_len_ok`, `check_v2_key_lengths` (VR-009 esdk half); `hkdf_key_len_ok`, `salt_size_core`, `no_salt_slice_core` (VR-009 prim half, T3); the VR-008 (`prim/src/ecdsa.rs`) and VR-006 (`prim/src/lib.rs`) prim cores; the VR-013 prim wrapper length contracts (`digest_core`, `digest_finish_core`, `hmac_core`); the VR-014 AES buffer effects (`aes_encrypt_core`, `aes_decrypt_core`; BUG-07(a) proved, BUG-07(b) recorded under A-OPEN, not fixed); the VR-018 encrypt header length checks (`check_v2_suite_data`, `data_key_len_ok` in `esdk/src/encrypt.rs`).
- **Done in-crate (VR-001 (a)):** the key-commitment accept/reject decision (`suite_data_check`, called from `validate_suite_data` in `esdk/src/message/header.rs`). VR-001 (b), the order, is Category 1e. VR-001 (c), constant time, is trusted (aws-lc-rs); Verus does not model timing.
- **Agent:** `verus-header-parsing-proofs`.

### 1b. Abstract behavioural refinement (exec code ⟶ `Seq` / `Map`)
- **Done in-crate:** body AAD is exactly `message_id ‖ content ‖ seq_be(4) ‖ len_be(8)` (`body_aad_core`, `iv_seq_core`; VR-005); the `secret.rs` accessors against their closed `view()` and the `PublicBytes` label invariant (VR-011 Verus layer only).
- **Agent:** `verus-header-parsing-proofs`.

### 1c. Round-trip parsing and serialization
- **Done in-crate (VR-012):** `lemma_u32_round_trip` and `lemma_u64_round_trip` in `esdk/src/message/serialize_functions.rs` prove the verified big-endian encoders and decoders are exact inverses for `u32` and `u64`.
- **Encoder/decoder asymmetry — by design, not a bug.** The decoders exist for u16/u32/u64 (`spec_be_u16/32/64`, `be_u16/32/64`) but the hand-written big-endian *encoders* exist only for u32/u64 (`spec_u32_to_be`/`spec_u64_to_be`). This is deliberate, not a missing function: u16 values *are* written and read at runtime (`write_u16`/`read_u16`), but `write_u16`/`write_u32`/`write_u8` call `to_be_bytes()` directly and do not use the hand-written encoders. The `*_to_be` encoders were added only where a *proof* needed to reason about the bytes of a field — so far the body AAD's u32 sequence number and u64 content length (`body_aad.rs`), hence u32 and u64 only. No proof has needed to reason about the bytes of a written u16, so no `u16_to_be` was written. Consequence: the VR-012 round-trip lemma covers the u32 and u64 pairs that exist; u16 is decoder-only. Adding a `u16_to_be` + round-trip later would be a proof-coverage *completeness* improvement, not a bug fix.
- **Blocked:** a full header serialize/parse round-trip. It is a Vest-shaped property, but the parser and serializer are async over `dyn Source` / `dyn Sink`, so only sync sub-pieces are provable.
- **Note on Vest:** [Vest](https://github.com/verus-lang/vest) generates verified, non-malleable binary parsers/serializers with round-trip proofs. Cite it as methodology for the property shape, not as a dependency.
- **Agent:** `verus-header-parsing-proofs`.

### 1d. State machine / algorithmic equivalence
- **Done in-crate:** frame-sequence checks and lemmas (`next_expected_frame`, `final_frame_seq_ok`, `lemma_accepts_run`, `lemma_frames_start_at_1`; VR-004). The async loop that threads `expected_frame` is unverified glue.
- **Done in-crate (VR-017):** the encrypt-side frame counter `EncryptFrameSeq` in `esdk/src/message/body/body_encrypt.rs` (starts at 1, +1 per regular frame, never wraps).
- Header-auth ordering (VR-002) and commitment ordering (VR-001 (b)) used to be model-only here. They are now covered in shipped code by typestate tokens (Category 1e). The models `verification/header_auth_ordering_proofs.rs` and `verification/commitment_ordering_proofs.rs` are kept as history.
- **Agent:** `verus-header-parsing-proofs`.

### 1e. Ordering via typestate tokens

Verus cannot check the order of `.await` steps. The order can still be covered in shipped code when it is written as a data dependency: the guarded step takes a token as an argument, and only a verified sync gate can make the token.

- **Token shape:** a struct inside `verus!` with private fields (often `Ghost` fields), a `#[verifier::type_invariant]` that records what the check established, no `Clone` or `Copy`, in its own module (Rust field privacy is per module).
- **Verus-proven (ladder level 1 for the gate):** the gate returns a token only on the success path of the check. Its `ensures` and the type invariant say so.
- **Compiler-enforced (ladder level 2 for the order):** code outside the module cannot build a token, and the guarded step cannot be called without one. This does not depend on how the async runtime schedules the steps.
- **Still trusted:** the adapters pass the real check results to the gate; the guarded step is the only entry point to the protected action (checked by grep, not by the compiler); the token is not tied to one particular message; the async wiring around the gate.
- **Mutation classes to record** ("Mutation testing" in the `verus` skill): minting a token on a failure path is Verus-caught; building a token outside the module or calling the step without one is compiler-caught (`E0451`, `E0425`, `E0616`, `E0061`, `E0308`); deleting the token parameter and its argument **compiles**, so it is review-only.
- **Done in-crate:** `CommitmentAccepted` and `HeaderVerified` (VR-001 (b), VR-002), `SignaturePresence`, `SignatureRequired`, `SignatureVerified` and `HeldFinalPlaintext` (VR-015, VR-015 (b)) in `esdk/src/decrypt_gate.rs`; `OpenBuffers` (VR-016, the same token shape used for buffer sizing: `secret::open` takes only an `OpenBuffers`, built only by the verified `open_buffers`) in `esdk/src/secret.rs`; `SigningKeyPresent` (VR-019, one direction only; finding VR-019 F1) in `esdk/src/encrypt_gate.rs`.
- **Agent:** `verus-header-parsing-proofs` (same as 1d).

---

## Category 2: Zero-panic guarantees

### 2a. Slice and buffer bounds / 2b. arithmetic / 2c. division
- **Done in-crate:** `bounded_len_u32`, `bounded_len_u64`, `next_chunk_end` (VR-003), `write_frame_prefix` (VR-005), the overflow-free increment in `next_expected_frame` (VR-004), the encrypt MAX_DATA budget `PlaintextBudget` and frame counter `EncryptFrameSeq` (VR-017, `esdk/src/message/body/body_encrypt.rs`).
- **Open surface:** `esdk/src/lib.rs` leaves `clippy::indexing_slicing` and `clippy::panic` off, so slice indexing outside `verus!` is an allowed, unproven panic surface. A sweep of indexing/arithmetic sites in `esdk/src` is a capability-driven source of targets (only sync, `verus!`-extractable sites qualify).

### 2d. Total error handling (no panicking `unwrap` / `expect`)
- Known `.expect` sites (re-check before scoping): `esdk/src/shapes.rs` has a `const DEFAULT_FRAME_LENGTH: NonZeroU32 = NonZeroU32::new(4096).expect(...)`, a compile-time constant over a non-zero literal that cannot panic at runtime (not a target). The old `esdk/src/encrypt.rs` HKDF output-length `.expect` no longer exists: that derivation moved behind `esdk/src/secret.rs` with VR-011. (This supersedes the `d8c1c3d` panic inventory in `docs/verification-recommendations.md`.)
- **In-crate (VR-008):** `sign_fixed_len_core` in `prim/src/ecdsa.rs` — the real retry loop is inside `verus!` with `decreases MAX_SIGN_ATTEMPTS - attempt` (termination) and the guarded `copy_from_slice` proven in bounds. The `aws-lc-rs` `Signature` / signing closure is the trusted boundary (`external_type_specification` + `assume_specification`); the thin `sign_fixed_len` adapter builds the `Error`; no crypto property is proven.
- **In-crate (VR-006):** `aes_encrypt_extend_core` and `aes_decrypt_len_ok` in `prim/src/lib.rs` — both inside `verus!`. `aes_encrypt_extend_core` extends `cipher_text` with `message` and returns the appended tail as a slice of exactly `message.len()` bytes; the `split_at_mut(old_size)` index is proven in bounds by the `extend_from_slice` length fact, so `cipher_text[old_size..]` can never panic. `aes_decrypt_len_ok` is the decision core proving `Ok` iff `plain_text.len() >= cipher_text.len()` — the guard that makes the `aws-lc-rs` gather buffer-safe. Since VR-014 the aws-lc-rs calls (`UnboundKey::new`, the seal and the open) sit inside `aes_encrypt_core` / `aes_decrypt_core` in the `verus!` block, against the trusted specs in `prim/src/aws_lc_specs.rs` (A14–A20). The thin `aes_encrypt`/`aes_decrypt` adapters outside `verus!` only build the `Error`. **Not proven:** the AES-GCM key length (16/24/32) and the IV validity — those are enforced inside `aws-lc-rs` (`UnboundKey::new` / `Nonce::try_assume_unique_for_key` return `Err`), a trusted boundary Verus cannot see into; and no crypto property.
- **In-crate (T3):** `prim/src/hkdf.rs` (VR-009 prim half) carries a `verus!` block — the `{16, 24, 32}` HKDF key-length decision and the no-salt slice bound are verified in place; the aws-lc-rs HKDF crypto stays trusted.
- **In-crate (VR-013, VR-014):** the prim wrapper length contracts and the AES buffer effects (see 1a). Every aws-lc-rs call they make is trusted not to panic, because no TCB row has a `requires`.
- **Agent:** `verus-zero-panic` for all of category 2.

---

## Category 3: Safety of low-level and `unsafe` code

- **No in-crate surface.** `esdk/src`, `mpl/src` and `prim/src` contain no `unsafe`.
- **The C++ shim** (`esdk/shims/aws-esdk-cpp/src/lib.rs`, 4 `unsafe` expressions): the validity of C++-supplied pointers is not Verus-provable (it is a property of the C++ caller; trusted). Treat any shim concern as threat-driven, not a Verus target, unless a Rust-side null/ownership decision can be extracted into a sync core.
- **The trusted aws-lc-rs boundary** is the TCB list in `prim/src/aws_lc_specs.rs`, owned by `verus-unsafe-ffi-safety`. Its format and rules are in "Trusted boundary" in the `verus` skill.
- **Safe-wrapper preconditions** (AES key length 16/24/32, IV 12, tag 16): these are enforced inside `aws-lc-rs` (its key/nonce constructors return `Err`), not by Rust-side branches in `prim`, so Verus cannot prove them — they are a trusted boundary. What *is* in-crate for AES-GCM (VR-006, `prim/src/lib.rs`) is the Rust-side buffer safety only: the `aes_encrypt` slice bounds and the `aes_decrypt` plaintext-vs-ciphertext length precondition. The ECDSA length gate is in-crate too (VR-008, `prim/src/ecdsa.rs`).
- **Zeroization:** `zeroize` derive, trusted. VR-010 model is deferred (removed code).
- **Agent:** `verus-unsafe-ffi-safety` if a target ever qualifies.

---

## Category 4: Concurrency and linear ghost permissions

- **Not applicable in `esdk`.** The concurrent paths are async/tokio, which Verus cannot verify, and `esdk` has no hand-written lock protocol. The MPL storm-tracking cache is outside ESDK scope. The order of sequential async steps is a different question; see Category 1e.

---

## Provable vs. not-here: decision aid

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
| Constant-time comparison / no timing leak | **No**: Verus does not model timing | n/a | out of scope; review / tooling |
| AES-GCM, ECDSA, HKDF are cryptographically secure | **No**: crypto analysis, not code proof | n/a | out of scope; aws-lc-rs / design |
| KMS enforces the right key policy | **No**: external service | n/a | out of scope; operational control |
| RNG / data-key entropy quality | **No**: probabilistic | n/a | out of scope; RNG / design |
| Confinement, or absence of a function (e.g. VR-011 "no code outside `secret.rs` reads key bytes") | **No**: Verus does not check that a function is absent | Checked by compiler privacy + clippy `disallowed-methods` | not a Verus target; never describe as Verus-proven |
| Validity of C++-supplied raw pointers in the shim | **No**: property of the caller | n/a | trusted; threat-driven review |
| Async ordering in shipped code | **Yes**, if the order can be expressed as a data dependency on a token minted by a sync verified gate (Category 1e). Verus proves the gate; the compiler enforces the order | Yes (VR-001 (b), VR-002, VR-015, VR-019) | `verus-header-parsing-proofs` |
| `dyn Source` / `dyn Sink` behaviour, or an order that cannot be written as a token | **No** in the installed Verus | n/a | model only or tests |

Rule of thumb: Verus proves **properties of the code's behaviour on all inputs** (functional correctness, no panic, memory safety, race freedom) for code inside `verus!` in `esdk` and `prim`. It does not prove cryptographic hardness, external-service policy, probabilistic secrecy, timing, or the absence of code paths.

## Track record (for justifying effort)

Verus has verified OS memory management and microkernels (CortenMM, Atmosphere), the AWS Nitro isolation engine, confidential-VM security modules (VeriSMo), storage and distributed key-value systems, Kubernetes controllers (Anvil), and non-malleable protocol parsers (Vest). Cite the closest analogue: Vest for codec / round-trip proofs, VeriSMo or Nitro for secret-handling proofs.

## How to use this agent

1. Take a candidate property (from the threat model, a spec requirement, or the Stage 2' sweep) and find its row in the decision aid. Confirm it is Verus-provable **and** provable in place in `esdk` or `prim` (or deliberately model-only).
2. Identify the category (1–4, including 1e) and the concrete `esdk/src` or `prim/src` file and function, and check whether a VR target already covers it (the target table in `docs/verus-proofs-report.md` §3; VR-001…VR-019 at `578b1faa`) so work is not duplicated.
3. Hand off to the named agent with the file/function, the spec citation (with the Duvet annotation where one exists) and, for capability-driven targets, the code invariant.
4. If the property is "No" or "not here", do not create a verification target. Record it as out of scope with the reason (timing, crypto hardness, external service, probabilistic, absence-of-code, an order that cannot be written as a token, `mpl` not Verus-checked).

## Rules

- Only recommend targets that are genuinely Verus-provable **and** provable in this repo as it is configured; use the decision aid, do not over-promise
- Never scope cryptographic security, external-service policy, probabilistic secrecy or timing as Verus targets
- Label every claim with its honesty-ladder level (`verus` skill). Never call a compiler, lint, test, model, code-reading or trusted fact Verus-proven; for a typestate gate, only the gate is Verus-proven and the order is compiler-enforced
- Ground every target in a real `esdk/src` or `prim/src` file/function and a `spec/` citation (with the Duvet annotation where one exists)
- Respect the recorded decisions: `esdk` and `prim` are Verus-checked in place (only code inside `verus!` is verified); `mpl` is not Verus-checked
- Do not manufacture raw-FFI or `unsafe` proof work: there is no `unsafe` in `esdk/src`, `mpl/src` or `prim/src`
- New targets take the next free id and carry `origin: threat-driven` or `origin: capability-driven`. At `578b1faa` the next free id is VR-020 (YAML `VR-2026-020`); re-check with a grep over `docs/`, `verification/`, `esdk/src` and `prim/src` before using it. Existing ids keep their numbers; retired ids are not reused
- Report verified counts only from the latest `0 errors` tool output; defer to the `verus` skill's soundness invariants
