---
name: verus-capabilities
description: Reference guide to what Verus can and cannot prove, mapped onto the native-Rust AWS Encryption SDK (`aws-esdk`, `esdk/`) in this repository. Defines the four proof categories (functional correctness against mathematical specs, zero-panic guarantees, safety of low-level/unsafe code, concurrency with ghost permissions) and points each at concrete `esdk` code and the VR-001…VR-011 targets. Use it to decide whether a proposed property is Verus-provable here, to pick the proof category and executing agent, and as the provability gate the verification-recommender applies to every candidate. Not an executable proof-writer; it feeds the verification-recommender and the three verus-* proof agents.
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

The non-negotiable soundness rules are in the `verus` skill and `.kiro/steering/verus-verification.md`: never use `assume`, `admit`, `#[verifier::external_body]` or `#[verifier::external]` to force a pass; a proof counts only when the tool prints `0 errors`. This agent scopes work. It does not relax proof standards.

## Toolchain and how to run

- Verus `0.2026.07.12.0b42f4c`, Rust toolchain `1.96.0`, binary `~/verus/verus`. `esdk` depends on `vstd = "=0.0.0-2026-06-14-0213"`.
- **In-crate (shipped code):** `make -C esdk verus` (from the repo root). It runs `cargo verus verify` twice: default features, then `--no-default-features --features aws-lc-sys`. `vstd` is verified first (`1858 verified, 0 errors`); the `aws-esdk` result is the **second** `verification results::` line. A cached run prints no results line; `touch esdk/src/lib.rs` forces a re-check.
- **Standalone models:** `make -C verification verify` (or `~/verus/verus verification/<file>.rs`). These import nothing from the crates and can drift from the code; see `verification/README.md` for which are superseded, stale or model-only.

## Current verified state (snapshot, not re-run for this document)

As recorded in `docs/verus-proofs-report.md` and `docs/verification-recommendations.md` (branch `vr011-confinement` / `Mahnush_Verus`):
- In-crate: **57 verified, 0 errors** on both feature sets, over 34 exec fns and 3 proof fns in `esdk/src/message/`, `esdk/src/key_derivation.rs` and `esdk/src/secret.rs`.
- Standalone: **71 verified, 0 errors** over 10 files in `verification/`.

These numbers go stale as soon as code changes. Before citing a count, re-run the command above and read the latest tool output. Never claim a property is verified from reading code.

## Repository grounding

| Crate / item | Path | Verus status |
|--------------|------|--------------|
| `aws-esdk` | `esdk/src/` | **Verus-checked.** `[package.metadata.verus] verify = true`; only code inside `verus! { }` is verified. |
| `aws-crypto-mpl` | `mpl/src/` | Dependency. Built by `cargo-verus` with plain rustc; not verified. Keyrings, CMMs, material types (`PlaintextDataKey`, `AlgorithmSuite`). |
| `aws-mpl-primitives` | `prim/src/` | **Verus-enabled for VR-008, VR-006 and VR-009 prim half.** `[package.metadata.verus] verify = true`, `make -C prim verus`; `prim/src/ecdsa.rs` has a `verus!` block (VR-008: the real `sign_fixed_len` retry loop verified in place with `decreases` + a bounds-proven copy), `prim/src/lib.rs` has one (VR-006: `aes_encrypt`/`aes_decrypt` buffer-safety cores — the slice-bounds and the plaintext-vs-ciphertext length precondition) and `prim/src/hkdf.rs` has one (VR-009 prim half, T3: the `{16, 24, 32}` HKDF key-length decision `hkdf_key_len_ok` and the no-salt slice bound `salt_size_core`/`no_salt_slice_core`). All three prim panic-point targets are in-crate. Safe wrappers over `aws-lc-rs` (AES-GCM, HKDF, ECDSA, digest, RNG); the crypto itself stays trusted. |
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
- A verified fn cannot call or name items declared outside `verus!` (mpl types, the esdk `Error`, prim fns). Those calls stay in unverified adapters, listed by name as the trusted base.
- A trait declared in `verus!` but implemented outside it has its `ensures` trusted silently. Give such traits `requires` only.
- `to_be_bytes` is not modeled by vstd. Use `u32_to_be` / `u64_to_be` (`esdk/src/message/serialize_functions.rs`).
- Never hide exec code behind `#[cfg(not(verus_keep_ghost))]`. Keep one definition per type.
- A property whose only proof would be `Ok ⇒ Ok` over an aws-lc-rs result is not worth an in-crate proof.

---

## Category 1: Functional correctness against mathematical specs

### 1a. Pre-/postcondition adherence (`requires` / `ensures`)
- **Done in-crate:** header-field decision cores (`msg_format_version_from_u8`, `msg_type_from_u8`, `content_type_from_u8`, `classify_version_byte`, `reserved_bytes_ok`, `iv_len_matches`; VR-003); `edk_count_check` (VR-007); `identity_kdf_key_len_ok`, `check_v2_key_lengths` (VR-009 esdk half); `hkdf_key_len_ok`, `salt_size_core`, `no_salt_slice_core` (VR-009 prim half, T3); the VR-008 (`prim/src/ecdsa.rs`) and VR-006 (`prim/src/lib.rs`) prim cores.
- **Not started:** the key-commitment accept/reject decision in `validate_suite_data` (`esdk/src/message/header.rs`, VR-001). Only the equality decision is provable; constant-time behaviour is not (see the decision aid).
- **Agent:** `verus-header-parsing-proofs`.

### 1b. Abstract behavioural refinement (exec code ⟶ `Seq` / `Map`)
- **Done in-crate:** body AAD is exactly `message_id ‖ content ‖ seq_be(4) ‖ len_be(8)` (`body_aad_core`, `iv_seq_core`; VR-005); the `secret.rs` accessors against their closed `view()` and the `PublicBytes` label invariant (VR-011 Verus layer only).
- **Agent:** `verus-header-parsing-proofs`.

### 1c. Round-trip parsing and serialization
- **Candidate (not proven):** a lemma linking the verified decoders and encoders in `serialize_functions.rs`, e.g. `spec_be_u32` of the bytes of `spec_u32_to_be(x)` equals `x` (and the u64 analogue). Cheap, sync, in-crate.
- **Blocked:** a full header serialize/parse round-trip. It is a Vest-shaped property, but the parser and serializer are async over `dyn Source` / `dyn Sink`, so only sync sub-pieces are provable.
- **Note on Vest:** [Vest](https://github.com/verus-lang/vest) generates verified, non-malleable binary parsers/serializers with round-trip proofs. Cite it as methodology for the property shape, not as a dependency.
- **Agent:** `verus-header-parsing-proofs`.

### 1d. State machine / algorithmic equivalence
- **Done in-crate:** frame-sequence checks and lemmas (`next_expected_frame`, `final_frame_seq_ok`, `lemma_accepts_run`, `lemma_frames_start_at_1`; VR-004). The async loop that threads `expected_frame` is unverified glue.
- **Model only:** header-auth ordering (VR-002, `verification/header_auth_ordering_proofs.rs`). The shipped order is a sequence of `.await?` calls in `decrypt_steps`, which Verus cannot verify.
- **Agent:** `verus-header-parsing-proofs`.

---

## Category 2: Zero-panic guarantees

### 2a. Slice and buffer bounds / 2b. arithmetic / 2c. division
- **Done in-crate:** `bounded_len_u32`, `bounded_len_u64`, `next_chunk_end` (VR-003), `write_frame_prefix` (VR-005), the overflow-free increment in `next_expected_frame` (VR-004).
- **Open surface:** `esdk/src/lib.rs` leaves `clippy::indexing_slicing` and `clippy::panic` off, so slice indexing outside `verus!` is an allowed, unproven panic surface. A sweep of indexing/arithmetic sites in `esdk/src` is a capability-driven source of targets (only sync, `verus!`-extractable sites qualify).

### 2d. Total error handling (no panicking `unwrap` / `expect`)
- Known `.expect` sites (from the `d8c1c3d` panic inventory in `docs/verification-recommendations.md`, not re-audited): `esdk/src/encrypt.rs` HKDF output-length `expect`; `esdk/src/types.rs` default-config `NonZeroU32::new(4096).expect` / `.unwrap()`. Re-check before scoping.
- **In-crate (VR-008):** `sign_fixed_len_core` in `prim/src/ecdsa.rs` — the real retry loop is inside `verus!` with `decreases MAX_SIGN_ATTEMPTS - attempt` (termination) and the guarded `copy_from_slice` proven in bounds. The `aws-lc-rs` `Signature` / signing closure is the trusted boundary (`external_type_specification` + `assume_specification`); the thin `sign_fixed_len` adapter builds the `Error`; no crypto property is proven.
- **In-crate (VR-006):** `aes_encrypt_extend_core` and `aes_decrypt_len_ok` in `prim/src/lib.rs` — both inside `verus!`. `aes_encrypt_extend_core` extends `cipher_text` with `message` and returns the appended tail as a slice of exactly `message.len()` bytes; the `split_at_mut(old_size)` index is proven in bounds by the `extend_from_slice` length fact, so `cipher_text[old_size..]` can never panic. `aes_decrypt_len_ok` is the decision core proving `Ok` iff `plain_text.len() >= cipher_text.len()` — the guard that makes the `aws-lc-rs` gather buffer-safe. The thin `aes_encrypt`/`aes_decrypt` adapters outside `verus!` build the `Error` and own all `aws-lc-rs` calls. **Not proven:** the AES-GCM key length (16/24/32) and the IV validity — those are enforced inside `aws-lc-rs` (`UnboundKey::new` / `Nonce::try_assume_unique_for_key` return `Err`), a trusted boundary Verus cannot see into; and no crypto property.
- **In-crate (T3):** `prim/src/hkdf.rs` (VR-009 prim half) carries a `verus!` block — the `{16, 24, 32}` HKDF key-length decision and the no-salt slice bound are verified in place; the aws-lc-rs HKDF crypto stays trusted.
- **Agent:** `verus-zero-panic` for all of category 2.

---

## Category 3: Safety of low-level and `unsafe` code

- **No in-crate surface.** `esdk/src`, `mpl/src` and `prim/src` contain no `unsafe`.
- **The C++ shim** (`esdk/shims/aws-esdk-cpp/src/lib.rs`, 4 `unsafe` expressions): the validity of C++-supplied pointers is not Verus-provable (it is a property of the C++ caller; trusted). Treat any shim concern as threat-driven, not a Verus target, unless a Rust-side null/ownership decision can be extracted into a sync core.
- **Safe-wrapper preconditions** (AES key length 16/24/32, IV 12, tag 16): these are enforced inside `aws-lc-rs` (its key/nonce constructors return `Err`), not by Rust-side branches in `prim`, so Verus cannot prove them — they are a trusted boundary. What *is* in-crate for AES-GCM (VR-006, `prim/src/lib.rs`) is the Rust-side buffer safety only: the `aes_encrypt` slice bounds and the `aes_decrypt` plaintext-vs-ciphertext length precondition. The ECDSA length gate is in-crate too (VR-008, `prim/src/ecdsa.rs`).
- **Zeroization:** `zeroize` derive, trusted. VR-010 model is deferred (removed code).
- **Agent:** `verus-unsafe-ffi-safety` if a target ever qualifies.

---

## Category 4: Concurrency and linear ghost permissions

- **Not applicable in `esdk`.** The concurrent paths are async/tokio, which Verus cannot verify, and `esdk` has no hand-written lock protocol. The MPL storm-tracking cache is outside ESDK scope.

---

## Provable vs. not-here: decision aid

| Property | Verus-provable? | Here, in place? | Route to |
|----------|-----------------|-----------------|----------|
| Header-field / EDK-count / key-length decision returns the spec result | Yes | Yes (done: VR-003, VR-007, VR-009 esdk half) | `verus-header-parsing-proofs` |
| Key-commitment accept iff derived commit key == header suite data | Yes (the decision) | Yes (not started, VR-001) | `verus-header-parsing-proofs` |
| Body AAD / IV / frame-prefix layout equals the spec bytes | Yes | Yes (done: VR-005) | `verus-header-parsing-proofs` |
| Frame sequence accepted iff sequential from 1 | Yes | Yes for the checks (VR-004); the async loop is glue | `verus-header-parsing-proofs` |
| `spec_be_uN ∘ spec_uN_to_be` identity lemma | Yes | Yes (candidate) | `verus-header-parsing-proofs` |
| Sync indexing / arithmetic cores in `esdk/src` never panic | Yes | Yes, if extractable into `verus!` | `verus-zero-panic` |
| Header-auth tag verified before any frame (shipped order) | Yes on a model | **No in place**: async `.await?` order | model only (VR-002) |
| `prim` ECDSA `sign_fixed_len` terminates / no OOB copy | Yes | **Yes, in place** (done: VR-008, `prim/src/ecdsa.rs`) | `verus-zero-panic` |
| `prim` AES-GCM / HKDF Rust-side buffer & decision safety | Yes | Yes (done: VR-006 in `prim/src/lib.rs`, VR-009 prim half in `prim/src/hkdf.rs`) | `verus-zero-panic` |
| Anything inside `mpl` in place | Yes in kind | **No**: `mpl` not Verus-checked | out of scope here |
| Constant-time comparison / no timing leak | **No**: Verus does not model timing | n/a | out of scope; review / tooling |
| AES-GCM, ECDSA, HKDF are cryptographically secure | **No**: crypto analysis, not code proof | n/a | out of scope; aws-lc-rs / design |
| KMS enforces the right key policy | **No**: external service | n/a | out of scope; operational control |
| RNG / data-key entropy quality | **No**: probabilistic | n/a | out of scope; RNG / design |
| Confinement, or absence of a function (e.g. VR-011 "no code outside `secret.rs` reads key bytes") | **No**: Verus does not check that a function is absent | Checked by compiler privacy + clippy `disallowed-methods` | not a Verus target; never describe as Verus-proven |
| Validity of C++-supplied raw pointers in the shim | **No**: property of the caller | n/a | trusted; threat-driven review |
| Async ordering / `dyn Source` / `dyn Sink` behaviour in shipped code | **No** in the installed Verus | n/a | model only or tests |

Rule of thumb: Verus proves **properties of the code's behaviour on all inputs** (functional correctness, no panic, memory safety, race freedom) for code inside `verus!` in `esdk`. It does not prove cryptographic hardness, external-service policy, probabilistic secrecy, timing, or the absence of code paths.

## Track record (for justifying effort)

Verus has verified OS memory management and microkernels (CortenMM, Atmosphere), the AWS Nitro isolation engine, confidential-VM security modules (VeriSMo), storage and distributed key-value systems, Kubernetes controllers (Anvil), and non-malleable protocol parsers (Vest). Cite the closest analogue: Vest for codec / round-trip proofs, VeriSMo or Nitro for secret-handling proofs.

## How to use this agent

1. Take a candidate property (from the threat model, a spec requirement, or the Stage 2' sweep) and find its row in the decision aid. Confirm it is Verus-provable **and** provable in place in `esdk` (or deliberately model-only).
2. Identify the category (1–4) and the concrete `esdk/src` file and function, and check whether a VR target already covers it (VR-001…VR-011 above) so work is not duplicated.
3. Hand off to the named agent with the file/function, the spec citation (with the Duvet annotation where one exists) and, for capability-driven targets, the code invariant.
4. If the property is "No" or "not here", do not create a verification target. Record it as out of scope with the reason (timing, crypto hardness, external service, probabilistic, absence-of-code, async, `prim`/`mpl` decision).

## Rules

- Only recommend targets that are genuinely Verus-provable **and** provable in this repo as it is configured; use the decision aid, do not over-promise
- Never scope cryptographic security, external-service policy, probabilistic secrecy or timing as Verus targets
- Never describe a compiler, lint (clippy) or test check as Verus-proven; never describe a model-only proof as covering the shipped code
- Ground every target in a real `esdk/src` file/function and a `spec/` citation (with the Duvet annotation where one exists)
- Respect the recorded decisions: `esdk` and all three prim panic-point cores — VR-008 (`prim/src/ecdsa.rs`), VR-006 (`prim/src/lib.rs`) and VR-009 prim half (`prim/src/hkdf.rs`) — are Verus-checked in place; the rest of `prim` and all of `mpl` are not verified in place
- Do not manufacture raw-FFI or `unsafe` proof work: there is no `unsafe` in `esdk/src`, `mpl/src` or `prim/src`
- New targets continue the existing numbering (`VR-012`, `VR-013`, …; YAML id `VR-2026-012`, …) and carry `origin: threat-driven` or `origin: capability-driven`. VR-001…VR-011 keep their ids
- Report verified counts only from the latest `0 errors` tool output; defer to the `verus` skill's soundness invariants
