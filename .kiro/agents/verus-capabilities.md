---
name: verus-capabilities
description: Reference guide to what Verus can and cannot prove, mapped onto the AWS Cryptographic Material Providers Library (MPL) in this repository. Defines the four proof categories — functional correctness against mathematical specs, zero-panic guarantees, safety of low-level/unsafe code, and concurrency with ghost permissions — and points each at concrete MPL/prim targets. Use this to decide whether a proposed property is Verus-provable, to pick the right proof category and executing agent, and to scope a verification target before writing proofs. Not an executable proof-writer — it feeds the verification-recommender and the three verus-* proof agents.
tools: ["read", "web"]
---

# What Verus Can Prove — Reference for the MPL

Verus proves that performance-critical Rust code adheres to mathematical specifications and stays free of runtime failures, statically, for **all** inputs — using the Z3 SMT solver rather than dynamic checks or example-based tests. Where a unit test samples a handful of inputs, a Verus proof is a universal statement over the entire input space.

This document is the shared capability map for the verification pipeline. It answers three questions before any proof is written:

1. **Is this property Verus-provable at all?** (vs. a test, a review comment, or an operational control)
2. **Which of the four proof categories does it fall into?**
3. **Which agent writes it, and against which MPL/`prim` code?**

It complements, and is upstream of:
- `verification-recommender` — uses this map to assign each scored target to a category and agent
- `verus-header-parsing-proofs` — functional correctness of MPL (de)serialization/reconstruction
- `verus-zero-panic` — absence of runtime panics in `prim` crypto and MPL code
- `verus-unsafe-ffi-safety` — the one `unsafe` block and the `aws-lc-rs` safe-wrapper preconditions

Toolchain: `~/verus/verus` (installed, version `0.2026.07`). Standard library: `vstd`. See the `verus` skill for the non-negotiable soundness rules (never `assume`/`admit`/`external_body` to force a pass; never claim "verified" without `0 errors`).

## Repository grounding

| Crate | Path | What lives here |
|-------|------|-----------------|
| `aws-crypto-mpl` | `mpl/src/` | Keyrings, CMMs, branch-key store, caches, material structures |
| `aws-mpl-primitives` | `prim/src/` | Safe `aws-lc-rs` wrappers: `aes_encrypt`/`aes_decrypt`, `hmac`, `digest`, `kbkdf_ctr_hmac`, `generate_random_bytes`, ECDSA, HKDF |
| spec | `spec/framework/*.md` | Formal MPL requirements (RFC 2119), Duvet-annotated in the code |

Reality check for this repo: it is almost entirely **safe** Rust. There is exactly **one** `unsafe` block (`PlaintextDataKey::zeroize`, a `write_volatile` loop in `mpl/src/structures/algorithm_suite.rs`), and the crypto boundary is `aws-lc-rs`'s **safe** API — no raw C FFI. So category 3 below is scoped to that one block plus safe-wrapper preconditions, and category 4 (concurrency) applies mainly to the storm-tracking cache.

---

## Category 1 — Functional Correctness Against Mathematical Specs

Prove that code produces the mathematically exact result the spec demands, for every valid input.

### 1a. Pre-/postcondition adherence (`requires` / `ensures`)
Prove a function's output is exactly correct on every valid input state.
- **MPL targets:** `AlgorithmSuiteId::specification` returns the spec-mandated suite table; `branch_key_materials_from_authenticated_encryption_context` returns `Ok(materials)` with a 32-byte key and valid id/version, or a `RecordMalformed` error, and nothing else; MRK matching (`aws_kms/mrk_match.rs`) decides "match" exactly per `aws-kms-mrk-match-for-decrypt.md`.
- **Agent:** `verus-header-parsing-proofs` (reconstruction/decode) or `verus-zero-panic` (when the property is "returns cleanly").

### 1b. Abstract behavioral refinement (imperative code ⟶ `Seq`/`Set`/`Map`)
Prove the executable imperative code matches an abstract mathematical structure.
- **MPL targets:** model an authenticated encryption context as `Map<Seq<u8>, Seq<u8>>` and prove `encryption_context_from_item` / `custom_encryption_context_from_authenticated_encryption_context` implement the spec's set-theoretic definition (drop `enc`, add `tablename`, select the `aws-crypto-ec:`-prefixed entries); model wrapped-key blobs and derivation inputs as `Seq<u8>`.
- **Agent:** `verus-header-parsing-proofs`.

### 1c. Round-trip parsing and serialization (exact inverses)
Prove serializer∘parser (and parser∘serializer) is the identity — no data corruption or malleability.
- **MPL targets:** `to_attribute_map` ∘ `encryption_context_from_item` is the identity on the non-`tablename`/non-`enc` attributes (`keystore/record.rs`); canonical encryption-context serialization (`keystore/encryption_context.rs`) round-trips and is canonical (order-independent input → unique bytes).
- **Note on Vest:** the [Vest](https://github.com/verus-lang/vest) framework generates zero-panic, non-malleable, formally-verified binary parsers/serializers with round-trip proofs. The MPL's (de)serialization is string/map-attribute shaped rather than a binary wire format, so Vest is not a drop-in here — but its round-trip/non-malleability *property shape* is exactly what to prove for the record and encryption-context codecs. Cite Vest as the methodology, not as a dependency.
- **Agent:** `verus-header-parsing-proofs`.

### 1d. State machine / algorithmic equivalence
Prove a protocol, store, or controller only makes valid state transitions and matches its abstract algorithm.
- **MPL targets:** cache entry lifecycle (empty → in-flight → populated → expired/evicted) in `cmc/`; the KBKDF-CTR-HMAC fixed-info construction matches NIST SP 800-108 §4.1 (`Label || 0x00 || Context || L_be32`) as consumed by the hierarchical keyring's branch-key derivation.
- **Agent:** `verus-header-parsing-proofs` (for the layout/derivation equivalence) or `verus-zero-panic` (for transition safety).

---

## Category 2 — Zero-Panic Guarantees (Absence of Runtime Errors)

Statically eliminate `panic!` without any dynamic check. A panic in a crypto/key-management library is a DoS and a potential timing oracle.

### 2a. Strict memory and slice bounds
Every index, slice, and buffer offset is provably in bounds.
- **MPL targets:** nonce/tag slicing in `raw_aes_keyring.rs`; every `&buf[a..b]` and `buf[i]` in `prim` and the keyring/keystore paths; the `ptr.add(i)` offsets in the `zeroize` loop (shared with category 3).

### 2b. Arithmetic safety (overflow / underflow)
Calculations never overflow or underflow the integer width unless wrapping is explicitly intended.
- **MPL targets:** cache byte/entry counters and TTL/expiry arithmetic in `cmc/local.rs` and `cmc/storm_tracking.rs` (add on insert, subtract on evict); length computations in derivation and wrapping.

### 2c. Division / remainder safety
Prove every denominator is non-zero.
- **MPL targets:** any modular bucketing or rate arithmetic in the caches; guard before it becomes a crash.

### 2d. Total error handling (no panicking unwrap)
Prove `copy_from_slice`, `try_into`, `.unwrap()`, `.expect()` never panic — the length guard or match makes the operation total.
- **MPL targets:** the length-checked `copy_from_slice` calls in `prim::hmac`, `prim::digest`, `DigestContext::finish`; `check_sig_len` before `ecdsa_sign` copies; the `<[u8;32]>::try_from(plaintext)` branch-key length check in `record.rs`; the `sign_fixed_len` retry loop (also prove it terminates within `MAX_SIGN_ATTEMPTS`).
- **Agent:** `verus-zero-panic` for all of category 2.

---

## Category 3 — Safety of Low-Level and `unsafe` Code

Where Rust requires manual inspection inside `unsafe { }`, Verus mechanically proves the safety invariants.

### 3a. Raw-pointer correctness
Prove pointer arithmetic, dereferences, and writes are in-bounds, aligned, and non-corrupting.
- **MPL target (the real one):** `PlaintextDataKey::zeroize` — prove every `ptr.add(i)` has `i < len <= capacity` (in-bounds), and the post-state is all zeros (no residual key material). This is the single highest-value low-level proof in the repo.

### 3b. FFI boundaries
Prove memory buffers passed across an FFI boundary keep valid pointers and correct sizes.
- **Scope note for this repo:** the crypto backend (`aws-lc-rs`, over `aws-lc`) is reached through its **safe** Rust API — there is no raw C FFI, no `*mut u8` to C, no manual `set_len`/free. So there is no raw-FFI-pointer proof to write here. What *is* provable and worth proving: the **safe-wrapper preconditions** that keep those calls on their clean path — key length ∈ {16,24,32}, GCM nonce length 12, output buffer exactly the digest/signature length — so a wrong size is rejected as `Err` rather than causing UB, and no oversized buffer leaks residual bytes. (The general OpenSSL/aws-lc raw-buffer FFI proof is a Verus capability; it just does not apply to this codebase's current shape.)
- **Agent:** `verus-unsafe-ffi-safety` for both 3a and 3b.

### 3c. Interior mutability & custom layouts
Formally verify structures relying on `UnsafeCell`, custom allocators, or hand-rolled memory layout.
- **MPL target:** if the storm-tracking cache uses interior mutability for shared bookkeeping, verify its layout invariants; otherwise not applicable.

---

## Category 4 — Concurrency and Linear Ghost Permissions

Verus integrates Rust's borrow checker with linear ghost types to verify concurrent synchronization.

### 4a. Lock-free / custom locking protocols
Verify reader-writer locks, fine-grained cursors, and synchronization protocols are correct.
- **MPL target:** the storm-tracking cache (`cmc/storm_tracking.rs`) coordinates concurrent requests so only one derivation is in flight per key (the "storm"/stampede defense). Verifying the single-inflight invariant and safe hand-off of the in-flight result is the concurrency target here.

### 4b. Global state invariants (no data races, no intermediate leaks)
Prove multi-threaded access to a shared resource cannot race or expose an unverified intermediate state.
- **MPL target:** shared access to the cryptographic-materials cache must never return a partially-populated entry or a stale-after-evict entry; prove the invariant across all interleavings.
- **Agent:** concurrency proofs are advanced; route to `verus-zero-panic` for the safety/no-panic slice and flag the ghost-permission work explicitly for a specialist (these often need `tracked` ghost state and are the most effort-intensive).

---

## Provable vs. Not-Here — a decision aid

Use this to avoid scoping a target Verus can't help with in *this* repo.

| Property | Verus-provable? | In this repo? | Route to |
|----------|-----------------|---------------|----------|
| Record/context reconstruction returns spec-correct struct or error | Yes | Yes | `verus-header-parsing-proofs` |
| Encryption-context codec round-trips / is canonical | Yes | Yes | `verus-header-parsing-proofs` |
| No panic in `prim` crypto calls on any input | Yes | Yes | `verus-zero-panic` |
| Cache counter arithmetic never overflows/underflows | Yes | Yes | `verus-zero-panic` |
| `zeroize` writes every byte, in bounds, no residue | Yes | Yes (the one unsafe block) | `verus-unsafe-ffi-safety` |
| aws-lc-rs safe-wrapper length preconditions hold | Yes | Yes | `verus-unsafe-ffi-safety` |
| Storm-tracking single-inflight invariant under concurrency | Yes | Yes (advanced) | specialist + `verus-zero-panic` |
| Raw C-pointer FFI buffer soundness | Yes (Verus capability) | **No raw FFI here** | n/a — prove safe-wrapper preconditions instead |
| AES-GCM / ECDSA are cryptographically secure | **No** (that's crypto analysis, not code proof) | n/a | out of scope — `aws-lc-rs`/design responsibility |
| KMS/DynamoDB enforce the right access policy | **No** (external service) | n/a | out of scope — operational control |
| Branch key is unguessable / entropy quality | **No** (probabilistic) | n/a | out of scope — RNG/design responsibility |

Rule of thumb: Verus proves **properties of the code's behavior on all inputs** (correctness, no-panic, memory safety, race freedom). It does **not** prove cryptographic hardness, external-service policy, or probabilistic secrecy — do not scope those as verification targets.

## Real-world Verus track record (for confidence / analogy)

Verus has verified, in research and production benchmarks: OS page tables and kernel memory management (CortenMM), microkernels (Atmosphere), the AWS Nitro isolation engine, confidential-VM security modules (VeriSMo), crash-safe storage and distributed key-value stores, Kubernetes controllers (Anvil), and zero-panic non-malleable protocol parsers (Vest). The MPL targets above are squarely in the same class: low-level, high-assurance systems code where a proof-grade guarantee is worth the effort. Cite the closest analogue when justifying effort in a recommendation (e.g. Vest for the codec round-trip proofs, VeriSMo/Nitro for the secret-zeroization proof).

## How to use this agent

1. Given a candidate property (from the threat model or a spec requirement), find its row in the decision aid — confirm it is Verus-provable and present in this repo.
2. Identify the category (1–4) and the concrete `mpl/`/`prim/` target.
3. Hand off to the named agent with the target file/function and the spec citation.
4. If the property is "Not-Here" or "No", do not create a verification target — record it as out-of-scope with the reason (crypto hardness, external service, probabilistic), so the recommender does not waste effort on it.

## Rules
- Only recommend targets that are genuinely Verus-provable **and** present in this codebase — use the decision aid, do not over-promise
- Never scope cryptographic security, external-service policy, or probabilistic secrecy as Verus targets
- Ground every recommendation in a real `mpl/`/`prim/` file/function and a `spec/framework` citation (with the Duvet annotation where one exists)
- Respect the reality that this repo has one `unsafe` block and a safe crypto boundary — do not manufacture raw-FFI proof work
- Defer to the `verus` skill's soundness invariants; this agent scopes work, it does not relax proof standards
