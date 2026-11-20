---
name: verus-capabilities
description: Reference guide to what Verus can and cannot prove, mapped onto the crates of the library under verification (named in the library profile). Defines the four proof categories (functional correctness against mathematical specs, zero-panic guarantees, safety of low-level/unsafe code, concurrency with ghost permissions) and points each at the library's Verus-checked code and its existing targets (including ordering via typestate tokens, Category 1e). Use it to decide whether a proposed property is Verus-provable here, to pick the proof category and executing agent, and as the provability gate the verification-recommender applies to every candidate. Not an executable proof-writer; it feeds the verification-recommender and the three verus-* proof agents.
tools: ["read", "web"]
---

# What Verus Can Prove: Reference

**Library profile.** Everything specific to the library under verification (crates and paths, commands, result-line rule, spec and traceability, trust boundaries and the TCB, gate modules, target ids and done targets, maintained docs, CI checks, environment limits, packaging decisions, domain tables) is in the library profile at `.kiro/verification-profile/verification-profile.yaml`, with prose appendices next to it. Read it first. References below have the form profile `field.path`. This file holds only the generic method.

Verus proves that Rust code meets a mathematical specification and is free of runtime failures, statically, for **all** inputs, using the Z3 SMT solver. A unit test samples some inputs; a Verus proof is a statement over the whole input space.

This document is the shared capability map for the verification pipeline. It answers three questions before any proof is written:

1. **Is this property Verus-provable at all?** (vs. a test, a compiler/lint check, a review comment or an operational control)
2. **Which of the four proof categories does it fall into?**
3. **Which agent writes it, and against which code (profile `crates`)?**

It is upstream of:
- `verification-recommender`: uses this map (a) as the Stage 2' map of where to look for capability-driven targets and (b) as the "can Verus prove this, here?" gate for every candidate, threat-driven or capability-driven
- `verus-header-parsing-proofs`: functional correctness of message header / body parsing and layout
- `verus-zero-panic`: absence of runtime panics
- `verus-unsafe-ffi-safety`: `unsafe` and FFI-boundary safety (see Category 3 and profile `unsafe_surface`)

The non-negotiable soundness rules are in the `verus` skill: never use `assume`, `admit`, `#[verifier::external_body]` or `#[verifier::external]` to force a pass; a proof counts only when the tool prints `0 errors`. Every claim in this file uses the levels of the **honesty ladder** in the `verus` skill (`.kiro/skills/verus/SKILL.md`, "Honesty ladder"). This agent scopes work. It does not relax proof standards.

## Toolchain and how to run

- Version pins and the binary: profile `toolchain` (`verus_version`, `rust_toolchain`, `verus_binary`, `vstd_pin`, `cargo_verus`).
- **In-crate (shipped code):** for each crate with `verus_enabled: true` in profile `crates[]`, run `verify_cmd` for every entry of `feature_sets`. Read the result line chosen by `result_line`: the `verification results::` line printed right after `Checking <crate name> v…`, never by position (dependencies such as vstd print their own lines first, and a cached crate prints none). `cache_bust` forces a re-check. Details: "Running Verus" in the `verus` skill.
- **Standalone models:** profile `models` (`verify_cmd`, `files[]` with each model's status, `status_file`). Models import nothing from the crates and can drift from the code; check each model's status before relying on it.

## Current verified state

Counts: read them from the live output of the commands above and from the source named in profile `artifacts.counts_source`. Do not copy a count from this file or from the profile.

Never claim a property is verified from reading code.

## Repository grounding

Which crates are Verus-checked, which are dependencies built with plain rustc, where the gate modules, the trusted specs and any `unsafe` live: profile `crates` (`role`, `verus_enabled`, `source_dirs`, `unsafe`), `unsafe_surface`, `tcb`, `trust_boundaries`, `typestate_gates`, `spec`, `traceability`. For the library's grounding table and reality check (what is absent, what is trusted): profile appendix `targets.md` §Repository grounding.

Only code inside `verus! { }` in a crate with `verus_enabled: true` is verified. A dependency built by `cargo-verus` with plain rustc is not verified; its invariants count as `code_reading` at most.

## In-crate constraints (decide what is provable *here*)

From the `verus` skill and the library's proofs report:
- Verus cannot verify `async fn` or `dyn` trait objects. Decision logic goes in synchronous cores inside `verus!`; async readers and writers over `dyn` streams stay as thin **unverified** adapters ("Core/adapter pattern" in the `verus` skill; the library's adapter names: profile appendix `idioms.md`).
- A verified fn cannot call or name items declared outside `verus!` (dependency types, the crate's error type, functions of another crate) unless they get a spec at the trusted boundary ("Trusted boundary" in the `verus` skill; profile `tcb.crate_rules` says which crates may do this). Otherwise those calls stay in unverified adapters, listed by name as the trusted base.
- Verus cannot check the order of `.await` steps directly. An order can still be covered when it is expressed as a data dependency on a token (Category 1e).
- A trait declared in `verus!` but implemented outside it has its `ensures` trusted silently. Give such traits `requires` only.
- `to_be_bytes` is not modeled by vstd. Use the library's verified encoders (profile appendix `idioms.md`).
- Never hide exec code behind `#[cfg(not(verus_keep_ghost))]`. Keep one definition per type.
- A property whose only proof would be `Ok ⇒ Ok` over a trusted third-party result is not worth an in-crate proof.

---

## Category 1: Functional correctness against mathematical specs

### 1a. Pre-/postcondition adherence (`requires` / `ensures`)
- Decision cores (field classification, count and length checks, accept/reject decisions) proven to return the spec result for every input.
- See profile appendix `targets.md` §Category 1a for what is done in this library.
- **Agent:** `verus-header-parsing-proofs`.

### 1b. Abstract behavioural refinement (exec code ⟶ `Seq` / `Map`)
- Exec code proven equal to a spec-level `Seq` / `Map` description (byte layouts, accessors against a closed `view()`).
- See profile appendix `targets.md` §Category 1b for what is done in this library.
- **Agent:** `verus-header-parsing-proofs`.

### 1c. Round-trip parsing and serialization
- Verified encoders and decoders proven to be exact inverses. A full serialize/parse round-trip is provable only for sync code; parsers and serializers over `dyn` streams allow only sync sub-pieces.
- See profile appendix `targets.md` §Category 1c for what is done and blocked in this library.
- **Note on Vest:** [Vest](https://github.com/verus-lang/vest) generates verified, non-malleable binary parsers/serializers with round-trip proofs. Cite it as methodology for the property shape, not as a dependency.
- **Agent:** `verus-header-parsing-proofs`.

### 1d. State machine / algorithmic equivalence
- Sequence checks, counters and their lemmas, proven on the sync cores; the async loop that threads the state is unverified glue.
- See profile appendix `targets.md` §Category 1d for what is done in this library.
- **Agent:** `verus-header-parsing-proofs`.

### 1e. Ordering via typestate tokens

Verus cannot check the order of `.await` steps. The order can still be covered in shipped code when it is written as a data dependency: the guarded step takes a token as an argument, and only a verified sync gate can make the token.

- **Token shape:** a struct inside `verus!` with private fields (often `Ghost` fields), a `#[verifier::type_invariant]` that records what the check established, no `Clone` or `Copy`, in its own module (Rust field privacy is per module).
- **Verus-proven (ladder level 1 for the gate):** the gate returns a token only on the success path of the check. Its `ensures` and the type invariant say so.
- **Compiler-enforced (ladder level 2 for the order):** code outside the module cannot build a token, and the guarded step cannot be called without one. This does not depend on how the async runtime schedules the steps.
- **Still trusted:** the adapters pass the real check results to the gate; the guarded step is the only entry point to the protected action (checked by grep, not by the compiler); the token is not tied to one particular message; the async wiring around the gate.
- **Mutation classes to record** ("Mutation testing" in the `verus` skill): minting a token on a failure path is Verus-caught; building a token outside the module or calling the step without one is compiler-caught (`E0451`, `E0425`, `E0616`, `E0061`, `E0308`); deleting the token parameter and its argument **compiles**, so it is review-only.
- **Done in this library:** profile `typestate_gates` (module, tokens, targets) and profile appendix `targets.md` §Category 1e.
- **Agent:** `verus-header-parsing-proofs` (same as 1d).

---

## Category 2: Zero-panic guarantees

### 2a. Slice and buffer bounds / 2b. arithmetic / 2c. division
- Indexing, slicing, arithmetic and division in sync cores inside `verus!` proven never to panic or overflow.
- A sweep of indexing/arithmetic sites outside `verus!` is a capability-driven source of targets (only sync, `verus!`-extractable sites qualify). Which lints leave such sites unblocked: profile appendix `idioms.md`.
- See profile appendix `targets.md` §Category 2 for what is done and what is open in this library.

### 2d. Total error handling (no panicking `unwrap` / `expect`)
- Every input-dependent `unwrap` / `expect` is either proven unreachable or replaced by total error handling. A compile-time constant over a literal that cannot fail is not a target. Re-check every site before scoping.
- Cores that call a trusted third-party library are proven against its trusted specs; every trusted call is assumed not to panic unless its TCB row has a `requires`.
- See profile appendix `targets.md` §Category 2d for the library's `.expect` inventory and done cores.
- **Agent:** `verus-zero-panic` for all of category 2.

---

## Category 3: Safety of low-level and `unsafe` code

- **Surface:** profile `unsafe_surface` (`in_crate`, `elsewhere[]`, `confirm_cmd`). Run `confirm_cmd` before scoping. If there is no in-crate `unsafe`, there is no raw-pointer target.
- **Pointer validity supplied by a foreign caller** (for example a C or C++ caller of a shim) is not Verus-provable: it is a property of the caller, so it is trusted. Treat such a concern as threat-driven, not a Verus target, unless a Rust-side null/ownership decision can be extracted into a sync core.
- **The trusted third-party boundary** is the TCB list (profile `tcb.modules`, `tcb.doc_section`), owned by the agent named in profile `tcb.owner_agent`. Its format and rules are in "Trusted boundary" in the `verus` skill.
- **Safe-wrapper preconditions** enforced inside a third-party library (its constructors return `Err`) are a trusted boundary; Verus cannot prove them. Only the Rust-side buffer and decision safety around the call is in-crate.
- See profile appendix `targets.md` §Category 3 for this library's facts (surface, zeroization, trusted boundary).
- **Agent:** `verus-unsafe-ffi-safety` if a target ever qualifies.

---

## Category 4: Concurrency and linear ghost permissions

- Applies only to a hand-written lock or permission protocol in sync code. Async/tokio concurrency cannot be verified. The order of sequential async steps is a different question; see Category 1e.
- See profile appendix `targets.md` §Category 4 for whether this applies to the library.

---

## Provable vs. not-here: decision aid

The rows below are generic. The library's own rows (with its target ids): profile appendix `targets.md` §Decision aid rows.

| Property | Verus-provable? | Here, in place? | Route to |
|----------|-----------------|-----------------|----------|
| A sync decision core (field, count or key-length check) returns the spec result | Yes | Yes, if the core is inside `verus!` in a crate with `verus_enabled: true` | `verus-header-parsing-proofs` |
| A layout (AAD, IV, frame prefix) equals the spec bytes | Yes | Yes, for sync code inside `verus!` | `verus-header-parsing-proofs` |
| Encoder / decoder round-trip identity lemma | Yes | Yes, for the verified encoders that exist | `verus-header-parsing-proofs` |
| A sync function over std `BTreeMap` / `BTreeSet` returns a spec-level result (filter, restrict) | Yes, relative to vstd's collection specs and their `obeys_cmp` precondition | Yes, inside `verus!`; a key type whose `obeys_cmp` vstd does not prove needs a TCB row (SKILL Idioms) | `verus-header-parsing-proofs` |
| Sync indexing / arithmetic cores never panic | Yes | Yes, if extractable into `verus!` | `verus-zero-panic` |
| Wrapper output lengths and buffer effects against trusted third-party specs | Yes, relative to the TCB rows | Yes, in a crate whose `tcb.crate_rules` allow boundary specs | `verus-zero-panic`; TCB rows owned by the agent in profile `tcb.owner_agent` |
| Anything inside a crate with `verus_enabled: false`, in place | Yes in kind | **No**: that crate is not Verus-checked | out of scope here |
| Constant-time comparison / no timing leak | **No**: Verus does not model timing | n/a | out of scope; review / tooling |
| A cipher, signature scheme or KDF is cryptographically secure | **No**: crypto analysis, not code proof | n/a | out of scope; crypto library / design |
| An external service enforces the right key policy | **No**: external service | n/a | out of scope; operational control |
| RNG / data-key entropy quality | **No**: probabilistic | n/a | out of scope; RNG / design |
| Confinement, or absence of a function (for example "no code outside one module reads key bytes") | **No**: Verus does not check that a function is absent | Checked by compiler privacy + lints | not a Verus target; never describe as Verus-proven |
| Validity of raw pointers supplied by a C/C++ caller | **No**: property of the caller | n/a | trusted; threat-driven review |
| Async ordering in shipped code | **Yes**, if the order can be expressed as a data dependency on a token minted by a sync verified gate (Category 1e). Verus proves the gate; the compiler enforces the order | Yes, where a gate exists (profile `typestate_gates`) | `verus-header-parsing-proofs` |
| `dyn` stream behaviour, or an order that cannot be written as a token | **No** in the installed Verus | n/a | model only or tests |

Rule of thumb: Verus proves **properties of the code's behaviour on all inputs** (functional correctness, no panic, memory safety, race freedom) for code inside `verus!` in crates with `verus_enabled: true`. It does not prove cryptographic hardness, external-service policy, probabilistic secrecy, timing, or the absence of code paths.

## Track record (for justifying effort)

Verus has verified OS memory management and microkernels (CortenMM, Atmosphere), the AWS Nitro isolation engine, confidential-VM security modules (VeriSMo), storage and distributed key-value systems, Kubernetes controllers (Anvil), and non-malleable protocol parsers (Vest). Cite the closest analogue: Vest for codec / round-trip proofs, VeriSMo or Nitro for secret-handling proofs.

## How to use this agent

1. Take a candidate property (from the threat model, a spec requirement, or the Stage 2' sweep) and find its row in the decision aid (generic rows above, library rows in profile appendix `targets.md` §Decision aid rows). Confirm it is Verus-provable **and** provable in place in a crate with `verus_enabled: true` (or deliberately model-only).
2. Identify the category (1–4, including 1e) and the concrete file and function under profile `crates[].source_dirs`, and check whether a target already covers it (profile `targets` and the status oracle named in profile `artifacts.status_oracle`) so work is not duplicated.
3. Hand off to the named agent with the file/function, the spec citation (with the traceability annotation where one exists, profile `traceability`) and, for capability-driven targets, the code invariant.
4. If the property is "No" or "not here", do not create a verification target. Record it as out of scope with the reason (timing, crypto hardness, external service, probabilistic, absence-of-code, an order that cannot be written as a token, a crate that is not Verus-checked).

## Rules

- Only recommend targets that are genuinely Verus-provable **and** provable in this repo as it is configured; use the decision aid, do not over-promise
- Never scope cryptographic security, external-service policy, probabilistic secrecy or timing as Verus targets
- Label every claim with its honesty-ladder level (`verus` skill). Never call a compiler, lint, test, model, code-reading or trusted fact Verus-proven; for a typestate gate, only the gate is Verus-proven and the order is compiler-enforced
- Ground every target in a real file/function under profile `crates[].source_dirs` and a spec citation (profile `spec`; with the traceability annotation where one exists)
- Respect the recorded decisions: crates with `verus_enabled: true` are Verus-checked in place (only code inside `verus!` is verified); crates with `verus_enabled: false` are not
- Do not manufacture raw-FFI or `unsafe` proof work: check profile `unsafe_surface` first
- New targets take the next free id (profile `ids.next_free`, format `ids.target_format`, YAML `ids.yaml_id_format`) and carry `origin: threat-driven` or `origin: capability-driven`. Re-check with profile `ids.next_free_check` before using it. Existing ids keep their numbers; retired ids are not reused
- Report verified counts only from the latest `0 errors` tool output; defer to the `verus` skill's soundness invariants
