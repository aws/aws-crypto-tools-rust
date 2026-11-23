---
name: verus
description: Write, run, and debug Verus formal verification proofs for Rust code. Use when verifying Rust functions with requires/ensures contracts, proving absence of panics or arithmetic overflow, proving array/slice bounds safety, modeling byte buffers as Seq<u8>, writing proof functions and lemmas, verifying unsafe FFI code, or when encountering Verus verification errors. Covers spec/proof/exec function modes, vstd, and the ~/verus/verus CLI.
---

# Verus Formal Verification

Verus is a tool for verifying the correctness of Rust code. Developers write specifications (requires/ensures) and Verus statically proves the executable Rust always satisfies them for all possible inputs, using the Z3 SMT solver.

**Library profile.** Everything specific to the library under verification (crates and paths, commands, result-line rule, spec and traceability, trust boundaries and the TCB, gate modules, target ids and done targets, maintained docs, CI checks, environment limits, packaging decisions, domain tables) is in the library profile at `.kiro/verification-profile/verification-profile.yaml`, with prose appendices next to it. Read it first. References below have the form profile `field.path`. This file holds only the generic method.

## ABSOLUTE INVARIANTS — NEVER VIOLATE

These rules are non-negotiable. Violating any of them produces proofs that are unsound, misleading, or worthless — which is worse than no proof at all in a cryptographic library.

1. **NEVER weaken a proof to make it pass.** Do not add `assume(...)`, `#[verifier::external_body]`, `#[verifier::external]`, or `admit()` to bypass a failing proof without asking the human who runs the agent. These tell Verus to trust an unproven claim. If a proof won't go through, ask to fix the code or the specification — do not silence the verifier. The one sanctioned use of `external_body` is on the wrapper struct that `#[verifier::external_type_specification]` requires; see "Trusted boundary" below.

2. **NEVER report a proof as verified unless the Verus run prints `0 errors`.** (The default binary is `~/verus/verus`.) Always run the tool and show the actual output. Do not claim success from reading the code alone.

3. **NEVER add a `requires` clause that the real callers cannot satisfy.** Preconditions must be satisfiable in the actual call sites. An over-constrained precondition creates a proof that is vacuously true but protects nothing.

4. **NEVER change the specification (`ensures`) to match buggy behavior.** The specification is the source of truth, derived from the library's specification and threat model. If the code violates the spec, the code is wrong — report it as a finding (see "Stop and report findings"); do not rewrite the `ensures` to describe the bug.

5. **NEVER use `assume(false)` or contradictory `requires` to trivially discharge obligations.** A contradiction in preconditions makes every postcondition provable and every proof meaningless.

6. **NEVER delete or comment out a failing `assert`, `invariant`, or `ensures` to get a green result.** If you cannot prove it, leave it failing and explain why.

7. **NEVER mark `unsafe` FFI code as `external_body` and call it "verified."** Wrapping unsafe code to hide it from Verus is the opposite of proving its safety. Model the FFI contract explicitly (see `verus-unsafe-ffi-safety` agent) or state clearly that it remains unverified.

8. **ALWAYS preserve the meaning of the code.** Proof annotations (`spec`, `proof`, `requires`, `ensures`, `invariant`, `assert`) are ghost and must not change runtime behavior. Never alter executable logic solely to make verification easier without confirming the behavior is still correct.

9. **ALWAYS keep `decreases` clauses honest.** A `decreases` expression must genuinely decrease and be bounded below. Never fabricate one that Verus happens to accept but does not reflect real termination.

10. **When blocked, escalate — do not fake.** If a property cannot be proven after genuine effort, say so explicitly, describe what blocks it, and leave the obligation visible. An honest "unproven" is infinitely more valuable than a dishonest "verified."

11. **No `#[cfg(not(verus_keep_ghost))]` regions. No exceptions.** Hiding code from Verus this way still compiles and runs it, so the green result silently leaves that code out. Do these instead:
    - The logic you want proven goes inside `verus! { }`.
    - A third-party or std call that a verified function must make gets a spec through `assume_specification` (or its type through `external_type_specification`). See "Trusted boundary".
    - Code Verus cannot handle at all (async, `dyn`, building the crate's error type, `format!` strings) stays in a thin adapter **outside** `verus!`. Name that adapter as unverified glue in the docs.

12. **ALL structs and traits MUST have a single definition shared between cargo and Verus.** NO `cfg`-gated duplicate struct/trait definitions. If Verus sees one definition of a type and cargo compiles a different one, every proof about that type is meaningless — the verified model and the shipped code silently diverge. Enforce this by:
    - Applying `#[cfg(verus_keep_ghost)]` to **individual ghost fields**, never to an entire struct or trait.
    - Defining traits **inside** `verus! { }` blocks so ghost items (spec functions, proof obligations) are automatically erased for the cargo build while the type itself stays identical.
    There must be exactly one source-of-truth definition per struct and per trait.

13. **Verify what you claim.** When completing a task, confirm the target function is actually inside a `verus! { }` block by inspecting the source — not just by checking the verification count. A rising "N verified" number means nothing if the function you were asked to prove was silently excluded from verification. Always trace the specific target function to a `verus!` block and confirm its `requires`/`ensures` are present before reporting the task done.

14. **Type-invariant chain.** A proof about a value must be tied to the code that made the value. When a lemma relies on a fact about a value of some type, put that fact in the type's `#[verifier::type_invariant]`, let only verified functions build the type (private fields), and have the lemma take the value and call `use_type_invariant`. Do not write lemmas over a free spec predicate that no running code is shown to satisfy. Ghost fields must hold the real values from construction, never `arbitrary()`.

15. **Mutation-test every new obligation.** Every new `ensures`, `requires`, type invariant, loop invariant and `decreases` gets at least one mutation that must make the check fail. "0 errors" alone can be a tautology. Record each mutation, its result line and the revert. See "Mutation testing" below.



## Honesty ladder

This is the one list of evidence levels. Every agent, doc and commit message labels each claim with one of these levels. Agents refer to this section; they do not keep their own version.

| Level | Label | What it means | Evidence needed |
|---|---|---|---|
| 1 | `verus_in_crate` (Verus-proven in shipped code) | The shipped function is inside `verus!` and its `ensures` hold | the crate's Verus run prints `0 errors`; the function is traced to the `verus!` block (invariant 13); each obligation is mutation-tested and Verus-caught |
| 2 | `verus_gate_compiler_order` (Verus-proven gate, compiler-enforced order) | Verus proves a token is created only when a check passed; the Rust compiler enforces that the guarded step cannot run without the token | level 1 for the gate; compiler-caught mutations for the order; the trusted rest listed |
| 3 | `compiler_lint` (compiler-enforced) | Rust types, field privacy, or a clippy lint rule something out | the build or lint fails on the forbidden code |
| 4 | `model_only` | Proven on a standalone model that does not import the shipped code | the model's `0 errors`; the model can drift from the code |
| 5 | `tested` | Tests exercise the property | test names; tests sample inputs, they do not prove |
| 6 | `code_reading` | A person or agent read the code and found it holds. This includes facts that rest on a dependency's invariants that nothing checks | file and function cited; no tool checks it |
| 7 | `trusted` | Assumed true, written down as a trusted-boundary (TCB) row with a source | a TCB row (see "Trusted boundary") |
| 8 | `assumed_labeled` | A trusted assumption about third-party behavior that its docs do not fully state. Named and flagged | a TCB row marked as a labeled assumption |
| 9 | `deferred` / `not_started` | No current evidence | the reason |

Rules:
- Only level 1 and the gate part of level 2 may be called "Verus-proven". Never use that word for a compiler check, a lint, a model, a test, code reading, or a trusted assumption.
- One target can sit on several levels. Report each part at its own level (for example: the decision is level 1, the order is level 2, constant time is level 7).
- When a target moves up a level, check every doc that cites it.

## Mutation testing

A proof that passes is not yet evidence. It may prove a tautology (an `ensures` that restates the `requires`, or a check that holds for any code), or the real logic may sit outside `verus!`. Mutation testing shows the obligation constrains the code.

**Tautology check.** Before a proof counts, answer both:
- Does the target function sit inside `verus!` (invariant 13)?
- Does at least one realistic change to the code (drop a guard, flip a comparison, off-by-one, return the wrong variant, mint a token on the failure path) make Verus fail?
If no mutation fails, the obligation is a tautology or does not reach the code. Fix the spec or report it; do not count it.

**Recipe.**
1. Run the crate's Verus command and record the baseline `verification results::` line.
2. Save a copy of the file. Apply one mutation.
3. Bust the cache (profile `crates[].cache_bust`: touch the file the crate's verify command watches) and run the same command. Record the result line and the first error lines.
4. Revert. Compare the file byte-for-byte with the saved copy (`cmp`, or `git diff --exit-code` on that file). Record "reverted: yes".
5. Repeat for each new obligation. At least one mutation per new `ensures`, `requires`, type invariant, loop invariant and `decreases`.

**Log format** (one row per mutation, kept in the task's `logs/mutations.md` and summarized in the commit message).

**Example from the ESDK profile:**

| Id | Mutation | Result line | Errors | Reverted |
|---|---|---|---|---|
| M1 | `digest_core`: remove the length guard | `verification results:: 17 verified, 1 errors` | postcondition not satisfied; precondition not satisfied | yes |

**Outcome classes.** Record which tool caught each mutation:
- **Verus-caught:** the result line shows at least one error. Only this class supports a level 1 claim.
- **Compiler-caught:** `cargo build` fails, for example `E0451` (private field), `E0425` (name not in scope), `E0616` (private field access), `E0061` (wrong number of arguments), `E0308` (type mismatch). This supports a level 2 or level 3 claim.
- **Review-only:** the mutation compiles and verifies. Example: deleting a token parameter and its argument. Say so in the docs; only code review catches it.
- **Adapter glue, never caught:** a change in an unverified adapter outside `verus!`. Neither tool sees it. State this; do not present the adapter as covered.

## Trusted boundary

Verus cannot see into third-party crates or most of std. The sanctioned way to reason about such code is to give it a spec and then prove the code around it. Everything given a spec this way is trusted, not proven. For a function whose core is a third-party crypto call, only the logic around the call is provable, against trusted specs of the call.

**Allowed constructs:**
- `#[verifier::external_type_specification]` for an opaque type. Verus requires `#[verifier::external_body]` on its wrapper struct; that pairing is allowed.
- `assume_specification[...]` for a function Verus cannot see.
- `#[verifier::external_trait_specification]` for a std trait a spec must name.

**Not allowed:** `#[verifier::external_body]` or `#[verifier::external]` on a function to force a pass, `assume(...)`, `admit()`.

**Rules for each spec:**
- Restate the real contract. Never weaken it. Take `requires` from the documented contract and `ensures` only from what the docs or source support. Cite the source line.
- **A function with no `requires` is trusted not to panic on any input.** Say this in the TCB list.
- Each new TCB row needs the user's approval before it is committed. Record the approval in the task's "Decisions (do not re-decide)" block.

**TCB table format.** Every trusted spec is one row.

**Example from the ESDK profile:**

| Id | Item | Spec (`requires` / `ensures`) | Why trusted (kind and source) |
|---|---|---|---|
| A2 | `digest::digest(algorithm, data)` | `ensures spec_digest_len(&d) == spec_digest_output_len(algorithm)` | TRUSTED length (`digest.rs:194-201`) |

Kinds: *naming* (introduces a symbol, claims nothing), *TRUSTED* (a real assumption, with source), *labeled assumption* (not fully stated by the docs; ladder level 8), *Rust type fact* (for example, a `&mut [u8]` cannot change length). The agent named in profile `tcb.owner_agent` owns the TCB list (profile `tcb`).

## Stop and report findings

When the code does not match the target, stop. Do not fix behavior silently. This covers:
- the property is false for the shipped code;
- a check works only one way (for example, rejects A without B but accepts B without A);
- the code is stricter or looser than the spec;
- the proof would need a new check, a changed error, or a changed error order.

Record it as a finding with an id prefixed by the target (profile `ids.finding_format`, for example `<target id> Fk`). Give the exact location, what the spec says, what the code does, and the options with a recommendation. Then wait for the user's decision. Write that decision word for word in a "Decisions (do not re-decide)" block in the task notes, and pass the block forward to later steps.

## Environment

- **Binary:** `~/verus/verus` (installed via binary release)
- **Version check:** `~/verus/verus --version`
- **Required toolchain:** the Rust version that the Verus release names (install with `rustup install <version>`)
- **Z3:** bundled with the Verus release (no separate install)
- **Pins:** profile `toolchain` (`toolchain.verus_version`, `toolchain.verus_binary`, `toolchain.rust_toolchain`, `toolchain.vstd_pin`, `toolchain.cargo_verus`)

## Running Verus

Verify a single file:
```bash
~/verus/verus path/to/file.rs
```

Verify a crate in place via Cargo (`cargo-verus` must be on `PATH`):
```bash
cargo verus verify
```
`cargo-verus` builds the dependencies with plain rustc and verifies only the crates whose `Cargo.toml` sets `[package.metadata.verus] verify = true`.

In a library with a profile, run profile `crates[].verify_cmd` for each feature set in `crates[].feature_sets`, read the line chosen by `crates[].result_line` (never by position; dependencies such as vstd print their own lines first, and a cached crate prints none), and bust the cache with `crates[].cache_bust`. If a dependency's count differs between runs, explain it; compare like with like. Standalone models: profile `models.verify_cmd`.

Success output looks like:
```
verification results:: N verified, 0 errors
```
Each verified crate prints its own `verification results::` line right after its `Checking <crate name> v...` line. Read that line for the crate you changed.

## Core/adapter pattern

Verus cannot verify async code or trait objects (`dyn`). When shipped code is async or works over `dyn` readers and writers:
- Put the decision logic in pure synchronous cores inside `verus! { }`, with `requires`/`ensures`.
- Keep the async fns as thin **unverified** adapters outside `verus!`: they read the bytes, call the core, and build the crate's error type. Name them as unverified glue in the docs.
- Never hide exec code behind `#[cfg(not(verus_keep_ghost))]` (invariant 11). Keep one definition per type: move an enum into `verus!` unchanged, never duplicate it (invariant 12).
- Keep traceability comments next to the code they annotate (markers in profile `traceability.markers`).
- Ordering between async steps: typestate tokens, Category 1e in `verus-capabilities`; gate modules in profile `typestate_gates`.

The library's core and adapter names are in profile appendix `idioms.md`.

## Idioms (probe-confirmed on Verus 0.2026.07.12; re-probe on another version)

- Slice element write: `slice[i] = v;` (the `.set()` method is deprecated).
- Postconditions on `&mut` params: use `final(x)` and `old(x)`, not bare `x`.
- `Seq` ops in `ensures`: apply the view first, e.g. `x@.subrange(a, b)`.
- `u32::to_be_bytes` / `u64::to_be_bytes` are NOT modeled by vstd. Do not reach for `assume_specification`; instead define a `spec fn` big-endian source of truth and a verified exec helper, and document the one-line equivalence to std.
- Take fixed-size `[u8; N]` params; spec indexing `b[0]` works as-is.
- Big-endian: `u16::from(u8)` (and `u32`/`u64`) times constant multipliers. Avoid `as` casts in exec code where the crate enables the clippy `cast_*` lints.
- `usize::try_from(u64)` / `usize::try_from(u32)` and `usize::from(u8)` are specified.
- A const shift such as `1 << 20` must be written `1_048_576`.
- `derive(Clone, Copy, Debug, Default, Eq, Hash, PartialEq)` and `#[default]` on an enum inside `verus!` are accepted.
- `ensures` may use `r is Variant` and `r matches E::V(n) ==> ...`.
- Doc-comment every new item (where the crate enables `missing_docs`), and add in-module `#[cfg(test)] mod tests` for new cores.
- `const`s inside `verus!` are accepted and can be named in specs.
- `&str` consts inside `verus!` need an explicit `&'static str` (Verus rejects the elided lifetime); add `#[expect(clippy::redundant_static_lifetimes, reason = …)]`. Their bytes in specs: `vstd::string::StringSliceAdditionalSpecFns::spec_bytes(s)`; `str::as_bytes` ensures `b@ == s.spec_bytes()`. Call the trait by path: a plain `use` of it is an unused import in the cargo build.
- Spec fns are erased in the cargo build, so do not `use` them from another module; import the module (`use … ::<module> as m;`) and write `m::spec_fn_name(..)`.
- Cast-free byte from a value `< 256`: `match u8::try_from(v) { Ok(b) => b, Err(_) => 0 }` (vstd has no spec for `unwrap_or_default`).
- `Vec::clear`, `Vec::extend_from_slice` and indexed slice writes are specified; prefer them over `to_be_bytes` / `copy_from_slice` for encoding.
- Ghost values built from an expression: write `let ghost g: bool = a.s@ || b.s@;` then `Ghost(g)`. An inline `Ghost(a.s@ || b.s@)` is rejected ("unexpected ghost block attribute").
- `zeroize::Zeroizing<_>` cannot be a field of a type inside `verus!`: Verus rejects it unless it gets an `external_type_specification`, which is a trusted spec (a TCB row). The per-crate choice is in profile `tcb.crate_rules`.
- A `pub`/`pub(crate)` fn's `ensures` cannot read a private field ("field expression for an opaque datatype"). Add a `closed spec fn view(&self)` and write the `ensures` against `self.view()`.
- A trait declared inside `verus!` but implemented outside it has its method `ensures` trusted silently (an impl that breaks them still verifies). Give such traits `requires` only, no `ensures`, unless a named trusted assumption is approved.
- std `BTreeMap` / `BTreeSet`: vstd specifies them only under `obeys_cmp::<K>()` (the key type's `Eq`/`Ord` obey the laws). vstd proves that law for integer keys, not for `String`. A `String` (or other unproven) key needs a TCB row for the law, approved per "Trusted boundary".
- Verus desugars `for` loops; the desugaring can trigger the `unused_qualifications` lint in the Verus build only (the cargo build is clean). Allow it where it fires, with a reason.
- `for x in &map` over a `BTreeMap` does not verify: vstd specifies `BTreeMap::iter` but not `IntoIterator for &BTreeMap`. Write `for x in map.iter()`; where the crate enables clippy `explicit_iter_loop`, allow it with that reason.
- Under a `for` loop, Verus's loop wrapper already carries the iterator-position relation (vstd `VerusForLoopWrapper::wf`). A loop invariant that restates it is redundant: it still verifies when deleted, so it is not counted as an obligation ("Mutation testing", tautology check); flag it for a later cleanup.
- Call `vstd::std_specs::iter::IteratorSpec` methods by path (for example `IteratorSpec::remaining(&it)`); a plain `use` of the trait is an unused import in the cargo build.
- A verified fn cannot call a fn or name a type declared outside `verus!` (dependency types, the crate's error type, functions of another crate) unless that item is given a spec at the trusted boundary. Otherwise keep such calls in unverified adapters outside `verus!` and list them by name as the trusted base.

Library-specific idioms (helper names, lint settings, per-crate decisions): profile appendix `idioms.md`.

## Confinement is not Verus

Confinement (private fields, no byte accessors, clippy `disallowed-methods` or other lint rules) is compiler- or lint-checked. Its ladder level is `compiler_lint`, never Verus-proven. Verus does not check that a function is absent; do not describe confinement as Verus-proven.

## Packaging decisions

Any nightly-only or Verus-only build attribute, a new dependency, or a CI change is a packaging decision: check profile `packaging_decisions`, record and ask.

## Core Concepts

### Three Function Modes

| Mode | Keyword | Purpose | Compiled to runtime? |
|------|---------|---------|---------------------|
| Executable | `fn` | Normal Rust code that runs | Yes |
| Specification | `spec fn` | Pure mathematical definitions used in contracts | No (ghost) |
| Proof | `proof fn` | Lemmas that establish facts for the verifier | No (ghost) |

### Basic Structure

Every Verus file wraps code in a `verus! { }` macro and imports vstd:

```rust
use vstd::prelude::*;

verus! {

spec fn min(x: int, y: int) -> int {
    if x <= y { x } else { y }
}

fn compute_min(a: u64, b: u64) -> (result: u64)
    ensures
        result == min(a as int, b as int),
{
    if a <= b { a } else { b }
}

} // verus!
```

## Contracts: requires / ensures

- **`requires`** — preconditions the caller MUST satisfy
- **`ensures`** — postconditions the function guarantees on return
- Name the return value with `-> (name: Type)` to reference it in `ensures`

```rust
fn divide(a: u32, b: u32) -> (q: u32)
    requires b != 0,                 // caller must ensure non-zero divisor
    ensures q == a / b,              // no division-by-zero panic possible
{
    a / b
}
```

## Common Verification Goals

### 1. Bounds Safety (no index-out-of-bounds panic)

```rust
fn get_first(v: &Vec<u8>) -> (x: u8)
    requires v.len() > 0,
    ensures x == v[0],
{
    v[0]
}
```

### 2. No Arithmetic Overflow

Verus checks overflow by default in `verus!` blocks. Add preconditions to prove safety:

```rust
fn add(a: u32, b: u32) -> (sum: u32)
    requires a + b <= u32::MAX,
    ensures sum == a + b,
{
    a + b
}
```

### 3. Slice Extraction Safety (e.g. crypto nonce/tag)

```rust
fn extract_tag(buf: &[u8], offset: usize) -> (tag: &[u8])
    requires offset + 16 <= buf.len(),
    ensures tag.len() == 16,
{
    &buf[offset..offset + 16]
}
```

### 4. Panic Freedom

Verus proves absence of panics automatically once contracts are satisfied. Replace `.unwrap()` with proven-safe patterns or add preconditions guaranteeing the value is `Some`/`Ok`.

## Modeling Byte Buffers as Seq<u8>

Use the `@` operator (the "view") to get the mathematical `Seq<u8>` of a slice or Vec for reasoning:

```rust
fn parse_u16_be(buf: &[u8]) -> (val: u16)
    requires buf.len() >= 2,
    ensures val == (buf[0] as u16) * 256 + (buf[1] as u16),
{
    (buf[0] as u16) * 256 + (buf[1] as u16)
}
```

Key `Seq` operations in spec code:
- `s.len()` — length
- `s[i]` — indexing
- `s.subrange(start, end)` — sub-sequence
- `s.index(i)` — explicit index

## Proof Functions and Lemmas

Use `proof fn` to establish facts the SMT solver can't derive on its own:

```rust
proof fn lemma_bounds(offset: nat, len: nat, total: nat)
    requires offset + len <= total,
    ensures forall|i: nat| i < len ==> offset + i < total,
{
    // often provable automatically; add hints if not
}
```

Invoke a lemma inside exec/proof code with `proof { lemma_bounds(...); }`.

## Quantifiers

```rust
// forall
ensures forall|i: int| 0 <= i < v.len() ==> v[i] > 0,

// exists
ensures exists|i: int| 0 <= i < v.len() && v[i] == target,
```

Use `int` and `nat` (unbounded integers) in spec/proof code; use sized types (`u8`, `usize`) in exec code.

## Loops: invariants

Loops require explicit invariants for verification:

```rust
fn sum(v: &Vec<u64>) -> (s: u64)
    requires forall|i: int| 0 <= i < v.len() ==> v[i] == 0,
    ensures s == 0,
{
    let mut total: u64 = 0;
    let mut idx: usize = 0;
    while idx < v.len()
        invariant
            total == 0,
            forall|i: int| 0 <= i < v.len() ==> v[i] == 0,
        decreases v.len() - idx,
    {
        total = total + v[idx];
        idx = idx + 1;
    }
    total
}
```

- `invariant` — must hold before and after each iteration
- `decreases` — proves termination (required for `while`/recursion)

## Debugging Verification Failures

When Verus reports an error, it points at the failing assertion or postcondition:

1. **"postcondition not satisfied"** — the function body doesn't prove the `ensures`. Add intermediate `assert(...)` statements to find where the proof breaks.
2. **"possible arithmetic overflow"** — add a `requires` bounding the inputs, or use `checked_add`.
3. **"possible out-of-bounds"** — add a `requires` on the length/index.
4. **"assertion might not hold"** — the fact isn't derivable; add a supporting `proof fn` lemma and call it.
5. **"recommendation not met"** — a `spec fn` with `recommends` was used outside its intended domain.

Use `assert(expr);` liberally to probe what the verifier knows at each point. Verus checks each assert, so a failing assert localizes the gap.

## Workflow for Adding Proofs to Existing Code

1. Read the target function and identify what could panic or violate the spec (indexing, arithmetic, unwraps, slices)
2. Write the weakest `requires` that eliminates each hazard
3. Write `ensures` capturing the correctness property
4. Run `~/verus/verus file.rs`
5. If it fails, add `assert(...)` probes or `proof fn` lemmas until it passes
6. Verify the preconditions are actually satisfiable by callers (don't over-constrain)
7. Mutation-test each new obligation and run the tautology check (see "Mutation testing")
8. Label each claim with its honesty-ladder level

## Quick Reference

| Task | Syntax |
|------|--------|
| Import | `use vstd::prelude::*;` |
| Wrap code | `verus! { ... }` |
| Precondition | `requires cond,` |
| Postcondition | `ensures cond,` |
| Name return | `fn f() -> (r: T)` |
| Spec function | `spec fn name(...) -> T { ... }` |
| Proof function | `proof fn name(...) requires ... ensures ... { ... }` |
| Byte buffer view | `buf@` (gives `Seq<u8>`) |
| Loop invariant | `invariant cond,` |
| Termination | `decreases expr,` |
| Probe verifier | `assert(cond);` |
| Call a lemma | `proof { lemma_name(args); }` |
| Unbounded int | `int`, `nat` (spec/proof only) |

## Library profile

The library profile is at `.kiro/verification-profile/verification-profile.yaml`; read it before any proof work. This skill uses profile `crates` (commands, feature sets, result line, cache bust), `toolchain`, `tcb`, `typestate_gates`, `ids`, `packaging_decisions` and profile appendix `idioms.md`.
Counts are never in the profile: re-read them from the live run (profile `artifacts.counts_source`).

## References

- Verus Guide: https://verus-lang.github.io/verus/guide/
- Verus repo: https://github.com/verus-lang/verus
- Related project agents: `.kiro/agents/verus-header-parsing-proofs.md`, `.kiro/agents/verus-zero-panic.md`, `.kiro/agents/verus-unsafe-ffi-safety.md`
