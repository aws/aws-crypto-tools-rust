---
name: verus
description: Write, run, and debug Verus formal verification proofs for Rust code. Use when verifying Rust functions with requires/ensures contracts, proving absence of panics or arithmetic overflow, proving array/slice bounds safety, modeling byte buffers as Seq<u8>, writing proof functions and lemmas, verifying unsafe FFI code, or when encountering Verus verification errors. Covers spec/proof/exec function modes, vstd, and the ~/verus/verus CLI.
---

# Verus Formal Verification

Verus is a tool for verifying the correctness of Rust code. Developers write specifications (requires/ensures) and Verus statically proves the executable Rust always satisfies them for all possible inputs, using the Z3 SMT solver.

## ABSOLUTE INVARIANTS — NEVER VIOLATE

These rules are non-negotiable. Violating any of them produces proofs that are unsound, misleading, or worthless — which is worse than no proof at all in a cryptographic library.

1. **NEVER weaken a proof to make it pass.** Do not add `assume(...)`, `#[verifier::external_body]`, `#[verifier::external]`, or `admit()` to bypass a failing proof without asking the human who runs the agent. These tell Verus to trust an unproven claim. If a proof won't go through, ask to fix the code or the specification — do not silence the verifier.

2. **NEVER report a proof as verified unless `~/verus/verus` prints `0 errors`.** Always run the tool and show the actual output. Do not claim success from reading the code alone.

3. **NEVER add a `requires` clause that the real callers cannot satisfy.** Preconditions must be satisfiable in the actual call sites. An over-constrained precondition creates a proof that is vacuously true but protects nothing.

4. **NEVER change the specification (`ensures`) to match buggy behavior.** The specification is the source of truth derived from the MPL framework spec (`spec/framework/*.md`) and threat model. If the code violates the spec, the code is wrong — report it as a finding; do not rewrite the `ensures` to describe the bug.

5. **NEVER use `assume(false)` or contradictory `requires` to trivially discharge obligations.** A contradiction in preconditions makes every postcondition provable and every proof meaningless.

6. **NEVER delete or comment out a failing `assert`, `invariant`, or `ensures` to get a green result.** If you cannot prove it, leave it failing and explain why.

7. **NEVER mark `unsafe` FFI code as `external_body` and call it "verified."** Wrapping unsafe code to hide it from Verus is the opposite of proving its safety. Model the FFI contract explicitly (see `verus-unsafe-ffi-safety` agent) or state clearly that it remains unverified.

8. **ALWAYS preserve the meaning of the code.** Proof annotations (`spec`, `proof`, `requires`, `ensures`, `invariant`, `assert`) are ghost and must not change runtime behavior. Never alter executable logic solely to make verification easier without confirming the behavior is still correct.

9. **ALWAYS keep `decreases` clauses honest.** A `decreases` expression must genuinely decrease and be bounded below. Never fabricate one that Verus happens to accept but does not reflect real termination.

10. **When blocked, escalate — do not fake.** If a property cannot be proven after genuine effort, say so explicitly, describe what blocks it, and leave the obligation visible. An honest "unproven" is infinitely more valuable than a dishonest "verified."

11. **ALL exec code MUST live inside `verus! { }` blocks.** Using `#[cfg(not(verus_keep_ghost))]` to hide exec functions from Verus is FORBIDDEN — it excludes code from verification while still compiling and running it, producing a green result that silently omits arbitrary logic. The ONLY exceptions are:
    - External crate calls that Verus cannot model (e.g., `ring`, `chrono`, `serde`, `aws-lc-rs`) placed in `#[cfg(not(verus_keep_ghost))]` blocks **within** a `verus!` body.
    - `format!`-based path/error strings that are purely cosmetic and carry no verified logic.
    Any other use of `#[cfg(not(verus_keep_ghost))]` to sidestep verification is a violation. When an exception is used, keep the excluded region as small as possible and document why Verus cannot verify it.

12. **ALL structs and traits MUST have a single definition shared between cargo and Verus.** NO `cfg`-gated duplicate struct/trait definitions. If Verus sees one definition of a type and cargo compiles a different one, every proof about that type is meaningless — the verified model and the shipped code silently diverge. Enforce this by:
    - Applying `#[cfg(verus_keep_ghost)]` to **individual ghost fields**, never to an entire struct or trait.
    - Defining traits **inside** `verus! { }` blocks so ghost items (spec functions, proof obligations) are automatically erased for the cargo build while the type itself stays identical.
    There must be exactly one source-of-truth definition per struct and per trait.

13. **Verify what you claim.** When completing a task, confirm the target function is actually inside a `verus! { }` block by inspecting the source — not just by checking the verification count. A rising "N verified" number means nothing if the function you were asked to prove was silently excluded from verification. Always trace the specific target function to a `verus!` block and confirm its `requires`/`ensures` are present before reporting the task done.

14. **The proof chain MUST be complete.** Every piece of verified code must participate in a coherent logical argument from implementation to proof function. There must be a machine-checked path from the running code to every predicate a proof relies on. The required chain is:

    ```
    exec code  →  #[verifier::type_invariant]  →  type.is_valid(ctx)  →  proof fn requires
    ```

    Concretely:
    - Every validated wrapper type (`ValidatedFoo`) MUST have a `#[verifier::type_invariant]` that calls `SpecFoo { ... }.is_valid(self.ghost_ctx@)` — **not** ad-hoc conjuncts of individual field predicates.
    - The `ghost_ctx` MUST be populated with the real `ctx.config.deep_view()` at construction time (**not** `arbitrary()`), so the invariant reflects the actual validation context rather than an unconstrained one.
    - Every public proof function that derives a property from a validated type MUST use `type.is_valid(ctx)` as its `requires` premise — **not** the underlying free spec function directly.
    - Transformation functions that do not produce validated types (e.g., `normalize_uri`) MUST return a `ValidatedXxx` wrapper type whose `type_invariant` asserts the transformation's output properties via `is_valid(ctx)`.

    **Why this matters:** Without this chain, proof functions float free — they prove things about spec predicates in isolation, but there is no machine-checked path from the running code to those predicates. The chain guarantees that if the code runs and produces a `ValidatedFoo`, then `SpecFoo.is_valid(ctx)` holds, and therefore every proof function with `requires foo.is_valid(ctx)` genuinely applies to that value. A "verified" proof that is not anchored to the code via this chain proves nothing about what actually executes.



## Environment

- **Binary:** `~/verus/verus` (installed via binary release)
- **Version check:** `~/verus/verus --version`
- **Required toolchain:** Rust 1.96.0 (installed via `rustup install 1.96.0-aarch64-apple-darwin`)
- **Z3:** bundled with the Verus release (no separate install)

## Running Verus

Verify a single file:
```bash
~/verus/verus path/to/file.rs
```

Verify a multi-crate project via Cargo:
```bash
cargo-verus build
```

Success output looks like:
```
verification results:: N verified, 0 errors
```

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

## References

- Verus Guide: https://verus-lang.github.io/verus/guide/
- Verus repo: https://github.com/verus-lang/verus
- Related project agents: `.kiro/agents/verus-header-parsing-proofs.md`, `.kiro/agents/verus-zero-panic.md`, `.kiro/agents/verus-unsafe-ffi-safety.md`
