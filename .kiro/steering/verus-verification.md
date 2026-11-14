---
inclusion: fileMatch
fileMatchPattern: 'verification/**'
---

# Verus Verification in this Repo

Formal Verus proofs for the AWS ESDK live in `verus!` blocks inside `esdk/src/`
(shipped code) and as standalone models in `verification/`. They follow the
pipeline in `.kiro/agents/ai-verification-pipeline.md` and the target ranking in
`docs/verification-recommendations.md`.

## How to run
```bash
make -C verification verify      # runs ~/verus/verus over every proof file
# or a single file:
~/verus/verus verification/body_aad_proofs.rs
```
Success prints `verification results:: N verified, 0 errors`. Verus binary is at
`~/verus/verus` (v0.2026.07.12, toolchain 1.96.0).

## Ground rules (from the `verus` skill — non-negotiable)
- Never weaken a proof to make it pass: no `assume(...)`, `admit()`,
  `#[verifier::external_body]`, or `#[verifier::external]` to bypass a failing
  obligation. If it won't prove, leave it failing and say why.
- Never report success without showing actual `0 errors` output.
- Never over-constrain `requires` beyond what real callers satisfy.
- Never change an `ensures` to match buggy behavior — report the bug instead.

## In-crate proofs (`verus!` in `esdk/`)
Shipped `esdk` code is verified in place. `esdk/Cargo.toml` sets
`[package.metadata.verus] verify = true` and depends on `vstd`
(`=0.0.0-2026-06-14-0213`). `cargo-verus` builds the dependencies (`aws-lc-rs`,
`tokio`, `aws-sdk-*`, `mpl`, `prim`) with plain rustc and verifies only the
`verus!` blocks in `esdk`:
```bash
make -C esdk verus   # cargo verus verify, default and --no-default-features --features aws-lc-sys
```
It verifies `vstd` first (`1858 verified, 0 errors`); the `aws-esdk` result is
the second `verification results::` line and must read `N verified, 0 errors`.
A cached run prints no results line; `touch esdk/src/lib.rs` forces a re-check.

The pattern: the shipped readers are `async fn`s over `&mut dyn Source` (tokio
`AsyncRead`) that mirror bytes into `&mut Tee` (`dyn Write + Send`). Verus
cannot verify async or trait objects, so the decision logic lives in pure
synchronous cores inside `verus! { }`, and the async fns are thin **unverified**
adapters that read the bytes, call the core, and build the `Error` (`ser_err` /
`err` / `val_err`). Never hide exec code behind `#[cfg(not(verus_keep_ghost))]`;
keep one definition per type (move an enum into `verus!` unchanged, never
duplicate it); keep duvet `//=` annotations next to the code they annotate.

The standalone models in `verification/` are kept; see `verification/README.md`
for which ones are superseded in-crate or stale.

## This-repo Verus idioms (confirmed against the installed version)
- Slice element write: `slice[i] = v;` (the `.set()` method is deprecated).
- Postconditions on `&mut` params: use `final(x)` and `old(x)`, not bare `x`.
- `Seq` ops in `ensures`: apply the view first, e.g. `x@.subrange(a, b)`.
- `u32::to_be_bytes` / `u64::to_be_bytes` are NOT modeled by vstd. Do not reach
  for `assume_specification`; instead define a `spec fn` big-endian
  source-of-truth (see `spec_u32_be`/`spec_u64_be` in `body_aad_proofs.rs`) and
  a verified exec helper, and document the one-line equivalence to std.

In-crate (`esdk/`), probe-confirmed:
- Take fixed-size `[u8; N]` params; spec indexing `b[0]` works as-is.
- Big-endian: `u16::from(u8)` (and `u32`/`u64`) times constant multipliers.
  Avoid `as` casts in exec code; they trip the clippy `cast_*` lints.
- `usize::try_from(u64)` / `usize::try_from(u32)` and `usize::from(u8)` are specified.
- A const shift such as `1 << 20` must be written `1_048_576`.
- `derive(Clone, Copy, Debug, Default, Eq, Hash, PartialEq)` and `#[default]`
  on an enum inside `verus!` are accepted.
- `ensures` may use `r is Variant` and `r matches E::V(n) ==> ...`.
- Doc-comment every new item (`missing_docs` is on), and add in-module
  `#[cfg(test)] mod tests` for new cores.
- `const`s inside `verus!` are accepted and can be named in specs.
- `&str` consts inside `verus!` need an explicit `&'static str` (Verus rejects
  the elided lifetime); add `#[expect(clippy::redundant_static_lifetimes, reason = …)]`.
  Their bytes in specs: `vstd::string::StringSliceAdditionalSpecFns::spec_bytes(s)`;
  `str::as_bytes` ensures `b@ == s.spec_bytes()`. Call the trait by path: a
  plain `use` of it is an unused import in the cargo build.
- Spec fns are erased in the cargo build, so do not `use` them from another
  module; import the module (`use … ::serialize_functions as sf;`) and write
  `sf::spec_u32_to_be(..)`.
- Cast-free byte from a value `< 256`: `match u8::try_from(v) { Ok(b) => b, Err(_) => 0 }`
  (see `low_byte`; vstd has no spec for `unwrap_or_default`).
- Big-endian encoding: use `u32_to_be` / `u64_to_be` (`serialize_functions.rs`),
  not `to_be_bytes` / `copy_from_slice`; `Vec::clear`, `Vec::extend_from_slice`
  and indexed slice writes are specified.

Secret and labelled types (VR-011, `esdk/src/secret.rs`), probe-confirmed:
- Ghost values built from an expression: write `let ghost g: bool = a.s@ || b.s@;`
  then `Ghost(g)`. An inline `Ghost(a.s@ || b.s@)` is rejected ("unexpected
  ghost block attribute").
- `zeroize::Zeroizing<_>` cannot be a field of a type inside `verus!`: Verus
  rejects it unless it gets an `external_type_specification`, which is a
  trusted spec and not allowed here. Hold a `Vec<u8>` and
  `#[derive(Zeroize, ZeroizeOnDrop)]` (zeroize `derive` feature) instead.
- A `pub`/`pub(crate)` fn's `ensures` cannot read a private field ("field
  expression for an opaque datatype"). Add a `closed spec fn view(&self)` and
  write the `ensures` against `self.view()`.
- A trait declared inside `verus!` but implemented outside it has its method
  `ensures` trusted silently (an impl that breaks them still verifies). Give
  such traits `requires` only, no `ensures`, unless a named trusted assumption
  is approved.
- A verified fn cannot call a fn or name a type declared outside `verus!`
  (mpl types, the esdk `Error`, prim fns). Keep such calls in unverified
  adapters outside `verus!` and list them by name as the trusted base.
- Confinement (private fields, no byte accessors, clippy `disallowed-methods`)
  is compiler/lint-checked, not Verus. Verus does not check that a function is
  absent; do not describe confinement as Verus-proven.

## Good next targets (self-contained, no external crypto)
- Nothing self-contained is left in esdk. The remaining models
  (header-auth ordering, EDK list loop, frame `ct ‖ tag`, AES-GCM bounds in
  `prim`) are blocked by async fns, `dyn Source` / `dyn Sink`, aws-lc-rs, or
  the decision not to add Verus to `prim`; see `verification/README.md`.

Avoid targeting functions whose core is an `aws-lc-rs` call (AES-GCM, ECDSA,
HKDF): Verus cannot model the FFI backend, so only the surrounding
bounds/overflow logic is provable.
