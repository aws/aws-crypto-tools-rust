---
inclusion: fileMatch
fileMatchPattern: 'verification/**'
---

# Verus Verification in this Repo

Formal Verus proofs for the AWS ESDK live in `verification/`. They follow the
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

## Why proofs are standalone models (not `verus!` in `esdk/`)
The `esdk` crate depends on `aws-lc-rs`, `tokio`, `aws-sdk-*`, and
`SafeRead`/`SafeWrite` trait objects that Verus cannot build or model. So each
proof file is a faithful, self-contained model of a specific *pure* function:
the exact executable body plus `requires`/`ensures`. `verification/` is
referenced by no `Cargo.toml`, so it never affects the normal `cargo` build.

When migrating a model in-crate later, put the code inside a `verus! { }` block
(never hide exec code behind `#[cfg(not(verus_keep_ghost))]`), keep a single
source-of-truth definition per type, and re-verify.

## This-repo Verus idioms (confirmed against the installed version)
- Slice element write: `slice[i] = v;` (the `.set()` method is deprecated).
- Postconditions on `&mut` params: use `final(x)` and `old(x)`, not bare `x`.
- `Seq` ops in `ensures`: apply the view first, e.g. `x@.subrange(a, b)`.
- `u32::to_be_bytes` / `u64::to_be_bytes` are NOT modeled by vstd. Do not reach
  for `assume_specification`; instead define a `spec fn` big-endian
  source-of-truth (see `spec_u32_be`/`spec_u64_be` in `body_aad_proofs.rs`) and
  a verified exec helper, and document the one-line equivalence to std.

## Good next targets (self-contained, no external crypto)
- `validate_max_encrypted_data_keys` (`esdk/src/message/header.rs`) — EDK count.
- `write_volatile` zeroization loop (`mpl/src/structures/algorithm_suite.rs`).
- Big-endian readers/writers once a non-trait-object seam is available.

Avoid targeting functions whose core is an `aws-lc-rs` call (AES-GCM, ECDSA,
HKDF): Verus cannot model the FFI backend, so only the surrounding
bounds/overflow logic is provable.
