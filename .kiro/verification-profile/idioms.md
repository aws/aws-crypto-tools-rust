# ESDK profile appendix: idioms

Library-specific Verus idioms for the ESDK crates (`esdk/`, `prim/`). The generic idioms (probe-confirmed on Verus 0.2026.07.12) go to the "Idioms" section of the `verus` skill; this file keeps the halves that name ESDK files, helpers, lints and decisions. Text is copied verbatim from the files at `4054fd89`; each block names its source. Bare file names in the copied text are relative to `esdk/src/message/` (`serialize_functions.rs`), `verification/` (`body_aad_proofs.rs`) or `prim/src/` (`aws_lc_specs.rs`).

## Core/adapter names

Source: `.kiro/steering/verus-verification.md` §In-crate proofs (`verus!` in `esdk/`).

> The pattern: the shipped readers are `async fn`s over `&mut dyn Source` (tokio
> `AsyncRead`) that mirror bytes into `&mut Tee` (`dyn Write + Send`). Verus
> cannot verify async or trait objects, so the decision logic lives in pure
> synchronous cores inside `verus! { }`, and the async fns are thin **unverified**
> adapters that read the bytes, call the core, and build the `Error` (`ser_err` /
> `err` / `val_err`). Never hide exec code behind `#[cfg(not(verus_keep_ghost))]`;
> keep one definition per type (move an enum into `verus!` unchanged, never
> duplicate it); keep duvet `//=` annotations next to the code they annotate.

Facts checked at `4054fd89`: `val_err`, `err` and `ser_err` are defined in `esdk/src/error.rs` (lines 179, 184, 198).

## Big-endian helpers

Source: `.kiro/steering/verus-verification.md` §This-repo Verus idioms.

> - `u32::to_be_bytes` / `u64::to_be_bytes` are NOT modeled by vstd. Do not reach
>   for `assume_specification`; instead define a `spec fn` big-endian
>   source-of-truth (see `spec_u32_be`/`spec_u64_be` in `body_aad_proofs.rs`) and
>   a verified exec helper, and document the one-line equivalence to std.

Source: `.kiro/steering/verus-verification.md` §This-repo Verus idioms, "In-crate (`esdk/`), probe-confirmed".

> - Big-endian: `u16::from(u8)` (and `u32`/`u64`) times constant multipliers.
>   Avoid `as` casts in exec code; they trip the clippy `cast_*` lints.
> - Spec fns are erased in the cargo build, so do not `use` them from another
>   module; import the module (`use … ::serialize_functions as sf;`) and write
>   `sf::spec_u32_to_be(..)`.
> - Cast-free byte from a value `< 256`: `match u8::try_from(v) { Ok(b) => b, Err(_) => 0 }`
>   (see `low_byte`; vstd has no spec for `unwrap_or_default`).
> - Big-endian encoding: use `u32_to_be` / `u64_to_be` (`serialize_functions.rs`),
>   not `to_be_bytes` / `copy_from_slice`; `Vec::clear`, `Vec::extend_from_slice`
>   and indexed slice writes are specified.

Source: `.kiro/agents/verus-header-parsing-proofs.md` §In-Crate Constraints (the same line is in `.kiro/agents/verus-zero-panic.md` §In-Crate Constraints and `.kiro/agents/verus-capabilities.md` §In-crate constraints).

> - `to_be_bytes` is not modeled by vstd. Use `u32_to_be` / `u64_to_be` (`esdk/src/message/serialize_functions.rs`).

Facts checked at `4054fd89`: `low_byte`, `u32_to_be` and `u64_to_be` are in `esdk/src/message/serialize_functions.rs`; `spec_u32_be` and `spec_u64_be` are in `verification/body_aad_proofs.rs`; `esdk/src/message/body/body_aad.rs` has `use crate::message::serialize_functions as sf;`.

## Lints in esdk

Source: `.kiro/steering/verus-verification.md` §This-repo Verus idioms, "In-crate (`esdk/`), probe-confirmed".

> - Doc-comment every new item (`missing_docs` is on), and add in-module
>   `#[cfg(test)] mod tests` for new cores.

Source: `.kiro/agents/verus-zero-panic.md` §Open Panic Surface (not yet closed).

> - `esdk/src/lib.rs` leaves `clippy::indexing_slicing` and `clippy::panic` **off** (they are listed in the lint policy as deliberately not enabled, because indexing is too noisy in serialization code and `panic!()` is forced by `#[non_exhaustive]` MPL enums). So raw indexing and `panic!()` are not lint-blocked; Verus bounds proofs are what actually rule them out where they run.

Facts checked at `4054fd89`: `esdk/src/lib.rs:127` `missing_docs`; `esdk/src/lib.rs:155` `clippy::pedantic` (the source of the `cast_*` lints); `esdk/src/lib.rs:178-179` list `clippy::panic` and `clippy::indexing_slicing` as not enabled; `esdk/clippy.toml:4` `disallowed-methods`.

Source: `.kiro/agents/verus-zero-panic.md` §Verus Patterns You Must Use (the note above the pattern code).

> The pattern code below is illustrative. Some of it uses `as u8` casts in exec code (`sequence_number_to_iv`, `write_u16_be`, `write_u32_be`). The shipped code avoids `as` casts in exec code (clippy `cast_*` lints) and uses `low_byte` / `u32_to_be` instead; see `.kiro/steering/verus-verification.md`.

## Names outside verus!

Source: `.kiro/steering/verus-verification.md` §This-repo Verus idioms, "Secret and labelled types (VR-011, `esdk/src/secret.rs`), probe-confirmed".

> - A verified fn cannot call a fn or name a type declared outside `verus!`
>   (mpl types, the esdk `Error`, prim fns) unless that item is given a spec at
>   the trusted boundary (`prim` does this for aws-lc-rs). Otherwise keep such
>   calls in unverified adapters outside `verus!` and list them by name as the
>   trusted base.

## Secret types in esdk (VR-011 decision)

Source: `.kiro/steering/verus-verification.md` §This-repo Verus idioms, "Secret and labelled types (VR-011, `esdk/src/secret.rs`), probe-confirmed".

> - `zeroize::Zeroizing<_>` cannot be a field of a type inside `verus!`: Verus
>   rejects it unless it gets an `external_type_specification`. That would be a
>   trusted spec, and for the esdk secret types the VR-011 decision was not to
>   add one. Hold a `Vec<u8>` and `#[derive(Zeroize, ZeroizeOnDrop)]` (zeroize
>   `derive` feature) instead. This is a decision for esdk secret types only. In
>   `prim`, `external_type_specification` is the sanctioned boundary for the
>   aws-lc-rs types, with a TCB row for each (see "Trusted boundary" in the
>   `verus` skill).

The two boundary decisions are also in profile `tcb.crate_rules`.

## prim: nightly attribute for ExAsRef

Source: `.kiro/steering/verus-verification.md` §In-crate proofs (`verus!` in `prim/`).

> The trusted
> specs for the aws-lc-rs calls are in `prim/src/aws_lc_specs.rs` (the TCB list;
> see `verus-unsafe-ffi-safety`). `prim/src/lib.rs` carries
> `#![cfg_attr(verus_keep_ghost, feature(sized_hierarchy))]`, needed only in
> Verus builds for the `ExAsRef` trait spec; whether to keep it is an open
> packaging question.

Fact checked at `4054fd89`: `prim/src/lib.rs:10`. The packaging question is profile `packaging_decisions` id `nightly-cfg-attr`.

## String keys in esdk collections (VR-020)
The generic idiom is in the `verus` skill, "Idioms" (vstd specifies `BTreeMap` / `BTreeSet` only under `obeys_cmp::<K>()`). In esdk, `String` keys use TCB row T-cmp: `required_ec_entries` in `esdk/src/decrypt.rs` has `requires vstd::laws_cmp::obeys_cmp::<String>()` (VR-020; the row is listed in profile `tcb.modules` and `tcb.row_ids`). The same function carries the `unused_qualifications` and `clippy::explicit_iter_loop` allows of the generic `for`-loop idioms, each with a reason, and calls `vstd::std_specs::iter::IteratorSpec::remaining` by path.
Fact checked at `cf326cb3`: `esdk/src/decrypt.rs` lines 783, 787, 790, 795, 804.
