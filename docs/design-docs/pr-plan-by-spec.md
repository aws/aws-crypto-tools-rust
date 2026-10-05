# PR Plan: Breaking Out `aws-crypto-rust/unreviewed`

This doc is the source of truth for slicing the work on `aws-crypto-rust/unreviewed`
into focused review PRs. Each entry below defines one PR and the files that
belong to it. The PR pair-programmer agent keys off `pr_number` to derive
`scope_files`, `review_branch`, and `sync_worktree`.

## Conventions

- All paths are relative to the repository root (`aws-crypto-tools-rust/`).
- `review_branch` follows the pattern `aws-crypto-rust/<slug>-review`.
- `sync_worktree` follows the pattern
  `/Users/jocorell/crypto-tools/rust/aws-crypto-tools-rust-<slug>` and tracks
  the matching `review_branch`.
- **Review branches are stacked.** Slice 1's review branch is cut from `main`.
  Each subsequent slice's review branch is cut from the *previous* slice's
  review branch. Each PR's base branch is the previous slice's review branch
  (slice 1's PR base is `main`). This way each PR diff shows only that
  slice's contribution. Once a slice's PR merges, the previous review branch
  is retired and the next un-merged slice cuts from `main` (which now
  contains the merged slice's content), effectively resetting the stack.
- **Each review branch is a buildable, CI-passing snapshot** of `main` plus
  slices 1..N's cumulative content. Achieving this requires that "shared
  files" (those touched by multiple slices — see the next section) carry
  their per-stack-level snapshot, not the latest state on
  `aws-crypto-rust/unreviewed`. The simple `git checkout
  aws-crypto-rust/unreviewed -- <file>` works only for files newly introduced
  in that slice; shared files require a curated snapshot at the right stack
  level.
- CI runs on PRs cut from review branches and is expected to **pass**. If CI
  fails on a review PR, the slice's snapshot is wrong (usually because a
  shared file was synced from the wrong source).
- A given file's *substance* is owned by exactly one PR (the PR where its
  primary purpose is reviewed). Shared files can be modified by later slices;
  each slice's PR shows only its incremental diff to a shared file.

## Status snapshot

Snapshot as of 2026-08-03. Update this table whenever a slice's state
changes (branch cut, PR opened, PR merged, PR closed).

| PR | Slug | GitHub PR | Status | Review branch |
|---|---|---|---|---|
| 1 | `client-scaffold` | [#10](https://github.com/aws/aws-crypto-tools-rust/pull/10) | **Merged** 2026-06-11 | retired after merge |
| 2 | `structures` | [#15](https://github.com/aws/aws-crypto-tools-rust/pull/15) | **Merged** 2026-07-07 (merge commit `72b161e`) | retired after merge |
| 3 | `algorithm-suite` | [#16](https://github.com/aws/aws-crypto-tools-rust/pull/16) | **Merged** 2026-07-09 (merge commit `12ba944`) | retired after merge |
| 4 | `commitment-policy` | [#17](https://github.com/aws/aws-crypto-tools-rust/pull/17) | **Merged** 2026-07-13 (merge commit `55d0e28`) | retired after merge |
| 5 | `keyring-and-cmm-interfaces` | [#20](https://github.com/aws/aws-crypto-tools-rust/pull/20) | **Merged** 2026-07-14 (merge commit `3e58ec3`) | retired after merge |
| 6 | `default-cmm` | [#28](https://github.com/aws/aws-crypto-tools-rust/pull/28) | **Merged** 2026-07-16 (merge commit `703322c`) | retired after merge |
| 7 | `structures-polish` | — | **Folded into PR 8** (substance landed with PR 2; residual drift moves to PR 8) | — |
| 8 | `mrk-match` | [#29](https://github.com/aws/aws-crypto-tools-rust/pull/29) | **Merged** 2026-07-16 (merge commit `6214783`) | retired after merge |
| 9 | `cmc-interface` | [#30](https://github.com/aws/aws-crypto-tools-rust/pull/30) | **Merged** 2026-07-16 (merge commit `a917ccf`) | retired after merge |
| 10 | `local-cmc` | [#31](https://github.com/aws/aws-crypto-tools-rust/pull/31) | **Merged** 2026-07-20 (merge commit `8a5ae90`) | retired after merge |
| 11 | `storm-tracking-cmc` | [#33](https://github.com/aws/aws-crypto-tools-rust/pull/33) | **Merged** 2026-07-31 (merge commit `81aa540`) | retired after merge |
| 12 | `keystore-interface` | [#35](https://github.com/aws/aws-crypto-tools-rust/pull/35) | **Merged** 2026-07-31 (merge commit `3ae7b4e`) | retired after merge |
| 13 | `keystore-support` | [#36](https://github.com/aws/aws-crypto-tools-rust/pull/36) | **Merged** 2026-07-31 (merge commit `538dbd9`) | retired after merge |
| 14 | `branch-key-store` | [#48](https://github.com/aws/aws-crypto-tools-rust/pull/48) | **Merged** 2026-07-31 (merge commit `3d0d3f7`) | retired after merge |
| 15 | `hkeyring-support` | — | Not started (blocked on PR 20 — needs `prim`) | — |
| 16 | `hkeyring` | — | Not started | — |
| 17 | `client-factories` | — | Not started | — |
| 18 | `hkeyring-examples` | — | Not started | — |
| 19 | `branch-key-store-write` | [#49](https://github.com/aws/aws-crypto-tools-rust/pull/49) | **Merged** 2026-08-03 (merge commit `6d00fae`) | retired after merge |
| 20 | `primitives` | — | Not started (next up) | `aws-crypto-rust/primitives-review` |

**Next action:** PR 19 ([#49](https://github.com/aws/aws-crypto-tools-rust/pull/49)) merged, and `main` has been merged back into `aws-crypto-rust/unreviewed` (merge commit `08156c8`) so the two are in sync. The stack has fully reset — every opened slice is merged and no review branch is live. The next slice to start is PR 20 (`primitives`), which bases on `main`. It is sequenced ahead of PR 15 because PR 15's source depends on the `prim` crate, and `prim` does not exist on `main` at all.

**Divergence note on PR 2:** the review branch's `encryption_materials.rs`
carries a hand-rolled slice-2-compatible version of the None-side
`symmetric_signing_keys` invariant, using the pre-rename
`AlgorithmSuite::new(false, true)` API. The equivalent invariant on
`aws-crypto-rust/unreviewed` uses the post-rename `AlgorithmSuiteId`
enum and is currently unreachable (commit `406e57f`, see PR 7 notes).
Both branches deliberately hold semantically equivalent versions
tailored to their type systems; do **not** sync this file between them.

## Shared files (modified across slices)

These files are touched by more than one slice. Each slice's PR diff includes
that slice's incremental change to the file. The full file at the end of a
given slice's review branch is the snapshot of cumulative work through that
stack level.

- `mpl/Cargo.toml`, `mpl/Cargo.lock` — slice 1 introduces the scaffold (no
  deps). Later slices add deps as needed: PR 5 adds `async-trait` under
  `[dependencies]` and `tokio` (with just `["rt", "macros"]` features)
  under `[dev-dependencies]` for `#[tokio::test]` on the contract
  harnesses; PR 11 promotes `tokio` to `[dependencies]` with features
  `["rt", "macros", "time"]` because `StormTrackingCmc` calls
  `tokio::time::sleep` in the library body; PR 14 adds `aws-config`,
  `aws-sdk-dynamodb`, `aws-sdk-kms`, `base64`, `uuid` (with `features =
  ["v4"]`);
  PR 15 adds the `aws-mpl-primitives` path dependency on the `prim` crate
  (introduced by PR 20); PR 18 adds the `[[example]] name =
  "aws_kms_hierarchical"` block. Each slice's PR shows
  the diff it introduces.
- `mpl/src/lib.rs` — slice 1 introduces the scaffold (`mod client; pub use
  client::*;`). Slice 2 adds `pub mod structures;`. Slice 5 adds `pub mod
  keyring; pub use keyring::Keyring;` and `pub mod cmm; pub use
  cmm::{...};`. Slice 8 adds `pub mod aws_kms;`. Slice 9 adds `pub mod
  cmc; pub use cmc::{Cmc, CacheEntry, ...};` — later CMC slices extend
  the re-export list. Slice 12 adds `pub mod keystore;`. Slice 14 adds
  `pub use keystore::{BranchKeyStore, KeyStoreConfig, ...};`. Each slice's PR
  shows the lib.rs diff it introduces.
- `mpl/src/structures/mod.rs` — slice 2 introduces it. Slices 3 and 4 add
  submodule + re-export lines for `algorithm_suite` and `commitment_policy`.
  Slice 5 adds `MaterialsErrorKind` alongside `MaterialsError` in the
  `error` re-export so tests and downstream code can name the kind
  variant at the top-level `structures::` path.
- `mpl/src/structures/error.rs` — slice 2 introduces `MaterialsError` /
  `MaterialsErrorKind`. Slice 5 (keyring + cmm) extends with new variants.
- `mpl/src/structures/encryption_context.rs` and materials structs —
  slice 2 introduces them; slice 7's originally-planned polish (reject-
  trailing-bytes fix, boundary / UTF-8 / known-vector tests, BTreeMap-
  entry-API perf, drop-redundant-duvet-annotation stance) landed with
  PR 2's merge. The remaining drift on `unreviewed`
  (`#[derive(Clone)]` + `uuid`-decode doc extension on
  `BranchKeyMaterials`, and a `MaterialsErrorKind::Validation` comment
  update in `test_encryption_context.rs`) is folded into PR 8's scope
  so PR 7 does not ship as a standalone slice.
- `mpl/src/client.rs` — slice 1 introduces it. Slice 17
  (`client-factories`) adds `create_cryptographic_materials_cache`,
  `create_branch_key_store`, and `create_aws_kms_hierarchical_keyring`
  factory methods. Slice 17's PR shows the incremental diff.
- `mpl/src/cmm/mod.rs` — slice 5 introduces it. Slice 6 modifies its
  re-exports for `DefaultCmm`.
- `mpl/src/aws_kms/mod.rs` — slice 8 (`mrk-match`) introduces the
  scaffold with `pub mod mrk_match;`. Slice 15 (`hkeyring-support`)
  extends with `pub(crate) mod branch_key_wrap;`, `pub(crate) mod
  cache_entry_identifier;`, and the `__test_internals` re-export module.
  Slice 16 (`hkeyring`) extends with `pub mod hierarchical_keyring;`.
- `mpl/src/cmc/mod.rs` — slice 9 (`cmc-interface`) introduces it with
  the `Cmc` trait, `entry` submodule, and initial re-exports. Slice 10
  (`local-cmc`) adds `pub mod local; pub use local::LocalCmc;`. Slice 11
  (`storm-tracking-cmc`) adds `pub mod storm_tracking; pub use
  storm_tracking::{StormTrackingCmc, TimeUnits};`.
- `mpl/src/keystore/mod.rs` — slice 12 (`keystore-interface`) introduces
  it with the `Keystore` trait scaffold plus `config`, `kms_config`, and
  `error` submodules. Slice 13 (`keystore-support`) adds `pub mod
  record;` and `pub mod encryption_context;`. Slice 14
  (`branch-key-store`) adds `pub mod branch_key_store; pub use
  branch_key_store::BranchKeyStore; pub(crate) mod kms_ops;`.
- **`keystore` cargo feature — repo-wide correction.** Earlier revisions of
  this plan gated the keystore behind a `keystore` cargo feature. That
  feature was removed crate-wide: `mpl/Cargo.toml` defines only
  `default = []` and `test-utils`, and there are zero occurrences of
  `feature = "keystore"` in tracked `mpl/src`, `mpl/tests`, or
  `mpl/examples`. The keystore is unconditional. The per-slice entries
  below have been updated to drop the `#[cfg(feature = "keystore")]`
  gates and the `required-features = ["keystore"]` example attribute.
  Relatedly, `mpl` declares no `fips` feature at all — `esdk`, `prim`,
  and both `unsafe-unreviewed-mpl` crates do, but `mpl` does not, so
  FIPS is not reachable from `mpl` even with `--all-features`.
- **Compliance paths — repo-wide correction.** There is no `mpl/compliance/`
  directory and no `mpl/.duvet/config.toml`. The real duvet requirement TOMLs
  live under `mpl/.duvet/requirements/spec/framework/...`, and the root
  `.gitignore` excludes `**/.duvet/requirements/**`, `**/.duvet/snapshot.txt`,
  and `**/.duvet/reports/**` — so nothing under `mpl/.duvet/` is tracked at
  all (`esdk/.duvet/config.toml` is the only tracked duvet file in the repo).
  Every `**Compliance:**` entry below that names a `mpl/compliance/...toml`
  path therefore refers to files that cannot be committed and must never
  appear in a slice's `scope_files`. Separately, commit `159de6e` stripped
  2431 annotation lines from 33 files across `mpl`, so "incremental
  annotations" is not a live deliverable anywhere in `mpl` today. The
  `**Compliance:**` lines are retained below as a record of which spec
  sections each slice covers, not as a file manifest.

## Never in a PR (unreviewed-only tooling)

Files listed here live on `aws-crypto-rust/unreviewed` only. They must never
appear in any review PR's `scope_files`, and must not be synced to any review
branch. If one of these files needs to be updated, the change is made directly
on `unreviewed` outside the PR-slice workflow.

- `mpl/scripts/duvet_summary.py` — duvet coverage summary helper. Runs
  against the local `.duvet/` output to produce a human-readable coverage
  breakdown; not part of the shipped crate, not referenced from CI, and not
  part of any spec-driven slice.

## Out of scope (already on `main`)

- `.github/workflows/pull.yml`, `.github/workflows/retry_failed_ci.yml` —
  already merged to `main` directly.
- `.github/workflows/library_rust_tests.yml` — PR 1 introduces the
  scaffold changes; PR 18 owns the examples-driven follow-on
  (`1bd7853`: clippy `--all-features` + `cargo build --examples` +
  commented-out example run slot). PR 20 owns the `prim` backend-matrix
  change (default-backend coverage gate + FIPS-only parity step).
  `764ebc4` (go install for `aws-lc-rust-fips`) **has already landed on
  `main`** — the `actions/setup-go@v5` step is present in the workflow
  today, so it needs no home. The only still-unassigned drift is
  `9541d05` (commented-out keystore integ-test slot); the natural fit is
  PR 14 (`branch-key-store` owns keystore integ), but that assignment
  isn't final.

## PRs

### PR 1 — `client-scaffold`

**Topic:** Initial `mpl` crate scaffolding, async client/builder skeleton, and
repo-level dev-loop / CI infra (git hooks, workflow updates).
**Spec:** none (pre-spec setup).
**Review branch:** `aws-crypto-rust/client-scaffold-review`
**Sync worktree:** `/Users/jocorell/crypto-tools/rust/aws-crypto-tools-rust-client-scaffold`
**Base branch (PR target):** `main`
**Depends on:** —

**Source (mpl scaffold):**
- `mpl/Cargo.toml` (scaffold state — empty `[dependencies]`)
- `mpl/Cargo.lock` (scaffold state — package only)
- `mpl/src/lib.rs` (scaffold state — `mod client; pub use client::*;`)
- `mpl/src/client.rs`

**Source (repo / CI / dev-loop infra):**
- `.gitignore` (new — `target`, `.agent-reports`, duvet artifacts)
- `.githooks/pre-commit` (new — `cargo fmt` pre-commit hook)
- `.githooks/README.md` (new — hook setup docs)
- `.github/workflows/library_rust_tests.yml` (modified — adds Go install,
  `llvm-tools-preview`, `cargo-llvm-cov`, replaces `cargo test` with
  `cargo llvm-cov --all-features --workspace --fail-under-lines 100`)
- `CONTRIBUTING.md` (modified — adds hook install instructions)

**Tests:**
- `mpl/tests/test_mpl_client.rs`

**Compliance:** none.

**Notes:**
- This slice's review branch is the buildable scaffold that all later
  review branches stack on. CI is expected to pass, including the new 100%
  line-coverage gate.
- `lib.rs`, `Cargo.toml`, and `Cargo.lock` are shared files (see "Shared
  files" section). PR 1's snapshot is the original scaffold state from
  commit `c498a02`, **not** the current state on
  `aws-crypto-rust/unreviewed` — the unreviewed state references modules
  (`structures`, `cmm`, `keyring`) and depends on crates that are added by
  later slices. Each later slice's PR shows its incremental diff to these
  shared files.
- The infra files (gitignore, hooks, workflow, CONTRIBUTING) are
  one-time additions and are not modified again by later slices.

---

### PR 2 — `structures`

**Topic:** Framework structures (encryption / decryption materials, EDK,
encryption context, branch / beacon key materials, MaterialsError).
**Spec:** [`spec/framework/structures.md`](../../spec/framework/structures.md)
**Review branch:** `aws-crypto-rust/structures-review`
**Sync worktree:** `/Users/jocorell/crypto-tools/rust/aws-crypto-tools-rust-structures`
**Base branch (PR target):** `aws-crypto-rust/client-scaffold-review`
**Depends on:** PR 1

**Source:**
- `mpl/src/structures/mod.rs`
- `mpl/src/structures/decryption_materials.rs`
- `mpl/src/structures/encryption_materials.rs`
- `mpl/src/structures/encrypted_data_key.rs`
- `mpl/src/structures/encryption_context.rs`
- `mpl/src/structures/branch_key_materials.rs`
- `mpl/src/structures/beacon_key_materials.rs`
- `mpl/src/structures/error.rs`

**Tests:**
- `mpl/tests/test_decryption_materials.rs`
- `mpl/tests/test_encryption_materials.rs`
- `mpl/tests/test_encrypted_data_key.rs`
- `mpl/tests/test_encryption_context.rs`
- `mpl/tests/test_branch_key_materials.rs`
- `mpl/tests/test_beacon_key_materials.rs`

**Compliance:** annotations are inline in source/tests; no dedicated
compliance directory.

**Notes:**
- This snapshot is the slice-2-state of these files: structures and
  `MaterialsError` as introduced by this slice. Later slices contribute
  incremental diffs to shared files (`error.rs` in PR 5; `encrypted_data_key.rs`
  and the materials structs in PRs 3 / 5) — those diffs appear in the
  later PR, not this one.
- `algorithm_suite.rs` and `commitment_policy.rs` are owned by PRs 3 and 4
  respectively and are not in this PR.
- `mpl/src/lib.rs`, `mpl/Cargo.toml`, and `mpl/Cargo.lock` are shared files
  carried over from PR 1; PR 2's diff to them (e.g., `+pub mod structures;`
  in `lib.rs`) is included in this PR.

---

### PR 3 — `algorithm-suite`

**Topic:** `AlgorithmSuiteId` enum, per-suite spec table, and full algorithm
suite types (encryption alg, KDF, signature alg, format).
**Spec:** [`spec/framework/algorithm-suites.md`](../../spec/framework/algorithm-suites.md)
**Review branch:** `aws-crypto-rust/algorithm-suite-review`
**Sync worktree:** `/Users/jocorell/crypto-tools/rust/aws-crypto-tools-rust-algorithm-suite`
**Base branch (PR target):** `aws-crypto-rust/structures-review`
**Depends on:** PR 2

**Source:**
- `mpl/src/structures/algorithm_suite.rs`

**Tests:**
- `mpl/tests/test_algorithm_suite.rs`
- `mpl/tests/test_algorithm_suite_id.rs`

**Compliance:**
- `mpl/compliance/spec/framework/algorithm-suites/*.toml`

**Notes:**
- `algorithm_suite.rs` was first introduced in the structures commit but is
  primarily reviewed here because the substantive content (enum, per-suite
  table, type system) is this slice's concern.

---

### PR 4 — `commitment-policy`

**Topic:** `CommitmentPolicy` enum (ESDK + DBE variants) with
default-suite-lookup and per-suite allow checks.
**Spec:** [`spec/framework/commitment-policy.md`](../../spec/framework/commitment-policy.md)
**Review branch:** `aws-crypto-rust/commitment-policy-review`
**Sync worktree:** `/Users/jocorell/crypto-tools/rust/aws-crypto-tools-rust-commitment-policy`
**Base branch (PR target):** `aws-crypto-rust/algorithm-suite-review`
**Depends on:** PR 3

**Source:**
- `mpl/src/structures/commitment_policy.rs`

**Tests:**
- `mpl/tests/test_commitment_policy.rs`

**Compliance:**
- `mpl/compliance/spec/framework/commitment-policy/*.toml`

**Notes:**
- Touches `algorithm_suite.rs` only via its public surface; no source ownership
  shifts.

---

### PR 5 — `keyring-and-cmm-interfaces`

**Topic:** `Keyring` and `Cmm` async traits, `EncryptionMaterialsRequest`,
`DecryptMaterialsRequest`, and the `MaterialsError` extensions used by
both interfaces.
**Spec:**
- [`spec/framework/keyring-interface.md`](../../spec/framework/keyring-interface.md)
- [`spec/framework/cmm-interface.md`](../../spec/framework/cmm-interface.md)

**Review branch:** `aws-crypto-rust/keyring-and-cmm-interfaces-review`
**Sync worktree:** `/Users/jocorell/crypto-tools/rust/aws-crypto-tools-rust-keyring-and-cmm-interfaces`
**Base branch (PR target):** `main`
**Depends on:** PR 2 (materials, error), PR 3 (algorithm suite), PR 4 (commitment policy — used on the `EncryptionMaterialsRequest` type)

**Source:**
- `mpl/src/keyring/mod.rs`
- `mpl/src/cmm/mod.rs`
- `mpl/src/cmm/request.rs`

**Tests:**
- `mpl/tests/test_keyring_contract.rs`
- `mpl/tests/test_materials_error.rs`
- `mpl/tests/test_cmm_contract.rs`

**Compliance:**
- `mpl/compliance/spec/framework/keyring-interface/*.toml`
- `mpl/compliance/spec/framework/cmm-interface/*.toml`

**Notes:**
- Originally scoped as two separate slices (PR 5 `keyring-interface` and
  PR 6 `cmm-interface`); combined into one because the Keyring and Cmm
  traits share the `MaterialsError` extensions and both follow the
  identical dyn-trait pattern, so reviewing them together is more
  coherent than a stacked pair.
- The `MaterialsError` extensions live in `mpl/src/structures/error.rs`,
  which is **introduced by PR 2** but extended here with new
  `MaterialsErrorKind` variants used by both traits. PR 5's diff to
  `error.rs` shows those variants added on top of PR 2's snapshot.
- Contract tests (`test_keyring_contract.rs` and `test_cmm_contract.rs`)
  use the same dyn-trait pattern; `test_materials_error.rs` covers the
  new error variants directly.
- Shared-file modifications introduced by this PR: `lib.rs` (adds
  `pub mod keyring; pub use keyring::Keyring;` and `pub mod cmm; pub use
  cmm::{Cmm, DecryptMaterialsRequest, EncryptionMaterialsRequest};`);
  `Cargo.toml` / `Cargo.lock` (adds `async-trait` under `[dependencies]`
  and `tokio` with `["rt", "macros"]` features under `[dev-dependencies]`
  for `#[tokio::test]` on the contract tests); `structures/mod.rs`
  (re-exports `MaterialsErrorKind` alongside `MaterialsError`);
  `error.rs` (new `MaterialsErrorKind` variants and matching
  constructors).

---

### PR 6 — `default-cmm`

**Topic:** `DefaultCmm` implementation (delegates to a `Keyring`, applies
commitment-policy and algorithm-suite rules).
**Spec:** [`spec/framework/default-cmm.md`](../../spec/framework/default-cmm.md)
**Review branch:** `aws-crypto-rust/default-cmm-review`
**Sync worktree:** `/Users/jocorell/crypto-tools/rust/aws-crypto-tools-rust-default-cmm`
**Base branch (PR target):** `main` (PR 5 is merged; the stack resets here)
**Depends on:** PR 4, PR 5

**Source:**
- `mpl/src/cmm/default_cmm.rs`

**Tests:**
- `mpl/tests/test_default_cmm.rs`

**Compliance:** annotations are inline in source/tests; no dedicated
compliance directory yet.

**Notes:**
- Modifies `mpl/src/cmm/mod.rs` (re-export). That file is **introduced by
  PR 5**; PR 6's diff to it appears in this PR.
- Shared-file modifications introduced by this PR: `cmm/mod.rs` (re-export
  for `DefaultCmm`), `lib.rs` (if applicable), `Cargo.toml` / `Cargo.lock`
  (any new deps).

---

### PR 7 — `structures-polish` *(folded into PR 8)*

**Status:** folded. The originally-planned polish content
(`EncryptionContext` reject-trailing-bytes bugfix, u16::MAX boundary,
multibyte-UTF-8 and known-vector tests, BTreeMap-entry-API perf,
`derive(Debug)` on materials structs, drop-redundant-duvet-annotation
stance) all landed as part of PR 2's merge (#15). The two residual
drift diffs on `unreviewed`
(`#[derive(Clone)]` + `uuid`-decode doc extension on
`BranchKeyMaterials`, and a `MaterialsErrorKind::Validation` comment
update in `test_encryption_context.rs`) are absorbed into PR 8's
`scope_files` and ship with `mrk-match`. This slot is retained for
numbering stability; the review branch, sync worktree, and PR were
never opened.

---

### PR 8 — `mrk-match`

**Topic:** `aws_kms::mrk_match` shared utility — the MRK-match-for-decrypt
algorithm used by hierarchical keyring and (future) MRK keyring decrypt
paths. Absorbs the residual `structures-polish` drift from the folded
PR 7.
**Spec:** [`spec/framework/aws-kms/aws-kms-mrk-match-for-decrypt.md`](../../spec/framework/aws-kms/aws-kms-mrk-match-for-decrypt.md)
**Review branch:** `aws-crypto-rust/mrk-match-review`
**Sync worktree:** `/Users/jocorell/crypto-tools/rust/aws-crypto-tools-rust-mrk-match`
**Base branch (PR target):** `main` (PR 6 is merged; PR 7 is folded — stack is currently reset)
**Depends on:** PR 1 (scaffold)

**Source:**
- `mpl/src/aws_kms/mod.rs` (introduces the module with `pub mod mrk_match;`)
- `mpl/src/aws_kms/mrk_match.rs`

**Source (folded from PR 7 — diffs to PR-2-owned files):**
- `mpl/src/structures/branch_key_materials.rs` (`#[derive(Clone)]` and
  `branch_key_version` doc extension referencing the `uuid`-decode
  path)

**Tests:**
- `mpl/tests/test_aws_kms_mrk_match.rs`

**Tests (folded from PR 7):**
- `mpl/tests/test_encryption_context.rs` (comment update referencing
  `MaterialsErrorKind::Validation`)

**Compliance:**
- `mpl/compliance/spec/framework/aws-kms/aws-kms-mrk-match-for-decrypt/*.toml`

**Notes:**
- Shared-file modifications introduced by this PR: `lib.rs` (adds `pub
  mod aws_kms;`), `.duvet/config.toml` (registers the mrk-match spec).
- Later slices (16, 17) extend `aws_kms/mod.rs` with feature-gated
  hkeyring modules.
- The two files inherited from PR 7 are small non-substantive
  cleanups; they are listed here so PR 8's review branch is a
  buildable, spec-consistent snapshot of `main` plus this slice.

---

### PR 9 — `cmc-interface`

**Topic:** Abstract `Cmc` async trait, `CacheEntry`, `CachedMaterials`,
`UsageMetadata`, `BytesUsage`, `MessageUsage` — the cache contract that
every concrete CMC implements.
**Spec:** [`spec/framework/cryptographic-materials-cache.md`](../../spec/framework/cryptographic-materials-cache.md)
**Review branch:** `aws-crypto-rust/cmc-interface-review`
**Sync worktree:** `/Users/jocorell/crypto-tools/rust/aws-crypto-tools-rust-cmc-interface`
**Base branch (PR target):** `aws-crypto-rust/mrk-match-review`
**Depends on:** PR 2 (materials), PR 3 (algorithm suite)

**Source:**
- `mpl/src/cmc/mod.rs`
- `mpl/src/cmc/entry.rs`

**Tests:**
- `mpl/tests/test_cmc_contract.rs`

**Compliance:**
- `mpl/compliance/spec/framework/cryptographic-materials-cache/*.toml`

**Notes:**
- Uses `async_trait` for `dyn Cmc` compatibility, same rationale as
  PR 5. Behavioral MUSTs on `put_cache_entry` / `get_cache_entry`
  are annotated `type=exception` here; slices 10 and 12 convert them to
  `type=implementation` + `type=test` on concrete caches.
- Shared-file modifications introduced by this PR: `lib.rs` (adds `pub
  mod cmc; pub use cmc::{Cmc, CacheEntry, CachedMaterials, UsageMetadata,
  BytesUsage, MessageUsage};`), `.duvet/config.toml` (registers the
  cryptographic-materials-cache spec).

---

### PR 10 — `local-cmc`

**Topic:** `LocalCmc` — the concrete in-memory LRU cache with TTL-aware
pruning that the MPL ships as its default cache.
**Spec:** [`spec/framework/local-cryptographic-materials-cache.md`](../../spec/framework/local-cryptographic-materials-cache.md)
**Review branch:** `aws-crypto-rust/local-cmc-review`
**Sync worktree:** `/Users/jocorell/crypto-tools/rust/aws-crypto-tools-rust-local-cmc`
**Base branch (PR target):** `aws-crypto-rust/cmc-interface-review`
**Depends on:** PR 9

**Source:**
- `mpl/src/cmc/local.rs`

**Tests:**
- `mpl/tests/test_local_cmc.rs`

**Compliance:**
- `mpl/compliance/spec/framework/local-cryptographic-materials-cache/*.toml`

**Notes:**
- Shared-file modifications introduced by this PR: `cmc/mod.rs` (adds
  `pub mod local; pub use local::LocalCmc;`); `.duvet/config.toml`
  (registers the local-cmc spec).
- Fulfils PR 9's TTL / entry-lifecycle exception annotations with
  `type=implementation` + `type=test` on `LocalCmc`.

---

### PR 11 — `storm-tracking-cmc`

**Topic:** `StormTrackingCmc` — storm-tracking wrapper around `LocalCmc`
that suppresses thundering-herd on cache misses.
**Spec:** [`spec/framework/storm-tracking-cryptographic-materials-cache.md`](../../spec/framework/storm-tracking-cryptographic-materials-cache.md)
**Review branch:** `aws-crypto-rust/storm-tracking-cmc-review`
**Sync worktree:** `/Users/jocorell/crypto-tools/rust/aws-crypto-tools-rust-storm-tracking-cmc`
**Base branch (PR target):** `main` (PR 10 is merged; the stack resets here)
**Depends on:** PR 10

**Source:**
- `mpl/src/cmc/storm_tracking.rs`
- `mpl/src/cmc/local.rs` (retrofits `test-utils` feature gate onto PR 10's
  `LocalCmc::with_clock`; splits `with_clock` into feature-gated public
  wrapper + `pub(crate)` `with_clock_impl` so `StormTrackingCmc` can
  still construct its inner cache without depending on the `test-utils`
  feature)

**Tests:**
- `mpl/tests/test_storm_tracking_cmc.rs`
- `mpl/tests/test_local_cmc.rs` (adds `#![cfg(feature = "test-utils")]`
  crate-level gate matching the storm-tracking test file, because these
  tests rely on `LocalCmc::with_clock`)

**Compliance:**
- `mpl/compliance/spec/framework/storm-tracking-cryptographic-materials-cache/*.toml`

**Notes:**
- Shared-file modifications introduced by this PR: `cmc/mod.rs` (adds
  `pub mod storm_tracking; pub use storm_tracking::{StormTrackingCmc,
  TimeUnits};`); `mpl/Cargo.toml` (promotes `tokio` to `[dependencies]`
  with features `["rt", "macros", "time"]` because
  `StormTrackingCmc::get_cache_entry` calls `tokio::time::sleep` in the
  library body; also adds `test-utils = []` under `[features]` to gate
  the test-only constructor / observability hooks on both `LocalCmc`
  and `StormTrackingCmc`); `.duvet/config.toml` (registers the
  storm-tracking spec).
- Scope note: PR 10 (`local-cmc`) is already merged as of `8a5ae90`,
  but this PR retrofits the `test-utils` feature gate onto
  `LocalCmc::with_clock` and the corresponding test file. That
  expansion is intentional — the `test-utils` feature is introduced by
  this PR, so applying it to `LocalCmc` in the same PR keeps the
  visibility change coherent and avoids leaving `LocalCmc::with_clock`
  as a publicly exposed test-only constructor after PR 11 merges.

---

### PR 12 — `keystore-interface`

**Topic:** `Keystore` async trait scaffolding, `KeyStoreConfig`,
`KmsConfiguration`, `KeystoreError` — the abstract keystore contract.
No concrete keystore yet; every operation method is annotated
`type=exception` with a `reason=` pointing at the phase that will
fulfil it.
**Spec:** [`spec/framework/branch-key-store.md`](../../spec/framework/branch-key-store.md) (interface-level requirements)
**Review branch:** `aws-crypto-rust/keystore-interface-review`
**Sync worktree:** `/Users/jocorell/crypto-tools/rust/aws-crypto-tools-rust-keystore-interface`
**Base branch (PR target):** `main`
**Depends on:** PR 2 (materials), PR 3 (algorithm suite)

**Source:**
- `mpl/src/keystore/mod.rs`
- `mpl/src/keystore/config.rs`
- `mpl/src/keystore/kms_config.rs`
- `mpl/src/keystore/error.rs`

**Tests:**
- `mpl/tests/test_keystore_contract.rs`

**Compliance:**
- `mpl/compliance/spec/framework/branch-key-store/*.toml` (introduces
  the full compliance directory; interface-level TOMLs get
  `type=exception` annotations here, operation-specific TOMLs get their
  concrete annotations in slices 13 and 15)

**Notes:**
- Base is `main`, not the previous slice's review branch — PR 12 has no
  code dependency on PR 11 (`storm-tracking-cmc`), so the two can be
  opened and reviewed in parallel. Shared-file diffs to `Cargo.toml`
  and `lib.rs` overlap in the `[features]` block and module list
  respectively but their content is disjoint (PR 11 adds `test-utils` +
  the tokio promotion; PR 12 adds the keystore mod line).
  When PR 11 merges, PR 12 rebases onto the new `main` and its diff is
  unchanged. When PR 12 merges first, PR 11 rebases its shared-file
  diffs on top of PR 12's.
- Introduces the `pub mod keystore;` line in `lib.rs`. (The original plan
  gated this behind a `keystore` cargo feature; that feature was later
  removed crate-wide and the keystore is unconditional — see the
  repo-wide note in "Shared files".)
- Registers `branch-key-store.md` in `.duvet/config.toml`.
- No new runtime deps yet; deps come with the concrete impl in PR 14.

---

### PR 13 — `keystore-support`

**Topic:** Pure-logic keystore helpers — record format serialization
and encryption-context construction. Called by (future) concrete
keystore implementations.
**Spec:** `spec/framework/branch-key-store.md` (record-format /
encryption-context sub-requirements)
**Review branch:** `aws-crypto-rust/keystore-support-review`
**Sync worktree:** `/Users/jocorell/crypto-tools/rust/aws-crypto-tools-rust-keystore-support`
**Base branch (PR target):** `aws-crypto-rust/keystore-interface-review`
**Depends on:** PR 12

**Source:**
- `mpl/src/keystore/record.rs`
- `mpl/src/keystore/encryption_context.rs`

**Tests:**
- `mpl/tests/test_keystore_record.rs`
- `mpl/tests/test_keystore_encryption_context.rs`
- `mpl/tests/test_keystore_kms_config.rs`

**Compliance:** incremental annotations on
`mpl/compliance/spec/framework/branch-key-store/{record-format,
encryption-context, active-encryption-context, decrypt-only-encryption-context,
custom-encryption-context, ...}.toml`.

**Notes:**
- Shared-file modifications introduced by this PR: `keystore/mod.rs`
  (adds `pub mod record;` and `pub mod encryption_context;`).
- No new runtime deps.

---

### PR 14 — `branch-key-store`

**Topic:** Concrete `BranchKeyStore` — construction, `GetKeyStoreInfo`,
and the read path (`GetActiveBranchKey`, `GetBranchKeyVersion`) plus the
KMS decrypt helper. Real DDB-backed keystore. The write operations are
deferred to PR 19.
**Spec:** `spec/framework/branch-key-store.md` (operation-level
requirements)
**Review branch:** `aws-crypto-rust/branch-key-store-review`
**Sync worktree:** `/Users/jocorell/crypto-tools/rust/aws-crypto-tools-rust-branch-key-store`
**Base branch (PR target):** `main` (PR 13 merged; stack reset)
**Depends on:** PR 12, PR 13

**Source:**
- `mpl/src/keystore/branch_key_store.rs`
- `mpl/src/keystore/kms_ops.rs`

**Tests:**
- `mpl/tests/test_keystore_branch_key_store.rs`
- `mpl/tests/test_keystore_branch_key_store_integ.rs`

**Compliance:** incremental annotations on
`mpl/compliance/spec/framework/branch-key-store/{getactivebranchkey,
getbranchkeyversion, getkeystoreinfo, aws-kms-branch-key-decryption,
dynamodb-client, kms-client, keystore-id, ...}.toml`. The `createkey`,
`versionkey`, `createkeystore`, `getbeaconkey`, and
`authenticating-a-keystore-item` operation TOMLs are owned by PR 19.

**Notes:**
- Delivers construction + `GetKeyStoreInfo` + the read path only. The
  write operations (`CreateKeyStore`, `CreateKey`, `VersionKey`) and
  `GetBeaconKey` are stubbed here (return `KeystoreError::Internal`
  "not yet implemented") and implemented in PR 19
  (`branch-key-store-write`).
- Shared-file modifications introduced by this PR: `Cargo.toml` /
  `Cargo.lock` (adds `aws-config`, `aws-sdk-dynamodb`, `aws-sdk-kms`,
  `base64`, `uuid`, `tokio`); `keystore/mod.rs` (adds `pub mod
  branch_key_store; pub use branch_key_store::BranchKeyStore;
  pub(crate) mod kms_ops;`); `lib.rs` (adds `pub use
  keystore::{BranchKeyStore, KeyStoreConfig, KeyStoreInfo,
  Keystore, KeystoreError, KmsConfiguration, encryption_context,
  kms_config, record};`).
- Includes the DDB-Number-typed-attribute parsing fix and the
  `uuid`-crate switch for keystore-id generation.
- Integration tests (`_integ`) are gated on env vars and are noop when
  credentials aren't present; a commented-out CI step reserves the slot
  for running them once OIDC-role plumbing lands. Coordinate with the
  Out-of-scope note on `library_rust_tests.yml`.
- Converts PR 12's remaining `type=exception` annotations on operation
  methods to `type=implementation` + `type=test`.

---

### PR 19 — `branch-key-store-write`

**Topic:** The remaining concrete `BranchKeyStore` operations —
`CreateKeyStore`, `CreateKey`, `VersionKey`, and `GetBeaconKey` —
completing the DDB-backed keystore. Adds the KMS `ReEncrypt`-based
"authenticating a keystore item" helper, the KMS
`GenerateDataKeyWithoutPlaintext` create/version paths, and the DDB
`CreateTable` / `TransactWriteItems` write paths. Replaces the
`not_implemented_yet` stubs left by PR 14.
**Spec:** `spec/framework/branch-key-store.md` (`createkey`,
`versionkey`, `createkeystore`, `getbeaconkey`, and
`authenticating-a-keystore-item` operation-level requirements)
**Review branch:** `aws-crypto-rust/branch-key-store-write-review`
**Sync worktree:** `/Users/jocorell/crypto-tools/rust/aws-crypto-tools-rust-branch-key-store-write`
**Base branch (PR target):** `main` (rebased onto `main` after PR 14 merged; the stack reset)
**Depends on:** PR 12, PR 13, PR 14

**Sequencing:** slotted here (before PR 15) so a functionally complete
keystore lands before the hierarchical-keyring work builds on it. The
higher PR number preserves stable identifiers (numbers are IDs, not
ordering — see the PR 7 precedent); the review order is what governs
sequencing.

**Source:**
- `mpl/src/keystore/branch_key_store.rs` (implements the four stubbed
  operations)
- `mpl/src/keystore/kms_ops.rs` (restores the `authenticate_keystore_item`
  `ReEncrypt` helper removed as dead code in PR 14, plus the
  `GenerateDataKeyWithoutPlaintext` helper)

**Tests:**
- `mpl/tests/test_keystore_branch_key_store.rs` (input validation +
  record construction for the new operations)
- `mpl/tests/test_keystore_branch_key_store_integ.rs` (real-AWS
  create / version / beacon round trips)

**Compliance:** incremental annotations on
`mpl/compliance/spec/framework/branch-key-store/{createkey, versionkey,
createkeystore, getbeaconkey, authenticating-a-keystore-item, ...}.toml`.

**Notes:**
- No new runtime deps: `CreateKey` / `VersionKey` use
  `aws-sdk-kms` (`GenerateDataKeyWithoutPlaintext`, `Decrypt`,
  `ReEncrypt`) and `aws-sdk-dynamodb` (`TransactWriteItems`);
  `CreateKeyStore` uses `aws-sdk-dynamodb` `CreateTable` — all already
  carried from PR 14.
- No new shared-file changes: `keystore/mod.rs` already declares
  `branch_key_store` / `kms_ops` (PR 14). This slice's diff is confined
  to the two source files, the two test files, and the compliance TOMLs.

---

### PR 20 — `primitives`

**Topic:** The `prim` crate (`aws-mpl-primitives`) — a thin, internal
wrapper over `aws-lc-rs` providing the crypto primitives the rest of the
repo builds on: AES-GCM, HMAC, digest, HKDF, ECDSA, KBKDF-CTR-HMAC,
constant-time compare, and a CSPRNG helper. Entirely new; absent from
`main`.
**Spec:** none. There is no primitives spec under `spec/`, and the crate
carries no duvet annotations. Non-spec slice, like PR 1.
**Review branch:** `aws-crypto-rust/primitives-review`
**Sync worktree:** `/Users/jocorell/crypto-tools/rust/aws-crypto-tools-rust-primitives`
**Base branch (PR target):** `main`
**Depends on:** —

**Sequencing:** must land before PR 15. PR 15's source imports
`aws_mpl_primitives`, and the crate does not exist on `main`, so PR 15
cannot build without it. Numbers are IDs, not ordering — see the PR 7 and
PR 19 precedents; the review order is what governs sequencing.

**Source:**
- `prim/Cargo.toml`
- `prim/Cargo.lock`
- `prim/Makefile`
- `prim/README.md`
- `prim/.gitignore`
- `prim/src/lib.rs` (`DigestAlg`, `Error`, `AesGcm`,
  `generate_random_bytes`, `aes_encrypt`, `aes_decrypt`, `hmac`,
  `digest`, `constant_time_equal`, `kbkdf_ctr_hmac`)
- `prim/src/ecdsa.rs` (`DigestContext`, `EcdsaSignatureAlgorithm`,
  `ecdsa_sign`, `ecdsa_sign_digest`, `ecdsa_verify`,
  `ecdsa_verify_context`, `ecdsa_generate_keypair`)
- `prim/src/hkdf.rs` (`Prk`, `hkdf`, `hkdf_no_salt`, `hkdf_extract`,
  `hkdf_expand`)

**Source (CI):**
- `.github/workflows/library_rust_tests.yml` (modified — excludes `prim`
  from `--all-features` on the coverage step so the gate measures the
  default non-FIPS backend, and adds a `prim`-only `cargo test
  --no-default-features --features fips` parity step. `esdk` and `mpl`
  behaviour is unchanged.)

**Tests:**
- `prim/tests/test_aes.rs`
- `prim/tests/test_constant_time.rs`
- `prim/tests/test_digest.rs`
- `prim/tests/test_ecdsa.rs`
- `prim/tests/test_error.rs`
- `prim/tests/test_generate_random_bytes.rs`
- `prim/tests/test_hkdf.rs`
- `prim/tests/test_hmac.rs`
- `prim/tests/test_kbkdf_ctr_hmac.rs`

**Compliance:** none.

**Notes:**
- 69 tests, passing on both backends. Line coverage 96.52%, comfortably
  over the workflow's 80% gate. Vectors are real: RFC 5869 A.1–A.3 for
  HKDF, NIST SP 800-108 vectors for KBKDF-CTR-HMAC.
- **Backends.** `default = ["aws-lc-rs/aws-lc-sys"]` (non-FIPS) and an
  opt-in `fips = ["aws-lc-rs/fips"]`. `fips` is an *override*, not an
  addition: `aws-lc-rs` gates `extern crate aws_lc_fips_sys` on
  `cfg(feature = "fips")`, so `--features fips` alone leaves `default`
  on and wastefully compiles `aws-lc-sys` too. A FIPS-only build needs
  `--no-default-features --features fips`. This is why the coverage step
  drops `--all-features` for `prim` — otherwise the gate would measure
  FIPS and the shipping default backend would go untested. `prim` has no
  `cfg(feature = ...)` code, so this costs no coverage.
- **`aws-lc-rs` version.** `prim` declares `1.15.4` with
  `default-features = false`, resolving to 1.17.1. This matches `esdk`
  exactly (same version string, same `default`/`fips` feature pair) —
  `esdk` uses no `=` pins at all. `mpl` is the outlier at `=1.17.0`. No
  reconciliation is needed for this slice: there is no workspace
  `Cargo.toml` (each crate has its own lockfile) and `main`'s `mpl` does
  not depend on `prim`. Reconcile in PR 15, where `mpl` first takes the
  dependency; the two requirements unify at 1.17.0 there.
- **Scope is `prim`-only, deliberately.** Of the `prim` consumers on
  `unreviewed`, `branch_key_wrap.rs`, `cache_entry_identifier.rs`,
  `hierarchical_keyring.rs`, and
  `test_aws_kms_hierarchical_keyring.rs` are all absent from `main`
  (PR 15 / PR 16 files). Only `mpl/src/cmm/default_cmm.rs` is on `main`,
  where it still imports `aws_lc_rs::signature`; its migration onto
  `prim` is left to PR 15 or a follow-up. Pulling it in would drag
  `mpl/Cargo.toml` into scope, and per `pull.yml` any `mpl/**` change
  fans CI out to every project — a full-repo CI event for a refactor of
  an already-merged file.
- A second, unrelated crate also named `aws-mpl-primitives` lives at
  `unsafe-unreviewed-mpl/prim` and is already on `main`. `esdk` depends
  on `unsafe-unreviewed-mpl/mpl`, which depends on *its own* sibling
  `../prim`, not this one. No collision (there is no workspace), and
  landing `prim/` cannot affect `esdk` — but the duplicate name is a
  future footgun.
- Coverage in `ecdsa.rs` is mildly nondeterministic (96.2–96.5%): the
  retry loops in `ecdsa_sign` / `ecdsa_sign_digest` spin until the DER
  signature hits a fixed length, so whether the retry branch is taken
  varies run to run. Harmless against an 80% gate; it will flake if the
  gate is raised toward 100.

---

### PR 15 — `hkeyring-support`

**Topic:** `aws_kms::branch_key_wrap` (branch-key wrap / unwrap AEAD
crypto) and `aws_kms::cache_entry_identifier` (cache-key derivation for
hierarchical keyring). Both crate-internal, exposed via
`__test_internals` for integration tests.
**Spec:** `spec/framework/aws-kms/aws-kms-hierarchical-keyring.md`
(wrap/unwrap and cache-identifier sub-requirements)
**Review branch:** `aws-crypto-rust/hkeyring-support-review`
**Sync worktree:** `/Users/jocorell/crypto-tools/rust/aws-crypto-tools-rust-hkeyring-support`
**Base branch (PR target):** `aws-crypto-rust/primitives-review` (PR 20 — required, since this slice's source imports the `prim` crate, which is absent from `main`)
**Depends on:** PR 8 (aws_kms module), PR 14 (branch-key-store types), PR 19 (sequencing — stacked on the complete keystore), PR 20 (`prim` crate — hard code dependency)

**Source:**
- `mpl/src/aws_kms/branch_key_wrap.rs`
- `mpl/src/aws_kms/cache_entry_identifier.rs`

**Tests:** none direct — exposed via `#[doc(hidden)] pub mod
__test_internals` and exercised by the hkeyring integration tests in
PR 16.

**Compliance:** incremental annotations on
`mpl/compliance/spec/framework/aws-kms/aws-kms-hierarchical-keyring/*.toml`
(wrap/unwrap and cache-identifier sub-requirements only).

**Notes:**
- Shared-file modifications introduced by this PR: `Cargo.toml` /
  `Cargo.lock` (adds the `aws-mpl-primitives` path dependency for the
  AEAD wrap/unwrap and KBKDF primitives — **not** `aws-lc-rs`; `mpl` has
  no `fips` feature and, once migrated, should not declare `aws-lc-rs`
  directly at all. Note `aws-lc-rs` stays in `mpl`'s graph transitively
  via `rustls` / `aws-smithy-http-client` regardless);
  `aws_kms/mod.rs` (adds `pub(crate) mod branch_key_wrap;`,
  `pub(crate) mod cache_entry_identifier;`, and the
  `#[doc(hidden)] pub mod __test_internals` re-export module).
- The `mpl` migration commits are `a5b8f55` (KBKDF-CTR-HMAC routed
  through `prim`) and `b665b03` (RNG, digest, AES-GCM call sites). The
  `prim` APIs they rely on were added on `unreviewed` only: `a555b58`
  (`kbkdf_ctr_hmac`) and `025baca` (`DigestAlg::output_len`).
  Pre-migration versions of these files are recoverable at `a5b8f55^`.
- `mpl/src/cmm/default_cmm.rs` was also migrated onto `prim` on
  `unreviewed`, but it is a PR-6 file already merged to `main` in its
  `aws-lc-rs` form. That migration diff is deliberately **not** in
  PR 20 (which is `prim`-only) and should land here or in a dedicated
  follow-up slice.
- Consider testing directly here instead of leaning entirely on PR 16's
  integration tests — reviewers to flag if additional unit coverage is
  wanted.

---

### PR 16 — `hkeyring`

**Topic:** `HierarchicalKeyring` — full `on_encrypt` / `on_decrypt`
implementation, `CacheType` enum (default local + custom-sized + shared
CMC + storm-tracking), `BranchKeySupplier` trait.
**Spec:** [`spec/framework/aws-kms/aws-kms-hierarchical-keyring.md`](../../spec/framework/aws-kms/aws-kms-hierarchical-keyring.md)
**Review branch:** `aws-crypto-rust/hkeyring-review`
**Sync worktree:** `/Users/jocorell/crypto-tools/rust/aws-crypto-tools-rust-hkeyring`
**Base branch (PR target):** `aws-crypto-rust/hkeyring-support-review`
**Depends on:** PR 8 (mrk-match), PR 11 (CMC family), PR 14
(BranchKeyStore), PR 15 (hkeyring-support)

**Source:**
- `mpl/src/aws_kms/hierarchical_keyring.rs`

**Tests:**
- `mpl/tests/test_aws_kms_hierarchical_keyring.rs`
- `mpl/tests/test_aws_kms_hierarchical_keyring_integ.rs`

**Compliance:**
- `mpl/compliance/spec/framework/aws-kms/aws-kms-hierarchical-keyring/*.toml`
  (remaining operation-level TOMLs; wrap/unwrap and cache-identifier
  TOMLs are already annotated by PR 15)

**Notes:**
- Shared-file modifications introduced by this PR: `aws_kms/mod.rs`
  (adds `pub mod hierarchical_keyring;`).
- Contributing commits: `7e5be02`, `2fe3ad9`, `405e461`, `0340578`,
  `228b418`, `90e817e`. Reviewers may want a further split
  (construction vs. on_encrypt vs. on_decrypt vs. cache-wiring) if the
  ~49 KB single file is too big for one review.

---

### PR 17 — `client-factories`

**Topic:** `MaterialProviders` client factory methods —
`create_cryptographic_materials_cache`, `create_branch_key_store`, and
`create_aws_kms_hierarchical_keyring` — plus corresponding builder types.
**Spec:** none new (composition surface only).
**Review branch:** `aws-crypto-rust/client-factories-review`
**Sync worktree:** `/Users/jocorell/crypto-tools/rust/aws-crypto-tools-rust-client-factories`
**Base branch (PR target):** `aws-crypto-rust/hkeyring-review`
**Depends on:** PR 11 (CMC), PR 14 (BranchKeyStore), PR 16
(HierarchicalKeyring)

**Source:**
- `mpl/src/client.rs` (diffs to PR-1-owned file — adds the three factory
  methods and their builder types)

**Tests:**
- `mpl/tests/test_mpl_client.rs` (diffs — coverage for the three
  factories)

**Compliance:** none.

**Notes:**
- Every file in this slice is a shared file introduced by PR 1. This
  PR shows the incremental diff only.
- No new deps; all runtime deps already in place from PR 14 / PR 15.

---

### PR 18 — `hkeyring-examples`

**Topic:** Runnable AWS KMS Hierarchical Keyring examples demonstrating
single-tenant, multi-tenant, and cache-configuration composition patterns
against a real keystore.
**Spec:** none (runnable docs; no new spec).
**Review branch:** `aws-crypto-rust/hkeyring-examples-review`
**Sync worktree:** `/Users/jocorell/crypto-tools/rust/aws-crypto-tools-rust-hkeyring-examples`
**Base branch (PR target):** `aws-crypto-rust/client-factories-review`
**Depends on:** PR 14, PR 16, PR 17

**Source (examples):**
- `mpl/examples/aws_kms_hierarchical/main.rs`
- `mpl/examples/aws_kms_hierarchical/common.rs`
- `mpl/examples/aws_kms_hierarchical/static_branch_key.rs`
- `mpl/examples/aws_kms_hierarchical/branch_key_supplier.rs`
- `mpl/examples/aws_kms_hierarchical/example_branch_key_id_supplier.rs`
- `mpl/examples/aws_kms_hierarchical/cache_configurations.rs`

**Source (CI):**
- `.github/workflows/library_rust_tests.yml` (modified — switches
  `cargo clippy --all-targets` to `--all-features` so feature-gated
  targets get linted, adds an explicit `cargo build --all-features
  --examples --verbose` step so the example is compile-verified in CI,
  and reserves a commented-out `TODO(integ-tests-creds)`-sibling block
  for actually running the example against real AWS once OIDC-role
  plumbing lands)

**Tests:** none. Compile coverage is enforced by the `cargo build
--all-features --examples` step in CI added by this slice; runtime
execution against real AWS is deferred until the paired OIDC-role
plumbing lands.

**Compliance:** none.

**Notes:**
- Terminal slice — MUST land after PRs 14, 17, and 18 so the review
  branch's `cargo build --examples` step resolves
  `HierarchicalKeyring`, `BranchKeyStore`, and the
  `MaterialProviders::create_*` factories. This "don't break CI"
  constraint is what pins the slice terminal.
- Shared-file modification introduced by this PR: `mpl/Cargo.toml`
  gains the `[[example]] name = "aws_kms_hierarchical"` block. All runtime
  dependencies
  (`aws-config`, `aws-sdk-kms`, `aws-sdk-dynamodb`, `tokio`) are
  already carried from earlier slices; this PR adds no new deps.
- This slice owns the examples-driven CI drift in
  `.github/workflows/library_rust_tests.yml` (commit `1bd7853`). Earlier
  workflow drift (`9541d05` keystore integ slot, `764ebc4` go install)
  is still unassigned — see the Out-of-scope note above.
- Modeled after the ESDK Rust hierarchical-keyring blueprint
  (`aws/aws-encryption-sdk/releases/rust/esdk/examples/keyring/aws_kms_hierarchical`),
  with two deviations documented on commit `9a9fc03`: the supplier is
  async (matches this repo's `BranchKeySupplier` trait), and encrypt /
  decrypt happen at the keyring layer (no ESDK client to drive through).

---

## Recommended review order

Status markers reflect the Status snapshot above; keep the two in sync.

1. PR 1 — `client-scaffold` — ✅ merged
2. PR 2 — `structures` — ✅ merged
3. PR 3 — `algorithm-suite` — ✅ merged as [#16](https://github.com/aws/aws-crypto-tools-rust/pull/16)
4. PR 4 — `commitment-policy` — ✅ merged as [#17](https://github.com/aws/aws-crypto-tools-rust/pull/17)
5. PR 5 — `keyring-and-cmm-interfaces` — ✅ merged as [#20](https://github.com/aws/aws-crypto-tools-rust/pull/20)
6. PR 6 — `default-cmm` — ✅ merged as [#28](https://github.com/aws/aws-crypto-tools-rust/pull/28)
7. PR 7 — `structures-polish` — 🗑️ folded into PR 8 *(substance landed via PR 2)*
8. PR 8 — `mrk-match` — ✅ merged as [#29](https://github.com/aws/aws-crypto-tools-rust/pull/29)
9. PR 9 — `cmc-interface` — ✅ merged as [#30](https://github.com/aws/aws-crypto-tools-rust/pull/30)
10. PR 10 — `local-cmc` — ✅ merged as [#31](https://github.com/aws/aws-crypto-tools-rust/pull/31)
11. PR 11 — `storm-tracking-cmc` — ✅ merged as [#33](https://github.com/aws/aws-crypto-tools-rust/pull/33)
12. PR 12 — `keystore-interface` — ✅ merged as [#35](https://github.com/aws/aws-crypto-tools-rust/pull/35)
13. PR 13 — `keystore-support` — ✅ merged as [#36](https://github.com/aws/aws-crypto-tools-rust/pull/36)
14. PR 14 — `branch-key-store` — ✅ merged as [#48](https://github.com/aws/aws-crypto-tools-rust/pull/48)
    - **Then PR 19 — `branch-key-store-write`** — ✅ merged as [#49](https://github.com/aws/aws-crypto-tools-rust/pull/49) (merge commit `6d00fae`); completed the keystore (`CreateKeyStore` / `CreateKey` / `VersionKey` / `GetBeaconKey`) before the keyring work.
15. PR 20 — `primitives` — ⬅️ **next up** *(bases on `main`; must precede PR 15, which cannot build without the `prim` crate)*
16. PR 15 — `hkeyring-support` *(bases on `aws-crypto-rust/primitives-review`)*
17. PR 16 — `hkeyring`
18. PR 17 — `client-factories`
19. PR 18 — `hkeyring-examples` *(terminal)*

Each PR description should:

- Note that this branch is part of a stacked review chain (see
  `docs/design-docs/pr-plan-by-spec.md`) and that CI is expected to pass
  on its own scope.
- Link to `aws-crypto-rust/unreviewed` for the full working tree.
- Link to the relevant `spec/framework/<file>.md`.
- Call out any shared-file modifications (lib.rs, Cargo.toml, error.rs,
  etc.) the PR introduces.
