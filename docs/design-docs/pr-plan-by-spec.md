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
  slice's contribution.
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

## Shared files (modified across slices)

These files are touched by more than one slice. Each slice's PR diff includes
that slice's incremental change to the file. The full file at the end of a
given slice's review branch is the snapshot of cumulative work through that
stack level.

- `mpl/Cargo.toml`, `mpl/Cargo.lock` — slice 1 introduces the scaffold (no
  deps). Later slices add deps as needed: PR 5 adds `async-trait`; PR 15
  adds `aws-config`, `aws-sdk-dynamodb`, `aws-sdk-kms`, `base64`, `uuid`,
  `tokio`; PR 16 adds `aws-lc-rs` (fips); PR 19 adds the
  `[[example]] name = "aws_kms_hierarchical"` block with
  `required-features = ["keystore"]`. PR 13 introduces the `[features]
  keystore` flag. Each slice's PR shows the diff it introduces.
- `mpl/src/lib.rs` — slice 1 introduces the scaffold (`mod client; pub use
  client::*;`). Slice 2 adds `pub mod structures;`. Slice 5 adds `pub mod
  keyring; pub use keyring::Keyring;`. Slice 6 adds `pub mod cmm; pub use
  cmm::{...};`. Slice 9 adds `pub mod aws_kms;`. Slice 10 adds `pub mod
  cmc; pub use cmc::{Cmc, CacheEntry, ...};` — later CMC slices extend
  the re-export list. Slice 13 adds `#[cfg(feature = "keystore")] pub
  mod keystore;`. Slice 15 adds `#[cfg(feature = "keystore")] pub use
  keystore::{BranchKeyStore, KeyStoreConfig, ...};`. Each slice's PR
  shows the lib.rs diff it introduces.
- `mpl/src/structures/mod.rs` — slice 2 introduces it. Slices 3 and 4 add
  submodule + re-export lines for `algorithm_suite` and `commitment_policy`.
- `mpl/src/structures/error.rs` — slice 2 introduces `MaterialsError` /
  `MaterialsErrorKind`. Slice 5 (keyring) extends with new variants. Slice 6
  may extend further.
- `mpl/src/structures/encryption_context.rs` and materials structs —
  slice 2 introduces them; slice 8 (`structures-polish`) applies the
  reject-trailing-bytes fix, boundary / UTF-8 / known-vector tests,
  BTreeMap-entry-API perf, materials `derive(Debug)`, and the
  drop-redundant-duvet-annotation stance. Slice 8's PR shows its
  incremental diff to these PR-2-owned files.
- `mpl/src/client.rs` — slice 1 introduces it. Slice 18
  (`client-factories`) adds `create_cryptographic_materials_cache`,
  `create_branch_key_store`, and `create_aws_kms_hierarchical_keyring`
  factory methods. Slice 18's PR shows the incremental diff.
- `mpl/src/cmm/mod.rs` — slice 6 introduces it. Slice 7 modifies its
  re-exports for `DefaultCmm`.
- `mpl/src/aws_kms/mod.rs` — slice 9 (`mrk-match`) introduces the
  scaffold with `pub mod mrk_match;`. Slice 16 (`hkeyring-support`)
  extends with `#[cfg(feature = "keystore")] pub(crate) mod
  branch_key_wrap;`, `#[cfg(feature = "keystore")] pub(crate) mod
  cache_entry_identifier;`, and the `__test_internals` re-export module.
  Slice 17 (`hkeyring`) extends with `#[cfg(feature = "keystore")] pub
  mod hierarchical_keyring;`.
- `mpl/src/cmc/mod.rs` — slice 10 (`cmc-interface`) introduces it with
  the `Cmc` trait, `entry` submodule, and initial re-exports. Slice 11
  (`local-cmc`) adds `pub mod local; pub use local::LocalCmc;`. Slice 12
  (`storm-tracking-cmc`) adds `pub mod storm_tracking; pub use
  storm_tracking::{StormTrackingCmc, TimeUnits};`.
- `mpl/src/keystore/mod.rs` — slice 13 (`keystore-interface`) introduces
  it with the `Keystore` trait scaffold plus `config`, `kms_config`, and
  `error` submodules. Slice 14 (`keystore-support`) adds `pub mod
  record;` and `pub mod encryption_context;`. Slice 15
  (`branch-key-store`) adds `pub mod branch_key_store; pub use
  branch_key_store::BranchKeyStore; pub(crate) mod kms_ops;`.
- `mpl/.duvet/config.toml` — adds one `[[specification]]` entry per slice
  that introduces a new spec file.

## Out of scope (already on `main`)

- `.github/workflows/pull.yml`, `.github/workflows/retry_failed_ci.yml` —
  already merged to `main` directly.
- `.github/workflows/library_rust_tests.yml` — PR 1 introduces the
  scaffold changes; subsequent CI drift (`764ebc4` go install,
  `9541d05` commented-out keystore integ slot, `1bd7853` clippy
  `--all-features` + `cargo build --examples` + commented-out example
  run slot) is currently unassigned. Decide before landing PR 19
  whether the examples-driven CI edits fold into PR 19 or split into a
  standalone infra amendment PR.

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
  and the materials structs in PRs 3 / 5 / 6) — those diffs appear in the
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

### PR 5 — `keyring-interface`

**Topic:** `Keyring` async trait and accompanying `MaterialsError` extensions.
**Spec:** [`spec/framework/keyring-interface.md`](../../spec/framework/keyring-interface.md)
**Review branch:** `aws-crypto-rust/keyring-interface-review`
**Sync worktree:** `/Users/jocorell/crypto-tools/rust/aws-crypto-tools-rust-keyring-interface`
**Base branch (PR target):** `aws-crypto-rust/commitment-policy-review`
**Depends on:** PR 2 (materials, error), PR 3 (algorithm suite)

**Source:**
- `mpl/src/keyring/mod.rs`

**Tests:**
- `mpl/tests/test_keyring_contract.rs`
- `mpl/tests/test_materials_error.rs`

**Compliance:**
- `mpl/compliance/spec/framework/keyring-interface/*.toml`

**Notes:**
- The `MaterialsError` extensions live in `mpl/src/structures/error.rs`,
  which is **introduced by PR 2** but extended here. PR 5's diff includes the
  new `MaterialsErrorKind` variants added on top of PR 2's snapshot.
- Shared-file modifications introduced by this PR: `lib.rs`
  (`+pub mod keyring; pub use keyring::Keyring;`), `Cargo.toml` /
  `Cargo.lock` (adds `async-trait`), `error.rs` (new variants).

---

### PR 6 — `cmm-interface`

**Topic:** `Cmm` async trait, `EncryptionMaterialsRequest`, and
`DecryptMaterialsRequest`.
**Spec:** [`spec/framework/cmm-interface.md`](../../spec/framework/cmm-interface.md)
**Review branch:** `aws-crypto-rust/cmm-interface-review`
**Sync worktree:** `/Users/jocorell/crypto-tools/rust/aws-crypto-tools-rust-cmm-interface`
**Base branch (PR target):** `aws-crypto-rust/keyring-interface-review`
**Depends on:** PR 2, PR 3, PR 4 (commitment policy is on the request type)

**Source:**
- `mpl/src/cmm/mod.rs`
- `mpl/src/cmm/request.rs`

**Tests:**
- `mpl/tests/test_cmm_contract.rs`

**Compliance:**
- `mpl/compliance/spec/framework/cmm-interface/*.toml`

**Notes:**
- Contract tests use the same dyn-trait pattern as `test_keyring_contract.rs`.

---

### PR 7 — `default-cmm`

**Topic:** `DefaultCmm` implementation (delegates to a `Keyring`, applies
commitment-policy and algorithm-suite rules).
**Spec:** [`spec/framework/default-cmm.md`](../../spec/framework/default-cmm.md)
**Review branch:** `aws-crypto-rust/default-cmm-review`
**Sync worktree:** `/Users/jocorell/crypto-tools/rust/aws-crypto-tools-rust-default-cmm`
**Base branch (PR target):** `aws-crypto-rust/cmm-interface-review`
**Depends on:** PR 4, PR 5, PR 6

**Source:**
- `mpl/src/cmm/default_cmm.rs`

**Tests:**
- `mpl/tests/test_default_cmm.rs`

**Compliance:** annotations are inline in source/tests; no dedicated
compliance directory yet.

**Notes:**
- Modifies `mpl/src/cmm/mod.rs` (re-export). That file is **introduced by
  PR 6**; PR 7's diff to it appears in this PR.
- Shared-file modifications introduced by this PR: `cmm/mod.rs` (re-export
  for `DefaultCmm`), `lib.rs` (if applicable), `Cargo.toml` / `Cargo.lock`
  (any new deps).

---

### PR 8 — `structures-polish`

**Topic:** Post-PR-2 refinements to structures files:
`EncryptionContext` reject-trailing-bytes bugfix, u16::MAX boundary +
multibyte-UTF-8 + known-vector tests, BTreeMap-entry-API perf, empty-key
spec-gap doc; `derive(Debug)` on materials structs; drop-redundant-duvet-
annotation stance from PR 2 files.
**Spec:** none new — extends PR 2's `structures.md` coverage; annotations
inline in source / tests.
**Review branch:** `aws-crypto-rust/structures-polish-review`
**Sync worktree:** `/Users/jocorell/crypto-tools/rust/aws-crypto-tools-rust-structures-polish`
**Base branch (PR target):** `aws-crypto-rust/default-cmm-review`
**Depends on:** PR 2

**Source (diffs to PR-2-owned files):**
- `mpl/src/structures/encryption_context.rs`
- `mpl/src/structures/encryption_materials.rs`
- `mpl/src/structures/decryption_materials.rs`
- `mpl/src/structures/branch_key_materials.rs`
- `mpl/src/structures/beacon_key_materials.rs`
- `mpl/src/structures/encrypted_data_key.rs`

**Tests:**
- `mpl/tests/test_encryption_context.rs` (diffs — boundary / UTF-8 /
  known-vector / API-surface additions)

**Compliance:** none new.

**Notes:**
- Every file in this slice is a shared file introduced by PR 2. This PR
  shows the incremental diff only.
- Contributing commits: `730d6f6`, `40e215e`, `2471927`, `a07e760`,
  `b3826b6`, `c8f620b`, `751bccd`, `619f561`, `251521c`. Reviewers may
  prefer to fold these into PR 2's snapshot instead of cutting a
  standalone slice; the decision is deferred to the review team.

---

### PR 9 — `mrk-match`

**Topic:** `aws_kms::mrk_match` shared utility — the MRK-match-for-decrypt
algorithm used by hierarchical keyring and (future) MRK keyring decrypt
paths.
**Spec:** [`spec/framework/aws-kms/aws-kms-mrk-match-for-decrypt.md`](../../spec/framework/aws-kms/aws-kms-mrk-match-for-decrypt.md)
**Review branch:** `aws-crypto-rust/mrk-match-review`
**Sync worktree:** `/Users/jocorell/crypto-tools/rust/aws-crypto-tools-rust-mrk-match`
**Base branch (PR target):** `aws-crypto-rust/structures-polish-review`
**Depends on:** PR 1 (scaffold)

**Source:**
- `mpl/src/aws_kms/mod.rs` (introduces the module with `pub mod mrk_match;`)
- `mpl/src/aws_kms/mrk_match.rs`

**Tests:**
- `mpl/tests/test_aws_kms_mrk_match.rs`

**Compliance:**
- `mpl/compliance/spec/framework/aws-kms/aws-kms-mrk-match-for-decrypt/*.toml`

**Notes:**
- Shared-file modifications introduced by this PR: `lib.rs` (adds `pub
  mod aws_kms;`), `.duvet/config.toml` (registers the mrk-match spec).
- Later slices (16, 17) extend `aws_kms/mod.rs` with feature-gated
  hkeyring modules.

---

### PR 10 — `cmc-interface`

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
  PR 5 / PR 6. Behavioral MUSTs on `put_cache_entry` / `get_cache_entry`
  are annotated `type=exception` here; slices 11 and 12 convert them to
  `type=implementation` + `type=test` on concrete caches.
- Shared-file modifications introduced by this PR: `lib.rs` (adds `pub
  mod cmc; pub use cmc::{Cmc, CacheEntry, CachedMaterials, UsageMetadata,
  BytesUsage, MessageUsage};`), `.duvet/config.toml` (registers the
  cryptographic-materials-cache spec).

---

### PR 11 — `local-cmc`

**Topic:** `LocalCmc` — the concrete in-memory LRU cache with TTL-aware
pruning that the MPL ships as its default cache.
**Spec:** [`spec/framework/local-cryptographic-materials-cache.md`](../../spec/framework/local-cryptographic-materials-cache.md)
**Review branch:** `aws-crypto-rust/local-cmc-review`
**Sync worktree:** `/Users/jocorell/crypto-tools/rust/aws-crypto-tools-rust-local-cmc`
**Base branch (PR target):** `aws-crypto-rust/cmc-interface-review`
**Depends on:** PR 10

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
- Fulfils PR 10's TTL / entry-lifecycle exception annotations with
  `type=implementation` + `type=test` on `LocalCmc`.

---

### PR 12 — `storm-tracking-cmc`

**Topic:** `StormTrackingCmc` — storm-tracking wrapper around `LocalCmc`
that suppresses thundering-herd on cache misses.
**Spec:** [`spec/framework/storm-tracking-cryptographic-materials-cache.md`](../../spec/framework/storm-tracking-cryptographic-materials-cache.md)
**Review branch:** `aws-crypto-rust/storm-tracking-cmc-review`
**Sync worktree:** `/Users/jocorell/crypto-tools/rust/aws-crypto-tools-rust-storm-tracking-cmc`
**Base branch (PR target):** `aws-crypto-rust/local-cmc-review`
**Depends on:** PR 11

**Source:**
- `mpl/src/cmc/storm_tracking.rs`

**Tests:**
- `mpl/tests/test_storm_tracking_cmc.rs`

**Compliance:**
- `mpl/compliance/spec/framework/storm-tracking-cryptographic-materials-cache/*.toml`

**Notes:**
- Shared-file modifications introduced by this PR: `cmc/mod.rs` (adds
  `pub mod storm_tracking; pub use storm_tracking::{StormTrackingCmc,
  TimeUnits};`); `.duvet/config.toml` (registers the storm-tracking
  spec).

---

### PR 13 — `keystore-interface`

**Topic:** `Keystore` async trait scaffolding, `KeyStoreConfig`,
`KmsConfiguration`, `KeystoreError` — the abstract keystore contract.
No concrete keystore yet; every operation method is annotated
`type=exception` with a `reason=` pointing at the phase that will
fulfil it.
**Spec:** [`spec/framework/branch-key-store.md`](../../spec/framework/branch-key-store.md) (interface-level requirements)
**Review branch:** `aws-crypto-rust/keystore-interface-review`
**Sync worktree:** `/Users/jocorell/crypto-tools/rust/aws-crypto-tools-rust-keystore-interface`
**Base branch (PR target):** `aws-crypto-rust/storm-tracking-cmc-review`
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
  concrete annotations in slices 14 and 15)

**Notes:**
- Introduces the `[features] keystore` flag in `Cargo.toml` and the
  `#[cfg(feature = "keystore")] pub mod keystore;` line in `lib.rs`.
- Registers `branch-key-store.md` in `.duvet/config.toml`.
- No new runtime deps yet; deps come with the concrete impl in PR 15.

---

### PR 14 — `keystore-support`

**Topic:** Pure-logic keystore helpers — record format serialization
and encryption-context construction. Called by (future) concrete
keystore implementations.
**Spec:** `spec/framework/branch-key-store.md` (record-format /
encryption-context sub-requirements)
**Review branch:** `aws-crypto-rust/keystore-support-review`
**Sync worktree:** `/Users/jocorell/crypto-tools/rust/aws-crypto-tools-rust-keystore-support`
**Base branch (PR target):** `aws-crypto-rust/keystore-interface-review`
**Depends on:** PR 13

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

### PR 15 — `branch-key-store`

**Topic:** Concrete `BranchKeyStore` — construction, `GetKeyStoreInfo`,
`GetActiveBranchKey`, `GetBranchKeyVersion`, plus KMS auth / decrypt
helpers. Real DDB-backed keystore behind the `keystore` feature flag.
**Spec:** `spec/framework/branch-key-store.md` (operation-level
requirements)
**Review branch:** `aws-crypto-rust/branch-key-store-review`
**Sync worktree:** `/Users/jocorell/crypto-tools/rust/aws-crypto-tools-rust-branch-key-store`
**Base branch (PR target):** `aws-crypto-rust/keystore-support-review`
**Depends on:** PR 13, PR 14

**Source:**
- `mpl/src/keystore/branch_key_store.rs`
- `mpl/src/keystore/kms_ops.rs`

**Tests:**
- `mpl/tests/test_keystore_branch_key_store.rs`
- `mpl/tests/test_keystore_branch_key_store_integ.rs`

**Compliance:** incremental annotations on
`mpl/compliance/spec/framework/branch-key-store/{createkey,
versionkey, getactivebranchkey, getbranchkeyversion, getbeaconkey,
getkeystoreinfo, aws-kms-branch-key-decryption,
authenticating-a-keystore-item, dynamodb-client, kms-client,
keystore-id, ...}.toml`.

**Notes:**
- Shared-file modifications introduced by this PR: `Cargo.toml` /
  `Cargo.lock` (adds `aws-config`, `aws-sdk-dynamodb`, `aws-sdk-kms`,
  `base64`, `uuid`, `tokio`); `keystore/mod.rs` (adds `pub mod
  branch_key_store; pub use branch_key_store::BranchKeyStore;
  pub(crate) mod kms_ops;`); `lib.rs` (adds `#[cfg(feature = "keystore")]
  pub use keystore::{BranchKeyStore, KeyStoreConfig, KeyStoreInfo,
  Keystore, KeystoreError, KmsConfiguration, encryption_context,
  kms_config, record};`).
- Includes the DDB-Number-typed-attribute parsing fix and the
  `uuid`-crate switch for keystore-id generation.
- Integration tests (`_integ`) are gated on env vars and are noop when
  credentials aren't present; a commented-out CI step reserves the slot
  for running them once OIDC-role plumbing lands. Coordinate with the
  Out-of-scope note on `library_rust_tests.yml`.
- Converts PR 13's remaining `type=exception` annotations on operation
  methods to `type=implementation` + `type=test`.

---

### PR 16 — `hkeyring-support`

**Topic:** `aws_kms::branch_key_wrap` (branch-key wrap / unwrap AEAD
crypto) and `aws_kms::cache_entry_identifier` (cache-key derivation for
hierarchical keyring). Both crate-internal, exposed via
`__test_internals` for integration tests.
**Spec:** `spec/framework/aws-kms/aws-kms-hierarchical-keyring.md`
(wrap/unwrap and cache-identifier sub-requirements)
**Review branch:** `aws-crypto-rust/hkeyring-support-review`
**Sync worktree:** `/Users/jocorell/crypto-tools/rust/aws-crypto-tools-rust-hkeyring-support`
**Base branch (PR target):** `aws-crypto-rust/branch-key-store-review`
**Depends on:** PR 9 (aws_kms module), PR 15 (branch-key-store types)

**Source:**
- `mpl/src/aws_kms/branch_key_wrap.rs`
- `mpl/src/aws_kms/cache_entry_identifier.rs`

**Tests:** none direct — exposed via `#[doc(hidden)] pub mod
__test_internals` and exercised by the hkeyring integration tests in
PR 17.

**Compliance:** incremental annotations on
`mpl/compliance/spec/framework/aws-kms/aws-kms-hierarchical-keyring/*.toml`
(wrap/unwrap and cache-identifier sub-requirements only).

**Notes:**
- Shared-file modifications introduced by this PR: `Cargo.toml` /
  `Cargo.lock` (adds `aws-lc-rs` with the `fips` feature for AEAD
  wrap/unwrap); `aws_kms/mod.rs` (adds `#[cfg(feature = "keystore")]
  pub(crate) mod branch_key_wrap;`, `#[cfg(feature = "keystore")]
  pub(crate) mod cache_entry_identifier;`, and the
  `#[cfg(feature = "keystore")] #[doc(hidden)] pub mod __test_internals`
  re-export module).
- Consider testing directly here instead of leaning entirely on PR 17's
  integration tests — reviewers to flag if additional unit coverage is
  wanted.

---

### PR 17 — `hkeyring`

**Topic:** `HierarchicalKeyring` — full `on_encrypt` / `on_decrypt`
implementation, `CacheType` enum (default local + custom-sized + shared
CMC + storm-tracking), `BranchKeySupplier` trait.
**Spec:** [`spec/framework/aws-kms/aws-kms-hierarchical-keyring.md`](../../spec/framework/aws-kms/aws-kms-hierarchical-keyring.md)
**Review branch:** `aws-crypto-rust/hkeyring-review`
**Sync worktree:** `/Users/jocorell/crypto-tools/rust/aws-crypto-tools-rust-hkeyring`
**Base branch (PR target):** `aws-crypto-rust/hkeyring-support-review`
**Depends on:** PR 9 (mrk-match), PR 12 (CMC family), PR 15
(BranchKeyStore), PR 16 (hkeyring-support)

**Source:**
- `mpl/src/aws_kms/hierarchical_keyring.rs`

**Tests:**
- `mpl/tests/test_aws_kms_hierarchical_keyring.rs`
- `mpl/tests/test_aws_kms_hierarchical_keyring_integ.rs`

**Compliance:**
- `mpl/compliance/spec/framework/aws-kms/aws-kms-hierarchical-keyring/*.toml`
  (remaining operation-level TOMLs; wrap/unwrap and cache-identifier
  TOMLs are already annotated by PR 16)

**Notes:**
- Shared-file modifications introduced by this PR: `aws_kms/mod.rs`
  (adds `#[cfg(feature = "keystore")] pub mod hierarchical_keyring;`);
  `.duvet/config.toml` (registers the hkeyring spec).
- Contributing commits: `7e5be02`, `2fe3ad9`, `405e461`, `0340578`,
  `228b418`, `90e817e`. Reviewers may want a further split
  (construction vs. on_encrypt vs. on_decrypt vs. cache-wiring) if the
  ~49 KB single file is too big for one review.

---

### PR 18 — `client-factories`

**Topic:** `MaterialProviders` client factory methods —
`create_cryptographic_materials_cache`, `create_branch_key_store`, and
`create_aws_kms_hierarchical_keyring` — plus corresponding builder types.
**Spec:** none new (composition surface only).
**Review branch:** `aws-crypto-rust/client-factories-review`
**Sync worktree:** `/Users/jocorell/crypto-tools/rust/aws-crypto-tools-rust-client-factories`
**Base branch (PR target):** `aws-crypto-rust/hkeyring-review`
**Depends on:** PR 12 (CMC), PR 15 (BranchKeyStore), PR 17
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
- No new deps; all runtime deps already in place from PR 15 / PR 16.

---

### PR 19 — `hkeyring-examples`

**Topic:** Runnable AWS KMS Hierarchical Keyring examples demonstrating
single-tenant, multi-tenant, and cache-configuration composition patterns
against a real keystore.
**Spec:** none (runnable docs; no new spec).
**Review branch:** `aws-crypto-rust/hkeyring-examples-review`
**Sync worktree:** `/Users/jocorell/crypto-tools/rust/aws-crypto-tools-rust-hkeyring-examples`
**Base branch (PR target):** `aws-crypto-rust/client-factories-review`
**Depends on:** PR 15, PR 17, PR 18

**Source:**
- `mpl/examples/aws_kms_hierarchical/main.rs`
- `mpl/examples/aws_kms_hierarchical/common.rs`
- `mpl/examples/aws_kms_hierarchical/static_branch_key.rs`
- `mpl/examples/aws_kms_hierarchical/branch_key_supplier.rs`
- `mpl/examples/aws_kms_hierarchical/example_branch_key_id_supplier.rs`
- `mpl/examples/aws_kms_hierarchical/cache_configurations.rs`

**Tests:** none. Compile coverage is enforced by the `cargo build
--all-features --examples` step in CI; runtime execution against real
AWS is deferred until OIDC-role plumbing lands (paired with the existing
`TODO(integ-tests-creds)` block).

**Compliance:** none.

**Notes:**
- Terminal slice — MUST land after PRs 15, 17, and 18 so the review
  branch's `cargo build --examples` step resolves
  `HierarchicalKeyring`, `BranchKeyStore`, and the
  `MaterialProviders::create_*` factories. This "don't break CI"
  constraint is what pins the slice terminal.
- Shared-file modification introduced by this PR: `mpl/Cargo.toml`
  gains the `[[example]] name = "aws_kms_hierarchical"` block with
  `required-features = ["keystore"]`. All runtime dependencies
  (`aws-config`, `aws-sdk-kms`, `aws-sdk-dynamodb`, `tokio`) are
  already carried from earlier slices; this PR adds no new deps.
- The CI update in `.github/workflows/library_rust_tests.yml` —
  switching `cargo clippy --all-targets` to `--all-features` and
  adding `cargo build --all-features --examples --verbose` — is
  intentionally **not** in this PR. That workflow file is called out
  as out of scope above; the exclusion needs to be revisited or split
  into a separate infra amendment.
- Modeled after the ESDK Rust hierarchical-keyring blueprint
  (`aws/aws-encryption-sdk/releases/rust/esdk/examples/keyring/aws_kms_hierarchical`),
  with two deviations documented on commit `9a9fc03`: the supplier is
  async (matches this repo's `BranchKeySupplier` trait), and encrypt /
  decrypt happen at the keyring layer (no ESDK client to drive through).

---

## Recommended review order

1. PR 1 — `client-scaffold`
2. PR 2 — `structures`
3. PR 3 — `algorithm-suite`
4. PR 4 — `commitment-policy`
5. PR 5 — `keyring-interface`
6. PR 6 — `cmm-interface`
7. PR 7 — `default-cmm`
8. PR 8 — `structures-polish` *(diffs to PR-2 files; may fold into PR 2)*
9. PR 9 — `mrk-match`
10. PR 10 — `cmc-interface`
11. PR 11 — `local-cmc`
12. PR 12 — `storm-tracking-cmc`
13. PR 13 — `keystore-interface`
14. PR 14 — `keystore-support`
15. PR 15 — `branch-key-store`
16. PR 16 — `hkeyring-support`
17. PR 17 — `hkeyring`
18. PR 18 — `client-factories`
19. PR 19 — `hkeyring-examples` *(terminal)*

Each PR description should:

- Note that this branch is part of a stacked review chain (see
  `docs/design-docs/pr-plan-by-spec.md`) and that CI is expected to pass
  on its own scope.
- Link to `aws-crypto-rust/unreviewed` for the full working tree.
- Link to the relevant `spec/framework/<file>.md`.
- Call out any shared-file modifications (lib.rs, Cargo.toml, error.rs,
  etc.) the PR introduces.
