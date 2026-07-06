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
  deps). Later slices add deps as needed (notably PR 5 `async-trait`, PR 7
  if applicable). Each slice's PR shows the dep diff it introduces.
- `mpl/src/lib.rs` — slice 1 introduces the scaffold (`mod client; pub use
  client::*;`). Slice 2 adds `pub mod structures;`. Slice 5 adds `pub mod
  keyring; pub use keyring::Keyring;`. Slice 6 adds `pub mod cmm; pub use
  cmm::{...};`. Each slice's PR shows the lib.rs diff it introduces.
- `mpl/src/structures/mod.rs` — slice 2 introduces it. Slices 3 and 4 add
  submodule + re-export lines for `algorithm_suite` and `commitment_policy`.
- `mpl/src/structures/error.rs` — slice 2 introduces `MaterialsError` /
  `MaterialsErrorKind`. Slice 5 (keyring) extends with new variants. Slice 6
  may extend further.
- `mpl/src/cmm/mod.rs` — slice 6 introduces it. Slice 7 modifies its
  re-exports for `DefaultCmm`.
- `mpl/.duvet/config.toml` — adds one `[[specification]]` entry per slice
  that introduces a new spec file.

## Out of scope (already on `main`)

- `.github/workflows/pull.yml`, `.github/workflows/retry_failed_ci.yml` —
  already merged to `main` directly.

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

### PR X — `hkeyring-examples`

**Topic:** Runnable AWS KMS Hierarchical Keyring examples demonstrating
single-tenant, multi-tenant, and cache-configuration composition patterns
against a real keystore.
**Spec:** none (runnable docs; no new spec).
**Review branch:** `aws-crypto-rust/hkeyring-examples-review`
**Sync worktree:** `/Users/jocorell/crypto-tools/rust/aws-crypto-tools-rust-hkeyring-examples`
**Base branch (PR target):** TBD — terminal slice; base is the
client-factories review branch once that slice is drafted.
**Depends on:** future `keystore`, `hkeyring`, and `client-factories`
slices (not yet in this plan). PR number and base branch will be assigned
once those intermediate slices are named.

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
- MUST land after the `keystore`, `hkeyring`, and `client-factories`
  slices — otherwise the review branch's `cargo build --examples` step
  fails on missing symbols (`HierarchicalKeyring`, `BranchKeyStore`,
  `MaterialProviders::create_branch_key_store`,
  `MaterialProviders::create_cryptographic_materials_cache`,
  `MaterialProviders::create_aws_kms_hierarchical_keyring`). This
  "don't break CI" constraint is what pins the slice to terminal.
- Shared-file modification introduced by this PR: `mpl/Cargo.toml` gains
  the `[[example]] name = "aws_kms_hierarchical"` block with
  `required-features = ["keystore"]`. All runtime dependencies
  (`aws-config`, `aws-sdk-kms`, `aws-sdk-dynamodb`, `tokio`) are already
  carried from earlier slices; this PR adds no new deps.
- The CI update in `.github/workflows/library_rust_tests.yml` — switching
  `cargo clippy --all-targets` to `--all-features` and adding
  `cargo build --all-features --examples --verbose` — is intentionally
  **not** in this PR. That workflow file is called out as "already on
  `main`" in the "Out of scope" section above; the exclusion needs to
  be revisited or split into a separate infra amendment.
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
8. *(future slices: `keystore`, `hkeyring`, `client-factories` — not yet
   drafted; must land before `hkeyring-examples` to keep CI green.)*
9. PR X — `hkeyring-examples` *(terminal; depends on 8's intermediate
   slices)*

Each PR description should:

- Note that this branch is part of a stacked review chain (see
  `docs/design-docs/pr-plan-by-spec.md`) and that CI is expected to pass
  on its own scope.
- Link to `aws-crypto-rust/unreviewed` for the full working tree.
- Link to the relevant `spec/framework/<file>.md`.
- Call out any shared-file modifications (lib.rs, Cargo.toml, error.rs,
  etc.) the PR introduces.
