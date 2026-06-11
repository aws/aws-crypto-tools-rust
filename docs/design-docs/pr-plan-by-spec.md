# PR Plan: Breaking Out `aws-crypto-rust/unreviewed`

This doc is the source of truth for slicing the work on `aws-crypto-rust/unreviewed`
into focused review PRs. Each entry below defines one PR and the files that
belong to it. The PR pair-programmer agent keys off `pr_number` to derive
`scope_files`, `review_branch`, and `sync_worktree`.

## Conventions

- All paths are relative to the repository root (`aws-crypto-tools-rust/`).
- `review_branch` follows the pattern `aws-crypto-rust/<slug>-review` and is
  cut from `main`.
- `sync_worktree` follows the pattern
  `/Users/jocorell/crypto-tools/rust/aws-crypto-tools-rust-<slug>` and tracks
  the matching `review_branch`.
- Review branches intentionally omit shared test helpers, scaffolding, and
  cross-slice infra. They are read-only references for focused review and are
  not expected to compile on their own. Working code lives on
  `aws-crypto-rust/unreviewed`.
- CI runs on PRs cut from review branches. Because review branches
  intentionally omit `Cargo.toml`, `Cargo.lock`, and shared helpers, CI is
  expected to fail and should be treated as informational. Verification of
  build, tests, and coverage happens on `aws-crypto-rust/unreviewed`.
- A given source file is "owned" by exactly one PR (the PR where its substance
  is the primary concern). When a later slice modifies an earlier slice's file
  in a non-trivial way, that is called out in the later PR's notes.

## Cross-slice infra (not its own PR)

These files aggregate changes across slices and stay only on `unreviewed`. They
are reviewed implicitly by the slice that introduced their relevant content:

- `mpl/Cargo.toml`, `mpl/Cargo.lock` — dependencies grow with each slice.
- `mpl/src/lib.rs` — public re-exports grow with each slice.
- `mpl/src/structures/mod.rs` — submodule wiring grows with each structures slice.
- `mpl/.duvet/config.toml` — adds one `[[specification]]` entry per slice
  introducing a new spec file.
- `.github/workflows/*.yml`, `.githooks/*` — already merged via separate PRs to `main`.

## PRs

### PR 1 — `client-scaffold`

**Topic:** Initial `mpl` crate scaffolding and async client/builder skeleton.
**Spec:** none (pre-spec setup).
**Review branch:** `aws-crypto-rust/client-scaffold-review`
**Sync worktree:** `/Users/jocorell/crypto-tools/rust/aws-crypto-tools-rust-client-scaffold`
**Depends on:** —

**Source:**
- `mpl/src/lib.rs`
- `mpl/src/client.rs`

**Tests:**
- `mpl/tests/test_mpl_client.rs`

**Compliance:** none.

**Notes:**
- `lib.rs` will be repeatedly modified by later slices to wire in new modules.
  This PR shows the original scaffold version. Reviewers should check later PRs
  for the full module surface.
- Includes the duvet bootstrap (`mpl/.duvet/config.toml` initial state) only
  conceptually; the file itself stays on `unreviewed` because it accumulates
  additions across slices.

---

### PR 2 — `structures`

**Topic:** Framework structures (encryption / decryption materials, EDK,
encryption context, branch / beacon key materials, MaterialsError).
**Spec:** [`spec/framework/structures.md`](../../spec/framework/structures.md)
**Review branch:** `aws-crypto-rust/structures-review`
**Sync worktree:** `/Users/jocorell/crypto-tools/rust/aws-crypto-tools-rust-structures`
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
- `error.rs` is later extended in PR 5 (keyring) with new `MaterialsErrorKind`
  variants. This PR's snapshot reflects the **current** state of
  `error.rs` on `unreviewed`, including those later additions, because the
  file is owned here.
- `encrypted_data_key.rs` and the materials structs are also lightly modified
  by later slices (algorithm-suite, keyring). Same story: review the current
  snapshot.
- `algorithm_suite.rs` and `commitment_policy.rs` are owned by PRs 3 and 4
  respectively and are not in this PR.

---

### PR 3 — `algorithm-suite`

**Topic:** `AlgorithmSuiteId` enum, per-suite spec table, and full algorithm
suite types (encryption alg, KDF, signature alg, format).
**Spec:** [`spec/framework/algorithm-suites.md`](../../spec/framework/algorithm-suites.md)
**Review branch:** `aws-crypto-rust/algorithm-suite-review`
**Sync worktree:** `/Users/jocorell/crypto-tools/rust/aws-crypto-tools-rust-algorithm-suite`
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
**Depends on:** PR 2 (materials, error), PR 3 (algorithm suite)

**Source:**
- `mpl/src/keyring/mod.rs`

**Tests:**
- `mpl/tests/test_keyring_contract.rs`
- `mpl/tests/test_materials_error.rs`

**Compliance:**
- `mpl/compliance/spec/framework/keyring-interface/*.toml`

**Notes:**
- The `MaterialsError` extensions live in `mpl/src/structures/error.rs`, which
  is **owned by PR 2**. Reviewers should read `error.rs` on the `structures`
  review branch in conjunction with this PR's contract tests.

---

### PR 6 — `cmm-interface`

**Topic:** `Cmm` async trait, `EncryptionMaterialsRequest`, and
`DecryptMaterialsRequest`.
**Spec:** [`spec/framework/cmm-interface.md`](../../spec/framework/cmm-interface.md)
**Review branch:** `aws-crypto-rust/cmm-interface-review`
**Sync worktree:** `/Users/jocorell/crypto-tools/rust/aws-crypto-tools-rust-cmm-interface`
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
**Depends on:** PR 4, PR 5, PR 6

**Source:**
- `mpl/src/cmm/default_cmm.rs`

**Tests:**
- `mpl/tests/test_default_cmm.rs`

**Compliance:** annotations are inline in source/tests; no dedicated
compliance directory yet.

**Notes:**
- Modifies `mpl/src/cmm/mod.rs` (re-export). That file is **owned by PR 6**.

---

## Recommended review order

1. PR 1 — `client-scaffold`
2. PR 2 — `structures`
3. PR 3 — `algorithm-suite`
4. PR 4 — `commitment-policy`
5. PR 5 — `keyring-interface`
6. PR 6 — `cmm-interface`
7. PR 7 — `default-cmm`

Each PR description should:

- Note that this branch intentionally omits helpers and scaffolding
  (`Cargo.toml`, `Cargo.lock`, shared test helpers), so CI is expected to
  fail. Verification of build, tests, and coverage is done on
  `aws-crypto-rust/unreviewed`.
- Link to `aws-crypto-rust/unreviewed` for the full working tree.
- Link to the relevant `spec/framework/<file>.md`.
- Call out any cross-slice file ownership (see each PR's Notes section above).
