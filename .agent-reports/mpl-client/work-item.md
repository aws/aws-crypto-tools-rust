# Work Item: fix mpl-client (Round 1)

This is a `fix` pass derived from the review findings in
`.agent-reports/mpl-client/review-annotations.md`, `review-tests.md`, and
`review-code.md`. Address the findings by setting up duvet infrastructure and
implementing a concrete, bounded spec increment with full annotations + tests.

## Spec
- Primary spec section for this increment: `spec/framework/commitment-policy.md`
- Spec root: `spec/`

## Primary files
- `mpl/src/client.rs`
- `mpl/src/error.rs`
- `mpl/src/lib.rs`
- New: `mpl/src/commitment_policy.rs` (or similar) for the policy enums
- `mpl/tests/test_mpl_client.rs` (+ a new test file for commitment policy if cleaner)

## Scope of THIS increment (bounded — do all of it)

### A. Set up duvet infrastructure (recommended step 1)
1. Create `.duvet/config.toml` at the repo root (schema v0.4.0). Register:
   - `[[source]] pattern = "mpl/src/**/*.rs"`
   - `[[source]] pattern = "mpl/tests/**/*.rs"` with `type = "test"`
   - `[[specification]] source = "spec/framework/commitment-policy.md"` (format = "markdown")
     plus any other `spec/framework/*.md` you actually annotate this round
   - `[[requirement]] pattern = "compliance/**/*.toml"`
   - `[report.html] enabled = true` and `[report.snapshot] enabled = true`
2. Generate the compliance TOMLs from the spec so requirement quotes exist to cite:
   `duvet extract -f markdown -o compliance spec/framework/commitment-policy.md`
   (verify a TOML appears under `compliance/` with the commitment-policy requirements).
   Adjust the output path so the `target` paths in the generated TOMLs match what
   `duvet report` expects for `//= spec/framework/commitment-policy.md#...` annotations.
3. Confirm `duvet report` runs and produces a snapshot. Commit the snapshot.

### B. Implement the commitment policy enums (recommended steps 2 + 3)
Implement these two requirements from `spec/framework/commitment-policy.md` FULLY
(implementation + `type=test` + exact-quote annotations):

- "The Material Providers Library MUST provide a distinct commitment policy ENUM
  for each format." → define an ESDK policy enum
  (`FORBID_ENCRYPT_ALLOW_DECRYPT`, `REQUIRE_ENCRYPT_ALLOW_DECRYPT`,
  `REQUIRE_ENCRYPT_REQUIRE_DECRYPT`) and a DBE policy enum
  (`REQUIRE_ENCRYPT_REQUIRE_DECRYPT`).
- "The Material Providers Library also MUST provide a union ENUM for all distinct
  commitment policy ENUMs called the Commitment Policy ENUM." → define a union
  `CommitmentPolicy` enum (e.g. `Esdk(EsdkCommitmentPolicy)` / `Dbe(DbeCommitmentPolicy)`).

Use exact quotes copied from the generated `compliance/` TOML (never paraphrase).
Use idiomatic Rust naming (PascalCase variants like `ForbidEncryptAllowDecrypt`),
but keep the spec's SCREAMING_SNAKE names available if natural (doc comments are fine).

### C. Give the config a real field + wire up validation (recommended steps 2 + 4)
- Add a `commitment_policy: CommitmentPolicy` field to `MaterialProvidersConfig`
  (with a sensible default — ESDK `REQUIRE_ENCRYPT_REQUIRE_DECRYPT` is the safe default).
- Make `MaterialProvidersBuilder::build()` actually validate, returning
  `Err(Error::InvalidConfig { .. })` for an invalid configuration (this removes the
  dead-code finding for `Error::InvalidConfig`). If no validation rule is genuinely
  needed yet, prefer to KEEP the variant and validate the union (e.g. reject a
  DBE policy that is not the single allowed value) rather than leave it dead.

### D. Fix the test-quality findings (recommended step in test review)
- Remove / fix the dead `let _ = MaterialProviders::default()` line in
  `test_mpl_default_uses_default_config` so every statement asserts something.
- Add tests with `//= type=test` annotations for the two ENUM requirements above.
- Add an error-path test that triggers `Error::InvalidConfig` via `build()`, asserting
  on the error kind (not a bare `is_err()`).

### OUT OF SCOPE this round (mark, do not silently skip)
The per-policy behavioral MUSTs ("X MUST be the default algorithm suite",
"Get Encryption Materials MUST only support suites with Key Commitment = True/False",
"Decrypt Materials MUST support …") depend on `algorithm-suites.md` and
`cmm-interface.md`, which are NOT implemented in this crate. For each such
requirement, add a `//= type=todo` annotation with a `tracking-issue=` note
(or a clearly-named TODO) so they are explicitly tracked as follow-up increments.
Do NOT fabricate algorithm-suite or CMM behavior to satisfy them.

## Success criteria
- `.duvet/config.toml` exists; `compliance/` has commitment-policy TOMLs; `duvet report` runs.
- The two "MUST provide ENUM" requirements have exact-quote `implementation` + `type=test`
  annotations, and the tests would fail if the requirement were violated.
- `MaterialProvidersConfig` carries a real `commitment_policy` field; `build()` performs
  real validation and `Error::InvalidConfig` is reachable and tested.
- No dead test statements; no `assert!()`/`unwrap()`/`expect()` in library code.
- `cargo check`, `cargo clippy -- -D warnings`, and `cargo test` all pass from `mpl/`.
- Behavioral commitment-policy MUSTs are explicitly marked `type=todo`, not omitted.

Write `.agent-reports/mpl-client/implementation-summary.md` listing modified files,
the requirements covered (impl + test), and the todo-tracked follow-ups.
