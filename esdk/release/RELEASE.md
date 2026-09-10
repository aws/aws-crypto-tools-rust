# Releasing `aws-esdk` (git → Brazil)

A release syncs the crate into the Brazil package **`AwsCryptoToolsRust`** and
publishes it via PackageBuilder. It is **two review-gated steps** — the sync
goes through a code review, never a direct push to mainline:

1. **`release.sh`** — verify, build docs, smoke test, then open a code review
   that puts this crate on a **new branch** of the package.
2. **`release.sh --publish`** — after that review is approved and **merged to
   the package's mainline**, PackageBuilder builds it and publishes to the
   version set.

The code review between the two steps is the gate: a CR cannot auto-merge, so
publishing is a deliberate second command after a human approves.

## Release

Run from a Brazil-capable environment (the `brazil` CLI on PATH, Midway
authenticated):

```bash
mwinit                                  # Brazil metadata/build calls need Midway
./esdk/release/release.sh               # step 1: verify + open the sync CR
# ... get the CR reviewed and merged to AwsCryptoToolsRust mainline ...
./esdk/release/release.sh --publish     # step 2: build + publish
```

`--dry-run` runs the read-only phases and prints the CR and `pb build` commands
instead of running them. `--yes` installs missing dependencies without prompting.

## How it works

**Step 1 (sync).** `AWS_ESDK_BRAZIL_IMPORT_CMD` copies the crate + Brazil
`Config` onto a **new branch** of the package checkout and opens a code review.
It must not push to mainline. For example:

```bash
export AWS_ESDK_BRAZIL_IMPORT_CMD='
  cd "$PKG" && git fetch -q origin && git checkout -B "release/aws-esdk-$(date +%s)" origin/mainline &&
  rsync -a --exclude .git --exclude target --exclude release/build "$ESDK/" "$PKG/" &&
  git add -A && git commit -m "chore: sync aws-esdk from GitHub" && cr'
```

**Step 2 (publish).** `brazil packagebuilder build` builds the package
**server-side from its mainline** and publishes into the version set.
`--autoMergeEnabled` pulls missing dependencies from the tracking version set —
how the crate's ~210-crate closure resolves, **provided the tracking/parent
version set is Rust-enabled** (has CargoBrazil and the crates.io mirror):

```bash
brazil packagebuilder build \
  --versionSet "$AWS_ESDK_BRAZIL_VERSION_SET" \
  --package AwsCryptoToolsRust --branch mainline \
  --useLatestChange --setAsTarget --autoMergeEnabled \
  --releaseNotes "aws-esdk release" --waitForCompletion
```

## Versioning — there isn't one per release

Consumers depend on the package at its **major-version line** in the version set
(Brazil's `Package-major.minor` / `.x` mechanism), so each release is just the
latest build on that line. There is **no per-release version and no git tag**.
The package's major version is declared once in its Brazil `Config` and bumped
only on a breaking change. The `version` in `esdk/Cargo.toml` is the crate
manifest version, not the release mechanism.

## One-time setup

- `mwinit` for Brazil metadata/build calls.
- There is **no version set yet**; create one from a Rust-enabled parent (see
  OPEN QUESTIONS) with the package as a target:

  ```bash
  brazil versionset create \
    --versionSet AwsCryptoToolsRust/development \
    --from <RUST_ENABLED_PARENT_VS> \
    --targets AwsCryptoToolsRust-1.0 \
    --platforms AL2_x86_64,AL2_aarch64
  ```

- Coordinates, in the environment or `esdk/release/brazil.env` (sourced
  automatically):

  ```bash
  AWS_ESDK_BRAZIL_VERSION_SET=AwsCryptoToolsRust/development
  AWS_ESDK_BRAZIL_BRANCH=mainline          # package mainline branch (default)
  AWS_ESDK_BRAZIL_IMPORT_CMD=<command>     # opens the branch + code review sync
  AWS_ESDK_BRAZIL_PUBLISH_CMD=<command>    # optional: override the pb build command
  ```

- The Rust toolchain and native build tools (`make`, a C compiler, `cmake`,
  `go`) are handled by the `deps` phase, which offers to install anything missing.

## What each step does

| Step | Phase | Effect |
|------|-------|--------|
| both | deps | checks required tools; offers to install missing ones (Y/n, or `--yes`) |
| both | gate | working tree clean; HEAD pushed to `origin`; fatal on a real run |
| stage | verify | `make clippy` (all feature combos); `make test` when AWS credentials are present |
| stage | docs | `cargo doc --all-features --no-deps` → `build/docs/` (ORR links `aws_esdk/index.html`) |
| stage | smoke-test | standalone consumer runs an encrypt/decrypt round-trip |
| stage | import | opens the branch + code review sync (`AWS_ESDK_BRAZIL_IMPORT_CMD`) |
| publish | publish | `brazil pb build` builds mainline and publishes to the version set |

The smoke test needs no AWS credentials — it uses a local raw-AES keyring.

## OPEN QUESTIONS (Brazil-side)

The package (`AwsCryptoToolsRust`), sync model (branch + code review), and
publish (`brazil pb build`) are settled. What remains:

1. **Rust-enabled parent version set** — `brazil vs create --from <?>` needs a
   parent that already has CargoBrazil and the crates.io closure, so
   `--autoMergeEnabled` can resolve the crate's ~210 dependencies. **This is the
   blocker:** if no Rust-enabled version set exists in the org, Rust-in-Brazil
   has to be stood up first. Find whoever owns Rust in the org's version sets.
2. **`Config`** — the CargoBrazil `Config` for the package (build system, major
   version, and a `cargo doc` step so docs ship in the package). Base it on an
   existing CargoBrazil package. It is part of what the sync CR lands.
3. **Dependencies** — confirm the vendored `aws-mpl-native` resolves in the
   version set (its own package, or the real MPL package), given the MPL is
   being torn out.
4. **Consumer** — how a consumer depends on the published `aws-esdk`; then
   repoint `smoke-test/Cargo.toml` off the in-repo path dep.
