# Releasing `aws-esdk` (git → Brazil)

A release publishes the crate to Brazil via PackageBuilder. It is one command —
[`release.sh`](./release.sh) checks its own dependencies, runs every gate and
phase, and offers to install anything missing, so there is no manual checklist.

## Release

Run it from a Brazil-capable environment (the `brazil` CLI on PATH), with the
Brazil coordinates set (see One-time setup):

```bash
./esdk/release/release.sh
```

The script checks the tools it needs first and offers to install any that are
missing (`--yes` installs without prompting). On a non-interactive stdin it does
not prompt — it reports what is missing and stops.

### Where it runs

Today: a Brazil-capable machine (e.g. a Cloud Desktop) — GitHub Actions runners
have no `brazil` CLI, so they cannot publish. The fully hands-off endgame
(triggered on merge, no machine in the loop) is to run this same script from an
internal, Brazil-capable CI job (CodeBuild) or to trigger PackageBuilder from a
Pipeline; both are Brazil-side (see OPEN QUESTIONS). The script is the portable
core either way.

## How the publish works

`brazil packagebuilder build` builds the package **server-side from its source
branch** and publishes it into the version set. `--autoMergeEnabled` pulls any
missing dependencies from the tracking version set — which is how the crate's
~210-crate dependency closure resolves, **provided the tracking/parent version
set is Rust-enabled** (has CargoBrazil and the crates.io mirror). The script
runs, by default:

```bash
brazil packagebuilder build \
  --versionSet "$AWS_ESDK_BRAZIL_VERSION_SET" \
  --package "$AWS_ESDK_BRAZIL_PACKAGE" --branch "$AWS_ESDK_BRAZIL_BRANCH" \
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

- The Brazil coordinates below, exported in your environment or written once to
  `esdk/release/brazil.env` (sourced automatically):

  ```bash
  AWS_ESDK_BRAZIL_PACKAGE=<package>          # Brazil package that builds the crate
  AWS_ESDK_BRAZIL_VERSION_SET=<version-set>  # version set to publish into
  AWS_ESDK_BRAZIL_BRANCH=mainline            # package source branch (default)
  AWS_ESDK_BRAZIL_IMPORT_CMD=<command>       # optional: sync repo -> package source
  AWS_ESDK_BRAZIL_PUBLISH_CMD=<command>      # optional: override the pb build command
  ```

- A Rust toolchain and the native build tools (`make`, a C compiler, `cmake`,
  `go`). The `deps` phase checks these and offers to install any that are
  missing, so no manual toolchain setup is required.

## What the one command does

| Phase | Effect |
|-------|--------|
| deps | checks required tools; offers to install missing ones (Y/n, or `--yes`) |
| gate | enforces the gates below; a failure stops the release |
| verify | `make clippy` (compiles + lints every test, all feature combos); `make test` too when AWS credentials are present |
| docs | `cargo doc --all-features --no-deps`, copied to `build/docs/` (the ORR links `build/docs/aws_esdk/index.html`) |
| brazil | `brazil pb build` — PackageBuilder builds the package from its branch and publishes into the version set |
| smoke-test | builds a standalone consumer and runs an encrypt/decrypt round-trip against the released crate |

Gates (fatal on a real run; warnings under `--dry-run`):

- Working tree is clean.
- HEAD is pushed to `origin` (Brazil mirrors git).

The smoke test needs no AWS credentials — it uses a local raw-AES keyring.

## Dry run

Validate from a work-in-progress checkout — runs the deps check, gates (as
warnings), verify, docs, and smoke test, and prints the `pb build --dryrun`
command instead of publishing:

```bash
./esdk/release/release.sh --dry-run
```

## OPEN QUESTIONS (Brazil-side)

The publish mechanism is known (`brazil pb build` into a version set). What
remains cannot be resolved from this repo — these are the inputs/setup the
release still needs; `TODO(brazil)` markers in `release.sh` point at the same.

1. **Package** (`AWS_ESDK_BRAZIL_PACKAGE`) — does a Brazil package that builds
   this crate exist? If not, create one with a CargoBrazil `Config`. Is it
   GitHub-backed (source mirrors this repo, no import step) or does source get
   pushed per release (set `AWS_ESDK_BRAZIL_IMPORT_CMD`)?
2. **Version set** (`AWS_ESDK_BRAZIL_VERSION_SET`) — which version set /
   major-version line, and **is its tracking/parent VS Rust-enabled** (has
   CargoBrazil + the crates.io closure)? This is what makes the ~210-crate
   closure resolve under `--autoMergeEnabled`.
3. **Dependencies** — confirm the vendored `aws-mpl-native` (path dep) resolves
   in the version set (its own package, or the real MPL package), given the MPL
   is being torn out.
4. **Docs in the package** — have the crate's Brazil `Config` build run
   `cargo doc` so the HTML ships in the published package; confirm where Brazil
   serves it so the ORR link is stable.
5. **Consumer** — how a consumer depends on the published `aws-esdk`; then
   repoint `smoke-test/Cargo.toml` off the in-repo path dep for release runs.
