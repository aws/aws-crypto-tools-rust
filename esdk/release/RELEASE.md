# Releasing `aws-esdk` (git → Brazil)

A release copies the crate from git into its Brazil package and publishes it.
It is one command — [`release.sh`](./release.sh) checks its own dependencies,
runs every gate and phase, and offers to install anything missing, so there is
no manual checklist.

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
internal, Brazil-capable CI job (CodeBuild) or to use a Brazil live/import
version set; both are Brazil-side (see OPEN QUESTIONS). The script is the
portable core either way.

## Versioning — there isn't one per release

Consumers depend on the package at its **major-version line** in the version set
(Brazil's `Package-major.minor` / `.x` mechanism), so each release is just the
latest build on that line. There is **no per-release version and no git tag**;
the script copies git → Brazil every time. The package's major version is
declared once in its Brazil `Config` and bumped only on a breaking change. The
`version` in `esdk/Cargo.toml` is the crate manifest version, not the release
mechanism.

## One-time setup

- The Brazil coordinates below, exported in your environment or written once to
  `esdk/release/brazil.env` (sourced automatically):

  ```bash
  AWS_ESDK_BRAZIL_PACKAGE=<package>          # Brazil package that mirrors the crate
  AWS_ESDK_BRAZIL_PACKAGE_DIR=<local path>   # its workspace on disk
  AWS_ESDK_BRAZIL_VERSION_SET=<version-set>  # version set it publishes into
  AWS_ESDK_BRAZIL_PUBLISH_CMD=<command>      # command that publishes the package
  AWS_ESDK_BRAZIL_DOC_DIR=doc                # docs subdir in the package (default)
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
| brazil | copies the crate into its Brazil package, builds, bundles the docs, and publishes |
| smoke-test | builds a standalone consumer and runs an encrypt/decrypt round-trip against the released crate |

Gates (fatal on a real run; warnings under `--dry-run`):

- Working tree is clean.
- HEAD is pushed to `origin` (Brazil mirrors git).

The smoke test needs no AWS credentials — it uses a local raw-AES keyring.

## Dry run

Validate from a work-in-progress checkout — runs the deps check, gates (as
warnings), verify, docs, and smoke test, and prints the Brazil commands instead
of running them:

```bash
./esdk/release/release.sh --dry-run
```

## OPEN QUESTIONS (Brazil-side)

These cannot be resolved from this repo. Each is a config value the script reads
from the environment / `brazil.env`; once all are set, the one command publishes
end-to-end. Steps whose exact form is still unknown are marked `TODO(brazil)` in
`release.sh`.

| Question | Config value |
|----------|--------------|
| 1. Does a Brazil package mirroring this crate exist? What is its name? | `AWS_ESDK_BRAZIL_PACKAGE` |
| 2. Is git → Brazil a live/import package or a source sync? Does it need a `Config`/build spec? (script `rsync`s `esdk/` into the package) | `AWS_ESDK_BRAZIL_PACKAGE_DIR` |
| 3. Which version set / major-version line does it publish into? | `AWS_ESDK_BRAZIL_VERSION_SET` |
| 4. What command publishes the built package (pipeline, `brazil-recursive-cmd`, package-builder)? | `AWS_ESDK_BRAZIL_PUBLISH_CMD` |
| 5. Where does Brazil publish the bundled HTML from so the ORR link is stable? | `AWS_ESDK_BRAZIL_DOC_DIR` |
| 6. How does a consumer depend on the Brazil-published `aws-esdk`? Then repoint `smoke-test/Cargo.toml` off the in-repo path dep. | — |
| 7. How do the crate's dependencies (including vendored `aws-mpl-native`) resolve in the version set? | — |
