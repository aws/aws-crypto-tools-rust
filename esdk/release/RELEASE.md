# Releasing `aws-esdk` (git → Brazil)

A release copies the crate from git into its Brazil package and publishes it.
It is one command — [`release.sh`](./release.sh) runs every gate, phase, and
check itself, so there is no manual checklist.

## Release

On a Brazil-capable environment (the `brazil` CLI on PATH), with the Brazil
coordinates set (see One-time setup):

```bash
./esdk/release/release.sh
```

The [aws-esdk Release workflow](../../.github/workflows/esdk-release.yml)
(`workflow_dispatch`) runs the same script in `--dry-run` on a GitHub runner —
gates, build verify, docs, and smoke test — and uploads the built docs as an
artifact. It does not publish, because GitHub runners have no Brazil CLI.

## Versioning — there isn't one per release

Consumers depend on the package at its **major-version line** in the version set
(Brazil's `Package-major.minor` / `.x` mechanism), so each release is just the
latest build on that line. There is **no per-release version and no git tag**;
the script copies git → Brazil every time. The package's major version is
declared once in its Brazil `Config` and bumped only on a breaking change. The
`version` in `esdk/Cargo.toml` is the crate manifest version, not the release
mechanism.

## One-time setup

- A Rust toolchain (`cargo`, `rustc`) — the version CI pins in
  `.github/workflows/library_rust_tests.yml`.
- The Brazil coordinates below, exported in your environment or written once to
  `esdk/release/brazil.env` (sourced automatically):

```bash
AWS_ESDK_BRAZIL_PACKAGE=<package>          # Brazil package that mirrors the crate
AWS_ESDK_BRAZIL_PACKAGE_DIR=<local path>   # its workspace on disk
AWS_ESDK_BRAZIL_VERSION_SET=<version-set>  # version set it publishes into
AWS_ESDK_BRAZIL_PUBLISH_CMD=<command>      # command that publishes the package
AWS_ESDK_BRAZIL_DOC_DIR=doc                # docs subdir in the package (default)
```

## What the one command does

| Phase | Effect |
|-------|--------|
| gate | enforces the gates below; a failure stops the release |
| verify | `make clippy` (compiles + lints every test, all feature combos); `make test` too when AWS credentials are present |
| docs | `cargo doc --all-features --no-deps`, copied to `build/docs/` (the ORR links `build/docs/aws_esdk/index.html`) |
| brazil | copies the crate into its Brazil package, builds, bundles the docs, and publishes |
| smoke-test | builds a standalone consumer and runs an encrypt/decrypt round-trip against the released crate |

Gates (fatal on a real run; warnings under `--dry-run`):

- `cargo`/`rustc` present.
- Working tree is clean.
- HEAD is pushed to `origin` (Brazil mirrors git).

The smoke test needs no AWS credentials — it uses a local raw-AES keyring.

## Dry run

Validate from a work-in-progress checkout — runs the gates (as warnings), verify,
docs, and smoke test, and prints the Brazil commands instead of running them:

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
