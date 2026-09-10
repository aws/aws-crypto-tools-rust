# Releasing `aws-esdk` (git → Brazil)

A release publishes the crate to the Brazil package **`AwsCryptoToolsRust`** via
PackageBuilder. It is one command — [`release.sh`](./release.sh) checks its own
dependencies, runs every gate and phase, and offers to install anything missing,
so there is no manual checklist.

## Release

Run it from a Brazil-capable environment (the `brazil` CLI on PATH, Midway
authenticated), with the version set set (see One-time setup):

```bash
mwinit                       # Brazil metadata/build calls need Midway auth
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
Pipeline; both are Brazil-side. The script is the portable core either way.

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
  --package AwsCryptoToolsRust --branch "$AWS_ESDK_BRAZIL_BRANCH" \
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

Any Brazil metadata/build command needs Midway auth first:

```bash
mwinit
```

The Brazil package is **`AwsCryptoToolsRust`** (the script's default). Its source
is populated by copying this repo's crate in, plus a Brazil `Config`, and landing
a code review to the package's `mainline` — the "import" step (its CR merge is
approval-gated).

There is **no version set yet**; create one from a Rust-enabled parent (see OPEN
QUESTIONS) with the package as a target:

```bash
brazil versionset create \
  --versionSet AwsCryptoToolsRust/development \
  --from <RUST_ENABLED_PARENT_VS> \
  --targets AwsCryptoToolsRust-1.0 \
  --platforms AL2_x86_64,AL2_aarch64
```

Then point the script at it (environment or `esdk/release/brazil.env`, sourced
automatically):

```bash
AWS_ESDK_BRAZIL_VERSION_SET=AwsCryptoToolsRust/development
AWS_ESDK_BRAZIL_BRANCH=mainline          # package source branch (default)
AWS_ESDK_BRAZIL_IMPORT_CMD=<command>     # optional: copy repo -> package source + open CR
AWS_ESDK_BRAZIL_PUBLISH_CMD=<command>    # optional: override the pb build command
```

The Rust toolchain and native build tools (`make`, a C compiler, `cmake`, `go`)
are handled by the `deps` phase, which offers to install anything missing.

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

The package (`AwsCryptoToolsRust`) and publish mechanism (`brazil pb build`) are
known. What remains:

1. **Rust-enabled parent version set** — `brazil vs create --from <?>` needs a
   parent that already has CargoBrazil and the crates.io closure, so
   `--autoMergeEnabled` can resolve the crate's ~210 dependencies. **This is the
   blocker:** if no Rust-enabled version set exists in the org, Rust-in-Brazil
   has to be stood up first. Find whoever owns Rust in the org's version sets.
2. **`Config`** — the CargoBrazil `Config` for the package (build system, major
   version, and a `cargo doc` step so docs ship in the package). Base it on an
   existing CargoBrazil package.
3. **Import** — the copy-in + `Config` + CR-to-`mainline` step; its merge is
   approval-gated. Automate the copy + CR creation via `AWS_ESDK_BRAZIL_IMPORT_CMD`
   if desired.
4. **Dependencies** — confirm the vendored `aws-mpl-native` resolves in the
   version set (its own package, or the real MPL package), given the MPL is
   being torn out.
5. **Consumer** — how a consumer depends on the published `aws-esdk`; then
   repoint `smoke-test/Cargo.toml` off the in-repo path dep.
