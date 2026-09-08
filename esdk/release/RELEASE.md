# Releasing `aws-esdk` (git → Brazil)

The release is one command. [`release.sh`](./release.sh) runs every gate, phase,
and check itself — there is no manual checklist.

## Release

```bash
./esdk/release/release.sh
```

The version is read from `esdk/Cargo.toml`; set it there (in the normal PR) and
that is the version released. The script is non-interactive and safe to re-run.

## One-time setup

- A Rust toolchain (`cargo`, `rustc`) — the version CI pins in
  `.github/workflows/library_rust_tests.yml`.
- The Brazil coordinates below, exported in your environment or written once to
  `esdk/release/brazil.env` (sourced automatically). The smoke test needs no AWS
  credentials — it uses a local raw-AES keyring.

## What the one command does

| Phase | Effect |
|-------|--------|
| gate | enforces every release gate (below); a failure stops the release |
| docs | `cargo doc --all-features --no-deps`, copied to `build/docs/` (the ORR links `build/docs/aws_esdk/index.html`) |
| brazil | imports the crate into its Brazil package, builds, bundles the docs, and publishes |
| smoke-test | builds a standalone consumer and runs an encrypt/decrypt round-trip against the released crate |

Gates enforced automatically (fatal on a real run; warnings under `--dry-run`):

- `cargo`/`rustc` present.
- `esdk/Cargo.toml` version is `N.N.N`.
- Working tree is clean.
- Tag `v<version>` does not already exist (no accidental re-release).
- HEAD is pushed to `origin` (you release code that is on the remote).

## Dry run

Validate from a work-in-progress checkout — runs the gates (as warnings), docs,
and smoke test, and prints the Brazil commands instead of running them:

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
| 2. Is git → Brazil a live/import package or a manual source sync? Does it need a `Config`/build spec? (script `rsync`s `esdk/` into the package) | `AWS_ESDK_BRAZIL_PACKAGE_DIR` |
| 3. Which version set, and how does the Cargo.toml version map to the Brazil major version? | `AWS_ESDK_BRAZIL_VERSION_SET` |
| 4. What command publishes the built package (pipeline, `brazil-recursive-cmd`, package-builder)? | `AWS_ESDK_BRAZIL_PUBLISH_CMD` |
| 5. Where does Brazil publish the bundled HTML from so the ORR link is stable? | `AWS_ESDK_BRAZIL_DOC_DIR` |
| 6. How does a consumer depend on the Brazil-published `aws-esdk`? Then repoint `smoke-test/Cargo.toml` off the in-repo path dep. | — |
| 7. How do the crate's dependencies (including vendored `aws-mpl-native`) resolve in the version set? | — |
