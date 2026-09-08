# Releasing `aws-esdk` (git → Brazil)

How the native Rust `aws-esdk` crate is released from this GitHub repo into its
internal Brazil package. Driven by [`release.sh`](./release.sh).

## Prerequisites

- A clean checkout of the branch being released (release from a clean tree).
- A Rust toolchain (`cargo`, `rustc`) — see the version CI pins in
  `.github/workflows/library_rust_tests.yml`.
- For the Brazil phase: the `brazil` CLI and the Brazil coordinates below.

## Steps

1. Confirm the version in `esdk/Cargo.toml` is the version you intend to release.
2. From a clean checkout, run the release script:

   ```bash
   ./esdk/release/release.sh <N.N.N>
   ```

   `<N.N.N>` is optional; when given it must match `esdk/Cargo.toml` (a typo
   guard). This runs, in order: preflight → docs → brazil-sync → smoke-test.
3. Review the staged docs at `esdk/release/build/docs/aws_esdk/index.html`.
   The ORR links this `index.html`.
4. Confirm the smoke test printed `OK: ... round-trip succeeded`.
5. Complete the Brazil publish (see OPEN QUESTIONS) and confirm the published
   version resolves for internal consumers.

## What the script does

| Phase | Command / effect | Runs from a plain checkout? |
|-------|------------------|-----------------------------|
| preflight | tool + version checks, clean-tree check | yes |
| docs | `cargo doc --all-features --no-deps`, copied to `build/docs/` | yes |
| brazil-sync | import the crate into its Brazil package, build, bundle docs, publish | no — needs Brazil coordinates |
| smoke-test | build a standalone consumer and run an encrypt/decrypt round-trip | yes |

The smoke test (`smoke-test/`) is a standalone crate that depends on `aws-esdk`
as an external consumer would and runs one encrypt/decrypt round-trip with a
local raw-AES keyring (no AWS credentials or network).

The Brazil phase is skipped, not failed, when its coordinates are unset, so a
local run still generates docs and runs the smoke test against the in-repo crate.

Brazil coordinates are supplied via the environment:

```bash
AWS_ESDK_BRAZIL_PACKAGE=<package>       \
AWS_ESDK_BRAZIL_VERSION_SET=<version-set> \
AWS_ESDK_BRAZIL_PACKAGE_DIR=<local path>  \
  ./esdk/release/release.sh --execute-brazil <N.N.N>
```

Without `--execute-brazil` the Brazil phase prints the commands it would run.

## OPEN QUESTIONS (Brazil-side)

These cannot be resolved from this repo alone. They gate the `brazil-sync`
phase (marked `TODO(brazil)` in `release.sh`) and the published-crate smoke test.

1. **Brazil package.** Does a Brazil package that mirrors this crate already
   exist? What is its name (`AWS_ESDK_BRAZIL_PACKAGE`)? If not, create it.
2. **Import mechanism.** Is git → Brazil a live/import package that tracks this
   repo, or a manual source sync into the package workspace? The script
   currently `rsync`s `esdk/` into `AWS_ESDK_BRAZIL_PACKAGE_DIR`; confirm the
   expected source layout and whether the crate needs a `Config`/build spec.
3. **Version set.** Which version set does it publish into
   (`AWS_ESDK_BRAZIL_VERSION_SET`), and how does the Cargo.toml version map to
   the Brazil package major version?
4. **Publish command.** What actually publishes the built package (a pipeline,
   `brazil-recursive-cmd`, package-builder)? This is the final `TODO(brazil)`.
5. **Docs destination.** Where does Brazil publish the bundled HTML from so the
   ORR link is stable? The script stages docs into `<package>/doc`; confirm the
   real published path (and whether an internal docs host serves it).
6. **Published-crate smoke test.** How does a consumer depend on the
   Brazil-published `aws-esdk` (version-set dependency)? Once known, repoint
   `smoke-test/Cargo.toml` off the in-repo `path` dependency for release runs.
7. **Dependencies.** How do `aws-esdk`'s dependencies (including the vendored
   `aws-mpl-native`) resolve inside the version set?
