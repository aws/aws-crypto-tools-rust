#!/usr/bin/env bash
# Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
#
# One-command git -> Brazil release for the aws-esdk crate.
#
# A release copies the crate from git into its Brazil package and publishes it;
# Brazil's major-version (.x) version-set line handles consumption, so there is
# no per-release version and no git tag. Running this with no arguments performs
# the whole release: it enforces the gates, verifies the build, bundles the
# docs, copies to Brazil and publishes, then runs an encrypt/decrypt smoke test.
# It is non-interactive and every gate is checked by the script, so there is no
# manual checklist and a failed gate stops the release before anything ships.
#
# Phases: gate -> verify -> docs -> brazil -> smoke-test.
#
# --dry-run runs the read-only phases and prints the Brazil commands instead of
# running them, for validating from a work-in-progress checkout.
#
# Brazil coordinates come from the environment (one-time setup, see RELEASE.md);
# esdk/release/brazil.env is sourced when present. Until they are set, a run
# verifies the build, bundles the docs, and runs the smoke test but does not
# publish, and says so.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ESDK_DIR="$(cd "${SCRIPT_DIR}/.." && pwd)"
REPO_ROOT="$(cd "${ESDK_DIR}/.." && pwd)"
SMOKE_DIR="${SCRIPT_DIR}/smoke-test"
STAGE="${SCRIPT_DIR}/build"
DOCS_OUT="${STAGE}/docs"

# shellcheck source=/dev/null
[ -f "${SCRIPT_DIR}/brazil.env" ] && . "${SCRIPT_DIR}/brazil.env"

# Brazil coordinates. Each maps to an OPEN QUESTION in RELEASE.md; setting them
# all makes this script copy to Brazil and publish with no further manual steps.
BRAZIL_PACKAGE="${AWS_ESDK_BRAZIL_PACKAGE:-}"
BRAZIL_PACKAGE_DIR="${AWS_ESDK_BRAZIL_PACKAGE_DIR:-}"
BRAZIL_VERSION_SET="${AWS_ESDK_BRAZIL_VERSION_SET:-}"
BRAZIL_PUBLISH_CMD="${AWS_ESDK_BRAZIL_PUBLISH_CMD:-}"
BRAZIL_DOC_DIR="${AWS_ESDK_BRAZIL_DOC_DIR:-doc}"

DRY_RUN=0

log()  { printf '\n\033[1m== %s\033[0m\n' "$*"; }
warn() { printf '\033[33mWARN: %s\033[0m\n' "$*" >&2; }
die()  { printf '\033[31mERROR: %s\033[0m\n' "$*" >&2; exit 1; }

# In a real run, execute the command; in a dry run, print it.
run() {
    if [ "${DRY_RUN}" -eq 1 ]; then
        printf '  [dry-run] %s\n' "$*"
    else
        "$@"
    fi
}

usage() {
    cat <<'EOF'
USAGE: release.sh [--dry-run]

Runs the whole aws-esdk git -> Brazil release. No arguments and no manual steps.

  --dry-run   Run the gates, build verify, docs, and smoke test; print the
              Brazil commands instead of running them, and relax the outbound
              gates.
  -h, --help  Show this help.

Brazil coordinates are read from the environment or esdk/release/brazil.env:
  AWS_ESDK_BRAZIL_PACKAGE      Brazil package that mirrors the crate.
  AWS_ESDK_BRAZIL_PACKAGE_DIR  Local path to the Brazil package workspace.
  AWS_ESDK_BRAZIL_VERSION_SET  Version set the package publishes into.
  AWS_ESDK_BRAZIL_PUBLISH_CMD  Command that publishes the built package.
  AWS_ESDK_BRAZIL_DOC_DIR      Docs subdir in the package (default: doc).
EOF
}

while [ $# -gt 0 ]; do
    case "$1" in
        --dry-run)  DRY_RUN=1 ;;
        -h|--help)  usage; exit 0 ;;
        *)          die "unknown argument: $1 (try --help)" ;;
    esac
    shift
done

# Release gates, enforced automatically. On a real run a failing gate is fatal;
# --dry-run downgrades the outbound gates (clean tree, pushed) to warnings so a
# work-in-progress checkout can be validated.
gate() {
    log "gate"
    command -v cargo >/dev/null || die "cargo not found on PATH"
    command -v rustc >/dev/null || die "rustc not found on PATH"
    echo "cargo:  $(cargo --version)"
    echo "rustc:  $(rustc --version)"

    local fail=die
    [ "${DRY_RUN}" -eq 1 ] && fail=warn

    [ -z "$(git -C "${REPO_ROOT}" status --porcelain)" ] \
        || ${fail} "working tree is not clean; release from a clean checkout"

    if [ "${DRY_RUN}" -eq 0 ]; then
        git -C "${REPO_ROOT}" fetch -q origin || die "cannot reach origin to verify HEAD is pushed"
        [ -n "$(git -C "${REPO_ROOT}" branch -r --contains HEAD 2>/dev/null)" ] \
            || die "current commit is not pushed to origin; push before releasing (Brazil mirrors git)"
    fi
}

# Build gate: clippy compiles and lints every test across all feature combos
# (credential-free). The full test matrix additionally runs only when AWS
# credentials are present, since some tests are KMS-backed.
verify() {
    log "verify: make clippy"
    ( cd "${ESDK_DIR}" && make clippy )

    if command -v aws >/dev/null 2>&1 && aws sts get-caller-identity >/dev/null 2>&1; then
        log "verify: make test"
        ( cd "${ESDK_DIR}" && make test )
    else
        warn "no AWS credentials detected; skipping make test (KMS-backed). clippy compiled every test; CI runs the full matrix on the PR."
    fi
}

# cargo doc --all-features --no-deps, staged so the built HTML ships with the
# package and the ORR can link build/docs/aws_esdk/index.html.
build_docs() {
    log "docs: cargo doc --all-features --no-deps"
    ( cd "${ESDK_DIR}" && cargo doc --all-features --no-deps )

    local index="${ESDK_DIR}/target/doc/aws_esdk/index.html"
    [ -f "${index}" ] || die "expected generated docs at ${index}"

    rm -rf "${DOCS_OUT}"
    mkdir -p "${DOCS_OUT}"
    cp -R "${ESDK_DIR}/target/doc/." "${DOCS_OUT}/"
    echo "docs staged at: ${DOCS_OUT}/aws_esdk/index.html"
}

# Copy the crate into its Brazil package, build it, bundle the docs, and
# publish. Runs end-to-end once the Brazil coordinates are set; the source
# layout, publish command, and docs destination are OPEN QUESTIONS (RELEASE.md)
# supplied via the environment.
brazil() {
    log "brazil"
    if [ -z "${BRAZIL_PACKAGE}" ]; then
        warn "NOT PUBLISHED: Brazil coordinates unset; verified the build, bundled docs, and ran the smoke test only."
        warn "Set AWS_ESDK_BRAZIL_* (see RELEASE.md) and re-run to publish."
        PUBLISHED=0
        return 0
    fi

    command -v brazil >/dev/null || die "brazil CLI not found on PATH"
    [ -n "${BRAZIL_PACKAGE_DIR}" ] || die "AWS_ESDK_BRAZIL_PACKAGE_DIR must be set"
    [ -n "${BRAZIL_PUBLISH_CMD}" ] || die "AWS_ESDK_BRAZIL_PUBLISH_CMD must be set (OPEN QUESTION)"

    echo "package:      ${BRAZIL_PACKAGE}"
    echo "version set:  ${BRAZIL_VERSION_SET:-<unset>}"
    echo "package dir:  ${BRAZIL_PACKAGE_DIR}"

    # TODO(brazil): confirm the package's expected source layout / subdir.
    run rsync -a --delete --exclude target --exclude release/build \
        "${ESDK_DIR}/" "${BRAZIL_PACKAGE_DIR}/"
    run bash -c "cd '${BRAZIL_PACKAGE_DIR}' && brazil-build"
    # TODO(brazil): confirm the path Brazil publishes docs from.
    run cp -R "${DOCS_OUT}" "${BRAZIL_PACKAGE_DIR}/${BRAZIL_DOC_DIR}"
    run bash -c "cd '${BRAZIL_PACKAGE_DIR}' && ${BRAZIL_PUBLISH_CMD}"
    PUBLISHED=1
}

# Build a standalone consumer of the released crate and run an encrypt/decrypt
# round-trip. A non-zero exit here fails the release.
smoke_test() {
    log "smoke-test"
    if [ "${PUBLISHED}" -eq 1 ]; then
        # TODO(brazil): repoint smoke-test/Cargo.toml at the Brazil-published
        # crate (version-set dependency) instead of the in-repo path dep.
        warn "consuming the Brazil-published crate is not wired yet; running against the in-repo crate."
    fi
    ( cd "${SMOKE_DIR}" && cargo run --release )
}

PUBLISHED=0
gate
verify
build_docs
brazil
smoke_test

log "release complete"
[ "${PUBLISHED}" -eq 1 ] || warn "reminder: nothing was published (see the brazil phase above)"
