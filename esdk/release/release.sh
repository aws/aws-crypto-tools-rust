#!/usr/bin/env bash
# Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
#
# git -> Brazil release for the aws-esdk crate. Runs in phases:
#
#   1. preflight    tool + version checks, clean-tree check
#   2. docs         cargo doc --all-features --no-deps, staged into build/docs
#   3. brazil-sync  import the crate into its Brazil package and publish
#   4. smoke-test   encrypt/decrypt round-trip against the released crate
#
# Phases 2 and 4 run from a plain GitHub checkout. Phase 3 needs Brazil
# coordinates that live outside this repo; see the "OPEN QUESTIONS" in
# RELEASE.md. When those are not configured the phase is skipped (not failed)
# and the smoke test consumes the in-repo crate, so a local run still
# generates docs and proves the crate round-trips.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ESDK_DIR="$(cd "${SCRIPT_DIR}/.." && pwd)"
REPO_ROOT="$(cd "${ESDK_DIR}/.." && pwd)"
SMOKE_DIR="${SCRIPT_DIR}/smoke-test"
STAGE="${SCRIPT_DIR}/build"
DOCS_OUT="${STAGE}/docs"

# Brazil coordinates. Unset here because they are not yet decided; override via
# the environment once they are (see RELEASE.md OPEN QUESTIONS).
BRAZIL_PACKAGE="${AWS_ESDK_BRAZIL_PACKAGE:-}"
BRAZIL_VERSION_SET="${AWS_ESDK_BRAZIL_VERSION_SET:-}"
BRAZIL_PACKAGE_DIR="${AWS_ESDK_BRAZIL_PACKAGE_DIR:-}"

RUN_DOCS=1
RUN_BRAZIL=1
RUN_SMOKE=1
EXECUTE_BRAZIL=0
EXPECTED_VERSION=""

log()  { printf '\n\033[1m== %s\033[0m\n' "$*"; }
warn() { printf '\033[33mWARN: %s\033[0m\n' "$*" >&2; }
die()  { printf '\033[31mERROR: %s\033[0m\n' "$*" >&2; exit 1; }

usage() {
    cat <<'EOF'
USAGE: release.sh [OPTIONS] [VERSION]

  VERSION            Optional N.N.N. If given, must match esdk/Cargo.toml.

OPTIONS:
  --skip-docs        Skip the cargo doc phase.
  --skip-smoke-test  Skip the smoke-test phase.
  --no-brazil        Skip the Brazil import/publish phase.
  --execute-brazil   Run the Brazil commands instead of printing the plan.
  -h, --help         Show this help.

ENVIRONMENT (Brazil phase):
  AWS_ESDK_BRAZIL_PACKAGE      Brazil package that mirrors the crate.
  AWS_ESDK_BRAZIL_VERSION_SET  Version set to publish into.
  AWS_ESDK_BRAZIL_PACKAGE_DIR  Local path to the Brazil package workspace.
EOF
}

while [ $# -gt 0 ]; do
    case "$1" in
        --skip-docs)       RUN_DOCS=0 ;;
        --skip-smoke-test) RUN_SMOKE=0 ;;
        --no-brazil)       RUN_BRAZIL=0 ;;
        --execute-brazil)  EXECUTE_BRAZIL=1 ;;
        -h|--help)         usage; exit 0 ;;
        -*)                die "unknown option: $1 (try --help)" ;;
        *)                 EXPECTED_VERSION="$1" ;;
    esac
    shift
done

crate_version() {
    cargo metadata --no-deps --format-version=1 --manifest-path "${ESDK_DIR}/Cargo.toml" \
        | grep -o '"version":"[0-9][^"]*"' | head -1 | cut -d'"' -f4
}

preflight() {
    log "preflight"
    command -v cargo >/dev/null || die "cargo not found on PATH"
    local version
    version="$(crate_version)"
    echo "aws-esdk version: ${version}"
    echo "cargo:  $(cargo --version)"
    echo "rustc:  $(rustc --version)"

    if [ -n "${EXPECTED_VERSION}" ] && [ "${EXPECTED_VERSION}" != "${version}" ]; then
        die "requested version '${EXPECTED_VERSION}' != esdk/Cargo.toml '${version}'"
    fi

    if [ -n "$(git -C "${REPO_ROOT}" status --porcelain)" ]; then
        warn "working tree is not clean; release should be cut from a clean checkout"
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

# Import the crate into its Brazil package and publish it, bundling the staged
# docs into the published layout. The exact package name, publish command, and
# docs destination are OPEN QUESTIONS (RELEASE.md); the unresolved steps are
# marked TODO(brazil). Without --execute-brazil this prints the plan only.
brazil_sync() {
    log "brazil-sync"
    if [ -z "${BRAZIL_PACKAGE}" ]; then
        warn "Brazil coordinates not configured (AWS_ESDK_BRAZIL_PACKAGE unset) -- skipping."
        warn "See RELEASE.md 'OPEN QUESTIONS' for what remains to wire up."
        RUN_BRAZIL=0
        return 0
    fi

    local run="echo   [plan]"
    [ "${EXECUTE_BRAZIL}" -eq 1 ] && run=""

    command -v brazil >/dev/null || die "brazil CLI not found on PATH"
    [ -n "${BRAZIL_PACKAGE_DIR}" ] || die "AWS_ESDK_BRAZIL_PACKAGE_DIR must be set"

    echo "package:     ${BRAZIL_PACKAGE}"
    echo "version set:  ${BRAZIL_VERSION_SET:-<unset>}"
    echo "package dir:  ${BRAZIL_PACKAGE_DIR}"

    # 1. Sync crate source into the Brazil package.
    # TODO(brazil): confirm the package's expected source layout / subdir.
    ${run} rsync -a --delete \
        --exclude target --exclude release/build \
        "${ESDK_DIR}/" "${BRAZIL_PACKAGE_DIR}/"

    # 2. Build under Brazil.
    ${run} bash -c "cd '${BRAZIL_PACKAGE_DIR}' && brazil-build"

    # 3. Bundle the built docs into the published layout.
    # TODO(brazil): confirm the path Brazil publishes docs from.
    ${run} cp -R "${DOCS_OUT}" "${BRAZIL_PACKAGE_DIR}/doc"

    # 4. Publish to the version set.
    # TODO(brazil): confirm the publish command (brazil-recursive-cmd release,
    # a pipeline, or a package-builder publish).
    ${run} echo "TODO(brazil): publish ${BRAZIL_PACKAGE} to ${BRAZIL_VERSION_SET}"
}

# Consume the released crate and run an encrypt/decrypt round-trip.
smoke_test() {
    log "smoke-test"
    if [ "${RUN_BRAZIL}" -eq 1 ]; then
        # TODO(brazil): repoint smoke-test/Cargo.toml at the Brazil-published
        # crate (version-set dependency) instead of the in-repo path dep.
        warn "consuming the Brazil-published crate is not wired yet; running against the in-repo crate."
    fi
    ( cd "${SMOKE_DIR}" && cargo run --release )
}

preflight
if [ "${RUN_DOCS}" -eq 1 ];   then build_docs;  fi
if [ "${RUN_BRAZIL}" -eq 1 ]; then brazil_sync;  fi
if [ "${RUN_SMOKE}" -eq 1 ];  then smoke_test;   fi

log "done"
