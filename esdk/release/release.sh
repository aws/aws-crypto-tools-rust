#!/usr/bin/env bash
# Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
#
# One-command git -> Brazil release for the aws-esdk crate.
#
# A release copies the crate from git into its Brazil package and publishes it;
# Brazil's major-version (.x) version-set line handles consumption, so there is
# no per-release version and no git tag. Running this with no arguments performs
# the whole release: it checks its own dependencies (offering to install any
# that are missing), enforces the gates, verifies the build, bundles the docs,
# publishes to Brazil via PackageBuilder, then runs an encrypt/decrypt smoke
# test. It is
# otherwise non-interactive, and a failed gate stops the release before
# anything ships.
#
# Phases: deps -> gate -> verify -> docs -> brazil -> smoke-test.
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

# Brazil coordinates. Setting the package + version set makes this script
# publish via PackageBuilder with no further manual steps. See RELEASE.md.
BRAZIL_PACKAGE="${AWS_ESDK_BRAZIL_PACKAGE:-AwsCryptoToolsRust}"
BRAZIL_VERSION_SET="${AWS_ESDK_BRAZIL_VERSION_SET:-}"
BRAZIL_BRANCH="${AWS_ESDK_BRAZIL_BRANCH:-mainline}"
# Optional: a command that syncs this repo's crate into the Brazil package's
# source. Leave unset when the package is GitHub-backed (source already mirrored).
BRAZIL_IMPORT_CMD="${AWS_ESDK_BRAZIL_IMPORT_CMD:-}"
# Optional: overrides the default `brazil pb build` publish command entirely.
BRAZIL_PUBLISH_CMD="${AWS_ESDK_BRAZIL_PUBLISH_CMD:-}"

DRY_RUN=0
ASSUME_YES=0

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

# 0 = yes, 1 = no. --yes answers yes; a non-interactive stdin answers no so the
# script never hangs waiting for input.
prompt_yn() {
    [ "${ASSUME_YES}" -eq 1 ] && return 0
    [ -t 0 ] || return 1
    local ans
    printf '%s [Y/n] ' "$1"
    read -r ans || return 1
    case "${ans}" in ""|[Yy]|[Yy][Ee][Ss]) return 0 ;; *) return 1 ;; esac
}

usage() {
    cat <<'EOF'
USAGE: release.sh [--dry-run] [--yes]

Runs the whole aws-esdk git -> Brazil release. No arguments and no manual steps.

  --dry-run   Run the deps check, gates, build verify, docs, and smoke test;
              print the Brazil commands instead of running them, and relax the
              outbound gates.
  -y, --yes   Install missing dependencies without prompting.
  -h, --help  Show this help.

Brazil coordinates are read from the environment or esdk/release/brazil.env:
  AWS_ESDK_BRAZIL_PACKAGE      Brazil package that builds the crate.
  AWS_ESDK_BRAZIL_VERSION_SET  Version set to publish into (PackageBuilder).
  AWS_ESDK_BRAZIL_BRANCH       Package source branch (default: mainline).
  AWS_ESDK_BRAZIL_IMPORT_CMD   Optional: sync repo -> package source (skip if GitHub-backed).
  AWS_ESDK_BRAZIL_PUBLISH_CMD  Optional: override the default `brazil pb build`.
EOF
}

while [ $# -gt 0 ]; do
    case "$1" in
        --dry-run)  DRY_RUN=1 ;;
        -y|--yes)   ASSUME_YES=1 ;;
        -h|--help)  usage; exit 0 ;;
        *)          die "unknown argument: $1 (try --help)" ;;
    esac
    shift
done

# ---- dependency checking -------------------------------------------------

PKG_MGR=""
PKG=""
detect_pkg_mgr() {
    if   command -v dnf     >/dev/null 2>&1; then PKG_MGR=dnf; PKG="dnf install -y"
    elif command -v yum     >/dev/null 2>&1; then PKG_MGR=yum; PKG="yum install -y"
    elif command -v apt-get >/dev/null 2>&1; then PKG_MGR=apt; PKG="apt-get install -y"
    elif command -v brew    >/dev/null 2>&1; then PKG_MGR=brew; PKG="brew install"
    fi
    if [ -n "${PKG_MGR}" ] && [ "${PKG_MGR}" != brew ] && [ "$(id -u)" -ne 0 ] && command -v sudo >/dev/null 2>&1; then
        PKG="sudo ${PKG}"
    fi
}

# Package name per manager: $1 dnf, $2 yum, $3 apt, $4 brew.
pkg_cmd() {
    case "${PKG_MGR}" in
        dnf) echo "${PKG} $1" ;; yum) echo "${PKG} $2" ;;
        apt) echo "${PKG} $3" ;; brew) echo "${PKG} $4" ;;
        *) echo "" ;;
    esac
}

# Install command for a tool, or empty if it must be installed manually.
install_cmd_for() {
    case "$1" in
        cargo|rustc) echo "curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y" ;;
        clippy)      command -v rustup >/dev/null 2>&1 && echo "rustup component add clippy" || echo "" ;;
        go)          pkg_cmd golang golang golang-go go ;;
        cmake)       pkg_cmd cmake cmake cmake cmake ;;
        cc)          pkg_cmd gcc gcc build-essential gcc ;;
        make)        pkg_cmd make make make make ;;
        rsync)       pkg_cmd rsync rsync rsync rsync ;;
        git)         pkg_cmd git git git git ;;
        *)           echo "" ;;
    esac
}

have_tool() {
    case "$1" in
        cc)     command -v cc >/dev/null 2>&1 || command -v gcc >/dev/null 2>&1 || command -v clang >/dev/null 2>&1 ;;
        clippy) command -v cargo-clippy >/dev/null 2>&1 ;;
        *)      command -v "$1" >/dev/null 2>&1 ;;
    esac
}

# Verify every tool the run needs and offer to install any that are missing.
# Brazil publishing tools are required only for a real publish.
check_deps() {
    log "dependencies"
    detect_pkg_mgr

    local required=(git cargo rustc clippy make cc cmake go)
    if [ -n "${BRAZIL_PACKAGE}" ] && [ "${DRY_RUN}" -eq 0 ]; then
        required+=(brazil)
    fi

    local missing=() t
    for t in "${required[@]}"; do
        have_tool "${t}" || missing+=("${t}")
    done
    if [ "${#missing[@]}" -eq 0 ]; then
        echo "all required tools present"
        return 0
    fi

    warn "missing tools: ${missing[*]}"
    local still=() cmd
    for t in "${missing[@]}"; do
        have_tool "${t}" && continue   # a previous install may have provided it
        cmd="$(install_cmd_for "${t}")"
        if [ -z "${cmd}" ]; then
            warn "${t}: install manually (no automatic installer available here)"
            [ "${t}" = brazil ] && warn "  brazil: install via toolbox (toolbox install brazilcli)"
            still+=("${t}")
            continue
        fi
        echo "  ${t} -> ${cmd}"
        if prompt_yn "install ${t}?"; then
            if bash -c "${cmd}"; then
                [ -f "${HOME}/.cargo/env" ] && . "${HOME}/.cargo/env"
                have_tool "${t}" || { warn "${t} still not found after install"; still+=("${t}"); }
            else
                warn "install of ${t} failed"
                still+=("${t}")
            fi
        else
            still+=("${t}")
        fi
    done

    [ "${#still[@]}" -eq 0 ] || die "missing required tools: ${still[*]}"
}

# ---- release phases ------------------------------------------------------

# Release gates. On a real run a failing gate is fatal; --dry-run downgrades the
# outbound gates (clean tree, pushed) to warnings so a WIP checkout validates.
gate() {
    log "gate"
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

# Publish to Brazil via PackageBuilder: it builds the package from its source
# branch and publishes into the version set. --autoMergeEnabled pulls missing
# dependencies from the tracking version set, which must be Rust-enabled to
# resolve the crate's ~210-crate closure. Set AWS_ESDK_BRAZIL_IMPORT_CMD if the
# package is not GitHub-backed and needs the repo synced into its source first.
brazil() {
    log "brazil"
    if [ -z "${BRAZIL_PACKAGE}" ] || [ -z "${BRAZIL_VERSION_SET}" ]; then
        warn "NOT PUBLISHED: set AWS_ESDK_BRAZIL_PACKAGE and AWS_ESDK_BRAZIL_VERSION_SET to publish (see RELEASE.md)."
        warn "The build was verified, the docs bundled, and the smoke test run."
        PUBLISHED=0
        return 0
    fi

    command -v brazil >/dev/null || die "brazil CLI not found on PATH"
    echo "package:      ${BRAZIL_PACKAGE}"
    echo "version set:  ${BRAZIL_VERSION_SET}"
    echo "branch:       ${BRAZIL_BRANCH}"

    # TODO(brazil): confirm whether the package is GitHub-backed (no import step)
    # or needs a source push per release; set AWS_ESDK_BRAZIL_IMPORT_CMD if so.
    [ -n "${BRAZIL_IMPORT_CMD}" ] && run bash -c "${BRAZIL_IMPORT_CMD}"

    if [ -n "${BRAZIL_PUBLISH_CMD}" ]; then
        run bash -c "${BRAZIL_PUBLISH_CMD}"
    else
        local dry=""
        [ "${DRY_RUN}" -eq 1 ] && dry="--dryrun"
        run brazil packagebuilder build \
            --versionSet "${BRAZIL_VERSION_SET}" \
            --package "${BRAZIL_PACKAGE}" --branch "${BRAZIL_BRANCH}" \
            --useLatestChange --setAsTarget --autoMergeEnabled \
            --releaseNotes "aws-esdk release" --waitForCompletion ${dry}
    fi
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
check_deps
gate
verify
build_docs
brazil
smoke_test

log "release complete"
[ "${PUBLISHED}" -eq 1 ] || warn "reminder: nothing was published (see the brazil phase above)"
