#!/usr/bin/env bash
# Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
#
# git -> Brazil release for the aws-esdk crate, in two review-gated steps:
#
#   1. release.sh            Check deps, run the gates, verify the build, bundle
#                            the docs, run the smoke test, then sync this crate
#                            onto a NEW BRANCH of the Brazil package and open a
#                            code review. Never a direct push to mainline.
#   2. release.sh --publish  After the code review is approved and merged to the
#                            package's mainline, PackageBuilder builds it and
#                            publishes to the version set.
#
# The review between the two steps is the gate: a code review cannot auto-merge,
# so publishing is deliberately a second command after a human approves.
#
# --dry-run runs the read-only phases and prints the mutating commands (the CR
# and the PackageBuilder build) instead of running them.
#
# Brazil coordinates come from the environment (one-time setup, see RELEASE.md);
# esdk/release/brazil.env is sourced when present.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ESDK_DIR="$(cd "${SCRIPT_DIR}/.." && pwd)"
REPO_ROOT="$(cd "${ESDK_DIR}/.." && pwd)"
SMOKE_DIR="${SCRIPT_DIR}/smoke-test"
STAGE="${SCRIPT_DIR}/build"
DOCS_OUT="${STAGE}/docs"

# shellcheck source=/dev/null
[ -f "${SCRIPT_DIR}/brazil.env" ] && . "${SCRIPT_DIR}/brazil.env"

BRAZIL_PACKAGE="${AWS_ESDK_BRAZIL_PACKAGE:-AwsCryptoToolsRust}"
BRAZIL_VERSION_SET="${AWS_ESDK_BRAZIL_VERSION_SET:-}"
BRAZIL_BRANCH="${AWS_ESDK_BRAZIL_BRANCH:-mainline}"
# Command that copies this crate + Config onto a NEW BRANCH of the package
# checkout and opens a code review. It must not push to mainline directly.
BRAZIL_IMPORT_CMD="${AWS_ESDK_BRAZIL_IMPORT_CMD:-}"
# Optional: overrides the default `brazil pb build` publish command entirely.
BRAZIL_PUBLISH_CMD="${AWS_ESDK_BRAZIL_PUBLISH_CMD:-}"

DRY_RUN=0
ASSUME_YES=0
PUBLISH_MODE=0

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
USAGE: release.sh [--dry-run] [--yes]        stage: verify + open the sync CR
       release.sh --publish [--dry-run]      after the CR merges: build + publish

  --dry-run   Run the read-only phases; print the CR and PackageBuilder commands
              instead of running them, and relax the outbound gates.
  --publish   Build the package from its mainline and publish to the version set
              (run after the sync code review is approved and merged).
  -y, --yes   Install missing dependencies without prompting.
  -h, --help  Show this help.

Brazil coordinates are read from the environment or esdk/release/brazil.env:
  AWS_ESDK_BRAZIL_PACKAGE      Brazil package (default: AwsCryptoToolsRust).
  AWS_ESDK_BRAZIL_VERSION_SET  Version set to publish into (PackageBuilder).
  AWS_ESDK_BRAZIL_BRANCH       Package mainline branch (default: mainline).
  AWS_ESDK_BRAZIL_IMPORT_CMD   Command that opens the branch + code review sync.
  AWS_ESDK_BRAZIL_PUBLISH_CMD  Optional: override the default `brazil pb build`.
EOF
}

while [ $# -gt 0 ]; do
    case "$1" in
        --dry-run)  DRY_RUN=1 ;;
        --publish)  PUBLISH_MODE=1 ;;
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
        cr)          echo "" ;;
        brazil)      echo "" ;;
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
# The stage run needs the build toolchain; --publish needs the brazil CLI.
check_deps() {
    log "dependencies"
    detect_pkg_mgr

    local required
    if [ "${PUBLISH_MODE}" -eq 1 ]; then
        required=(git brazil)
    else
        required=(git cargo rustc clippy make cc cmake go)
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

# ---- gates ---------------------------------------------------------------

# On a real run a failing gate is fatal; --dry-run downgrades the outbound gates
# (clean tree, pushed) to warnings so a WIP checkout validates.
gate() {
    log "gate"
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

# ---- stage phases --------------------------------------------------------

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

# Build a standalone consumer of the crate and run an encrypt/decrypt round-trip.
smoke_test() {
    log "smoke-test"
    ( cd "${SMOKE_DIR}" && cargo run --release )
}

# Sync this crate into the Brazil package by opening a code review on a NEW
# BRANCH -- never a direct push to mainline. The copy + Config + review is done
# by AWS_ESDK_BRAZIL_IMPORT_CMD (it knows the package's layout); this phase runs
# it and points you at the next step.
import_to_brazil() {
    log "import: open the sync code review"
    if [ -z "${BRAZIL_IMPORT_CMD}" ]; then
        warn "No sync configured. Set AWS_ESDK_BRAZIL_IMPORT_CMD to a command that copies"
        warn "this crate + Config onto a NEW BRANCH of the ${BRAZIL_PACKAGE} checkout and"
        warn "opens a code review (cr). It must not push to mainline directly."
        return 0
    fi
    run bash -c "${BRAZIL_IMPORT_CMD}"
    warn "Once the code review is approved and merged to ${BRAZIL_PACKAGE} mainline, run:"
    warn "  ./esdk/release/release.sh --publish"
}

# ---- publish phase -------------------------------------------------------

# PackageBuilder builds the package from its mainline and publishes into the
# version set. --autoMergeEnabled pulls missing dependencies from the tracking
# version set, which must be Rust-enabled to resolve the crate's ~210-crate
# closure.
publish() {
    log "publish: brazil pb build"
    [ -n "${BRAZIL_VERSION_SET}" ] || die "AWS_ESDK_BRAZIL_VERSION_SET must be set to publish (see RELEASE.md)"
    command -v brazil >/dev/null || die "brazil CLI not found on PATH"

    echo "package:      ${BRAZIL_PACKAGE}"
    echo "version set:  ${BRAZIL_VERSION_SET}"
    echo "branch:       ${BRAZIL_BRANCH}"

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
}

# ---- flow ----------------------------------------------------------------

check_deps
gate
if [ "${PUBLISH_MODE}" -eq 1 ]; then
    publish
    log "published"
else
    verify
    build_docs
    smoke_test
    import_to_brazil
    log "staged"
fi
