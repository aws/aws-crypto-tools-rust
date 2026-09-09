#!/usr/bin/env bash
# Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
#
# Verifies that source files across the whole repository carry the header:
#     // SPDX-License-Identifier: Apache-2.0
#
# Applies to every project in the repo, and to any project added later, with
# no per-project wiring. The vendored unsafe-unreviewed-mpl tree is excluded
# (it is slated for removal); git submodules are not scanned.
#
# Modes:
#     check-license-headers.sh                changed vs merge-base(HEAD, origin/main)
#     check-license-headers.sh --base <ref>   changed vs merge-base(HEAD, <ref>)   (CI)
#     check-license-headers.sh --all          every tracked source file in the repo
#     check-license-headers.sh <file>...      the listed files only
#
# Exits non-zero and lists the offenders when a checked file lacks the header.

set -euo pipefail

SPDX="SPDX-License-Identifier: Apache-2.0"
# Number of leading lines searched for the header.
HEAD_LINES=15
# Source-file extensions this check applies to.
EXTENSIONS=(rs c cc cpp cxx h hpp hh hxx)
# Path prefixes (repo-root-relative) excluded from the check.
EXCLUDES=(unsafe-unreviewed-mpl/)

repo_root="$(git rev-parse --show-toplevel)"

mode="changed"
base_ref="origin/main"
explicit=()
while [[ $# -gt 0 ]]; do
    case "$1" in
        --all) mode="all"; shift ;;
        --base) base_ref="$2"; shift 2 ;;
        --) shift; explicit+=("$@"); break ;;
        -*) echo "unknown option: $1" >&2; exit 2 ;;
        *) explicit+=("$1"); shift ;;
    esac
done

is_source() {
    local ext
    for ext in "${EXTENSIONS[@]}"; do
        [[ "$1" == *."$ext" ]] && return 0
    done
    return 1
}

is_excluded() {
    local prefix
    for prefix in "${EXCLUDES[@]}"; do
        [[ "$1" == "$prefix"* ]] && return 0
    done
    return 1
}

candidates=()
if [[ ${#explicit[@]} -gt 0 ]]; then
    candidates=("${explicit[@]}")
elif [[ "$mode" == "all" ]]; then
    mapfile -t candidates < <(git -C "$repo_root" ls-files)
else
    base="$(git -C "$repo_root" merge-base HEAD "$base_ref")"
    mapfile -t candidates < <(git -C "$repo_root" diff --name-only --diff-filter=ACMR "$base" HEAD)
fi

checked=0
missing=()
if [[ ${#candidates[@]} -gt 0 ]]; then
    for f in "${candidates[@]}"; do
        is_source "$f" || continue
        is_excluded "$f" && continue
        path="$f"
        [[ -f "$path" ]] || path="$repo_root/$f"
        [[ -f "$path" ]] || continue
        checked=$((checked + 1))
        if ! head -n "$HEAD_LINES" "$path" | grep -q -- "$SPDX"; then
            missing+=("$f")
        fi
    done
fi

if [[ ${#missing[@]} -gt 0 ]]; then
    echo "Missing '$SPDX' header in:" >&2
    printf '  %s\n' "${missing[@]}" >&2
    exit 1
fi

echo "License header check passed ($checked file(s) checked)."
