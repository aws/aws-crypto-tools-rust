#!/usr/bin/env bash
# Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
#
# Verifies that every source file begins with the license header:
#     <comment> Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
#     <comment> SPDX-License-Identifier: Apache-2.0
# The first line includes the copyright notice;
# the second includes the SPDX license identifier.
# The header MUST be the first two lines.
# Only the text is checked, not the comment prefix, so //, #, and any other line-comment style satisfy it.
# Applies to every project in the repo and to any project added later.
#
# Modes:
#     check-license-headers.sh                changed vs merge-base(HEAD, origin/main)
#     check-license-headers.sh --base <ref>   changed vs merge-base(HEAD, <ref>)   (CI)
#     check-license-headers.sh --all          every tracked source file in the repo
#     check-license-headers.sh <file>...      the listed files only
#
# If a file is missing the header, exits non-zero and lists the offending file(s).

set -euo pipefail

# Text the first two lines must contain.
# The comment prefix (//, #, ...) is not checked.
COPYRIGHT_TEXT="Copyright Amazon.com Inc. or its affiliates. All Rights Reserved."
SPDX_TEXT="SPDX-License-Identifier: Apache-2.0"
# Source-file extensions this check applies to.
EXTENSIONS=(rs c cc cpp cxx h hpp hh hxx)

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
        path="$f"
        [[ -f "$path" ]] || path="$repo_root/$f"
        [[ -f "$path" ]] || continue
        checked=$((checked + 1))
        line1="$(sed -n '1p' "$path")"
        line2="$(sed -n '2p' "$path")"
        if [[ "$line1" != *"$COPYRIGHT_TEXT"* || "$line2" != *"$SPDX_TEXT"* ]]; then
            missing+=("$f")
        fi
    done
fi

if [[ ${#missing[@]} -gt 0 ]]; then
    echo "The first two lines must contain the copyright notice and SPDX identifier:" >&2
    echo "  <comment> $COPYRIGHT_TEXT" >&2
    echo "  <comment> $SPDX_TEXT" >&2
    echo "Missing or misplaced in:" >&2
    printf '  %s\n' "${missing[@]}" >&2
    exit 1
fi

echo "License header check passed ($checked file(s) checked)."
