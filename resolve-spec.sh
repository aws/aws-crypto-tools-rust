#!/usr/bin/env bash
# Resolve the spec dependency declared in spec-source.json into <repo-root>/spec.
# The spec is a build-time dependency cloned at the configured ref, not a git submodule.
# `ref` may be a branch (tracks its tip) or a commit.
set -euo pipefail

root="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
config="$root/spec-source.json"
url="$(jq -er '.spec.url' "$config")"
ref="$(jq -er '.spec.ref' "$config")"
dest="$root/spec"

if [ ! -e "$dest/.git" ]; then
  git init -q "$dest"
  git -C "$dest" remote add origin "$url"
fi
git -C "$dest" remote set-url origin "$url"
git -C "$dest" fetch -q --depth 1 origin "$ref"
git -C "$dest" checkout -q --detach FETCH_HEAD
