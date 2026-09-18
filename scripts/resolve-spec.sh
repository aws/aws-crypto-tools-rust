#!/usr/bin/env bash
# Checks out the spec ref declared in spec-source.json into <repo-root>/spec.
# This script is run on every `make duvet` invocation.
# Every time `make duvet` runs, the checked-out spec is updated to this ref.
# The spec is not a git submodule.
set -euo pipefail

script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
repo_root="$(cd "$script_dir/.." && pwd)"
config="$script_dir/spec-source.json"
url="$(jq -er '.spec.url' "$config")"
ref="$(jq -er '.spec.ref' "$config")"
dest="$repo_root/spec"

if [ ! -e "$dest/.git" ]; then
  git init -q "$dest"
  git -C "$dest" remote add origin "$url"
fi
git -C "$dest" remote set-url origin "$url"

# The checkout below overwrites the checked-out spec ref.
# If it has uncommitted local edits, offer to commit and push them to the ref's branch before re-syncing.
# (Intended use case is for a developer writing spec and code at the same time.)
if git -C "$dest" rev-parse -q --verify HEAD >/dev/null 2>&1 \
   && ! git -C "$dest" diff --quiet HEAD --; then
  echo "resolve-spec: $dest has uncommitted local changes to the spec." >&2
  printf "Commit and push them to '%s'? [y/N] " "$ref" >&2
  read -r reply
  case "$reply" in
    [yY] | [yY][eE][sS])
      printf "Commit message: " >&2
      read -r msg
      [ -n "$msg" ] || msg="Update spec"
      git -C "$dest" add -A
      git -C "$dest" commit -q -m "$msg"
      git -C "$dest" push -q origin "HEAD:refs/heads/$ref"
      echo "resolve-spec: pushed local spec changes to $ref" >&2
      ;;
    *)
      echo "resolve-spec: aborting." >&2
      exit 1
      ;;
  esac
fi

git -C "$dest" fetch -q --depth 1 origin "$ref"
git -C "$dest" checkout -q --detach FETCH_HEAD
