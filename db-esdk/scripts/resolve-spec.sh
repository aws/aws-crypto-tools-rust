#!/usr/bin/env bash
# Checks out the DB-ESDK spec pinned in spec-source.json and links it at <db-esdk>/spec.
# Duvet annotations then cite it as `spec/<area>/<file>.md`.
# The spec lives in the Dafny DB-ESDK repo, so this fetches only its spec folder, at depth 1.
# `make duvet` runs this every time.
#
# DBESDK_SPEC_URL overrides the URL (e.g. a local clone, for offline runs).
set -euo pipefail

script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
crate_root="$(cd "$script_dir/.." && pwd)"
config="$script_dir/spec-source.json"
url="${DBESDK_SPEC_URL:-$(jq -er '.spec.url' "$config")}"
ref="$(jq -er '.spec.ref' "$config")"
path="$(jq -er '.spec.path' "$config")"
src="$crate_root/.spec-src"
link="$crate_root/spec"

if [ ! -e "$src/.git" ]; then
  git init -q "$src"
  git -C "$src" remote add origin "$url"
  git -C "$src" sparse-checkout set --no-cone "/$path/"
fi
git -C "$src" remote set-url origin "$url"

git -C "$src" fetch -q --depth 1 origin "$ref"
git -C "$src" checkout -q --force --detach FETCH_HEAD

[ -d "$src/$path" ] || { echo "resolve-spec: $path missing at $ref" >&2; exit 1; }
ln -sfn ".spec-src/$path" "$link"
