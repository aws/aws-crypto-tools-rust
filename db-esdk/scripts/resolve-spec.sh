#!/usr/bin/env bash
# Checks out the DB-ESDK specification declared in spec-source.json and links it
# at <db-esdk>/spec, so duvet annotations cite it as `spec/<area>/<file>.md`.
# Run on every `make duvet`. The spec lives in the Dafny DB-ESDK repo, so this
# is a sparse, shallow checkout of only its spec folder. It is not a submodule.
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
