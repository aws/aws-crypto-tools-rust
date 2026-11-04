#!/usr/bin/env python3
# Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
"""Write the review page's exported decisions into the conformance config.

Usage: apply_decisions.py <config.toml> <conformance-decisions.json>

Each decision names an entry by its id (a deviation's `id`, a rename's or
out-of-scope entry's `shape`, a mirror's `rust`) and says `approved` or
`rejected`:
  approved -> status = "accepted" (the status line is removed; accepted is the default)
  rejected -> status = "rejected" (conform.py keeps the finding open: fix the code)
Mirrors have no status; a decision on one is reported and left alone.
Only status lines change; the rest of the file, comments included, stays as it was.
"""

import json
import re
import sys
import tomllib

TRIPLE = "'" * 3


def set_status(entry, choice):
    """`entry` with its status line replaced, skipping lines inside ''' strings."""
    body = entry.rstrip("\n")
    tail = entry[len(body):] or "\n"
    out, inside = [], False
    for line in body.split("\n"):
        if line.count(TRIPLE) % 2 == 1:
            inside = not inside
        elif not inside and line.startswith("status = "):
            continue
        out.append(line)
    if choice == "rejected":
        out.append('status = "rejected"')
    return "\n".join(out) + tail


def main():
    cfg_path, decisions_path = sys.argv[1:3]
    text = open(cfg_path).read()
    decisions = {k: v for k, v in json.load(open(decisions_path)).items() if v}
    for key, choice in decisions.items():
        if choice not in ("approved", "rejected"):
            sys.exit(f"unknown decision {choice!r} for {key}")

    # Split on table headers, so an entry runs to the next header no matter
    # what its multi-line example strings contain (blank lines included).
    parts = re.split(r"(?m)(?=^\[\[[a-z_]+\]\]$)", text)
    index = {}
    for i, part in enumerate(parts):
        m = re.match(r"\[\[(deviation|rename|out_of_scope|mirror)\]\]\n", part)
        if not m:
            continue
        field = {"deviation": "id", "mirror": "rust"}.get(m.group(1), "shape")
        k = re.search(rf'^{field} = "(.*)"$', part, re.M)
        if k:
            index[k.group(1)] = (i, m.group(1))

    done, missing = [], []
    for key, choice in decisions.items():
        if key not in index:
            missing.append(key)
            continue
        i, kind = index[key]
        if kind == "mirror":
            done.append((key, f"{choice} (mirrors have no status; left alone)"))
            continue
        parts[i] = set_status(parts[i], choice)
        done.append((key, choice))

    text = "".join(parts)
    tomllib.loads(text)  # refuse to write a file that no longer parses
    open(cfg_path, "w").write(text)
    for key, choice in done:
        print(f"{choice:9} {key}")
    for key in missing:
        print(f"not found {key}", file=sys.stderr)
    sys.exit(1 if missing else 0)


if __name__ == "__main__":
    main()
