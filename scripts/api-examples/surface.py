#!/usr/bin/env python3
# Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
"""List every way a customer can build each keyring, CMM and the ESDK client.

Usage: surface.py <out-dir> [--target-dir DIR]

Writes <out-dir>/mpl/surface.json and <out-dir>/esdk/surface.json in the format
that aws-crypto-tools-commons' api-examples builder script reads.
Reads each crate's public API from rustdoc JSON with ../smithy-conformance/rust_surface.py,
so it needs a nightly toolchain.

- Keyrings and CMMs are the types that convert into SharedKeyring or SharedCmm.
- The ESDK client is the type with `encrypt` and `decrypt` methods.
- An API's ways are its constructors, the setters of the builder that its `builder()` returns,
  and for `encrypt` and `decrypt`, the client method plus the setters of the builder that it returns.
"""

import argparse
import json
import os
import re
import subprocess
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
REPO = os.path.dirname(os.path.dirname(HERE))
RUST_SURFACE = os.path.join(REPO, "scripts", "smithy-conformance", "rust_surface.py")

# The trait each group's types implement, and the handle that holds one.
COMPONENT_GROUPS = [("Keyrings", "SharedKeyring"), ("CMMs", "SharedCmm")]
OPERATIONS = ["encrypt", "decrypt"]

# Words that the display name spells in capitals.
ACRONYMS = {"aws": "AWS", "aes": "AES", "kms": "KMS", "cmm": "CMM", "rsa": "RSA", "ecdh": "ECDH", "mrk": "MRK"}


def words(type_name):
    return re.findall(r"[A-Z][a-z0-9]*", type_name)


def api_id(type_name):
    return "-".join(w.lower() for w in words(type_name))


def display_name(type_name):
    out = []
    for i, w in enumerate(words(type_name)):
        low = w.lower()
        out.append(ACRONYMS.get(low, w if i == 0 else low))
    return " ".join(out)


def camel(name):
    head, *rest = name.split("_")
    return head + "".join(p.capitalize() for p in rest)


def signature(m):
    params = ([m["receiver"]] if m["receiver"] else []) + [f"{n}: {t}" for n, t in m["inputs"]]
    asyncness = "async " if m["is_async"] else ""
    return f"pub {asyncness}fn {m['name']}({', '.join(params)}) -> {m['output']}"


def is_setter(m):
    return (m["receiver"] in ("self", "&mut self") and m["output"] in ("Self", "&mut Self")
            and m["name"] not in ("build", "send"))


def setter_ways(builder):
    ways = []
    for m in builder["methods"]:
        if is_setter(m):
            option = m["name"][len("set_"):] if m["name"].startswith("set_") else m["name"]
            ways.append({"id": m["name"], "option": camel(option), "kind": "setter",
                         "signature": signature(m)})
    return ways


def builds(types, builder_path, target_path):
    builder = types.get(builder_path)
    return builder is not None and any(
        m["name"] == "build" and m["output_path"] == target_path for m in builder["methods"])


def constructor_ways(types, path):
    """Each public way to get a value of the type at `path`, and the builder that `builder()` returns."""
    t = types[path]
    ways, builder = [], None
    for m in t["methods"]:
        if m["receiver"] is not None:
            continue
        returns_self = m["output"] in ("Self", t["name"]) or m["output_path"] == path
        if returns_self or builds(types, m["output_path"], path):
            ways.append({"id": m["name"], "option": None, "kind": "constructor",
                         "signature": signature(m)})
            if not returns_self:
                builder = types[m["output_path"]]
    # Trait impls. A blanket impl shows as a bare trait name, so `From` alone is
    # `impl<T> From<T> for T` and not a way to build this type.
    if "Default" in t["traits"]:
        ways.append({"id": "default", "option": None, "kind": "constructor",
                     "signature": f"impl Default for {t['name']}"})
    sources = [tr[len("From<"):-1] for tr in t["traits"] if tr.startswith("From<")]
    if sources:
        ways.append({"id": "from", "option": None, "kind": "constructor",
                     "signature": "; ".join(f"impl From<{s}> for {t['name']}" for s in sources)})
    return ways, builder


def type_by_name(types, name):
    found = [p for p, t in types.items() if t["name"] == name]
    if len(found) != 1:
        sys.exit(f"expected one public type named {name}, found {found}")
    return found[0]


def mpl_apis(surface):
    types = surface["types"]
    apis = []
    for group, handle_name in COMPONENT_GROUPS:
        handle = types[type_by_name(types, handle_name)]
        # Each built-in component has `impl FromUnshared<Component> for Handle`,
        # which is how it converts into the handle.
        members = sorted(tr[len("FromUnshared<"):-1] for tr in handle["traits"]
                         if tr.startswith("FromUnshared<"))
        for name in members:
            if name in (handle_name, "T"):
                continue
            path = type_by_name(types, name)
            ways, builder = constructor_ways(types, path)
            if builder is not None:
                ways += setter_ways(builder)
            apis.append({"id": api_id(name), "group": group, "name": display_name(name),
                         "type": path, "ways": ways})
    return apis


def esdk_apis(surface):
    types = surface["types"]
    clients = [p for p, t in types.items()
               if all(any(m["name"] == op and m["receiver"] == "&self" for m in t["methods"])
                      for op in OPERATIONS)]
    if len(clients) != 1:
        sys.exit(f"expected one type with {OPERATIONS} methods, found {clients}")
    path = clients[0]
    client = types[path]
    ways, builder = constructor_ways(types, path)
    if builder is not None:
        ways += setter_ways(builder)
    apis = [{"id": api_id(client["name"]), "group": "Client", "name": display_name(client["name"]),
             "type": path, "ways": ways}]
    for op in OPERATIONS:
        method = next(m for m in client["methods"] if m["name"] == op)
        fluent = types[method["output_path"]]
        op_ways = [{"id": op, "option": None, "kind": "method", "signature": signature(method)}]
        op_ways += setter_ways(fluent)
        apis.append({"id": op, "group": "Client", "name": op.capitalize(),
                     "type": method["output_path"], "ways": op_ways})
    return apis


LIBRARIES = [("mpl", "mpl", mpl_apis), ("esdk", "esdk", esdk_apis)]


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("out_dir")
    ap.add_argument("--target-dir", default=os.environ.get("CARGO_TARGET_DIR"))
    a = ap.parse_args()
    with tempfile.TemporaryDirectory() as tmp:
        for library, crate_dir, find_apis in LIBRARIES:
            raw = os.path.join(tmp, f"{library}.json")
            cmd = [sys.executable, RUST_SURFACE, os.path.join(REPO, crate_dir), raw]
            if a.target_dir:
                cmd += ["--target-dir", a.target_dir]
            subprocess.run(cmd, check=True)
            apis = find_apis(json.load(open(raw)))
            out = {"schema": 1, "language": "rust", "library": library, "apis": apis}
            os.makedirs(os.path.join(a.out_dir, library), exist_ok=True)
            path = os.path.join(a.out_dir, library, "surface.json")
            with open(path, "w") as f:
                json.dump(out, f, indent=2)
                f.write("\n")
            n_ways = sum(len(api["ways"]) for api in apis)
            print(f"{library}: {len(apis)} APIs, {n_ways} ways -> {path}", file=sys.stderr)


if __name__ == "__main__":
    main()
