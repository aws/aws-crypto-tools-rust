#!/usr/bin/env python3
# Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
"""List a Rust crate's public API from rustdoc JSON.

Usage: rust_surface.py <crate-dir> <out.json> [--features a,b] [--target-dir DIR]

Runs `cargo +nightly rustdoc --output-format json` on the crate, then walks the
module tree from the crate root, following `pub use` re-exports and skipping
anything rustdoc hides (`#[doc(hidden)]`). Only items a caller can name are
listed. Each type records its public path, kind, attributes, trait impls, its
variants (enums) and its inherent methods with rendered signatures.
"""

import argparse
import json
import os
import subprocess
import sys


# rustdoc's id -> real item name. A signature spells a type the way the source
# does, which may be a `use .. as ..` alias; render the real name so an alias
# can't make two spellings of one type compare unequal.
REAL_NAMES = {}


def render(t):
    """Render a rustdoc type as Rust source, each type by its real (unaliased) name."""
    if t is None:
        return "()"
    (k, v), = t.items()
    if k == "primitive" or k == "generic":
        return v
    if k == "resolved_path":
        name = REAL_NAMES.get(str(v.get("id")), v["path"].split("::")[-1])
        args = v.get("args") or {}
        if "angle_bracketed" in args:
            parts = []
            for a in args["angle_bracketed"]["args"]:
                if "type" in a:
                    parts.append(render(a["type"]))
                elif "lifetime" in a:
                    continue
                elif "const" in a:
                    parts.append(str(a["const"].get("expr")))
            for c in args["angle_bracketed"].get("constraints", []):
                b = c.get("binding", {})
                if "equality" in b and "type" in b["equality"]:
                    parts.append(f"{c['name']}={render(b['equality']['type'])}")
            if parts:
                name += "<" + ", ".join(parts) + ">"
        return name
    if k == "borrowed_ref":
        return "&" + ("mut " if v["is_mutable"] else "") + render(v["type"])
    if k == "slice":
        return "[" + render(v) + "]"
    if k == "array":
        return f"[{render(v['type'])}; {v['len']}]"
    if k == "tuple":
        return "(" + ", ".join(render(x) for x in v) + ")"
    if k == "impl_trait":
        return "impl " + " + ".join(bound(b) for b in v)
    if k == "dyn_trait":
        return "dyn " + " + ".join(render({"resolved_path": p["trait"]}) for p in v["traits"])
    if k == "qualified_path":
        return f"<{render(v['self_type'])}>::{v['name']}"
    if k == "raw_pointer":
        return "*" + render(v["type"])
    return k


def bound(b):
    if "trait_bound" in b:
        return render({"resolved_path": b["trait_bound"]["trait"]})
    if "outlives" in b:
        return b["outlives"]
    return "?"


def attrs_of(item):
    return [a if isinstance(a, str) else json.dumps(a) for a in item.get("attrs", [])]


def function(item, idx):
    f = item["inner"]["function"]
    sig = f["sig"]
    # `impl Trait` arguments show up as synthetic generics; inline their bounds.
    synthetic = {}
    for p in f["generics"]["params"]:
        kind = p["kind"].get("type")
        if kind is not None and kind.get("is_synthetic"):
            synthetic[p["name"]] = "impl " + " + ".join(bound(b) for b in kind["bounds"])
    inputs = []
    receiver = None
    for name, t in sig["inputs"]:
        r = render(t)
        if name == "self":
            receiver = {"Self": "self", "&Self": "&self", "&mut Self": "&mut self"}.get(r, r)
            continue
        inputs.append([name, synthetic.get(r, r)])
    output = render(sig["output"]) if sig["output"] is not None else "()"
    out_t = sig["output"] or {}
    if "resolved_path" in out_t and out_t["resolved_path"].get("args"):
        # Look through Result<T, _> / Option<T> to the type the method hands back.
        if out_t["resolved_path"]["path"].split("::")[-1] in ("Result", "Option"):
            first = out_t["resolved_path"]["args"].get("angle_bracketed", {}).get("args", [{}])[0]
            out_t = first.get("type", {})
    output_id = out_t.get("resolved_path", {}).get("id") if isinstance(out_t, dict) else None
    # async_trait methods return Pin<Box<dyn Future<Output=T>>>; report T.
    prefix = "Pin<Box<dyn Future<Output="
    if output.startswith(prefix):
        rest, depth, end = output[len(prefix):], 0, None
        for i, c in enumerate(rest):
            depth += (c == "<") - (c == ">")
            if depth < 0:
                end = i
                break
        output = rest[:end]
        asyncish = True
    else:
        asyncish = f["header"]["is_async"]
    return {
        "name": item["name"],
        "receiver": receiver,
        "inputs": inputs,
        "output": output,
        "output_id": output_id,
        "is_const": f["header"]["is_const"],
        "is_async": asyncish,
        "has_body": f.get("has_body", True),
        "docs": item.get("docs") or "",
    }


# rustdoc JSON formats this walker was checked against. A newer nightly may
# rename fields; fail loudly rather than silently read nothing.
SUPPORTED_FORMATS = {61}


def walk(doc):
    if doc.get("format_version") not in SUPPORTED_FORMATS:
        sys.exit(f"rustdoc JSON format {doc.get('format_version')} is not in {sorted(SUPPORTED_FORMATS)}; "
                 "check rust_surface.py against the new format, then add it")
    idx = doc["index"]
    REAL_NAMES.clear()
    REAL_NAMES.update({k: v["path"][-1] for k, v in doc["paths"].items()})
    out = {"crate": idx[str(doc["root"])]["name"], "types": {}, "traits": {}, "functions": {},
           "aliases": []}
    seen = set()

    def visit_module(mid, path):
        key = (mid, tuple(path))
        if key in seen:
            return
        seen.add(key)
        for child in idx[str(mid)]["inner"]["module"]["items"]:
            visit(child, path)

    def visit(iid, path, alias=None):
        item = idx.get(str(iid))
        if item is None or item["crate_id"] != 0 or item["visibility"] != "public":
            return
        kind, inner = next(iter(item["inner"].items()))
        name = alias or item["name"]
        if kind == "use":
            if inner["id"] is None:
                return
            target = idx.get(str(inner["id"]))
            real = REAL_NAMES.get(str(inner["id"]))
            kind = doc["paths"].get(str(inner["id"]), {}).get("kind")
            if real and not inner["is_glob"] and inner["name"] != real and kind in (
                    "struct", "enum", "union", "trait", "type_alias"):
                out["aliases"].append({"path": "::".join(path + [inner["name"]]), "real": real,
                                       "source": inner["source"]})
            if target is None or target["crate_id"] != 0:
                return
            if inner["is_glob"]:
                if "module" in target["inner"]:
                    visit_module(inner["id"], path)
                return
            visit(inner["id"], path, alias=inner["name"])
            return
        full = "::".join(path + [name])
        if kind == "module":
            visit_module(iid, path + [name])
        elif kind in ("struct", "enum", "union"):
            record_type(iid, item, kind, inner, full, name)
        elif kind == "trait":
            record_trait(item, inner, full, name)
        elif kind == "function":
            out["functions"][full] = function(item, idx)

    def record_type(iid, item, kind, inner, full, name):
        if str(iid) in done_types:
            done_types[str(iid)]["paths"].append(full)
            return
        traits, methods = [], []
        for imp_id in inner.get("impls", []):
            imp = idx.get(str(imp_id))
            if not imp:
                continue
            im = imp["inner"]["impl"]
            if im.get("blanket_impl") is not None or im.get("is_synthetic"):
                if im["trait"]:
                    traits.append(im["trait"]["path"].split("::")[-1])
                continue
            if im["trait"]:
                t = render({"resolved_path": im["trait"]})
                traits.append(t)
                continue
            for mid in im["items"]:
                m = idx.get(str(mid))
                if m and "function" in m["inner"] and m["visibility"] == "public":
                    methods.append(function(m, idx))
        rec = {
            "name": name,
            "paths": [full],
            "kind": kind,
            "attrs": attrs_of(item),
            "non_exhaustive": any("non_exhaustive" in a for a in attrs_of(item)),
            "docs": item.get("docs") or "",
            "traits": sorted(set(traits)),
            "methods": methods,
        }
        if kind == "enum":
            rec["variants"] = []
            for vid in inner["variants"]:
                v = idx[str(vid)]
                vk = v["inner"]["variant"]["kind"]
                if vk == "plain":
                    payload = None
                elif "tuple" in vk:
                    payload = [render(idx[str(f)]["inner"]["struct_field"]) if f is not None else "_"
                               for f in vk["tuple"]]
                else:
                    payload = {idx[str(f)]["name"]: render(idx[str(f)]["inner"]["struct_field"])
                               for f in vk["struct"]["fields"]}
                rec["variants"].append({"name": v["name"], "payload": payload, "docs": v.get("docs") or ""})
        if kind == "struct":
            k = inner["kind"]
            pub_fields = []
            if "plain" in k:
                for f in k["plain"]["fields"]:
                    fi = idx[str(f)]
                    pub_fields.append([fi["name"], render(fi["inner"]["struct_field"])])
            elif "tuple" in k:
                pub_fields = [["{}".format(i), render(idx[str(f)]["inner"]["struct_field"])]
                              for i, f in enumerate(k["tuple"]) if f is not None]
            rec["pub_fields"] = pub_fields
        done_types[str(iid)] = rec
        out["types"][full] = rec

    def record_trait(item, inner, full, name):
        methods = []
        for mid in inner["items"]:
            m = idx[str(mid)]
            if "function" in m["inner"]:
                methods.append(function(m, idx))
        out["traits"][full] = {
            "name": name,
            "paths": [full],
            "supertraits": [bound(b) for b in inner["bounds"]],
            "docs": item.get("docs") or "",
            "methods": methods,
        }

    done_types = {}
    visit_module(doc["root"], [out["crate"]])
    # A type re-exported at several paths is stored once, under its first path.
    out["types"] = {r["paths"][0]: r for r in done_types.values()}
    id_to_path = {k: r["paths"][0] for k, r in done_types.items()}
    for r in list(out["types"].values()) + list(out["traits"].values()):
        for m in r["methods"]:
            m["output_path"] = id_to_path.get(str(m.pop("output_id", None)))
    for f in out["functions"].values():
        f["output_path"] = id_to_path.get(str(f.pop("output_id", None)))
    return out


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("crate_dir")
    ap.add_argument("out")
    ap.add_argument("--features", default="")
    ap.add_argument("--target-dir", default=os.environ.get("CARGO_TARGET_DIR"))
    a = ap.parse_args()
    cmd = ["cargo", "+nightly", "rustdoc", "-q", "--lib"]
    if a.features:
        cmd += ["--features", a.features]
    cmd += ["--", "-Z", "unstable-options", "--output-format", "json"]
    env = dict(os.environ)
    if a.target_dir:
        env["CARGO_TARGET_DIR"] = a.target_dir
    subprocess.run(cmd, cwd=a.crate_dir, env=env, check=True, stderr=subprocess.DEVNULL)
    meta = json.loads(subprocess.run(
        ["cargo", "metadata", "--no-deps", "--format-version", "1"],
        cwd=a.crate_dir, env=env, check=True, capture_output=True).stdout)
    target = a.target_dir or meta["target_directory"]
    manifest = os.path.realpath(os.path.join(a.crate_dir, "Cargo.toml"))
    pkg = next(p for p in meta["packages"] if os.path.realpath(p["manifest_path"]) == manifest)
    # A crate that also builds a C library lists "rlib" (or "staticlib", "cdylib") instead of "lib".
    lib = next(t for t in pkg["targets"] if {"lib", "rlib", "staticlib", "cdylib"} & set(t["kind"]))
    doc = json.load(open(os.path.join(target, "doc", lib["name"].replace("-", "_") + ".json")))
    surface = walk(doc)
    json.dump(surface, open(a.out, "w"), indent=1, sort_keys=True)
    print(f"{surface['crate']}: {len(surface['types'])} types, {len(surface['traits'])} traits, "
          f"{len(surface['functions'])} free functions -> {a.out}", file=sys.stderr)


if __name__ == "__main__":
    main()
