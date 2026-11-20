# Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
"""Rules every public type must follow, with or without a Smithy model.

Each rule protects room to grow: once a crate ships, breaking any of these
needs a major version.
"""

import re

from check import Finding
from model import snake

# Types that mean a builder holds something that does I/O, so build() must be async.
IO_TYPES = re.compile(r"\b(\w*Key[Ss]tore\w*|\w*Client|SdkConfig)\b")

NUMBERS = {"u8", "u16", "u32", "u64", "u128", "usize", "i8", "i16", "i32", "i64", "i128", "isize",
           "f32", "f64"}


def lint(surfaces, settings=None):
    """`settings` is the config's [lint] table: `const_ok` names structs that
    are fixed tables, whose getters may stay const."""
    settings = settings or {}
    const_ok = set(settings.get("const_ok", []))
    out = []
    # A variant may wrap a struct (it can gain fields) or a #[non_exhaustive]
    # enum (it can gain variants); never a primitive, a String or nothing.
    struct_names = {t["name"] for s in surfaces.values() for t in s["types"].values()
                    if t["kind"] == "struct" or (t["kind"] == "enum" and t["non_exhaustive"])}
    out += number_wrappers(surfaces)
    setter_types = {}
    for crate, s in surfaces.items():
        for path, t in s["types"].items():
            out += lint_type(path, t, struct_names)
            for m in t["methods"]:
                out += lint_method(path, m, t["name"], t["kind"], const_ok)
                if (m["receiver"] == "self" and m["output"] == "Self" and len(m["inputs"]) == 1
                        and not m["name"].startswith(("set_", "get_"))):
                    arg = m["inputs"][0][1]
                    base = re.sub(r"^impl Into<(.*)>$", r"\1", arg)
                    setter_types.setdefault((m["name"], base), {}).setdefault(arg, []).append(path)
        # `pub use X as Y`: callers see Y, the type is X; two names for one type.
        for a in s.get("aliases", []):
            out.append(Finding("lint.renamed_reexport", a["path"],
                               f"re-exports {a['source']} under another name", observed=a["real"],
                               where=a["path"], rust_type=a["path"].split("::")[-1]))
        for path, f in s["functions"].items():
            out += lint_method(path.rsplit("::", 1)[0], f, "", "fn", const_ok)
    # The same setter, for the same value type, should take it the same way everywhere.
    for (name, base), forms in sorted(setter_types.items()):
        if len(forms) > 1:
            where = "; ".join(f"{a}: {p[0]}" for a, p in sorted(forms.items()))
            for arg, paths in forms.items():
                for p in paths:
                    out.append(Finding("lint.setter_style", f"{name}({base})@{p}",
                                       f"`{name}` takes {base} in more than one way", observed=where,
                                       rust_type=p.split("::")[-1], rust_member=name))
    return out


NUMBER_SET = None


def number_wrappers(surfaces):
    """A struct that only wraps one number: `new(n)` plus a getter returning it.

    Callers should pass and read the plain number. Fixing it changes every
    method that takes or returns the wrapper, so the finding names them all.
    """
    out = []
    for s in surfaces.values():
        for path, t in s["types"].items():
            if t["kind"] != "struct" or t.get("pub_fields"):
                continue
            ms = t["methods"]
            ctor = [m for m in ms if m["receiver"] is None and len(m["inputs"]) == 1
                    and m["inputs"][0][1] in NUMBERS and m["output"] == "Self"]
            reads = [m for m in ms if m["receiver"] in ("self", "&self") and not m["inputs"]
                     and m["output"] in NUMBERS]
            if not ctor or not reads or len(ms) != len(ctor) + len(reads):
                continue
            name = t["name"]
            pat = re.compile(r"\b" + re.escape(name) + r"\b")
            users = [(u["name"], m["name"]) for s2 in surfaces.values() for u in s2["types"].values()
                     for m in u["methods"]
                     if any(pat.search(x) for _, x in m["inputs"]) or pat.search(m["output"])]
            out.append(Finding("lint.number_wrapper", path,
                               f"{name} only wraps a {reads[0]['output']}; take and return the number",
                               where=path, rust_type=name, extra_keys=users))
    return out


def lint_type(path, t, struct_names):
    out = []
    tag = {"rust_type": t["name"]}
    # Required on an enum or a struct with a public field. A struct with only
    # private fields may have it, but it changes nothing for callers there.
    grows = t["kind"] == "enum" or (t["kind"] == "struct" and t.get("pub_fields"))
    if grows and not t["non_exhaustive"]:
        out.append(Finding("lint.non_exhaustive", path, "public type is not #[non_exhaustive]", where=path, **tag))
    is_builder = t["name"].endswith("Builder")
    if "Clone" not in t["traits"]:
        check = "lint.builder_clone" if is_builder else "lint.clone"
        out.append(Finding(check, path, "public type does not implement Clone", where=path, **tag))
    if "Debug" not in t["traits"]:
        out.append(Finding("lint.debug", path, "public type does not implement Debug", where=path, **tag))
    build = next((m for m in t["methods"] if m["name"] == "build" and m["receiver"] == "self"), None)
    if is_builder and build and not build["is_async"]:
        holds = [m["inputs"][0][1] for m in t["methods"]
                 if m["inputs"] and IO_TYPES.search(m["inputs"][0][1])]
        if holds:
            out.append(Finding("lint.build_async", path,
                               "a builder that holds a key store or AWS client must build async",
                               observed=holds[0], where=path, rust_type=t["name"], rust_member="build"))
    if t["kind"] == "enum" and any(v["payload"] is not None for v in t["variants"]):
        for v in t["variants"]:
            p = v["payload"]
            ok = isinstance(p, list) and len(p) == 1 and p[0] in struct_names
            if not ok:
                # Fixing it adds a struct named after the variant (with a builder)
                # and changes the `as_<variant>` accessor to return it.
                out.append(Finding("lint.variant_payload", f"{path}::{v['name']}",
                                   "a data-carrying enum's variant should wrap one struct or "
                                   "#[non_exhaustive] enum, so it can grow later", observed=str(p), where=path,
                                   rust_type=t["name"], rust_member=v["name"],
                                   extra_keys=[(t["name"], "as_" + snake(v["name"])),
                                               (v["name"], ""), (v["name"] + "Builder", "")]))
    return out


TIME_NAME = re.compile(r"(^|_)(ttl|timeout|period|interval|sleep|delay|age|seconds|secs|millis?|milli)(_|$)")


def lint_method(path, m, type_name, kind, const_ok=frozenset()):
    out = []
    sig = " ".join(t for _, t in m["inputs"]) + " -> " + m["output"]
    subject = f"{path}::{m['name']}"
    tag = {"where": path, "rust_type": type_name, "rust_member": m["name"]}
    if "NonZero" in sig:
        out.append(Finding("lint.nonzero", subject, "NonZero* in a public signature", observed=sig, **tag))
    for _, t in m["inputs"]:
        mm = re.fullmatch(r"impl Into<(\w+)>", t)
        if mm and mm.group(1) in NUMBERS:
            out.append(Finding("lint.into_number", subject,
                               f"`impl Into<{mm.group(1)}>` rejects a bare integer literal", observed=t, **tag))
    if re.search(r"\b(Arc|Rc|Mutex|RwLock|RefCell|Cell)<", sig):
        out.append(Finding("lint.smart_pointer", subject,
                           "Arc/Mutex/RefCell in a public signature exposes how the value is stored",
                           observed=sig, **tag))
    # House rule: every operation may do I/O, so `send` is async.
    if m["name"] == "send" and m["receiver"] == "self" and not m["is_async"]:
        out.append(Finding("lint.send_async", subject, "`send` must be async", observed=sig, **tag))
    # Fixed values (enum lookups, free functions) may be const. A struct's
    # getters and setters may not: dropping const later breaks callers.
    if m["is_const"] and kind == "struct" and type_name not in const_ok:
        out.append(Finding("lint.const_fn", subject, "public `const fn` on a struct: dropping const later breaks callers", **tag))
    if re.search(r"(^|_)(len|length)$", m["name"]) and m["output"] in NUMBERS - {"usize"}:
        out.append(Finding("lint.length_type", subject, "a length should be usize", observed=m["output"], **tag))
    # A span of time is a Duration, never a bare count of seconds or millis.
    if TIME_NAME.search(m["name"]):
        types = [t for _, t in m["inputs"]] + [m["output"]]
        if any(re.sub(r"^(&|Option<|&Option<)+|>+$", "", t) in NUMBERS for t in types):
            out.append(Finding("lint.time_type", subject, "a span of time should be a Duration",
                               observed=sig, **tag))
    # A constructor taking several values can't gain an optional one; use a builder.
    if (m["receiver"] is None and type_name and len(m["inputs"]) >= 2
            and re.fullmatch(r"(Self|Result<Self, \w+>)", m["output"])):
        out.append(Finding("lint.positional_constructor", subject,
                           f"`{m['name']}` takes {len(m['inputs'])} values; use a builder", observed=sig,
                           extra_keys=[(type_name, "builder"), (type_name + "Builder", "")], **tag))
    return out
