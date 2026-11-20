# Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
"""Load a Smithy JSON AST and compute the shapes a service owes its callers."""

import json
import re

PRELUDE = "smithy.api#"
POLY = "aws.polymorph#"


def short(shape_id):
    """`aws.cryptography.keyStore#Foo$bar` -> `keyStore#Foo$bar`."""
    ns, _, rest = shape_id.partition("#")
    return ns.split(".")[-1] + "#" + rest


def name_of(shape_id):
    return shape_id.split("#", 1)[1].split("$", 1)[0]


def namespace(shape_id):
    return shape_id.split("#", 1)[0]


def norm(name):
    """Casing-free token sequence: `kmsMRKeyArn`, `kms_mr_key_arn`, `KmsMrKeyArn` all compare equal."""
    return re.sub(r"[^a-z0-9]", "", name.lower())


def snake(name):
    s = re.sub(r"([A-Z]+)([A-Z][a-z])", r"\1_\2", name)
    s = re.sub(r"([a-z0-9])([A-Z])", r"\1_\2", s)
    return s.replace("-", "_").lower()


def pascal(name):
    if "_" in name or name.isupper():
        return "".join(p.capitalize() for p in name.lower().split("_") if p)
    return name[0].upper() + name[1:]


class Model:
    def __init__(self, ast_path):
        self.shapes = json.load(open(ast_path))["shapes"]

    def get(self, sid):
        return self.shapes.get(sid)

    def traits(self, sid):
        s = self.shapes.get(sid) or {}
        return s.get("traits", {})

    def docs(self, sid, member=None):
        if member is not None:
            t = self.shapes[sid].get("members", {}).get(member, {}).get("traits", {})
        else:
            t = self.traits(sid)
        return t.get(PRELUDE + "documentation") or t.get(POLY + "javadoc") or ""

    def kind(self, sid):
        if sid.startswith(PRELUDE):
            return sid[len(PRELUDE):].lower()
        s = self.shapes.get(sid)
        if s is None:
            return "unknown"
        if s["type"] == "string" and PRELUDE + "enum" in s.get("traits", {}):
            return "enum"
        if s["type"] == "structure" and POLY + "reference" in s.get("traits", {}):
            return "reference"
        if s["type"] == "structure" and PRELUDE + "error" in s.get("traits", {}):
            return "error"
        return s["type"]

    def enum_values(self, sid):
        s = self.shapes[sid]
        if s["type"] == "enum":
            return [m for m in s["members"]]
        return [e.get("name") or e["value"] for e in s["traits"][PRELUDE + "enum"]]

    def members(self, sid):
        return (self.shapes.get(sid) or {}).get("members", {})

    def positional_member(self, sid):
        """The single member a `@positional` operation input/output unwraps to, else None."""
        if sid and POLY + "positional" in self.traits(sid):
            (m,) = self.members(sid).values()
            return m["target"]
        return None

    def reference_target(self, sid):
        ref = self.traits(sid).get(POLY + "reference", {})
        return ref.get("resource") or ref.get("service")

    def closure(self, roots, out_of_scope):
        """Every shape reachable from `roots`, cutting off at `out_of_scope` ids.

        Walks operations, resources, errors, inputs, outputs, members, list and
        map targets, and the resource or service a `@reference` structure names.
        """
        seen, stack = set(), list(roots)
        while stack:
            sid = stack.pop()
            if sid in seen or sid in out_of_scope or sid.startswith(PRELUDE) or sid not in self.shapes:
                continue
            seen.add(sid)
            s = self.shapes[sid]
            nxt = []
            for key in ("operations", "resources", "errors"):
                nxt += [x["target"] for x in s.get(key, [])]
            for key in ("input", "output", "member", "key", "value"):
                if key in s:
                    nxt.append(s[key]["target"])
            nxt += [m["target"] for m in s.get("members", {}).values()]
            ref = self.reference_target(sid)
            if ref:
                nxt.append(ref)
            stack += nxt
        return seen

    def operation_owner(self):
        """Map each operation id to the service or resource that declares it."""
        owner = {}
        for sid, s in self.shapes.items():
            if s["type"] in ("service", "resource"):
                for o in s.get("operations", []):
                    owner[o["target"]] = sid
        return owner

    def constraints(self, sid, member=None):
        keys = ("length", "range", "pattern")
        found = {}
        if member is not None:
            m = self.members(sid)[member]
            for k in keys:
                if PRELUDE + k in m.get("traits", {}):
                    found[k] = m["traits"][PRELUDE + k]
            sid = m["target"]
        for k in keys:
            if PRELUDE + k in self.traits(sid):
                found.setdefault(k, self.traits(sid)[PRELUDE + k])
        return found
