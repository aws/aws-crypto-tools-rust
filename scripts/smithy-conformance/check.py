# Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
"""Compare a Smithy model's shapes with a Rust crate's public API.

Every comparison here is mechanical. Each mismatch becomes a Finding with a
stable id (`<check>:<shape>`) so a deviations file can accept it by id.
"""

import os
import re
import tomllib
from dataclasses import dataclass, field

from model import POLY, PRELUDE, Model, name_of, namespace, norm, pascal, short, snake

MAPPINGS = os.path.join(os.path.dirname(os.path.abspath(__file__)), "mappings")


def load_mapping(language="rust"):
    return tomllib.load(open(os.path.join(MAPPINGS, f"{language}.toml"), "rb"))


@dataclass
class Finding:
    check: str
    subject: str
    message: str
    observed: str = ""
    expected: str = ""
    where: str = ""
    # The Rust type and member the finding is about (by name), so a later
    # change to exactly that item can be traced back to this finding.
    rust_type: str = ""
    rust_member: str = ""
    # Further (type, member) pairs the finding foretells, e.g. a missing
    # builder foretells the `FooBuilder` type as well as `Foo::builder`.
    extra_keys: list = field(default_factory=list)

    @property
    def id(self):
        return f"{self.check}:{self.subject}"


@dataclass
class Review:
    """A question only a reader of the code can settle (the LLM's part)."""
    kind: str
    subject: str
    question: str
    where: str = ""


@dataclass
class Index:
    """Every public type and trait across the crates under check, by casing-free name."""
    types: dict = field(default_factory=dict)
    traits: dict = field(default_factory=dict)
    surfaces: dict = field(default_factory=dict)

    @classmethod
    def build(cls, surfaces):
        ix = cls()
        ix.surfaces = surfaces
        for crate, s in surfaces.items():
            for path, t in s["types"].items():
                ix.types.setdefault(norm(t["name"]), []).append((crate, path, t))
            for path, t in s["traits"].items():
                ix.traits.setdefault(norm(t["name"]), []).append((crate, path, t))
        return ix

    def find(self, table, name, crate, own_only=False):
        hits = table.get(norm(name), [])
        own = [h for h in hits if h[0] == crate]
        if own_only:
            return (own or [None])[0]
        return (own or hits or [None])[0]


def same_type(observed, expected):
    """Casing-free type match: `EsdkAlgorithmSuiteId` matches the model's `ESDKAlgorithmSuiteId`."""
    key = observed.lower().replace("_", "")
    return any(key == e.lower().replace("_", "") for e in expected)


def follow(ix, m, crate):
    """The type a method returns: by its exact public path when known, else by name."""
    path = m.get("output_path")
    if path:
        for c, s in ix.surfaces.items():
            if path in s["types"]:
                return (c, path, s["types"][path])
    return ix.find(ix.types, m["output"], crate)


def method(t, name, receiver="&self", nargs=None):
    for m in t.get("methods", []):
        if m["name"] == name and (receiver is None or m["receiver"] == receiver):
            if nargs is None or len(m["inputs"]) == nargs:
                return m
    return None


def norm_doc(s):
    return " ".join(s.replace("`", "").split()).strip().lower()


class Checker:
    def __init__(self, model: Model, config, surfaces, crate, services):
        self.m = model
        self.crate = crate
        self.ix = Index.build(surfaces)
        # A rejected entry means "fix the code": the shape is checked as if the entry were absent.
        kept = lambda entries: [e for e in entries if e.get("status") != "rejected"]  # noqa: E731
        self.renames = {r["shape"]: r["rust"] for r in kept(config.get("rename", []))}
        self.out_of_scope = {o["shape"] for o in kept(config.get("out_of_scope", []))}
        self.services = services
        self.namespaces = {namespace(s) for s in services}
        self.findings, self.reviews, self.located = [], [], {}
        self.check_docs = config.get("checks", {}).get("docs", True)
        # Rust-only operations shaped like a modeled one (e.g. EncryptStream like Encrypt).
        self.mirrors = config.get("mirror", [])
        self.map = load_mapping(config.get("language", "rust"))

    # ---- naming -------------------------------------------------------------

    def rust_name(self, sid):
        if sid in self.renames:
            return self.renames[sid]
        k = self.m.kind(sid)
        if k == "service":
            return self.map["naming"]["client"]
        return name_of(sid)

    def member_name(self, sid, member):
        return self.renames.get(f"{sid}${member}", snake(member))

    def handle_name(self, resource):
        # A service's handle is named after its trait (the model name), not
        # after the concrete client a rename points at.
        base = name_of(resource) if self.m.kind(resource) == "service" else self.rust_name(resource)
        return self.map["naming"]["handle_prefix"] + base

    # ---- expected Rust types ---------------------------------------------------

    def owned(self, target):
        """Owned Rust spellings a value of `target` may take."""
        k = self.m.kind(target)
        named = set()
        if not target.startswith(PRELUDE) and k not in ("reference",):
            named = {self.rust_name(target)}
        if k in self.map["scalar"]:
            return set(self.map["scalar"][k]) | named
        if k == "reference":
            return {self.handle_name(self.m.reference_target(target))}
        if k == "list":
            inner = self.owned(self.m.get(target)["member"]["target"])
            return {f.replace("{T}", x) for f in self.map["collection"]["list"] for x in inner} | named
        if k == "map":
            s = self.m.get(target)
            ks, vs = self.owned(s["key"]["target"]), self.owned(s["value"]["target"])
            return {f.replace("{K}", a).replace("{V}", b) for f in self.map["collection"]["map"]
                    for a in ks for b in vs} | named
        return named

    def borrowed(self, target):
        out = set()
        for o in self.owned(target):
            out.add(o)
            out.add("&" + o)
            if o == "String":
                out.add("&str")
            if o.startswith("Vec<"):
                out.add("&[" + o[4:-1] + "]")
        return out

    def expected(self, target, required):
        base = self.borrowed(target)
        if required:
            return base
        return {f"Option<{b}>" for b in base} | {f"&Option<{b}>" for b in base}

    # ---- helpers ---------------------------------------------------------------

    def add(self, check, sid, message, **kw):
        self.findings.append(Finding(check, short(sid), message, **kw))

    def locate_type(self, sid):
        own = [h for h in self.ix.types.get(norm(self.rust_name(sid)), []) if h[0] == self.crate]
        if len({h[1] for h in own}) > 1:
            self.add("ambiguous_name", sid, f"several public types are named {self.rust_name(sid)}",
                     observed=", ".join(sorted(h[1] for h in own)), rust_type=self.rust_name(sid))
        # A rename says what the type should be called; the model name still
        # counts as found, so code that kept the model name is checked too.
        hit = (self.ix.find(self.ix.types, self.rust_name(sid), self.crate)
               or self.ix.find(self.ix.types, name_of(sid), self.crate))
        if hit:
            self.located[sid] = hit[1]
        return hit

    def doc_check(self, sid, docs_text, where, member=None):
        if not self.check_docs:
            return
        want = norm_doc(self.m.docs(sid, member))
        if want and want not in norm_doc(docs_text):
            subject = sid if member is None else f"{sid}${member}"
            self.add("doc_missing", subject, "modeled documentation is not in the Rust docs",
                     expected=self.m.docs(sid, member)[:200], where=where)

    # ---- per-shape checks --------------------------------------------------------

    def run(self):
        roots = list(self.services)
        shapes = self.m.closure(roots, self.out_of_scope)
        owner = self.m.operation_owner()
        for sid in sorted(shapes):
            if namespace(sid) not in self.namespaces:
                continue
            k = self.m.kind(sid)
            if k in ("structure", "error"):
                self.structure(sid, k)
            elif k == "union":
                self.union(sid)
            elif k == "enum":
                self.enum(sid)
            elif k == "operation":
                self.operation(sid, owner.get(sid))
            elif k == "resource":
                self.resource(sid)
            elif k == "service":
                self.service(sid)
        for mo in self.mirrors:
            if namespace(mo["like"]) in self.namespaces:
                self.mirror(mo)
        return shapes

    def mirror(self, mo):
        """Check a Rust-only operation as if the model declared it like `mo["like"]`."""
        like, name = mo["like"], mo["rust"]
        op = self.m.get(like)
        for key, suffix in (("input", "Input"), ("output", "Output")):
            target = op.get(key, {}).get("target")
            if not target:
                continue
            pseudo = f"{namespace(like)}#{name}{suffix}"
            self.m.shapes.setdefault(pseudo, dict(self.m.get(target), traits=self.m.traits(target)))
            hidden = set(mo.get("drop_members", []))
            for key_, val in list(self.renames.items()):
                if key_.startswith(target + "$"):
                    self.renames.setdefault(pseudo + key_[len(target):], val)
            self.m.shapes[pseudo] = dict(self.m.shapes[pseudo], members={
                k: v for k, v in self.m.members(target).items() if k not in hidden})
            self.structure(pseudo, "structure")
        owner = self.m.operation_owner().get(like)
        pseudo_op = f"{namespace(like)}#{name}"
        self.m.shapes.setdefault(pseudo_op, {"type": "operation",
                                             "input": {"target": f"{namespace(like)}#{name}Input"},
                                             "output": {"target": f"{namespace(like)}#{name}Output"}})
        self.operation(pseudo_op, owner)

    def structure(self, sid, kind):
        hit = self.locate_type(sid)
        other = self.ix.find(self.ix.types, name_of(sid), self.crate, own_only=True)
        if hit and other and other[1] != hit[1]:
            # Both the renamed type and one with the model's own name exist:
            # check the model-named one too.
            self.structure_at(sid, kind, other)
        self.structure_at(sid, kind, hit)

    def structure_at(self, sid, kind, hit):
        if not hit:
            self.add("type_missing", sid, f"no public Rust type named {self.rust_name(sid)}",
                     rust_type=self.rust_name(sid), extra_keys=[(self.rust_name(sid) + "Builder", "")])
            return
        _, path, t = hit
        if t["kind"] != "struct":
            self.add("wrong_kind", sid, "a Smithy structure should be a Rust struct",
                     observed=t["kind"], expected="struct", where=path)
        self.doc_check(sid, t["docs"], path)
        builder = None
        b = method(t, "builder", receiver=None, nargs=0)
        if b:
            bh = follow(self.ix, b, self.crate)
            builder = bh[2] if bh else None
        elif self.m.members(sid) and kind != "error":
            self.add("builder_missing", sid, f"{path} has no `builder()`", where=path,
                     rust_type=t["name"], rust_member="builder", extra_keys=[(t["name"] + "Builder", "")])
        required = [n for n, mem in self.m.members(sid).items() if PRELUDE + "required" in mem.get("traits", {})]
        zero_new = method(t, "new", receiver=None, nargs=0)
        if required and ("Default" in t["traits"] or zero_new):
            self.add("default_with_required", sid,
                     f"{path} can be made empty (Default or new()) but {required[0]} is required", where=path,
                     rust_type=t["name"], rust_member="",
                     extra_keys=[(t["name"], "impl Default"), (t["name"], "new")])
        for fname, _ in t.get("pub_fields", []):
            self.add("public_field", f"{sid}${fname}", f"{path}.{fname} is a public field; use a getter",
                     where=path, rust_type=t["name"], rust_member=fname)
        modeled = set()
        for mname, mem in self.m.members(sid).items():
            rname = self.member_name(sid, mname)
            modeled.add(rname)
            msid = f"{sid}${mname}"
            required = PRELUDE + "required" in mem.get("traits", {})
            getter = method(t, rname, nargs=0)
            field = next((f for f in t.get("pub_fields", []) if f[0] == rname), None)
            observed = getter["output"] if getter else (field[1] if field else None)
            if observed is None:
                if builder and method(builder, rname, receiver="self"):
                    self.add("getter_missing", msid, f"{path} has no `{rname}()` getter", where=path,
                             rust_type=t["name"], rust_member=rname)
                elif kind != "error":
                    self.add("member_missing", msid, f"{path} has no `{rname}` member", where=path,
                             rust_type=t["name"], rust_member=rname)
            else:
                want = self.expected(mem["target"], required)
                if self.m.kind(mem["target"]) == "list":
                    # aws-sdk-rust: a list getter returns &[T], empty when unset.
                    want = {w for w in self.borrowed(mem["target"]) if w.startswith("&[")}
                    for wrap in ("&Option<", "Option<"):
                        if observed.startswith(wrap) and observed.endswith(">"):
                            self.add("list_getter_option", msid,
                                     f"`{rname}()` should return a slice, empty when unset, not an Option",
                                     observed=observed, where=path, rust_type=t["name"], rust_member=rname)
                            observed = observed[len(wrap):-1]
                            break
                if not same_type(observed, want):
                    other = self.expected(mem["target"], not required)
                    check = "member_required" if same_type(observed, other) else "member_type"
                    self.add(check, msid,
                             f"`{rname}` is {'required' if required else 'optional'} "
                             f"and targets {short(mem['target'])}",
                             observed=observed, expected=" | ".join(sorted(want)[:6]), where=path,
                             rust_type=t["name"], rust_member=rname)
            if builder:
                self.builder_member(sid, mname, mem, builder, path)
            docs = (getter or {}).get("docs", "")
            if builder and method(builder, rname, receiver=None):
                docs += "\n" + method(builder, rname, receiver=None)["docs"]
            self.doc_check(sid, docs, path, member=mname)
            c = self.m.constraints(sid, mname)
            if c:
                self.reviews.append(Review("constraint", short(msid),
                                           f"is {c} enforced on `{rname}` (builder, setter or operation)?",
                                           where=path))
        if builder:
            for m_ in builder.get("methods", []):
                if m_["name"].startswith("set_") and m_["name"][4:] not in modeled:
                    self.add("member_extra", f"{sid}${m_['name'][4:]}",
                             f"{t['name']} has a `{m_['name'][4:]}` member the model lacks", where=path,
                             rust_type=builder["name"], rust_member=m_["name"][4:])

    def union(self, sid):
        hit = self.locate_type(sid)
        if not hit:
            self.add("type_missing", sid, f"no public Rust type named {self.rust_name(sid)}",
                     rust_type=self.rust_name(sid), extra_keys=[(self.rust_name(sid) + "Builder", "")])
            return
        _, path, t = hit
        if t["kind"] != "enum":
            self.add("wrong_kind", sid, "a Smithy union should be a Rust enum",
                     observed=t["kind"], expected="enum", where=path)
            return
        self.doc_check(sid, t["docs"], path)
        variants = {norm(v["name"]): v for v in t["variants"]}
        want = set()
        for mname, mem in self.m.members(sid).items():
            vname = self.renames.get(f"{sid}${mname}", pascal(mname))
            want.add(norm(vname))
            v = variants.get(norm(vname))
            msid = f"{sid}${mname}"
            if v is None:
                self.add("variant_missing", msid, f"{path} has no `{vname}` variant", where=path,
                         rust_type=t["name"], rust_member=vname)
                continue
            exp = self.owned(mem["target"])
            got = v["payload"]
            if not (isinstance(got, list) and len(got) == 1 and same_type(got[0], exp)):
                self.add("variant_type", msid, f"`{v['name']}` should carry one {short(mem['target'])}",
                         observed=str(got), expected=" | ".join(sorted(exp)), where=path,
                         rust_type=t["name"], rust_member=v["name"])
        for n, v in variants.items():
            if n not in want:
                self.add("variant_extra", f"{sid}${v['name']}", f"{path} has a `{v['name']}` variant the model lacks",
                         where=path)

    def enum(self, sid):
        hit = self.locate_type(sid)
        if not hit:
            self.add("type_missing", sid, f"no public Rust type named {self.rust_name(sid)}",
                     rust_type=self.rust_name(sid), extra_keys=[(self.rust_name(sid) + "Builder", "")])
            return
        _, path, t = hit
        if t["kind"] != "enum":
            self.add("wrong_kind", sid, "a Smithy enum should be a Rust enum",
                     observed=t["kind"], expected="enum", where=path)
            return
        self.doc_check(sid, t["docs"], path)
        variants = {norm(v["name"]): v["name"] for v in t["variants"]}
        want = {}
        for val in self.m.enum_values(sid):
            vname = self.renames.get(f"{sid}${val}", pascal(val))
            want[norm(vname)] = vname
            if norm(vname) not in variants:
                self.add("variant_missing", f"{sid}${val}", f"{path} has no `{vname}` variant", where=path)
        for n, v in variants.items():
            if n not in want:
                self.add("variant_extra", f"{sid}${v}", f"{path} has a `{v}` variant the model lacks", where=path)
        self.reviews.append(Review("enum_values", short(sid),
                                   "do the variants' string forms match the modeled enum values exactly?",
                                   where=path))

    def op_io(self, sid, key):
        s = self.m.get(sid)
        target = s.get(key, {}).get("target")
        if not target or target == PRELUDE + "Unit":
            return None
        return self.m.positional_member(target) or target

    def operation(self, sid, owner):
        if owner is None:
            return
        rname = self.renames.get(sid, snake(name_of(sid)))
        okind = self.m.kind(owner)
        inp, outp = self.op_io(sid, "input"), self.op_io(sid, "output")
        if okind == "resource":
            th = self.ix.find(self.ix.traits, self.rust_name(owner), self.crate, own_only=True)
            if not th:
                return  # resource() reports the missing trait
            _, path, tr = th
            m = next((x for x in tr["methods"] if x["name"] == rname), None)
            if not m:
                self.add("operation_missing", sid, f"trait {tr['name']} has no `{rname}`", where=path,
                         rust_type=tr["name"], rust_member=rname)
                return
            self.signature(sid, m, inp, outp, path)
            hh = self.ix.find(self.ix.types, self.handle_name(owner), self.crate, own_only=True)
            hm = hh and method(hh[2], rname)
            fb = hm and follow(self.ix, hm, self.crate)
            if fb and inp and self.m.kind(inp) == "structure":
                self.builder_covers(sid, inp, fb[2], fb[1])
            return
        # Service operation: a client method, or a renamed `Type::method` entry point.
        if "::" in rname:
            tname, mname = rname.split("::", 1)
            th = self.ix.find(self.ix.types, tname, self.crate)
            m = th and method(th[2], mname, receiver=None)
            if not m:
                self.add("operation_missing", sid, f"no `{rname}`", rust_type=tname, rust_member=mname,
                         extra_keys=[(tname + "Builder", "")] if mname == "builder" else [])
                return
            path = th[1]
            bh = follow(self.ix, m, self.crate)
            if bh and inp and self.m.kind(inp) == "structure":
                self.builder_covers(sid, inp, bh[2], bh[1])
            return
        ch = self.ix.find(self.ix.types, self.rust_name(owner), self.crate, own_only=True)
        if not ch:
            return  # service() reports the missing client
        _, path, client = ch
        m = method(client, rname)
        if not m:
            self.add("operation_missing", sid, f"{path} has no `{rname}()`", where=path,
                     rust_type=client["name"], rust_member=rname,
                     extra_keys=[(pascal(name_of(sid)) + self.map["naming"]["fluent_builder_suffix"], "")])
            return
        fb = follow(self.ix, m, self.crate)
        if fb and fb[2]["name"].endswith(self.map["naming"]["fluent_builder_suffix"]):
            send = method(fb[2], "send", receiver="self")
            if not send:
                self.add("operation_shape", sid, f"{fb[2]['name']} has no `send()`", where=fb[1],
                         rust_type=fb[2]["name"], rust_member="send")
            else:
                self.signature(sid, send, None, outp, fb[1])
                if not send["is_async"]:
                    self.add("send_not_async", sid, f"{fb[2]['name']}::send is not async", where=fb[1],
                             rust_type=fb[2]["name"], rust_member="send")
            if inp and self.m.kind(inp) == "structure":
                self.builder_covers(sid, inp, fb[2], fb[1])
        else:
            self.signature(sid, m, inp, outp, path)

    def builder_covers(self, op, inp, builder, path):
        for mname, mem in self.m.members(inp).items():
            rname = self.member_name(inp, mname)
            if not method(builder, rname, receiver=None):
                self.add("operation_input_missing", f"{inp}${mname}",
                         f"{builder['name']} has no `{rname}` for {short(op)}", where=path,
                         rust_type=builder["name"], rust_member=rname)
            else:
                self.builder_member(inp, mname, mem, builder, path)

    def setter_args(self, target):
        """Argument spellings a plain setter `x(..)` may take for one value of `target`."""
        k = self.m.kind(target)
        if k == "reference":
            h = self.handle_name(self.m.reference_target(target))
            return {f"impl IntoShared<{h}>", h}
        owned = self.owned(target)
        return owned | {f"impl Into<{o}>" for o in owned} | self.borrowed(target)

    def builder_member(self, sid, mname, mem, builder, path):
        """The aws-sdk-rust setter trio for one member: `x`, `set_x`, `get_x`.

        A list member's `x` appends one item and a map member's `x` inserts one
        entry; `set_x` replaces the whole value from an Option; `get_x` returns
        `&Option<T>`.
        """
        rname = self.member_name(sid, mname)
        msid = f"{sid}${mname}"
        target = mem["target"]
        k = self.m.kind(target)
        owned = self.owned(target)

        def flag(check, setter, message, observed="", expected=""):
            self.add(check, f"{msid}#{setter}", message, observed=observed, expected=expected,
                     where=path, rust_type=builder["name"], rust_member=setter)

        x = method(builder, rname, receiver=None)
        if not x:
            flag("builder_method_missing", rname, f"{builder['name']} has no `{rname}`")
        else:
            got = [t for _, t in x["inputs"]]
            if k == "list":
                want = [self.setter_args(self.m.get(target)["member"]["target"])]
            elif k == "map":
                s_ = self.m.get(target)
                want = [self.setter_args(s_["key"]["target"]), self.setter_args(s_["value"]["target"])]
            else:
                want = [self.setter_args(target)]
            # Two separate questions, so fixing one clears its own finding:
            # does `x` add one item (shape), and is that item the modeled type?
            whole = re.compile(r"Vec<|IntoIterator|\[|Set<|Map<")
            shape_ok = (len(got) == len(want)
                        and not (k == "list" and whole.search(got[0])))
            if k in ("list", "map") and not shape_ok:
                shape = {"list": "one item", "map": "one key and one value"}[k]
                flag("setter_shape", rname, f"`{rname}` should add {shape} per call, not take the whole {k}",
                     observed=", ".join(got))
            elif not all(same_type(g, w) for g, w in zip(got, want)) or len(got) != len(want):
                flag("setter_type", rname, f"`{rname}` should take {short(target)} values",
                     observed=", ".join(got), expected=" ; ".join(" | ".join(sorted(w)[:4]) for w in want))
        sx = method(builder, f"set_{rname}", receiver=None)
        if not sx:
            flag("builder_method_missing", f"set_{rname}", f"{builder['name']} has no `set_{rname}`")
        else:
            want = {f"Option<{o}>" for o in self.setter_args(target) if not o.startswith("impl ")}
            got = [t for _, t in sx["inputs"]]
            if len(got) != 1 or not same_type(got[0], want):
                flag("setter_type", f"set_{rname}", f"`set_{rname}` should take Option<{short(target)}>",
                     observed=", ".join(got), expected=" | ".join(sorted(want)[:4]))
        gx = method(builder, f"get_{rname}")
        if not gx:
            flag("builder_method_missing", f"get_{rname}", f"{builder['name']} has no `get_{rname}`")
        else:
            want = {f"&Option<{o}>" for o in self.setter_args(target) if not o.startswith("impl ")}
            if not same_type(gx["output"], want):
                flag("getter_type", f"get_{rname}", f"`get_{rname}` should return &Option<{short(target)}>",
                     observed=gx["output"], expected=" | ".join(sorted(want)[:4]))

    def signature(self, sid, m, inp, outp, path):
        if inp is not None:
            want = self.borrowed(inp)
            got = [t for _, t in m["inputs"]]
            if len(got) != 1 or not same_type(got[0], want):
                self.add("operation_input", sid, f"`{m['name']}` should take one {short(inp)}",
                         observed=", ".join(got), expected=" | ".join(sorted(want)), where=path,
                         rust_member=m["name"], rust_type=path.split("::")[-1])
        if outp is not None:
            want = {f"Result<{o}, Error>" for o in self.owned(outp)}
            if not same_type(m["output"], want):
                self.add("operation_output", sid, f"`{m['name']}` should return {short(outp)}",
                         observed=m["output"], expected=" | ".join(sorted(want)), where=path,
                         rust_member=m["name"], rust_type=path.split("::")[-1])

    def resource(self, sid):
        th = self.ix.find(self.ix.traits, self.rust_name(sid), self.crate, own_only=True)
        if not th and POLY + "extendable" in self.m.traits(sid):
            self.add("trait_missing", sid, f"no public trait named {self.rust_name(sid)}",
                     rust_type=self.rust_name(sid))
        hh = self.ix.find(self.ix.types, self.handle_name(sid), self.crate, own_only=True)
        if not hh:
            self.add("handle_missing", sid, f"no public handle type named {self.handle_name(sid)}",
                     rust_type=self.handle_name(sid))

    def service(self, sid):
        client = self.rust_name(sid)
        ops = [pascal(name_of(o["target"])) + self.map["naming"]["fluent_builder_suffix"]
               for o in self.m.get(sid).get("operations", []) if o["target"] not in self.out_of_scope]
        if not self.ix.find(self.ix.types, client, self.crate, own_only=True):
            self.add("client_missing", sid, f"no public client type named {client}",
                     rust_type=client, extra_keys=[(o, "") for o in ops])
        cfg = self.m.traits(sid).get(POLY + "localService", {}).get("config")
        if cfg:
            want = self.renames.get(cfg, self.map["naming"].get("config", "Config"))
            ch = self.ix.find(self.ix.types, want, self.crate, own_only=True)
            if not ch:
                self.add("config_missing", sid, f"no public config type named {want}",
                         rust_type=want, rust_member="builder", extra_keys=[(want + "Builder", "")])
                return
            b = method(ch[2], "builder", receiver=None, nargs=0)
            bh = b and follow(self.ix, b, self.crate)
            if not bh:
                self.add("builder_missing", cfg, f"{ch[1]} has no `builder()`", where=ch[1],
                         rust_type=ch[2]["name"], rust_member="builder",
                         extra_keys=[(ch[2]["name"] + "Builder", "")])
                return
            for mname, mem in self.m.members(cfg).items():
                self.builder_member(cfg, mname, mem, bh[2], bh[1])
