#!/usr/bin/env python3
# Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
"""Check a Rust repo's public API against Smithy models and the lint rules.

Usage: conform.py [--config FILE] [--repo DIR] [--out DIR] [--reuse]

Checks every published library crate in the repo; each model service is matched
to the crate that implements it. The config (config.toml next to this script by
default; see config-format.md) pins the model sources and lists every accepted
deviation with its reason. Exit status: 0 when every finding is accepted and no deviation is
stale; 1 otherwise; 2 on a setup error.
"""

import argparse
import fnmatch
import hashlib
import json
import os
import subprocess
import sys
import tomllib
import urllib.request
import zipfile
from collections import Counter

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from check import Checker  # noqa: E402
from lint import lint  # noqa: E402
from check import Index  # noqa: E402
from model import Model, norm  # noqa: E402

CACHE = os.path.expanduser(os.environ.get("SMITHY_CONFORMANCE_CACHE", "~/.cache/smithy-conformance"))
HERE = os.path.dirname(os.path.abspath(__file__))


def smithy_cli(cfg):
    version, digest = cfg["smithy"]["version"], cfg["smithy"]["sha256"]
    home = os.path.join(CACHE, f"smithy-cli-{version}")
    exe = os.path.join(home, "smithy-cli-linux-x86_64", "bin", "smithy")
    if os.path.exists(exe):
        return exe
    os.makedirs(home, exist_ok=True)
    url = f"https://github.com/smithy-lang/smithy/releases/download/{version}/smithy-cli-linux-x86_64.zip"
    zpath = os.path.join(home, "cli.zip")
    print(f"downloading Smithy CLI {version}", file=sys.stderr)
    urllib.request.urlretrieve(url, zpath)
    got = hashlib.sha256(open(zpath, "rb").read()).hexdigest()
    if got != digest:
        os.remove(zpath)
        sys.exit(f"Smithy CLI checksum mismatch: got {got}, config pins {digest}")
    with zipfile.ZipFile(zpath) as z:
        z.extractall(home)
    for root, _, files in os.walk(home):
        for f in files:
            p = os.path.join(root, f)
            if "/bin/" in p or "/lib/" in p:
                os.chmod(p, 0o755)
    return exe


def checkout(repo, ref):
    name = repo.rstrip("/").split("/")[-1].removesuffix(".git")
    d = os.path.join(CACHE, "models", name)
    if not os.path.isdir(os.path.join(d, ".git")):
        subprocess.run(["git", "clone", "-q", "--filter=blob:none", "--no-checkout", repo, d], check=True)
    have = subprocess.run(["git", "-C", d, "cat-file", "-e", ref + "^{commit}"], capture_output=True)
    if have.returncode != 0:
        subprocess.run(["git", "-C", d, "fetch", "-q", "origin", ref], check=True)
    subprocess.run(["git", "-C", d, "checkout", "-q", "--detach", ref], check=True)
    return d


def build_ast(cfg, out):
    exe = smithy_cli(cfg)
    files = []
    for src in cfg["model"]:
        d = checkout(src["repo"], src["ref"])
        files += [os.path.join(d, p) for p in src["paths"]]
    with open(out, "w") as f:
        r = subprocess.run([exe, "ast", "--allow-unknown-traits", *files], stdout=f, stderr=subprocess.PIPE,
                           text=True)
    if r.returncode != 0:
        sys.exit("smithy ast failed:\n" + r.stderr)


def discover_crates(repo):
    """Every published library crate in the repo: its path from the repo root.

    A crate is skipped when its manifest says `publish = false` or it has no
    library target; test servers, benchmarks, examples, and xtask are all
    marked that way.
    """
    tracked = subprocess.run(["git", "-C", repo, "ls-files", "*Cargo.toml"], capture_output=True, text=True,
                             check=True).stdout.split()
    crates = []
    for manifest in sorted(tracked):
        d = os.path.dirname(manifest)
        pkg = tomllib.load(open(os.path.join(repo, manifest), "rb")).get("package")
        if not pkg or pkg.get("publish") is False:
            continue
        lib_path = tomllib.load(open(os.path.join(repo, manifest), "rb")).get("lib", {}).get("path", "src/lib.rs")
        if os.path.exists(os.path.join(repo, d, lib_path)):
            crates.append(d)
    return crates


def assign_services(model, surfaces):
    """Map each crate to the model's local services it implements.

    A service belongs to the crate that defines the most of the shape names it
    reaches. A service no crate defines any shape of is left out.
    """

    ix = Index.build(surfaces)
    services = {crate: [] for crate in surfaces}
    for sid in sorted(model.shapes):
        if model.kind(sid) != "service" or "aws.polymorph#localService" not in model.traits(sid):
            continue
        ns = sid.split("#", 1)[0]
        names = {norm(s.split("#", 1)[1]) for s in model.closure([sid], set()) if s.startswith(ns + "#")}
        score = Counter(crate for n in names for crate, _, _ in ix.types.get(n, []) + ix.traits.get(n, []))
        if score:
            best = max(sorted(score), key=lambda c: score[c])
            services[best].append(sid)
    return [{"crate": crate, "services": svc} for crate, svc in services.items()]


def owners(text, libs, surfaces):
    """The crates a finding id or deviation id is about.

    A model id names its namespace (`materialProviders#...`), owned by the crate
    implementing a service in it; a lint id names a Rust path (`aws_esdk::...`).
    An id naming neither (such as a bare `*` glob) belongs to every crate.
    """
    hits = set()
    for lib in libs:
        lib_name = surfaces[lib["crate"]]["crate"]
        namespaces = {sid.split("#", 1)[0].rsplit(".", 1)[-1] for sid in lib["services"]}
        if f"{lib_name}::" in text or any(f"{ns}#" in text for ns in namespaces):
            hits.add(lib["crate"])
    return hits or {lib["crate"] for lib in libs}


def surfaces_for(cfg, repo, out, reuse):
    surfaces = {}
    for lib in cfg["library"]:
        path = os.path.join(out, f"surface-{lib['crate'].replace('/', '_')}.json")
        if not (reuse and os.path.exists(path)):
            cmd = [sys.executable, os.path.join(HERE, "rust_surface.py"), os.path.join(repo, lib["crate"]), path]
            if lib.get("features"):
                cmd += ["--features", lib["features"]]
            subprocess.run(cmd, check=True)
        surfaces[lib["crate"]] = json.load(open(path))
    return surfaces


def apply_deviations(findings, deviations):
    """Accept each finding by the deviations whose id glob matches it.

    A finding several deviations match is an overlap: the order of the file
    would decide the outcome, so it stays open until one entry is narrowed.
    A pinned `observed` that no longer matches reopens the finding; it never
    falls through to a broader entry.
    """
    used = [0] * len(deviations)
    for f in findings:
        f.accepted, f.status, f.changed, f.overlap, f.deviation = None, None, None, [], None
        hits = [i for i, d in enumerate(deviations) if fnmatch.fnmatchcase(f.id, d["id"])]
        for i in hits:
            used[i] += 1
        if not hits:
            continue
        if len(hits) > 1:
            f.overlap = [deviations[i]["id"] for i in hits]
            continue
        d = deviations[hits[0]]
        if d.get("status") == "rejected":
            # The reviewer said fix the code: the finding stays open, and the
            # entry stays so its reason is kept and it doesn't look stale.
            f.changed = "rejected in review"
            continue
        if "observed" in d and d["observed"] != f.observed:
            f.changed = d["observed"]
            continue
        f.accepted = d["reason"]
        f.status = d.get("status", "accepted")
        f.deviation = d["id"]
    return [d for d, n in zip(deviations, used) if n == 0]


def report(findings, stale, reviews, unmatched, proposed_scope, out):
    open_ = [f for f in findings if not f.accepted]
    proposed = [f for f in findings if f.accepted and f.status == "proposed"]
    deferred = [f for f in findings if f.accepted and f.status == "deferred"]
    lines = ["# Smithy conformance report", ""]
    lines.append(f"- findings: {len(findings)} ({len(findings) - len(open_)} accepted, {len(open_)} open)")
    lines.append(f"- proposed, not yet accepted: {len(proposed)} findings, {len(proposed_scope)} out-of-scope shapes")
    lines.append(f"- deferred (tracked, not failing): {len(deferred)}")
    lines.append(f"- stale deviations: {len(stale)}")
    lines.append(f"- review questions: {len(reviews)}")
    ok = not open_ and not stale and not proposed and not proposed_scope
    lines.append(f"- result: **{'PASS' if ok else 'FAIL'}**")
    lines.append("")
    if open_:
        lines += ["## Open findings", "", "| id | message | observed | expected |", "|---|---|---|---|"]
        for f in sorted(open_, key=lambda f: f.id):
            changed = (" (rejected in review: fix the code)" if f.changed == "rejected in review"
                       else f" (deviation pinned `{f.changed}`)" if f.changed else "")
            if f.overlap:
                changed += " (matched by " + ", ".join(f"`{o}`" for o in f.overlap) + "; narrow one)"
            lines.append(f"| `{f.id}` | {f.message}{changed} | `{f.observed}` | `{f.expected}` |")
        lines.append("")
    if stale:
        lines += ["## Stale deviations (match nothing; delete them)", ""]
        lines += [f"- `{d['id']}`: {d['reason']}" for d in stale]
        lines.append("")
    lines += ["## Open findings by check", ""]
    lines += [f"- {k}: {v}" for k, v in sorted(Counter(f.check for f in open_).items())]
    lines += ["", "## Proposed deviations (accept by deleting `status = \"proposed\"`, or fix the code)", ""]
    lines += [f"- {v} x {k}" for k, v in Counter(f.accepted for f in proposed).most_common()]
    lines += [f"- {o.get('kind', 'entry')}: `{o['shape']}`: {o['reason']}" for o in proposed_scope]
    lines += ["", "## Deferred (fix later)", ""]
    lines += [f"- {v} x {k}" for k, v in Counter(f.accepted for f in deferred).most_common()]
    lines += ["", "## Accepted deviations by reason", ""]
    lines += [f"- {v} x {k}" for k, v in
              Counter(f.accepted for f in findings if f.accepted and f.status == "accepted").most_common()]
    lines += ["", "## Review questions (answer each with file:line)", ""]
    lines += [f"- [{r.kind}] `{r.subject}` ({r.where}): {r.question}" for r in reviews]
    lines += ["", "## Public types with no model shape (confirm each is meant to be public)", ""]
    lines += [f"- `{p}`" for p in unmatched]
    open(os.path.join(out, "report.md"), "w").write("\n".join(lines) + "\n")
    json.dump([dict(vars(f), id=f.id, crates=sorted(getattr(f, "crates", ()))) for f in findings], open(os.path.join(out, "findings.json"), "w"),
              indent=1)
    return ok


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--config", default=os.path.join(HERE, "config.toml"))
    ap.add_argument("--repo", help="repo root (default: the git repo this script is in)")
    ap.add_argument("--out", default=os.path.join(CACHE, "run"))
    ap.add_argument("--reuse", action="store_true", help="reuse surface JSON already in --out")
    ap.add_argument("--crate", help="report and fail only on this crate (its path from the repo root); "
                                    "every crate is still built, to match model services to crates")
    ap.add_argument("--list", action="store_true", help="print the checked crates as a JSON list and exit")
    a = ap.parse_args()
    cfg = tomllib.load(open(a.config, "rb"))
    repo = a.repo or subprocess.run(["git", "-C", HERE, "rev-parse", "--show-toplevel"], capture_output=True,
                                    text=True, check=True).stdout.strip()
    if a.list:
        print(json.dumps(discover_crates(repo)))
        return
    if a.crate and a.crate not in discover_crates(repo):
        sys.exit(f"{a.crate} is not a published library crate in {repo}: {discover_crates(repo)}")
    os.makedirs(a.out, exist_ok=True)
    for d in cfg.get("rename", []) + cfg.get("out_of_scope", []) + cfg.get("deviation", []):
        if not d.get("reason"):
            sys.exit(f"config entry has no reason: {d}")
        if d.get("status", "accepted") not in ("accepted", "proposed", "deferred", "rejected"):
            sys.exit(f"status must be accepted, proposed, deferred or rejected: {d}")

    ast = os.path.join(a.out, "model.json")
    if not (a.reuse and os.path.exists(ast)):
        build_ast(cfg, ast)
    model = Model(ast)
    cfg["library"] = [{"crate": c} for c in discover_crates(repo)]
    surfaces = surfaces_for(cfg, repo, a.out, a.reuse)
    cfg["library"] = assign_services(model, surfaces)
    for lib in cfg["library"]:
        print(f"{lib['crate']}: {', '.join(lib['services']) or 'no model service (lint only)'}", file=sys.stderr)

    findings, reviews, located = [], [], set()
    for lib in cfg["library"]:
        c = Checker(model, cfg, surfaces, lib["crate"], lib.get("services", []))
        c.run()
        for f in c.findings:
            f.crates = {lib["crate"]}
        findings += c.findings
        reviews += [r for r in c.reviews if not a.crate or lib["crate"] == a.crate]
        located |= set(c.located.values())
    for f in lint(surfaces, cfg.get("lint")):
        f.crates = owners(f.id, cfg["library"], surfaces)
        findings.append(f)
    unmatched = sorted(p for crate, s in surfaces.items() for p, t in s["types"].items()
                       if p not in located and not t["name"].endswith("Builder")
                       and "::error::" not in p and (not a.crate or crate == a.crate))

    stale = apply_deviations(findings, cfg.get("deviation", []))
    proposed_scope = [dict(o, kind=k) for k in ("rename", "out_of_scope") for o in cfg.get(k, [])
                      if o.get("status") == "proposed"]
    for k in ("rename", "out_of_scope"):
        for o in cfg.get(k, []):
            base = o["shape"].split("$", 1)[0]
            if base not in model.shapes:
                stale.append({"id": f"{k}:{o['shape']}", "reason": "shape is not in the model"})
    if a.crate:
        # Deviations are matched against every crate's findings first, so an entry
        # only another crate uses is not reported stale here.
        findings = [f for f in findings if a.crate in f.crates]
        stale = [d for d in stale if a.crate in owners(d["id"], cfg["library"], surfaces)]
        proposed_scope = [o for o in proposed_scope if a.crate in owners(o["shape"], cfg["library"], surfaces)]
    ok = report(findings, stale, reviews, unmatched, proposed_scope, a.out)
    subprocess.run([sys.executable, os.path.join(HERE, "review_html.py"), a.config,
                    os.path.join(a.out, "findings.json"), os.path.join(a.out, "review.html")], check=True)
    print(open(os.path.join(a.out, "report.md")).read().split("## Open findings by check")[0])
    print(f"full report: {os.path.join(a.out, 'report.md')}", file=sys.stderr)
    sys.exit(0 if ok else 1)


if __name__ == "__main__":
    main()
