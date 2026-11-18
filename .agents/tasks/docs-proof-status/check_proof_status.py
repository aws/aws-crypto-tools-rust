#!/usr/bin/env python3
"""Checks for the proof-status documentation run.
1. Canonical status strings present where required.
2. Ranked tables and YAML blocks in the three targets docs equal HEAD apart from the added column / fields (no score, rank, gap, quick-win change).
3. Every "N verified, M errors" mention in the docs is one of the five real result lines.
4. Proof files exist at cited paths (and, with --rerun, the live result line matches).
5. No code / proof / log / RECHECK change (git diff --quiet).
"""
import os, re, subprocess, sys
ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))
Q = "model level, not the shipped code, under stated hypotheses"
RES = {"T02": "21 verified, 1 errors", "C01": "40 verified, 0 errors", "C02": "21 verified, 0 errors",
       "T03": "39 verified, 0 errors", "T05": "33 verified, 0 errors"}
PS = {k: f"{'Partly proved' if k == 'T02' else 'Proved'} ({Q}): {v}" for k, v in RES.items()}
FILES = {"T02": "t02_record_reconstruction", "C01": "c01_ec_roundtrip", "C02": "c02_sign_fixed_len",
         "T03": "t03_resolve_pinned_arn", "T05": "t05_kbkdf_fixed_info"}
T = {"merged": "docs/mpl-verification-targets.md", "01": "docs/mpl-verification-targets/01-threat-driven.md",
     "02": "docs/mpl-verification-targets/02-capability-driven.md"}
problems = []
def read(p): return open(os.path.join(ROOT, p)).read()
def head(p):
    o = subprocess.run(["git", "-C", ROOT, "show", "HEAD:" + p], capture_output=True, text=True).stdout
    # after the docs/mpl-* rename the old HEAD path may be the one that exists
    return o or subprocess.run(["git", "-C", ROOT, "show", "HEAD:" + p.replace("docs/mpl-", "docs/", 1)], capture_output=True, text=True).stdout

# 1 canonical strings in targets docs
need = {"merged": ["T02", "C01", "C02", "T03", "T05"], "01": ["T02", "T03", "T05"], "02": ["C01", "C02"]}
for k, ids in need.items():
    t = read(T[k])
    for i in ids:
        n = t.count(PS[i])
        # YAML field, table cell, Proofs-written list
        if n != 3:
            problems.append(f"{k} {i}: canonical status string occurs {n} times (expected 3: YAML, table, list)")
        if f"proof_file: verus-proofs/{FILES[i]}.rs" not in t:
            problems.append(f"{k} {i}: proof_file missing")
        if f"`verification results:: {RES[i]}`" not in t:
            problems.append(f"{k} {i}: full result line missing in Proofs written table")

# 2 tables and YAML equal HEAD apart from additions
def table_rows(t):
    return [l for l in t.split("\n") if re.match(r"^\| (\d+|—) \| ", l)]
def strip_last(l):
    return l[: l.rstrip().rstrip("|").rstrip().rfind("|") + 1].rstrip()
for k, p in T.items():
    new, old = read(p), head(p)
    nr, orr = table_rows(new), table_rows(old)
    # only the ranked tables (rows with Proof status suffix) change
    changed = [r for r in nr if r not in orr]
    stripped_ok = 0
    for r in changed:
        base = strip_last(r)
        if base in orr:
            stripped_ok += 1
        else:
            problems.append(f"{k}: table row changed beyond the added column: {r[:90]}")
    # YAML
    ny = re.findall(r"```yaml\n(.*?)```", new, re.S)
    oy = re.findall(r"```yaml\n(.*?)```", old, re.S)
    if len(ny) != len(oy):
        problems.append(f"{k}: YAML block count {len(ny)} != {len(oy)}")
    for a, b in zip(ny, oy):
        a2 = "\n".join(l for l in a.split("\n") if not re.match(r"\s*proof_(status|file):", l))
        if a2.strip("\n") != b.strip("\n"):
            idm = re.search(r"id:\s*(\S+)", b).group(1)
            problems.append(f"{k}: YAML block {idm} differs from HEAD beyond proof_status/proof_file")
    # every block has proof_status
    miss = [re.search(r"id:\s*(\S+)", a).group(1) for a in ny if "proof_status:" not in a]
    if miss:
        problems.append(f"{k}: YAML blocks without proof_status: {miss}")
    print(f"{k}: ranked rows with Proof status column: {stripped_ok}; YAML blocks: {len(ny)}")

# 3 any 'N verified, M errors' in docs must be a real line
DOCS = [T["merged"], T["01"], T["02"], "docs/mpl-verification-targets/04-validation.md", "docs/mpl-threat-model.md",
        "docs/mpl-completeness-audit.md", "docs/mpl-spec-security-analysis.md", "docs/chorus/MPL-Threat-Model.md",
        "docs/chorus/MPL-Bug-Reports.md", "docs/mpl-bug-reports/README.md"]
import glob
DOCS += [os.path.relpath(p, ROOT) for p in glob.glob(os.path.join(ROOT, "docs/mpl-bug-reports/BUG-*.md"))]
valid = set(RES.values())
for p in DOCS:
    if not os.path.exists(os.path.join(ROOT, p)):
        problems.append(f"missing doc {p}")
        continue
    for ln, l in enumerate(read(p).split("\n"), 1):
        for m in re.finditer(r"(\d+) verified, (\d+) errors", l):
            if m.group(0) not in valid:
                problems.append(f"{p}:{ln}: unknown result line '{m.group(0)}'")
        # status word without qualifier on a line that gives a result line
        for i, r in RES.items():
            if r in l and "model level" not in l and "verification results::" not in l:
                problems.append(f"{p}:{ln}: result line {r} without 'model level' qualifier on the same line")


# 3b required canonical status per document
import glob as _g
REQ = {
    "docs/mpl-threat-model.md": ["T02", "C01", "C02", "T03", "T05"],
    "docs/chorus/MPL-Threat-Model.md": ["T02", "C01", "C02", "T03", "T05"],
    "docs/mpl-completeness-audit.md": ["T02"],
    "docs/mpl-spec-security-analysis.md": ["T02", "T03", "T05"],
    "docs/chorus/MPL-Bug-Reports.md": ["C01"],
    "docs/mpl-bug-reports/BUG-08-build-base-collision-branch-unreachable.md": ["C01"],
}
for p, ids in REQ.items():
    t = read(p)
    for i in ids:
        if PS[i] not in t:
            problems.append(f"{p}: canonical status string for {i} missing")
# findings present
FIND = {
    "docs/mpl-threat-model.md": ["G1", "O1", "O2", "F1", "A_ITER"],
    "docs/chorus/MPL-Threat-Model.md": ["G1", "O1", "O2", "F1", "A_ITER"],
    "docs/mpl-completeness-audit.md": ["Confirmed formally by the T02 proof"],
    "docs/mpl-spec-security-analysis.md": ["G1", "O1", "O2", "F1"],
    "docs/chorus/MPL-Bug-Reports.md": ["A_ITER", "Formal check (C01)"],
    "docs/mpl-bug-reports/BUG-08-build-base-collision-branch-unreachable.md": ["A_ITER", "Formal check (C01)"],
    "docs/mpl-verification-targets.md": ["G1", "O1", "O2", "F1", "A_ITER", "copy_from_slice"],
    "docs/mpl-verification-targets/01-threat-driven.md": ["G1", "O1", "O2", "F1"],
    "docs/mpl-verification-targets/02-capability-driven.md": ["A_ITER", "copy_from_slice"],
}
for p, keys in FIND.items():
    t = read(p)
    for k in keys:
        if k not in t:
            problems.append(f"{p}: finding marker '{k}' missing")
# format: no html tags / emoji / footnotes / unbalanced fences in changed md
import subprocess as _sp
changed = [l[3:].split(" -> ")[-1] for l in _sp.run(["git", "-C", ROOT, "status", "--short"], capture_output=True, text=True).stdout.split("\n") if l.strip().endswith(".md") and l[3:].split(" -> ")[-1].startswith("docs/")]
for p in changed:
    t = read(p)
    if t.count("```") % 2:
        problems.append(f"{p}: unbalanced code fences")
    body = re.sub(r"```.*?```", "", t, flags=re.S)
    body = re.sub(r"`[^`\n]*`", "", body)
    if re.search(r"</?[a-zA-Z][^>]*>", body):
        problems.append(f"{p}: HTML tag outside code")
    if re.search(r"\[\^[^\]]+\]", body):
        problems.append(f"{p}: footnote marker")
    if re.search("[\U0001F300-\U0001FAFF\u2600-\u27BF]", body):
        problems.append(f"{p}: emoji")
    if "mermaid" in t.lower():
        problems.append(f"{p}: mermaid")
print("format-checked md files:", len(changed))

# 4 files exist
for i, f in FILES.items():
    if not os.path.exists(os.path.join(ROOT, "verus-proofs", f + ".rs")):
        problems.append(f"{i}: proof file missing")
for p in DOCS:
    t = read(p) if os.path.exists(os.path.join(ROOT, p)) else ""
    for m in re.finditer(r"verus-proofs/([A-Za-z0-9_.-]+)", t):
        n = m.group(1).rstrip(".,)`")
        if n and not os.path.exists(os.path.join(ROOT, "verus-proofs", n)) and "<" not in n:
            problems.append(f"{p}: cited proof path verus-proofs/{n} missing")
if "--rerun" in sys.argv:
    for i, f in FILES.items():
        out = subprocess.run([os.path.expanduser("~/verus/verus"), f"verus-proofs/{f}.rs"], cwd=ROOT, capture_output=True, text=True).stdout
        m = re.search(r"verification results:: (\d+ verified, \d+ errors)", out)
        got = m.group(1) if m else None
        print(f"rerun {i}: {got}")
        if got != RES[i]:
            problems.append(f"{i}: re-run gives {got}, expected {RES[i]}")

# 5 diff guard
r = subprocess.run(["git", "-C", ROOT, "diff", "--quiet", "HEAD", "--", "mpl", "prim", "esdk", "verus-proofs", "docs/mpl-bug-reports/RECHECK-main-620771c.md"])
print("git diff --quiet HEAD -- mpl prim esdk verus-proofs RECHECK: exit", r.returncode)
if r.returncode:
    problems.append("forbidden paths changed")
st = subprocess.run(["git", "-C", ROOT, "status", "--short"], capture_output=True, text=True).stdout.split("\n")
for l in st:
    if l.strip() and not (l[3:].split(" -> ")[-1].startswith("docs/") or l[3:].startswith(".agents/tasks/docs-proof-status")):
        problems.append(f"status outside docs/ and notes: {l}")
print("PROBLEMS:" if problems else "PROBLEMS: none")
for p in problems:
    print("  -", p)
