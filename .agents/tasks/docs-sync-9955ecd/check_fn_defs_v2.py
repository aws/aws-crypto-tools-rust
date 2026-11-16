#!/usr/bin/env python3
"""Second citation pass: name-anchored check.

For every `NAME ... :LINE` where NAME (the identifier written immediately before
the line reference) is defined somewhere in mpl/, prim/, esdk/ as a fn / struct /
enum / trait / const / macro, check that one of its definitions sits within +-3
lines of LINE. Prints DEF-OK / DEF-MISMATCH lines; names with no definition are
skipped (they are prose words, not code names).
"""
import os, re, subprocess

ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))
DOCS = [
    "docs/spec-security-analysis.md",
    "docs/threat-model.md",
    "docs/verification-targets.md",
    "docs/verification-targets/01-threat-driven.md",
    "docs/verification-targets/02-capability-driven.md",
    "docs/verification-targets/04-validation.md",
]
files = [f for f in subprocess.run(["git", "-C", ROOT, "ls-files", "mpl", "prim", "esdk"],
         capture_output=True, text=True).stdout.split() if f.endswith(".rs")]
defs = {}
DEF_RE = re.compile(r"^\s*(?:pub(?:\([a-z]+\))?\s+)?(?:async\s+)?(?:unsafe\s+)?(?:const\s+)?(?:fn|struct|enum|trait|const|static|type|macro_rules!)\s*([A-Za-z_][A-Za-z0-9_]*)")
for f in files:
    for i, l in enumerate(open(os.path.join(ROOT, f), errors="replace"), 1):
        m = DEF_RE.match(l)
        if m:
            defs.setdefault(m.group(1), []).append((f, i))

# NAME then up to a few non-word chars, then optional file.rs, then :LINE
PAT = re.compile(r"([A-Za-z_][A-Za-z0-9_]{3,})`?\)?(?:\s*\(|\s+`?|`\s*\(`?|\s*`\s*`?)(?:[A-Za-z0-9_./-]+\.rs)?:(\d+)")
ok = bad = 0
for doc in DOCS:
    for ln, line in enumerate(open(os.path.join(os.environ.get("DOCROOT", ROOT), doc)), 1):
        for m in PAT.finditer(line):
            name, n = m.group(1), int(m.group(2))
            if name not in defs:
                continue
            locs = defs[name]
            if any(abs(i - n) <= 3 for _, i in locs):
                ok += 1
            else:
                bad += 1
                print(f"DEF-MISMATCH\t{doc}:{ln}\t{name} cited :{n}\tdefined at {', '.join(f'{f}:{i}' for f, i in locs[:4])}")
print(f"SUMMARY\tdef-ok={ok}\tdef-mismatch={bad}")
