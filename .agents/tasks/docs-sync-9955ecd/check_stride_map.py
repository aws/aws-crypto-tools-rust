#!/usr/bin/env python3
"""Cross-check: 01 section 6 threat->targets table and merged section 4 STRIDE table vs the threat_references of the
Active threat-driven YAML blocks in 01, and vs the threat model's STRIDE letters (primary = first letter)."""
import re, os, collections
ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))
rd = lambda p: open(os.path.join(ROOT, p)).read()
d01 = rd("docs/verification-targets/01-threat-driven.md"); dm = rd("docs/verification-targets.md"); tm = rd("docs/threat-model.md")
score = {}
t2 = collections.defaultdict(set)
for b in re.finditer(r"```yaml\n(.*?)```", d01, re.S):
    blk = b.group(1); m = re.search(r"\bid:\s*VR-2026-(T\d+)", blk)
    if not m or re.search(r"\n\s*status:\s*Retired", blk): continue
    ps = re.search(r"priority_score:\s*([0-9.]+)", blk); score[m.group(1)] = float(ps.group(1))
    for r in re.findall(r"id:\s*(TM-MPL-\d+)", blk): t2[r].add(m.group(1))
bad = 0
sec6 = d01[d01.index("## 6. Accounting"):]
for m in re.finditer(r"^\| (TM-MPL-\d{3}) \| [^|]+\| ([^|]+)\|", sec6, re.M):
    ids = set(re.findall(r"T\d{2}", m.group(2).replace("T08 retired", "")))
    if ids != t2.get(m.group(1), set()):
        print("01 s6 map differs:", m.group(1), sorted(ids), "YAML", sorted(t2.get(m.group(1), set()))); bad += 1
# STRIDE
letters = {"S": "Spoofing", "T": "Tampering", "R": "Repudiation", "I": "Information Disclosure", "D": "Denial of Service", "E": "Elevation of Privilege"}
cat = {}
for m in re.finditer(r"^\| (TM-MPL-\d{3}) \| ([A-Z/]+) \| \**\w+\** \| \**\w+\** \|", tm, re.M):
    cat[m.group(1)] = m.group(2)
# threat-model section 7 lists the STRIDE category of each threat: read its table
for m in re.finditer(r"^\| (TM-MPL-\d{3}) \|[^\n]*$", tm[tm.index("STRIDE"):], re.M): pass
rows = re.findall(r"^\| (Spoofing|Tampering|Repudiation|Information Disclosure|Denial of Service|Elevation of Privilege) \| (\d+) \(([^)]*)\) \| (\d+) \| (\d+) \| (\d+)(?: \([^)]*\))? \| ([^|]*)\|", dm, re.M)
tot = 0
for name, n, ids, ver, withT, excl, tg in rows:
    idl = ["TM-MPL-" + x.strip() for x in ids.split(",")]
    tot += len(idl)
    if len(idl) != int(n): print("count mismatch", name); bad += 1
    got = set()
    for i in idl: got |= t2.get(i, set())
    listed = set(re.findall(r"T\d{2}", tg))
    wt = sum(1 for i in idl if t2.get(i))
    if got != listed: print("STRIDE targets differ:", name, "listed", sorted(listed), "YAML", sorted(got)); bad += 1
    if wt != int(withT) or len(idl) - wt != int(excl): print("with/excl differ:", name, wt, excl); bad += 1
    # categories from threat model appendix (first letter)
    for i in idl:
        L = cat[i].split("/")[0]
        if letters[L] != name: print("category differs from threat-model appendix:", i, cat[i], "doc", name); bad += 1
print("STRIDE rows", len(rows), "threats", tot, "problems", bad)
