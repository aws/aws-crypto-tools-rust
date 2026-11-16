#!/usr/bin/env python3
"""Ratings check: threat-model appendix (Severity, Likelihood) vs 01 section 6 table vs the YAML severity / feasibility
of every active threat-driven target (primary threat = first threat_references id) in 01 and merged doc."""
import re, os
ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))
rd = lambda p: open(os.path.join(ROOT, p)).read()
tm = rd("docs/threat-model.md")
R = {}
for m in re.finditer(r"^\| (TM-MPL-\d{3}) \| ([A-Z/]+) \| \**(\w+)\** \| \**(\w+)\** \|", tm, re.M):
    R[m.group(1)] = (m.group(3), m.group(4))
print("appendix rows:", len(R))
bad = 0
doc01 = rd("docs/verification-targets/01-threat-driven.md")
sec6 = doc01[doc01.index("## 6. Accounting"):]
for m in re.finditer(r"^\| (TM-MPL-\d{3}) \| \**(\w+)\**(?: / | /\s*)\**(\w+)\**", sec6, re.M):
    if R.get(m.group(1)) != (m.group(2), m.group(3)):
        print("01 s6 differs:", m.group(1), (m.group(2), m.group(3)), "appendix", R.get(m.group(1))); bad += 1
SEV = {"Critical": 4, "High": 3, "Medium": 2, "Low": 1}
LIK = {"Low": 0.4, "Medium": 0.7, "High": 1.0}
n = 0
for k, p in (("01", "docs/verification-targets/01-threat-driven.md"), ("merged", "docs/verification-targets.md")):
    for b in re.finditer(r"```yaml\n(.*?)```", rd(p), re.S):
        blk = b.group(1)
        idm = re.search(r"\bid:\s*VR-2026-(T\d+)", blk)
        if not idm or re.search(r"\n\s*status:\s*Retired", blk): continue
        sc = re.search(r"scoring:\s*\{severity:\s*(\d+),\s*coverage_gap:\s*([0-9.]+),\s*feasibility:\s*([0-9.]+)", blk)
        if not sc:
            sc2 = re.search(r"scoring:\s*\n\s*severity:\s*(\d+)[^\n]*\n\s*coverage_gap:\s*([0-9.]+)[^\n]*\n\s*feasibility:\s*([0-9.]+)", blk)
            sc = sc2
        refs = re.findall(r"id:\s*(TM-MPL-\d+)", blk)
        if not sc or not refs: print(k, idm.group(1), "no scoring/refs parsed"); bad += 1; continue
        sev, fe = int(sc.group(1)), float(sc.group(3))
        prim = refs[0]
        es, el = R[prim]
        n += 1
        ok = SEV[es] == sev and abs(LIK[el] - fe) < 1e-9
        # severity: a target may cite several threats; accept if equal to the primary's
        if not ok:
            print(k, idm.group(1), "primary", prim, "appendix", (es, el), "yaml S/F", sev, fe); bad += 1
print("targets checked:", n, "mismatches:", bad)
