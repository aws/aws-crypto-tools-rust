#!/usr/bin/env python3
"""Check threat IDs + ratings and target IDs written in docs/mpl-bug-reports/*.md against
docs/mpl-threat-model.md (Appendix: Threat Risk Matrix, last column) and docs/mpl-verification-targets.md."""
import re, os, glob
ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))
rd = lambda p: open(os.path.join(ROOT, p)).read()
tm = rd("docs/mpl-threat-model.md")
risk = {}
for m in re.finditer(r"^\| (TM-MPL-\d{3}) \| [A-Z/]+ \| \w+ \| \w+ \| [^|]+ \| [^|]+ \| \**(\w+)\** \|", tm, re.M):
    risk[m.group(1)] = m.group(2)
print("risk rows:", len(risk))
vt = rd("docs/mpl-verification-targets.md")
targets = set(re.findall(r"\b([TC]\d\d)\b", vt))
bad = 0
docs = sorted(glob.glob(os.path.join(ROOT, "docs/mpl-bug-reports/*.md"))) + [os.path.join(ROOT, "docs/mpl-spec-security-analysis.md")]
for d in docs:
    name = os.path.basename(d)
    for ln, line in enumerate(open(d), 1):
        for m in re.finditer(r"TM-MPL-(\d{3}) \((High|Medium|Low)\b", line):
            tid = "TM-MPL-" + m.group(1)
            if tid not in risk:
                print("UNKNOWN", name, ln, tid); bad += 1
            elif risk[tid] != m.group(2):
                print("RATING", name, ln, tid, "doc", m.group(2), "tm", risk[tid]); bad += 1
        for m in re.finditer(r"TM-MPL-(\d{3})", line):
            if "TM-MPL-" + m.group(1) not in risk:
                print("UNKNOWN-ID", name, ln, m.group(0)); bad += 1
        if "VR-2026" in line or name == "README.md" or "Related targets" in line:
            for m in re.finditer(r"\b([TC]\d\d)\b", line):
                if m.group(1) not in targets:
                    print("UNKNOWN-TARGET", name, ln, m.group(1)); bad += 1
print("problems:", bad)
