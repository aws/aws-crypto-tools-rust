#!/usr/bin/env python3
"""Prose score mentions of the form 'T27 (3.78' / 'T01 (8.96)' / 'C02 (6.40, ...' in the three docs vs YAML score.
Lines that describe history (old scores: 'was', '->', '→', 'Old', 'a1e23d7', '620771c', '0.1') are listed separately."""
import re, os
ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))
P = ["docs/verification-targets.md", "docs/verification-targets/01-threat-driven.md", "docs/verification-targets/02-capability-driven.md"]
sc = {}
for p in P[1:]:
    t = open(os.path.join(ROOT, p)).read()
    for b in re.finditer(r"```yaml\n(.*?)```", t, re.S):
        m = re.search(r"\bid:\s*VR-2026-([TC]\d+)", b.group(1))
        s = re.search(r"priority_score:\s*([0-9.]+)", b.group(1))
        if m and s and not re.search(r"status:\s*Retired", b.group(1)): sc[m.group(1)] = s.group(1)
hist = re.compile(r"was |→|->|Old |old |previous|a1e23d7|620771c|before|from \d")
bad = []; hist_hits = []; n = 0
for p in P:
    sec01 = False
    for ln, line in enumerate(open(os.path.join(ROOT, p)), 1):
        for m in re.finditer(r"\b([TC]\d{2})\s*\((\d\.\d\d)\b", line):
            n += 1
            if sc.get(m.group(1)) != m.group(2):
                (hist_hits if hist.search(line) else bad).append((p.split("/")[-1], ln, m.group(1), m.group(2), sc.get(m.group(1))))
print("mentions checked:", n, "mismatching:", len(bad), "mismatching on history lines:", len(hist_hits))
for b in bad: print("  BAD", b)
for b in hist_hits: print("  hist", b)
