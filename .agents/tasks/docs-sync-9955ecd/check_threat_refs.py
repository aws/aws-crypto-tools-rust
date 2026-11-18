#!/usr/bin/env python3
"""Check (a): threat references in the three targets docs vs docs/mpl-threat-model.md, and coverage of TM-MPL-001..026.
A threat is 'accounted for' when it appears in a YAML threat_references list of an Active target (01) or in an
out-of-scope / excluded row. Prints sets so a reviewer can read them."""
import re, os, collections
ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))
rd = lambda p: open(os.path.join(ROOT, p)).read()
tm = rd("docs/mpl-threat-model.md")
tm_ids = sorted(set(re.findall(r"TM-MPL-\d{3}", tm)))
heads = sorted(set(re.findall(r"^#{2,4}\s+(TM-MPL-\d{3})", tm, re.M)))
print("threat-model ids:", len(tm_ids), tm_ids[0], tm_ids[-1], "headings:", len(heads))
D = {"merged": "docs/mpl-verification-targets.md", "01": "docs/mpl-verification-targets/01-threat-driven.md", "02": "docs/mpl-verification-targets/02-capability-driven.md"}
allref = collections.defaultdict(set)
for k, p in D.items():
    t = rd(p)
    for m in re.finditer(r"TM-MPL-(\d+)", t):
        n = int(m.group(1))
        allref[k].add(f"TM-MPL-{n:03d}")
    # shorthand ranges like 'TM-MPL-001..024'
    print(k, "distinct refs:", len(allref[k]), "unknown (not in threat-model):", sorted(allref[k] - set(tm_ids)))
# per-target threat_references (YAML) in 01 and merged
tgt = collections.defaultdict(set)
for k in ("01", "merged"):
    t = rd(D[k])
    for b in re.finditer(r"```yaml\n(.*?)```", t, re.S):
        blk = b.group(1)
        idm = re.search(r"\bid:\s*VR-2026-(T\d+)", blk)
        if not idm: continue
        st = re.search(r"\n\s*status:\s*(\S+)", blk)
        status = st.group(1) if st else "Active"
        for r in re.findall(r"id:\s*(TM-MPL-\d+)", blk):
            tgt[(k, idm.group(1), status)].add(r)
act = collections.defaultdict(set)
for (k, tid, st), rs in tgt.items():
    if k == "01" and st == "Active":
        for r in rs: act[r].add(tid)
unk = {r for rs in tgt.values() for r in rs} - set(tm_ids)
print("YAML threat_references not in threat model:", sorted(unk))
print("threats with >=1 Active threat-driven target (01 YAML):", len(act))
missing = [i for i in tm_ids if i not in act]
print("threats without an Active 01 target:", missing)
for m in missing:
    print(" ", m, "-> mentioned in:", sorted(k for k in allref if m in allref[k]))
