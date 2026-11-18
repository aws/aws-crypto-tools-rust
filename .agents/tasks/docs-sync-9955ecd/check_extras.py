#!/usr/bin/env python3
"""Check (c) extras not covered by check_scores.py: quick_win flags and effort, merged section 5 list, agent totals,
rank claims in the merged refresh section, relative order of the T-only (01) and C-only (02) ranked tables."""
import re, os
from decimal import Decimal
ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))
rd = lambda p: open(os.path.join(ROOT, p)).read()
P = {"01": "docs/mpl-verification-targets/01-threat-driven.md", "02": "docs/mpl-verification-targets/02-capability-driven.md", "merged": "docs/mpl-verification-targets.md"}
T = {k: rd(p) for k, p in P.items()}
blocks = {}
for k in P:
    for b in re.finditer(r"```yaml\n(.*?)```", T[k], re.S):
        blk = b.group(1); m = re.search(r"\bid:\s*VR-2026-([TC]\d+)", blk)
        if not m: continue
        if re.search(r"\n\s*status:\s*Retired", blk): continue
        ps = Decimal(re.search(r"priority_score:\s*([0-9.]+)", blk).group(1))
        eff = re.search(r"estimated_effort:\s*(.+)", blk).group(1).strip()
        qw = re.search(r"quick_win:\s*(true|false)", blk)
        ag = re.search(r"\n\s*agent:\s*(\S+)", blk)
        blocks[(k, m.group(1))] = dict(score=ps, effort=eff, qw=qw.group(1) if qw else None, agent=ag.group(1) if ag else None)
def short(eff):
    m = re.match(r"(\d+)\s*(day|week|month)", eff)
    n, u = int(m.group(1)), m.group(2)
    return n * {"day": 1, "week": 7, "month": 30}[u] <= 7
bad = []
for (k, tid), r in blocks.items():
    exp = r["score"] > Decimal("6.0") and short(r["effort"])
    if r["qw"] is not None and (r["qw"] == "true") != exp:
        bad.append(f"{k} {tid}: quick_win {r['qw']} but score {r['score']} effort {r['effort']}")
    if r["qw"] is None: bad.append(f"{k} {tid}: no quick_win flag")
src = {tid: r for (k, tid), r in blocks.items() if k in ("01", "02")}
qs = sorted(t for t, r in src.items() if r["score"] > Decimal("6.0") and short(r["effort"]))
sec5 = T["merged"].split("## 5. Quick wins")[1].split("## 6.")[0]
listed = sorted(re.findall(r"VR-2026-([TC]\d+)", "\n".join(l for l in sec5.split("\n") if l.startswith("|"))))
print("quick wins computed:", qs, "listed in merged s5:", listed)
if qs != listed: bad.append("quick-win list differs")
# 01 / 02 quick-win mention
for k in ("01", "02"):
    for m in re.finditer(r"[Qq]uick wins?[^\n]*", T[k]): pass
ag = {}
for t, r in src.items(): ag[r["agent"]] = ag.get(r["agent"], 0) + 1
print("agent totals:", ag, "total", sum(ag.values()))
mt = re.search(r"mpl-verus-header-parsing-proofs ×(\d+), mpl-verus-zero-panic ×(\d+)[^,]*, mpl-verus-unsafe-ffi-safety ×(\d+)", T["merged"])
if mt: 
    got = tuple(int(x) for x in mt.groups())
    exp = (ag.get("mpl-verus-header-parsing-proofs", 0), ag.get("mpl-verus-zero-panic", 0), ag.get("mpl-verus-unsafe-ffi-safety", 0))
    print("merged refresh agent claim", got, "computed", exp)
    if got != exp: bad.append("agent totals differ")
sec1 = T["merged"].split("## 1. Combined ranked summary")[1].split("## 2.")[0]
rank = {t: int(r) for r, s, o, t in re.findall(r"^\| (\d+) \| ([0-9.]+) \| ([TC]) \| ([TC]\d+)", sec1, re.M)}
claims = {"T27": 14, "T14": 13, "T26": 15, "T25": 30, "C08": 33, "T16": 22, "T21": 23, "T02": 2}
for t, n in claims.items():
    if rank.get(t) != n: bad.append(f"merged s1 rank {t} = {rank.get(t)}, refresh text says {n}")
print("merged s1 ranks:", len(rank), "max", max(rank.values()))
# relative order in 01 and 02 ranked tables vs merged order
for k, pref in (("01", "T"), ("02", "C")):
    tb = re.findall(r"^\| (\d+) \| VR-2026-([TC]\d+) \| ([0-9.]+) \|", T[k], re.M)
    ids = [t for r, t, s in tb]
    exp = sorted(ids, key=lambda t: rank[t])
    print(k, "ranked table rows:", len(ids), "order matches merged:", ids == exp, "rank col sequential:", [int(r) for r, t, s in tb] == list(range(1, len(ids) + 1)))
    if ids != exp: bad.append(f"{k} ranked order differs from merged")
    if [int(r) for r, t, s in tb] != list(range(1, len(ids) + 1)): bad.append(f"{k} rank column not sequential")
    # all active IDs of this origin present
    act = sorted(t for (kk, t) in blocks if kk == k)
    if sorted(ids) != act: bad.append(f"{k} ranked table ids {sorted(set(act)^set(ids))} differ from YAML")
m = re.search(r"T27 is inserted at rank (\d+)", T["01"])
if m:
    tb = re.findall(r"^\| (\d+) \| VR-2026-(T\d+) \|", T["01"], re.M)
    pos = {t: int(r) for r, t in tb}
    print("01 claims T27 at rank", m.group(1), "table has", pos.get("T27"))
    if pos.get("T27") != int(m.group(1)): bad.append("01 T27 rank claim")
print("PROBLEMS:" if bad else "PROBLEMS: none")
for b in bad: print("  -", b)
