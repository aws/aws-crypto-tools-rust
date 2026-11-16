#!/usr/bin/env python3
"""Score / consistency check for the verification-target docs.

Parses every YAML `recommendation:` block in 01, 02 and the merged doc
(id, priority_score, top-level coverage_gap, scoring factors, product string,
status) plus the ranked tables (merged §1, 01 §1, 02 §1) and the merged §3 gap
table, recomputes S x G x F x B and reports every inconsistency.
"""
import os, re
from decimal import Decimal, ROUND_HALF_UP

ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))
D = {
    "merged": "docs/verification-targets.md",
    "01": "docs/verification-targets/01-threat-driven.md",
    "02": "docs/verification-targets/02-capability-driven.md",
}
problems = []
blocks = {k: {} for k in D}

def r2(x):
    return Decimal(str(x)).quantize(Decimal("0.01"), rounding=ROUND_HALF_UP)

for k, p in D.items():
    text = open(os.path.join(ROOT, p)).read()
    for m in re.finditer(r"```yaml\n(.*?)```", text, re.S):
        b = m.group(1)
        idm = re.search(r"\bid:\s*VR-2026-([TC]\d+)", b)
        if not idm:
            continue
        tid = idm.group(1)
        rec = {"raw": b}
        st = re.search(r"\n\s*status:\s*(\S+)", b)
        rec["status"] = st.group(1) if st else "Active"
        ps = re.search(r"priority_score:\s*([0-9.]+)", b)
        rec["score"] = Decimal(ps.group(1)) if ps else None
        top_gap = re.search(r"\n  coverage_gap:\s*([0-9.]+)", b)
        rec["top_gap"] = Decimal(top_gap.group(1)) if top_gap else None
        # scoring: inline {...} or block form
        sc = re.search(r"scoring:\s*\{([^}]*)\}", b)
        sblock = sc.group(1) if sc else (re.search(r"scoring:\n((?:\s{4,}.*\n?)+)", b).group(1) if re.search(r"scoring:\n", b) else "")
        f = {}
        for key in ("severity", "coverage_gap", "feasibility", "blast_radius"):
            mm = re.search(key + r":\s*([0-9.]+)", sblock)
            f[key] = Decimal(mm.group(1)) if mm else None
        rec["factors"] = f
        prod = re.search(r'product:\s*"([^"]*)"', sblock)
        rec["product"] = prod.group(1) if prod else None
        blocks[k][tid] = rec

for k, bs in blocks.items():
    for tid, rec in bs.items():
        if rec["status"].lower().startswith("retired"):
            continue
        f = rec["factors"]
        if None in f.values():
            problems.append(f"{k} {tid}: missing factor {f}")
            continue
        calc = r2(f["severity"] * f["coverage_gap"] * f["feasibility"] * f["blast_radius"])
        if rec["score"] != calc:
            problems.append(f"{k} {tid}: priority_score {rec['score']} != computed {calc}")
        if rec["top_gap"] is not None and rec["top_gap"] != f["coverage_gap"]:
            problems.append(f"{k} {tid}: top-level coverage_gap {rec['top_gap']} != scoring {f['coverage_gap']}")
        if rec["product"]:
            nums = re.findall(r"[0-9.]+", rec["product"])
            if len(nums) >= 5:
                a = [Decimal(n) for n in nums[:4]]
                if a != [f["severity"], f["coverage_gap"], f["feasibility"], f["blast_radius"]] or Decimal(nums[4]) != calc:
                    problems.append(f"{k} {tid}: product string '{rec['product']}' disagrees with factors/score {calc}")

# cross-doc: merged YAML vs 01/02 YAML
for tid, rec in blocks["merged"].items():
    src = blocks["01" if tid.startswith("T") else "02"].get(tid)
    if not src:
        problems.append(f"merged {tid}: no block in 01/02")
        continue
    if src["factors"] != rec["factors"] or src["score"] != rec["score"]:
        problems.append(f"merged {tid}: factors/score differ from source ({rec['factors']} {rec['score']} vs {src['factors']} {src['score']})")

# tables
merged = open(os.path.join(ROOT, D["merged"])).read()
sec1 = merged.split("## 1. Combined ranked summary")[1].split("## 2.")[0]
rows = re.findall(r"^\| (\d+|—) \| ([0-9.]+|Retired) \| ([TC]) \| ([TC]\d+)", sec1, re.M)
table_scores = {}
for rank, score, origin, tid in rows:
    table_scores[tid] = (rank, score)
src_all = {**blocks["01"], **blocks["02"]}
active_src = {t: r for t, r in src_all.items() if not r["status"].lower().startswith("retired")}
for tid, r in active_src.items():
    if tid not in table_scores:
        problems.append(f"merged §1: active {tid} missing")
    elif table_scores[tid][1] == "Retired" or Decimal(table_scores[tid][1]) != r["score"]:
        problems.append(f"merged §1: {tid} score {table_scores[tid][1]} != source {r['score']}")
for tid, (rank, score) in table_scores.items():
    if tid not in src_all:
        problems.append(f"merged §1: {tid} not in 01/02")
    elif score == "Retired" and not src_all[tid]["status"].lower().startswith("retired"):
        problems.append(f"merged §1: {tid} marked Retired but source active")
# rank order: score desc, severity desc, T before C, id
act = [(tid, Decimal(s), int(rk)) for rk, s, o, tid in rows if s != "Retired"]
def key(t):
    tid = t[0]
    sev = active_src[tid]["factors"]["severity"] if tid in active_src else 0
    return (-t[1], -sev, 0 if tid[0] == "T" else 1, int(tid[1:]))
exp = sorted(act, key=key)
for i, (e, a) in enumerate(zip(exp, act), 1):
    if e[0] != a[0] or a[2] != i:
        problems.append(f"merged §1 rank {i}: expected {e[0]} got {a[0]} (rank col {a[2]})")

# merged YAML rank field vs table
for tid, rec in blocks["merged"].items():
    rk = re.search(r"rank:\s*(\d+)", rec["raw"])
    if rk and table_scores.get(tid, ("?",))[0] != rk.group(1):
        problems.append(f"merged §2 {tid}: rank {rk.group(1)} != §1 rank {table_scores.get(tid)}")

# per-file ranked tables in 01 / 02
for k in ("01", "02"):
    t = open(os.path.join(ROOT, D[k])).read()
    for rank, tid, score in re.findall(r"^\| (\d+) \| VR-2026-([TC]\d+) \| ([0-9.]+) \|", t, re.M):
        rec = blocks[k].get(tid)
        if not rec:
            problems.append(f"{k} table: {tid} has no YAML block")
        elif Decimal(score) != rec["score"]:
            problems.append(f"{k} table: {tid} {score} != YAML {rec['score']}")

# merged §3 gap table
sec3 = merged.split("## 3. Coverage-gap analysis")[1].split("## 4.")[0]
gaps = dict(re.findall(r"^\| ([TC]\d+) \| [^|]* \| ([0-9.]+) \|", sec3, re.M))
for tid, r in active_src.items():
    if tid not in gaps:
        problems.append(f"merged §3: {tid} missing")
    elif Decimal(gaps[tid]) != r["factors"]["coverage_gap"]:
        problems.append(f"merged §3: {tid} gap {gaps[tid]} != YAML {r['factors']['coverage_gap']}")
for tid in gaps:
    if tid not in active_src:
        problems.append(f"merged §3: {tid} listed but not active")

print(f"yaml blocks: 01={len(blocks['01'])} 02={len(blocks['02'])} merged={len(blocks['merged'])}")
print("active:", " ".join(sorted(active_src, key=lambda t: (t[0], int(t[1:])))))
print("retired:", " ".join(sorted((t for t in src_all if t not in active_src), key=lambda t: (t[0], int(t[1:])))))
print(f"merged §1 rows: {len(rows)}  §3 rows: {len(gaps)}")
for tid, r in sorted(active_src.items(), key=lambda kv: -kv[1]['score']):
    f = r["factors"]
    print(f"  {tid}: {f['severity']} x {f['coverage_gap']} x {f['feasibility']} x {f['blast_radius']} = {r2(f['severity']*f['coverage_gap']*f['feasibility']*f['blast_radius'])} (doc {r['score']})")
print("PROBLEMS:" if problems else "PROBLEMS: none")
for p in problems:
    print("  -", p)
