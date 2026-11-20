#!/usr/bin/env python3
"""Checks 4, 7, 9: capability_reference present; ID stability vs HEAD; merged YAML block count and origins."""
import re, os, subprocess
ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))
P = {"01": "docs/mpl-verification-targets/01-threat-driven.md", "02": "docs/mpl-verification-targets/02-capability-driven.md", "merged": "docs/mpl-verification-targets.md"}
def blocks(text):
    out = {}
    for b in re.finditer(r"```yaml\n(.*?)```", text, re.S):
        blk = b.group(1); m = re.search(r"\bid:\s*VR-2026-([TC]\d+)", blk)
        if m: out[m.group(1)] = blk
    return out
now = {k: blocks(open(os.path.join(ROOT, p)).read()) for k, p in P.items()}
def _show(p):
    o = subprocess.run(["git", "-C", ROOT, "show", "HEAD:" + p], capture_output=True, text=True).stdout
    # before the docs/mpl-* rename is committed, HEAD still has the old path
    return o or subprocess.run(["git", "-C", ROOT, "show", "HEAD:" + p.replace("docs/mpl-", "docs/", 1)], capture_output=True, text=True).stdout
head = {k: blocks(_show(p)) for k, p in P.items()}
bad = []
# check 4
for k in ("02", "merged"):
    for tid, blk in now[k].items():
        if tid[0] != "C" or re.search(r"status:\s*Retired", blk): continue
        cat = re.search(r"capability_reference:\s*\n?\s*(?:category:\s*(\d)|\{[^}]*category:\s*(\d))", blk)
        inv = re.search(r"invariant:\s*(\S.*)", blk)
        ok = re.search(r"capability_reference", blk) and re.search(r"category", blk) and inv
        print("check4", k, tid, "capability_reference" in blk, "category" in blk, bool(inv))
        if not ok: bad.append(f"{k} {tid}: capability_reference incomplete")
# check 7
print("check7 HEAD ids:", {k: sorted(v) for k, v in head.items() if k != "merged"})
for k in ("01", "02"):
    h, n = set(head[k]), set(now[k])
    print("check7", k, "removed vs HEAD:", sorted(h - n), "added vs HEAD:", sorted(n - h))
    if h - n: bad.append(f"{k}: IDs removed {sorted(h-n)}")
    for tid in sorted(h & n):
        def key(blk):
            f = re.search(r"\n\s*file:\s*(.+)", blk); st = re.search(r"\n\s*status:\s*(\S+)", blk)
            return (f.group(1).strip()[:60] if f else None, st.group(1) if st else "Active")
        if key(head[k][tid]) != key(now[k][tid]): print("   file/status changed:", k, tid, key(head[k][tid]), "->", key(now[k][tid]))
for tid in ("T08", "C06"):
    for k in ("01", "02"):
        if tid in now[k]:
            print("check7 retired block present", k, tid, bool(re.search(r"status:\s*Retired", now[k][tid])), "reason" in now[k][tid] or "retired_reason" in now[k][tid])
# check 9
m = now["merged"]
orig = {t: (re.search(r"origin:\s*(\S+)", b).group(1)) for t, b in m.items()}
print("check9 merged blocks:", len(m), "origins:", {o: sorted(t for t, x in orig.items() if x == o) for o in set(orig.values())})
if len(m) < 5 or len(set(orig.values())) < 2: bad.append("merged YAML blocks < 5 or one origin")
print("PROBLEMS:" if bad else "PROBLEMS: none")
for b in bad: print("  -", b)
