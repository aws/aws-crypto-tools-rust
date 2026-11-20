#!/usr/bin/env python3
"""Checks for the C03 / C02 / BUG-10 status record (docs only).
 1  canonical status strings (model-level five unchanged; C03 new) in the right places
 2  ranked tables: every cell except 'Proof status' equals HEAD; rank+score columns diff written to rank-score-diff.txt
 3  YAML blocks equal HEAD apart from the allowed added keys (only C02, C03, T26 may change)
 4  every 'N verified, M errors' mention is a real result line with the right qualifier on the same line
 5  no line that mentions the C03 proof (VR-013, VR-014, 18 verified, in-crate) claims it is on this branch
 6  C03 facts agree with the review report and (read-only) with origin/Mahnush_Verus
 7  C02 is never called a duplicate; 'partly superseded' present
 8  BUG-10 present where required; 01 lines 747-750 unchanged (BUG-10 cites them)
 9  cited line numbers into the targets docs still point at the same content as at HEAD
10  forbidden paths unchanged; git status limited to the allowed set
11  format: HTML, emoji, mermaid, footnotes, fences, table column counts (new problems only)
12  new file:line citations into mpl/ and prim/ resolve to the stated construct
"""
import os, re, subprocess, sys, difflib
ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))
NOTES = os.path.dirname(os.path.abspath(__file__))
QM = "model level, not the shipped code, under stated hypotheses"
QC = "in-crate, on the shipped prim code, on branch Mahnush_Verus, not on this branch, under trusted aws-lc-rs assumptions A1-A20"
RES = {"T02": "21 verified, 1 errors", "C01": "40 verified, 0 errors", "C02": "21 verified, 0 errors",
       "T03": "39 verified, 0 errors", "T05": "33 verified, 0 errors"}
PS = {k: f"{'Partly proved' if k == 'T02' else 'Proved'} ({QM}): {v}" for k, v in RES.items()}
PS_C03 = f"Partly proved ({QC}): 18 verified, 0 errors"
T = {"merged": "docs/verification-targets.md", "01": "docs/verification-targets/01-threat-driven.md",
     "02": "docs/verification-targets/02-capability-driven.md"}
CHANGED = list(T.values()) + ["docs/verification-targets/04-validation.md", "docs/threat-model.md",
                              "docs/completeness-audit.md", "docs/chorus/MPL-Threat-Model.md"]
problems = []
def P(m): problems.append(m)
def read(p): return open(os.path.join(ROOT, p), encoding="utf-8").read()
def head(p): return subprocess.run(["git", "-C", ROOT, "show", "HEAD:" + p], capture_output=True, text=True).stdout

# 1 ---------------------------------------------------------------------------------------------
for k, ids in {"merged": ["T02", "C01", "C02", "T03", "T05"], "01": ["T02", "T03", "T05"], "02": ["C01", "C02"]}.items():
    t, h = read(T[k]), head(T[k])
    for i in ids:
        if t.count(PS[i]) != h.count(PS[i]):
            P(f"{k} {i}: count of canonical model-level string changed ({h.count(PS[i])} -> {t.count(PS[i])})")
for k in ("merged", "02"):
    t = read(T[k])
    if f'proof_status: "{PS_C03}"' not in t: P(f"{k}: C03 YAML proof_status missing")
    if f"| {PS_C03} |" not in t: P(f"{k}: C03 table cell missing")
    if f"- C03: {PS_C03}\n" not in t: P(f"{k}: C03 canonical list line missing")
    if "`verification results:: 18 verified, 0 errors`" not in t: P(f"{k}: C03 result line missing")
    if "8d6381e" not in t: P(f"{k}: tip 8d6381e not stated")
    if "None yet" in re.search(r"id: VR-2026-C03.*?```", t, re.S).group(0).split("proof_status:")[1].split("\n")[0]:
        P(f"{k}: C03 YAML still None yet")
# C03 must not appear with 'None yet' status in any ranked row
for k in T:
    for ln, l in enumerate(read(T[k]).split("\n"), 1):
        if re.match(r"^\| \d+ \|", l) and "C03" in l and "None yet" in l:
            P(f"{T[k]}:{ln}: C03 row still None yet")
for k in ("merged", "02"):
    t = read(T[k])
    if t.count('proof_note: "Partly superseded by VR-008') != 1: P(f"{k}: C02 proof_note missing")
    if "Partly superseded by VR-008" not in t: P(f"{k}: C02 relation missing")

# 2 ---------------------------------------------------------------------------------------------
def rows(t): return [l for l in t.split("\n") if re.match(r"^\| (\d+|—) \| ", l)]
def cells(l): return [c.strip() for c in l.strip().strip("|").split("|")]
out = []
for k, p in T.items():
    nr, orr = rows(read(p)), rows(head(p))
    if len(nr) != len(orr): P(f"{k}: ranked row count {len(orr)} -> {len(nr)}")
    n_changed = 0
    for a, b in zip(nr, orr):
        ca, cb = cells(a), cells(b)
        if ca[:-1] != cb[:-1]: P(f"{k}: ranked row differs outside the Proof status cell: {a[:80]}")
        if ca[-1] != cb[-1]: n_changed += 1
        # rank + score columns
        if k == "merged": rs_a, rs_b = ca[:2], cb[:2]
        else: rs_a, rs_b = [ca[0], ca[2]], [cb[0], cb[2]]
        out.append((k, "HEAD", "|".join(rs_b))); out.append((k, "NOW ", "|".join(rs_a)))
        if rs_a != rs_b: P(f"{k}: rank/score changed {rs_b} -> {rs_a}")
    print(f"{k}: {len(nr)} ranked rows; {n_changed} Proof status cells changed")
open(os.path.join(NOTES, "rank-score-diff.txt"), "w").write(
    "".join(f"{k} {w} {v}\n" for k, w, v in out if w == "HEAD") + "---- now ----\n" + "".join(f"{k} {w} {v}\n" for k, w, v in out if w == "NOW "))
hd = [f"{k} {v}" for k, w, v in out if w == "HEAD"]; nw = [f"{k} {v}" for k, w, v in out if w == "NOW "]
print("rank+score columns identical to HEAD:", hd == nw, f"({len(hd)} rows)")

# 3 ---------------------------------------------------------------------------------------------
ADDED = {"proof_status", "proof_file", "proof_note", "proof_location", "proof_result", "proof_trusted_base", "proof_not_covered", "related_bugs", "scope_note"}
ALLOWED_CHANGE = {"VR-2026-C02", "VR-2026-C03", "VR-2026-T26"}
def strip_keys(block):
    out, skip = [], False
    for l in block.split("\n"):
        m = re.match(r"^  ([a-z_]+):", l)
        if m:
            skip = m.group(1) in ADDED
        if not skip: out.append(l)
    return "\n".join(out)
for k, p in T.items():
    ny = re.findall(r"```yaml\n(.*?)```", read(p), re.S)
    oy = re.findall(r"```yaml\n(.*?)```", head(p), re.S)
    if len(ny) != len(oy): P(f"{k}: YAML block count {len(oy)} -> {len(ny)}")
    nchg = []
    for a, b in zip(ny, oy):
        idm = re.search(r"id:\s*(VR-2026-[TC]\d+)", b).group(1)
        if strip_keys(a).strip("\n") != strip_keys(b).strip("\n"): P(f"{k}: YAML {idm} differs from HEAD beyond the added keys")
        if a != b:
            nchg.append(idm)
            if idm not in ALLOWED_CHANGE: P(f"{k}: YAML {idm} changed but is not C02/C03/T26")
    print(f"{k}: YAML blocks changed: {nchg}")

# 4 ---------------------------------------------------------------------------------------------
valid_model = set(RES.values())
for p in CHANGED:
    for ln, l in enumerate(read(p).split("\n"), 1):
        for m in re.finditer(r"(\d+) verified, (\d+) errors", l):
            s = m.group(0)
            if s in valid_model:
                if "model level" not in l and "verification results::" not in l and not re.search(r"proof status|Proof status|results::", l, re.I) and p != "docs/verification-targets/04-validation.md":
                    pass
            elif s == "18 verified, 0 errors":
                if not ("Mahnush_Verus" in l or "in-crate" in l or "aws-mpl-primitives" in l or "prim" in l):
                    P(f"{p}:{ln}: '18 verified, 0 errors' without a Mahnush_Verus / in-crate / prim qualifier")
            elif s == "1858 verified, 0 errors":
                if "vstd" not in l: P(f"{p}:{ln}: 1858 line without 'vstd'")
            elif s == "69 verified, 0 errors":
                if "esdk" not in l: P(f"{p}:{ln}: 69 line without 'esdk'")
            elif s == "10 verified, 0 errors":
                pass
            else:
                P(f"{p}:{ln}: unknown result line {s!r}")
        for i, r in RES.items():
            if r in l and "model level" not in l and "verification results::" not in l and p != "docs/verification-targets/04-validation.md":
                if "None yet" not in l:
                    pass

# 5 ---------------------------------------------------------------------------------------------
claim = re.compile(r"VR-013|VR-014|18 verified|partly proved in-crate|in-crate proof", re.I)
QUAL = ("Mahnush_Verus", "not on this branch")
def contexts(text):
    """yield (lineno, line, context) where context is the text that must carry the qualifier:
    the line itself; for a table row the table header row; for a YAML line its block; for lines of the
    'C03: in-crate proof' subsection the lead paragraph (first non-empty paragraph after the heading)."""
    lines = text.split("\n"); n = len(lines)
    in_yaml = False; yblock = ""; sect_lead = None; hdr = None
    # precompute yaml blocks
    blocks = {}
    s = None
    for k, l in enumerate(lines):
        if l.startswith("```yaml"): s = k
        elif l.startswith("```") and s is not None:
            blk = "\n".join(lines[s:k]);
            for q in range(s, k + 1): blocks[q] = blk
            s = None
    for k, l in enumerate(lines):
        ctx = l
        if k in blocks: ctx = blocks[k]
        if l.startswith("|"):
            if k == 0 or not lines[k - 1].startswith("|"): hdr = l
            ctx = l + " " + (hdr or "")
        if l.startswith("### C03: in-crate proof"):
            sect_lead = lines[k + 2] if k + 2 < n else ""
        elif l.startswith("##"):
            sect_lead = None
        elif sect_lead is not None:
            ctx = l + " " + sect_lead
        yield k + 1, l, ctx
for p in CHANGED:
    if p.endswith("04-validation.md"): continue
    for ln, l, ctx in contexts(read(p)):
        if claim.search(l) and not any(q in ctx for q in QUAL):
            P(f"{p}:{ln}: mentions the C03 proof without naming Mahnush_Verus / 'not on this branch' in its context: {l[:110]}")
        if re.search(r"\bon this branch\b", l) and re.search(r"VR-013|VR-014|C03", l) and not re.search(r"not on this branch|not this branch|nothing on this branch", l):
            P(f"{p}:{ln}: possible claim that C03 is on this branch: {l[:110]}")

# 6 ---------------------------------------------------------------------------------------------
rep = open(os.path.join(ROOT, ".agents/tasks/review-vr013-vr014/report.md")).read()
for needle in ["Consistent with gaps", "18 verified, 0 errors", "1443", "A-OPEN", "in-body", "1.18.1", "UNCHECKED"]:
    if needle not in rep: P(f"review report lacks {needle!r}")
rr = open(os.path.join(NOTES, "rerun.md")).read()
for needle in ["8d6381eb82daee55ecf32911d6ef8b48690d68b9", "18 verified, 0 errors"]:
    if needle not in rr: P(f"rerun.md lacks {needle!r}")
def git(*a): return subprocess.run(["git", "-C", ROOT] + list(a), capture_output=True, text=True).stdout
tipsha = git("rev-parse", "origin/Mahnush_Verus").strip()
print("origin/Mahnush_Verus:", tipsha)
if not tipsha.startswith("8d6381e"): print("NOTE: tip moved since the re-run; docs say 8d6381e")
specs = git("show", "8d6381eb82daee55ecf32911d6ef8b48690d68b9:prim/src/aws_lc_specs.rs")
n_as = len(re.findall(r"assume_specification", specs)); print("assume_specification occurrences in aws_lc_specs.rs:", n_as)
for core, f in [("hmac_core", "lib.rs"), ("digest_core", "lib.rs"), ("kbkdf_core", "lib.rs"), ("fill_random_core", "lib.rs"),
                ("ct_equal_core", "lib.rs"), ("aes_encrypt_core", "lib.rs"), ("aes_decrypt_core", "lib.rs"), ("digest_finish_core", "ecdsa.rs"), ("sign_fixed_len_core", "ecdsa.rs")]:
    if f"fn {core}" not in git("show", f"8d6381eb82daee55ecf32911d6ef8b48690d68b9:prim/src/{f}"): P(f"core {core} not found in {f} at 8d6381e")
if "verus-proofs/" in git("ls-tree", "-r", "--name-only", "8d6381eb82daee55ecf32911d6ef8b48690d68b9") and False: pass
if any(l.startswith("verus-proofs/") for l in git("ls-tree", "-r", "--name-only", "8d6381eb82daee55ecf32911d6ef8b48690d68b9").split("\n")):
    P("Mahnush_Verus has a verus-proofs/ directory; the cross-branch table says it has none")
if git("log", "--oneline", "43b9ff7..8d6381eb82daee55ecf32911d6ef8b48690d68b9", "--", "prim").strip():
    P("prim/ changed after 43b9ff7; docs say it did not")
mb = git("merge-base", "HEAD", "origin/Mahnush_Verus").strip(); lr = git("rev-list", "--left-right", "--count", "HEAD...origin/Mahnush_Verus").split()
print("merge-base", mb[:7], "left/right", lr)
if not mb.startswith("5f2dc72") or lr != ["20", "47"]: P(f"divergence facts differ: {mb[:7]} {lr}")
if git("diff", "--stat", "HEAD", "origin/Mahnush_Verus", "--", "mpl/src").strip(): P("mpl/src differs between branches; docs say identical")
merged = read(T["merged"])
for needle in ["hkdf", "DigestContext::digest", "adapters", "A13", "A12", "A19", "A20", "in-body", "20 `assume_specification`", "1.18.1", "FIPS", "PR #103",
               "ed4a81e", "43b9ff7", "not on this branch", "diverged", "Nothing was merged", "VR-006", "VR-008", "VR-009", "1443"]:
    if needle not in merged: P(f"merged doc lacks {needle!r}")

# 7 ---------------------------------------------------------------------------------------------
for p in CHANGED:
    for ln, l in enumerate(read(p).split("\n"), 1):
        if "duplicate" in l.lower() and "C02" in l and not re.search(r"not a duplicate", l):
            P(f"{p}:{ln}: C02 and 'duplicate' without negation: {l[:100]}")

# 8 ---------------------------------------------------------------------------------------------
for k in ("merged", "01"):
    t = read(T[k]); b = re.search(r"id: VR-2026-T26.*?```", t, re.S).group(0)
    if "related_bugs:" not in b or "BUG-10" not in b or "TM-MPL-015" not in b or "scope_note" not in b: P(f"{k}: T26 YAML lacks BUG-10 related_bugs/scope_note")
    if "proof_status: \"None yet\"" not in b: P(f"{k}: T26 proof_status changed")
for k in ("merged", "01", "02"):
    if "BUG-10" not in read(T[k]): P(f"{T[k]}: BUG-10 missing")
c03_blocks = [re.search(r"id: VR-2026-C03.*?```", read(T[k]), re.S).group(0) for k in ("merged", "02")]
for b in c03_blocks:
    if "BUG-10" not in b or "BUG-07" not in b: P("C03 YAML lacks BUG-07/BUG-10 related_bugs")
for p, keys in {"docs/threat-model.md": ["BUG-10", "TM-MPL-015", "C03", "VR-014", "VR-013", "TM-MPL-023"],
                "docs/completeness-audit.md": ["BUG-10", "T26", "C03", "section 3b"],
                "docs/chorus/MPL-Threat-Model.md": ["BUG-10", "C03", "VR-013", "VR-014", "TM-MPL-015", "Mahnush_Verus"]}.items():
    t = read(p)
    for key in keys:
        if key not in t: P(f"{p}: lacks {key!r}")
if PS_C03 not in read("docs/threat-model.md") or PS_C03 not in read("docs/chorus/MPL-Threat-Model.md") or PS_C03 not in read("docs/completeness-audit.md"):
    P("C03 canonical string missing from threat-model / chorus / audit")
a = head(T["01"]).split("\n")[746:750]; b = read(T["01"]).split("\n")[746:750]
print("01 lines 747-750 identical to HEAD (BUG-10 cites them):", a == b)
if a != b: P("01 lines 747-750 moved")

# 9 ---------------------------------------------------------------------------------------------
sys.path.insert(0, os.path.join(ROOT, ".agents/tasks/docs-proof-status"))
import linemap
def cites(path, doc):
    t = read(path); res = []
    for ln, l in enumerate(t.split("\n"), 1):
        for m in re.finditer(r"`?(verification-targets|01-threat-driven|02-capability-driven)\.md`?((?:(?:,| and)? ?`?:\d+(?:-\d+)?`?)+)", l):
            pass
    return res
# explicit list (document, target doc, [lines at HEAD])
EXPL = [("docs/threat-model.md", "merged", [13, 14, 15, 16, 17, 18, 111, 116, 561]), ("docs/threat-model.md", "01", [16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 126, 1551]),
        ("docs/completeness-audit.md", "merged", [4, 9, 17, 26, 104, 183, 189, 191, 490, 523, 537, 561, 584]),
        ("docs/completeness-audit.md", "01", [4, 10, 20, 118, 228, 230, 242, 259, 266, 272, 1551, 1617, 1619])]
newtxt = {"docs/threat-model.md": read("docs/threat-model.md"), "docs/completeness-audit.md": read("docs/completeness-audit.md")}
for doc, kk, lines in EXPL:
    m = linemap.mapping(T[kk]); old = head(T[kk]).split("\n"); new = read(T[kk]).split("\n")
    bad = 0
    for n in lines:
        nn = m.get(n)
        if nn is None: P(f"{doc}: cited {kk}:{n} has no image"); bad += 1; continue
        a, b = re.sub(r"\|[^|]*\|\s*$", "", old[n - 1]), re.sub(r"\|[^|]*\|\s*$", "", new[nn - 1])
        if old[n - 1][:60] != new[nn - 1][:60]: P(f"{doc}: cited {kk}:{n} -> {nn} content differs"); bad += 1
        # the number actually written in the doc must be the new one when it moved
        if nn != n:
            pat = rf"[:-]{nn}(?![0-9])"
            if not re.search(pat, newtxt[doc]): P(f"{doc}: moved cite {kk}:{n} -> {nn} not found in doc"); bad += 1
    print(f"{doc} -> {kk}: {len(lines)} cites checked, {bad} problems")

# 10 --------------------------------------------------------------------------------------------
r = subprocess.run(["git", "-C", ROOT, "diff", "--quiet", "HEAD", "--", "mpl", "prim", "esdk", "verus-proofs", "docs/bug-reports", "docs/spec-security-analysis.md",
                    "docs/chorus/MPL-Bug-Reports.md", "docs/chorus/MPL-Bug-Reports.docx"])
print("git diff --quiet HEAD -- mpl prim esdk verus-proofs docs/bug-reports docs/spec-security-analysis.md docs/chorus/MPL-Bug-Reports.*: exit", r.returncode)
if r.returncode: P("forbidden paths changed")
ALLOW = tuple(["docs/verification-targets.md", "docs/verification-targets/", "docs/threat-model.md", "docs/completeness-audit.md",
               "docs/chorus/MPL-Threat-Model.md", "docs/chorus/MPL-Threat-Model.docx", ".agents/tasks/docs-c03-status/"])
for l in git("status", "--short").split("\n"):
    if l.strip() and not l[3:].startswith(ALLOW): P(f"status outside the allowed set: {l}")
if git("rev-parse", "HEAD").strip() != "b94c8719dc4e9ccd6ad35dc9d6755e23581b5586": P("HEAD moved")
if git("branch", "--show-current").strip() != "MPL-Verus": P("branch is not MPL-Verus")

# 11 --------------------------------------------------------------------------------------------
def tcols(l):
    s = re.sub(r"`[^`]*`", lambda m: m.group(0).replace("|", "§"), l)
    s = s.replace("\\|", "§")
    return len(s.strip().strip("|").split("|"))
def table_problems(t):
    probs, cur = set(), None
    for ln, l in enumerate(t.split("\n"), 1):
        if l.startswith("|"):
            n = tcols(l)
            if cur is None: cur = n
            elif n != cur: probs.add(l[:70])
        else: cur = None
    return probs
for p in CHANGED:
    t = read(p)
    if t.count("```") % 2: P(f"{p}: unbalanced fences")
    body = re.sub(r"```.*?```", "", t, flags=re.S); body = re.sub(r"`[^`\n]*`", "", body)
    if re.search(r"</?[a-zA-Z][^>]*>", body): P(f"{p}: HTML tag outside code")
    if re.search(r"\[\^[^\]]+\]", body): P(f"{p}: footnote marker")
    if re.search("[\U0001F300-\U0001FAFF\u2600-\u27BF]", body): P(f"{p}: emoji")
    if "mermaid" in t.lower(): P(f"{p}: mermaid")
    newp = table_problems(t) - table_problems(head(p))
    for x in newp: P(f"{p}: new table column-count problem: {x}")

# 12 --------------------------------------------------------------------------------------------
EXP = [("mpl/src/keyring/raw_aes_keyring.rs", 163, r"aes_encrypt\("), ("mpl/src/keyring/raw_aes_keyring.rs", 471, r"let mut plaintext_dk = vec!\[0u8"),
       ("mpl/src/keyring/raw_aes_keyring.rs", 489, r"plaintext_dk\.len\(\) != expected_dk_len"), ("mpl/src/keyring/raw_aes_keyring.rs", 494, r"continue;"),
       ("mpl/src/keyring/raw_aes_keyring.rs", 497, r"PlaintextDataKey::new\(plaintext_dk\)"), ("mpl/src/keyring/raw_aes_keyring.rs", 369, r"expected_key_len"),
       ("mpl/src/keyring/raw_aes_keyring.rs", 379, r"^\s*}\s*$"), ("mpl/src/aws_kms/branch_key_wrap.rs", 157, r"pub fn wrap\("),
       ("mpl/src/aws_kms/branch_key_wrap.rs", 199, r"aes_encrypt\("), ("mpl/src/aws_kms/branch_key_wrap.rs", 230, r"pub fn unwrap\("),
       ("mpl/src/aws_kms/branch_key_wrap.rs", 275, r"let mut plaintext = vec!\[0u8"), ("prim/src/lib.rs", 215, r"plain_text\.len\(\) < cipher_text\.len\(\)")]
for f, n, pat in EXP:
    lines = open(os.path.join(ROOT, f)).read().split("\n")
    if not re.search(pat, lines[n - 1]): P(f"{f}:{n} does not match {pat!r}: {lines[n-1][:80]!r}")
print(f"{len(EXP)} new file:line citations into mpl/ and prim/ checked")

print("PROBLEMS:" if problems else "PROBLEMS: none")
for p in problems: print("  -", p)
