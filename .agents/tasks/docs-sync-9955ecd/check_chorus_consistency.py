#!/usr/bin/env python3
"""Consistency check of docs/chorus/*.md against docs/mpl-threat-model.md, docs/mpl-verification-targets.md,
bug-reports README. Checks: register ratings, counts, target scores, bug severity (BUG-06 High), no Low for BUG-06,
mitigation of CVE wording, banned formats (HTML, emoji, mermaid, footnotes)."""
import os, re, collections
ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))
rd = lambda p: open(os.path.join(ROOT, p)).read()
tm = rd("docs/mpl-threat-model.md"); vt = rd("docs/mpl-verification-targets.md")
ct = rd("docs/chorus/MPL-Threat-Model.md"); cb = rd("docs/chorus/MPL-Bug-Reports.md")
prob = 0
def bad(*a):
    global prob; prob += 1; print("PROBLEM", *a)
# source matrix
src = {}
for m in re.finditer(r"^\| (TM-MPL-\d{3}) \| ([A-Z/]+) \| (\w+) \| (\w+) \| [^|]+ \| [^|]+ \| \**(\w+)\** \|", tm, re.M):
    src[m.group(1)] = (m.group(2), m.group(3), m.group(4), m.group(5))
print("source rows", len(src))
# chorus register
reg = {}
regsec = ct.split("## 5. Threat register")[1].split("## 6. Threat details")[0]
for m in re.finditer(r"^\| (TM-MPL-\d{3}) \| ([A-Z/]+) \| ([^|]+) \| ([^|]+) \| (\w+) \| (\w+) \| (\w+) \| ([^|]+) \|$", regsec, re.M):
    reg[m.group(1)] = (m.group(2), m.group(5), m.group(6), m.group(7))
print("chorus register rows", len(reg))
for k, v in src.items():
    if reg.get(k) != v: bad("register mismatch", k, reg.get(k), v)
# appendix B in chorus
app = {}
for m in re.finditer(r"^\| (TM-MPL-\d{3}) \| ([A-Z/]+) \| (\w+) \| (\w+) \| ([\w/]+) \| ([\w/]+) \| (\w+) \| ", ct, re.M):
    app[m.group(1)] = (m.group(2), m.group(3), m.group(4), m.group(7))
for k, v in src.items():
    if app.get(k) != v: bad("appendix B mismatch", k, app.get(k), v)
# counts
cr = collections.Counter(v[3] for v in src.values()); cs = collections.Counter(v[1] for v in src.values()); cl = collections.Counter(v[2] for v in src.values())
print("risk", dict(cr), "sev", dict(cs), "lik", dict(cl))
for s_ in ["3 High, 14 Medium, 9 Low", "5 Critical, 9 High, 10 Medium, 2 Low", "19 Low, 7 Medium, 0 High"]:
    if s_ not in ct: bad("missing count text", s_)
if (cr["High"], cr["Medium"], cr["Low"]) != (3, 14, 9): bad("source counts differ from expected")
# STRIDE counts from source section 7 headings
sec7 = tm.split("## 7. Threat Identification (STRIDE)")[1].split("## 8.")[0]
strides = {}
cur = None
for line in sec7.split("\n"):
    h = re.match(r"### (.+)", line)
    if h: cur = h.group(1).strip(); strides[cur] = 0
    elif cur and re.match(r"\| TM-MPL-\d{3} \|", line): strides[cur] += 1
print("STRIDE (source sec 7)", strides)
want = "Spoofing 3, Tampering 5, Repudiation 1, Information Disclosure 3, Denial of Service 4, Elevation of Privilege 10"
exp = {"Spoofing":3,"Tampering":5,"Repudiation":1,"Information Disclosure":3,"Denial of Service":4,"Elevation of Privilege":10}
if strides != exp: bad("stride counts", strides)
if want not in ct: bad("stride text missing")
# grid
grid = collections.Counter((v[1], v[2]) for v in src.values())
print("grid", dict(grid))
# target scores: parse merged section 1
scores = {}
for m in re.finditer(r"^\| \d+ \| ([\d.]+) \| [TC] \| ([TC]\d\d) ", vt, re.M):
    scores[m.group(2)] = m.group(1)
print("targets scored", len(scores))
for m in re.finditer(r"\b([TC]\d\d) \((\d+\.\d\d)\)", ct + cb):
    if scores.get(m.group(1)) != m.group(2): bad("score mismatch", m.group(0), scores.get(m.group(1)))
for m in re.finditer(r"\b([TC]\d\d) (?:property|\([a-z]+\)|\(\w\)) ?(?:\([^)]*\))? ?\((\d+\.\d\d)\)", ct + cb):
    pass
# Retired targets must not appear in cross-ref table rows
for t in ("T08", "C06"):
    for line in ct.split("\n"):
        if line.startswith("| TM-MPL-") and re.search(r"\b%s\b" % t, line): bad("retired target in cross-ref", t)
# threat ids in docs exist; risk words after TM ids match source
for name, txt in (("threat-model", ct), ("bug-reports", cb)):
    for m in re.finditer(r"TM-MPL-(\d{3}) \((High|Medium|Low)\b", txt):
        k = "TM-MPL-" + m.group(1)
        if k not in src: bad("unknown threat", name, k)
        elif src[k][3] != m.group(2): bad("rating mismatch", name, k, m.group(2), src[k][3])
# cross-ref table rows risk
for m in re.finditer(r"^\| (TM-MPL-\d{3}) \((High|Medium|Low)[,)]", ct, re.M):
    if src[m.group(1)][3] != m.group(2): bad("xref risk mismatch", m.group(1))
# BUG-06 severity everywhere
for name, txt in (("threat", ct), ("bugs", cb)):
    for i, line in enumerate(txt.split("\n"), 1):
        if "BUG-06" in line and re.search(r"\|\s*Low\s*\|", line.split("BUG-06", 1)[1]) and "TM-MPL-003" not in line:
            bad("BUG-06 row shows Low", name, i, line[:120])
        if re.search(r"BUG-06[^|]*\|[^|]*\|[^|]*\| Low \|", line): bad("BUG-06 Low in table", name, i)
for pat in ("Severity review suggested", "rated Low in the bug reports", "1 – Medium", "UNVERIFIED", "unverified", "a1e23d7 edition"):
    for name, txt in (("threat", ct), ("bugs", cb)):
        for i, line in enumerate(txt.split("\n"), 1):
            if pat in line:
                print("NOTE contains", repr(pat), name, i, line[:140])
if "| BUG-06 | Cache-identifier preimage not injective when fields contain NUL | Hierarchical keyring (cache identifier) | High" not in cb: bad("BUG-06 summary row")
if "Severity | High (raised from Low" not in cb: bad("BUG-06 attr row")
if "1 | BUG-06" not in cb: bad("agenda order")
# bug severities vs README
readme = rd("docs/mpl-bug-reports/README.md")
sev = {}
for m in re.finditer(r"^\| \[(BUG-\d\d)\]\([^)]*\) \| .*? \| .*? \| (High \(raised[^|]*|Low|Medium|Informational) \|", readme, re.M):
    sev[m.group(1)] = m.group(2).split(" (")[0]
print("README severities", sev)
for m in re.finditer(r"^\| (BUG-\d\d) \| .*? \| (?:.*? \| )?(High|Low|Medium|Informational)(?: \(raised[^|]*)? \| ", cb, re.M):
    pass
for b, v in sev.items():
    row = [l for l in cb.split("\n") if l.startswith("| %s | " % b) and "Hierarchical" in l or l.startswith("| %s | " % b) and "Status on main" not in l]
for b, v in sev.items():
    m = re.search(r"^\| %s \| (?:.+? \| ){2}(High|Low|Medium|Informational)\b" % b, cb, re.M)
    if not m or m.group(1) != v: bad("summary severity", b, m and m.group(1), v)
# format rules
for name, txt in (("threat", ct), ("bugs", cb)):
    if re.search(r"</?[a-zA-Z][^>]*>", re.sub(r"`[^`]*`", "", re.sub(r"```.*?```", "", txt, flags=re.S))): bad("html-like tag", name)
    if "```mermaid" in txt: bad("mermaid", name)
    if re.search(r"[\U0001F300-\U0001FAFF\u2600-\u27BF]", txt): bad("emoji", name)
    if re.search(r"\[\^", txt): bad("footnote", name)
    if "—" in txt: print("NOTE em-dash in", name, txt.count("—"))
print("problems:", prob)
