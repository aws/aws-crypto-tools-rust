#!/usr/bin/env python3
"""Mechanical citation check for the pipeline re-run docs (iteration helper).

For each in-scope doc, extract `file.rs:LINE[-LINE]` citations and bare `:LINE`
continuations (resolved against the most recent file named on the same line or,
inside a YAML block, the block's `file:` list). For each citation report:
  * whether the file resolves to a tracked file under mpl/, prim/, esdk/
  * whether the line is within range
  * whether an identifier quoted just before the citation occurs within +-W lines
Output: TSV-ish lines; status OK / NOID (no identifier to check) / MISS / BADFILE / RANGE.
"""
import os, re, subprocess, sys

ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))
import glob
DOCS = sorted(os.path.relpath(p, ROOT) for p in glob.glob(os.path.join(ROOT, "docs/bug-reports/*.md"))) + ["docs/spec-security-analysis.md"]
W = int(os.environ.get("W", "4"))

files = subprocess.run(["git", "-C", ROOT, "ls-files", "mpl", "prim", "esdk"],
                       capture_output=True, text=True).stdout.split()
files = [f for f in files if re.search(r"\.(rs|toml|h|hpp|cpp|md|smithy|py)$", f)]
cache = {}

def lines_of(p):
    if p not in cache:
        with open(os.path.join(ROOT, p), errors="replace") as fh:
            cache[p] = fh.read().split("\n")
    return cache[p]

def resolve(name):
    name = name.strip("`/ ")
    c = [f for f in files if f == name or f.endswith("/" + name)]
    # prefer core crates
    pri = [f for f in c if f.startswith(("mpl/src", "prim/src", "mpl/tests", "prim/tests"))]
    return c  # v2: keep every candidate file (shim lib.rs vs mpl lib.rs)

FILE_RE = re.compile(r"([A-Za-z0-9_./-]+\.(?:rs|toml|h|hpp|cpp|smithy|py|md)):(\d+)(?:-(\d+))?")
BARE_RE = re.compile(r"(?<![A-Za-z0-9_.])(?:`|\(|, |\s|/)?:(\d+)(?:-(\d+))?")
IDENT_RE = re.compile(r"[A-Za-z_][A-Za-z0-9_]{3,}")
STOP = set("""with from that this then only line file test tests calls call check checks
here when each none Location note Changed since keyring keyrings the and for not are
mpl src prim esdk shims aws esdk-cpp none true false Err Ok Some None self Self""".split())

def idents(ctx):
    # identifiers in backticks first, then plain tokens of the last clause
    bt = re.findall(r"`([^`]+)`", ctx)
    ids = []
    for b in bt[-2:]:
        ids += [t for t in IDENT_RE.findall(b.split("::")[-1]) if t not in STOP]
        ids += [t for t in IDENT_RE.findall(b) if t not in STOP]
    tail = re.split(r"[;|]", ctx)[-1][-60:]
    ids += [t for t in IDENT_RE.findall(tail) if t not in STOP and ("_" in t or t[0].isupper())]
    seen = []
    for i in ids:
        if i not in seen and not re.fullmatch(r".*\.(rs)", i) and not i.endswith("_rs"):
            seen.append(i)
    return seen

def check(doc, ln, path_cands, a, b, ctx, raw):
    a = int(a); b = int(b) if b else a
    if not path_cands:
        return ("BADFILE", raw, "", ctx[-70:])
    ids = idents(ctx)
    results = []
    for p in path_cands:
        L = lines_of(p)
        n = len(L) - (1 if L and L[-1] == "" else 0)
        if b > n or a < 1:
            results.append(("RANGE", p, f"len={n}"))
            continue
        lo, hi = max(1, a - W), min(n, b + W)
        window = "\n".join(L[lo - 1:hi])
        hit = [i for i in ids if i in window]
        if not ids:
            results.append(("NOID", p, L[a - 1].strip()[:90]))
        elif hit:
            results.append(("OK", p, ",".join(hit[:3])))
        else:
            results.append(("MISS", p, f"ids={ids[:5]} line={L[a-1].strip()[:90]}"))
    order = ["OK", "NOID", "MISS", "RANGE"]
    best = sorted(results, key=lambda r: order.index(r[0]))[0]
    if best[0] in ("MISS", "RANGE") and ids:
        # fallback: identifier at that line in some other tracked file
        alts = []
        for p in files:
            if not p.endswith(".rs"):
                continue
            L = lines_of(p)
            if b > len(L):
                continue
            window = "\n".join(L[max(0, a - 1 - W):b + W])
            hit = [i for i in ids[:3] if i in window]
            if hit and len(max(hit, key=len)) >= 8:
                alts.append((p, hit))
        if alts:
            best = ("ALT", alts[0][0] + (f" (+{len(alts)-1})" if len(alts) > 1 else ""), ",".join(alts[0][1][:2]))
    return (best[0], f"{best[1]}:{a}" + (f"-{b}" if b != a else ""), best[2], ctx[-70:].replace("\n", " "))

out = []
for doc in DOCS:
    text = open(os.path.join(os.environ.get("DOCROOT", ROOT), doc)).read().split("\n")
    yaml_files = []
    carry = None
    for ln, line in enumerate(text, 1):
        if not line.strip() or line.startswith(("#", "|")):
            carry = None
        m = re.match(r"\s*file:\s*(.+)", line)
        if m:
            yaml_files = []
            for part in re.split(r"[;,]", m.group(1)):
                part = part.strip().split(" ")[0]
                if part:
                    yaml_files += resolve(part)
        if line.startswith("```") or line.startswith("recommendation:"):
            pass
        last = carry
        pos = 0
        spans = []
        for m in FILE_RE.finditer(line):
            spans.append((m.start(), m.end(), m.group(1), m.group(2), m.group(3)))
        # bare continuations
        tokens = []
        for s in spans:
            tokens.append(("F",) + s)
        for m in re.finditer(r"\b([a-z][a-z0-9_]{3,})::", line):
            stem = m.group(1)
            cs = [f for f in files if f.endswith("/" + stem + ".rs")]
            if cs and not any(s_[0] <= m.start() < s_[1] for s_ in spans):
                tokens.append(("M", m.start(), m.end(), stem + ".rs", None, None))
        for m in re.finditer(r"([A-Za-z0-9_/-]+\.rs)(?!:\d)", line):
            if any(s[0] <= m.start() < s[1] for s in spans):
                continue
            tokens.append(("M", m.start(), m.end(), m.group(1), None, None))
        for m in re.finditer(r":(\d+)(?:-(\d+))?", line):
            st = m.start()
            if any(s[0] <= st < s[1] for s in spans):
                continue
            prev = line[st - 1] if st > 0 else " "
            if prev.isalnum() or prev in "_.)]>":
                continue  # e.g. 10:30, TM:..., urls
            if re.search(r"https?$|\w$", line[max(0, st - 6):st]):
                continue
            tokens.append(("B", st, m.end(), None, m.group(1), m.group(2)))
        tokens.sort(key=lambda t: t[1])
        for t in tokens:
            kind, st, en, f, a, b = t
            ctx = line[max(0, st - 140):st]
            if kind == "M":
                r = resolve(f)
                if r:
                    last = r
                continue
            if kind == "F" and f.endswith(".md"):
                last = ["EXTERNAL"]
                continue
            if kind == "F":
                last = resolve(f)
                out.append((doc, ln) + check(doc, ln, last, a, b, ctx + "`" + f.split("/")[-1].split(".")[0] + "`" if False else ctx, f"{f}:{a}"))
            else:
                cands = last if last else yaml_files
                if cands == ["EXTERNAL"]:
                    continue
                if not cands:
                    out.append((doc, ln, "NOFILE", f":{a}", "", ctx[-70:]))
                    continue
                out.append((doc, ln) + check(doc, ln, cands, a, b, ctx, f":{a}"))

        carry = last

for r in out:
    print("\t".join(str(x) for x in r))
