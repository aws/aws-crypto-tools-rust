#!/usr/bin/env python3
"""Link checker for all *.md under docs/ and verus-proofs/.
usage: check_links.py ROOT   -> prints one line per unresolved reference: FILE<TAB>KIND<TAB>TARGET
KIND: link (relative markdown link), anchor (link anchor not a heading), tick (backticked repo path), tickbare (backticked bare *.md name).
"""
import os, re, sys, glob

ROOT = os.path.abspath(sys.argv[1])
files = sorted(glob.glob(ROOT + '/docs/**/*.md', recursive=True) + glob.glob(ROOT + '/verus-proofs/**/*.md', recursive=True))
PREFIXES = ('docs/', 'verus-proofs/', '.agents/', '.kiro/', 'mpl/', 'prim/', 'esdk/')
LINK = re.compile(r'\[[^\]]*\]\(([^)\s]+)\)')
TICK = re.compile(r'`([^`\n]+)`')


def slug(h):
    h = re.sub(r'`', '', h.strip().lower())
    h = re.sub(r'[^\w\- ]', '', h)
    return h.replace(' ', '-')


_anch = {}


def anchors(path):
    if path not in _anch:
        s = set()
        try:
            fence = False
            for l in open(path, encoding='utf-8', errors='replace'):
                if l.lstrip().startswith('```'):
                    fence = not fence
                if not fence:
                    m = re.match(r'#{1,6}\s+(.*)', l)
                    if m:
                        s.add(slug(m.group(1)))
        except OSError:
            pass
        _anch[path] = s
    return _anch[path]


out = set()
for f in files:
    rel = os.path.relpath(f, ROOT)
    d = os.path.dirname(f)
    fence = False
    for l in open(f, encoding='utf-8', errors='replace'):
        if l.lstrip().startswith('```'):
            fence = not fence
            continue
        if fence:
            continue
        for m in LINK.finditer(l):
            t = m.group(1)
            if re.match(r'[a-z]+:', t) or t.startswith('#') and False:
                continue
            path, _, anc = t.partition('#')
            tgt = os.path.normpath(os.path.join(d, path)) if path else f
            if not os.path.exists(tgt):
                out.add((rel, 'link', t))
            elif anc and tgt.endswith('.md') and slug(anc) not in anchors(tgt) and anc not in anchors(tgt):
                out.add((rel, 'anchor', t))
        for m in TICK.finditer(l):
            t = m.group(1).strip()
            if any(c in t for c in '*<>{}$|') or '...' in t or ' ' in t:
                continue
            t2 = re.sub(r'(:\d+(-\d+)?)+$', '', t)
            t2 = t2.split('#')[0].rstrip('.,;)')
            if t2.startswith(PREFIXES):
                if not os.path.exists(os.path.join(ROOT, t2)):
                    out.add((rel, 'tick', t2))
            elif re.fullmatch(r'[\w.-]+\.md', t2):
                cands = [d, ROOT + '/docs', ROOT + '/docs/mpl-verification-targets', ROOT + '/docs/verification-targets',
                         ROOT + '/docs/mpl-bug-reports', ROOT + '/docs/bug-reports', ROOT + '/verus-proofs', ROOT]
                if not any(os.path.exists(os.path.join(c, t2)) for c in cands):
                    out.add((rel, 'tickbare', t2))
for r in sorted(out):
    print('\t'.join(r))
