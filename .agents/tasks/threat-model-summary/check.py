import re, os, sys, collections
ROOT = '/Users/mahnush/Desktop/ESDK-Rust-Verus/MPL/esdk-native-mpl'
DOC = ROOT + '/docs/chorus/MPL-Threat-Model-Summary.md'
TM = open(ROOT + '/docs/mpl-threat-model.md').read()
BR = open(ROOT + '/docs/mpl-bug-reports/README.md').read()
doc = open(DOC).read()
out = []
def P(*a):
    out.append(' '.join(str(x) for x in a))

# split sections
def section(title, nxt=None):
    m = re.search(r'^## ' + re.escape(title) + r'\s*$', doc, re.M)
    assert m, title
    rest = doc[m.end():]
    n = re.search(r'^## ', rest, re.M)
    return rest[:n.start()] if n else rest

# ---- source matrix (current risk column = last Risk column)
app = TM[TM.index('## Appendix: Threat Risk Matrix'):TM.index('## Impact on verification targets')]
src = {}
for line in app.splitlines():
    m = re.match(r'\|\s*(TM-MPL-\d{3})\s*\|.*\|', line)
    if m:
        cells = [c.strip().strip('*') for c in line.strip().strip('|').split('|')]
        src[cells[0]] = cells[6]  # ID, STRIDE, Sev, Lik, R1, R2, R3
P('## Check 1: ratings vs source current risk matrix')
ids = ['TM-MPL-%03d' % i for i in range(1, 27)]
P('source IDs parsed:', len(src), 'all 26 present:', sorted(src) == ids)
glance = section('All threats at a glance')
appB = section('Appendix B: Threat table in AWS template form')
def rows(txt):
    r = {}
    for line in txt.splitlines():
        if line.startswith('| TM-MPL-'):
            c = [x.strip() for x in line.strip().strip('|').split('|')]
            r[c[0]] = c
    return r
g = rows(glance); b = rows(appB)
mism = []
for i in ids:
    if i not in g: mism.append((i, 'missing in glance'))
    elif g[i][2] != src[i]: mism.append((i, 'glance', g[i][2], src[i]))
    if i not in b: mism.append((i, 'missing in appB'))
    elif b[i][1] != src[i]: mism.append((i, 'appB', b[i][1], src[i]))
    if i in g and i in b and g[i][3] != b[i][7]: mism.append((i, 'status differs glance/appB', g[i][3], b[i][7]))
P('glance rows:', len(g), 'appB rows:', len(b), 'appB columns:', len(next(iter(b.values()))))
P('mismatches:', mism if mism else 'none')
stat = collections.Counter(v[3] for v in g.values())
P('status counts:', dict(stat))
bad_status = [k for k, v in g.items() if v[3] not in ('Mitigated', 'Partly mitigated', 'Open', 'See full model')]
P('invalid status words:', bad_status or 'none')
P('max words in glance threat text:', max(len(v[1].split()) for v in g.values()))
hdr = [l for l in appB.splitlines() if l.startswith('| Threat Number')][0]
P('appB header:', hdr)

# ---- check 2
P('\n## Check 2: counts')
sc = collections.Counter(src.values())
P('source counts:', dict(sc), 'total', sum(sc.values()))
sm = section('Summary')
m = re.search(r'\| Threats by rating \| (\d+) \| (\d+) \| (\d+) \| (\d+) \|', sm)
doc_c = tuple(int(x) for x in m.groups())
P('doc counts H/M/L/total:', doc_c, 'equal:', doc_c == (sc['High'], sc['Medium'], sc['Low'], 26))
gc = collections.Counter(v[2] for v in g.values())
P('glance table counts:', dict(gc), 'equal:', (gc['High'], gc['Medium'], gc['Low']) == (sc['High'], sc['Medium'], sc['Low']))

# ---- check 3
P('\n## Check 3: bugs')
bugs = {}
for line in BR.splitlines():
    m = re.match(r'\| \[(BUG-\d\d)\]', line)
    if m:
        c = [x.strip() for x in line.strip().strip('|').split('|')]
        sev = c[3]; status = c[6]
        sev = 'High' if sev.startswith('High') else sev
        bugs[m.group(1)] = (sev, 'Fixed' if status.startswith('Fixed') else 'Open')
P('source bugs:', len(bugs), bugs)
sec7 = section('Known problems found')
d7 = {}
for line in sec7.splitlines():
    m = re.match(r'\| (BUG-\d\d) \|', line)
    if m:
        c = [x.strip() for x in line.strip().strip('|').split('|')]
        d7[c[0]] = (c[2], c[3])
P('doc sec7 rows:', len(d7), 'equal to source:', d7 == bugs)
fixed = sorted(k for k, v in bugs.items() if v[1] == 'Fixed')
P('fixed:', fixed, 'open count:', sum(1 for v in bugs.values() if v[1] == 'Open'))
m = re.search(r'\| Count \| (\d+) \| (\d+) \| (\d+) \|', sm)
P('summary bugs found/fixed/open:', m.groups(), 'expected', (str(len(bugs)), str(len(fixed)), str(len(bugs) - len(fixed))))
op = collections.Counter(v[0] for v in bugs.values() if v[1] == 'Open')
P('open by severity (source):', dict(op))
P('summary sentence:', re.search(r'The seven open bugs are:[^\n]*', sm).group(0))
P('BUG-06 severity in doc:', d7['BUG-06'])
# related threat IDs in doc exist in source README rows
rel_src = {}
for line in BR.splitlines():
    m = re.match(r'\| \[(BUG-\d\d)\]', line)
    if m:
        c = [x.strip() for x in line.strip().strip('|').split('|')]
        rel_src[m.group(1)] = set(re.findall(r'TM-MPL-\d{3}', c[7]))
rel_doc = {}
for line in sec7.splitlines():
    m = re.match(r'\| (BUG-\d\d) \|', line)
    if m:
        rel_doc[m.group(1)] = set(re.findall(r'TM-MPL-\d{3}', line))
P('related threats in doc subset of README:', {k: sorted(rel_doc[k] - rel_src[k]) for k in rel_doc if rel_doc[k] - rel_src[k]} or 'all subset')
P('README threats not in doc:', {k: sorted(rel_src[k] - rel_doc[k]) for k in rel_src if rel_src[k] - rel_doc[k]} or 'none')

# ---- check 4
P('\n## Check 4: exclusion grep')
pats = [r'second pass', r'first pass', r'\bsince\b', r'previously', r'\braised\b', r'\blowered\b', r'changed from',
        r'VR-', r' T0', r' C0', r'\bT\d\d\b', r'\bC\d\d\b', r'\.rs:', r'file:line', r'mermaid', r'\b[0-9a-f]{7,40}\b',
        r'<[a-zA-Z/][^>]*>', r'\[\^', r'—', r'–', r'```', r'Changes since', r'\bpipeline\b', r'\bagent\b', r'\bworkflow\b', r'a1e23d7|620771c|851977d']
for p in pats:
    f = [(m.start(), doc[max(0, m.start() - 30):m.end() + 30].replace('\n', ' ')) for m in re.finditer(p, doc, re.I if p not in (r'VR-', r' T0', r' C0') else 0)]
    P('%-28s %s' % (p, 'clean' if not f else f[:5]))
emoji = [c for c in doc if ord(c) > 0x2000 and ord(c) not in (0x2014, 0x2013)]
P('non-ASCII/emoji chars:', emoji or 'none')
P('non-ASCII any:', sorted(set(c for c in doc if ord(c) > 127)) or 'none')

# ---- check 5
P('\n## Check 5: words and sentences (sections Summary..Where to read more, no tables)')
start = doc.index('## Summary'); end = doc.index('## Appendix A')
body = doc[start:end]
body_nt = '\n'.join(l for l in body.splitlines() if not l.strip().startswith('|'))
words = re.findall(r"[A-Za-z0-9][A-Za-z0-9'\-+/.]*", re.sub(r'`[^`]*`', ' ', body_nt))
P('body words excluding tables (and headings counted):', len(words))
allw = re.findall(r"[A-Za-z0-9][A-Za-z0-9'\-+/.]*", body)
P('body words including tables:', len(allw))
text = re.sub(r'`([^`]*)`', r'\1', body_nt)
text = re.sub(r'^#+ .*$', '', text, flags=re.M)
text = re.sub(r'\*\*', '', text)
units = []
for para in text.splitlines():
    para = re.sub(r'^\s*[-*]\s+', '', para).strip()
    if not para: continue
    # split into sentences on . ? ! followed by space+capital, protect abbreviations
    para2 = re.sub(r'\b(e\.g|i\.e)\.', lambda m: m.group(0).replace('.', '~'), para)
    parts = re.split(r'(?<=[.!?])\s+(?=[A-Z(])', para2)
    for s in parts:
        s = s.strip()
        if s: units.append(s)
lens = [len(re.findall(r"\S+", s)) for s in units]
P('sentences:', len(units), 'avg words:', round(sum(lens) / len(lens), 1), 'max:', max(lens))
P('over 35 words:', [(l, u[:80]) for l, u in zip(lens, units) if l > 35] or 'none')
P('over 28 words:', [(l, u[:60]) for l, u in zip(lens, units) if l > 28] or 'none')
# acronyms
allowed_pre = set()
acr = re.compile(r'\b[A-Z][A-Z0-9]{1,}(?:-[A-Z0-9]+)*\b')
skip = re.compile(r'^(BUG|TM|MPL-\d+)')
seen_def = {}
for m in re.finditer(r'\(([A-Z][A-Za-z0-9\-]{1,})\)', doc):
    seen_def.setdefault(m.group(1), m.start())
problems = []
firsts = {}
for m in acr.finditer(doc):
    a = m.group(0)
    if a in firsts: continue
    firsts[a] = m.start()
ign = {'TM', 'BUG', 'MPL', 'AWS'}
for a, pos in sorted(firsts.items(), key=lambda x: x[1]):
    if re.match(r'^(BUG|TM)-', a) or a in ('TM-MPL',): continue
    d = seen_def.get(a)
    # defined if "(A)" occurs at or before first use or first use IS the definition
    if d is None or d > pos + len(a) + 2:
        problems.append((a, doc[max(0, pos - 25):pos + 25].replace('\n', ' ')))
P('acronyms with no spell-out at/before first use:')
for p in problems: P('  ', p)

# ---- check 6
P('\n## Check 6: links and paths')
paths = set(re.findall(r'`((?:docs|mpl|prim)/[^`]*)`', doc))
links = re.findall(r'\]\(([^)]+)\)', doc)
P('markdown links:', links or 'none')
for p in sorted(paths):
    P('  %-45s %s' % (p, 'exists' if os.path.exists(os.path.join(ROOT, p)) else 'MISSING'))

notes = '''
## Notes on the results

- Check 1 and 2: ratings come from the last Risk column of the source Appendix matrix. No mismatches.
- Check 3: BUG-07 is related to TM-MPL-011 in the bug README only through a verification target, not as a cause. The document names this in 'The risks that matter most' and leaves TM-MPL-011 out of the BUG-07 row. All other bug-to-threat links match the README.
- Check 4: the only hit is the word 'agent' in 'user agent'; the text now says 'request metadata'. The commit hash for the code state was left out on purpose (hard exclusion: no commit hashes).
- Check 5: the sentence splitter also splits bullet labels, so the average is lower than the true average. Longest unit is 26 words. Acronym flags left as they are: MPL in the title (spelled out in the first bullet), README (file name), SDK (part of the product name AWS Encryption SDK), STRIDE (a name, explained where it is first used).
- Check 6: the paths are written as code paths, not clickable links, so they do not break in Chorus.
'''
open(ROOT + '/.agents/tasks/threat-model-summary/checks.md', 'w').write('# Checks (generated by check.py)\n\n```\n' + '\n'.join(out) + '\n```\n' + notes)
print('\n'.join(out))
