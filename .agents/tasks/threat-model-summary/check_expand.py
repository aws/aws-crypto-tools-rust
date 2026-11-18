import re, os, collections
ROOT = '/Users/mahnush/Desktop/ESDK-Rust-Verus/MPL/esdk-native-mpl'
DOC = ROOT + '/docs/chorus/MPL-Threat-Model-Summary.md'
TM = open(ROOT + '/docs/mpl-threat-model.md').read()
BR = open(ROOT + '/docs/mpl-bug-reports/README.md').read()
doc = open(DOC).read()
out = []
def P(*a): out.append(' '.join(str(x) for x in a))

def sec(text, title, level=2):
    h = '#' * level + ' '
    m = re.search(r'^' + h + re.escape(title) + r'[^\n]*$', text, re.M)
    assert m, title
    rest = text[m.end():]
    n = re.search(r'^#{1,%d} ' % level, rest, re.M)
    return rest[:n.start()] if n else rest

def ids_in_first_col(txt, pat):
    r = []
    for l in txt.splitlines():
        m = re.match(r'\|\s*(' + pat + r')\s*\|', l)
        if m: r.append(m.group(1))
    return r

# ---------- Check 1: coverage
P('## Check 1: coverage of source sections 2 to 7')
s3 = sec(TM, '3. Assets'); s4 = sec(TM, '4. Actors'); s5 = sec(TM, '5. Trust Boundaries'); s7 = sec(TM, '7. Threat Identification')
src_A = ids_in_first_col(s3, r'A\d+')
src_TA = sorted(set(re.findall(r'\bTA\d+\b', s4)), key=lambda x: int(x[2:]))
src_TB = ids_in_first_col(s5, r'TB\d+')
src_5a = [l for l in sec(TM, '5a. Attacker-controlled', 3).splitlines() if l.startswith('| TB')]
d_assets = sec(doc, 'What we protect'); d_actors = sec(doc, 'Who could attack it'); d_tb = sec(doc, 'Trust boundaries')
d_A = ids_in_first_col(d_assets, r'A\d+'); d_TA = ids_in_first_col(d_actors, r'TA\d+'); d_TB = ids_in_first_col(d_tb, r'TB\d+')
P('assets source:', src_A); P('assets in summary table:', d_A, 'missing:', sorted(set(src_A) - set(d_A)) or 'none')
P('threat actors source:', src_TA); P('threat actors in summary table:', d_TA, 'missing:', sorted(set(src_TA) - set(d_TA)) or 'none')
legit = ['application caller', 'KMS', 'DynamoDB', 'operators']
P('legitimate actors (source line):', re.search(r'Legitimate:[^\n]*', s4).group(0))
leg_tab = sec(doc, 'Who could attack it').split('**Threat actors.**')[0]
P('legitimate actors in summary table:', {k: (k.lower() in leg_tab.lower()) for k in legit})
P('trust boundaries source:', src_TB); P('trust boundaries in summary table:', d_TB, 'missing:', sorted(set(src_TB) - set(d_TB)) or 'none')
d5a = [l for l in sec(doc, 'Inputs an attacker controls at each boundary', 3).splitlines() if l.startswith('| TB')]
P('5a rows source:', len(src_5a), 'summary:', len(d5a))
for a, b in zip(src_5a, d5a):
    sa = set('TM-MPL-%s' % x for x in re.findall(r'\b0\d\d\b', a.split('|')[-2]))
    sb = set(re.findall(r'TM-MPL-\d{3}', b))
    if sa != sb: P('  5a threat mismatch:', a[:40], sa, sb)
P('5a threat columns equal row by row:', all(set('TM-MPL-%s' % x for x in re.findall(r'\b0\d\d\b', a.split('|')[-2])) == set(re.findall(r'TM-MPL-\d{3}', b)) for a, b in zip(src_5a, d5a)))
# STRIDE groups
cats = ['Spoofing', 'Tampering', 'Repudiation', 'Information Disclosure', 'Denial of Service', 'Elevation of Privilege']
dst = sec(doc, 'Threats by type (STRIDE)')
allsrc7 = []
for c in cats:
    sids = ids_in_first_col(sec(s7 + '\n## end', c, 3) if False else re.search(r'### ' + c + r'\n(.*?)(?=\n### |\Z)', s7, re.S).group(1), r'TM-MPL-\d{3}')
    allsrc7 += sids
    m = re.search(r'### ' + c + r'\n(.*?)(?=\n### |\Z)', dst, re.S | re.I)
    dids = ids_in_first_col(m.group(1), r'TM-MPL-\d{3}') if m else []
    P('%-24s source %s | summary %s | equal order: %s' % (c, sids, dids, sids == dids))
P('section 7 threats:', len(allsrc7), 'unique:', len(set(allsrc7)))

# Section 2 and 6 mapping (explicit)
P('\nSection 2 components -> summary location')
comp2 = [
 ('Caller: ESDK, C++ shim, DB-ESDK, S3EC', 'Who calls it', 'Database Encryption SDK'),
 ('CMM front end send(): materials complete check', 'Main parts', 'CMM front end'),
 ('DefaultCmm: commitment policy + suite, ECDSA keygen, reproduced-EC merge', 'Main parts', 'reproduced context'),
 ('Keyring front end send(): transition check', 'Main parts', 'materials before the call'),
 ('RawAesKeyring', 'Main parts', 'Raw AES keyring.'),
 ('HierarchicalKeyring', 'Main parts', 'Hierarchical keyring.'),
 ('AES-GCM local wrapping key, zeroize on drop', 'Main parts', 'wiped from memory when it is dropped'),
 ('SharedCmc, DefaultCmc = StormTracking -> Local', 'Main parts', 'storm tracking on top of a local cache'),
 ('SharedKeyStore / DynamoDbKeyStore', 'Main parts', 'DynamoDB key store'),
 ('AWS KMS (EC as AAD)', 'Main parts', 'additional authenticated data (AAD)'),
 ('Amazon DynamoDB (branch-key records)', 'Where KMS and DynamoDB fit', 'DynamoDB stores the branch key records'),
 ('branch_key_wrap (KBKDF + AES-256-GCM, derived key zeroized)', 'Main parts', 'Branch key wrap.'),
 ('prim: AES-GCM/KBKDF/HKDF/HMAC/ECDSA/digest/RNG/ct-compare', 'Main parts', 'constant-time comparison'),
 ('aws-lc-rs (aws-lc-sys or FIPS) FFI', 'Main parts', 'foreign function interface (FFI)'),
 ('no unsafe in mpl/ or prim/', 'Main parts', 'contains no `unsafe` Rust'),
 ('C++ shim: borrowed raw handles, adopted void* keyring', 'Main parts', 'adopts an untyped keyring pointer'),
 ('Trust: process, wrapping key, cache trusted', 'Trust statement', 'in-process cache are trusted'),
 ('Trust: KMS root of trust for branch and beacon keys', 'Trust statement', 'root of trust for branch keys and beacon keys'),
 ('Trust: DynamoDB untrusted, tamper-evident not fresh', 'Trust statement', 'not prove freshness'),
 ('Trust: aws-lc-rs only via safe prim wrappers', 'Trust statement', 'only through the safe wrappers'),
 ('Trust: user KeyStore/Cmc/Supplier trusted, not validated (TB7)', 'Trust statement', '(TB7)'),
 ('Trust: C++ raw handles (TB8)', 'Trust statement', '(TB8)'),
 ('Trust: ciphertext sender untrusted (TB1, 5a)', 'Trust statement', 'sender of a ciphertext is not trusted'),
 ('Diagram', 'System diagram', 'C++ callers --> C++ shim'),
]
P('| Source item | Summary section | Found |'); P('|---|---|---|')
for item, where, needle in comp2:
    found = needle in sec(doc, where, 3)
    P('| %s | %s | %s |' % (item, where, 'yes' if found else 'NO'))
P('\nSection 6 flow steps -> summary location')
enc = sec(doc, 'Encrypt with the hierarchical keyring', 3); dec = sec(doc, 'Decrypt with the hierarchical keyring', 3)
flow = [
 ('E: caller EC -> CMM get_encryption_materials', enc, '1. The caller passes an encryption context'),
 ('E: suite = policy default or requested (allows_for_encrypt)', enc, '2. The default CMM picks'),
 ('E: reserved key check; ECDSA keygen (BUG-05a)', enc, '3. The CMM rejects'),
 ('E: keyring on_encrypt; resolve branch key id (static | supplier)', enc, '4. The CMM calls the keyring'),
 ('E: cache_id = SHA384(...) (BUG-06)', enc, '5. The keyring builds the cache ID'),
 ('E: cache hit (elapsed <= ttl)', enc, '6. If the cache holds'),
 ('E: KeyStore get_active_branch_key; KMS Decrypt with auth EC as AAD; Discovery uses record ARN', enc, '7. On a cache miss'),
 ('E: put cache expiry = now + ttl unchecked (BUG-01)', enc, '8. The keyring stores'),
 ('E: wrap KBKDF(salt) -> derived key zeroized; AES-256-GCM(iv, aad=label,bkid,ver,EC)', enc, '9. The keyring wraps'),
 ('E: EDK kpid/kpinfo/ct layout', enc, '10. The result is an EDK'),
 ('E: transition check; materials complete check', enc, '11. The keyring front end'),
 ('D: EDKs + reproduced EC -> CMM decrypt_materials', dec, '1. The caller passes the EDKs'),
 ('D: allows_for_decrypt; merge reproduced EC; verification key', dec, '2. The CMM checks'),
 ('D: keyring on_decrypt filter kpid, UTF-8 kpinfo, bkid equality', dec, '3. The CMM calls the keyring'),
 ('D: for each matching EDK sequentially', dec, '4. The keyring tries'),
 ('D: len >= 44, version = ct[28..44], 60 later (BUG-05b)', dec, 'at least 44 bytes'),
 ('D: cache_id with version', dec, 'the branch key ID and the version'),
 ('D: cache hit or get_branch_key_version; failure not cached; in-flight mark stays (TM-025)', dec, 'A failed key store read is not cached'),
 ('D: unwrap len >= 60; KBKDF; AES-256-GCM open', dec, 'It requires at least 60 bytes'),
 ('D: add_data_key length checked -> transition -> complete', dec, '5. The keyring adds the data key'),
 ('Encrypt ASCII diagram', enc, 'caller context --> CMM'),
 ('Decrypt ASCII diagram', dec, 'EDKs + reproduced context --> CMM'),
]
P('| Source step | Found in summary |'); P('|---|---|')
for item, txt, needle in flow:
    P('| %s | %s |' % (item, 'yes' if needle in txt else 'NO'))

# ---------- Check 2
P('\n## Check 2: ratings and counts')
app = TM[TM.index('## Appendix: Threat Risk Matrix'):TM.index('## Impact on verification targets')]
src = {}
for line in app.splitlines():
    m = re.match(r'\|\s*(TM-MPL-\d{3})\s*\|.*\|', line)
    if m:
        cells = [c.strip().strip('*') for c in line.strip().strip('|').split('|')]
        src[cells[0]] = cells[6]
ids = ['TM-MPL-%03d' % i for i in range(1, 27)]
def rows(txt):
    r = {}
    for line in txt.splitlines():
        if line.startswith('| TM-MPL-'):
            c = [x.strip() for x in line.strip().strip('|').split('|')]; r[c[0]] = c
    return r
g = rows(sec(doc, 'All threats at a glance')); b = rows(sec(doc, 'Appendix B: Threat table in AWS template form'))
mism = []
for i in ids:
    if i not in g or g[i][2] != src[i]: mism.append((i, 'glance'))
    if i not in b or b[i][1] != src[i]: mism.append((i, 'appB'))
    if i in g and i in b and g[i][3] != b[i][7]: mism.append((i, 'status'))
P('source matrix IDs:', len(src), '| glance rows:', len(g), '| appB rows:', len(b), '| mismatches:', mism or 'none')
sc = collections.Counter(src.values())
P('source counts H/M/L:', sc['High'], sc['Medium'], sc['Low'])
m = re.search(r'\| Threats by rating \| (\d+) \| (\d+) \| (\d+) \| (\d+) \|', doc)
P('summary counts:', m.groups(), 'equal:', tuple(map(int, m.groups())) == (sc['High'], sc['Medium'], sc['Low'], 26))
bugs = {}
for line in BR.splitlines():
    mm = re.match(r'\| \[(BUG-\d\d)\]', line)
    if mm:
        c = [x.strip() for x in line.strip().strip('|').split('|')]
        bugs[mm.group(1)] = ('High' if c[3].startswith('High') else c[3], 'Fixed' if c[6].startswith('Fixed') else 'Open')
d7 = {}
for line in sec(doc, 'Known problems found').splitlines():
    mm = re.match(r'\| (BUG-\d\d) \|', line)
    if mm:
        c = [x.strip() for x in line.strip().strip('|').split('|')]; d7[c[0]] = (c[2], c[3])
fixed = sorted(k for k, v in bugs.items() if v[1] == 'Fixed')
P('bugs source:', len(bugs), 'fixed:', fixed, 'open:', len(bugs) - len(fixed), '| summary table equals source:', d7 == bugs)
P('summary bug counts row:', re.search(r'\| Count \| (\d+) \| (\d+) \| (\d+) \|', doc).groups())
P('open by severity:', dict(collections.Counter(v[0] for v in bugs.values() if v[1] == 'Open')))

# ---------- Check 3
P('\n## Check 3: exclusion grep')
pats = [r'second pass', r'first pass', r'\bsince\b', r'previously', r'\braised\b', r'\blowered\b', r'changed from', r'Changes since',
        r'VR-', r' T0', r' C0', r'\bT\d\d\b', r'\bC\d\d\b', r'\.rs:', r'\.rs\b', r'file:line', r'mermaid', r'\b[0-9a-f]{7,40}\b',
        r'<[a-zA-Z/][^>]*>', r'\[\^', '\u2014', '\u2013', r'\bpipeline\b', r'\bagent\b', r'\bworkflow\b', r'\bnew:', r'\bproofs? count', r'\bmerge[ds]? (into|from) ']
for p in pats:
    f = [doc[max(0, mm.start() - 30):mm.end() + 30].replace('\n', ' ') for mm in re.finditer(p, doc, 0 if p in ('VR-', ' T0', ' C0') else re.I)]
    P('%-26s %s' % (p, 'clean' if not f else f[:5]))
P('non-ASCII characters:', sorted(set(c for c in doc if ord(c) > 127)) or 'none')

# ---------- Check 4
P('\n## Check 4: words, sentences, acronyms')
body = doc[doc.index('## Summary'):doc.index('## Appendix A')]
body_nc = re.sub(r'```.*?```', '', body, flags=re.S)
body_nt = '\n'.join(l for l in body_nc.splitlines() if not l.strip().startswith('|'))
words = re.findall(r"[A-Za-z0-9][A-Za-z0-9'\-+/.]*", re.sub(r'`[^`]*`', ' x ', body_nt))
P('prose words, Summary to Where to read more, no tables, no code blocks:', len(words))
text = re.sub(r'`([^`]*)`', r'\1', body_nt); text = re.sub(r'^#+ .*$', '', text, flags=re.M); text = text.replace('**', '')
units = []
for para in text.splitlines():
    para = re.sub(r'^\s*(?:[-*]|\d+\.)\s+', '', para).strip()
    if not para: continue
    for s in re.split(r'(?<=[.!?])\s+(?=[A-Z(])', para):
        if s.strip(): units.append(s.strip())
lens = [len(s.split()) for s in units]
P('sentences:', len(units), 'average words:', round(sum(lens) / len(lens), 1), 'max:', max(lens))
P('over 35 words:', [(l, u[:70]) for l, u in zip(lens, units) if l > 35] or 'none')
P('over 25 words:', [(l, u[:70]) for l, u in zip(lens, units) if l > 25] or 'none')
acr = re.compile(r'\b[A-Z][A-Z0-9]{1,}\b')
defs = {}
for mm in re.finditer(r'\(([A-Z][A-Za-z0-9\-]{1,})\)', doc): defs.setdefault(mm.group(1), mm.start())
first = {}
for mm in acr.finditer(doc): first.setdefault(mm.group(0), mm.start())
probs = []
for a, pos in sorted(first.items(), key=lambda x: x[1]):
    if a in ('TM', 'BUG', 'MPL') and doc[pos:pos + 4] in ('TM-M', 'BUG-'): continue
    if re.fullmatch(r'(A|TA|TB)\d+', a): continue  # traceability IDs, not acronyms
    d = defs.get(a)
    if d is None or d > pos + len(a) + 2:
        probs.append((a, doc[max(0, pos - 25):pos + 25].replace('\n', ' ')))
P('acronyms with no "(X)" spell-out at or before first use:')
for p in probs: P('  ', p)

# ---------- Check 5
P('\n## Check 5: links and paths')
paths = set(re.findall(r'`((?:docs|mpl|prim)/[^`]*)`', doc))
P('markdown links:', re.findall(r'\]\(([^)]+)\)', doc) or 'none')
for p in sorted(paths): P('  %-40s %s' % (p, 'exists' if os.path.exists(os.path.join(ROOT, p)) else 'MISSING'))

# ---------- Check 6
P('\n## Check 6: markdown sanity')
lines = doc.splitlines(); infence = False; prev = 0; bad_h = []; fences = 0; tbl_bad = []; widths = []
i = 0
while i < len(lines):
    l = lines[i]
    if l.startswith('```'):
        infence = not infence; fences += 1; i += 1; continue
    if infence:
        widths.append(len(l)); i += 1; continue
    m = re.match(r'^(#+) ', l)
    if m:
        lv = len(m.group(1))
        if lv > prev + 1: bad_h.append(l)
        prev = lv
    if l.startswith('|'):
        n = l.count('|') - l.count('\\|'); j = i
        while j < len(lines) and lines[j].startswith('|'):
            if lines[j].count('|') - lines[j].count('\\|') != n: tbl_bad.append(lines[j][:50])
            j += 1
        i = j; continue
    i += 1
P('heading level jumps:', bad_h or 'none'); P('fence markers:', fences, 'balanced:', fences % 2 == 0)
P('tables with inconsistent column counts:', tbl_bad or 'none'); P('max code block line width:', max(widths))
open(ROOT + '/.agents/tasks/threat-model-summary/checks-expand.md', 'w').write(
    '# Checks for the expanded summary (generated by check_expand.py)\n\n```\n' + '\n'.join(out) + '\n```\n' + open(ROOT + '/.agents/tasks/threat-model-summary/checks-expand-notes.md').read())
print('\n'.join(out))
