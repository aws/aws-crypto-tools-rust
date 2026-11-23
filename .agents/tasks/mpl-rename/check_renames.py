#!/usr/bin/env python3
"""For every file renamed vs HEAD (git diff -M HEAD): apply the path-rewrite rule to the HEAD content and require it to equal the
working-tree content. Proves the only differences are path/link text. Also reports the RECHECK snapshot diff."""
import re, subprocess, sys, difflib
G = ['git', '-C', sys.argv[1]]
OLD = r'(?:threat-model|spec-security-analysis|verification-targets|completeness-audit|bug-reports)'
R1 = re.compile(r'(?<![A-Za-z0-9_-])docs/(' + OLD + r')(?![A-Za-z0-9_-])(?!-)')
R2 = re.compile(r'(?<![A-Za-z0-9_-])(?<!tasks/)(?<!docs/)(?<!mpl-)(threat-model\.md|spec-security-analysis\.md|verification-targets\.md|verification-targets/|completeness-audit\.md|bug-reports\b)')


def rule(t):
    t = R1.sub(lambda m: 'docs/mpl-' + m.group(1), t)
    return R2.sub(lambda m: 'mpl-' + m.group(1), t)


def run(*a):
    return subprocess.run(G + list(a), capture_output=True, text=True).stdout


names = run('diff', '-M', '--name-status', 'HEAD').splitlines()
bad = 0
n = 0
changed_lines = 0
for l in names:
    p = l.split('\t')
    st = p[0]
    if st.startswith('R'):
        old, new = p[1], p[2]
    elif st == 'M':
        old = new = p[1]
    else:
        print('OTHER', l); continue
    if not new.endswith('.md'):
        continue
    n += 1
    a = run('show', 'HEAD:' + old)
    b = open(sys.argv[1] + '/' + new, encoding='utf-8').read()
    inv = re.sub(r'mpl-(?=' + OLD + r')', '', b)
    ok = rule(a) == b and inv == a   # forward rule AND independent inverse (strip the added prefix -> HEAD text)
    pure = (a == b)
    nl = sum(1 for x, y in zip(a.splitlines(), b.splitlines()) if x != y)
    changed_lines += nl
    if not ok:
        bad += 1
        print('NOT PATH-ONLY:', old, '->', new)
        for d in list(difflib.unified_diff(rule(a).splitlines(), b.splitlines(), lineterm='', n=0))[:20]:
            print('   ', d)
print(f'md files compared: {n}; path-only violations: {bad}; total lines with path/link text changed: {changed_lines}')
sys.exit(1 if bad else 0)
