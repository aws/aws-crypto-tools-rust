#!/usr/bin/env python3
"""Rewrite old MPL agent/skill identifiers to the mpl- names. Usage: rewrite_ids.py FILE... ; prints per-file counts.
Word-boundary: the old name must not be preceded/followed by [A-Za-z0-9_-] (so mpl-<old> and longer names are untouched,
and the rule cannot apply twice). Skill: the backticked `verus` followed by ' skill', frontmatter 'name: verus' in SKILL.md,
and the path .kiro/skills/verus/ ."""
import re, sys
AGENTS = ['ai-verification-pipeline', 'spec-analyzer', 'threat-model-generator', 'verification-recommender',
          'verus-capabilities', 'verus-header-parsing-proofs', 'verus-unsafe-ffi-safety', 'verus-zero-panic']
AG = re.compile(r'(?<![A-Za-z0-9_-])(' + '|'.join(sorted(AGENTS, key=len, reverse=True)) + r')(?![A-Za-z0-9_-])')
SK1 = re.compile(r'`verus`( skill)')
SK2 = re.compile(r'(?<![A-Za-z0-9_-])(\.kiro/skills/)verus/')
SK3 = re.compile(r'(?<![A-Za-z0-9_-])skill::verus(?![A-Za-z0-9_-])')
tot = 0
for f in sys.argv[1:]:
    t = open(f, encoding='utf-8').read()
    t2, n1 = AG.subn(lambda m: 'mpl-' + m.group(1), t)
    t2, n2 = SK1.subn(lambda m: '`mpl-verus`' + m.group(1), t2)
    t2, n3 = SK2.subn(lambda m: m.group(1) + 'mpl-verus/', t2)
    t2, n4 = SK3.subn('skill::mpl-verus', t2)
    n5 = 0
    if f.endswith('SKILL.md'):
        t2, n5 = re.subn(r'\A(---\nname: )verus\n', r'\1mpl-verus\n', t2)
    if t2 != t:
        open(f, 'w', encoding='utf-8').write(t2)
    print(f"{f}\tagents={n1}\tskill-refs={n2+n3+n4}\tskill-name={n5}")
    tot += n1 + n2 + n3 + n4 + n5
print("TOTAL", tot)
