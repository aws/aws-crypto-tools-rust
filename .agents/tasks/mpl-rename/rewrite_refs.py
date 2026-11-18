#!/usr/bin/env python3
"""Rewrite references to the renamed MPL docs. Usage: rewrite_refs.py FILE... ; prints per-file replacement counts.
Rule 1: docs/<old> -> docs/mpl-<old>.  Rule 2 (markdown only): bare relative names (not preceded by [A-Za-z0-9_-], 'tasks/', 'docs/', 'mpl-')."""
import re, sys
OLD = r'(?:threat-model|spec-security-analysis|verification-targets|completeness-audit|bug-reports)'
R1 = re.compile(r'(?<![A-Za-z0-9_-])docs/(' + OLD + r')(?![A-Za-z0-9_-])(?!-)')
R2 = re.compile(r'(?<![A-Za-z0-9_-])(?<!tasks/)(?<!docs/)(?<!mpl-)(threat-model\.md|spec-security-analysis\.md|verification-targets\.md|verification-targets/|completeness-audit\.md|bug-reports\b)')
md_only = '--bare' in sys.argv
tot = 0
for f in [a for a in sys.argv[1:] if not a.startswith('--')]:
    t = open(f, encoding='utf-8').read()
    n1 = len(R1.findall(t)); t2 = R1.sub(lambda m: 'docs/mpl-' + m.group(1), t)
    n2 = 0
    if md_only:
        n2 = len(R2.findall(t2)); t2 = R2.sub(lambda m: 'mpl-' + m.group(1), t2)
    if t2 != t:
        open(f, 'w', encoding='utf-8').write(t2)
    print(f"{f}\tdocs-prefixed={n1}\tbare={n2}")
    tot += n1 + n2
print("TOTAL", tot)
