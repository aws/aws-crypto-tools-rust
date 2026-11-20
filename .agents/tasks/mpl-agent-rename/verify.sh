#!/bin/bash
# Verification for the mpl- agent/skill rename. Run from anywhere; output is saved to verify-output.txt by the caller.
W=/Users/mahnush/Desktop/ESDK-Rust-Verus/MPL
R=$W/esdk-native-mpl
N=$R/.agents/tasks/mpl-agent-rename
G="git -C $R"
cd $R
AG='ai-verification-pipeline|spec-analyzer|threat-model-generator|verification-recommender|verus-capabilities|verus-header-parsing-proofs|verus-unsafe-ffi-safety|verus-zero-panic'
OLDRE="(^|[^A-Za-z0-9_-])($AG)([^A-Za-z0-9_-]|\$)"
FAIL=0
echo "=== 0. state"; $G branch --show-current; $G rev-parse --short HEAD

echo; echo "=== 1. structure"
echo "--- .kiro copies byte-identical (workspace vs repo; .DS_Store ignored, it is untracked Finder metadata)"
diff -r -x .DS_Store $W/.kiro $R/.kiro && echo "IDENTICAL"
echo "--- file lists"; (cd $R/.kiro && find . -type f ! -name .DS_Store | sort)
echo "--- frontmatter name == file stem (agents) and skill dir == skill name; name/description/tools present"
python3 - <<'P'
import os, re, sys
bad = 0
for base in ('/Users/mahnush/Desktop/ESDK-Rust-Verus/MPL/.kiro', '/Users/mahnush/Desktop/ESDK-Rust-Verus/MPL/esdk-native-mpl/.kiro'):
    for kind, pat in (('agents', None), ('skills', 'SKILL.md')):
        d = os.path.join(base, kind)
        items = sorted(os.listdir(d))
        for it in items:
            if it.startswith('.'): continue
            if kind == 'agents':
                path, stem = os.path.join(d, it), it[:-3]
            else:
                path, stem = os.path.join(d, it, 'SKILL.md'), it
            t = open(path, encoding='utf-8').read()
            m = re.match(r'---\n(.*?)\n---\n', t, re.S)
            fm = m.group(1) if m else ''
            name = re.search(r'^name:\s*(\S+)\s*$', fm, re.M)
            desc = re.search(r'^description:\s*\S', fm, re.M)
            tools = re.search(r'^tools:\s*\[', fm, re.M)
            ok = bool(name) and name.group(1) == stem and bool(desc) and (tools is not None or kind == 'skills') and stem.startswith('mpl-')
            if not ok: bad += 1
            print(('OK  ' if ok else 'BAD ') + base.split('/MPL/')[1], kind, stem, '| name=%s desc=%s tools=%s' % (name.group(1) if name else None, bool(desc), bool(tools)))
print('frontmatter problems:', bad)
P
echo "--- no file at any old path (both copies)"
for b in $W/.kiro $R/.kiro; do for a in ${AG//|/ }; do [ -e $b/agents/$a.md ] && echo "OLD PATH STILL EXISTS: $b/agents/$a.md"; done; [ -e $b/skills/verus ] && echo "OLD PATH STILL EXISTS: $b/skills/verus"; done; echo "(none listed above = pass)"
echo "--- git status (R = rename)"; $G status --short
echo "--- renames in index+worktree vs HEAD (git diff -M HEAD --summary): $($G diff -M HEAD --summary | grep -c 'rename') (expected 9)"
$G diff -M HEAD --summary | grep rename

echo; echo "=== 2. old identifiers left (must list only deliberate keeps; none expected in these areas)"
echo "--- docs/ verus-proofs/*.md .kiro/ and workspace .kiro/"
grep -rnIE "$OLDRE" docs verus-proofs/*.md .kiro $W/.kiro --exclude=.DS_Store; echo "exit $? (1 = none found)"
echo "--- backticked \`verus\` skill / skill::verus / .kiro/skills/verus/ / name: verus"
grep -rnIE '`verus` skill|skill::verus|\.kiro/skills/verus/|^name: verus$' docs verus-proofs/*.md .kiro $W/.kiro --exclude=.DS_Store; echo "exit $? (1 = none found)"
echo "--- mpl-mpl- anywhere in changed files / areas"
grep -rnI 'mpl-mpl-' docs verus-proofs .kiro $W/.kiro .agents/tasks/docs-sync-9955ecd/check_extras.py --exclude=.DS_Store; echo "exit $? (1 = none found)"
echo "--- old identifiers in verus-proofs/*.rs (informational; none expected)"
grep -nE "$AG" verus-proofs/*.rs; echo "exit $? (1 = none)"
echo "--- chorus .docx plain text"
for f in docs/chorus/*.docx; do echo "$f: $(/opt/homebrew/bin/pandoc $f -t plain | grep -cE "$OLDRE") lines with old identifiers; size $(stat -f%z $f) bytes"; /opt/homebrew/bin/pandoc $f -t plain | head -1; done

echo; echo "=== 3. every referenced path / agent name resolves"
python3 - <<'P'
import os, re, glob, subprocess
R = '/Users/mahnush/Desktop/ESDK-Rust-Verus/MPL/esdk-native-mpl'
W = '/Users/mahnush/Desktop/ESDK-Rust-Verus/MPL'
os.chdir(R)
files = [f for f in subprocess.run(['git','ls-files','docs','verus-proofs','.kiro'],capture_output=True,text=True).stdout.split() if f.endswith('.md')]
files = [f for f in files if os.path.exists(f)]
files += glob.glob('docs/**/*.md', recursive=True) + glob.glob('.kiro/**/*.md', recursive=True)
files = sorted(set(files))
pat = re.compile(r'\.kiro/(agents/[A-Za-z0-9_.-]+\.md|skills/[A-Za-z0-9_.-]+/SKILL\.md)')
bad = n = 0
for f in files:
    for m in pat.finditer(open(f, encoding='utf-8').read()):
        n += 1
        for base in (R, W):
            if not os.path.exists(os.path.join(base, '.kiro', m.group(1))):
                bad += 1; print('UNRESOLVED', f, m.group(0), 'in', base)
print('.kiro paths mentioned:', n, 'unresolved:', bad)
stems = {os.path.basename(p)[:-3] for p in glob.glob('.kiro/agents/*.md')} | {os.path.basename(os.path.dirname(p)) for p in glob.glob('.kiro/skills/*/SKILL.md')}
ids = re.compile(r'(?<![A-Za-z0-9_/-])(mpl-[a-z0-9-]*[a-z0-9])(?![A-Za-z0-9_-]|\.md)')  # skips docs paths (docs/mpl-x.md) and the branch duvet/mpl-annotations
bad2 = 0
for p in sorted(glob.glob('.kiro/agents/*.md') + glob.glob('.kiro/skills/*/SKILL.md')):
    t = open(p, encoding='utf-8').read()
    found = {m.group(1) for m in ids.finditer(t)}
    # only names that look like agent/skill ids we own; docs paths such as mpl-threat-model.md have a suffix and are skipped
    unknown = sorted(x for x in found if x not in stems)
    print(p, '-> mpl- names mentioned:', sorted(found), 'unresolved:', unknown)
    bad2 += len(unknown)
print('agent/skill names in agent bodies unresolved:', bad2)
# YAML agent: fields and 'Agent routing' in docs
y = 0; badagent = 0
for f in glob.glob('docs/**/*.md', recursive=True):
    for m in re.finditer(r'^\s*agent:\s*(\S+)', open(f, encoding='utf-8').read(), re.M):
        y += 1
        if m.group(1) not in stems: badagent += 1; print('UNRESOLVED agent field', f, m.group(1))
print('docs YAML agent: fields:', y, 'unresolved:', badagent)
P

echo; echo "=== 4. no content change beyond identifiers"
python3 - <<'P'
# Independent check: undo the rename on the working-tree text (strip the mpl- prefix on the 8 agent ids and the skill id)
# and compare with HEAD line by line. Renamed .kiro files are compared with their old path at HEAD.
import re, subprocess, os
R = '/Users/mahnush/Desktop/ESDK-Rust-Verus/MPL/esdk-native-mpl'
os.chdir(R)
AG = ['ai-verification-pipeline','spec-analyzer','threat-model-generator','verification-recommender','verus-capabilities','verus-header-parsing-proofs','verus-unsafe-ffi-safety','verus-zero-panic']
UN = re.compile(r'(?<![A-Za-z0-9_-])mpl-(' + '|'.join(AG) + r')(?![A-Za-z0-9_-])')
def undo(t):
    t = UN.sub(r'\1', t)
    t = t.replace('`mpl-verus` skill', '`verus` skill').replace('.kiro/skills/mpl-verus/', '.kiro/skills/verus/')
    t = re.sub(r'\A(---\nname: )mpl-verus\n', r'\1verus\n', t)
    return t
def head(p): return subprocess.run(['git','show','HEAD:'+p],capture_output=True,text=True).stdout
st = subprocess.run(['git','diff','-M','--name-status','HEAD'],capture_output=True,text=True).stdout.strip().splitlines()
bad = n = 0
for l in st:
    parts = l.split('\t')
    if parts[0].startswith('R'): old, new = parts[1], parts[2]
    elif parts[0] == 'M': old = new = parts[1]
    else: print('other status', l); continue
    if not new.endswith(('.md', '.py')): print('skip (binary/other):', new); continue
    a, b = head(old), undo(open(new, encoding='utf-8').read())
    same = a == b
    n += 1
    if not same: bad += 1
    print('IDENTICAL after undo' if same else 'DIFFERS             ', old, '->' if old != new else '', new if old != new else '')
print('files compared:', n, 'differing:', bad)
P
echo "--- files with zero agent identifiers must be byte-identical to HEAD (bug reports incl. RECHECK, chorus .md, verus-proofs READMEs)"
$G diff --quiet HEAD -- docs/mpl-bug-reports docs/chorus/MPL-Bug-Reports.md docs/chorus/MPL-Threat-Model.md verus-proofs/README.md verus-proofs/README-t03-t05.md && echo "byte-identical to HEAD: yes"
echo "--- check_scores.py"; python3 .agents/tasks/docs-sync-9955ecd/check_scores.py | tail -3
echo "--- check_extras.py (updated to new agent names)"; python3 .agents/tasks/docs-sync-9955ecd/check_extras.py | tail -8 | cut -c1-200
echo "--- rank+score columns of the ranked tables vs HEAD"
python3 - <<'P'
import re, subprocess, os
R = '/Users/mahnush/Desktop/ESDK-Rust-Verus/MPL/esdk-native-mpl'
os.chdir(R)
for p in ('docs/mpl-verification-targets.md','docs/mpl-verification-targets/01-threat-driven.md','docs/mpl-verification-targets/02-capability-driven.md'):
    cols = lambda t: [tuple(c.strip() for c in l.split('|')[1:5]) for l in t.splitlines() if re.match(r'^\| \d+ \| ', l)]
    now = cols(open(p, encoding='utf-8').read())
    hd = cols(subprocess.run(['git','show','HEAD:'+p],capture_output=True,text=True).stdout)
    print(p, 'rows', len(now), 'rank/score/id columns identical to HEAD:', now == hd)
P

echo; echo "=== 5. mpl/ prim/ esdk/ and verus-proofs/*.rs untouched"
$G diff --quiet HEAD -- mpl prim esdk 'verus-proofs/*.rs' && echo "git diff --quiet exit 0: OK"
$G status --short -- mpl prim esdk 'verus-proofs/*.rs' | wc -l | sed 's/^/ untracked-or-modified entries there: /'

echo; echo "=== 6. collisions with origin/Mahnush_Verus (.kiro)"
$G ls-tree -r --name-only origin/Mahnush_Verus | grep '^\.kiro/' | sort > /tmp/mv-kiro.txt
$G ls-files .kiro | sort > /tmp/mine-kiro.txt
echo "origin/Mahnush_Verus .kiro files: $(wc -l < /tmp/mv-kiro.txt); ours (tracked): $(wc -l < /tmp/mine-kiro.txt)"
echo "comm -12 (colliding paths; must be empty):"; comm -12 /tmp/mv-kiro.txt /tmp/mine-kiro.txt; echo "(end)"
echo "docs/ and verus-proofs/ colliding paths (informational):"; $G ls-tree -r --name-only origin/Mahnush_Verus | grep -E '^(docs/|verus-proofs/)' | sort > /tmp/mv-docs.txt; $G ls-files docs verus-proofs | sort | comm -12 /tmp/mv-docs.txt - ; echo "(end)"

echo; echo "=== 7. reference counts per area (old identifier occurrences at HEAD that were rewritten)"
for area in "docs/mpl-verification-targets.md" "docs/mpl-verification-targets/" "docs/mpl-threat-model.md" "docs/mpl-spec-security-analysis.md" "docs/mpl-completeness-audit.md" "docs/mpl-bug-reports/" "docs/chorus/" "verus-proofs/*.md" ".kiro/"; do
  c=$($G grep -hoE "(^|[^A-Za-z0-9_-])($AG)([^A-Za-z0-9_-]|\$)|\`verus\` skill" HEAD -- "$area" 2>/dev/null | wc -l | tr -d ' ')
  echo "$area : $c"
done
echo "(counts above are matches at HEAD; the rewrite_ids.py per-file counts are in rewrite-counts-repo.txt)"
