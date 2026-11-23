#!/bin/bash
# Verification for the mpl- rename. Run from anywhere. Output is saved to verify-output.txt by the caller.
R=/Users/mahnush/Desktop/ESDK-Rust-Verus/MPL/esdk-native-mpl
N=$R/.agents/tasks/mpl-rename
G="git -C $R"
cd $R
OLDRE='docs/(threat-model|spec-security-analysis|verification-targets|completeness-audit|bug-reports)'
echo "=== 0. state: branch / HEAD"; $G branch --show-current; $G rev-parse --short HEAD
echo; echo "=== 1. renames (git status --short; git diff -M HEAD --summary / --stat)"
$G status --short
echo "--- rename summary (similarity)"; $G diff -M HEAD --summary | grep -E 'rename|delete|create'
echo "--- count of renames: $($G diff -M HEAD --summary | grep -c 'rename')   (expected 19 = 4 top-level docs + 3 files in verification-targets/ + 12 files in bug-reports/)"
echo "--- path-only proof for every renamed/modified .md (forward rule + inverse)"
python3 $N/check_renames.py $R; echo "exit $?"
echo "--- RECHECK snapshot: line diff old->new (only path/link text may differ)"
$G show HEAD:docs/bug-reports/RECHECK-main-620771c.md > /tmp/recheck-old.md
diff /tmp/recheck-old.md docs/mpl-bug-reports/RECHECK-main-620771c.md | grep '^[<>]' | sed 's/^\(.\) /\1 /' | cut -c1-170
echo "--- RECHECK with the path rewrite undone (strip 'mpl-' on renamed names) vs HEAD: must be identical"
sed -E 's#mpl-(threat-model|spec-security-analysis|verification-targets|completeness-audit|bug-reports)#\1#g' docs/mpl-bug-reports/RECHECK-main-620771c.md | diff - /tmp/recheck-old.md && echo "RECHECK identical apart from path text"
echo; echo "=== 2. link checker (docs/ + verus-proofs/ *.md): working tree vs HEAD"
rm -rf /tmp/mpl-head && mkdir /tmp/mpl-head && $G archive HEAD | tar -x -C /tmp/mpl-head
( cd /tmp/mpl-head && git init -q && git add -A >/dev/null 2>&1 && git -c user.email=a@b -c user.name=x commit -qm base >/dev/null 2>&1 )
python3 $N/check_links.py $R > /tmp/links-new.tsv
python3 $N/check_links.py /tmp/mpl-head > /tmp/links-head.tsv
echo "unresolved now: $(wc -l < /tmp/links-new.tsv); unresolved at HEAD: $(wc -l < /tmp/links-head.tsv)"
python3 - <<'P'
import re
OLD=r'(?:threat-model|spec-security-analysis|verification-targets|completeness-audit|bug-reports)'
R1=re.compile(r'(?<![A-Za-z0-9_-])docs/('+OLD+r')(?![A-Za-z0-9_-])(?!-)')
R2=re.compile(r'(?<![A-Za-z0-9_-])(?<!tasks/)(?<!docs/)(?<!mpl-)(threat-model\.md|spec-security-analysis\.md|verification-targets\.md|verification-targets/|completeness-audit\.md|bug-reports\b)')
def m(s): return R2.sub(lambda x:'mpl-'+x.group(1),R1.sub(lambda x:'docs/mpl-'+x.group(1),s))
new=set(tuple(l.rstrip('\n').split('\t')) for l in open('/tmp/links-new.tsv'))
head=set(tuple(m(c) for c in l.rstrip('\n').split('\t')) for l in open('/tmp/links-head.tsv'))
print("NEW unresolved (not present at HEAD after mapping old->new names):", len(new-head))
for x in sorted(new-head): print("   NEW ", x)
print("pre-existing unresolved (same at HEAD, shown with new names):", len(new&head))
for x in sorted(new&head): print("   PRE ", x)
print("fixed vs HEAD:", len(head-new))
for x in sorted(head-new): print("   GONE", x)
P
echo; echo "=== 3. old paths left in docs/ verus-proofs/*.md .kiro/ ../.kiro/ (must be empty except listed .rs)"
grep -rnE "(^|[^A-Za-z0-9_-])$OLDRE" docs verus-proofs/*.md .kiro ../.kiro --include='*.md' ; echo "grep .md exit $? (1 = none found)"
echo "--- old bare names (threat-model.md, spec-security-analysis.md, verification-targets.md, completeness-audit.md, bug-reports/) not preceded by mpl-/tasks/"
grep -rnE "(^|[^A-Za-z0-9_/-])(threat-model\.md|spec-security-analysis\.md|verification-targets\.md|verification-targets/|completeness-audit\.md|bug-reports/)" docs verus-proofs/*.md .kiro ../.kiro --include='*.md'; echo "exit $? (1 = none)"
echo "--- chorus .docx text (plain) for old paths"
for f in docs/chorus/*.docx; do echo "$f: $(/opt/homebrew/bin/pandoc $f -t plain | grep -cE "$OLDRE") old-path lines"; done
echo "--- .rs files mentioning old docs paths (known stale, left as is)"
grep -rnE "$OLDRE" verus-proofs/*.rs | cut -c1-170
echo "--- other repo files outside .agents/tasks mentioning old paths"
grep -rlE "$OLDRE" . --exclude-dir=.git --exclude-dir=target --exclude-dir=.agents 2>/dev/null
echo "--- scripts under .agents with old docs paths remaining (historical or one-shot)"
grep -rlE "$OLDRE" .agents --include='*.py' --include='*.sh' | grep -v tasks/mpl-rename | sort
echo; echo "=== 4. checker scripts"
for s in docs-sync-9955ecd/check_scores.py; do echo "--- $s"; python3 .agents/tasks/$s | tail -2; done
for s in check_threat_refs check_ratings check_stride_map check_prose_scores check_extras check_misc check_bug_xrefs check_chorus_consistency check_citations check_fn_defs; do echo "--- $s (new paths)"; python3 .agents/tasks/docs-sync-9955ecd/$s.py 2>&1 | tail -3 | cut -c1-200; done
echo "--- pipeline-rerun-620771c/check_scores.py"; python3 .agents/tasks/pipeline-rerun-620771c/check_scores.py | tail -1
echo "--- every check_*.py in docs-sync-9955ecd: full output at pristine HEAD (HEAD scripts + HEAD docs in /tmp/mpl-head) vs working tree (changed scripts + renamed docs); identical after removing the 'mpl-' prefix (tab columns 1-4 only: the 5th/6th columns are a text snippet whose window shifts by the 4-char prefix)?"
for s in $(cd $R/.agents/tasks/docs-sync-9955ecd && ls check_*.py) ; do
  ( cd /tmp/mpl-head && python3 .agents/tasks/docs-sync-9955ecd/$s 2>&1 | sed 's/mpl-//g' | cut -f1-4 > /tmp/cs-head-$s.txt )
  python3 .agents/tasks/docs-sync-9955ecd/$s 2>&1 | sed 's/mpl-//g' | cut -f1-4 > /tmp/cs-new-$s.txt
  if diff -q /tmp/cs-head-$s.txt /tmp/cs-new-$s.txt >/dev/null; then echo "same output  $s ($(wc -l < /tmp/cs-new-$s.txt) lines)"; else echo "DIFFERENT    $s"; diff /tmp/cs-head-$s.txt /tmp/cs-new-$s.txt | head -5; fi
done
for s in check_scores check_citations check_fn_defs; do
  ( cd /tmp/mpl-head && python3 .agents/tasks/pipeline-rerun-620771c/$s.py 2>&1 | sed 's/mpl-//g' | cut -f1-4 > /tmp/cp-head-$s.txt )
  python3 .agents/tasks/pipeline-rerun-620771c/$s.py 2>&1 | sed 's/mpl-//g' | cut -f1-4 > /tmp/cp-new-$s.txt
  diff -q /tmp/cp-head-$s.txt /tmp/cp-new-$s.txt >/dev/null && echo "same output  pipeline-rerun-620771c/$s.py" || echo "DIFFERENT    pipeline-rerun-620771c/$s.py"
done
echo "--- 'HTML tag outside code' in BUG-10 is pre-existing? (same regex on HEAD file)"
$G show HEAD:docs/bug-reports/BUG-10-raw-aes-on-decrypt-unwiped-data-key.md | python3 -c "
import re,sys; t=sys.stdin.read(); b=re.sub(r'\`\`\`.*?\`\`\`','',t,flags=re.S); b=re.sub(r'\`[^\`\n]*\`','',b); print(re.findall(r'</?[a-zA-Z][^>]*>',b)[:3])"
echo "--- check_proof_status.py: baseline (pristine HEAD copy in /tmp/mpl-head, same script) vs working tree"
( cd /tmp/mpl-head && python3 .agents/tasks/docs-proof-status/check_proof_status.py 2>&1 | grep -v 'status outside' | sed 's/mpl-//g' > /tmp/cps-head.txt )
python3 .agents/tasks/docs-proof-status/check_proof_status.py 2>&1 | grep -v 'status outside' | sed 's/mpl-//g' > /tmp/cps-new.txt
echo "problem lines: HEAD baseline $(grep -c '^  - ' /tmp/cps-head.txt) vs now $(grep -c '^  - ' /tmp/cps-new.txt); differences:"; diff /tmp/cps-head.txt /tmp/cps-new.txt
echo "(the script already reports problems on pristine HEAD, it is a one-shot post-edit validator; the differences above come from the dirty tree: it format-checks changed files and its diff guard sees the renamed RECHECK/README paths)"
echo "--- rank+score columns of the ranked tables: HEAD old paths vs working tree new paths"
: > /tmp/rs-head.txt; : > /tmp/rs-now.txt
ext() { grep -E '^\| ([0-9]+|—) \| ' | awk -F'|' -v c="$1" 'BEGIN{n=split(c,a,",")} {s="row"; for(i=1;i<=n;i++){x=$(a[i]); gsub(/^ +| +$/,"",x); s=s" | "x} print s}'; }
for spec in "verification-targets.md:2,3" "verification-targets/01-threat-driven.md:2,3,4" "verification-targets/02-capability-driven.md:2,3,4"; do
  f=${spec%%:*}; cols=${spec##*:}
  { echo "## $f"; $G show HEAD:docs/$f | ext $cols; } >> /tmp/rs-head.txt
  { echo "## $f"; cat docs/mpl-$f | ext $cols; } >> /tmp/rs-now.txt
done
wc -l /tmp/rs-head.txt /tmp/rs-now.txt | head -3; diff /tmp/rs-head.txt /tmp/rs-now.txt && echo "rank+score columns IDENTICAL"
echo; echo "=== 5. code unchanged"
$G diff --quiet HEAD -- mpl prim esdk; echo "git diff --quiet HEAD -- mpl prim esdk: exit $?"
$G diff --quiet HEAD -- 'verus-proofs/*.rs'; echo "git diff --quiet HEAD -- 'verus-proofs/*.rs': exit $?"
echo "untracked/changed under mpl prim esdk or verus-proofs/*.rs:"; $G status --short -- mpl prim esdk 'verus-proofs/*.rs' | wc -l
echo "verus-proofs changes (only the two READMEs expected):"; $G status --short -- verus-proofs
echo "sha256 of verus-proofs/*.rs working tree vs HEAD:"
for f in verus-proofs/*.rs; do a=$(shasum -a 256 < $f | cut -c1-16); b=$($G show HEAD:$f | shasum -a 256 | cut -c1-16); [ "$a" = "$b" ] && echo "same $f $a" || echo "DIFF $f"; done
echo; echo "=== 6. .kiro/agents copies byte-identical"
diff -r $R/.kiro/agents /Users/mahnush/Desktop/ESDK-Rust-Verus/MPL/.kiro/agents && echo "IDENTICAL"
$G diff --stat HEAD -- .kiro
echo; echo "=== 7. no file at old paths, no empty dirs"
for p in docs/threat-model.md docs/spec-security-analysis.md docs/verification-targets.md docs/verification-targets docs/completeness-audit.md docs/bug-reports; do [ -e $p ] && echo "EXISTS $p" || echo "absent $p"; done
echo "empty dirs under docs: $(find docs -type d -empty | wc -l)"; ls -R docs | head -50
echo; echo "=== 8. collisions with origin/Mahnush_Verus"
$G ls-tree -r --name-only origin/Mahnush_Verus | sort > /tmp/mv-paths.txt
$G ls-files | sort > /tmp/mine-paths.txt
echo "origin/Mahnush_Verus tip: $($G rev-parse --short origin/Mahnush_Verus)"
echo "--- comm -12, docs/ only, tracked files after rename"; comm -12 <(grep '^docs/' /tmp/mine-paths.txt) <(grep '^docs/' /tmp/mv-paths.txt); echo "(end; empty above = no docs/ collision)"
echo "--- comm -12 at HEAD (before rename), docs/ only"; comm -12 <($G ls-tree -r --name-only HEAD | grep '^docs/' | sort) <(grep '^docs/' /tmp/mv-paths.txt)
echo "--- paths outside docs/ present on both branches (same path) with DIFFERENT content (real collisions); identical-content shared paths are not listed"
$G ls-tree -r origin/Mahnush_Verus | awk '{print $3" "$4}' | sort -k2 > /tmp/mv-blobs.txt
$G ls-files -s | awk '{print $2" "$4}' | sort -k2 > /tmp/mine-blobs.txt
join -1 2 -2 2 /tmp/mine-blobs.txt /tmp/mv-blobs.txt | awk '$2 != $3 {print $1}' | grep -v '^docs/'
echo "(end)"
echo "--- number of shared paths outside docs/ (identical content, no conflict): $(join -1 2 -2 2 /tmp/mine-blobs.txt /tmp/mv-blobs.txt | awk '$2 == $3 {print $1}' | grep -vc '^docs/')"
echo "--- .kiro/agents, .kiro/skills and verus-proofs paths on Mahnush_Verus vs here"
$G ls-tree -r --name-only origin/Mahnush_Verus | grep -E '^(verus-proofs|\.agents)/' | head -5; echo "(.agents/ and verus-proofs/ paths on Mahnush_Verus shown above, if any)"
echo; echo "=== 9. docx"
ls -l docs/chorus/*.docx; for f in docs/chorus/*.docx; do echo "$f"; /opt/homebrew/bin/pandoc $f -t plain | head -2; done
echo; echo "=== 10. final git status"; $G status --short
