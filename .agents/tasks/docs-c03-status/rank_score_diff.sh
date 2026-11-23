#!/bin/bash
# Extracts rank+score(+ID) columns of every ranked table row at HEAD and in the working tree, and diffs them.
cd "$(dirname "$0")/../../.."
N=.agents/tasks/docs-c03-status
: > $N/rank-score.head.txt; : > $N/rank-score.now.txt
ext() { grep -E '^\| ([0-9]+|—) \| ' | awk -F'|' -v c="$2" -v f="$1" 'BEGIN{n=split(c,a,",")} {s=f; for(i=1;i<=n;i++){x=$(a[i]); gsub(/^ +| +$/,"",x); s=s" | "x} print s}'; }
for spec in "docs/verification-targets.md:2,3" "docs/verification-targets/01-threat-driven.md:2,3,4" "docs/verification-targets/02-capability-driven.md:2,3,4"; do
  f=${spec%%:*}; cols=${spec##*:}
  git show HEAD:$f | ext $f $cols >> $N/rank-score.head.txt
  cat $f | ext $f $cols >> $N/rank-score.now.txt
done
wc -l $N/rank-score.head.txt $N/rank-score.now.txt
diff $N/rank-score.head.txt $N/rank-score.now.txt > $N/rank-score.diff; echo "diff exit $? (0 = identical)"
