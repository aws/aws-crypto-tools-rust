#!/bin/zsh
# Usage: sweep2_cov.sh <ERE>... ; prints per-doc hit count (TM, VT-index, VT01, VT02, SSA)
cd "${0:A:h}/../../.."
D=(docs/threat-model.md docs/verification-targets.md docs/verification-targets/01-threat-driven.md docs/verification-targets/02-capability-driven.md docs/spec-security-analysis.md)
for pat in "$@"; do
  out=""; for d in $D; do out+="$(grep -cE -- "$pat" $d) "; done
  printf '%-58s TM/VT/VT01/VT02/SSA = %s\n' "$pat" "$out"
done
