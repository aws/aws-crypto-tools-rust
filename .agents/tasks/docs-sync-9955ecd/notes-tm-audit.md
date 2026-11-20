# notes-tm-audit (steps 2, 3, 4; nothing committed)

Ran: `git status`, `grep -n 'BUG-06'` over docs/threat-model.md, docs/completeness-audit.md, docs/verification-targets.md, docs/verification-targets/*.md; sed -n on every cited line of 01-threat-driven.md and verification-targets.md after editing; `git diff --quiet -- mpl prim esdk` (clean).

## docs/threat-model.md
- BUG-06 severity statements aligned: line 39 (table row, "The bug report now rates BUG-06 High, consistent with this row"), line 353 (reference reworded from "severity mismatch" to "severity in the bug report"), closing note (now ~line 676) replaced. Other BUG-06 mentions (lines 58, 64, 65, 90, 109, 197, 230, 319, 345, 361, 517, 530, 558, 611, 612) carry no bug-report severity.
- Added `### Resolution (HEAD 9955ecd)` table after the original "Impact on verification targets" table (original rows kept), plus the one-line audit note (no missed threat) and the BUG-06 closing note.
- No rating, ID or citation changed.

## docs/completeness-audit.md
- Appended `## 7. Resolution status` (G1, G2, G4-1, BUG-06 severity) with cited lines, all re-read by sed.
- Findings not changed. One severity label for the bug report was reworded: section 4 bullet "BUG-06 Low in the bug report vs TM-MPL-009/010 High: explained at `threat-model.md:653`" now points to section 7 (the old `:653` anchor no longer exists). Section 3b row for BUG-06 has no severity; unchanged.
- G2 "fixed in 9955ecd": `git show 9955ecd` touches threat-model.md and spec-security-analysis.md; `grep '00 14'` finds nothing in either.

## Targets docs (step 4)
- No statement of BUG-06's severity exists in docs/verification-targets.md or docs/verification-targets/*.md (only "Likelihood Low -> Medium" for TM-MPL-009, which is a threat likelihood, not the bug severity). No edit. Target scores use threat Severity, not the bug-report severity, so no re-scoring or warning.
