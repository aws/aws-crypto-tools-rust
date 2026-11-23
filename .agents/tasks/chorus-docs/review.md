# Review: Chorus editions of the MPL threat model and bug reports

Verdict: APPROVED (no blocking findings). Two small fidelity fixes applied directly to MPL-Threat-Model.md; .docx regenerated.

## Evidence read
fix-verification.md, threat-model-verification.md, bug-reports-verification.md, tooling.md, baseline-git-status.txt. Full suites not re-run. Spot-checks run: git remote/status, `git ls-files` for reproducers, greps against sources, pandoc plain dump of both .docx files.

## 1. Fidelity
Threat model, checked against docs/threat-model.md and docs/verification-targets.md:
- All 23 register rows match the source risk matrix (severity/likelihood/risk/STRIDE). I recomputed the headline counts: risk 1/15/7; severity 5/9/7/2; STRIDE 3/5/1/3/3/8. All correct.
- Cross-reference targets match verification-targets.md §6 for every threat (for example TM-MPL-001 -> T24, T20; TM-MPL-018 -> T21, T06; TM-MPL-023 -> T16, T20, T06; 019/020 fully excluded). Bug links match each report's Related IDs line (BUG-01 -> 018/022/023; BUG-06 -> 009/010; BUG-09 -> 010; BUG-02/08 capability-only).
- TM-MPL-005 detail, TM-MPL-012 (224 bits, 2^96 / 2^-32), TM-MPL-014 fixed-info layout, TM-MPL-016 condition expression and the residual-risk table (including "Low-Med") all match the source.
- CVE-2026-6550 / GHSA-v638-38fc-rhfv is marked UNVERIFIED everywhere it appears (TM-MPL-010 detail, open question 7, references).
- Editor's notes cover the source disagreements: the TM-MPL-010 I vs I/E label, TM-MPL-023 Low vs Low-Med, the zeroization wording, likelihood that appears only in the matrix, and commit drift.
- The mitigation-status column is editorial and disclosed as such (note 1). Accepted.

Bug reports, checked against README.md and BUG-01..09:
- Severity, spec conflict and priority match README and the reports for all nine bugs. The confidence label in each per-bug section matches its report verbatim (BUG-04, BUG-05 and BUG-09 qualifiers checked). The summary table uses the README short form, which is disclosed in Appendix C.
- Spot-checks matched the sources: BUG-01 thresholds (9.2 × 10^18 s, 1.8 × 10^12 s); BUG-06 roughly 6% NUL probability; BUG-07 `prim/src/lib.rs:197-218`, `:236`; BUG-09 1950 ms / 2050 ms; BUG-04 `kms_ops.rs:104-107`; and every recommendation (BUG-01 option 1, BUG-04 option 1 plus spec clarification, BUG-08 option 1, BUG-09 option 2 / option 1).
- GitHub links use origin `aws/aws-crypto-tools-rust`, branch MPL-Verus. The reproducer files are tracked (`git ls-files`).

Fixes applied (non-blocking, now resolved):
- F1 (MPL-Threat-Model.md, §1): "No target is proven yet" was a claim no source makes. Changed to "The targets are recommendations; the sources report no completed proofs."
- F2 (MPL-Threat-Model.md, §9.1): the source recommends a "unique partition-id only when cache sharing is intended". The draft had silently reworded this to "shared", which changes the source text. I restored the source wording and added Appendix A note 8 explaining the ambiguity for reviewers.

## 2. Structure
- Threat model: title block (a1e23d7, Draft, how produced), executive summary (about half a page), in/out scope with the ESDK message format out of scope, ASCII diagram in a code block plus prose, components, trust boundaries, assets and actors tables, register, per-threat details, cross-reference, residual risks, recommendations (configuration/implementation/operational), open questions, references, editor's notes. Complete.
- Bug doc: title block and introduction, a 7-column summary table, the agenda in priority order (1..9 matches README), and BUG-01..09 in order. Each bug has Summary, attribute table, Location, Expected vs actual, Impact, Evidence, Fix options, Recommendation and Questions. Each bug has at most one code excerpt of 15 lines or fewer, plus test-output blocks. GitHub links are present, and the note that a1e23d7 is 45 commits behind main appears in the introduction and in Appendix C.

## 3. Readability and format
The prose is plain and neutral. Only GFM is used: no HTML (the angle brackets are Rust generics in code), no Mermaid, emoji or footnotes, per the evidence greps.

## 4. Done criteria
- All four files exist. MPL-Threat-Model.docx (29,121 bytes, regenerated after F1/F2 with `pandoc -f gfm -t docx`) and MPL-Bug-Reports.docx (40,888 bytes) are non-empty.
- The docx dump contains all 23 TM IDs, and BUG IDs appear throughout.
- `git status --porcelain` shows only `?? docs/chorus/`. The baseline was clean.

## Blocking findings
None.
