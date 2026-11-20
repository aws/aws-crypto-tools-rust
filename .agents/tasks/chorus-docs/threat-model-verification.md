# Threat model (Chorus edition) verification note

Outputs
- esdk-native-mpl/docs/chorus/MPL-Threat-Model.md (37,639 bytes)
- esdk-native-mpl/docs/chorus/MPL-Threat-Model.docx (28,943 bytes)

Converter: pandoc 3.10.2 at /opt/homebrew/bin/pandoc, `-f gfm -t docx`.

Checks and results
- All 23 IDs TM-MPL-001..023 appear in the .md (grep per ID) and in `pandoc MPL-Threat-Model.docx -t plain` output: pass.
- docx exists and is non-empty; plain-text dump shows the title, the title-block table and the threat register table: pass.
- Register severity/likelihood/risk for all 23 threats diffed mechanically against the source risk matrix (docs/threat-model.md appendix): identical.
- Headline counts recomputed from the register: risk 1 High / 15 Medium / 7 Low; severity 5 Critical / 9 High / 7 Medium / 2 Low; STRIDE 3/5/1/3/3/8 (matches verification-targets.md section 4).
- Spot checks against sources:
  1. TM-MPL-005 = Critical / Medium / High (threat-model.md matrix): match.
  2. TM-MPL-018 = Medium / Medium / Medium: match.
  3. TM-MPL-010 -> VR-2026-T13, T14 (verification-targets.md section 6) and BUG-06, BUG-09 (Related IDs lines in BUG-06, BUG-09): match.
  4. TM-MPL-023 -> T16, T20, T06 and BUG-01, BUG-05: match.
  5. TM-MPL-007 -> T17 and BUG-04: match.
- CVE-2026-6550 / GHSA-v638-38fc-rhfv presented only as UNVERIFIED (threat detail TM-MPL-010, open question 7, references).
- No HTML, Mermaid, emoji or footnote syntax (grep).
- No source code, existing docs or MPL-Bug-Reports.* touched; nothing committed or pushed.

Editor's notes recorded in the document (Appendix A)
1. Mitigation-status column is an editorial summary; the source has no such field.
2. TM-MPL-010 listed under Information Disclosure in source section 7 but labeled I/E in section 8 and the matrix; I/E kept.
3. TM-MPL-023 residual table says "Low-Med" while matrix risk is Low; both reproduced.
4. Zeroization wording differs (sections 5/9 "no zeroization" vs section 8 manual non-Drop `zeroize` on PlaintextDataKey).
5. Likelihood for several threats exists only in the matrix, not section 8.
6. Analyzed code is a1e23d7. a4f4693 and bbb8ec2 change no source (verified with git diff on mpl/src, prim/src, esdk/src). During this task the branch tip moved to c256243 (merge of main), which does change mpl/src and prim/src; the document was not re-checked against it and says so.
7. BUG-02 and BUG-08 map only to capability targets (C04, C01), so they have no threat link.
