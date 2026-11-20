# Fix verification (iteration 1, no review.json present)

review.json did not exist, so this pass ran the done-criteria verification on the fresh drafts. No edits were needed; no files in docs/chorus/ were changed in this pass.

## Files and sizes (`ls -la esdk-native-mpl/docs/chorus/`)
- MPL-Threat-Model.md: 37,639 bytes
- MPL-Threat-Model.docx: 28,943 bytes (> 0, newer than .md)
- MPL-Bug-Reports.md: 63,237 bytes
- MPL-Bug-Reports.docx: 40,888 bytes (> 0, newer than .md)

## ID coverage (`grep -c` per ID)
- TM-MPL-001..023 in MPL-Threat-Model.md: all present (3 to 12 occurrences each; none zero).
- BUG-01..09 in MPL-Bug-Reports.md: all present (8 to 19 occurrences each; none zero).

## Syntax checks
- HTML / Mermaid / footnote grep (`<tag>`, ```` ```mermaid ````, `[^`): no Mermaid, no footnotes. The only `<...>` matches are Rust generics in inline code (`Result<EncryptionMaterials, MaterialsError>`, `BTreeMap<Vec<u8>, Vec<u8>>`, line 401 and 667) and verbatim text inside fenced blocks (`Vec<u8>` at line 484 in a ```rust block at 483-495; `<disabled>` at lines 597/601/602 in a ```text block at 596-605). Not HTML.
- Emoji grep (perl, U+1F300-1FAFF, U+2600-27BF, U+2B50, U+2705, U+274C): no matches.

## pandoc title check (`/opt/homebrew/bin/pandoc <file>.docx -t plain | head -40`)
- MPL-Threat-Model.docx: first line "MPL Threat Model: AWS Cryptographic Material Providers Library (native Rust)", followed by title-block table.
- MPL-Bug-Reports.docx: first line "MPL Native Rust: Bug Reports for Engineering Discussion", followed by title-block table.

## UNVERIFIED advisory
`grep -n "CVE-2026-6550\|GHSA-v638"`: 3 occurrences, all in MPL-Threat-Model.md (lines 260, 436, 452), each marked UNVERIFIED / unverified.

## git status
`git -C esdk-native-mpl status --porcelain` output:
```
?? docs/chorus/
```
Baseline (baseline-git-status.txt) was empty; the only difference is untracked docs/chorus/. Nothing committed or pushed.

## Content fidelity
Relied on the drafting steps' mechanical diff of severity/likelihood/risk against the source risk matrix and their source spot-checks (threat-model-verification.md, bug-reports-verification.md). No ratings, severities or confidence labels were changed in this pass.
