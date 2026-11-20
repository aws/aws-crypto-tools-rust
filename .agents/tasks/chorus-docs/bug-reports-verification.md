# Verification note: MPL-Bug-Reports (consolidated)

Outputs:
- /Users/mahnush/Desktop/ESDK-Rust-Verus/MPL/esdk-native-mpl/docs/chorus/MPL-Bug-Reports.md (63,237 bytes)
- /Users/mahnush/Desktop/ESDK-Rust-Verus/MPL/esdk-native-mpl/docs/chorus/MPL-Bug-Reports.docx (40,888 bytes)

Sources: docs/bug-reports/README.md and BUG-01..BUG-09 *.md (branch MPL-Verus). Reproducer files exist and are tracked under .agents/tasks/bug-reports/reproducers (9 files), so the GitHub links point to real paths.

Converter: pandoc 3.10.2 (/opt/homebrew/bin/pandoc), `pandoc MPL-Bug-Reports.md -f gfm -t docx -o MPL-Bug-Reports.docx`.

Checks:
- Both files exist and are non-empty.
- `pandoc MPL-Bug-Reports.docx -t plain | head -40` shows the title, the title-block table and the start of the introduction; the Summary table renders further down with all 7 columns.
- Every ID BUG-01 through BUG-09 appears in the .md (8 to 19 occurrences each).
- No HTML, Mermaid or footnote syntax. The only `<...>` matches are `<disabled>` inside fenced test-output blocks (verbatim log text).
- Commit a1e23d7 confirmed 45 commits behind origin/main (`git rev-list --count a1e23d7..origin/main`).
- Spot-checks against sources (all match):
  1. BUG-02 severity Medium (BUG-02 report, README).
  2. BUG-08 confidence "Confirmed by code reading" (BUG-08 report).
  3. BUG-04 location `mpl/src/keystore/kms_ops.rs:104-107` (BUG-04 report).
  4. BUG-01 recommendation "option 1 at all four sites" (BUG-01 report).
  5. BUG-09 recommendation "option 2, unless ... option 1" (BUG-09 report).
  6. BUG-06 location `cache_entry_identifier.rs:35-66` (BUG-06 report).
- No source code or existing docs were modified; nothing was committed. MPL-Threat-Model.* files were not touched.

Editor's notes (also in Appendix C of the document):
- No conflicts in severity, spec conflict or priority between README and reports.
- Confidence for BUG-04, BUG-05 and BUG-09 carries extra qualifiers in the individual reports; per-bug sections use the report wording, the summary table keeps the README short form.
- README titles are shorter than report titles (BUG-05 drops "before rejection"); same meaning.
- Code and output excerpts trimmed; BUG-04 key UUIDs shortened in the output excerpt.
