
## Notes on the results

- Check 1: the source has A1 to A14, TA1 to TA9 and TB1 to TB9 (more than the A12, TA6, TB8 named in the task brief). All are carried. The TB list shows TB2, TB3, TB8, TB9 twice because the parser also reads the first column of the section 5a table; the 5a table is carried row by row (11 rows) with equal threat columns.
- Check 1, sections 2 and 6: every component, trust statement and flow step maps to a summary location (table above). The source has no separate key store write flow; the summary says so.
- Check 2: ratings come from the last Risk column of the source Appendix matrix. No mismatches. Counts 3/14/9 verified from the source, not copied.
- Check 3: all exclusion patterns clean. No non-ASCII characters. The source diagrams used Unicode box characters; the summary versions use ASCII only.
- Check 4: the sentence splitter also splits bullet labels, so the average is lower than the true average. The longest sentence is 29 words. Remaining acronym flags are accepted: MPL (title; spelled out in the first bullet), README (file name), SDK (part of the product name AWS Encryption SDK), GCM, SHA and ARN (the checker misses the spelled-out forms "(AES-GCM)", "(SHA-384)" and "(ARNs)"), UTF-8 (explained in place and in the glossary), STRIDE (a name, expanded where first used), MUST (spec keyword in quotes). Asset, actor and boundary IDs are skipped as traceability IDs.
- Check 5: paths are written as code paths, not clickable links, so they do not break in Chorus. All exist.
- Check 6: heading levels consecutive, fences balanced, tables consistent, widest diagram line 90 columns.
