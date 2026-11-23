# Review: bug-report docs update to main 620771c

Reviewer pass 1. Repo `esdk-native-mpl`, branch `MPL-Verus`, HEAD `c256243` (= `origin/MPL-Verus`), changes uncommitted. Inputs read: `docs/bug-reports/RECHECK-main-620771c.md`, the coder's `docs-update/verification.md`, all nine BUG reports, `docs/bug-reports/README.md` (and its diff against HEAD), `docs/chorus/MPL-Bug-Reports.md`, `docs/chorus/MPL-Threat-Model.md`, the re-check logs. No reproducers were re-run.

Verdict: APPROVED. No blocking findings. No fixes were applied by the reviewer.

## Checks and results

1. Status blocks. All nine reports have a "Status on main (620771c)" section with status, re-check date 2026-11-10, one-line evidence with the `recheckNN.log` path, and a link to `RECHECK-main-620771c.md` (link resolves). BUG-02/03/09 name `e9bde48` (#98) and the fix location (`algorithm_suite.rs:547` + callers; `encryption_context.rs:145`, `:199`, `:205-210`, `:230`; `hierarchical_keyring.rs:989-995`). Statuses match the RECHECK table, including BUG-05 (a)/(b) and BUG-07 (a and b). Result: pass.

2. Current locations and excerpts.
   - Own spot-checks with `sed -n` against the current tree: `hierarchical_keyring.rs` 535, 547, 596, 600, 605, 626, 665, 684, 702, 767, 798, 879, 908, 927, 934, 945, 989, 994; `storm_tracking.rs` 333, 606-626, 680; `cache_entry_identifier.rs` 35-66; `kms_ops.rs` 88-103, 144-157, 162, 179; `key_store/mod.rs:36`; `branch_key_store.rs` 112, 116, 122, 641, 644, 663, 801, 839, 874; `mrk_match.rs:52`; `default_cmm.rs:137-138`; `prim/src/ecdsa.rs` 373-396; `branch_key_wrap.rs:236`, `:199`; `prim/src/lib.rs` 175-229; `key_store/encryption_context.rs` 36-104; `key_store/attributes.rs` 11-24; `structures/encryption_context.rs` 16, 145, 198-211, 230; `algorithm_suite.rs` 547-562; `encryption_materials.rs` 60, 365; `decryption_materials.rs` 56, 303; `keyring/raw_aes_keyring.rs:163`; `esdk/src/message/body/body_encrypt.rs:244`; `esdk/src/encrypt.rs:776`; `mpl/tests/test_aws_kms_hierarchical_keyring.rs:1547`. All match what the docs claim.
   - Own script: every numbered line in every `rust` block of the nine reports and the Chorus doc was compared against all tracked `.rs` files. Every block matches a current source file exactly (each block ≤ 15 lines). The one Chorus block that spans two files (BUG-01: `hierarchical_keyring.rs:698-703` plus `storm_tracking.rs:333`, `:680`) matches line by line, and the bullets above it name both files.
   - Every report has an "Originally reported at `a1e23d7`" line. `keystore/` → `key_store/` and `resolve_keystore_arn` → `resolve_key_store_arn` are correct. aws-lc-rs 1.18.1 confirmed in all three `Cargo.lock` files.
   - Result: pass.

3. Fixed bugs (02, 03, 09): summary labeled "as found at `a1e23d7`", original analysis under "Original analysis at a1e23d7 (history)", a "Re-check on main (620771c)" subsection with adapted output, then a "Resolved" note. Still-present bugs show re-check output and say the test was "adapted for API changes only". BUG-07 says it ran unchanged. All links to `.agents/tasks/bug-recheck/reproducers/*.rs` resolve locally. Script check: every line of each re-check `text` block appears in the cited `recheckNN.log` (0 missing, all nine reports). In the Chorus doc, the only non-verbatim lines are the declared trims (UUIDs shortened to `1234abcd-...`, `...` elisions), and Appendix C states them. Result: pass.

4. Severity and conclusions. Diffed the Severity / Confidence / Spec conflict lines of every report against HEAD: unchanged. The only removed lines are the three "Recommendation" lines in the fixed reports, which went with the fix options (as briefed). BUG-06 stays Low, and the "Severity review suggested" note is clearly marked and does not claim new evidence. The BUG-05 statement that the BUG-02 fix does not resolve (b) is backed by the RECHECK output (44-59-byte EDKs still make 1 key store call). Result: pass.

5. README.
   - Has the "Status on main (620771c)" column and an intro paragraph about the re-check with the RECHECK link. BUG-02/03/09 are marked fixed.
   - Priority: the old order was 02, 06, 01, 04, 03, 07, 05, 09, 08. The new order is 06, 01, 04, 07, 05, 08, then 02, 03, 09. That is BUG-06 first, the remaining open bugs in their previous relative order, then the fixed bugs.
   - The reorder is explained in the last bullet. It takes a few sentences rather than one; acceptable.
   - Result: pass.

6. Chorus bug doc.
   - Title block says `main` `620771c` (originally `a1e23d7`). It has a status column, and the agenda puts BUG-06 first and the fixed bugs last.
   - Each open bug has a Status section and a current Location section, and there is a "Resolved on main" section.
   - The "45 commits behind main" note is gone (grep), replaced by accurate ancestry notes. The links use `https://github.com/aws/aws-crypto-tools-rust/blob/MPL-Verus/docs/bug-reports/...`, and the RECHECK link is present.
   - No HTML tags (the only `<...>` matches are Rust generics in code), no Mermaid, no footnotes, no emoji (script).
   - Chorus threat model: all 23 TM-MPL rows (STRIDE, impact, likelihood, risk) match `docs/threat-model.md`'s rating table exactly (script diff). Only bug-status annotations were added.
   - Result: pass.

7. Cross-document agreement. README, Chorus summary table, Chorus threat-model bug table and each report's status line agree with RECHECK for all 9 bugs (BUG-05 a/b and BUG-07 a/b shown in one row each, consistently). Result: pass.

8. .docx. Both exist (`MPL-Bug-Reports.docx` 40993 B, `MPL-Threat-Model.docx` 29131 B). `pandoc docs/chorus/MPL-Bug-Reports.docx -t plain | head` renders the title "MPL Native Rust: Bug Reports for Engineering Discussion". A word-level comparison of `pandoc md -t plain` and `pandoc docx -t plain` gives 0 differences for both documents, so the docx files are in sync with the current .md files. Result: pass.

9. Git. `git diff --quiet HEAD -- mpl prim esdk` exits 0. `git status --short` shows only the 10 modified `docs/bug-reports/*.md` files plus untracked `docs/bug-reports/RECHECK-main-620771c.md`, `docs/chorus/`, `.agents/tasks/bug-recheck/`. No `zz_bugrepro_*` in `mpl/tests` or `prim/tests`. HEAD = `origin/MPL-Verus` = `c256243`, so nothing was committed or pushed. Forbidden files (`docs/threat-model.md`, `docs/spec-security-analysis.md`, `docs/verification-targets*`, RECHECK) are not modified. Result: pass.

## Fixes applied by reviewer

None.

## Items for the user (non-blocking)

- GitHub links to `.agents/tasks/bug-recheck/...` (Chorus Appendix A, and the relative reproducer links in the reports) will only resolve after `.agents/tasks/bug-recheck/` is committed and pushed. Today only `.agents/tasks/bug-reports/` is on `origin/MPL-Verus`. The same applies to `RECHECK-main-620771c.md` and `docs/chorus/`, which are still untracked.
- The BUG-06 "Severity review suggested" note asks the team to decide whether Low is still the right rating. The docs leave the rating unchanged, which is correct, but the decision is still open.
- Spec line references (for example in BUG-04) and the ESDK V1 HKDF path were not re-checked, because the spec submodule was removed on main. The docs say so explicitly.
