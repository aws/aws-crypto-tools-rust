# Review: bug docs from Mahnush_Verus (independent reviewer)

Scope: BUG-07 new section, BUG-10, README, Chorus MPL-Bug-Reports.{md,docx}, notes. Tree `MPL-Verus` HEAD `e3abf2d`, uncommitted. Other branch read with `git show 2d229377:...` (origin/Mahnush_Verus already fetched, tip `8d6381e`).

## Checked
1. Citations: re-read every file:line in BUG-07's new section, BUG-10, README and Chorus with `awk`/`sed` on our tree (raw_aes_keyring.rs, branch_key_wrap.rs, hierarchical_keyring.rs, algorithm_suite.rs, decryption_materials.rs, aes_wrapping_alg.rs, mod.rs, test_raw_aes_keyring.rs, esdk body_encrypt/body_decrypt/encrypt/decrypt, prim/tests/test_aes.rs, threat-model/verification-targets lines). The BUG-10 and Chorus code excerpts were compared line by line with the source (exact match).
2. claims.md: each claim re-read independently. Statuses are correct. The two "Differs on MPL-Verus" items (no `secret::seal/open` module; prim tests do not pin buffer contents) are stated plainly in BUG-07's section. Nothing is "not confirmed"; nothing is silently dropped.
3. Evidence levels: BUG-07 diff is append-only (86 insertions, 0 deletions); the new section has its own "Last cross-checked" line. No mpl/esdk statement says proved; (b) stays "RECORDED, not proved"; BUG-10 is code reading. No other bug's severity/status/confidence/evidence changed (README and Chorus diffs only renumber priorities).
4. Proof cross-check at `2d229377`: the quoted `ensures` of `aes_encrypt_core` (`prim/src/lib.rs:405-416`) match exactly. Key/nonce and seal-Err statements are exported postconditions. The Ok-case "ciphertext then tag" order is only the in-body `assert` at `:437`; the exported Ok clause gives length `old+|m|+16` and prefix `old`; `+16` rests on trusted A19; seal-Err length rests on A18. A "Reviewer note" exists and is warranted (stated PROVED is stronger than the exported Ok postcondition). "PROVED" is quoted and attributed to the other branch.
5. Consistency: ten/10/BUG-01..10 in README, BUG-10, Chorus (remaining "nine" only where scoped to BUG-01..09). BUG-10 is priority 6 among the Low open bugs (BUG-08 -> 7, fixed bugs -> 8..10), explained, relative order otherwise unchanged. BUG-07 row and section point to BUG-10 and BUG-10 points back to BUG-07. BUG-10 has "Status on main", "Last cross-checked", and states T26 and TM-MPL-015 already cover the site. Plain GitHub Markdown, no HTML/Mermaid/footnotes/emoji.
6. Docx: exists, 50,197 bytes, newer than the .md (12:23 vs 11:58). `pandoc` plain shows the title and 16 mentions of BUG-10. MPL-Threat-Model.{md,docx} untouched.
7. Exclusions: `git diff --quiet HEAD -- <excluded paths>` succeeds. `git status --short` shows only BUG-07, README, Chorus .md/.docx modified; BUG-10, the notes dir and review-vr013-vr014 untracked. HEAD is still `e3abf2d`; nothing committed.

## Fixed by the reviewer
- BUG-07 section: aws-lc-rs 1.18.1 `unbound_key.rs` check was cited as `if` at `:139`, `Err` at `:140`. In the local source the comment is `:139`, `if` `:140`, `return Err` `:141`, `}` `:142`, so the finding's `:139-142` is exact. Text corrected.
- BUG-07 section: `IV_LEN = 12` is at `branch_key_wrap.rs:24` (`:23` is its doc comment). Corrected.
- Same corrections applied to claims.md, crosscheck.md and run-log.md.
- Chorus .md needed no change, so the .docx was not regenerated (still newer than the .md).

## Remaining
No blockers. Minor, not blocking: the README line "Last cross-checked: HEAD 9955ecd" was not updated and predates BUG-10 (BUG-10 carries its own line).
