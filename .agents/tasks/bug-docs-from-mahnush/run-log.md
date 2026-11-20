# Run log: bug docs from Mahnush_Verus (iteration 1, 2026-11-17)

No `review.json` existed at the start, so this is the first iteration. Nothing committed or pushed. No branch was checked out; `Mahnush_Verus` was read only with `git show` / `git grep` / `git diff --stat`.

## Commands and results

| Step | Command | Result |
|---|---|---|
| Baseline | `git status --short`; `git log --oneline -1` | Only `?? .agents/tasks/review-vr013-vr014/`; HEAD `e3abf2d` on `MPL-Verus` |
| Fetch (read-only) | `git -c credential.helper= -c credential.helper='!gh auth git-credential' fetch https://github.com/aws/aws-crypto-tools-rust.git +refs/heads/Mahnush_Verus:refs/remotes/origin/Mahnush_Verus` | `43b9ff7..8d6381e`. No auth error. `2d229377` is an ancestor of `8d6381e`; `git diff --stat 2d229377 8d6381e -- prim mpl esdk` empty (docs-only commit) |
| prim unchanged since our review | `git diff --stat 43b9ff7 2d229377 -- prim` | empty |
| Proof read | `git show 2d229377:prim/src/lib.rs` (`:360-540`), `git show 2d229377:prim/src/aws_lc_specs.rs` (`:362-405`) | `ensures` quoted in crosscheck.md |
| mpl files identical across branches | `git diff --stat HEAD 2d229377 -- mpl/src/keyring/raw_aes_keyring.rs mpl/src/aws_kms/branch_key_wrap.rs mpl/src/aws_kms/hierarchical_keyring.rs mpl/src/structures/algorithm_suite.rs mpl/src/structures/decryption_materials.rs` | empty |
| esdk wrapper | `git grep -n 'pub(crate) fn seal\|pub(crate) fn open' 2d229377 -- esdk/src` | `esdk/src/secret.rs:390`, `:407` on Mahnush_Verus; no `secret` module on MPL-Verus |
| A-OPEN source | `sed -n 130,145p ~/.cargo/registry/src/index.crates.io-*/aws-lc-rs-1.18.1/src/aead/unbound_key.rs` | length check at `:140-141` (comment `:139`) |
| Site re-finding | `grep -n` / `sed -n` on `mpl/src/keyring/raw_aes_keyring.rs`, `mpl/src/aws_kms/branch_key_wrap.rs`, `mpl/src/aws_kms/hierarchical_keyring.rs`, `mpl/src/aws_kms/mod.rs`, `mpl/src/structures/{algorithm_suite,decryption_materials,aes_wrapping_alg}.rs`, `mpl/tests/test_raw_aes_keyring.rs`, `prim/src/lib.rs`, `prim/tests/test_aes.rs`, `esdk/src/{encrypt,decrypt}.rs`, `esdk/src/message/body/{body_encrypt,body_decrypt}.rs`, `esdk/tests/test_custom_keyring.rs`, `docs/threat-model.md`, `docs/verification-targets.md`, `docs/verification-targets/01-threat-driven.md` | per-claim results in claims.md; several first-pass line numbers in claims.md were corrected after a second `sed -n` pass |
| Docx | `cd docs/chorus && /opt/homebrew/bin/pandoc MPL-Bug-Reports.md -f gfm -t docx -o MPL-Bug-Reports.docx` | exit 0; 50,197 bytes (was 45,368) |
| Docx check | `pandoc MPL-Bug-Reports.docx -t plain \| head -5` | first line "MPL Native Rust: Bug Reports for Engineering Discussion"; `grep -c BUG-10` on the plain dump = 16 |
| Markdown hygiene | `grep -nE '<[a-zA-Z/][^>]*>\|```mermaid\|\[\^' docs/chorus/MPL-Bug-Reports.md` | only a pre-existing Rust excerpt (`Vec<u8>` in a code block) |
| Protected paths | `git diff --quiet HEAD -- mpl prim esdk verus-proofs docs/bug-reports/RECHECK-main-620771c.md docs/threat-model.md docs/verification-targets.md docs/verification-targets docs/spec-security-analysis.md docs/completeness-audit.md docs/chorus/MPL-Threat-Model.md` | exit 0 (also exit 0 for `docs/chorus/MPL-Threat-Model.docx`) |
| Final status | `git status --short` | `M` BUG-07, README, MPL-Bug-Reports.md, MPL-Bug-Reports.docx; `??` BUG-10, `.agents/tasks/bug-docs-from-mahnush/`, `.agents/tasks/review-vr013-vr014/` |
| BUG-07 append-only | `git diff --stat` | BUG-07: 86 insertions, 0 deletions |

## Files changed

- `docs/bug-reports/BUG-07-prim-aes-buffer-handling.md`: new section "Impact on callers (from Mahnush_Verus)" appended; the existing text is unchanged.
- `docs/bug-reports/BUG-10-raw-aes-on-decrypt-unwiped-data-key.md`: new report.
- `docs/bug-reports/README.md`: "ten reports"; intro and re-check sentences scoped to BUG-01..09; BUG-10 row; BUG-07 row pointer; priority 6 for BUG-10 (BUG-08 -> 7, BUG-02 -> 8, BUG-03 -> 9, BUG-09 -> 10) with a one-sentence rationale; note that BUG-10 is not in completeness-audit 3b.
- `docs/chorus/MPL-Bug-Reports.md` and `.docx`: same counts, table rows, cross-reference row, agenda row 6, BUG-07 "Impact on callers" subsection, BUG-10 section, Appendix A/B/C updates.
