# Verification: bug-report docs update to main 620771c

Iteration: first iteration. `.agents/tasks/bug-recheck/docs-update/review.json` did not exist, so the full update was done from scratch.

Repo: `esdk-native-mpl`, branch `MPL-Verus`, HEAD `c256243`. Nothing was committed or pushed.

## Files changed

Tracked (modified):

- `docs/bug-reports/BUG-01-ttl-duration-overflow-panic.md`
- `docs/bug-reports/BUG-02-plaintext-data-key-length-not-enforced.md`
- `docs/bug-reports/BUG-03-encryption-context-deserialize-accepts-unsorted.md`
- `docs/bug-reports/BUG-04-mrdiscovery-rewrites-non-mrk-arn-region.md`
- `docs/bug-reports/BUG-05-keygen-expect-and-short-edk-keystore-lookup.md`
- `docs/bug-reports/BUG-06-cache-identifier-not-injective-with-nul.md`
- `docs/bug-reports/BUG-07-prim-aes-buffer-handling.md`
- `docs/bug-reports/BUG-08-build-base-collision-branch-unreachable.md`
- `docs/bug-reports/BUG-09-cache-ttl-check-whole-second-truncation.md`
- `docs/bug-reports/README.md`

Untracked (already untracked before this step; contents updated):

- `docs/chorus/MPL-Bug-Reports.md` and `docs/chorus/MPL-Bug-Reports.docx` (regenerated)
- `docs/chorus/MPL-Threat-Model.md` and `docs/chorus/MPL-Threat-Model.docx` (regenerated; bug references only)
- `.agents/tasks/bug-recheck/docs-update/verification.md` (this file, new)

Not edited: `docs/bug-reports/RECHECK-main-620771c.md`, `docs/threat-model.md`, `docs/spec-security-analysis.md`, `docs/verification-targets*.md`, and anything under `mpl/`, `prim/` or `esdk/`.

## What changed, per document

- Each BUG report has a "Status on main (620771c)" block. It gives the status, the re-check date (2026-11-10), one line of evidence with the log path, and a link to `RECHECK-main-620771c.md`. For BUG-02, BUG-03 and BUG-09 it also names the fixing commit `e9bde48` (#98) and where the fix lives.
- The Location sections cite current file:line (with `keystore/` renamed to `key_store/`), with excerpts taken from current source, and end with an "Originally reported at `a1e23d7`" line. Each report notes that line numbers in other sections are historical `a1e23d7` references.
- Still-present bugs (01, 04, 05, 06, 07, 08):
  - Reproduction sections now show the re-check run, marked "adapted for API changes only", with output from `recheckNN.log`.
  - The adapted reproducers for BUG-04 and BUG-08 are inlined, as they are short. BUG-01 (173 lines), BUG-05 (115 lines) and BUG-06 (127 lines) link to `.agents/tasks/bug-recheck/reproducers/`. BUG-07 ran unchanged, so it keeps the original source with the new output.
  - Fix options got a one-paragraph note that maps old names to current code. For BUG-05 the note says the BUG-02 fix does not resolve (b).
- Fixed bugs (02, 03, 09):
  - The summary is labeled "as found at `a1e23d7`". The original Expected/Actual/Impact/Reproduction sections sit under "Original analysis at a1e23d7 (history)", followed by "Re-check on main (620771c)" with the adapted output.
  - Fix options and questions were replaced by a "Resolved" note. Questions that are still relevant (cross-runtime parity, the unchecked ESDK path) are kept.
- README: the intro states the re-check and links the RECHECK doc. The table gained a "Status on main (620771c)" column. Priorities were reordered, with one explanatory sentence: BUG-06 1, BUG-01 2, BUG-04 3, BUG-07 4, BUG-05 5, BUG-08 6, then the fixed bugs BUG-02 7, BUG-03 8, BUG-09 9.
- Chorus bug doc:
  - Title block: "Code reviewed" is now `main` `620771c` (originally found at `a1e23d7`).
  - The intro replaces the "45 commits behind main" note with an accurate note about which line numbers are current.
  - Summary table: status column added, same values as the README.
  - Agenda reordered (BUG-06 first; fixed bugs as a single last row).
  - Open-bug sections got Status and current Location, and their Evidence is replaced with re-check output.
  - BUG-02, BUG-03 and BUG-09 were moved to a short "Resolved on main" section.
  - Appendix A lists the original and adapted reproducers. Appendix B adds a RECHECK link (GitHub `blob/MPL-Verus/docs/bug-reports/RECHECK-main-620771c.md`). Appendix C replaces the 45-commit note with the ancestry facts.
  - GFM only; no HTML, Mermaid, emoji or footnotes.
- Chorus threat model:
  - The executive-summary bug bullet notes that 3 of 9 are fixed on main.
  - Section 7 cross-reference: BUG-03 (TM-MPL-013, TM-MPL-017) and BUG-09 (TM-MPL-010) are marked "(fixed on main)", and the intro sentence explains the marker. The "Bugs not linked" sentence marks BUG-02 as fixed.
  - The bug summary table gained a "Status on main (620771c)" column.
  - Open question 8 notes that BUG-02 is fixed. Appendix A note 6 says only bug status was re-checked. A RECHECK reference was added.
  - No threat, rating, likelihood, severity or mitigation text was changed.

## Status consistency (README, Chorus, RECHECK)

A script parsed both summary tables. The README and Chorus rows are identical for all 9 bugs (status and priority columns):

| Bug | Status (README = Chorus = RECHECK) | Priority |
|---|---|---|
| BUG-01 | Still present | 2 |
| BUG-02 | Fixed on main (`e9bde48`, #98) | 7 |
| BUG-03 | Fixed on main (`e9bde48`, #98) | 8 |
| BUG-04 | Still present | 3 |
| BUG-05 | (a) Still present; (b) Still present (likely not a bug) | 5 |
| BUG-06 | Still present | 1 |
| BUG-07 | Still present (a and b) | 4 |
| BUG-08 | Still present | 6 |
| BUG-09 | Fixed on main (`e9bde48`, #98) | 9 |

Every BUG report's "- Status:" line matches this table. The threat-model status column uses the same values.

## Current file:line checks

Checked with a script (`verify_lines.py`, run from a temp dir and then deleted). It reads each cited line of the current tree and checks for the expected text. Result: 107/107 OK.

| File:line | Content found | Result |
|---|---|---|
| `mpl/src/aws_kms/hierarchical_keyring.rs:535` | `pub async fn build(self) -> Result<HierarchicalKeyring, Error>` | OK |
| `hierarchical_keyring.rs:547` | `if ttl.is_zero() {` | OK |
| `hierarchical_keyring.rs:596` | `Some(s) => s.into_bytes(),` | OK |
| `hierarchical_keyring.rs:600`, `:605` | `let logical_key_store_name = key_store` ... `.logical_key_store_name;` | OK |
| `hierarchical_keyring.rs:626` | `fn generate_partition_id()` | OK |
| `hierarchical_keyring.rs:665`, `:908` | `build_cache_identifier(` call sites | OK |
| `hierarchical_keyring.rs:684`, `:927` | `cache_entry_within_limits(&entry, self.inner.ttl)` | OK |
| `hierarchical_keyring.rs:702`, `:945` | `.expiry_time(now + self.inner.ttl)` | OK |
| `hierarchical_keyring.rs:764`, `:767` | `try_decrypt_edk` match; `materials.add_data_key(PlaintextDataKey::new(..))?` | OK |
| `hierarchical_keyring.rs:798` | `Err(Error::all_failed(` | OK |
| `hierarchical_keyring.rs:867`, `:879` | `async fn try_decrypt_edk(`; 44-byte check | OK |
| `hierarchical_keyring.rs:901`, `:934`, `:958` | `decrypt_edk_at_version(`; `.get_branch_key_version()`; `branch_key_wrap::unwrap(..)` | OK |
| `hierarchical_keyring.rs:987`, `:989`, `:994`, `:995` | `cache_entry_within_limits` doc, signature, `elapsed <= ttl`, `}` | OK |
| `mpl/src/cmc/storm_tracking.rs:333` | `deadline: Some(now + self.inner.in_flight_ttl),` | OK |
| `storm_tracking.rs:606`, `:622`, `:626` | `StormTrackingCmcBuilder::build`; `grace_interval > in_flight_ttl`; end of checks | OK |
| `storm_tracking.rs:675`, `:680` | `within_grace_interval(`; `now < inflight + grace_interval` | OK |
| `mpl/src/structures/algorithm_suite.rs:547`, `:562` | `check_data_key_length(` ... `}` | OK |
| `encryption_materials.rs:60`, `:365`; `decryption_materials.rs:56`, `:303` | `check_data_key_length(` calls | OK |
| `mpl/src/structures/encryption_context.rs:16` | `pub struct EncryptionContext(BTreeMap<String, String>);` | OK |
| `encryption_context.rs:145`, `:198`, `:199`, `:205`, `:208`, `:210`, `:230` | `from_bytes`, previous-key, duplicate and order checks, `utf8` | OK |
| `mpl/src/key_store/kms_ops.rs:88`, `:100`, `:103` | `resolve_key_store_arn(`; MrDiscovery arm | OK |
| `kms_ops.rs:144`, `:157` | `fn rewrite_arn_region(..)` ... `}` (docs cite `:144-157`) | OK |
| `kms_ops.rs:162`, `:179` | `decrypt_branch_key(`; `resolve_key_store_arn(..)` call | OK |
| `mpl/src/key_store/mod.rs:36` | `mod kms_ops;` | OK |
| `mpl/src/aws_kms/mrk_match.rs:52` | `fn is_multi_region_arn(s: &str) -> bool` | OK |
| `mpl/src/key_store/branch_key_store.rs:112`, `:116`, `:122` | `configured_kms_key_arn` rejects Discovery/MrDiscovery | OK |
| `branch_key_store.rs:641`, `:644`, `:663` | `version_key`; `configured_kms_key_arn()?`; `resolve_key_store_arn(` | OK |
| `branch_key_store.rs:801`, `:839`, `:874` | `decrypt_branch_key(` calls | OK |
| `mpl/src/cmm/default_cmm.rs:85`, `:137`, `:138` | `get_encryption_materials(`; `ecdsa_generate_keypair(alg)`; `.expect(..)` | OK |
| `prim/src/ecdsa.rs:373`, `:375`, `:380`, `:386`, `:391`, `:392`, `:396` | `ecdsa_generate_keypair` and its four `Err` paths | OK |
| `mpl/src/aws_kms/branch_key_wrap.rs:236` | `if ciphertext.len() < FIXED_OVERHEAD_LEN` | OK |
| `mpl/src/aws_kms/cache_entry_identifier.rs:35`, `:49`, `:59`, `:66` | `build_cache_identifier(`, partition append, version append, `}` | OK |
| `prim/src/lib.rs:175`, `:185`, `:187`, `:189`, `:192`, `:194`, `:197` | `aes_encrypt` append-before-check and seal | OK |
| `prim/src/lib.rs:206`, `:215`, `:228`, `:229` | `aes_decrypt`, guard, callee, error mapping | OK |
| `raw_aes_keyring.rs:163`, `branch_key_wrap.rs:199`, `esdk/src/message/body/body_encrypt.rs:244`, `esdk/src/encrypt.rs:776` | `aes_encrypt(` callers | OK |
| `mpl/src/key_store/encryption_context.rs:36`, `:40`, `:60`, `:79`, `:86`, `:89`, `:92`, `:95`, `:101`, `:104` | `custom_ec`, `build_base`, base inserts, dead `Err` | OK |
| `mpl/src/key_store/attributes.rs:11`, `:17`, `:24` | base attribute constants, `CUSTOM_EC_PREFIX` | OK |
| `mpl/tests/test_aws_kms_hierarchical_keyring.rs:1547` | `async fn on_encrypt_ttl_compares_the_full_duration()` | OK |

Excerpt check: a second script compared every numbered line inside ```` ```rust ```` blocks in the nine reports and the Chorus bug doc against current source, at the same line number. Result: 162/162 lines match current source. No `a1e23d7`-era numbered excerpts remain.

Other checks:

- `git diff --stat a1e23d7 HEAD -- mpl/src/aws_kms/cache_entry_identifier.rs` is empty, which supports "file unchanged" for BUG-06.
- aws-lc-rs is 1.18.1 in `prim/Cargo.lock`, `mpl/Cargo.lock` and `esdk/Cargo.lock`, as cited in BUG-07.
- Commits `e9bde48` (#98), `9646828` (#167) and `6ef7d80` (#91) exist with the cited subjects.
- `git merge-base --is-ancestor a1e23d7 620771c` gives 1 (not an ancestor). `git merge-base --is-ancestor a1e23d7 c256243` gives 0 (ancestor). `git diff --quiet 620771c c256243 -- mpl prim esdk` gives 0.
- Relative links: in the reports, every new link (`RECHECK-main-620771c.md`, `../../.agents/tasks/bug-recheck/reproducers/*.rs`) resolves. The only unresolved relative links are pre-existing spec-quote links (`algorithm-suites.md`, `structures.md`), which I did not touch. In the Chorus bug doc, all 31 GitHub `MPL-Verus` paths exist in the local tree. The `.agents/tasks/bug-recheck/` paths will exist on GitHub once the orchestrator pushes that directory.

## docx checks

Commands run from the repo root:

- `/opt/homebrew/bin/pandoc docs/chorus/MPL-Bug-Reports.md -o docs/chorus/MPL-Bug-Reports.docx` gives 40993 bytes.
- `/opt/homebrew/bin/pandoc docs/chorus/MPL-Threat-Model.md -o docs/chorus/MPL-Threat-Model.docx` gives 29131 bytes.

`pandoc docs/chorus/MPL-Bug-Reports.docx -t plain | head` shows the title and a title-block row with the new code revision:

```text
MPL Native Rust: Bug Reports for Engineering Discussion
  ----------------------------------------------------------------------------
  Field                          Value
  ...
  Code reviewed                  main commit 620771c (merged into MPL-Verus as
                                 c256243). The bugs were originally found at
                                 commit a1e23d7.
```

`pandoc docs/chorus/MPL-Threat-Model.docx -t plain | head` shows:

```text
MPL Threat Model: AWS Cryptographic Material Providers Library (native Rust)
  -------------------------------------------------------------
  Field                          Value
```

`grep "fixed on main"` on the plain-text threat model shows the new markers in the executive summary, section 7 and question 8.

## Git checks

```text
$ git diff --quiet HEAD -- mpl prim esdk; echo "exit=$?"
exit=0

$ git status --short
 M docs/bug-reports/BUG-01-ttl-duration-overflow-panic.md
 M docs/bug-reports/BUG-02-plaintext-data-key-length-not-enforced.md
 M docs/bug-reports/BUG-03-encryption-context-deserialize-accepts-unsorted.md
 M docs/bug-reports/BUG-04-mrdiscovery-rewrites-non-mrk-arn-region.md
 M docs/bug-reports/BUG-05-keygen-expect-and-short-edk-keystore-lookup.md
 M docs/bug-reports/BUG-06-cache-identifier-not-injective-with-nul.md
 M docs/bug-reports/BUG-07-prim-aes-buffer-handling.md
 M docs/bug-reports/BUG-08-build-base-collision-branch-unreachable.md
 M docs/bug-reports/BUG-09-cache-ttl-check-whole-second-truncation.md
 M docs/bug-reports/README.md
?? .agents/tasks/bug-recheck/
?? docs/bug-reports/RECHECK-main-620771c.md
?? docs/chorus/
```

Only `docs/` and the already-untracked `.agents/tasks/bug-recheck/` appear. There are no `zz_bugrepro_*` files in `mpl/tests` or `prim/tests`.

## Judgement calls

1. BUG-06 "Severity review suggested": added to the BUG-06 report's Status block and the Chorus BUG-06 Status, clearly marked. The severity stays Low. My reasoning: the end-to-end evidence (keyring B served keystore A's branch key) is not new. The original `a1e23d7` run already showed it, and the Low rating was set with it known, so the re-check alone does not justify raising it. The note still asks reviewers to revisit the rating, because it is now confirmed on current code and is the open finding with the most direct confidentiality impact now that BUG-02 is fixed. The README and Chorus tables keep Low and mention the note.
2. Priority reorder: BUG-06 first, then the remaining open bugs in their original relative order (01, 04, 07, 05, 08), then the fixed bugs in their original relative order (02, 03, 09), labeled "Resolved". Open bugs keep their original High/Medium/Low label word. In the Chorus agenda, the three fixed bugs share one final row (order 7), because no decision is needed. The summary tables give them 7, 8 and 9 to match the README.
3. Threat model: changed, because it has a threat-to-bug cross-reference (section 7), a bug summary table, and bug mentions in the executive summary, question 8 and Appendix A note 6. Only bug-status annotations were added. Threats, ratings and the analyzed revision (`a1e23d7`) are unchanged.
4. Reproducer inlining: the adapted sources are inlined only where they are short (BUG-04, 38 lines; BUG-08, 35 lines), with their header comments omitted and noted. Long ones (BUG-01, BUG-05, BUG-06) are linked instead. Fixed bugs keep the original reproducer source inside the labeled history section and link the adapted one.
5. Fixed bugs: the fix options were removed from the reports (they remain in git history), as the brief asked to replace that emphasis with a "Resolved" note. I mapped each fix to the closest original option: BUG-02 is option 3 in effect, BUG-03 is option 3, and BUG-09 is option 1. That mapping is my reading of the fixes, not a statement from the re-check.
6. Line-number precision: the docs cite `kms_ops.rs:144-157` for `rewrite_arn_region`. The RECHECK doc says `:144-158`, but line 158 is the blank line after the closing brace. I did not edit the RECHECK doc.
7. Validation-line citations: BUG-01 cites `hierarchical_keyring.rs:547` (the `if ttl.is_zero()` line), as the RECHECK doc does.
8. Things not re-verified and stated as such in the docs: the aws-lc-rs 1.18.1 callee source, the ESDK `key_derivation.rs` V1 HKDF path, the integration-test range `test_aws_kms_hierarchical_keyring_integ.rs:815-866`, and spec line numbers (the spec submodule was removed on `main`).
