# Review: docs-c03-status (C03 / C02 / BUG-10 status record)

Branch `MPL-Verus`, HEAD `b94c871` (unchanged). Reviewed `git diff HEAD` (8 documents, uncommitted) plus `coder-notes.md` and `rerun.md`. No Verus suite and no re-run were repeated. Nothing committed or pushed.

## Verdict: APPROVED (no blockers)

## Evidence

1. Statuses against the review report and the other branch
   - `origin/Mahnush_Verus` = `8d6381e`. `git diff --stat 43b9ff7 origin/Mahnush_Verus` touches only `docs/verus-proofs-report.md`, so "no commit after 43b9ff7 touches prim/" and "2d22937 and 8d6381e are docs only" are true.
   - Read via `git show`: 20 `assume_specification` in `prim/src/aws_lc_specs.rs`, no `assume(`/`admit(`; cores `hmac_core`, `digest_core`, `kbkdf_core`, `fill_random_core`, `ct_equal_core`, `aes_encrypt_core`, `aes_decrypt_core` in `prim/src/lib.rs`; `digest_finish_core` and `sign_fixed_len_core` (VR-008) in `prim/src/ecdsa.rs`; no `verus-proofs/` there; `mpl/src` identical to this branch; divergence 20 / 47, merge base `5f2dc72`; `mpl/Cargo.toml` and `mpl/` have no Verus.
   - C03 gaps in every document match review report "Verdict", "Coverage table" and "C03 and BUG-07 items still uncovered": hkdf/hkdf_expand not end to end, `DigestContext::digest`'s `finish` unmodeled, adapters outside `verus!`, A12/A13 near-vacuous, `Ok` order is an in-body assert and `+16` relies on A19, seal-Err tail bytes undescribed, BUG-07(b) assumption-relative (A20 / A-OPEN). "Partly" and "in-body assert" are used; the other branch's stronger wording is flagged, not copied.
   - Re-run line: `rerun.md` and both logs: `rerun-default.log` lines 27 and 29 (`1858 verified` vstd, `18 verified, 0 errors` aws-mpl-primitives), `rerun-aws-lc-sys.log` line 2 (`18 verified, 0 errors`). Documents record `verification results:: 18 verified, 0 errors` at `8d6381e`, say 1858 is the vstd dependency and not a C03 result, and say 18 counts the whole prim crate (base 6b51de8 gave 10). Matches.
   - Re-run worktree: `/tmp/c03-status-check` is gone; `git worktree list` shows only the main repo.
2. No-score-change rule (run by me)
   - `check_scores.py`, `check_extras.py`, `check_misc.py`: `PROBLEMS: none`. `check_ratings.py`: 0 mismatches. `check_prose_scores.py`: 0 mismatching (1 history line, pre-existing). `check_proof_status.py` is bound to the old five-proof baseline: its only non-baseline output is "unknown result line '18 verified...'" (expected, the new C03 line) and stale-baseline YAML diffs; not usable as a gate here, replaced by the two checks below.
   - Rank, ID and score columns of the 73 ranked rows (merged 38, 01 27, 02 8): identical to `git show HEAD:` (`rank_score_diff.sh`, exit 0). Every ranked row differs from HEAD only in its last (Proof status) cell, checked by stripping the last two cells.
   - Own YAML diff of all blocks against HEAD: same ID sets (13 / 27 / 8). Changed blocks: C02 (added `proof_note` only), C03 (replaced `proof_status: "None yet"`, added `proof_location`, `proof_result`, `proof_trusted_base`, `proof_not_covered`, `related_bugs`), T26 (added `related_bugs`, `scope_note`; `proof_status` still "None yet"). No score, gap, feasibility, severity or quick-win key changed. Quick-wins prose only gains a sentence that C03 (5.60) is not one.
3. Cross-document consistency: the C03 status string, the C02 relation string, gaps and result line + commit are identical in merged, 02, 01 (section 7), threat model (proof-status rows), audit (resolution status), 04-validation, Chorus `.md`. `.docx` text (pandoc plain) equals the `.md` after normalizing table widths, so it was regenerated. Bug count updated to ten / twelve items in the Chorus document and no "nine bugs" claim remains. Headers (merged line 5, 01, 02, 04, Chorus "Added later" bullet, Date) match the bodies.
4. Evidence levels: C03 is "in-crate, shipped prim code, on Mahnush_Verus, not on this branch, under A1-A20", never "on this branch"; C02 keeps its model-level string, is "partly superseded", "not a duplicate and not demoted"; BUG-07(a) prim facts "proved on Mahnush_Verus", caller impact, BUG-10 and the "cannot fire today" conclusions are "code reading"; BUG-07(b) "relative to A20, not proved"; mpl "not Verus-enabled". No upgrade found. Qualifier of the "Verified is 0" threat counter correctly limited to this branch's shipped code.
5. Excluded paths and state: `git diff --quiet HEAD -- mpl prim esdk verus-proofs docs/bug-reports docs/spec-security-analysis.md docs/chorus/MPL-Bug-Reports.md` succeeds. `git status --porcelain`: the eight allowed documents plus untracked `.agents/tasks/docs-c03-status/`. HEAD `b94c871`, branch `MPL-Verus`. `origin/Mahnush_Verus` was added by a read-only fetch (reflog); `origin/main` moved 620771c to 5f2dc72 in an earlier fetch step, not by this work, and `prim/` and `mpl/` are identical across that move. Added Markdown has no HTML (only `Vec<u8>` / `<file>` inside code), emoji, footnote or Mermaid.
6. New cites: `raw_aes_keyring.rs:146,163,369-379,471,489-497`, `branch_key_wrap.rs:157,199,230,275`, `prim/src/lib.rs:215` read with `sed`; each points at the described construct.

## Fixes I made (in-scope documents only)

- `docs/completeness-audit.md` line 213 and `docs/verification-targets/04-validation.md` line 3 and the section 209 heading said "HEAD b94c871 plus the uncommitted edits / working tree". After the orchestrator commits, that is false. Reworded to "the update commit on top of HEAD `b94c871`". No other text changed; the Chorus `.md` was not touched, so the `.docx` needs no regeneration.

## Non-blocking observations (not findings)

- The threat model prints TM-MPL-015 as Medium/Low in some places and Low in others; pre-existing, ratings untouched (coder note 4).
- Cited section line numbers in the audit and threat model were remapped by the coder and spot-checked; the audit's findings table keeps audit-time numbers on purpose.
