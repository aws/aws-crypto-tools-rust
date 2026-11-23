# Response to review.md (T04 proof)

Checked each finding against `mpl/src/aws_kms/branch_key_wrap.rs`, `prim/src/lib.rs` and the spec. Edits are to `verus-proofs/t04_branch_key_wrap.rs` (comments only; the proof still shows 45 verified, 0 errors) and to `mutate.py` / `mutations.md` in this directory. Nothing under `mpl/`, `prim/`, `esdk/` changed. Not committed.

## Applied

1. (blocking) R8 and the `wrap_twice` doc now say "four distinct log positions (not necessarily different values)". Correct: the proof only indexes n..n+3, and the toy generator meets A_RNG with equal values.
2. (blocking) "on every invocation" is now "on every call that returns Ok (a call can fail before or after the draws)" in section 0 and in the `wrap` doc. Section 6 gains "Termination with Ok" (partial correctness only). I re-ran the review's mutant A as `MA`: it survives (45 verified, 0 errors). Detail: placed as the literal first statement it is rejected, only because `log_extends` needs its refl lemma; `MA` is placed after that lemma.
3. R2 now says the 16 + n tail is A_AES, not proved (matches `aes_encrypt`, prim :185-196, and the release-compiled-out `debug_assert` at :209).
4. Section 5 "audited model" is now "hand-checked model".
5. Section 6 notes that `unwrap` binds the version as `_version` (:254) and never uses it. Verified in the code.
6. H_NO_STATE notes that the log covers this call chain only and that the aws-lc-rs generator is process-global.
7. `mutations.md` regenerated with real output; added `MA` (always Err, survives, explained), `MB` (zeros instead of version, rejected) and `MC` (salt draw failure ignored, rejected; the mutant the review suggested for the honesty point). `mutate.py` is stored in this directory.
8. Covered by 2(b): the "always Err" survivor and the section 6 note.
9. Spec range corrected to `:108-135` (heading `### Ciphertext` is at :108).

## Rejected

- Finding 7, part "copy the mutant files out of /tmp": not done. `mutate.py` regenerates all mutant copies from the proof file, so storing 19 near-copies of a 1300-line file adds nothing and would go stale.
- Salt/IV freshness: no claim added. The only distinctness statement remains the conditional R8 (premise H_RNG_DIFFERS, never established).
