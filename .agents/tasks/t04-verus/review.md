# Independent review: T04 proof (`verus-proofs/t04_branch_key_wrap.rs`)

Scope: (1) faithfulness of the model to `mpl/src/aws_kms/branch_key_wrap.rs` and `prim/src/lib.rs`; (2) overclaiming in header, comments and `ensures`; plus a review of `mutations.md`. HEAD d6e42d8, proof file untracked. Nothing under `mpl/`, `prim/`, `esdk/` or the proof file was edited.

Evidence used: read all of `branch_key_wrap.rs` and `prim/src/lib.rs` (:122-197, :313-330), the spec sections (:108-135, :206-222), the whole proof file, and `mutations.md`. I ran the proof file once (`45 verified, 0 errors`, matches the header). I ran two extra mutants in `/tmp/t04review/` (not in the repo): A = `wrap` returns `Err` as its first statement; B = zeros written where the version bytes belong.

## Faithfulness result (check 1)

Compared line by line; no unstated difference found in:
- RNG calls and order: two separate `generate_random_bytes` calls, salt (:163-166) then IV (:169-172), both before the KDF, AAD and version steps. Only these two calls exist in the file (grep). Model matches.
- Sizes and offsets: constants 16/12/16/16/32, `FIXED_OVERHEAD_LEN` = 60, label bytes (17), prefix order salt, IV, version, then `aes_encrypt` appends ciphertext and tag (prim :185 and :196). Model matches. The `Vec` capacity argument (60 + n, no reallocation) holds.
- KDF input: `Sha256`, `branch_key()` as key, `label || 0 || salt || be32(256)`, 32 bytes out. Matches `derive_branch_key` (:122-144).
- AES-GCM input: `Aes256Gcm`, IV array, derived key, plaintext, AAD bytes. Matches :199-207. The two `requires` of A_AES correspond to prim :187-189.
- Error paths: every `?` maps to `Kind::Cryptographic` except the helper errors, which pass through unchanged. Error order (KDF, AAD, version) is the same in model and code.
- Unwrap parse: gate at :236, offsets :247-262, KDF salt `ct[0..16]`. Matches.
- Wiping: H_WIPE (`Zeroizing` at :135, passed as `&*derived_branch_key` at :202, dropped on every exit) is stated accurately as code reading, not proof. O1 (plaintext left in `output` after a failed seal, prim :185) is accurate.
- Header line numbers I checked are correct, apart from finding 9.

Model differences that ARE stated in the header: aad and version passed as values (H_AAD_PURE; `compute_aad` and `uuid_str_to_16_bytes` read no state, I confirmed none draws randomness), `debug_assert` turned into a proved `assert`, `Zeroizing` dropped, error messages dropped.

## Findings

1. **blocking. R8 wording "four different log entries" (header section 7, R8, text under `wrap_twice`).**
   The proof shows the two calls use four distinct log POSITIONS (indices n, n+1, n+2, n+3). It does not show the entries are different values. The file's own `toy_generate_random_bytes` returns zeros every time and meets the contract, so all four entries can be equal. "Different entries" reads as a uniqueness claim, which the file says elsewhere it does not make.
   Fix: in section 7 R8 replace "that the two calls use four different log entries, call 1 the first two and call 2 the last two" with "that the two calls use four distinct log positions (not necessarily different values), call 1 the first two and call 2 the last two".

2. **blocking. The proof is partial correctness only, and the header says "on every invocation".**
   Section 0 says "`wrap` makes two separate generator calls on every invocation", and the `wrap` doc comment says "on every invocation". Every `ensures` about the draws and the layout is of the form `r is Ok ==> ...`. I confirmed with mutant A (`return Err(..)` as the first statement of `wrap`) that Verus still reports `45 verified, 0 errors`. So the proof does not show that `wrap` can succeed, nor that any draw is made on a failing call (if the salt draw fails, the IV draw is not made, by the model's own early return). No sentence in the header says this.
   Fix: (a) section 0: replace "on every invocation" with "on every call that returns Ok (a call can fail before or after the draws)"; same change in the `wrap` doc comment, item 2. (b) add to section 6 (NOT COVERED): "All `ensures` are partial correctness (`r is Ok ==> ...`). Nothing proves that `wrap` returns Ok for any input; a model that always returned Err satisfies them (mutant tried, see mutations.md)." (c) add mutant A to `mutations.md` as a survivor that is explained by (b).

3. **minor. R2 says PROVED for "60 + |pt|" but the `+ 16` tail comes from the A_AES assumption.**
   The 44-byte prefix is proved; the n + 16 appended by `aes_encrypt` is the contract (A_AES), and the shipped `debug_assert` that would catch a violation is compiled out in release. Section 8 has this caveat, section 7 does not.
   Fix: in R2 append "(the 16 + n tail is A_AES, not proved; see section 8)".

4. **minor. Section 5 ends "audited model + machine-checked logic".**
   "Audited" suggests a completed independent audit. The model was written and checked by its author.
   Fix: replace with "hand-checked model + machine-checked logic".

5. **minor. Unwrap discards the version bytes; the header does not say so.**
   `unwrap` binds the ciphertext version as `_version` (branch_key_wrap.rs:254) and never uses it; the AAD uses the materials' version. The model returns `version` in `Parsed`, and R6/R7 say parse "recovers" the version. A reader may think unwrap checks it.
   Fix: add to section 6 or 2: "unwrap parses the version field but does not use or compare it (:254, `_version`); R6/R7 show only that the layout carries it."

6. **minor. The ghost log ignores other threads.**
   `rand::fill` uses a process-global generator. R1 ("grows by exactly two") and `wrap_twice` ("four entries") are per call chain on a sequential log; other threads' draws are not modeled. Section 5 mentions the ghost log only as something the real generator lacks.
   Fix: add one sentence to H_NO_STATE or A_RNG: "The log lists the draws of this call chain only; draws by other threads are not modeled. This does not affect the per-call structure proved."

7. **minor. `mutations.md` coverage (see section below).**
   Fix: add mutant A (always Err, survives) and mutant B (zero bytes instead of version, rejected: `44 verified, 1 errors`), and copy `mutate.py` and the mutant files out of `/tmp/t04work/` into `.agents/tasks/t04-verus/` so the run can be reproduced.

8. **minor. Satisfiability witness covers A_RNG only (already said), but the header title for R9 reads as general.**
   A_KDF and A_AES are also satisfied trivially by an implementation that always returns Err, which is why finding 2 applies. No fix beyond finding 2(b).

9. **minor. Spec line range.** Section 3 cites the spec "Ciphertext" section as `:106-135`; it starts at :108 (`### Ciphertext`). Fix: `:108-135`.

## mutations.md (is it meaningful?)

Mostly yes. The mutants are small model edits, each rejected by an assertion or postcondition that is about the property named (offsets M1, M16; one draw reused M2; draw order M7; KDF salt M4; AES IV M5, M13; algorithm/key size M6; length M3, M12; error handling M14, M15; unwrap M8, M9; conditional lemmas M10, M11). M2, M7 and M10/M11 are the ones that matter for TM-MPL-012: they show the proof fails if one draw is reused, if the order changes, or if the "distinct draws" premise is dropped. Real output lines are quoted, and exit codes are consistent with the counts.

Weak or missing:
- M12 (TAG_LEN = 15) is caught by `lemma_constants`, a constant arithmetic check, not by `wrap`. Low value.
- No mutant for "wrap can never succeed". I ran it (mutant A): it survives. See finding 2.
- No mutant that ignores an RNG error (salt draw failure continues with zero salt). I did not run it; the log-length assertions should reject it, but it is the most relevant mutant for the honesty point and should be added.
- Mutant files and script live in `/tmp` only (finding 7).
- The document correctly says a rejection shows sensitivity of the model, not correctness of the shipped code.

## Verdict

CHANGES_REQUESTED: findings 1 and 2 are wording and scope statements that the header's own honesty requirement needs; no proof change is required for them. Findings 3 to 9 are minor.
