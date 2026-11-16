# C02 working notes: ECDSA `sign_fixed_len` bounded retry (VR-2026-C02)

Proof: `verus-proofs/c02_sign_fixed_len.rs`
Log:   `.agents/tasks/verus-proofs-quickwins/logs/c02_sign_fixed_len.log`
Result line: `verification results:: 21 verified, 0 errors`  (Verus 0.2026.07.12, HEAD 66aba1c)
Status: **Proved**, for a re-typed model. Not machine-linked to the shipped Rust (see gap).

## Decisions
- aws-lc-rs cannot be compiled by Verus, so the file is a standalone model:
  `Signature` = local struct over `Vec<u8>`; `Error` = unit struct; the aws-lc-rs calls
  (key parse, sign, sign_digest, DigestContext::digest) = methods of a contract-free
  `trait Backend`; the closure = generic `F: FnMut() -> Result<Signature, Error>`
  with only `call_requires(f, ())`.
- Call counting is done with a ghost log (`&mut Ghost<Seq<Option<Seq<u8>>>>`), one entry
  pushed per `sign_once()` call. Reason: vstd's `axiom_fn_mut_call_ensures` states
  `mut_ref_current(f) == mut_ref_future(f)`, so FnMut state is not tracked and calls
  cannot be counted through the closure itself. `log_from_closure` ties each entry to
  `call_ensures`, so the log is justified by the closure's contract.
- Termination of the shipped `for _ in 0..128` comes from vstd's Range iterator spec.
  A `while ... decreases MAX_SIGN_ATTEMPTS - attempt` variant (`sign_fixed_len_while`) proves
  the same postcondition without relying on that spec. Labeled as a cross-check.
- `?` is written out as `match` (identity `From`). The ghost push sits between the call
  and the match, so the Err exit is logged.
- `for` loop exit facts need a loop-level `ensures` (checked by Verus at normal exit)
  to get `n == 128` for exhaustion; `iter.iter.start` is the progress counter.
- Early `return` inside a loop does not see `old(..)`/params that the loop does not
  mention: invariants `sig0 == old(signature)@`, `log0 == old(log)@`, `sign_once == f0`
  were needed.

## What was proved (`sign_fixed_len_post`, `ecdsa_sign_post`)
- T1: closure calls <= 128, old log is a prefix of the new one.
- T2: no panic in the modeled code (Verus overflow checks; `copy_from_slice`'s vstd
  `requires dst.len() == src.len()` is discharged by the length test at :187);
  termination.
- T3: Ok => buffer == the first candidate of exact length, written whole; Err => buffer
  unchanged; buffer length never changes.
- T4: Err is exactly (a) closure Err on call n after n-1 mismatching candidates, or
  (b) exhaustion n == 128 with all candidates mismatching. ecdsa_sign*: or n == 0.
- T5: `check_sig_len` Ok <==> len == signature_len(alg).
- T6: ecdsa_sign / ecdsa_sign_digest: wrong buffer length => Err, 0 calls, buffer untouched.
- Witnesses prove contracts are satisfiable: Ok after 1 call, exhaustion after exactly 128
  calls with unchanged buffer, wrong-length buffer rejected with 0 calls.

## Findings
- No code defect found in the C02 scope. Line anchors in the C02 YAML match HEAD 66aba1c
  (`:148`, `:180`, `:188`, `:200`, `:224`, `:253`).
- `sign_fixed_len` does not itself check `want_len in {71, 103}`. A direct caller with a wrong
  buffer would still stop after 128 calls (T1 does not need `check_sig_len`). The check only
  turns a 128-signature wait into an immediate Err; the function is private and both callers
  run `check_sig_len` first (T6).
- The "no partial write" property rests on `copy_from_slice` being all-or-nothing, which is
  vstd assumption A1 and std behavior.
- Out of scope, untouched: `ecdsa_verify*` ("never Err"), `ecdsa_generate_keypair`,
  `DigestContext::finish`.

## Gap to close (model vs shipped)
Machine-linking needs `prim` to compile under Verus (prim/ is read-only for this task), or a
shared source for the generic body, or a script that diffs the control-flow skeleton.
Until then the correspondence table in the file header is a manual review item.
