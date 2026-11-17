# Review report: branch `Mahnush_Verus` (ed4a81e, 43b9ff7), VR-013 / VR-014, pipeline target VR-2026-C03 + BUG-07

Read-only review. Base `6b51de8`, tip `43b9ff7`. Nothing was modified, committed or pushed; this file is untracked.
Source of every statement below: `notes-1-rerun.md` ... `notes-6-cleanup.md` and `logs/` in this directory. The worktrees were removed before this report was written, so I could not re-open the source. All `file:line` references are in `/prim/src` (prim crate) at 43b9ff7 and are copied from the notes, not re-checked.
The checklist text is not in the notes directory. I numbered it from the notes headers: 1 re-run, 2 scope coverage, 3 no duplication, 4 soundness/trusted base, 5 behavior preservation, 6 test file, 7 docs consistency, 8 C02 cross-check.

## Verdict

**Consistent with gaps.**

All six scope items have in-crate Verus proofs on the real code. No VR-006, VR-008 or VR-009 code or proof is repeated. No `assume(`/`admit(`/`requires` was added. All 20 aws-lc-rs assumptions are true for aws-lc-rs 1.18.1 (default backend). Observed runtime behavior is unchanged. Both Verus feature sets read `18 verified, 0 errors`.

The gaps:
- The BUG-07(a) "tag after ciphertext on `Ok`" fact is an `assert` inside `aes_encrypt_core`, not an `ensures`. The seal-`Err` tail bytes are not proved.
- C03 is documented as in-crate without saying that `hkdf`/`hkdf_expand` "Ok => |okm| in {16,24,32}" and the no-panic clause are not proved end to end.
- The docs contradict each other on counts, line order and status (see "Doc inconsistencies").
- The 19-mutation evidence log cited by the report is not in the branch.
- `make verus` itself and every FIPS run were not executed.

## Exact `verification results::` lines (notes-1, `logs/after-verus-*.log`, `logs/base-verus-*.log`)

Commands: `PATH="$HOME/verus:$PATH"`, run in `prim/`. Notes-1 says the Makefile `verus` target is two `cargo verus` runs. The literal `make verus` was not run (see "Unverified").

`cargo verus verify` (default features), tip 43b9ff7:
```
verification results:: 1858 verified, 0 errors     (vstd, a dependency)
verification results:: 18 verified, 0 errors       (aws-mpl-primitives)
```
`cargo verus verify --no-default-features --features aws-lc-sys`, tip 43b9ff7:
```
verification results:: 18 verified, 0 errors       (aws-mpl-primitives)
```
(That log has no vstd line because vstd was already built. The crate was re-checked: "Checking aws-mpl-primitives".)

Base 6b51de8: `1858 verified, 0 errors` then `10 verified, 0 errors` (default); `10 verified, 0 errors` (min). Exit 0 for all four runs, no Verus warnings. Delta 10 to 18.

Other runs on the tip (default features): `cargo build` exit 0; `cargo test` 92 tests + 8 doc-tests, 0 failures, including `test_wrapper_contracts` 7/7; `cargo clippy --tests --examples` exit 0, 0 warnings. A separate scratch run (notes-5) of `cargo verus verify` in `esdk/` printed `1858`, `18` (prim), `69 verified, 0 errors` (aws-esdk).

## Checklist answers

**1. Does it re-run clean?** Yes. See the Verus lines above. FIPS `cargo build/test/clippy` fail with "Missing dependency: cmake" in the `aws-lc-fips-sys` build script (`logs/after-build-fips.log:224`). The base fails identically (`logs/base-build-fips.log`), so it is the environment. FIPS tests and clippy were not run on either side. The Makefile has no FIPS Verus run.

**2. Scope coverage?** Items 1 to 5 and 6(a) key/nonce/`Ok`, and 6(b), are covered. 6(a) seal-`Err` is partly covered. 6(b) is correctly labeled assumption-relative. Details in the coverage table.

**3. No duplication of VR-006/008/009?** Yes. `aes_encrypt_extend_core` (lib.rs:192) body is unchanged, with two `ensures` conjuncts added (`slice@ == message@`, `final(ct) == old(ct) + final(slice)`). `aes_decrypt_len_ok` (lib.rs:227) is byte-identical to base and is called, not restated. `sign_fixed_len_core` (ecdsa.rs:270) is identical to base (diff of base 195-320 vs head 224-349). `hkdf.rs` has no diff. One mild overlap: the `!PlainTooShort` clause of `aes_decrypt_core` is a consequence of VR-006's `iff`.

**4. Sound and honest?** Mostly. Inventory (notes-3): `assume(`/`admit(`/axiom/broadcast/`#[verifier::external]` fn/unsafe = 0. Added `requires` = 0. `external_body` only on 15 opaque types. 8 `uninterp spec fn`. 20 `assume_specification` (A1-A20). 1 trait proxy. All are in the docs' TCB table. No vacuity was found: 21 `assert(false)` probes on the new paths each failed as they should, and one function using A1-A19 together did not make `assert(false)` provable. See "Trusted assumptions". Honesty problems are in docs wording (B2, B3, B4 below), not hidden assumptions.

**5. Behavior preserved?** Yes by inspection and by a differential run (notes-4). A harness ran base and tip `prim` on 1443 transcript lines (1359 `Err`): aes_encrypt/decrypt, hmac, digest, finish, kbkdf, random, constant_time. The outputs were byte-identical (`diff` empty), and the two binaries differ, so the tip code was exercised. The harness ran on aws-lc-rs 1.19.0, not the locked 1.18.1. The seal-failure path and the kbkdf "unavailable" branch are unreachable from the public API and were checked by inspection only. See "Behavior changes".

**6. Test file `prim/tests/test_wrapper_contracts.rs`?** 7 tests, deterministic, no env/network/files, no tautologies. They pass on tip and on base (7/7 each), so they pin behavior and would not catch a proof regression. Gaps: only Aes256 for the BUG-07(a) test; no seal-failure case; the `aes_decrypt` Err cases do not assert the buffer is untouched; no tests for `generate_random_bytes`/`constant_time_equal` here (existing suites cover them).

**7. Docs consistent?** No. Counts and the VR/BUG cross-references are right and the TCB list matches the code, but several documents contradict each other and some claims exceed the proofs. See "Doc inconsistencies".

**8. C02 vs VR-008?** On the real loop, VR-008 has the same retry bound (`MAX_SIGN_ATTEMPTS = 128`, `decreases`), termination, and guarded `copy_from_slice` as the C02 standalone model. It has no `ensures`, so C02's T1 as a stated postcondition, T3 (no partial write: `Err` leaves buffer unchanged, `Ok` writes one whole candidate), T4 (which `Err` exits exist), T5 (`check_sig_len`), T6 (`ecdsa_sign*` wrong-length contract) and the non-vacuity witnesses are not in VR-008. `check_sig_len` and `ecdsa_sign*` are outside `verus!`. VR-013/014 add none of these. `c02_sign_fixed_len.rs` is on the local `MPL-Verus` HEAD (35f24c9) but not on `origin/MPL-Verus`; it was read from disk.

## Coverage table, scope items 1-6

| # | Item | Function (file:line) | What `ensures` / what is proved | Status |
|---|---|---|---|---|
| 1 | `hmac` | `hmac_core` (lib.rs:283-306); adapter lib.rs:599 | `Ok <==> out.len() == spec_hmac_tag_len(alg)`; `Err ==> e.want_len == tag_len && final(out) == old(out)`; copy (lib.rs:301) only after guard. In-bounds relies on trusted A8. | Covered |
| 2 | `digest` | `digest_core` (lib.rs:256-276); adapter lib.rs:629 | Same three facts against `spec_digest_output_len`; copy lib.rs:272 after guard; trusted A2. | Covered |
| 3 | `DigestContext::finish` | `digest_finish_core` (ecdsa.rs:195-212); adapter ecdsa.rs:~84 | Same three facts against `spec_context_output_len`; copy ecdsa.rs:210 after guard; trusted A5 (length, and `expect("EVP_DigestFinal failed")` assumed unreachable). | Covered |
| 4 | `kbkdf_ctr_hmac` wrapper | `kbkdf_core` (lib.rs:319-337); adapter lib.rs:670-690 | `(r is Err(Unavailable)) <==> !spec_kbkdf_available(id)`; `Ok ==> available`; `okm` length kept. `Err -> DerivationFailed` is in the body. The `DigestAlg -> KbkdfCtrHmacAlgorithmId` match and message text stay in the unverified adapter. | Covered (wrapper logic only, as scoped) |
| 5a | `generate_random_bytes` | `fill_random_core` (lib.rs:350-357); adapter lib.rs:136 | No `requires`; `final(bytes).len == old(bytes).len`. Totality + a Rust type fact, no randomness claim. | Covered (totality only) |
| 5b | `constant_time_equal` | `ct_equal_core` (lib.rs:364-368); adapter lib.rs:647 | `r == spec_slices_equal_ok(a@, b@)`, with that fn `uninterp` and A13 saying only "function of the two byte sequences". No claim that `true` means equal, no timing claim. | Covered, but near-vacuous: restates A13 |
| 6a | BUG-07(a) `aes_encrypt` | `aes_encrypt_core` (lib.rs:397-439); extend core lib.rs:192-198 | Key/nonce `Err` ==> `final(ct) == old(ct) + message`. Seal `Err` ==> length `old+len(msg)` and prefix `old` unchanged. `Ok` ==> length `old+len(msg)+16`, prefix unchanged. | **Partly**: seal-`Err` tail contents not proved (A18 says nothing about bytes). `old ++ ct ++ tag` on `Ok` is an in-body `assert` (lib.rs:437), not an `ensures`, and the `+16` rests on trusted A19. |
| 6b | BUG-07(b) `aes_decrypt` guard weaker than callee | `aes_decrypt_core` (lib.rs:470-501), calls `aes_decrypt_len_ok` (lib.rs:~487) | `Ok ==> |plain| == |ct|`; `|plain| > |ct| ==> Err && !PlainTooShort`; `plain` length kept. Both clauses rest on A20 (A-OPEN). | Covered, labeled assumption-relative (lib.rs:~450-466 "assumed, not proved") |
| Extra | `ExAsRef` trait proxy, `#![cfg_attr(verus_keep_ghost, feature(sized_hierarchy))]`, `[lints.rust] unexpected_cfgs` | lib.rs:~10, `Cargo.toml`, `aws_lc_specs.rs:318-327` | Needed to name `Aad<A: AsRef<[u8]>>`. Inert unless `verus_keep_ghost`. `Cargo.lock` unchanged. | Extra (disclosed) |
| Extra | New tests | `prim/tests/test_wrapper_contracts.rs` | 7 behavior-pinning tests | Extra |
| Extra | Strengthened VR-006 core | `aes_encrypt_extend_core` lib.rs:192-198 | Two added `ensures` conjuncts; body unchanged | Extra (extends, not re-proves) |

Missing: nothing from items 1-6 is wholly absent.

## Trusted assumptions (aws_lc_specs.rs; checked against aws-lc-rs 1.18.1 source and aws-lc-sys 0.45.0; no `assume_specification` has a `requires`, so each call is assumed not to panic)

Judgment key: TRUE = matches the checked source. FIPS backend (`aws-lc-fips-sys` 0.14.2) C code was not read, so any claim that depends on C-side lengths is UNCHECKED for FIPS; the Rust layer is the same aws-lc-rs.

| Id | Assumes | file:line | Judgment | Evidence |
|---|---|---|---|---|
| T-ty (x15) | opaque types `digest::{Algorithm,Digest,Context}`, `hmac::{Algorithm,Key,Tag}`, `error::Unspecified`, `kdf::{KbkdfCtrHmacAlgorithm,KbkdfCtrHmacAlgorithmId}`, `aead::{Algorithm,UnboundKey,Nonce,LessSafeKey,Aad<A>,Tag}`; no fields or invariants | aws_lc_specs.rs:34..343 | TRUE (makes no claim) | `external_body` on types only |
| T-AsRef | `ExAsRef` proxy, signature only | :318-327 | TRUE (makes no claim) | no method spec; `cfg(verus_keep_ghost)` |
| T-uf (x8) | `spec_digest_output_len`, `spec_digest_len`, `spec_context_output_len`, `spec_hmac_tag_len`, `spec_hmac_key_alg`, `spec_hmac_tag_bytes_len`, `spec_kbkdf_available`, `spec_slices_equal_ok` uninterpreted | :53,58,63,141,146,151,223,265 | TRUE (makes no claim alone) | no axiom pins a value; only A19 pins `16` |
| A1 | `Algorithm::output_len == spec_digest_output_len` | :67 | TRUE | digest.rs:299-301 |
| A2 | `digest::digest` length = alg output length; no panic | :77 | TRUE | digest.rs:194-202; digest/sha.rs:200-228. FIPS C side UNCHECKED |
| A3 | `Digest::as_ref` has `spec_digest_len` bytes | :87 | TRUE | digest.rs:251-255 |
| A4 | `Context::algorithm` output_len `== spec_context_output_len` | :95 | TRUE | digest.rs:162-166 |
| A5 | `Context::finish` length = context output length; no panic | :106 | TRUE for length. No-panic TRUE only if C `EVP_DigestFinal` succeeds (`expect` at digest.rs:136-138) | digest.rs:151-158. FIPS C side UNCHECKED |
| A6 | `hmac::Algorithm::tag_len == spec_hmac_tag_len` | :154 | TRUE | hmac.rs:137-139 |
| A7 | `hmac::Key::new` keeps its algorithm; no panic | :162 | TRUE for the link. No-panic TRUE only if C succeeds (`expect("Unable to create HmacContext")`, hmac.rs:297-299) | hmac.rs:315-318 |
| A8 | `hmac::sign` tag length = key algorithm's tag length; no panic | :172 | TRUE for length. No-panic TRUE only if C succeeds (`expect` at hmac.rs:205, 391, 425) | hmac.rs:431-438, 446-469. FIPS C side UNCHECKED |
| A9 | `hmac::Tag::as_ref` length `== spec_hmac_tag_bytes_len` | :182 | TRUE | hmac.rs:166-171 |
| A10 | `get_kbkdf_ctr_hmac_algorithm`: `Some <==> spec_kbkdf_available(id)` | :228 | TRUE (weaker than reality: always `Some` in 1.18.1) | kdf/kbkdf.rs:38-49 |
| A11 | `kbkdf_ctr_hmac` keeps `output` length; no panic | :237 | TRUE | kdf/kbkdf.rs:103-145 |
| A12 | `rand::fill` keeps `dest` length; no panic | :253 | TRUE | rand.rs:205-210 |
| A13 | `verify_slices_are_equal`: `Ok` iff `spec_slices_equal_ok(a@, b@)` (function of bytes only); no panic | :270 | TRUE | constant_time.rs:15-26 |
| A14 | `UnboundKey::new` no panic | :346 | TRUE | aead/unbound_key.rs:36-42 |
| A15 | `Nonce::try_assume_unique_for_key` no panic | :352 | TRUE | aead/nonce.rs:26-28 |
| A16 | `LessSafeKey::new` no panic | :357 | TRUE | aead.rs:709-712 |
| A17 | `Aad::<A>::from` no panic | :362 | TRUE | aead.rs:661-666 |
| A18 | `seal_in_place_separate_tag` keeps `in_out` length; no panic | :368 | TRUE | aead.rs:890-902 -> unbound_key.rs:502-536 (`debug_assert_eq!` at :513 is debug-only) |
| A19 | `aead::Tag::as_ref` length is exactly 16 | :380 | TRUE for the AES-GCM tags prim produces. FIPS C side UNCHECKED | aead.rs:1032-1034, 1086; unbound_key.rs:535, 582; aws-lc-sys e_aes.c:1024-1025, 1116 |
| A20 = A-OPEN | `open_separate_gather`: `Ok ==> |in_ciphertext| == |out_plaintext|`; length kept; no panic | :393 | TRUE | check at aead/unbound_key.rs:~139-141 before the FFI call (line numbers disagree across notes, see inconsistencies) |
| pre-existing | `copy_from_slice` spec (VR-008) | ecdsa.rs:179-183 | TRUE | unchanged by this branch |
| implicit | every aws-lc-rs call is panic-free | blanket | TRUE only with C-library failure/OOM out of scope. Not checked: what makes `EVP_DigestFinal`, `HMAC_Init_ex`, `HMAC_Final` fail | notes-3 sec. 3, 7 |
| implicit | `hmac::Algorithm::tag_len() == digest output_len` (the new `hmac` guard source) | lib.rs:283-290 | TRUE for 1.18.1 and 1.19.0; UNCHECKED for later versions (Cargo requirement `1.18.1` allows them) | hmac.rs:137-139 |

Not read: `Context::update` and `DigestContext::new` panic sites in aws-lc-rs (digest.rs:99, :87). They are not on any proved path and have no spec.

## Behavior changes found

None observed. Notes, all with no observable change in the differential run:
- `hmac`: the guard length now comes from `hmac_alg.tag_len()` instead of `get_digest_alg(alg).output_len()`. Equal in aws-lc-rs 1.18.1 and 1.19.0 source. This is a change of source of truth, not of behavior, and could diverge in a future aws-lc-rs. Disclosed in `docs/verus-proofs-report.md:536-543`.
- `aes_decrypt`: `get_aes_alg` now runs before the guard (pure const fn); key/nonce/open errors use `err(..)` = `Err(serr(..))` instead of `serr(..)?`. Same kind and text; `Error` stores no location.
- `digest`, `finish`, `kbkdf_ctr_hmac`, `generate_random_bytes`, `constant_time_equal`, `aes_encrypt`: guard, message and order unchanged.
- BUG-07(a) and (b) are preserved exactly (plaintext still appended on `Err`; a longer plaintext buffer still reaches the callee and reports "authentication tag did not match"). They are recorded, not fixed.
- Build-level, non-runtime: `cfg_attr(verus_keep_ghost, feature(sized_hierarchy))`, `[lints.rust] unexpected_cfgs` (appended without a blank line), new module `aws_lc_specs.rs`. `cargo build` on the tip gives 0 warnings; `cargo tree` is unchanged; `Cargo.lock` is not in the diff.

## Doc inconsistencies

Claims stronger than the proofs:
- **B1.** C03 is presented as "in-crate" (`verus-proofs-report.md:106-112, 725-726`; `verification-recommendations.md:52-53, 250-251`) with no "partial". The C03 block also requires `hkdf`/`hkdf_expand` "Ok => |okm| in {16,24,32}" and "no listed function panics". VR-009 proves only `hkdf_key_len_ok`, `salt_size_core`, `no_salt_slice_core`. The remainder is not listed anywhere.
- **B2.** `Ok => old ++ ct ++ tag` is called proved in `verification/README.md:109`, `verification-recommendations.md:251, 988` and `verus-proofs-report.md:584, 726`. Only `verus-proofs-report.md:579` says "in-body assert". The `+16` relies on A19.
- **B3.** "A longer buffer ... ends in a callee-side `Err`" (`README.md:110`, `verus-proofs-report.md:585, 726`, `verification-recommendations.md:251`) is stronger than the postcondition (`Err` and `!PlainTooShort`), which also allows `InvalidKey`/`InvalidNonce`. The `!PlainTooShort` part follows from VR-006; the only new content is `Err` for a long buffer, and it comes entirely from A-OPEN.
- **B4.** "No panic" reads as unconditional for hmac. Only `Context::finish` is named (F4); the three hmac `expect` sites are not enumerated.
- **B5.** `ct_equal_core` and `fill_random_core` add no evidence beyond A13/A12. The docs say so (`verus-proofs-report.md:677-679`).

Contradictions and stale numbers:
- **C1.** `verification/README.md:20-21, 26-27` say the esdk result is the second `verification results::` line and `57 verified`. The new text at `:82-83` and the actual esdk run show it is the third line, `69 verified`. `esdk-verification-developers-guide.md:123-124, 148` repeat "second line", so a reader following it reads the prim `18` as the esdk result.
- **C2.** The guide says prim has "three cores" (`:48-49, 103`); prim now has six VR-013 cores, two VR-014 cores and `aws_lc_specs.rs`, which `:162` does not list.
- **C3.** `verification-recommendations.md:81, 166-167, 246, 699, 708` still say the VR-009 prim half is not proven and Verus is off in prim, contradicting `:94-99, 376, 691` and the README.
- **C4.** `verification-recommendations.md:71-72` say 12 targets; there are 14. Rows 13 and 14 score 5.6 but sit after rows scoring 6.0, 4.8, 4.0, so `rank` is id order, not score order. `:75` heading still says "Status at 4396173f (VR-012 branch)".
- **C5.** `docs/verification-dashboard-design.md:81` shows prim `10 verified`; `threat-model.md:825, 837` and `verus-in-crate-migration-design.md:21, 256` carry older counts (pre-existing).
- **C6.** The docs name branch `verus-prim-c03`; the branch is `Mahnush_Verus`.
- **C7.** `verus-proofs-report.md:755` cites `.agents/tasks/verus-prim-c03/logs/mutations.md` (M1-M19); no `.agents/` path exists in the branch, so the 19 mutation claims cannot be checked. The reviewer re-ran one mutation (guard removed from `digest_core`): `17 verified, 1 errors`, matching the report.
- **C8.** "+8 cores" reads as a function count; Verus's number counts obligations (the esdk README already says so; the prim section does not).
- **C9.** `verus-proofs-report.md:123-125`: two `>` blockquote notes run together (no `>` blank line between).
- **C10.** "2 call sites each ... esdk (2 + 5)" (`verus-proofs-report.md:608-611, 726`) is undefined; marked FOLLOW-UP.
- **C11.** A20 cites `unbound_key.rs:136-139`; see the next section for what the notes say the real lines are.

## Inconsistencies between the review notes themselves (not smoothed)

1. **A20 line numbers.** The docs cite `unbound_key.rs:136-139`. Notes-3 says the real check is at 139-141; notes-5 says 138-141. Unresolved. All agree the equality check sits before the FFI call.
2. **aws-lc-rs version.** Notes-1 and notes-3 use the locked 1.18.1 (`prim/Cargo.lock:36-39`). Notes-4's differential harness and its review-copy `cargo test` resolved aws-lc-rs 1.19.0 / aws-lc-sys 0.47.0 (copied lockfile). So "behavior identical" was shown on 1.19.0; the source-reading TRUE judgments are for 1.18.1; only `tag_len` was source-compared on both.
3. **Panic sites in `DigestContext::new`/`update`.** Notes-2 (8b item 4) says "no panic site found"; notes-3 (7.3) lists aws-lc-rs panic sites at digest.rs:87 and :99. The scopes differ (prim code vs aws-lc-rs code), but notes-2 alone overstates.
4. **Probe counts in notes-3.** It states 22 reachable-path probes but lists 21 error line numbers (2 in ecdsa.rs, 19 in lib.rs). It also reports `10 verified, 9 errors` (sum 19) for a crate of 18 verified functions; that adds up only if the `vac_all` function from its later step 3 was in that run, which the notes do not say. The conclusion (no `assert(false)` was provable) is not affected, but the counts do not reconcile.
5. **Scratch cleanup.** Notes-6 lists only `/tmp/review-*`; notes-3 and notes-5 used `/tmp/n3-*`, `/tmp/n5-scratch`. I checked: none of `/tmp/n3-*`, `/tmp/n5-*`, `/tmp/review-*` exist now.

## Unverified

- Literal `make verus`: not run. Equivalent `cargo verus` commands were.
- FIPS: no build, test, clippy or Verus run (cmake missing; base fails identically). FIPS C-side claims for A2, A5, A8, A19, A20 are UNCHECKED.
- Seal-failure path and kbkdf "unavailable" branch: unreachable from the public API; behavior checked by reading only.
- What the C library failure conditions are for `EVP_DigestFinal`, `HMAC_Init_ex`, `HMAC_Final`.
- I did not re-open source after the worktrees were removed; line numbers are the notes' numbers.

## C03 and BUG-07 items still uncovered

C03 (prim):
1. `hkdf` / `hkdf_expand` "Ok => |okm| in {16,24,32}" and no-panic: only the decision fn (VR-009) is proved; `Salt::new`, `extract`, `expand`, `fill` and `get_len` are unmodeled.
2. `DigestContext::digest(self)` (ecdsa.rs:~96, used by `ecdsa_sign_digest` and `ecdsa_verify_context`) calls `finish()`, which documents `expect("EVP_DigestFinal failed")` (digest.rs:131-137). A5 trusts it unreachable only inside `digest_finish_core`; this call site is unmodeled.
3. `DigestContext::new`, `new_from_ecdsa`, `update`, `output_len`: unmodeled thin calls.
4. ECDSA wrappers: `check_sig_len` (ecdsa.rs:359), `ecdsa_sign` (:~377), `ecdsa_sign_digest`, `ecdsa_verify`, `ecdsa_verify_context`, `ecdsa_generate_keypair`, and the `sign_fixed_len` adapter (:~330-352). These belong to C02.
5. Adapter code outside `verus!`: `format!` messages (hmac lib.rs:~609, digest lib.rs:~634, finish ecdsa.rs:~88, kbkdf lib.rs:~681, aes_decrypt lib.rs:~575), `get_aes_alg`, `get_digest_alg`, the `DigestAlg -> KbkdfId` match. Total matches, no panic by reading, not machine-checked.
6. Hand-maintained tables `DigestAlg::output_len` (lib.rs:~95-102) and `AesGcm::key_length` are not tied to aws-lc-rs.
7. All aws-lc-rs panic-freedom (A1-A20), plus A-OPEN, A19 and the A2/A5/A8 lengths, are trusted. OOM is out of scope per the task.

Unmodeled panic sites in prim: a scan of non-test `prim/src` found no `.expect(`, `.unwrap(`, `panic!`, `unreachable!`, `assert!`, index `[i]` or `as` casts. Every `copy_from_slice` (ecdsa.rs:210, :300; lib.rs:272, :301), slice (hkdf.rs:142) and `split_at_mut` (lib.rs:206) is inside a proved core. `unwrap_or_else` at ecdsa.rs:348 is not a panic. The only unmodeled panic-capable operations are the aws-lc-rs calls (above) and `finish` inside `DigestContext::digest`. `ecdsa_generate_keypair` returns `Err`; the `.expect` is in the caller (`mpl/src/cmm/default_cmm.rs:137-138`), outside prim.

BUG-07 caller-side impact (not reviewed by VR-014, which lists it as FOLLOW-UP; found by grep in notes-2):
- (a) `aes_encrypt` callers: `mpl/src/keyring/raw_aes_keyring.rs:163` (fresh `Vec`; `?` on `Err` drops the plaintext data key, not zeroized), `mpl/src/aws_kms/branch_key_wrap.rs:199` (plaintext data key appended after salt||iv||version, dropped on `?`), `esdk/src/secret.rs:398` -> `esdk/src/message/body/body_encrypt.rs:306` (`frame_buf` holds plaintext after `Err`; `construct_frame` only calls `clear()` at :177, no zeroing; the buffer is reused), `esdk/src/encrypt.rs:772` (message `&[]`, not affected). Impact is plaintext residue in freed or reused heap memory, not data corruption and not a confidentiality break across an API boundary in these callers. VR-014 proves the residue exists and says nothing about zeroization.
- (b) `aes_decrypt` callers size the buffer exactly to the ciphertext (`raw_aes_keyring.rs:468`, `branch_key_wrap.rs:274`, `body_decrypt.rs:~395, ~407`, nonframed `:763`), so (b) looks unreachable from in-repo callers; it is reachable only for external users of `prim::aes_decrypt`. `esdk/src/decrypt.rs:551` (header auth, `&[]` ciphertext) was not checked. The "authentication tag did not match" message for every callee error is adapter code, untouched and unproved.

C02 items not carried into VR-008: T1 as `ensures`, T3, T4, T5, T6, non-vacuity witnesses, `signature_len` table (see checklist 8).

## Recommended fixes for the other agent, ranked

1. **Fix the C03 status wording.** Change "in-crate" to "partly in-crate" in `verus-proofs-report.md:106-112, 725-726` and `verification-recommendations.md:52-53, 250-251`, and list the uncovered remainder (hkdf/hkdf_expand end to end, `DigestContext::digest`'s `finish` call).
2. **Make the tag-order fact honest.** Either export it (an `ensures` on `aes_encrypt_core` that the `Ok` suffix is the tag, which needs a way to name the tag bytes, so I have not tested that it verifies) or write "asserted in the body, not exported; +16 relies on A19" in `README.md:109`, `verification-recommendations.md:251, 988`, `verus-proofs-report.md:584, 726`.
3. **Reword BUG-07(b).** Say the core proves `Err` and `!PlainTooShort` under A-OPEN, that only the over-long-buffer `Err` is new, and that the "tag did not match" message is unproved adapter code. Replace "callee-side `Err`" (B3).
4. **Repair contradicting docs** (C1-C5): README 57 and "second line" to 69 and "third line"; same in the guide (`:123-124, 148`); guide "three cores" and file list; recommendations doc 12 to 14 targets, the five "prim not proven / Verus off" sentences, rank order, heading; dashboard example 10 to 18.
5. **Commit `mutations.md` or remove the reference** (C7), so M1-M19 are checkable.
6. **Add an F4-style note for the hmac panic sites** (hmac.rs:297-299, 205, 391, 425), relabel A4/A7 (they are real link facts, not only "naming"), and correct the A20 line numbers.
7. **Pin the hmac guard source.** Add a test that `tag_len()` equals the digest output length for each algorithm, or keep the old `get_digest_alg(alg).output_len()`. It is behavior-neutral today.
8. **Tests.** Assert the buffer is untouched on `aes_decrypt` Err cases; add AES-128/192 to the BUG-07(a) test.
9. **Cosmetics.** Branch name `verus-prim-c03` vs `Mahnush_Verus`; `>` blank line at `verus-proofs-report.md:123-125`; blank line before the `Cargo.toml` `[lints.rust]` table; say prim "N verified" counts obligations; define "2 + 5" call sites.
10. **Out of scope here, for the owners.** `ensures` on `sign_fixed_len_core` (`Err ==> final(signature) == old(signature)`, `Ok ==> length kept`) to close C02 T3; BUG-07(a) zeroization/caller drop analysis; BUG-07(b) message fix.

## Cleanup (notes-6)

The throwaway worktrees `/tmp/review-mahnush-verus` and `/tmp/review-mahnush-verus-base` were removed with `git worktree remove --force` and `git worktree prune`; `/tmp/review-vr013-harness`, `/tmp/review-base-copy`, `/tmp/review-tip-copy` were deleted. The main repo `esdk-native-mpl` is unchanged against `baseline-git-status.txt`: branch `MPL-Verus`, HEAD `e3abf2db6bc3678876ff303ec84a377a81714544`, only untracked `?? .agents/tasks/review-vr013-vr014/`, one worktree. `origin/Mahnush_Verus` is still `43b9ff7751eea2199f37344505861f1e78b0967c`. I re-checked status and HEAD while writing this report: same.
