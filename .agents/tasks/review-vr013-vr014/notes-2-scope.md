# Review notes 2/3/8: scope coverage, duplication, C02 cross-check (VR-013 / VR-014)

Reviewed: branch `Mahnush_Verus`, tip `43b9ff7` (worktree `/tmp/review-mahnush-verus`), base `6b51de8` (`/tmp/review-mahnush-verus-base`). Read-only. Nothing was run that builds or modifies either worktree; `make verus` was not run in this step (other checklist items).

Commands used:
- `git -C /tmp/review-mahnush-verus diff --stat 6b51de8 HEAD` (9 files, +1343/-65: prim/src/lib.rs, ecdsa.rs, new aws_lc_specs.rs, Cargo.toml, tests/test_wrapper_contracts.rs, verification/README.md, docs/verus-proofs-report.md, docs/verification-recommendations.md, docs/esdk-verification-developers-guide.md). `prim/src/hkdf.rs` is NOT in the diff.
- `git diff 6b51de8 HEAD -- prim/src/lib.rs prim/src/ecdsa.rs prim/Cargo.toml` (read in full), plus the docs diff.
- `git show origin/MPL-Verus:` for the C03 block, BUG-07 and RECHECK docs.
- NOTE: `verus-proofs/c02_sign_fixed_len.rs` is NOT in `origin/MPL-Verus` (`git show` fails: "exists on disk, but not in 'origin/MPL-Verus'"). It is committed on the local `MPL-Verus` HEAD (`git log` shows 35f24c9). I read it from disk.

All file:line refs are in `/tmp/review-mahnush-verus` at 43b9ff7 unless noted.

## 2. Scope coverage

| # | Scope item | What VR-013/VR-014 prove (fn, ensures, file:line) | Verdict |
|---|---|---|---|
| 1 | `hmac` | `hmac_core` (lib.rs:283-306): `(r is Ok) <==> out.len() == spec_hmac_tag_len(alg)`, `Err(e) ==> e.want_len == tag_len && final(out) == old(out)`, copy at lib.rs:301 only after the guard; in-bounds via trusted A8 (aws_lc_specs.rs: `hmac::sign` tag length == key algorithm tag length). Adapter `hmac` at lib.rs:599. | Covered. Behavior-change note below (guard length source). |
| 2 | `digest` | `digest_core` (lib.rs:256-276): same three facts against `spec_digest_output_len`; copy at lib.rs:272 after guard; in-bounds via trusted A2. Adapter lib.rs:629. | Covered |
| 3 | `DigestContext::finish` | `digest_finish_core` (ecdsa.rs:195-212): same three facts against `spec_context_output_len(&context)`; copy at ecdsa.rs:210 after guard; trusted A5 (length and `expect("EVP_DigestFinal failed")` unreachable). Adapter ecdsa.rs:~84. | Covered |
| 4 | `kbkdf_ctr_hmac` wrapper logic | `kbkdf_core` (lib.rs:319-337): `(r is Err(Unavailable)) <==> !spec_kbkdf_available(id)`, `Ok ==> available`, `okm` length kept; `Err(_) -> DerivationFailed` mapping is in the body (two-variant enum, so the mapping is exhaustive by construction, not a separate ensures). The `DigestAlg -> KbkdfCtrHmacAlgorithmId` match (lib.rs:~675) and the `Error` messages stay in the unverified adapter (lib.rs:670-690). No panic path: Verus checks the body, aws-lc-rs calls trusted not to panic (A10, A11 have no `requires`). | Covered (wrapper logic only, as scoped). Message mapping is adapter code, not proved. |
| 5a | `generate_random_bytes` | `fill_random_core` (lib.rs:350-357): no `requires`, `final(bytes).len == old(bytes).len`. This is totality plus a Rust type fact; no randomness claim. Adapter lib.rs:136. | Covered (totality only, as scoped) |
| 5b | `constant_time_equal` | `ct_equal_core` (lib.rs:364-368): `r == spec_slices_equal_ok(a@, b@)` where that spec fn is `uninterp`; A13 states only that the result is a function of the two sequences. No claim that `true` means equal, no timing claim. Adapter lib.rs:647. | Covered (deliberately no third-party semantics). Note the `ensures` is nearly vacuous: it proves no more than "totality + determinism". |
| 6a | BUG-07(a) `aes_encrypt` Err paths + Ok tag order | `aes_encrypt_core` (lib.rs:397-439): key or nonce `Err` => `final(ct) == old(ct) + message` (exact contents and length `old+len(msg)`); seal `Err` => length `old+len(msg)` and prefix `old` unchanged, tail NOT specified; `Ok` => length `old+len(msg)+16`, prefix `old` unchanged, and an in-body `assert(cipher_text@ =~= o + ct + tag_bytes@)` (lib.rs:437) for the tag after the ciphertext. Extend core strengthened with `slice@ == message@` and `final(ct) == old(ct) + final(slice)` (lib.rs:192-198). Same order of operations as shipped (extend first, then key, nonce, seal, tag). | Covered for key/nonce Err and Ok. **Partly** for seal Err: exact tail contents (is it still the plaintext?) is not proved, because A18 (aws_lc_specs.rs, seal) says nothing about the bytes. The docs state this openly (verus-proofs-report.md "What is NOT proven (VR-014)"). The tag-after-ciphertext fact is an assert inside the body, not an `ensures` of `aes_encrypt_core`; the `ensures` only gives prefix and total length, so callers of the core cannot use "last 16 bytes are the tag". |
| 6b | BUG-07(b) `aes_decrypt` guard weaker than callee | `aes_decrypt_core` (lib.rs:470-501): `r is Ok ==> |plain| == |ct|`; `|plain| > |ct| ==> r is Err && !PlainTooShort`; `plain` length kept. Calls the VR-006 guard `aes_decrypt_len_ok` first (lib.rs:~487). The first two clauses rely on A20 = labeled assumption A-OPEN (aws_lc_specs.rs:387-405: `open_separate_gather` returns `Ok` only if `|in_ciphertext| == |out_plaintext|`, citing aws-lc-rs 1.18.1 `aead.rs:~806` and `unbound_key.rs:136-139`). Doc comment lib.rs:~450-466 says "hold only under the LABELED ASSUMPTION A-OPEN" and "assumed, not proved". Docs F2 says "recorded under A-OPEN". | Covered, and correctly labeled as assumption-relative. Two weaknesses: (i) `!PlainTooShort` is a direct consequence of the VR-006 `iff` (`aes_decrypt_len_ok` ensures `Ok <==> plain >= ct`), so only `Err` for the over-long buffer is new and it comes entirely from A20. (ii) The ensures says "Err and not PlainTooShort", which also allows `InvalidKey`/`InvalidNonce`; the prose "rejected by the callee" is true only if key and nonce are valid. The adapter maps `Open` to "authentication tag did not match" (lib.rs:~575), which is the misleading message BUG-07 complains about; the adapter message mapping is unverified. |

Other C03 properties from the pipeline target and where they land:

| C03 property | Status |
|---|---|
| No panic in hmac/digest/finish/aes/kbkdf | Covered, conditional on A1-A20 having no `requires` (every aws-lc-rs call trusted not to panic). Documented in verus-proofs-report.md "VR-013 / VR-014 TCB". |
| `aes_decrypt Ok => |pt| == |ct|` | Covered under A-OPEN only; the pipeline stated it unconditionally. |
| `aes_encrypt Ok => |ct| = old + |msg| + 16` | Covered, rests on trusted A19 (AES-GCM tag is 16 bytes). |
| `hkdf_no_salt` `&salt[..sz]` in range; `hkdf` key length in {16,24,32} | Extra/not new: VR-009 prim half (hkdf.rs:83, :103, :127), unchanged. `hkdf`/`hkdf_expand` "Ok => |okm| in {16,24,32}" is not proved end to end; only the decision fn `hkdf_key_len_ok` is, and `get_len` (hkdf.rs adapter) is outside `verus!`. |
| Extra beyond scope | `ExAsRef` trait proxy and `#![cfg_attr(verus_keep_ghost, feature(sized_hierarchy))]` (lib.rs:~10, Cargo.toml `unexpected_cfgs`), needed to name `Aad<A: AsRef<[u8]>>`. This changes build attributes for the crate (nightly-only cfg, Verus builds only). Disclosed in docs. Also new integration tests `prim/tests/test_wrapper_contracts.rs` (7 tests: digest, hmac, finish, aes_encrypt Err/Ok, aes_decrypt buffer cases, kbkdf empty okm) pinning behavior. |

### Behavior-preservation notes (constraint: no runtime change)
- `hmac`: before, `want_len = get_digest_alg(alg).output_len()`; now `hmac_alg.tag_len()` (lib.rs:283-290, adapter lib.rs:599-615). Equal in aws-lc-rs 1.18.1: I checked `~/.cargo/registry/src/*/aws-lc-rs-1.18.1/src/hmac.rs:137-139`, `tag_len()` returns `self.digest_algorithm().output_len`. So accepted lengths and messages are unchanged for this version, but it is a source-of-truth change and a different aws-lc-rs could diverge. Disclosed by the author in the docs.
- `aes_decrypt`: key/nonce/open errors were `serr(..)` via `?`, now `err(..)` (lib.rs:560-590). `err` = `Err(serr(..))` (lib.rs:121-127), same kind and same text; `Error` stores no `Location` (grep of error.rs for location/track_caller/backtrace: no match). No observable change.
- `aes_encrypt`: same order (`get_aes_alg`, extend, key, nonce, seal, tag), same messages (lib.rs:522-545).
- `digest`, `finish`, `kbkdf_ctr_hmac`, `generate_random_bytes`, `constant_time_equal`: guard, error text and order unchanged by inspection of the diff.
- Constraint "no assume/admit/external_body on exec fns": `grep -nE 'assume\(|admit\(|external_body'` in prim/src shows only `external_body` on type specs (`Ex*` structs in aws_lc_specs.rs and `ExSignature` in ecdsa.rs:161, base) and `assume_specification` (ecdsa.rs:170, :179, base; plus aws_lc_specs.rs). No `assume(`/`admit(` calls. `assume_specification` for aws-lc-rs calls is the explicit trusted boundary the task asked for.
- Doc nit: the docs refer to "branch `verus-prim-c03`"; the actual branch is `Mahnush_Verus`.

## 3. No duplication

- `aes_encrypt_extend_core` (lib.rs:192): body unchanged (`diff` shows only two added `ensures` conjuncts, `slice@ == message@` and `final(cipher_text) == old + final(slice)`). Extended, not re-proved. The original `slice@.len() == message@.len()` clause is kept. VR-014 reuses it by calling it from `aes_encrypt_core`.
- `aes_decrypt_len_ok` (lib.rs:227): byte-identical to base; `aes_decrypt_core` calls it (lib.rs:~487), does not restate it. The `!PlainTooShort` clause of `aes_decrypt_core` re-derives a consequence of VR-006's `iff` (see 6b), which is a mild overlap but is the requested BUG-07(b) observation, not a re-proof.
- `sign_fixed_len_core` (ecdsa.rs:270): I diffed base lines 195-320 against head lines 224-349 of ecdsa.rs: identical (`SIGN_CORE_SAME`). Only `DigestContext::finish` (ecdsa.rs:~84-92) and the new `digest_finish_core` (ecdsa.rs:185-212) changed. `ExSignature`, `Signature::as_ref`, `copy_from_slice` specs (ecdsa.rs:160-182) are reused by `digest_core`/`hmac_core`, not redeclared (aws_lc_specs.rs header says so).
- `hkdf.rs`: no diff at all (`git diff --stat -- prim/src/hkdf.rs` is empty; `-U0` diff has 0 lines). `hkdf_key_len_ok` (:83), `salt_size_core` (:103), `no_salt_slice_core` (:127) untouched; VR-013/014 do not touch HKDF.
- Verdict: no VR-006, VR-008 or VR-009 code or proof is changed or re-proved. VR-006's extend core is extended. One mild overlap noted above.

## 8. Cross-branch: C02 standalone model vs in-crate VR-008

C02 file: `verus-proofs/c02_sign_fixed_len.rs` on local MPL-Verus (not on origin/MPL-Verus). VR-008 = `sign_fixed_len_core`, ecdsa.rs:270-306.

Same properties on the real loop (confirmed from code):
- Retry bound <= 128: ecdsa.rs:~225 `const MAX_SIGN_ATTEMPTS: u32 = 128` inside `verus!`; loop `while attempt < MAX_SIGN_ATTEMPTS` with `invariant attempt <= MAX_SIGN_ATTEMPTS` and `decreases MAX_SIGN_ATTEMPTS - attempt` (ecdsa.rs:~283-290). This is a structural bound: the loop cannot call `sign_once` more than 128 times. Verus checks it as termination.
- Termination: yes, explicit `decreases` (C02 had both a `for` over `Range` and a `while` cross-check).
- Guarded `copy_from_slice`: `if candidate_bytes.len() == want_len { signature.copy_from_slice(..) }` (ecdsa.rs:~297-301) with invariant `want_len == signature@.len()`; vstd `copy_from_slice` requires equal lengths. C02 had the same guard.
- VR-008 is on the REAL code (the shipped `sign_fixed_len_core` is the verified fn that the adapter calls); C02 was a retyped model with a human-checked correspondence table.

What C02 proved that VR-008 does not (VR-008 has no `ensures` at all, only a `requires` that the closure is callable):

| C02 theorem | In VR-008? |
|---|---|
| T1 `n <= 128` as a stated postcondition (ghost call log) | Not stated. Holds structurally from the loop bound, not as a checkable ensures, so no caller can use it. |
| T3 no partial write: `Ok` => buffer equals exactly the first candidate with the right length; `Err` => buffer unchanged; buffer length unchanged | **No.** `sign_fixed_len_core` has no `ensures`, so "buffer untouched on Err" and "buffer == one whole candidate on Ok" are not proved. The only write is one `copy_from_slice` that is then followed by `return Ok(())`, so it is true by reading, but Verus is not asked to check it. |
| T4 which Err exits exist (sign_once Err after n-1 mismatches, or exhaustion after exactly 128 mismatches) | No (the `SignCoreError` enum has the two variants, no ensures linking them to the loop state). |
| T5 `check_sig_len`: `Ok <==> len == signature_len(alg)` | No. `check_sig_len` (ecdsa.rs:359) is outside `verus!`. |
| T6 `ecdsa_sign` / `ecdsa_sign_digest`: wrong buffer length => Err, zero signing calls, buffer untouched; `Ok` => buffer length == `signature_len(alg)` | No. `ecdsa_sign`, `ecdsa_sign_digest` are unverified. |
| Non-vacuity witnesses (Ok first attempt, exhaustion after 128, wrong buffer) | No. |
| `signature_len` table (P256 71, P384 103) | No. |

VR-013 does not add any of these. Recommendation (not requested here): if C02's T3 matters, add an `ensures` to `sign_fixed_len_core` (`Err ==> final(signature) == old(signature)`, `Ok ==> final(signature).len == old.len`), which is a small extension of VR-008 and is in the owner's area.

## 8b. What remains of C03 and BUG-07 not covered by VR-013/VR-014

C03 (prim):
1. HKDF end to end: `hkdf` / `hkdf_expand` "Ok => |okm| in {16,24,32}" (hkdf.rs adapter calls `Salt::new`, `extract`, `expand`, `fill`, all trusted/unmodeled). Only the decision fn (VR-009) is proved.
2. `DigestContext::digest(self)` (ecdsa.rs:~96, used by `ecdsa_sign_digest`/`ecdsa_verify_context`) calls `context.finish()`, which documents a panic (`expect("EVP_DigestFinal failed")`, digest.rs:131-137). VR-013 trusts it unreachable only inside `digest_finish_core` (A5); this other call site is not modeled. Authors flag F4 for `finish` only.
3. ECDSA: `check_sig_len` (:359), `ecdsa_sign` (:~377), `ecdsa_sign_digest`, `ecdsa_verify`, `ecdsa_verify_context`, `ecdsa_generate_keypair` (four `Err` paths), and the `sign_fixed_len` adapter (ecdsa.rs:~330-352, including `sign_failure.unwrap_or_else`, no panic by reading). These belong to C02, not C03, and are unmodeled in-crate.
4. `DigestContext::new`, `new_from_ecdsa`, `update`, `output_len`: thin aws-lc-rs calls, no slicing, no arithmetic; not modeled, no panic site found.
5. Adapter code outside `verus!`: `format!` calls (hmac lib.rs:~609, digest lib.rs:~634, finish ecdsa.rs:~88, kbkdf lib.rs:~681, aes_decrypt lib.rs:~575), `get_aes_alg`, `get_digest_alg`, the `DigestAlg -> KbkdfId` match: total matches, no panic by reading, not machine-checked.
6. Hand-maintained tables vs aws-lc-rs: `DigestAlg::output_len` (lib.rs:~95-102) and `AesGcm::key_length` are constants; hmac/digest no longer use `DigestAlg::output_len`, but any caller that does is not tied to the aws-lc-rs value.
7. Every aws-lc-rs call is trusted not to panic (A1-A20 have no `requires`). OOM out of scope per task.
8. A-OPEN, A19 (16-byte tag), A2/A5/A8 (output lengths) are trusted, not proved.

Panic-site scan of `prim/src` non-test code (grep for `.expect(`, `.unwrap(`, `panic!`, `unreachable!`, `assert!`, `[..]` slicing, `copy_from_slice`, `split_at`, `as` casts, `+ - *`):
- `copy_from_slice`: ecdsa.rs:210 (digest_finish_core, modeled), ecdsa.rs:300 (VR-008, modeled), lib.rs:272 (digest_core, modeled), lib.rs:301 (hmac_core, modeled).
- slicing/split: hkdf.rs:142 `&salt[0..sz]` (VR-009, modeled), lib.rs:206 `split_at_mut(old_size)` (VR-006, modeled).
- `unwrap_or_else` at ecdsa.rs:348: not a panic site.
- No `.expect(`, `.unwrap(`, `panic!`, `unreachable!`, `assert!`, index `[i]` or `as` casts in non-test prim code. Arithmetic: only inside verus! (lib.rs:413 `+ 16`, ghost); Verus checks overflow there.
- `ecdsa_generate_keypair` returns `Err` instead of panicking; the panic for it is in the CALLER (`mpl/src/cmm/default_cmm.rs:137-138` `.expect`, per RECHECK BUG-05(a)); not a prim panic.
So every panic-capable operation in prim is modeled, except the unmodeled `finish` call inside `DigestContext::digest` (item 2 above) and the trusted aws-lc-rs calls.

BUG-07 (caller-side impact, grep of `aes_encrypt(`/`aes_decrypt(`/`seal(`/`open(` in mpl/ and esdk/ at the tip; VR-014 itself lists this as FOLLOW-UP and did not review it):
- `aes_encrypt` callers: `mpl/src/keyring/raw_aes_keyring.rs:163` (fresh `Vec::new()`, `?` on Err drops the Vec holding the plaintext data key; Vec is not zeroized), `mpl/src/aws_kms/branch_key_wrap.rs:199` (`output` already holds salt||iv||version, plaintext data key appended; dropped on `?`), `esdk/src/secret.rs:398` -> `esdk/src/message/body/body_encrypt.rs:306` (`frame_buf` holds plaintext after Err; `construct_frame` only does `frame_buf.clear()` at its start, :177, which does not zero; buffer is reused by the caller), `esdk/src/encrypt.rs:772` (message is `&[]`, nothing appended, not affected).
- So BUG-07(a) is a plaintext-residue-in-freed/reused-heap issue (no confidentiality failure across API boundary in these callers), not data corruption. VR-014 proves the residue exists; it does not prove anything about zeroization or caller drops. Impact analysis in the callers: NOT covered.
- `aes_decrypt` callers all size the plaintext buffer exactly to the ciphertext (`raw_aes_keyring.rs:468` `vec![0u8; encrypted_key.len()]`, `branch_key_wrap.rs:274` same, `body_decrypt.rs:~395` `&mut []` with empty ciphertext, `result.resize(enc_content.len(), 0)` before `open` at :407, nonframed `enc_content.clone()` before `open` at :763). I did not verify the header-auth call `esdk/src/decrypt.rs:551` plaintext buffer (it passes `&[]` ciphertext). So BUG-07(b) looks unreachable from in-repo callers; reachable only for external users of `prim::aes_decrypt`. The "authentication tag did not match" message mapping for every callee error (BUG-07(b) second half) is untouched and unproved (adapter message code).
- Not fixed, by design (BUG-07 stays a finding).

## Overall
- Scope items 1-5 and 6(a) key/nonce/Ok: covered. 6(a) seal-Err tail contents: partly. 6(b): covered and honestly labeled as assumption-relative.
- No duplication of VR-006/VR-008/VR-009 code or proofs.
- C02 -> VR-008: same loop bound, termination and guarded copy on the real code; C02's no-partial-write (T3), Err-exit characterization (T4), `check_sig_len` (T5), and `ecdsa_sign*` buffer contract (T6) are not in VR-008.
- Open observations: `hmac` guard now keyed on `tag_len()` (equal in 1.18.1); the tag-after-ciphertext fact is only an in-body assert; `ct_equal_core` ensures is nearly vacuous; build-attribute change (`sized_hierarchy`, `unexpected_cfgs`); docs name a branch that does not exist (`verus-prim-c03`).
