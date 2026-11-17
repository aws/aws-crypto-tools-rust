#!/usr/bin/env python3
"""Edits the three targets documents (merged, 01, 02) for the C03 status record.
All replacements are exact-string, must match exactly once, and are written only if every one of a file's edits applies.
01 is edited in place above its T26 YAML (lines 747-750 are cited by BUG-10 and must not move); new lines go below.
"""
import os, sys
ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))
P = {"merged": "docs/verification-targets.md",
     "01": "docs/verification-targets/01-threat-driven.md",
     "02": "docs/verification-targets/02-capability-driven.md"}

QM = "model level, not the shipped code, under stated hypotheses"
QC = "in-crate, on the shipped prim code, on branch Mahnush_Verus, not on this branch, under trusted aws-lc-rs assumptions A1-A20"
PS_C03 = f"Partly proved ({QC}): 18 verified, 0 errors"
PS_C02 = f"Proved ({QM}): 21 verified, 0 errors"
C02_CELL_NOTE = "Partly superseded by VR-008 (in-crate, on the shipped prim code, on branch Mahnush_Verus, not on this branch): retry bound, termination, guarded copy"
C02_NOTE_YAML = ("Partly superseded by VR-008 (in-crate, on the shipped prim code, on branch Mahnush_Verus, not on this branch): "
                 "the retry bound (at most 128 attempts), termination and the guarded copy_from_slice are also proved on the real loop (sign_fixed_len_core). "
                 "This target stays the only statement of T1 as a postcondition (at most 128 closure calls), T3 (no partial write: Err leaves the buffer unchanged, Ok writes one whole candidate), "
                 "T4 (which Err exits exist), T5 (check_sig_len), T6 (ecdsa_sign* wrong-length contract) and the three non-vacuity witnesses. The status above is unchanged. It is not a duplicate and is not demoted.")

TIP = "8d6381eb82daee55ecf32911d6ef8b48690d68b9"

C03_YAML = f'''  proof_status: "{PS_C03}"
  proof_location: "Branch Mahnush_Verus of aws/aws-crypto-tools-rust (PR #103), VR-013 (hmac_core, digest_core, digest_finish_core, kbkdf_core, fill_random_core, ct_equal_core) and VR-014 (BUG-07 buffer facts in aes_encrypt_core, aes_decrypt_core). NOT on MPL-Verus: prim/ here equals main 620771c and has no Verus annotation. Commits ed4a81e (feat) and 43b9ff7 (docs); tip read 8d6381e (the later commits change docs only)."
  proof_result: "verification results:: 18 verified, 0 errors (aws-mpl-primitives), from `cargo verus verify` (default features) and `cargo verus verify --no-default-features --features aws-lc-sys` in prim/, re-run at 8d6381e; same count at 43b9ff7 in our earlier review. 18 counts every verified function in the prim crate on that branch (VR-006, VR-008, VR-009 prim half, VR-013, VR-014); the base 6b51de8 gave 10."
  proof_trusted_base: "20 assume_specification (A1-A20) about aws-lc-rs in prim/src/aws_lc_specs.rs, each assumed not to panic; no assume, admit, external fn or unsafe. All judged TRUE for aws-lc-rs 1.18.1 by our review; the FIPS C side is unchecked."
  proof_not_covered: >
    hkdf and hkdf_expand "Ok implies len(okm) in {{16, 24, 32}}" and "no listed function panics" end to end (VR-009 proves only the decision functions);
    DigestContext::digest's call to finish; adapters outside verus! (format! messages, get_aes_alg, the DigestAlg to KbkdfCtrHmacAlgorithmId match);
    constant_time_equal and generate_random_bytes add little beyond assumptions A13 and A12; BUG-07(a): key/nonce Err buffer = old ++ message and seal-Err length and prefix
    are exported ensures, but the Ok-case order "old ++ ciphertext ++ tag" is an in-body assert and +16 relies on A19, and seal-Err tail bytes are not described;
    BUG-07(b) is assumption-relative (A20, A-OPEN), not proved; nothing about zeroization.
  related_bugs:
    - {{bug: "BUG-07(a)", evidence: "prim-side buffer facts proved in-crate on Mahnush_Verus (VR-014); caller impact is code reading", threat: TM-MPL-015, target: "T26 (F2), T07 (e)"}}
    - {{bug: "BUG-07(b)", evidence: "recorded, relative to assumption A20, not proved", threat: TM-MPL-023, target: C03}}
    - {{bug: BUG-10, evidence: "code reading", threat: TM-MPL-015, target: T26, note: "not part of C03: the buffers are in mpl, not prim"}}
'''

T26_RELATED = '''  related_bugs:
    - {bug: BUG-10, severity: Low, evidence: "code reading, no proof (mpl is not Verus-enabled)", threat: TM-MPL-015, target: T26, note: "RawAesKeyring::on_decrypt drops an authenticated plaintext data key un-wiped on the wrong-length path (site F1); branch_key_wrap::unwrap holds a plain Vec<u8> (site F3)"}
    - {bug: "BUG-07(a)", evidence: "prim-side facts proved in-crate on Mahnush_Verus (C03, VR-014); caller impact is code reading", threat: TM-MPL-015, target: "T26 (F2)", note: "callers wrap_data_key and branch_key_wrap::wrap drop the plaintext data key un-wiped on an aes_encrypt Err; cannot fire today"}
  scope_note: >
    Scope note only; no property, score, coverage gap, feasibility or severity changed. BUG-10 is the bug report for site F1's wrong-length continue
    (raw_aes_keyring.rs:489-494: an authenticated plaintext data key is dropped un-wiped, while the success path at :497 moves the buffer into PlaintextDataKey)
    and for F3's branch_key_wrap::unwrap buffer (:275, a bare Vec<u8> is returned). The BUG-07(a) caller impact names one caller that the function list above does not:
    branch_key_wrap::wrap (branch_key_wrap.rs:157, aes_encrypt call :199); wrap_data_key (raw_aes_keyring.rs:163) is already in F2. The failure cannot fire today:
    key and IV sizes are fixed by type in wrap, and the raw-AES wrapping-key length is checked at RawAesKeyringBuilder::build (raw_aes_keyring.rs:369-379).
'''

# ---------------------------------------------------------------- merged
C03_SECTION_BODY = f'''### C03: in-crate proof on branch Mahnush_Verus (not on this branch)

C03 (`prim::{{hmac, digest, aes_encrypt, aes_decrypt, hkdf*, kbkdf_ctr_hmac}}`, `DigestContext::finish`) has a different kind of proof from the five above. Verus checks the real prim code, not a re-typed model. The proof lives on branch `Mahnush_Verus` of aws/aws-crypto-tools-rust (PR #103) as VR-013 and VR-014. It is **not on this branch**: `prim/` here equals `main` `620771c` and has no Verus annotation. Nothing from `Mahnush_Verus` was merged, checked out or modified; it was read with `git fetch` and `git show` and re-run in a detached worktree under `/tmp` that was removed afterwards. Read no status in this subsection as saying that the code on `MPL-Verus` is verified.

| Field | Value |
|---|---|
| Status | {PS_C03} |
| Commits | `ed4a81e` (feat(prim): Verus proofs for the C03 wrappers) and `43b9ff7` (docs). Tip read for this record: `{TIP[:7]}`. The later commits `2d22937` and `8d6381e` change docs only, and no commit after `43b9ff7` touches `prim/` |
| Result line | `verification results:: 18 verified, 0 errors` (crate aws-mpl-primitives) |
| Re-run | At `{TIP[:7]}`, from `prim/`, with `PATH="$HOME/verus:$PATH"`: `cargo verus verify` (default features) and `cargo verus verify --no-default-features --features aws-lc-sys`. Both exit 0 and both print the line above. Our earlier review gave the same count at `43b9ff7`. The default-feature run also prints `1858 verified, 0 errors` for the vstd dependency; that line is not a C03 result |
| What 18 counts | Every verified function of the prim crate on that branch (VR-006, VR-008, VR-009 prim half, VR-013, VR-014), not only C03. The base `6b51de8` gave 10, so VR-013 and VR-014 added 8. Verus counts verification obligations (functions), not properties |
| Review | Our read-only review at `43b9ff7` (`.agents/tasks/review-vr013-vr014/report.md`): verdict "Consistent with gaps". On the tip it found prim tests (92 tests and 8 doc-tests) and clippy passing, and byte-identical behavior against the base on 1443 transcript lines (differential run on aws-lc-rs 1.19.0, not the locked 1.18.1). Those runs were not repeated at `{TIP[:7]}`; nothing under `prim/` changed |
| Not run | FIPS build, test and Verus runs (cmake is missing; the base fails the same way) and the literal `make verus` (the equivalent `cargo verus` runs were done) |

What the proof states (all in `verus!` in the shipped crate; names are the verified cores that the public functions call):

| Shipped function | Core on `Mahnush_Verus` | Proved (Verus, in-crate) |
|---|---|---|
| `hmac` | `hmac_core` (VR-013) | `Ok` iff the output buffer has the tag length; on `Err` the buffer is unchanged; the copy happens only after the guard and in bounds |
| `digest` | `digest_core` (VR-013) | Same, against the digest output length |
| `DigestContext::finish` | `digest_finish_core` (VR-013) | Same, against the context's output length |
| `kbkdf_ctr_hmac` | `kbkdf_core` (VR-013) | `Err(Unavailable)` iff the algorithm lookup returns `None`; output length kept. Wrapper logic only |
| `generate_random_bytes` | `fill_random_core` (VR-013) | Totality; length kept. Adds little beyond A12 |
| `constant_time_equal` | `ct_equal_core` (VR-013) | Totality; the result is the `Ok`-ness of the aws-lc-rs comparison. Restates A13; no equality-semantics or timing claim |
| `aes_encrypt` | `aes_encrypt_core` (VR-014) | BUG-07(a), exported postconditions: key or nonce `Err` leaves exactly `old ++ message`; seal `Err` keeps the length `old + len(message)` and the prefix `old`; `Ok` gives length `old + len(message) + 16` with prefix `old` |
| `aes_decrypt` | `aes_decrypt_core` (VR-014) | BUG-07(b), under assumption A20: `Ok` implies `len(plain) == len(cipher)`; a longer plaintext buffer ends in `Err` that is not `PlainTooShort` |

Trusted base. 20 `assume_specification` entries (A1 to A20) in `prim/src/aws_lc_specs.rs` about aws-lc-rs digest, HMAC, KBKDF, random, constant-time and AEAD calls; 15 opaque `external_body` types; 8 uninterpreted spec functions; one ghost-only `AsRef` trait proxy (it needs `#![cfg_attr(verus_keep_ghost, feature(sized_hierarchy))]` and a `[lints.rust] unexpected_cfgs` entry). There is no `assume`, `admit`, `#[verifier::external]` function or `unsafe`, and no `requires` was added. No `assume_specification` carries a `requires`, so every aws-lc-rs call is assumed not to panic. Our review judged A1 to A20 TRUE against the aws-lc-rs 1.18.1 source (aws-lc-sys 0.45.0); the no-panic part of A5, A7 and A8 holds only if the underlying C calls succeed; the FIPS C side (aws-lc-fips-sys) was not read. A20 is the labeled assumption for BUG-07(b).

Gaps (what the status "partly" means):

- `hkdf` and `hkdf_expand` "`Ok` implies `len(okm)` in 16, 24 or 32" and "no listed function panics for any argument" are not proved end to end. VR-009 proves only the decision functions (`hkdf_key_len_ok`, `salt_size_core`, `no_salt_slice_core`); `Salt::new`, `extract`, `expand`, `fill` and `get_len` are unmodeled.
- `DigestContext::digest` (used by `ecdsa_sign_digest` and `ecdsa_verify_context`) calls `finish`, which can `expect`. That call is unmodeled; A5's no-panic is trusted only inside `digest_finish_core`.
- Adapters outside `verus!` are unproved: the `format!` error messages, `get_aes_alg`, `get_digest_alg`, the `DigestAlg` to `KbkdfCtrHmacAlgorithmId` match, and the "authentication tag did not match" text of `aes_decrypt`.
- `constant_time_equal` and `generate_random_bytes`: the proofs add little beyond the assumptions A13 and A12.
- BUG-07(a): the key/nonce `Err` buffer (`old ++ message`) and the seal-`Err` length and prefix are exported postconditions. The `Ok`-case order `old ++ ciphertext ++ tag` is an in-body `assert`, not exported, and the `+ 16` relies on A19. The tail bytes after a seal `Err` are not described (A18 says nothing about bytes).
- BUG-07(b) is assumption-relative (A20 matches aws-lc-rs 1.18.1 `open_separate_gather`'s equality check), not proved.
- Not covered: zeroization (the proof says nothing about wiping), `DigestContext::new`, `new_from_ecdsa`, `update`, `output_len`, the ECDSA wrappers (`check_sig_len`, `ecdsa_sign*`, `ecdsa_verify*`, `ecdsa_generate_keypair`, which belong to C02) and the hand-maintained tables `DigestAlg::output_len` and `AesGcm::key_length`.

Wording note. The documents on `Mahnush_Verus` call C03 "in-crate" without "partly" and, in places, call the `Ok`-case order proved. Our review recommended wording fixes there. This record uses "partly" and "in-body assert".

### Cross-branch status (MPL-Verus and Mahnush_Verus)

The two branches have diverged (merge base `5f2dc72`; 20 commits only on `MPL-Verus`, 47 only on `Mahnush_Verus` at `{TIP[:7]}`). Nothing was merged. `mpl/` source files are identical on both (only the `Cargo.lock` files differ); `prim/` and `esdk/` differ.

| Item | On `MPL-Verus` (this branch) | On `Mahnush_Verus` (`{TIP[:7]}`) |
|---|---|---|
| T02, C01, T03, T05 | Proofs of models in `verus-proofs/` (model level, not the shipped code) | No `verus-proofs/` directory |
| C02 | Proof of a model (21 verified, 0 errors) | VR-008: the retry bound, termination and guarded copy are proved on the real loop (`sign_fixed_len_core`). C02 is partly superseded |
| C03 | No Verus in `prim/`; no proof | Partly proved in-crate as VR-013 and VR-014 |
| VR-006 (AES-GCM buffer bounds), VR-009 prim half (`hkdf` decision functions) | Not present | In-crate in `prim/` |
| Other `esdk` in-crate proofs | Not present | In-crate (69 verified in `esdk/` at `43b9ff7`); not examined for this record |

C02 and VR-008. The retry bound (at most 128 attempts), termination and the guarded `copy_from_slice` of `sign_fixed_len` are also proved on the real loop on `Mahnush_Verus` as VR-008. So that content of C02 is superseded. C02 is not a duplicate and is not demoted. It remains the only statement of T1 as a postcondition (at most 128 closure calls), T3 (no partial write: `Err` leaves the buffer unchanged, `Ok` writes one whole candidate), T4 (which `Err` exits exist), T5 (`check_sig_len`), T6 (the `ecdsa_sign*` wrong-length contract) and the three non-vacuity witnesses. VR-008 has no `ensures`, and `check_sig_len` and `ecdsa_sign*` are outside `verus!` there. Recorded status of C02: Proved at model level (unchanged); partly superseded by VR-008 (in-crate, `Mahnush_Verus`).

### Findings from the proofs
'''

M_FIND_ADD = '''- **BUG-07(a), prim side (C03, VR-014; not on this branch).** On `Mahnush_Verus` Verus proves that `aes_encrypt` appends the plaintext to the caller's buffer before the key, nonce or seal can fail: a key or nonce `Err` leaves exactly `old ++ message`, and a seal `Err` keeps the length `old + len(message)` and the prefix `old`. The `Ok`-case order `old ++ ciphertext ++ tag` is an in-body assert and the `+ 16` relies on A19. BUG-07(b) is recorded relative to A20, not proved.
- **BUG-07 caller impact (code reading, no proof; see the BUG-07 report, "Impact on callers").** mpl calls `aes_encrypt` at `RawAesKeyring::wrap_data_key` (`raw_aes_keyring.rs:163`) and `branch_key_wrap::wrap` (`branch_key_wrap.rs:199`) with a plaintext data key in a plain `Vec<u8>`. After a key or nonce `Err` the key stays in that buffer, which the caller drops un-wiped. It cannot reach an EDK, a return value or an error message. The failure cannot fire today: key and IV sizes are fixed by type in `wrap`, and the raw-AES wrapping-key length is checked at `RawAesKeyringBuilder::build` (`raw_aes_keyring.rs:369-379`). Severity Low (confidentiality). In the ESDK frame scratch buffer the plaintext is user data (Informational/Low). BUG-07(b) is unreachable from in-repo callers, which size the plaintext buffer exactly. VR-014 says what prim leaves in the buffer; what the callers do with it is outside C03 and belongs to T26 (F2).
- **BUG-10 (new, Low, code reading).** `RawAesKeyring::on_decrypt` (`raw_aes_keyring.rs:471`, wrong-length `continue` at `:489-494`) drops an authenticated plaintext data key un-wiped, and `branch_key_wrap::unwrap` (`:275`) holds a plain `Vec<u8>` and returns it bare. It maps to TM-MPL-015 and T26 (sites F1 and F3, already listed as known residuals; no score changed). It is not part of BUG-07, it is not proved, and C03 does not cover it: the proof is of prim, and these buffers are in mpl.
- **C02 versus VR-008.** See "Cross-branch status": C02 is partly superseded, not a duplicate.
'''

M_NEXT_ADD = '''- C03: decide how the in-crate prim proofs reach this branch (merge or port `prim/` and add Verus to the build). Not done, and an owner decision. Until then every C03 statement in these documents is about `Mahnush_Verus`, not about the code here.
- C03 on `Mahnush_Verus`: the wording and test fixes recommended by our review (`.agents/tasks/review-vr013-vr014/report.md`, "Recommended fixes") are for the owner of that branch.
'''

def merged_edits():
    E = []
    # header: in place on the 'Full per-target YAML' line
    E.append(("> Full per-target YAML lives in the two intermediate files. This document is the consolidated, ranked view. Validation: `docs/verification-targets/04-validation.md`.",
              "> Full per-target YAML lives in the two intermediate files. This document is the consolidated, ranked view. Validation: `docs/verification-targets/04-validation.md`. Proof-status record updated at HEAD `b94c871` (adds C03, which is partly proved in-crate on branch `Mahnush_Verus` and not on this branch, the C02 / VR-008 relation and BUG-10): no score, rank, coverage gap, feasibility, severity or quick-win changed."))
    # proofs written intro
    E.append(("Sources: `verus-proofs/README.md` (T02, C01, C02) and `verus-proofs/README-t03-t05.md` (T03, T05).\n",
              "Sources: `verus-proofs/README.md` (T02, C01, C02) and `verus-proofs/README-t03-t05.md` (T03, T05). This section also records C03, which has a different kind of status: in-crate, on the shipped prim code, on branch `Mahnush_Verus`, not on this branch (subsection \"C03: in-crate proof on branch Mahnush_Verus\" below). The wording of this paragraph applies to the five proofs in the table.\n"))
    # canonical strings
    E.append(("- T05: Proved (model level, not the shipped code, under stated hypotheses): 33 verified, 0 errors\n\n**Scores are unchanged.**",
              f"- T05: Proved (model level, not the shipped code, under stated hypotheses): 33 verified, 0 errors\n- C03: {PS_C03}\n- C02, relation added (the C02 status string above is unchanged): {C02_CELL_NOTE}\n\n**Scores are unchanged.**"))
    E.append(("and re-scoring would be arbitrary. Coverage gaps will be recalculated when a proof is linked to the shipped code (for example with `cargo verus` on the crate, or by moving the logic into `verus!`).\n\n### Findings from the proofs\n",
              "and re-scoring would be arbitrary. Coverage gaps will be recalculated when a proof is linked to the shipped code (for example with `cargo verus` on the crate, or by moving the logic into `verus!`). The same holds for C03: its proof is on `Mahnush_Verus`, not on this branch, so C03 stays at 5.60, rank 5, coverage gap 0.7, and is still not a quick win.\n\n" + C03_SECTION_BODY))
    # findings add: after the C02 assumption bullet
    E.append(("- **C02 assumption.** The no-partial-write claim relies on vstd's own `assume_specification` for `<[T]>::copy_from_slice`, listed in the proof's TCB.\n",
              "- **C02 assumption.** The no-partial-write claim relies on vstd's own `assume_specification` for `<[T]>::copy_from_slice`, listed in the proof's TCB.\n" + M_FIND_ADD))
    E.append(("- Add a CI step that runs the proof files and fails on any change to the result lines (T02 is expected to show `1 errors` until G1 is fixed).\n",
              "- Add a CI step that runs the proof files and fails on any change to the result lines (T02 is expected to show `1 errors` until G1 is fixed).\n" + M_NEXT_ADD))
    # methodology bugs
    E.append(("- **Bugs**: open BUG-01, 04, 05(a), 05(b), 06, 07(a/b), 08; fixed BUG-02, 03, 09.",
              "- **Bugs**: open BUG-01, 04, 05(a), 05(b), 06, 07(a/b), 08, 10 (BUG-10 added after the audit, by code reading); fixed BUG-02, 03, 09."))
    # ranked table cells
    E.append(("| verus-zero-panic | cap:cat2 (2d) | 1 week | " + PS_C02 + " |",
              "| verus-zero-panic | cap:cat2 (2d) | 1 week | " + PS_C02 + ". " + C02_CELL_NOTE + " |"))
    E.append(("| verus-zero-panic | cap:cat2 (2a/2d) | 1 week | None yet |",
              "| verus-zero-panic | cap:cat2 (2a/2d) | 1 week | " + PS_C03 + " |"))
    # YAML C02
    E.append(("  proof_file: verus-proofs/c02_sign_fixed_len.rs\n",
              "  proof_file: verus-proofs/c02_sign_fixed_len.rs\n  proof_note: \"" + C02_NOTE_YAML + "\"\n"))
    # YAML C03
    E.append(('  scoring: {severity: 2, coverage_gap: 0.7, feasibility: 1.0, blast_radius: 4, product: "2 × 0.7 × 1.0 × 4 = 5.60"}\n  quick_win: false\n  proof_status: "None yet"\n',
              '  scoring: {severity: 2, coverage_gap: 0.7, feasibility: 1.0, blast_radius: 4, product: "2 × 0.7 × 1.0 × 4 = 5.60"}\n  quick_win: false\n' + C03_YAML))
    # YAML T26 (merged)
    E.append(('  scoring: {severity: 2, coverage_gap: 1.0, feasibility: 0.4, blast_radius: 4, product: "2 × 1.0 × 0.4 × 4 = 3.20"}\n  quick_win: false\n  proof_status: "None yet"\n',
              '  scoring: {severity: 2, coverage_gap: 1.0, feasibility: 0.4, blast_radius: 4, product: "2 × 1.0 × 0.4 × 4 = 3.20"}\n  quick_win: false\n  proof_status: "None yet"\n' + T26_RELATED))
    # section 3
    E.append(("No Verus proof of the shipped code exists for any target. Five targets (T02, C01, C02, T03, T05) have a proof of a model, listed in \"Proofs written\"; the coverage gaps below are the pre-proof values and were not recalculated.",
              "No Verus proof of the shipped code exists on this branch for any target. Five targets (T02, C01, C02, T03, T05) have a proof of a model, listed in \"Proofs written\". C03 is partly proved in-crate on branch `Mahnush_Verus`, which is not this branch (see \"Proofs written\"). The coverage gaps below are the pre-proof values and were not recalculated, including C03's 0.7 and C02's 0.8."))
    # STRIDE
    E.append(("\"Verified\" is 0: it counts threats whose target is proved against the shipped code, and the five proofs in \"Proofs written\" are model level.",
              "\"Verified\" is 0: it counts threats whose target is proved against the shipped code on this branch. The five proofs in \"Proofs written\" are model level, and the in-crate C03 proof is on `Mahnush_Verus` (C03 is a capability target and cites no threat)."))
    # quick wins
    E.append(("Cheap targets below threshold: T03 (5.12, 1 day), T05 (4.32, 1 day), C05 (2.40, 1 day).",
              "Cheap targets below threshold: T03 (5.12, 1 day), T05 (4.32, 1 day), C05 (2.40, 1 day). C03 (5.60) is not a quick win, and its partly proved in-crate status on `Mahnush_Verus` does not change the list."))
    # section 7
    E.append(("and `ecdsa_generate_keypair` leaves the private-key `Vec` un-wiped on its error return (`ecdsa.rs:387`, `:391-392`).\n- T27",
              "and `ecdsa_generate_keypair` leaves the private-key `Vec` un-wiped on its error return (`ecdsa.rs:387`, `:391-392`). BUG-10 (Low, code reading, maps to TM-MPL-015 and T26): `RawAesKeyring::on_decrypt` drops an authenticated plaintext data key un-wiped when its length is wrong (`raw_aes_keyring.rs:489-494`), and `branch_key_wrap::unwrap` holds a plain `Vec<u8>` (`:275`). The BUG-07(a) caller impact (the data key in the caller's buffer after an `aes_encrypt` `Err`) is code reading and cannot fire today.\n- T27"))
    E.append(("- C03 (BUG-07b): `aes_decrypt` guard weaker than its callee; misleading error text.\n",
              "- C03 (BUG-07b): `aes_decrypt` guard weaker than its callee; misleading error text. Recorded, not proved: the VR-014 core states it relative to A20 on `Mahnush_Verus`. The BUG-07(a) prim-side buffer facts are proved there (partly proved, not on this branch); their caller impact is tracked in T26.\n"))
    return E

# ---------------------------------------------------------------- 02
C03_SECTION_02 = f'''### C03: in-crate proof on branch Mahnush_Verus (not on this branch)

C03 has a different kind of proof from C01 and C02. Verus checks the real prim code, not a re-typed model. It lives on branch `Mahnush_Verus` of aws/aws-crypto-tools-rust (PR #103) as VR-013 (`hmac_core`, `digest_core`, `digest_finish_core`, `kbkdf_core`, `fill_random_core`, `ct_equal_core`) and VR-014 (the BUG-07 buffer facts in `aes_encrypt_core` and `aes_decrypt_core`), and is **not on this branch**: `prim/` here equals `main` `620771c` and has no Verus annotation. Nothing was merged, checked out or modified; the branch was read with `git fetch` and `git show`.

- Status: {PS_C03}
- Result line: `verification results:: 18 verified, 0 errors` (crate aws-mpl-primitives). Re-run at `{TIP[:7]}` (the current tip; commits `ed4a81e` and `43b9ff7` hold VR-013 and VR-014, the later two are docs only) with `cargo verus verify` and with `cargo verus verify --no-default-features --features aws-lc-sys`, from `prim/`. Same count at `43b9ff7` in our earlier review (`.agents/tasks/review-vr013-vr014/report.md`, verdict "Consistent with gaps"). The 18 counts every verified function of the crate on that branch (VR-006, VR-008, VR-009 prim half, VR-013, VR-014); the base gave 10.
- Trusted base: 20 `assume_specification` (A1 to A20) about aws-lc-rs in `prim/src/aws_lc_specs.rs`, each assumed not to panic; no `assume`, `admit`, external function or `unsafe`. Our review judged all 20 TRUE for aws-lc-rs 1.18.1; the FIPS C side is unchecked.
- Gaps: `hkdf` and `hkdf_expand` "`Ok` implies `len(okm)` in 16, 24 or 32" and "no listed function panics" are not proved end to end (VR-009 proves only the decision functions); `DigestContext::digest`'s call to `finish` is unmodeled; adapters outside `verus!` (`format!` messages, `get_aes_alg`, the `DigestAlg` to `KbkdfCtrHmacAlgorithmId` match) are unproved; the `constant_time_equal` and `generate_random_bytes` proofs add little beyond A13 and A12; for BUG-07(a) the key/nonce `Err` buffer (`old ++ message`) and the seal-`Err` length and prefix are exported postconditions, but the `Ok`-case order `old ++ ciphertext ++ tag` is an in-body assert and the `+ 16` relies on A19, and the seal-`Err` tail bytes are not described; BUG-07(b) is assumption-relative (A20), not proved; zeroization is not covered.
- BUG-07 and BUG-10: the caller impact of BUG-07(a) (the plaintext data key left in the caller's buffer after an `aes_encrypt` `Err`) and BUG-10 (`RawAesKeyring::on_decrypt` drops an authenticated data key un-wiped) are code reading in mpl, tracked in T26, and are not proved by C03.

C02 and VR-008. The retry bound (at most 128 attempts), termination and the guarded `copy_from_slice` of `sign_fixed_len` are also proved on the real loop on `Mahnush_Verus` as VR-008. That content of C02 is superseded. C02 is not a duplicate and is not demoted: it remains the only statement of T1 as a postcondition, T3 (no partial write), T4 (which `Err` exits exist), T5 (`check_sig_len`), T6 (the `ecdsa_sign*` wrong-length contract) and the three non-vacuity witnesses. VR-008 has no `ensures`, and `check_sig_len` and `ecdsa_sign*` are outside `verus!` there. Recorded status of C02: Proved at model level (unchanged); partly superseded by VR-008 (in-crate, `Mahnush_Verus`). The cross-branch table and the full C03 tables are in `docs/verification-targets.md` ("Proofs written").

### Findings from the proofs
'''

def e02():
    E = []
    E.append(("Sources: `verus-proofs/README.md` (T02, C01, C02) and `verus-proofs/README-t03-t05.md` (T03, T05).\n",
              "Sources: `verus-proofs/README.md` (T02, C01, C02) and `verus-proofs/README-t03-t05.md` (T03, T05). C03 has a different kind of status, described in the subsection after the canonical strings: in-crate, on the shipped prim code, on branch `Mahnush_Verus`, not on this branch. C02 is partly superseded by VR-008 on that branch.\n"))
    E.append(("- C02: Proved (model level, not the shipped code, under stated hypotheses): 21 verified, 0 errors\n\n**Scores are unchanged.**",
              f"- C02: Proved (model level, not the shipped code, under stated hypotheses): 21 verified, 0 errors\n- C03: {PS_C03}\n- C02, relation added (the C02 status string above is unchanged): {C02_CELL_NOTE}\n\n**Scores are unchanged.**"))
    E.append(("and re-scoring would be arbitrary. Coverage gaps will be recalculated when a proof is linked to the shipped code (for example with `cargo verus` on the crate, or by moving the logic into `verus!`).\n\n### Findings from the proofs\n",
              "and re-scoring would be arbitrary. Coverage gaps will be recalculated when a proof is linked to the shipped code (for example with `cargo verus` on the crate, or by moving the logic into `verus!`). The same holds for C03: its proof is on `Mahnush_Verus`, not on this branch, so C03 stays at 5.60, rank 3, coverage gap 0.7.\n\n" + C03_SECTION_02))
    E.append(("- **C02 assumption.** The no-partial-write claim relies on vstd's own `assume_specification` for `<[T]>::copy_from_slice`, listed in the proof's TCB.\n",
              "- **C02 assumption.** The no-partial-write claim relies on vstd's own `assume_specification` for `<[T]>::copy_from_slice`, listed in the proof's TCB.\n"
              "- **C03 / BUG-07(a) (not on this branch).** On `Mahnush_Verus`, Verus proves in prim that a key or nonce `Err` of `aes_encrypt` leaves exactly `old ++ message` in the caller's buffer, and that a seal `Err` keeps the length `old + len(message)` and the prefix `old`. The `Ok`-case order is an in-body assert. BUG-07(b) is recorded relative to A20, not proved.\n"
              "- **BUG-10 (Low, code reading).** `RawAesKeyring::on_decrypt` drops an authenticated plaintext data key un-wiped on the wrong-length path. It maps to TM-MPL-015 and T26, not to C03.\n"))
    E.append(("- Add a CI step that runs the proof files and fails on any change to the result lines (T02 is expected to show `1 errors` until G1 is fixed).\n",
              "- Add a CI step that runs the proof files and fails on any change to the result lines (T02 is expected to show `1 errors` until G1 is fixed).\n"
              "- C03: decide how the in-crate prim proofs reach this branch (merge or port `prim/`); an owner decision, not done here.\n"))
    # summary table
    E.append(("| verus-zero-panic | cap:cat2 (2d) | 1 week (quick win) | " + PS_C02 + " |",
              "| verus-zero-panic | cap:cat2 (2d) | 1 week (quick win) | " + PS_C02 + ". " + C02_CELL_NOTE + " |"))
    E.append(("| verus-zero-panic | cap:cat2 (2a/2d) | 1 week | None yet |",
              "| verus-zero-panic | cap:cat2 (2a/2d) | 1 week | " + PS_C03 + " |"))
    E.append(("  proof_file: verus-proofs/c02_sign_fixed_len.rs\n",
              "  proof_file: verus-proofs/c02_sign_fixed_len.rs\n  proof_note: \"" + C02_NOTE_YAML + "\"\n"))
    E.append(('    product: "2 × 0.7 × 1.0 × 4 = 5.60"\n  quick_win: false\n  proof_status: "None yet"\n',
              '    product: "2 × 0.7 × 1.0 × 4 = 5.60"\n  quick_win: false\n' + C03_YAML))
    # section 4 rows
    E.append(("| `prim::aes_*` caller preconditions (cat 3b) | **T07** | Partial | C03 keeps the unconditional half. |",
              "| `prim::aes_*` caller preconditions (cat 3b) | **T07** | Partial | C03 keeps the unconditional half. VR-014 (on `Mahnush_Verus`, not on this branch) proves the prim-side buffer facts of BUG-07; the caller side (what mpl and the ESDK do with the buffer) stays with T26 and T07 (code reading). |"))
    E.append(("`ecdsa_generate_keypair` leaves the private-key `Vec` un-wiped on its error return (`prim/src/ecdsa.rs:387`, `:391-392`; C02 does not list `ecdsa_generate_keypair`). |",
              "`ecdsa_generate_keypair` leaves the private-key `Vec` un-wiped on its error return (`prim/src/ecdsa.rs:387`, `:391-392`; C02 does not list `ecdsa_generate_keypair`). Also in T26 and outside every C target: BUG-10 (the raw-AES `on_decrypt` wrong-length path, `raw_aes_keyring.rs:489-494`, and `branch_key_wrap::unwrap`'s plain `Vec<u8>`, `:275`), and the BUG-07(a) caller impact at `wrap_data_key` and `branch_key_wrap::wrap`; the buffers are in `mpl`, which no C target covers. |"))
    # section 6
    E.append(("- C03: BUG-07(b) `aes_decrypt` guard weaker than its callee; misleading error text (`prim/src/lib.rs:215`, error mapping after the callee).\n",
              "- C03: BUG-07(b) `aes_decrypt` guard weaker than its callee; misleading error text (`prim/src/lib.rs:215`, error mapping after the callee). Recorded, not proved: the VR-014 core states it relative to A20 on `Mahnush_Verus`. The BUG-07(a) prim-side buffer facts are proved there (partly proved, not on this branch).\n"
              "- T26, not a C target: BUG-10 (Low, code reading) `RawAesKeyring::on_decrypt` drops an authenticated plaintext data key un-wiped when its length is wrong (`raw_aes_keyring.rs:489-494`); `branch_key_wrap::unwrap` holds a plain `Vec<u8>` (`:275`).\n"))
    return E

# ---------------------------------------------------------------- 01
T26_01_ANCHOR = '    product: "2 × 1.0 × 0.4 × 4 = 3.20"\n  quick_win: false\n  proof_status: "None yet"\n'
SEC7_01 = f'''
## 7. Proof status and bug records added at HEAD b94c871

Added after the `9955ecd` refresh. No score, rank, coverage gap, feasibility, severity or quick-win changed.

- **C03 (in `02-capability-driven.md`).** Partly proved in-crate on branch `Mahnush_Verus` as VR-013 and VR-014 (the shipped prim code; not on this branch): `verification results:: 18 verified, 0 errors` at `{TIP[:7]}`. Status string: {PS_C03}. This is a different qualifier from the model-level proofs in this file (T02, T03, T05: "model level, not the shipped code"). C03 cites no threat, so no threat row here changed.
- **C02.** Proved at model level (unchanged); partly superseded by VR-008 (in-crate, `Mahnush_Verus`): the retry bound, termination and guarded copy. It is not a duplicate. Details in `02-capability-driven.md`.
- **BUG-10 -> TM-MPL-015 -> T26.** BUG-10 (Low, code reading, added 2026-11-17) is the bug report for T26's site F1 wrong-length path (`raw_aes_keyring.rs:489-494`) and for F3 (`branch_key_wrap::unwrap`, `:275`). It is recorded in T26's `related_bugs` and `scope_note`. T26's score (3.20), rank, gap and the TM-MPL-015 rating are unchanged, and its proof status is still "None yet". The completeness audit's section 3b predates BUG-10.
- **BUG-07(a) caller impact -> T26 (F2), T07.** The plaintext data key can stay in the caller's buffer after an `aes_encrypt` `Err` at `wrap_data_key` and `branch_key_wrap::wrap`. Code reading; it cannot fire today. The prim-side facts are proved only on `Mahnush_Verus` (C03, VR-014).
- **Open bugs.** BUG-01, 04, 05(a), 05(b), 06, 07(a/b), 08 and 10. Fixed: BUG-02, 03, 09.
'''

def e01():
    E = []
    E.append(("Sources: `verus-proofs/README.md` (T02, C01, C02) and `verus-proofs/README-t03-t05.md` (T03, T05).\n",
              "Sources: `verus-proofs/README.md` (T02, C01, C02) and `verus-proofs/README-t03-t05.md` (T03, T05). C03 is recorded in `02-capability-driven.md` and the merged document: it is partly proved in-crate on branch `Mahnush_Verus` (not on this branch), a different kind of status from the model-level proofs here. For T26 this file now records BUG-10 and the BUG-07(a) caller impact (T26 YAML and section 7). Scores are unchanged.\n"))
    E.append(("- **Bugs:** open BUG-01, 04, 05(a), 05(b), 06, 07(a/b), 08. Fixed BUG-02, 03, 09 (`e9bde48`).",
              "- **Bugs:** open BUG-01, 04, 05(a), 05(b), 06, 07(a/b), 08, 10 (BUG-10 added after the audit, by code reading). Fixed BUG-02, 03, 09 (`e9bde48`)."))
    E.append((T26_01_ANCHOR, T26_01_ANCHOR + T26_RELATED))
    E.append(("T26 (BUG-07a, unwiped decrypt buffers, expired cache entries resident until read, unwiped ECDSA private-key `Vec` on an error path)",
              "T26 (BUG-07a, unwiped decrypt buffers, BUG-10 (raw-AES `on_decrypt` wrong-length path, code reading), expired cache entries resident until read, unwiped ECDSA private-key `Vec` on an error path)"))
    return E

def apply(path, edits, append=None):
    full = os.path.join(ROOT, path)
    t = open(full, encoding="utf-8").read()
    for i, (old, new) in enumerate(edits):
        n = t.count(old)
        if n != 1:
            print(f"FAIL {path} edit {i}: {n} matches for {old[:80]!r}")
            sys.exit(1)
        t = t.replace(old, new)
    if append:
        t = t.rstrip("\n") + "\n" + append
    return full, t

if __name__ == "__main__":
    out = []
    out.append(apply(P["merged"], merged_edits()))
    out.append(apply(P["02"], e02()))
    out.append(apply(P["01"], e01(), SEC7_01))
    for full, t in out:
        open(full, "w", encoding="utf-8").write(t)
        print("written", full)
