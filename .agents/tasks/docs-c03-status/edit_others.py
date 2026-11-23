#!/usr/bin/env python3
"""Edits threat-model.md, completeness-audit.md and docs/chorus/MPL-Threat-Model.md for the C03 / C02 / BUG-10 record."""
import os, sys
ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))
QM = "model level, not the shipped code, under stated hypotheses"
QC = "in-crate, on the shipped prim code, on branch Mahnush_Verus, not on this branch, under trusted aws-lc-rs assumptions A1-A20"
PS_C03 = f"Partly proved ({QC}): 18 verified, 0 errors"
PS_C02 = f"Proved ({QM}): 21 verified, 0 errors"
C02_REL = "partly superseded by VR-008 (in-crate, on the shipped prim code, on branch Mahnush_Verus, not on this branch): retry bound, termination, guarded copy"
TIP7 = "8d6381e"

def apply(path, edits):
    full = os.path.join(ROOT, path)
    t = open(full, encoding="utf-8").read()
    for i, (old, new) in enumerate(edits):
        n = t.count(old)
        if n != 1:
            print(f"FAIL {path} edit {i}: {n} matches for {old[:90]!r}")
            sys.exit(1)
        t = t.replace(old, new)
    return full, t

# ------------------------------------------------------------------ threat-model.md
TM = []
TM.append(("A model-level proof reduces uncertainty about the logic, not about the shipped code. No threat rating and no threat ID changed.",
           "A model-level proof reduces uncertainty about the logic, not about the shipped code. No threat rating and no threat ID changed. A sixth target, C03 (the prim wrappers, VR-013 and VR-014), has a different kind of proof: in-crate, on the shipped prim code, on branch `Mahnush_Verus`, which is **not this branch**. Its rows below carry that qualifier, not the model-level one. VR-014 concerns buffer effects only, so C03 says nothing about IV uniqueness (TM-MPL-011). C02 is also partly superseded by VR-008 on that branch (see the C02 row)."))
TM.append(("| none (capability 2d) | C02 | " + PS_C02 + " | At most 128 signing attempts, no panic, no partial write. Relies on vstd's own `assume_specification` for `copy_from_slice` | Nonce randomness; panics inside aws-lc-rs |",
           "| none (capability 2d) | C02 | " + PS_C02 + ". Also " + C02_REL + " | At most 128 signing attempts, no panic, no partial write. Relies on vstd's own `assume_specification` for `copy_from_slice`. On `Mahnush_Verus` VR-008 proves the bound, termination and guarded copy on the real loop; C02 stays the only statement of no partial write (`Err` leaves the buffer unchanged), the exact `Err` exits, `check_sig_len` and the `ecdsa_sign*` wrong-length contract | Nonce randomness; panics inside aws-lc-rs |"))
TM.append(("| TM-MPL-015 and all other threats | | None yet | | |",
           "| TM-MPL-015 | C03 (VR-014, BUG-07(a)) | " + PS_C03 + " | In prim on `Mahnush_Verus`: a key or nonce `Err` of `aes_encrypt` leaves exactly `old ++ message` (the plaintext) in the caller's buffer, and a seal `Err` keeps the length `old + len(message)` and the prefix `old` (exported postconditions). The proof says nothing about wiping. The mpl callers `wrap_data_key` and `branch_key_wrap::wrap` drop that buffer un-wiped (code reading), and the failure cannot fire today | Zeroization; the mpl callers (mpl is not Verus-enabled); the `Ok`-case order `old ++ ciphertext ++ tag` (in-body assert) and the seal-`Err` tail bytes; the FIPS backend |\n"
           "| TM-MPL-015 | T26 (BUG-10, BUG-07(a) caller impact) | None yet | BUG-10 recorded (Low, code reading): `RawAesKeyring::on_decrypt` drops an authenticated plaintext data key un-wiped on the wrong-length path, and `branch_key_wrap::unwrap` holds a plain `Vec<u8>` | Everything: there is no proof, the evidence is code reading |\n"
           "| TM-MPL-023 | C03 (VR-013, VR-014, BUG-07(b)) | " + PS_C03 + " | In prim on `Mahnush_Verus`: `hmac`, `digest` and `DigestContext::finish` return `Err` unless the output buffer has the exact length and copy only after that guard; the `kbkdf_ctr_hmac` wrapper decision; BUG-07(b) relative to the labeled assumption A20 (`aes_decrypt` accepts a longer plaintext buffer and then `Err`s in the callee), recorded, not proved | `hkdf` and `hkdf_expand` output-length contract and \"no listed function panics\" end to end; `DigestContext::digest`'s call to `finish`; adapters outside `verus!`; panics inside aws-lc-rs (A1 to A20 are trusted; the FIPS C side is unchecked) |\n"
           "| All other threats | | None yet | | |"))
TM.append(("- The raw-AES decrypt buffer on the AES-error and wrong-length paths (`raw_aes_keyring.rs:471`, `:489`).\n",
           "- The raw-AES decrypt buffer on the AES-error and wrong-length paths (`raw_aes_keyring.rs:471`, `:489`). The wrong-length path (an authenticated data key dropped un-wiped) is recorded as BUG-10 (Low, code reading; `docs/bug-reports/BUG-10-raw-aes-on-decrypt-unwiped-data-key.md`). Target T26.\n"))
TM.append(("- The `Vec` returned by `branch_key_wrap::unwrap` before it is wrapped in `PlaintextDataKey`.\n",
           "- The `Vec` returned by `branch_key_wrap::unwrap` before it is wrapped in `PlaintextDataKey` (a plain `Vec<u8>`, `branch_key_wrap.rs:275`). Also part of BUG-10 (code reading).\n"))
TM.append(("The MPL callers then drop that buffer without wiping it.\n",
           "The MPL callers then drop that buffer without wiping it. Caller impact (code reading; the prim-side facts are proved in-crate only on `Mahnush_Verus`, VR-014): the callers are `wrap_data_key` (`raw_aes_keyring.rs:163`) and `branch_key_wrap::wrap` (`:199`). The key cannot leave through the API, and the failure cannot fire today, because key and IV sizes are fixed by type and the raw-AES wrapping-key length is checked at `RawAesKeyringBuilder::build` (`:369-379`). Low, confidentiality.\n"))
TM.append(("| BUG-09 TTL admits ttl + 1 s | **Fixed** | TM-MPL-010 | Mitigation added | none |\n",
           "| BUG-09 TTL admits ttl + 1 s | **Fixed** | TM-MPL-010 | Mitigation added | none |\n"
           "| BUG-10 raw-AES `on_decrypt` drops an authenticated data key un-wiped when its length is wrong | Open (code reading; added 2026-11-17) | TM-MPL-015 | None; inside the Low residual (the site was already listed there) | none |\n"))

# ------------------------------------------------------------------ completeness-audit.md
AU = []
AU.append(("The one statement in this audit that labelled BUG-06 as \"Low in the bug report\"",
           "| BUG-10 (added after the audit) | Recorded by content: BUG-10 maps to TM-MPL-015 -> T26. The audit's section 3b predates it and is unchanged. The site was already a known residual of TM-MPL-015 and T26 (F1, F3), so there is no new target and no new threat, and no score or rating changed | `docs/bug-reports/BUG-10-raw-aes-on-decrypt-unwiped-data-key.md`; T26 `related_bugs` and `scope_note` in `docs/verification-targets/01-threat-driven.md` and `docs/verification-targets.md`; the TM-MPL-015 residual exposures and the bug to threat table in `docs/threat-model.md` |\n"
           "| C03 proof status (added after the audit) | Recorded. C03 status: " + PS_C03 + " (`verification results:: 18 verified, 0 errors` at `" + TIP7 + "`, branch `Mahnush_Verus`, PR #103). C02 is " + C02_REL + ", and its model-level status (21 verified, 0 errors) is unchanged. The audit's findings and tables are unchanged: section 3b still lists BUG-07(b) -> C03 and BUG-07(a) -> T26, T07 | \"Proofs written\" in `docs/verification-targets.md`, `docs/verification-targets/02-capability-driven.md`; `docs/threat-model.md` \"Proof status\" |\n"
           "The one statement in this audit that labelled BUG-06 as \"Low in the bug report\""))
# the new rows must sit inside the table: put them before the paragraph that follows the table (table ends with BUG-06 / TM-MPL-025 rows)

# ------------------------------------------------------------------ chorus
CH = []
CH.append(("- Bug status was re-checked against `main`: BUG-02, BUG-03 and BUG-09 are fixed; the other six bugs are open. BUG-06 is rated High (section 7).\n",
           "- Bug status was re-checked against `main`: BUG-02, BUG-03 and BUG-09 are fixed; the other six bugs are open. BUG-06 is rated High (section 7).\n"
           "- Added later (2026-11-17): BUG-10 (a raw-AES keyring path drops an authenticated plaintext data key un-wiped; Low, code reading; TM-MPL-015, target T26) and the caller impact of BUG-07 (code reading). Target C03 is partly proved in-crate on branch `Mahnush_Verus`, which is not this branch, and C02 is partly superseded by VR-008 there (section 7). No threat rating, score or rank changed.\n"))
CH.append(("Five of them have a Verus proof of a model of the code (T02 partly, C01, C02, T03, T05; see section 7). None verifies the shipped code, and no score changed.",
           "Five of them have a Verus proof of a model of the code (T02 partly, C01, C02, T03, T05; see section 7). None of those verifies the shipped code, and no score changed. A sixth, C03, is partly proved in-crate on the shipped prim code, but on branch `Mahnush_Verus`, not on this branch (section 7); nothing on this branch is verified."))
CH.append(("- 9 bug reports exist (BUG-01 to BUG-09), 11 items when BUG-05 and BUG-07 are split into (a) and (b). All 9 link to at least one threat. On `main` `620771c` (re-checked 2026-11-10, with no change in `mpl/` or `prim/` since): open are BUG-01, BUG-04, BUG-05 (a) and (b), BUG-06, BUG-07 (a) and (b), BUG-08; fixed are BUG-02, BUG-03 and BUG-09 (commit `e9bde48`, #98).",
           "- 10 bug reports exist (BUG-01 to BUG-10), 12 items when BUG-05 and BUG-07 are split into (a) and (b). All 10 link to at least one threat. On `main` `620771c` (re-checked 2026-11-10, with no change in `mpl/` or `prim/` since): open are BUG-01, BUG-04, BUG-05 (a) and (b), BUG-06, BUG-07 (a) and (b), BUG-08, and BUG-10 (added 2026-11-17, by code reading on `MPL-Verus`; `mpl/` is identical to `620771c`); fixed are BUG-02, BUG-03 and BUG-09 (commit `e9bde48`, #98)."))
CH.append(("the raw-AES decrypt buffer on error paths (`raw_aes_keyring.rs:471`, `:489`), the `Vec` returned by `branch_key_wrap::unwrap`, the KMS SDK response `Blob` (`kms_ops.rs:207`), and BUG-07(a) (`prim/src/lib.rs:185-188`: `aes_encrypt` leaves plaintext in the caller's buffer on `Err`). By design, the cache holds plaintext branch keys for the TTL.",
           "the raw-AES decrypt buffer on error paths (`raw_aes_keyring.rs:471`, `:489`; the wrong-length path is recorded as BUG-10, Low, code reading), the `Vec` returned by `branch_key_wrap::unwrap` (also BUG-10), the KMS SDK response `Blob` (`kms_ops.rs:207`), and BUG-07(a) (`prim/src/lib.rs:185-188`: `aes_encrypt` leaves plaintext in the caller's buffer on `Err`; the callers `wrap_data_key` and `branch_key_wrap::wrap` drop it un-wiped, which cannot fire today, by code reading). By design, the cache holds plaintext branch keys for the TTL."))
CH.append(("Open: BUG-01, BUG-04, BUG-05 (a and b), BUG-06, BUG-07 (a and b), BUG-08. Fixed on `main` by `e9bde48` (#98): BUG-02, BUG-03, BUG-09.",
           "Open: BUG-01, BUG-04, BUG-05 (a and b), BUG-06, BUG-07 (a and b), BUG-08, BUG-10 (by code reading). Fixed on `main` by `e9bde48` (#98): BUG-02, BUG-03, BUG-09."))
CH.append(("| TM-MPL-015 (Low) | T26 (3.20) | BUG-07 (a) (open) | None yet |",
           "| TM-MPL-015 (Low) | T26 (3.20) | BUG-07 (a) (open), BUG-10 (open, code reading) | T26: None yet. C03 (VR-014, BUG-07(a)): " + PS_C03 + " |"))
CH.append(("| TM-MPL-023 (Low) | T16 (2.24), T20 (1.68), T06 (4.20) | BUG-01, BUG-05 (a and b), BUG-07 (b) (open); BUG-02 (fixed) | None yet |",
           "| TM-MPL-023 (Low) | T16 (2.24), T20 (1.68), T06 (4.20) | BUG-01, BUG-05 (a and b), BUG-07 (b) (open); BUG-02 (fixed) | T16, T20, T06: None yet. C03 (VR-013, VR-014, BUG-07(b)): " + PS_C03 + " |"))
CH.append(("C02 (Proved (model level, not the shipped code, under stated hypotheses): 21 verified, 0 errors) is a capability target and has no threat ID.\n",
           "C02 (Proved (model level, not the shipped code, under stated hypotheses): 21 verified, 0 errors) is a capability target and has no threat ID. C02 is also " + C02_REL + "; it is not a duplicate and is not demoted.\n"
           "C03 has a different kind of proof: in-crate, on the shipped prim code, on branch `Mahnush_Verus` (aws/aws-crypto-tools-rust, PR #103, VR-013 and VR-014), not on this branch. Status: " + PS_C03 + ". Re-run at `" + TIP7 + "` with `cargo verus verify` (both feature sets): `verification results:: 18 verified, 0 errors` for the prim crate, the same count as at `43b9ff7`. The 18 counts every verified function of the prim crate on that branch, not only C03. C03 cites no threat ID; its rows above are placed by the bug to threat links (BUG-07(a) to TM-MPL-015, BUG-07(b) to TM-MPL-023). It says nothing about IV uniqueness (TM-MPL-011).\n"))
CH.append(("- C02 relies on vstd's own `assume_specification` for `copy_from_slice`.\n",
           "- C02 relies on vstd's own `assume_specification` for `copy_from_slice`.\n"
           "- C03 gaps (not on this branch): `hkdf` and `hkdf_expand` output-length contract and \"no listed function panics\" are not proved end to end; `DigestContext::digest`'s call to `finish` is unmodeled; adapters outside `verus!` are unproved; `constant_time_equal` and `generate_random_bytes` add little beyond assumptions A13 and A12. BUG-07(a): the key or nonce `Err` buffer (`old ++ message`) and the seal-`Err` length and prefix are exported postconditions, but the `Ok`-case order `old ++ ciphertext ++ tag` is an in-body assert and the `+ 16` relies on A19. BUG-07(b) is relative to the labeled assumption A20, not proved. The trusted base is 20 `assume_specification` entries (A1 to A20) about aws-lc-rs, judged true for 1.18.1 by our review; the FIPS C side is unchecked.\n"
           "- BUG-10 (TM-MPL-015, T26): `RawAesKeyring::on_decrypt` drops an authenticated plaintext data key un-wiped when its length is wrong, and `branch_key_wrap::unwrap` holds a plain `Vec<u8>`. Low, code reading, not proved; not covered by C03.\n"))
CH.append(("Bugs and the capability targets that reference them. BUG-02 (fixed) relates to VR-2026-C04, BUG-07 (b) to VR-2026-C03 and BUG-08 to VR-2026-C01 (c).",
           "Bugs and the capability targets that reference them. BUG-02 (fixed) relates to VR-2026-C04, BUG-07 (b) to VR-2026-C03 and BUG-08 to VR-2026-C01 (c). BUG-07 (a) and BUG-10 map to TM-MPL-015 and T26 (BUG-07 (a) also to T07); the prim-side facts of BUG-07 (a) are what C03 proves on `Mahnush_Verus`."))
CH.append(("| BUG-09 | `cache_entry_within_limits` admits entries up to `ttl + 1 s` | Informational | TM-MPL-010 (High) | Fixed on main (`e9bde48`, #98) |\n",
           "| BUG-09 | `cache_entry_within_limits` admits entries up to `ttl + 1 s` | Informational | TM-MPL-010 (High) | Fixed on main (`e9bde48`, #98) |\n"
           "| BUG-10 | Raw AES `on_decrypt` drops an authenticated data key un-wiped when its length is wrong | Low | TM-MPL-015 (Low) | Still present (code reading) |\n"))
CH.append(("6. Bug-to-threat links. All nine bugs now map to a threat.",
           "6. Bug-to-threat links. All ten bugs now map to a threat. BUG-10 maps to TM-MPL-015 (and target T26) through its own report; `docs/completeness-audit.md` section 3b predates it."))
CH.append(("Five targets (T02, C01, C02, T03, T05) have a Verus proof of a model of the code, listed in section 7; scores and ranks are the pre-proof values and were not changed.",
           "Five targets (T02, C01, C02, T03, T05) have a Verus proof of a model of the code, listed in section 7; C03 is partly proved in-crate on branch `Mahnush_Verus`, which is not this branch. Scores and ranks are the pre-proof values and were not changed."))

if __name__ == "__main__":
    out = [apply("docs/threat-model.md", TM), apply("docs/completeness-audit.md", AU), apply("docs/chorus/MPL-Threat-Model.md", CH)]
    for full, t in out:
        open(full, "w", encoding="utf-8").write(t)
        print("written", full)
