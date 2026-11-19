#!/usr/bin/env python3
"""C04 model mutation set. Run from the repo root:
    python3 .agents/tasks/mpl-four-proofs/c04-mutate.py
Each mutant is a copy of verus-proofs/c04_pdk_length_invariant.rs with ONE deliberate change to
the MODEL (never to mpl/). The mutant is written to .agents/tasks/mpl-four-proofs/mutants/c04/,
run with ~/verus/verus, and compared with its prediction. The copy-check script is run on each
mutant too, to show which model edits it catches without Verus. Writes c04-mutation-run.txt.
These checks cover edits to the model only, not edits to the shipped code.
"""
import os, re, subprocess, sys

ROOT = os.getcwd()
SRC = os.path.join(ROOT, "verus-proofs/c04_pdk_length_invariant.rs")
OUT = os.path.join(ROOT, ".agents/tasks/mpl-four-proofs/mutants/c04")
REC = os.path.join(ROOT, ".agents/tasks/mpl-four-proofs/c04-mutation-run.txt")
CHECK = os.path.join(ROOT, ".agents/tasks/mpl-four-proofs/c04-copy-check.py")
VERUS = os.path.expanduser("~/verus/verus")
os.makedirs(OUT, exist_ok=True)
base = open(SRC).read()


def sub(text, old, new, count=1):
    n = text.count(old)
    if n != count:
        raise SystemExit(f"anchor found {n} times, expected {count}: {old!r}")
    return text.replace(old, new)


def run_verus(path):
    p = subprocess.run([VERUS, path], capture_output=True, text=True, cwd=ROOT)
    out = p.stdout + p.stderr
    m = re.search(r"verification results:: (\d+) verified, (\d+) errors", out)
    return out, ((int(m.group(1)), int(m.group(2))) if m else None), p.returncode


def failing_fns(out, text):
    lines = text.split("\n")
    names = []
    for m in re.finditer(r"-->\s+\S*?:(\d+):\d+", out):
        ln = int(m.group(1))
        for k in range(ln - 1, -1, -1):
            mm = re.match(r"\s*(?:pub )?(?:proof |open spec )?fn (\w+)", lines[k])
            if mm:
                names.append(mm.group(1))
                break
    seen = []
    for n in names:
        if n not in seen:
            seen.append(n)
    return seen


def copy_check(path):
    p = subprocess.run([sys.executable, CHECK, path], capture_output=True, text=True, cwd=ROOT)
    return [l for l in p.stdout.splitlines() if l.startswith("FAIL")]


# ---- anchors (exact text in the proof file) ----
CHK_BODY = "    if k.len != encryption_key_length(s) {\n        Err(MErr::InvalidMaterials)\n    } else {\n        Ok(())\n    }"
ENC_ADD = ("pub open spec fn enc_add_data_key(m: Mat, k: Pdk) -> Result<Mat, MErr> {\n    if m.pdk is Some {\n        Err(MErr::InvalidMaterials)\n    } else {\n"
           "        match check_data_key_length(m.suite, k) {\n            Err(e) => Err(e),\n            Ok(_) => Ok(Mat { suite: m.suite, pdk: Some(k) }),\n        }\n    }\n}")
DEC_ADD = ENC_ADD.replace("enc_add_data_key", "dec_add_data_key")
PDK_CHECK_ENC = "pub open spec fn enc_build(b: Bld, other_ok: bool) -> Result<Mat, MErr> {\n    match b.suite {\n        None => Err(MErr::Validation),\n        Some(sid) => {\n            let pdk_check: Result<(), MErr> = match b.pdk {\n                Some(k) => check_data_key_length(sid, k),\n                None => Ok(()),\n            };"
PDK_CHECK_DEC = PDK_CHECK_ENC.replace("enc_build", "dec_build")

M = []


def mut(mid, expect, desc, fn):
    M.append((mid, expect, desc, fn))


# --- paths that skip the check
mut("m01_enc_add_data_key_skips_check", "reject", "enc_add_data_key stores the key without calling check_data_key_length",
    lambda t: sub(t, ENC_ADD, ENC_ADD.replace("        match check_data_key_length(m.suite, k) {\n            Err(e) => Err(e),\n            Ok(_) => Ok(Mat { suite: m.suite, pdk: Some(k) }),\n        }", "        Ok(Mat { suite: m.suite, pdk: Some(k) })")))
mut("m02_dec_add_data_key_skips_check", "reject", "dec_add_data_key stores the key without calling check_data_key_length",
    lambda t: sub(t, DEC_ADD, DEC_ADD.replace("        match check_data_key_length(m.suite, k) {\n            Err(e) => Err(e),\n            Ok(_) => Ok(Mat { suite: m.suite, pdk: Some(k) }),\n        }", "        Ok(Mat { suite: m.suite, pdk: Some(k) })")))
mut("m03_enc_build_skips_check", "reject", "enc_build does not check the builder PDK",
    lambda t: sub(t, PDK_CHECK_ENC, PDK_CHECK_ENC.replace("Some(k) => check_data_key_length(sid, k),", "Some(_) => Ok(()),")))
mut("m04_dec_build_skips_check", "reject", "dec_build does not check the builder PDK",
    lambda t: sub(t, PDK_CHECK_DEC, PDK_CHECK_DEC.replace("Some(k) => check_data_key_length(sid, k),", "Some(_) => Ok(()),")))
mut("m05_raw_dec_bypasses_add_data_key", "reject", "raw_dec builds the materials directly from the first candidate length (no length test, no add_data_key)",
    lambda t: sub(t, "    } else if ns[0] != encryption_key_length(m.suite) {\n        raw_dec(m, ns.drop_first())\n    } else {\n        dec_add_data_key(m, Pdk { len: ns[0] })\n    }",
                  "    } else {\n        Ok(Mat { suite: m.suite, pdk: Some(Pdk { len: ns[0] }) })\n    }"))
mut("m06_hier_dec_bypasses_add_data_key", "reject", "hier_dec builds the materials directly from the first Ok length",
    lambda t: sub(t, "            Some(n) => dec_add_data_key(m, Pdk { len: n }),", "            Some(n) => Ok(Mat { suite: m.suite, pdk: Some(Pdk { len: n }) }),"))
mut("m07_build_checks_wrong_suite", "reject", "enc_build checks the builder PDK against the 256-bit suite for every suite",
    lambda t: sub(t, PDK_CHECK_ENC, PDK_CHECK_ENC.replace("Some(k) => check_data_key_length(sid, k),", "Some(k) => check_data_key_length(Suite::AlgAes256GcmIv12Tag16NoKdf, k),")))
mut("m08_build_checks_only_256", "reject", "dec_build checks the PDK only when the suite key length is 32",
    lambda t: sub(t, PDK_CHECK_DEC, PDK_CHECK_DEC.replace("Some(k) => check_data_key_length(sid, k),", "Some(k) => if encryption_key_length(sid) == 32 { check_data_key_length(sid, k) } else { Ok(()) },")))
# --- the check itself
mut("m09_check_wrong_field", "reject", "check_data_key_length compares with the IV length (12) instead of the key length",
    lambda t: sub(t, CHK_BODY, CHK_BODY.replace("k.len != encryption_key_length(s)", "k.len != code_row(s).iv_len")))
mut("m10_check_accepts_shorter", "reject", "check_data_key_length rejects only a longer key (`k.len > key_len`), so a shorter key passes",
    lambda t: sub(t, CHK_BODY, CHK_BODY.replace("k.len != encryption_key_length(s)", "k.len > encryption_key_length(s)")))
mut("m11_check_accepts_longer", "reject", "check_data_key_length rejects only a shorter key (`k.len < key_len`), so a longer key passes",
    lambda t: sub(t, CHK_BODY, CHK_BODY.replace("k.len != encryption_key_length(s)", "k.len < encryption_key_length(s)")))
mut("m12_check_off_by_one", "reject", "check_data_key_length compares `k.len + 1` with the key length",
    lambda t: sub(t, CHK_BODY, CHK_BODY.replace("k.len != encryption_key_length(s)", "k.len + 1 != encryption_key_length(s)")))
mut("m13_check_inverted", "reject", "check_data_key_length: the `!=` is `==` (accepts only wrong lengths)",
    lambda t: sub(t, CHK_BODY, CHK_BODY.replace("k.len != encryption_key_length(s)", "k.len == encryption_key_length(s)")))
# --- table copy
mut("m14_table_wrong_key_length", "reject", "copied table: row 00 46 key_len 24 -> 32 (spec says 192 bits)",
    lambda t: sub(t, "id0: 0x00, id1: 0x46, enc: CEnc::Aes, mode: CMode::Gcm,\n            key_len: 24,", "id0: 0x00, id1: 0x46, enc: CEnc::Aes, mode: CMode::Gcm,\n            key_len: 32,"))
mut("m15_table_non_aes_key_length", "reject", "copied table and both spec columns: row 03 46 key length 20 bytes / 160 bits (a consistent copy error, not an AES length)",
    lambda t: sub(sub(sub(t, "id0: 0x03, id1: 0x46, enc: CEnc::Aes, mode: CMode::Gcm,\n            key_len: 24,", "id0: 0x03, id1: 0x46, enc: CEnc::Aes, mode: CMode::Gcm,\n            key_len: 20,"),
                      "        Suite::AlgAes192GcmIv12Tag16HkdfSha384EcdsaP384 => 192,\n        Suite::AlgAes256GcmIv12Tag16HkdfSha384EcdsaP384 => 256,\n        Suite::AlgAes256GcmHkdfSha512CommitKey => 256,\n        Suite::AlgAes256GcmHkdfSha512CommitKeyEcdsaP384 => 256,\n    }\n}\n\n/// A_SPEC_COLS_COPY: spec \"Key Derivation Input Length (bits)\"",
                      "        Suite::AlgAes192GcmIv12Tag16HkdfSha384EcdsaP384 => 160,\n        Suite::AlgAes256GcmIv12Tag16HkdfSha384EcdsaP384 => 256,\n        Suite::AlgAes256GcmHkdfSha512CommitKey => 256,\n        Suite::AlgAes256GcmHkdfSha512CommitKeyEcdsaP384 => 256,\n    }\n}\n\n/// A_SPEC_COLS_COPY: spec \"Key Derivation Input Length (bits)\""),
                  "        Suite::AlgAes192GcmIv12Tag16HkdfSha384EcdsaP384 => 192,\n        Suite::AlgAes256GcmIv12Tag16HkdfSha384EcdsaP384 => 256,\n        Suite::AlgAes256GcmHkdfSha512CommitKey => 256,\n        Suite::AlgAes256GcmHkdfSha512CommitKeyEcdsaP384 => 256,\n    }\n}\n\n/// The key length of every suite",
                  "        Suite::AlgAes192GcmIv12Tag16HkdfSha384EcdsaP384 => 160,\n        Suite::AlgAes256GcmIv12Tag16HkdfSha384EcdsaP384 => 256,\n        Suite::AlgAes256GcmHkdfSha512CommitKey => 256,\n        Suite::AlgAes256GcmHkdfSha512CommitKeyEcdsaP384 => 256,\n    }\n}\n\n/// The key length of every suite"))
# --- producers
mut("m16_generator_one_byte_long", "reject", "gen_pdk returns a key one byte longer than the suite key length",
    lambda t: sub(t, "pub open spec fn gen_pdk(s: Suite) -> Pdk {\n    Pdk { len: encryption_key_length(s) }\n}", "pub open spec fn gen_pdk(s: Suite) -> Pdk {\n    Pdk { len: (encryption_key_length(s) + 1) as usize }\n}"))
mut("m17_generator_fixed_32", "reject", "gen_pdk always returns 32 bytes (a generator that ignores the suite)",
    lambda t: sub(t, "pub open spec fn gen_pdk(s: Suite) -> Pdk {\n    Pdk { len: encryption_key_length(s) }\n}", "pub open spec fn gen_pdk(s: Suite) -> Pdk {\n    Pdk { len: 32 }\n}"))
mut("m18_exec_generator_fixed_16", "reject", "generate_exec allocates a fixed 16 bytes",
    lambda t: sub(t, "vec![0u8; encryption_key_length_exec(s)]", "vec![0u8; 16]"))
mut("m19_exec_check_off_by_one", "reject", "check_data_key_length_exec: `key_len > expected_len` instead of `!=`",
    lambda t: sub(t, "    if key_len != expected_len {\n        Err(MErr::InvalidMaterials)", "    if key_len > expected_len {\n        Err(MErr::InvalidMaterials)"))
mut("m20_exec_lookup_wrong", "reject", "encryption_key_length_exec: the 192-bit NO_KDF suite returns 32",
    lambda t: sub(t, "Suite::AlgAes192GcmIv12Tag16NoKdf => 24,\n        Suite::AlgAes256GcmIv12Tag16NoKdf => 32,\n        Suite::AlgAes128GcmIv12Tag16HkdfSha256 => 16,", "Suite::AlgAes192GcmIv12Tag16NoKdf => 32,\n        Suite::AlgAes256GcmIv12Tag16NoKdf => 32,\n        Suite::AlgAes128GcmIv12Tag16HkdfSha256 => 16,"))
# --- state changes outside the add paths
mut("m21_add_edk_changes_suite", "reject", "enc_add_edk returns the materials with the suite replaced by the 128-bit suite and the PDK kept",
    lambda t: sub(t, "    if m.pdk is None {\n        Err(MErr::InvalidMaterials)\n    } else {\n        Ok(m)\n    }", "    if m.pdk is None {\n        Err(MErr::InvalidMaterials)\n    } else {\n        Ok(Mat { suite: Suite::AlgAes128GcmIv12Tag16NoKdf, pdk: m.pdk })\n    }"))
mut("m22_clone_changes_length", "reject", "CloneMat returns a copy whose PDK is one byte longer",
    lambda t: sub(t, "        Step::CloneMat => Ok(m),", "        Step::CloneMat => Ok(Mat { suite: m.suite, pdk: match m.pdk { Some(k) => Some(Pdk { len: (k.len + 1) as usize }), None => None } }),"))
mut("m23_add_data_key_overwrites", "reject", "dec_add_data_key drops the `already has a PDK` guard (a second key replaces the first)",
    lambda t: sub(t, DEC_ADD, DEC_ADD.replace("    if m.pdk is Some {\n        Err(MErr::InvalidMaterials)\n    } else {\n        match check_data_key_length(m.suite, k) {\n            Err(e) => Err(e),\n            Ok(_) => Ok(Mat { suite: m.suite, pdk: Some(k) }),\n        }\n    }",
                                                "    match check_data_key_length(m.suite, k) {\n        Err(e) => Err(e),\n        Ok(_) => Ok(Mat { suite: m.suite, pdk: Some(k) }),\n    }")))
mut("m24_invariant_weakened", "reject", "pdk_ok weakened to `k.len <= key_len` (a premise used by the spec-bits theorem)",
    lambda t: sub(t, "        Some(k) => k.len == encryption_key_length(m.suite),\n        None => true,", "        Some(k) => k.len <= encryption_key_length(m.suite),\n        None => true,"))
def m25(t):
    i = t.index("pub open spec fn enc_build(")
    j = t.index("pub open spec fn dec_build(")
    seg = t[i:j]
    new = seg.replace("Ok(Mat { suite: sid, pdk: b.pdk })", "Ok(Mat { suite: sid, pdk: match b.pdk { Some(_) => Some(Pdk { len: 0 }), None => None } })")
    assert new != seg
    return t[:i] + new + t[j:]


mut("m25_build_stores_other_key", "reject", "enc_build checks the builder PDK, then stores a PDK of length 0 instead of the checked one", m25)
# --- predicted survivors
mut("s01_generated_path_bypasses_check", "survive", "hier_enc stores the generated key without add_data_key (the generated key has the right length by construction, so the check is redundant in the model)",
    lambda t: sub(t, "    if kg.1 {\n        enc_add_data_key(m, kg.0)\n    } else {", "    if kg.1 {\n        Ok(Mat { suite: m.suite, pdk: Some(kg.0) })\n    } else {"))
mut("s02_raw_precheck_weakened", "survive", "raw_dec pre-check `ns[0] != key_len` becomes `ns[0] < key_len`: a longer key now reaches add_data_key, which rejects it (the pre-check is redundant for the invariant)",
    lambda t: sub(t, "    } else if ns[0] != encryption_key_length(m.suite) {\n        raw_dec(m, ns.drop_first())", "    } else if ns[0] < encryption_key_length(m.suite) {\n        raw_dec(m, ns.drop_first())"))
mut("s03_hier_dec_guard_removed", "survive", "hier_dec drops its own `already has a PDK` guard (dec_add_data_key has the same guard)",
    lambda t: sub(t, "pub open spec fn hier_dec(m: Mat, rs: Seq<Option<usize>>) -> Result<Mat, MErr>\n    decreases rs.len(),\n{\n    if m.pdk is Some {\n        Err(MErr::InvalidMaterials)\n    } else if rs.len() == 0 {",
                  "pub open spec fn hier_dec(m: Mat, rs: Seq<Option<usize>>) -> Result<Mat, MErr>\n    decreases rs.len(),\n{\n    if rs.len() == 0 {"))
mut("s04_closure_statement_weakened", "survive", "theorem_c04_closure: the conjunct `pdk_ok(r)` is removed from both ensures (Verus proves what is stated; a missing claim is not detected)",
    lambda t: sub(t, "        enc_build(b, other_ok) matches Ok(m) ==> (run(m, steps) matches Ok(r) ==> pdk_ok(r) && r.suite == m.suite\n            && m.suite == b.suite->Some_0),\n        dec_build(b, other_ok) matches Ok(m) ==> (run(m, steps) matches Ok(r) ==> pdk_ok(r) && r.suite == m.suite\n            && m.suite == b.suite->Some_0),",
                  "        enc_build(b, other_ok) matches Ok(m) ==> (run(m, steps) matches Ok(r) ==> r.suite == m.suite\n            && m.suite == b.suite->Some_0),\n        dec_build(b, other_ok) matches Ok(m) ==> (run(m, steps) matches Ok(r) ==> r.suite == m.suite\n            && m.suite == b.suite->Some_0),"))
mut("s05_consistent_copy_error", "survive", "copied table and both spec columns changed together: row 00 46 key length 32 bytes / 256 bits (a consistent copy error; 32 is a valid AES length)",
    lambda t: sub(sub(t, "id0: 0x00, id1: 0x46, enc: CEnc::Aes, mode: CMode::Gcm,\n            key_len: 24,", "id0: 0x00, id1: 0x46, enc: CEnc::Aes, mode: CMode::Gcm,\n            key_len: 32,"),
                  "        Suite::AlgAes192GcmIv12Tag16NoKdf => 192,\n", "        Suite::AlgAes192GcmIv12Tag16NoKdf => 256,\n", count=2))
mut("s06_exec_generator_unused_field", "survive", "generate_exec reads `bytes.len()` through a second binding (same value; a refactor with no effect)",
    lambda t: sub(t, "    Pdk { len: bytes.len() }\n}", "    let n = bytes.len();\n    Pdk { len: n }\n}"))

mut("m26_run_ignores_steps", "reject", "run returns Ok(m) without applying any step (the closure then holds trivially; the witness must catch it)",
    lambda t: sub(t, "    if steps.len() == 0 {\n        Ok(m)\n    } else {\n        match step(m, steps[0]) {\n            Err(e) => Err(e),\n            Ok(m2) => run(m2, steps.drop_first()),\n        }\n    }",
                  "    if steps.len() == 0 {\n        Ok(m)\n    } else {\n        run(m, steps.drop_first())\n    }"))
mut("s07_consistent_copy_error_all_three", "survive", "code_row, both spec columns AND the exec lookup changed together: row 00 46 key length 32 bytes / 256 bits (a consistent error in every copy)",
    lambda t: sub(sub(sub(t, "id0: 0x00, id1: 0x46, enc: CEnc::Aes, mode: CMode::Gcm,\n            key_len: 24,", "id0: 0x00, id1: 0x46, enc: CEnc::Aes, mode: CMode::Gcm,\n            key_len: 32,"),
                      "        Suite::AlgAes192GcmIv12Tag16NoKdf => 192,\n", "        Suite::AlgAes192GcmIv12Tag16NoKdf => 256,\n", count=2),
                  "Suite::AlgAes192GcmIv12Tag16NoKdf => 24,\n        Suite::AlgAes256GcmIv12Tag16NoKdf => 32,\n        Suite::AlgAes128GcmIv12Tag16HkdfSha256 => 16,",
                  "Suite::AlgAes192GcmIv12Tag16NoKdf => 32,\n        Suite::AlgAes256GcmIv12Tag16NoKdf => 32,\n        Suite::AlgAes128GcmIv12Tag16HkdfSha256 => 16,"))
mut("m27_step_drops_raw_dec", "reject", "step maps RawDec(..) to Ok(m): the raw-AES decrypt path is dropped from the closure (rejected by lemma_step_dispatch, added after the first run)",
    lambda t: sub(t, "        Step::RawDec(ns) => raw_dec(m, ns),", "        Step::RawDec(_ns) => Ok(m),"))

lines = []
out, res, rc = run_verus(SRC)
lines.append(f"BASELINE: {out.strip().splitlines()[-1] if res is None else 'verification results:: %d verified, %d errors' % res} (exit {rc})")
bfails = copy_check(SRC)
lines.append(f"BASELINE copy-check: exit {'0' if not bfails else '1'}, {len(bfails)} failing checks")
n_rej = n_surv = n_diff = n_invalid = 0
survivors = []
for mid, expect, desc, fn in M:
    text = fn(base)
    assert text != base, mid
    path = os.path.join(OUT, mid + ".rs")
    open(path, "w").write(text)
    out, res, rc = run_verus(path)
    invalid = res is None
    rejected = (not invalid) and res[1] > 0
    status = "INVALID (the mutant does not compile; not counted)" if invalid else ("REJECTED" if rejected else "SURVIVED")
    if invalid:
        n_invalid += 1
    elif rejected:
        n_rej += 1
    else:
        n_surv += 1
        survivors.append(mid)
    if not invalid and (expect == "reject") != rejected:
        n_diff += 1
    cc = copy_check(path)
    lines.append(f"{mid} [predicted: {expect}] {desc}")
    if res is None:
        lines.append(f"    -> no result line (exit {rc}); first error: " + next((l for l in out.splitlines() if l.startswith('error')), '')[:150] + f"  {status}")
    else:
        lines.append(f"    -> {res[0]} verified, {res[1]} errors  {status}")
    if rejected:
        ff = failing_fns(out, text)
        if ff:
            lines.append(f"    failing: {ff}")
    lines.append("    copy-check on the mutant: " + (f"catches it ({len(cc)} failing checks)" if cc else "does not catch it"))
lines.append(f"SUMMARY: {len(M)} mutants, {n_rej} rejected, {n_surv} survived, {n_invalid} invalid (compile error), {n_diff} differ from prediction")
lines.append("SURVIVORS: " + ", ".join(survivors))
lines += [
    "SURVIVOR REASONS",
    "s01: hier_enc stores a generated key without calling add_data_key. The generated key has the suite length by construction (gen_pdk), so the check on that path is redundant in the model and the invariant still holds. The mutant is not wrong at model level. It shows that the check inside add_data_key is not what protects the generated path; the length of the generated key is. In the code that length comes from `vec![0u8; suite.encryption_key_length()]` (H_VEC_LEN, H_FILL_SLICE).",
    "s06: a no-op refactor of generate_exec (same value through a second binding). It cannot change any result.",
    "s07: the same wrong key length typed into code_row, both spec columns and the exec lookup (a consistent error in every copy). Verus has nothing to compare. The copy-check script catches it (it reads the Rust source and the spec). This is the copied-by-hand limit, as in C05 m21.",
    "HISTORY of m27 (first run, before lemma_step_dispatch existed: 34 mutants, 30 rejected, 4 survived): the mutant that drops RawDec from `step` SURVIVED. The local lemma on raw_dec and theorem_producers_exact still held because they speak about raw_dec directly, and the closure no longer contained the path. The link between `step` and the path functions was by reading only. lemma_step_dispatch (a definition check) was added to the proof and the mutant is now rejected. The lemma is true by the definition of `step`; it only catches an edit of `step`. The proof file was changed after that first run, so the baseline moved from 23 to 24 verified.",
    "PREDICTION DIFFERENCES (4 mutants were predicted to survive and were rejected; the predictions were written before the first run)",
    "s02: the pre-check `ns[0] < key_len` lets a longer key reach add_data_key, which rejects it with Err, so the safety lemma still holds. It was rejected by lemma_decrypt_succeeds_on_right_length: a longer key before a right-length key now ends the loop with Err. So the liveness witness pins the pre-check behavior (continue on a mismatch). The prediction missed that witness.",
    "s03: hier_dec without its own already-has-a-PDK guard is equivalent in behavior (dec_add_data_key has the same guard and returns Err). It was rejected only because the hand-written induction in lemma_hier_dec follows the guard (the recursive case is entered only when no PDK is present). That is a fragile proof step, not a semantic catch. The mutant is an equivalent mutant that Verus rejects for proof-script reasons.",
    "s04: removing `pdk_ok(r)` from the ensures of theorem_c04_closure was rejected because theorem_c04_summary uses that ensures to prove its own `pdk_ok(r)` conjunct. A weakened statement is caught only where another theorem restates it. Verus does not detect a missing claim by itself.",
    "s05: the consistent change of code_row and both spec columns was rejected by encryption_key_length_exec, the exec lookup, which is a third independent copy of the key lengths. s07 changes all three copies and survives.",
    "NOTE m14, m15: the copy-check script also catches them; Verus catches them through lemma_key_len_table (spec columns) and the exec lookup.",
    "NOTE m01-m08: path-level edits are caught by the local exactness theorems and by the closure; m05 and m06 (a decrypt path that builds materials without add_data_key) are caught by lemma_raw_dec and lemma_hier_dec.",
    "These checks cover edits to the model only, not edits to the shipped code. The copy-check script does not catch model-logic edits (m01 to m13, m16 to m19, m21 to m27), only copy errors in the table and the spec columns, and some code-site changes in mpl/.",
]
open(REC, "w").write("\n".join(lines) + "\n")
print("\n".join(lines))
