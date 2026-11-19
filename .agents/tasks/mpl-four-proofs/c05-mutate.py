#!/usr/bin/env python3
"""C05 model mutation set. Run from the repo root:
    python3 .agents/tasks/mpl-four-proofs/c05-mutate.py

Each mutant is a copy of verus-proofs/c05_algorithm_suite_table.rs with ONE deliberate change to
the MODEL (never to mpl/). The mutant is written to .agents/tasks/mpl-four-proofs/mutants/c05/,
run with ~/verus/verus, and must be rejected. The copy-check script is run on each mutant too, to
show which model edits it catches without Verus. Writes c05-mutation-run.txt.
These checks cover edits to the model only, not edits to the shipped code.
"""
import os, re, subprocess, sys

ROOT = os.getcwd()
SRC = os.path.join(ROOT, "verus-proofs/c05_algorithm_suite_table.rs")
OUT = os.path.join(ROOT, ".agents/tasks/mpl-four-proofs/mutants/c05")
REC = os.path.join(ROOT, ".agents/tasks/mpl-four-proofs/c05-mutation-run.txt")
CHECK = os.path.join(ROOT, ".agents/tasks/mpl-four-proofs/c05-copy-check.py")
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
    return out, (int(m.group(1)), int(m.group(2))) if m else None, p.returncode


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
    fails = [l for l in p.stdout.splitlines() if l.startswith("FAIL")]
    return p.returncode, fails


R192 = "id0: 0x00, id1: 0x46, enc: CEnc::Aes, mode: CMode::Gcm,\n            key_len: 24, iv_len: 12, tag_len: 16,\n            enc_kdf: CKdf::IdentityKdf, commit_kdf: None,"
M = []


def mut(name, desc, fn, expect="reject"):
    M.append((name, desc, fn, expect))


mut("m01_wrong_key_length", "code row 00 46: key_len 24 -> 32 (spec says 192 bits)",
    lambda t: sub(t, R192, R192.replace("key_len: 24", "key_len: 32")))
mut("m02_duplicate_id", "code row 01 78 given the id 01 46 (a duplicate of the 192-bit HKDF suite)",
    lambda t: sub(t, "id0: 0x01, id1: 0x78, enc: CEnc::Aes, mode: CMode::Gcm,", "id0: 0x01, id1: 0x46, enc: CEnc::Aes, mode: CMode::Gcm,"))
mut("m03_wrong_commitment_flag", "code row 04 78: commit_kdf Some(HkdfSha512) -> None (format 2 and data length 32 kept)",
    lambda t: sub(t, "enc_kdf: CKdf::HkdfSha512, commit_kdf: Some(CKdf::HkdfSha512),\n            asym: None, sym: None, fmt: 0x02, data_len: 32,",
                  "enc_kdf: CKdf::HkdfSha512, commit_kdf: None,\n            asym: None, sym: None, fmt: 0x02, data_len: 32,"))
mut("m04_reserved_id", "code row 00 14: id bytes 00 14 -> 00 00 (the reserved id)",
    lambda t: sub(t, "id0: 0x00, id1: 0x14, enc: CEnc::Aes, mode: CMode::Gcm,", "id0: 0x00, id1: 0x00, enc: CEnc::Aes, mode: CMode::Gcm,"))
mut("m05_wrong_format_version", "code row 05 78: fmt 0x02 -> 0x01",
    lambda t: sub(t, "asym: Some(CAsym::EcdsaP384), sym: None, fmt: 0x02, data_len: 32,", "asym: Some(CAsym::EcdsaP384), sym: None, fmt: 0x01, data_len: 32,"))
mut("m06_wrong_data_len", "code row 05 78: data_len 32 -> 16",
    lambda t: sub(t, "asym: Some(CAsym::EcdsaP384), sym: None, fmt: 0x02, data_len: 32,", "asym: Some(CAsym::EcdsaP384), sym: None, fmt: 0x02, data_len: 16,"))
mut("m07_wrong_kdf_hash", "code row 03 46: HkdfSha384 -> HkdfSha256",
    lambda t: sub(t, "key_len: 24, iv_len: 12, tag_len: 16,\n            enc_kdf: CKdf::HkdfSha384, commit_kdf: None,", "key_len: 24, iv_len: 12, tag_len: 16,\n            enc_kdf: CKdf::HkdfSha256, commit_kdf: None,"))
mut("m08_symmetric_signature_present", "code row 01 14: sym None -> Some(HmacSha384)",
    lambda t: sub(t, "id0: 0x01, id1: 0x14, enc: CEnc::Aes, mode: CMode::Gcm,\n            key_len: 16, iv_len: 12, tag_len: 16,\n            enc_kdf: CKdf::HkdfSha256, commit_kdf: None,\n            asym: None, sym: None,",
                  "id0: 0x01, id1: 0x14, enc: CEnc::Aes, mode: CMode::Gcm,\n            key_len: 16, iv_len: 12, tag_len: 16,\n            enc_kdf: CKdf::HkdfSha256, commit_kdf: None,\n            asym: None, sym: Some(CSym::HmacSha384),"))
mut("m09_wrong_curve", "code row 02 14: asym EcdsaP256 -> EcdsaP384",
    lambda t: sub(t, "asym: Some(CAsym::EcdsaP256), sym: None, fmt: 0x01, data_len: 0,", "asym: Some(CAsym::EcdsaP384), sym: None, fmt: 0x01, data_len: 0,"))
mut("m10_wrong_vk_len_constant", "verification_key_length constant for P-256: 33 -> 32",
    lambda t: sub(t, "pub open spec fn vk_len_p256() -> usize { 33 }", "pub open spec fn vk_len_p256() -> usize { 32 }"))
mut("m11_all_order_swapped", "ALL order: entries 0 and 1 swapped in all_at",
    lambda t: sub(sub(t, "if i == 0 { Suite::AlgAes128GcmIv12Tag16NoKdf }", "if i == 0 { Suite::AlgAes192GcmIv12Tag16NoKdf }"),
                  "else if i == 1 { Suite::AlgAes192GcmIv12Tag16NoKdf }", "else if i == 1 { Suite::AlgAes128GcmIv12Tag16NoKdf }"))
mut("m12_all_misses_a_suite", "ALL lists suite 04 78 twice and omits 05 78 (entry 10)",
    lambda t: sub(t, "else { Suite::AlgAes256GcmHkdfSha512CommitKeyEcdsaP384 }\n}\n\n/// R2: same id bytes", "else { Suite::AlgAes256GcmHkdfSha512CommitKey }\n}\n\n/// R2: same id bytes"))
mut("m13_prim_key_length_wrong", "prim copy: Aes192Gcm key length 24 -> 32",
    lambda t: sub(t, "PAes::Aes192Gcm => 24,", "PAes::Aes192Gcm => 32,"))
mut("m14_get_alg_suite_wrong", "esdk get_alg_suite copy: 24 maps to Aes256Gcm",
    lambda t: sub(t, "else if key_len == 24 { Some(PAes::Aes192Gcm) }", "else if key_len == 24 { Some(PAes::Aes256Gcm) }"))
mut("m15_spec_row_wrong_id", "spec copy: row 00 78 typed as 0x0079",
    lambda t: sub(t, "id: 0x0078, enc: SEnc::Aes", "id: 0x0079, enc: SEnc::Aes"))
mut("m16_wrong_iv_length", "code row 00 14: iv_len 12 -> 16",
    lambda t: sub(t, "id0: 0x00, id1: 0x14, enc: CEnc::Aes, mode: CMode::Gcm,\n            key_len: 16, iv_len: 12,", "id0: 0x00, id1: 0x14, enc: CEnc::Aes, mode: CMode::Gcm,\n            key_len: 16, iv_len: 16,"))
mut("m17_other_format_id_collides", "spec_other_id(2): S3EC id 00 70 -> 00 14 (collides with an ESDK id)",
    lambda t: sub(t, "else if i == 2 { 0x0070 }", "else if i == 2 { 0x0014 }"))
mut("m18_search_skips_first", "from_id_bytes model: the search starts at index 1",
    lambda t: sub(t, "pub open spec fn from_id_bytes(b: (u8, u8)) -> Option<Suite> { find_from(b, 0) }", "pub open spec fn from_id_bytes(b: (u8, u8)) -> Option<Suite> { find_from(b, 1) }"))
mut("m19_wrong_spec_commit_hash", "spec copy: commit hash of row 04 78 typed as Sha256",
    lambda t: sub(t, "kdf_in_bits: 256, kdf: SKdf::Hkdf(SHash::Sha512), key_commitment: true,\n            commit: Some(SCommit { in_bits: 256, out_bits: 256, hash: SHash::Sha512 }),\n            asym: None,",
                  "kdf_in_bits: 256, kdf: SKdf::Hkdf(SHash::Sha512), key_commitment: true,\n            commit: Some(SCommit { in_bits: 256, out_bits: 256, hash: SHash::Sha256 }),\n            asym: None,"))
mut("m20_key_length_not_aes", "code and spec both changed for row 00 46: 20 bytes / 160 bits (a consistent copy error)",
    lambda t: sub(sub(t, R192, R192.replace("key_len: 24", "key_len: 20")),
                  "id: 0x0046, enc: SEnc::Aes, mode: SMode::Gcm, key_bits: 192, iv_bytes: 12, tag_bytes: 16,\n            kdf_in_bits: 192,",
                  "id: 0x0046, enc: SEnc::Aes, mode: SMode::Gcm, key_bits: 160, iv_bytes: 12, tag_bytes: 16,\n            kdf_in_bits: 160,"))
mut("m21_consistent_id_change", "code and spec both changed for row 00 14: id 00 14 -> 00 15 (a consistent copy error of an id)",
    lambda t: sub(sub(t, "id0: 0x00, id1: 0x14, enc: CEnc::Aes, mode: CMode::Gcm,", "id0: 0x00, id1: 0x15, enc: CEnc::Aes, mode: CMode::Gcm,"),
                  "id: 0x0014, enc: SEnc::Aes", "id: 0x0015, enc: SEnc::Aes"), expect="survive")
mut("m22_spec_ids_dropped_from_refinement", "refinement without the id comparison (weakened relation)",
    lambda t: sub(t, "    &&& c.id0 as int * 256 + c.id1 as int == r.id\n", ""), expect="survive")
mut("m23_id_out_of_order", "code row 01 14 given id 00 15 (not the spec id; ids no longer ascend in ALL order)",
    lambda t: sub(t, "id0: 0x01, id1: 0x14, enc: CEnc::Aes, mode: CMode::Gcm,", "id0: 0x00, id1: 0x15, enc: CEnc::Aes, mode: CMode::Gcm,"))

lines = []
out, res, rc = run_verus(SRC)
lines.append(f"BASELINE: verification results:: {res[0]} verified, {res[1]} errors (exit {rc})")
rc0, f0 = copy_check(SRC)
lines.append(f"BASELINE copy-check: exit {rc0}, {len(f0)} failing checks")
lines.append("")
rejected = survived = 0
unexpected = []
for name, desc, fn, expect in M:
    text = fn(base)
    assert text != base, name
    path = os.path.join(OUT, name + ".rs")
    open(path, "w").write(text)
    out, res, rc = run_verus(path)
    status = "REJECTED" if (res is None or res[1] > 0 or rc != 0) else "SURVIVED"
    if status == "REJECTED":
        rejected += 1
    else:
        survived += 1
    if (expect == "reject") != (status == "REJECTED"):
        unexpected.append(name)
    rc1, fails = copy_check(path)
    lines.append(f"{name} [predicted: {expect}] {desc}")
    if res is None:
        lines.append(f"    -> no result line (exit {rc}); first error: {out.strip().splitlines()[0] if out.strip() else ''}")
    else:
        lines.append(f"    -> {res[0]} verified, {res[1]} errors  {status}")
    lines.append(f"    failing lemmas: {failing_fns(out, text)}")
    lines.append(f"    copy-check on the mutant: {'catches it (' + str(len(fails)) + ' failing checks)' if rc1 else 'does not catch it'}")
lines.append("")
lines.append("SURVIVORS (expected, with the reason):")
lines.append("  m21: the same wrong id is typed into both copies, so the model is self-consistent and Verus has nothing to compare it with.")
lines.append("       Only the script that reads the Rust source and the spec file catches it (copy-check column). This is the copied-by-hand limit A_CODE_COPY / A_SPEC_COPY.")
lines.append("  m22: the definition of the refinement relation was weakened. Verus proves what the file states; it cannot tell that a relation")
lines.append("       is missing a field. Only a reader of row_refines (header R1 lists every field) catches it. Neither Verus nor the copy-check script does.")
lines.append("")
lines.append(f"SUMMARY: {len(M)} mutants, {rejected} rejected by Verus, {survived} survived; unexpected outcomes: {unexpected}")
open(REC, "w").write("\n".join(lines) + "\n")
print("\n".join(lines))
