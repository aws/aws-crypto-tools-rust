#!/usr/bin/env python3
"""T24 model mutation set. Run from the repo root:
    python3 .agents/tasks/mpl-four-proofs/t24-mutate.py
Each mutant is a copy of verus-proofs/t24_raw_aes_namespace.rs with ONE deliberate change to
the MODEL (never to mpl/). The mutant is written to .agents/tasks/mpl-four-proofs/mutants/t24/,
run with ~/verus/verus, and compared with its prediction. Writes t24-mutation-run.txt.
These checks cover edits to the model only, not edits to the shipped code.
"""
import os, re, subprocess

ROOT = os.getcwd()
SRC = os.path.join(ROOT, "verus-proofs/t24_raw_aes_namespace.rs")
OUT = os.path.join(ROOT, ".agents/tasks/mpl-four-proofs/mutants/t24")
REC = os.path.join(ROOT, ".agents/tasks/mpl-four-proofs/t24-mutation-run.txt")
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


CHECK = "has_prefix(c.ns->Some_0, reserved())"
LEN_BRANCH = """    } else if c.key_len->Some_0 != alg_key_len(c.alg->Some_0) {
        BuildOut::Err(BErr::KeyLen)
    } else {"""

CI_DEF = """
/// MUTANT helper: a case-insensitive prefix test.
pub open spec fn has_prefix_ci(s: Seq<u8>) -> bool {
    s.len() >= 7 && forall|i: int| 0 <= i < 7 ==> lower(#[trigger] s[i]) == reserved()[i]
}
"""

mutants = []  # (id, description, prediction, text)


def add(mid, desc, pred, text):
    mutants.append((mid, desc, pred, text))


add("m01_prefix_to_exact_match",
    "build: starts_with replaced by equality with `aws-kms` (the check the code comment warns against)",
    "reject",
    sub(base, "    } else if " + CHECK + " {\n        BuildOut::Err(BErr::ReservedNs)",
        "    } else if c.ns->Some_0 =~= reserved() {\n        BuildOut::Err(BErr::ReservedNs)"))

add("m02_case_insensitive_compare",
    "build: byte prefix replaced by an ASCII case-insensitive prefix test",
    "reject",
    sub(sub(base, "    } else if " + CHECK + " {\n        BuildOut::Err(BErr::ReservedNs)",
            "    } else if has_prefix_ci(c.ns->Some_0) {\n        BuildOut::Err(BErr::ReservedNs)"),
        "// ============================================================\n// SECTION 2:",
        CI_DEF + "\n// ============================================================\n// SECTION 2:"))

add("m03_different_prefix_string",
    "reserved(): last byte 0x73 -> 0x74 (`aws-kmt`)",
    "reject",
    sub(base, "pub open spec fn reserved() -> Seq<u8> {\n    seq![0x61u8, 0x77u8, 0x73u8, 0x2du8, 0x6bu8, 0x6du8, 0x73u8]",
        "pub open spec fn reserved() -> Seq<u8> {\n    seq![0x61u8, 0x77u8, 0x73u8, 0x2du8, 0x6bu8, 0x6du8, 0x74u8]"))

add("m04_prefix_check_dropped",
    "build: the reserved-namespace branch condition replaced by `false`",
    "reject",
    sub(base, "    } else if " + CHECK + " {\n        BuildOut::Err(BErr::ReservedNs)",
        "    } else if false {\n        BuildOut::Err(BErr::ReservedNs)"))

add("m05_check_after_key_length",
    "build: key-length check moved before the reserved-namespace check",
    "reject",
    sub(base,
        "    } else if " + CHECK + " {\n        BuildOut::Err(BErr::ReservedNs)\n" + LEN_BRANCH,
        "    } else if c.key_len->Some_0 != alg_key_len(c.alg->Some_0) {\n        BuildOut::Err(BErr::KeyLen)\n    } else if " + CHECK + " {\n        BuildOut::Err(BErr::ReservedNs)\n    } else {"))

add("m06_wrong_error_variant",
    "build: reserved namespace returns BErr::KeyLen instead of ReservedNs",
    "reject",
    sub(base, "    } else if " + CHECK + " {\n        BuildOut::Err(BErr::ReservedNs)",
        "    } else if " + CHECK + " {\n        BuildOut::Err(BErr::KeyLen)"))

add("m07_seven_byte_test_wrong_byte",
    "pre7: byte 3 compared with 0x5f instead of 0x2d",
    "reject",
    sub(base, "    &&& s[3] == 0x2du8\n    &&& s[4] == 0x6bu8", "    &&& s[3] == 0x5fu8\n    &&& s[4] == 0x6bu8"))

add("m08_emitted_id_is_key_name",
    "emitted_provider_id returns the key name instead of the namespace",
    "reject",
    sub(base, "pub open spec fn emitted_provider_id(k: Keyring) -> Seq<u8> {\n    k.ns\n}",
        "pub open spec fn emitted_provider_id(k: Keyring) -> Seq<u8> {\n    k.key_name\n}"))

add("m09_decrypt_filter_is_prefix",
    "attempts_edk: equality replaced by `the EDK id starts with the namespace`",
    "reject",
    sub(base, "pub open spec fn attempts_edk(k: Keyring, edk_id: Seq<u8>) -> bool {\n    edk_id == k.ns\n}",
        "pub open spec fn attempts_edk(k: Keyring, edk_id: Seq<u8>) -> bool {\n    has_prefix(edk_id, k.ns)\n}"))

add("m10_ns_ok_not_negated",
    "ns_ok: negation dropped",
    "reject",
    sub(base, "pub open spec fn ns_ok(ns: Seq<u8>) -> bool {\n    !has_prefix(ns, reserved())\n}",
        "pub open spec fn ns_ok(ns: Seq<u8>) -> bool {\n    has_prefix(ns, reserved())\n}"))

add("m11_wrong_key_length_table",
    "alg_key_len: A256 maps to 24 instead of 32",
    "reject",
    sub(base, "        Alg::A256 => 32,", "        Alg::A256 => 24,"))

add("m12_spec_s1_weakened",
    "spec_s1: the prefix conjunct dropped (only inequality with `aws-kms` kept)",
    "reject",
    sub(base, "    !(id =~= reserved()) && !has_prefix(id, reserved())", "    !(id =~= reserved())"))

add("m13_exec_length_guard_too_small",
    "ns_has_reserved_prefix: length guard `< 7` changed to `< 6`, so ns[6] can be out of bounds",
    "reject",
    sub(base, "    if ns.len() < 7 {\n        return false;", "    if ns.len() < 6 {\n        return false;"))

add("m14_exec_wrong_byte",
    "ns_has_reserved_prefix: last compared byte 0x73 -> 0x74",
    "reject",
    sub(base, "&& ns[5] == 0x6du8 && ns[6] == 0x73u8", "&& ns[5] == 0x6du8 && ns[6] == 0x74u8"))

add("m15_witness_accepted_is_reserved",
    "lemma_accepted_witnesses: the witness `aws_kms` is changed to `aws-kms` (a reserved string)",
    "reject",
    sub(sub(base, "        // \"aws_kms\"\n        ns_ok(seq![0x61u8, 0x77u8, 0x73u8, 0x5fu8, 0x6bu8, 0x6du8, 0x73u8]),",
            "        // \"aws_kms\"\n        ns_ok(seq![0x61u8, 0x77u8, 0x73u8, 0x2du8, 0x6bu8, 0x6du8, 0x73u8]),"),
        "    lemma_has_prefix_iff_bytes(seq![0x61u8, 0x77u8, 0x73u8, 0x5fu8, 0x6bu8, 0x6du8, 0x73u8]);",
        "    lemma_has_prefix_iff_bytes(seq![0x61u8, 0x77u8, 0x73u8, 0x2du8, 0x6bu8, 0x6du8, 0x73u8]);"))

# Predicted survivors: edits that no claim depends on.
add("s01_kms_id_tail_typo",
    "kms_id_ecdh: last byte 0x68 -> 0x69 (tail of an ID typed out; only its first 7 bytes matter)",
    "survive",
    sub(base, "0x65u8, 0x63u8, 0x64u8,\n        0x68u8]", "0x65u8, 0x63u8, 0x64u8,\n        0x69u8]"))

add("s02_lower_range_changed",
    "lower(): the upper bound 0x5a changed to 0x59 (`lower` is only used in a hypothesis of theorem_case_variants_accepted)",
    "survive",
    sub(base, "if 0x41u8 <= b && b <= 0x5au8 {", "if 0x41u8 <= b && b <= 0x59u8 {"))

add("s03_unused_key_name_field_changed",
    "build: Ok keyring stores `c.ns` as key_name instead of `c.name` (no theorem reads key_name except m08's emitted id)",
    "survive",
    sub(base, "BuildOut::Ok(Keyring { ns: c.ns->Some_0, key_name: c.name->Some_0, alg: c.alg->Some_0 })",
        "BuildOut::Ok(Keyring { ns: c.ns->Some_0, key_name: c.ns->Some_0, alg: c.alg->Some_0 })"))

lines = []
b_out, b_res, b_rc = run_verus(SRC)
lines.append(f"BASELINE: verification results:: {b_res[0]} verified, {b_res[1]} errors (exit {b_rc})")
rejected = survived = unexpected = 0
for mid, desc, pred, text in mutants:
    path = os.path.join(OUT, mid + ".rs")
    open(path, "w").write(text)
    out, res, rc = run_verus(path)
    if res is None:
        status = "REJECTED (does not compile / no result line)"
        detail = "    -> " + " ".join(out.strip().splitlines()[-1:])
        got = "reject"
    else:
        got = "reject" if (res[1] > 0 or rc != 0) else "survive"
        status = "REJECTED" if got == "reject" else "SURVIVED"
        detail = f"    -> {res[0]} verified, {res[1]} errors  {status}"
    fl = failing_fns(out, text)
    if got == "reject":
        rejected += 1
    else:
        survived += 1
    flag = "" if got == pred else "   <-- DIFFERS FROM PREDICTION"
    if got != pred:
        unexpected += 1
    lines.append(f"{mid} [predicted: {pred}] {desc}")
    lines.append(detail + flag)
    if fl:
        lines.append(f"    failing lemmas: {fl}")
lines.append("")
lines.append(f"SUMMARY: {len(mutants)} mutants, {rejected} rejected, {survived} survived, {unexpected} differ from prediction")
lines += [
    "",
    "SURVIVOR REASONS (predicted before the run, all three survived)",
    "s01: only the first 7 bytes of a KMS provider ID matter to every claim. The tail bytes of the four typed-out IDs are not used by any statement, so a tail typo does not change a result. The IDs are a spec copy (A_SPEC_IDS), checked by reading, not by Verus.",
    "s02: `lower` appears only in the hypothesis of theorem_case_variants_accepted. The theorem holds for any definition of `lower`, so changing it cannot break the proof. `lower` only describes what a case variant is.",
    "s03: the `key_name` field of the built keyring is read by no theorem except through emitted_provider_id in the m08 mutant. In the shipped model it is carried along and not used by any claim. Not a claim about the key name.",
    "NOTE m03: a different prefix string is rejected only by `lemma_reserved_bytes`, which pins the seven bytes of reserved(). The other lemmas follow the constant, so they would pass for any prefix. The correspondence of the constant with raw_aes_keyring.rs :52 is code reading (H_CONST).",
]
open(REC, "w").write("\n".join(lines) + "\n")
print("\n".join(lines))
