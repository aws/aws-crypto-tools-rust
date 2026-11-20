import subprocess, os, re, json, sys

SRC = "/Users/mahnush/Desktop/ESDK-Rust-Verus/MPL/esdk-native-mpl/verus-proofs/t04_branch_key_wrap.rs"
OUT = "/tmp/t04work/mut"
os.makedirs(OUT, exist_ok=True)
base = open(SRC).read()


def rep(s, a, b, count=1):
    assert s.count(a) == count, (a, s.count(a))
    return s.replace(a, b)


def m1(s):
    return rep(
        s,
        "    output.extend_from_slice(&salt);\n    output.extend_from_slice(&iv);\n",
        "    output.extend_from_slice(&iv);\n    output.extend_from_slice(&salt);\n",
    )


def m2(s):
    # one generator call reused for both: the IV is copied out of the salt draw
    i = s.index("    // 2. :169-172  iv")
    j = s.index("    let ghost log2 = rng.log@;")
    new = "    let iv = array12_from_slice(&salt[0..12]);\n"
    return s[:i] + new + s[j:]


def m3(s):
    return rep(s, "    output.extend_from_slice(&version_bytes);\n    let pre_encrypt_len", "    let pre_encrypt_len")


def m4(s):
    return rep(s, "match derive_branch_key::<P>(branch_key, &salt) {\n        Ok(d) => d,", "match derive_branch_key::<P>(branch_key, &[0u8; 16]) {\n        Ok(d) => d,")


def m5(s):
    return rep(s, "P::aes_encrypt(AesGcm::Aes256Gcm, &iv, &derived,", "P::aes_encrypt(AesGcm::Aes256Gcm, &[0u8; 12], &derived,")


def m6(s):
    return rep(s, "P::aes_encrypt(AesGcm::Aes256Gcm, &iv, &derived,", "P::aes_encrypt(AesGcm::Aes128Gcm, &iv, &derived,")


def m7(s):
    # swap the order of the two generator calls (IV first, salt second)
    s = rep(
        s,
        "    let mut salt = [0u8; 16];\n    match P::generate_random_bytes(rng, &mut salt) {",
        "    let mut salt = [0u8; 16];\n    let mut iv = [0u8; 12];\n    match P::generate_random_bytes(rng, &mut iv) {",
    )
    s = rep(
        s,
        "    let mut iv = [0u8; 12];\n    match P::generate_random_bytes(rng, &mut iv) {\n        Ok(()) => {},\n        Err(_) => {\n            proof {",
        "    match P::generate_random_bytes(rng, &mut salt) {\n        Ok(()) => {},\n        Err(_) => {\n            proof {",
    )
    return s


def m8(s):
    return rep(s, "array16_from_slice(&ct[0..SALT_LEN]);", "array16_from_slice(&ct[SALT_LEN..SALT_LEN + SALT_LEN]);")


def m9(s):
    return rep(s, "    if ct.len() < FIXED_OVERHEAD_LEN {\n        return Err(Error { kind: ErrKind::Cryptographic });\n    }\n    // :247-249", "    if ct.len() < FIXED_OVERHEAD_LEN - 1 {\n        return Err(Error { kind: ErrKind::Cryptographic });\n    }\n    // :247-249")


def m10(s):
    return rep(s, "        s1 != s2 || i1 != i2,  // H_RNG_DIFFERS (premise only)\n", "")


def m11(s):
    i = s.index("        // H_RNG_DIFFERS as an antecedent: different draws give different outputs.")
    j = s.index("r->Ok_0.0@ != r->Ok_0.1@,", i) + len("r->Ok_0.0@ != r->Ok_0.1@,")
    return s[:i] + "        r is Ok ==> r->Ok_0.0@ != r->Ok_0.1@,\n" + s[j:]


def m12(s):
    return rep(s, "pub const TAG_LEN: usize = 16;", "pub const TAG_LEN: usize = 15;")


def m13(s):
    return rep(s, "    let mut iv = [0u8; 12];\n    match P::generate_random_bytes(rng, &mut iv) {", "    let mut iv = [0u8; 16];\n    match P::generate_random_bytes(rng, &mut iv) {")


def m14(s):
    # an AES error does not abort: wrap carries on and returns the partial output
    return rep(
        s,
        "            // :207  `?` returns; `output` is dropped and never returned.\n            return Err(Error { kind: ErrKind::Cryptographic });\n",
        "",
    )


def m15(s):
    return rep(
        s,
        "    match P::generate_random_bytes(rng, &mut salt) {\n        Ok(()) => {},\n        Err(_) => {\n            return Err(Error { kind: ErrKind::Cryptographic });",
        "    match P::generate_random_bytes(rng, &mut salt) {\n        Ok(()) => {},\n        Err(_) => {\n            return Err(Error { kind: ErrKind::Other });",
    )


def m16(s):
    # the output is built from the version bytes twice: wrong layout, right length class broken
    return rep(s, "    output.extend_from_slice(&iv);\n    output.extend_from_slice(&version_bytes);\n", "    output.extend_from_slice(&iv);\n    output.extend_from_slice(&version_bytes);\n    output.extend_from_slice(&version_bytes);\n")


def ma(s):
    # wrap always returns Err right after the log-refl lemma: survives, because every ensures
    # about the draws and the layout is `r is Ok ==> ..`. (Placed as the literal first statement it
    # is rejected, but only by `log_extends(old, final)`, which needs the refl lemma.)
    return rep(s, "    let ghost log0 = rng.log@;\n    proof {\n        lemma_extends_refl(log0);\n    }\n", "    let ghost log0 = rng.log@;\n    proof {\n        lemma_extends_refl(log0);\n    }\n    return Err(Error { kind: ErrKind::Cryptographic });\n")
def mb(s):
    # zero bytes are written where the version bytes belong
    return rep(s, "    output.extend_from_slice(&version_bytes);\n    let pre_encrypt_len", "    output.extend_from_slice(&[0u8; 16]);\n    let pre_encrypt_len")
def mc(s):
    # a failing salt draw is ignored: wrap carries on with the zero-initialized salt
    return rep(s, "        Err(_) => {\n            return Err(Error { kind: ErrKind::Cryptographic });\n        },\n    }\n    let ghost log1", "        Err(_) => {},\n    }\n    let ghost log1")
MUTS = [
    ("M1", "swap salt and IV offsets in the output", m1),
    ("M2", "one generator call reused for both (IV copied from the salt draw)", m2),
    ("M3", "wrong length: version bytes left out of the output", m3),
    ("M4", "KDF fed a fixed zero salt instead of the salt draw", m4),
    ("M5", "AES call gets a fixed zero IV, output still carries the IV draw", m5),
    ("M6", "wrong algorithm: Aes128Gcm with the 32-byte derived key", m6),
    ("M7", "order of the two generator calls swapped (IV drawn first)", m7),
    ("M8", "unwrap_parse reads the salt from bytes 16..32", m8),
    ("M9", "unwrap_parse length gate off by one (59 accepted)", m9),
    ("M10", "distinctness lemma without the H_RNG_DIFFERS premise", m10),
    ("M11", "wrap_twice claims the outputs always differ (no antecedent)", m11),
    ("M12", "wrong length constant: TAG_LEN = 15", m12),
    ("M13", "wrong IV size: iv array of 16 bytes", m13),
    ("M14", "AES error does not return: wrap continues and returns the partial output", m14),
    ("M15", "RNG failure returns an Err of a different kind", m15),
    ("M16", "version bytes written twice into the output", m16),
    ("MA", "wrap always returns Err (right after the log setup)", ma),
    ("MB", "zero bytes instead of the version bytes in the output", mb),
    ("MC", "salt draw failure ignored, wrap continues", mc),
]

results = []
# baseline
open(f"{OUT}/M0_baseline.rs", "w").write(base)
p = subprocess.run(["/Users/mahnush/verus/verus", f"{OUT}/M0_baseline.rs"], capture_output=True, text=True)
results.append(("M0", "unmodified copy (control)", p.returncode, p.stdout + p.stderr))
for mid, desc, fn in MUTS:
    s = fn(base)
    assert s != base, mid
    path = f"{OUT}/{mid}.rs"
    open(path, "w").write(s)
    p = subprocess.run(["/Users/mahnush/verus/verus", path], capture_output=True, text=True)
    results.append((mid, desc, p.returncode, p.stdout + p.stderr))

json.dump(results, open(f"{OUT}/results.json", "w"))
for mid, desc, rc, out in results:
    line = [l for l in out.splitlines() if l.startswith("verification results")]
    errs = [l for l in out.splitlines() if l.startswith("error")]
    print(mid, rc, line[-1] if line else "NO RESULT LINE", "|", errs[:2])
