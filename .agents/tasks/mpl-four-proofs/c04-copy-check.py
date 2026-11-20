#!/usr/bin/env python3
"""C04: compare the hand-copied constants in the proof with their sources, and grep the code sites
that the hypotheses H_CLOSED, H_NO_MUT and H_NO_OTHER_PRODUCER rest on.
Run from the repo root:  python3 .agents/tasks/mpl-four-proofs/c04-copy-check.py [proof-file]
Reads (never writes): verus-proofs/c04_pdk_length_invariant.rs (or the argument),
  verus-proofs/c05_algorithm_suite_table.rs, mpl/src/**, prim/src/lib.rs,
  spec/framework/algorithm-suites.md
Exit code 0 when every check passes. This is a script check of copies and of grep counts, not a Verus proof.
"""
import glob, hashlib, os, re, sys

PROOF = open(sys.argv[1] if len(sys.argv) > 1 else "verus-proofs/c04_pdk_length_invariant.rs").read()
C05 = open("verus-proofs/c05_algorithm_suite_table.rs").read()
SUITE = open("mpl/src/structures/algorithm_suite.rs").read()
ENC = open("mpl/src/structures/encryption_materials.rs").read()
DEC = open("mpl/src/structures/decryption_materials.rs").read()
RAW = open("mpl/src/keyring/raw_aes_keyring.rs").read()
HIER = open("mpl/src/aws_kms/hierarchical_keyring.rs").read()
PRIM = open("prim/src/lib.rs").read()
SPEC = open("spec/framework/algorithm-suites.md").read()

fails = 0
checks = 0


def check(name, ok, detail=""):
    global fails, checks
    checks += 1
    if not ok:
        fails += 1
    print(("PASS " if ok else "FAIL ") + name + (("  " + detail) if detail and not ok else ""))


def block(src):
    a = src.index("/// EsdkAlgorithmSuiteId, :69-92. Same variant names as the code.")
    b = src.index("/// has_asymmetric_signing, :318-324.") if "/// has_asymmetric_signing, :318-324." in src else src.index("/// AlgorithmSuite::encryption_key_length, algorithm_suites.rs")
    return src[a:b].rstrip("\n") + "\n"


# ---------------------------------------------------------------- copy of the C05 block
def c04_block(src):
    a = src.index("/// EsdkAlgorithmSuiteId, :69-92. Same variant names as the code.")
    b = src.index("/// AlgorithmSuite::encryption_key_length, algorithm_suite.rs :378-380")
    return src[a:b].rstrip("\n") + "\n"


check("C05 file md5 is the one named in the C04 header",
      hashlib.md5(C05.encode()).hexdigest() == "98209a4dca774c1c6227ea394897afdc",
      hashlib.md5(C05.encode()).hexdigest())
check("C04 table block is byte-identical to the C05 block", c04_block(PROOF) == block(C05))
check("C04 header says the table was copied from C05", "COPIED FROM C05" in PROOF and "98209a4dca774c1c6227ea394897afdc" in PROOF)

# ---------------------------------------------------------------- key lengths against the Rust source
body = SUITE[SUITE.index("pub const fn specification(self) -> AlgorithmSuite {\n        match self {"):]
body = body[: body.index("    /// Returns the on-wire 2-byte")]
rust = {}
for m in re.finditer(r"Self::(\w+) => AlgorithmSuite \{(.*?)\n            \},", body, re.S):
    name, f = m.group(1), re.sub(r"//.*", "", m.group(2)) + "\n"
    kl = int(re.search(r"\bencryption_key_length:\s*(\d+),", f).group(1))
    rust[name] = kl
check("Rust source has 11 suite rows", len(rust) == 11, str(len(rust)))

proof_rows = {}
cb = c04_block(PROOF)
for m in re.finditer(r"Suite::(\w+) => CRow \{(.*?)\n        \},", cb, re.S):
    proof_rows[m.group(1)] = int(re.search(r"key_len:\s*(\d+),", m.group(2)).group(1))
check("proof has 11 code_row arms", len(proof_rows) == 11, str(len(proof_rows)))
for n in sorted(rust):
    check("key_len " + n, proof_rows.get(n) == rust[n], f"proof={proof_rows.get(n)} source={rust[n]}")

# the exec lookup in the proof has the same values
ex = PROOF[PROOF.index("fn encryption_key_length_exec"):]
ex = ex[: ex.index("\n}\n")]
exv = {m.group(1): int(m.group(2)) for m in re.finditer(r"Suite::(\w+) => (\d+),", ex)}
check("exec lookup equals the Rust key lengths", exv == rust, str(exv))

# ---------------------------------------------------------------- spec columns
def spec_cols(title, col_name):
    i = SPEC.index(title)
    lines = []
    started = False
    for l in SPEC[i:].splitlines()[1:]:
        if l.startswith("|"):
            started = True
            lines.append(l)
        elif started:
            break
    head = [c.strip() for c in lines[0].strip("|").split("|")]
    ci = head.index(col_name)
    out = {}
    for l in lines[2:]:
        cells = [c.strip() for c in l.strip("|").split("|")]
        if cells[0].startswith("ESDK."):
            out[cells[0][len("ESDK."):]] = cells[ci]
    return out


def enum_to_variant(e):
    # ALG_AES_128_GCM_IV12_TAG16_NO_KDF -> AlgAes128GcmIv12Tag16NoKdf
    return "".join(w.capitalize() for w in e.split("_"))


kb = spec_cols("## Algorithm Suites Encryption Settings", "Encryption Key Length (bits)")
kd = spec_cols("## Algorithm Suites Encryption Key Derivation Settings", "Key Derivation Input Length (bits)")
check("spec key-bits column has 11 ESDK rows", len(kb) == 11, str(len(kb)))
check("spec kdf-input column has 11 ESDK rows", len(kd) == 11, str(len(kd)))


def proof_col(fn):
    s = PROOF[PROOF.index("pub open spec fn " + fn):]
    s = s[: s.index("\n}\n")]
    return {m.group(1): int(m.group(2)) for m in re.finditer(r"Suite::(\w+) => (\d+),", s)}


pk, pd = proof_col("spec_key_bits"), proof_col("spec_kdf_in_bits")
for e, v in sorted(kb.items()):
    n = enum_to_variant(e)
    check("spec key bits " + e, pk.get(n) == int(v), f"proof={pk.get(n)} spec={v}")
for e, v in sorted(kd.items()):
    n = enum_to_variant(e)
    check("spec kdf input bits " + e, pd.get(n) == int(v), f"proof={pd.get(n)} spec={v}")

# ---------------------------------------------------------------- code sites (H_MODEL_MATCH, H_CLOSED, H_NO_MUT, H_NO_OTHER_PRODUCER)
chk = SUITE[SUITE.index("pub(crate) fn check_data_key_length("):]
chk = chk[: chk.index("\n}\n")]
check("check_data_key_length compares key.len() with suite.encryption_key_length() and returns Err on !=",
      "let expected_len = suite.encryption_key_length();" in chk and "if key.len() != expected_len {" in chk
      and "return Err(" in chk and chk.rstrip().endswith("Ok(())"))
check("encryption_key_length() returns the field",
      re.search(r"pub const fn encryption_key_length\(&self\) -> usize \{\s*self\.encryption_key_length\s*\}", SUITE) is not None)
check("check_data_key_length called 2x in encryption_materials.rs (add_data_key, build) + 1 import",
      len(re.findall(r"check_data_key_length\(", ENC)) == 2 and ENC.count("check_data_key_length,") == 1)
check("check_data_key_length called 2x in decryption_materials.rs (add_data_key, build) + 1 import",
      len(re.findall(r"check_data_key_length\(", DEC)) == 2 and DEC.count("check_data_key_length,") == 1)
callers = []
for f in glob.glob("mpl/src/**/*.rs", recursive=True) + glob.glob("esdk/src/**/*.rs", recursive=True):
    t = open(f).read()
    for m in re.finditer(r"check_data_key_length\(", t):
        callers.append(f)
check("check_data_key_length is called only from the two materials files (and defined once)",
      sorted(set(callers)) == ["mpl/src/structures/algorithm_suite.rs", "mpl/src/structures/decryption_materials.rs",
                               "mpl/src/structures/encryption_materials.rs"], str(sorted(set(callers))))
check("add_data_key (enc) order: already-has-PDK test, check, store",
      re.search(r"if self\.plaintext_data_key\.is_some\(\) \{.*?\}\s*check_data_key_length\(&self\.algorithm_suite\(\), &plaintext_data_key\)\?;\s*self\.plaintext_data_key = Some\(plaintext_data_key\);", ENC, re.S) is not None)
check("add_data_key (dec) order: already-has-PDK test, check, store",
      re.search(r"if self\.plaintext_data_key\.is_some\(\) \{.*?\}\s*check_data_key_length\(&self\.algorithm_suite\(\), &plaintext_data_key\)\?;\s*self\.plaintext_data_key = Some\(plaintext_data_key\);", DEC, re.S) is not None)
check("build (enc): check on the builder PDK with the builder suite, before the literal",
      re.search(r"if let Some\(key\) = &self\.plaintext_data_key \{\s*check_data_key_length\(&algorithm_suite_id\.specification\(\), key\)\?;", ENC) is not None)
check("build (dec): check on the builder PDK with the builder suite, before the literal",
      re.search(r"if let Some\(key\) = &self\.plaintext_data_key \{\s*check_data_key_length\(&algorithm_suite_id\.specification\(\), key\)\?;", DEC) is not None)
check("enc literal copies algorithm_suite_id and self.plaintext_data_key",
      re.search(r"Ok\(EncryptionMaterials \{\s*algorithm_suite_id,.*?plaintext_data_key: self\.plaintext_data_key,", ENC, re.S) is not None)
check("dec literal copies algorithm_suite_id and self.plaintext_data_key",
      re.search(r"Ok\(DecryptionMaterials \{\s*algorithm_suite_id,.*?plaintext_data_key: self\.plaintext_data_key,", DEC, re.S) is not None)

# writes of the plaintext_data_key field
def pdk_writes(t):
    return [l.strip() for l in t.splitlines()
            if re.search(r"self\.plaintext_data_key\s*=[^=]|^\s*plaintext_data_key:\s*(self\.|Option<PlaintextDataKey>)", l)
            and not l.strip().startswith("//")]


ew = pdk_writes(ENC)
dw = pdk_writes(DEC)
check("enc: PDK field written only by add_data_key, 2 builder setters and the build literal (+ the struct/builder field decls)",
      sorted(ew) == sorted(["plaintext_data_key: Option<PlaintextDataKey>,", "plaintext_data_key: Option<PlaintextDataKey>,",
                            "self.plaintext_data_key = Some(plaintext_data_key);", "self.plaintext_data_key = Some(plaintext_data_key.into());",
                            "self.plaintext_data_key = plaintext_data_key;", "plaintext_data_key: self.plaintext_data_key,"]), str(ew))
check("dec: PDK field written only by add_data_key, 2 builder setters and the build literal (+ the struct/builder field decls)",
      sorted(dw) == sorted(["plaintext_data_key: Option<PlaintextDataKey>,", "plaintext_data_key: Option<PlaintextDataKey>,",
                            "self.plaintext_data_key = Some(plaintext_data_key);", "self.plaintext_data_key = Some(plaintext_data_key.into());",
                            "self.plaintext_data_key = plaintext_data_key;", "plaintext_data_key: self.plaintext_data_key,"]), str(dw))
# no other file names the field in an assignment or literal
others = []
for f in glob.glob("mpl/src/**/*.rs", recursive=True):
    if f.endswith("encryption_materials.rs") or f.endswith("decryption_materials.rs"):
        continue
    t = open(f).read()
    for l in t.splitlines():
        if re.search(r"self\.plaintext_data_key\s*=[^=]|^\s*plaintext_data_key:\s*(self\.|Option<PlaintextDataKey>)", l) and not l.strip().startswith("//"):
            others.append((f, l.strip()))
check("no other file in mpl/src writes or declares a `plaintext_data_key` field", others == [], str(others))

check("both materials structs are #[non_exhaustive] with private fields",
      re.search(r"#\[non_exhaustive\]\s*pub struct EncryptionMaterials \{\s*algorithm_suite_id:", ENC) is not None
      and re.search(r"#\[non_exhaustive\]\s*pub struct DecryptionMaterials \{\s*algorithm_suite_id:", DEC) is not None)
check("materials files have no `&mut self` method", "&mut self" not in ENC.split("pub struct EncryptionMaterialsBuilder")[0]
      and "&mut self" not in DEC.split("pub struct DecryptionMaterialsBuilder")[0])
check("materials structs do not derive Default", "derive(Debug, Clone)]\n#[non_exhaustive]\npub struct EncryptionMaterials {" in ENC
      and "derive(Debug, Clone)]\n#[non_exhaustive]\npub struct DecryptionMaterials {" in DEC)
lits = []
for f in glob.glob("mpl/src/**/*.rs", recursive=True):
    for i, l in enumerate(open(f).read().splitlines(), 1):
        if re.search(r"(Ok\(|=\s*|return\s+)(En|De)cryptionMaterials \{", l) and not l.strip().startswith("//"):
            lits.append((f, i))
check("struct literals of the materials types in mpl/src: exactly the two `Ok(..Materials {` in build",
      sorted(lits) == [("mpl/src/structures/decryption_materials.rs", 349), ("mpl/src/structures/encryption_materials.rs", 427)], str(lits))

# PlaintextDataKey impl block: no &mut self method, no DerefMut
pk_start = SUITE.index("pub struct PlaintextDataKey(Vec<u8>);")
pk_end = SUITE.index("/// Signing key (secret).")
pk_text = SUITE[pk_start:pk_end]
check("PlaintextDataKey section has no `&mut self` and no DerefMut", "&mut self" not in pk_text and "DerefMut" not in SUITE)
check("PlaintextDataKey derives Clone, Zeroize, ZeroizeOnDrop only",
      "#[derive(Clone, Zeroize, ZeroizeOnDrop)]\npub struct PlaintextDataKey(Vec<u8>);" in SUITE)

# producers
news = []
for f in glob.glob("mpl/src/**/*.rs", recursive=True):
    for i, l in enumerate(open(f).read().splitlines(), 1):
        if re.search(r"PlaintextDataKey::(new|from)\(", l) and not l.strip().startswith("//"):
            news.append((f, i))
exp = {"mpl/src/keyring/raw_aes_keyring.rs": 2, "mpl/src/aws_kms/hierarchical_keyring.rs": 2}
got = {}
for f, i in news:
    got[f] = got.get(f, 0) + 1
check("PlaintextDataKey::new / ::from called only in raw_aes_keyring.rs (2) and hierarchical_keyring.rs (2) in mpl/src",
      got == exp, str(news))
check("From<Vec<u8>> for PlaintextDataKey is the only From impl", len(re.findall(r"impl From<.*?> for PlaintextDataKey", SUITE)) == 1)
check("both generators allocate vec![0u8; suite.encryption_key_length()] and fill it with a &mut Vec -> slice",
      "let mut bytes = vec![0u8; suite.encryption_key_length()];" in RAW
      and "let mut bytes = vec![0u8; suite.encryption_key_length()];" in HIER
      and "generate_random_bytes(&mut bytes)" in RAW and "generate_random_bytes(&mut bytes)" in HIER)
check("generators are called with materials.algorithm_suite()",
      "generate_random_data_key(materials.algorithm_suite())" in RAW and "generate_random_data_key(materials.algorithm_suite())" in HIER)
check("prim generate_random_bytes takes a slice `bytes: &mut [u8]`", "pub fn generate_random_bytes(bytes: &mut [u8]) -> Result<(), Error>" in PRIM)
check("raw on_decrypt: length test, then add_data_key(PlaintextDataKey::new(plaintext_dk))?",
      re.search(r"if plaintext_dk\.len\(\) != expected_dk_len \{.*?continue;\s*\}\s*let materials = materials\.add_data_key\(PlaintextDataKey::new\(plaintext_dk\)\)\?;", RAW, re.S) is not None)
check("raw on_decrypt: expected_dk_len is materials.algorithm_suite().encryption_key_length()",
      "let expected_dk_len = materials.algorithm_suite().encryption_key_length();" in RAW)
check("hier on_decrypt: Ok(bytes) goes straight to add_data_key(PlaintextDataKey::new(..))?",
      re.search(r"Ok\(plaintext_dk_bytes\) => \{\s*let materials =\s*materials\.add_data_key\(PlaintextDataKey::new\(plaintext_dk_bytes\)\)\?;", HIER) is not None)
check("hier on_encrypt: pdk.clone() when present, else generate; add_data_key only when generated",
      "Some(pdk) => (pdk.clone(), false)," in HIER and "None => (generate_random_data_key(materials.algorithm_suite())?, true)," in HIER
      and re.search(r"if generated \{\s*materials\.add_data_key\(plaintext_dk, edk\)\?\s*\} else \{\s*materials\.add_encrypted_data_key\(edk\)\?", HIER) is not None)
check("raw on_encrypt: present -> add_encrypted_data_key; absent -> generate then add_data_key",
      re.search(r"Some\(plaintext_dk\) => \{.*?materials\.add_encrypted_data_key\(edk\)\?.*?None => \{\s*let plaintext_dk = generate_random_data_key\(materials\.algorithm_suite\(\)\)\?;.*?materials\.add_data_key\(plaintext_dk, edk\)\?", RAW, re.S) is not None)

# calls of add_data_key / builder setter in mpl/src outside the materials files
adk = []
for f in glob.glob("mpl/src/**/*.rs", recursive=True):
    if f.endswith("encryption_materials.rs") or f.endswith("decryption_materials.rs"):
        continue
    for i, l in enumerate(open(f).read().splitlines(), 1):
        if re.search(r"\.add_data_key\(|\.set_plaintext_data_key\(|\.plaintext_data_key\(.*(into|Some|PlaintextDataKey)", l) and not l.strip().startswith("//"):
            adk.append((f, i))
check("add_data_key callers in mpl/src outside the materials files: raw (2) and hierarchical (2) keyrings only (+ doc comments)",
      sorted(set(f for f, i in adk)) == ["mpl/src/aws_kms/hierarchical_keyring.rs", "mpl/src/keyring/raw_aes_keyring.rs"], str(adk))

unsafe_hits = []
for f in glob.glob("mpl/src/**/*.rs", recursive=True):
    for i, l in enumerate(open(f).read().splitlines(), 1):
        if re.search(r"\bunsafe\b", l) and not l.strip().startswith("//"):
            unsafe_hits.append((f, i, l.strip()))
check("no `unsafe` code in mpl/src", unsafe_hits == [], str(unsafe_hits))

esdk_hits = []
for f in glob.glob("esdk/src/**/*.rs", recursive=True):
    t = open(f).read()
    if "PlaintextDataKey" in t or "Materials::builder" in t or ".add_data_key(" in t:
        esdk_hits.append(f)
check("esdk/src never names PlaintextDataKey and never builds materials or adds a data key", esdk_hits == [], str(esdk_hits))

# proof text sanity
code_lines = [l for l in PROOF.splitlines() if not l.strip().startswith("//")]
code_text = "\n".join(code_lines)
check("proof has no assume/admit/external_body/assume_specification/#[verifier",
      not re.search(r"\bassume\(|\badmit\(|external_body|assume_specification|#\[verifier", code_text))

print(f"\n{checks - fails} of {checks} checks pass")
sys.exit(1 if fails else 0)
