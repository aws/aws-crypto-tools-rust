#!/usr/bin/env python3
"""C05: compare the hand-copied constants in the proof with their sources.

Run from the repo root:  python3 .agents/tasks/mpl-four-proofs/c05-copy-check.py [proof-file]
Reads (never writes): verus-proofs/c05_algorithm_suite_table.rs,
  mpl/src/structures/algorithm_suite.rs, spec/framework/algorithm-suites.md,
  prim/src/lib.rs, prim/src/ecdsa.rs, esdk/src/message/body/mod.rs,
  .kiro/agents/mpl-verus-header-parsing-proofs.md
Exit code 0 when every check passes. This is a script check of the copies, not a Verus proof.
"""
import re, sys

PROOF = open(sys.argv[1] if len(sys.argv) > 1 else "verus-proofs/c05_algorithm_suite_table.rs").read()
CODE = open("mpl/src/structures/algorithm_suite.rs").read()
SPEC = open("spec/framework/algorithm-suites.md").read()
PRIM = open("prim/src/lib.rs").read()
ECDSA = open("prim/src/ecdsa.rs").read()
BODY = open("esdk/src/message/body/mod.rs").read()
AGENT = open(".kiro/agents/mpl-verus-header-parsing-proofs.md").read()

fails = 0
checks = 0


def check(name, ok, detail=""):
    global fails, checks
    checks += 1
    if not ok:
        fails += 1
    print(("PASS " if ok else "FAIL ") + name + (("  " + detail) if detail and not ok else ""))


def hexint(s):
    return int(s, 16)


# ---------------------------------------------------------------- code table (Rust source)
def rust_rows(src):
    body = src[src.index("pub const fn specification(self) -> AlgorithmSuite {\n        match self {"):]
    body = body[: body.index("    /// Returns the on-wire 2-byte")]
    rows = {}
    for m in re.finditer(r"Self::(\w+) => AlgorithmSuite \{(.*?)\n            \},", body, re.S):
        name, f = m.group(1), m.group(2)
        f = re.sub(r"//.*", "", f) + "\n"

        def g(key):
            mm = re.search(r"\b" + key + r":\s*(.*?),\n", f, re.S)
            return re.sub(r"\s+", " ", mm.group(1).strip())

        idm = re.match(r"\[(0x[0-9a-fA-F]+), (0x[0-9a-fA-F]+)\]", g("id"))
        rows[name] = dict(
            id0=hexint(idm.group(1)), id1=hexint(idm.group(2)),
            enc=g("encryption_algorithm").split("::")[-1],
            mode=g("encryption_algorithm_mode").split("::")[-1],
            key_len=int(g("encryption_key_length")), iv_len=int(g("iv_length")),
            tag_len=int(g("authentication_tag_length")),
            enc_kdf=g("encryption_kdf").split("::")[-1],
            commit_kdf=g("commit_kdf"),
            asym=g("asymmetric_signature_algorithm"), sym=g("symmetric_signature_algorithm"),
            fmt=hexint(g("message_format_version")),
            data_len=int(g("algorithm_suite_data_length")),
        )
    return rows


def opt(s, enum):
    s = s.strip()
    if s == "None":
        return None
    m = re.match(r"Some\((?:\w+::)*(\w+)\)", s)
    return m.group(1)


# ---------------------------------------------------------------- code table (proof file)
def proof_rows(src):
    start = src.index("pub open spec fn code_row(s: Suite) -> CRow {")
    end = src.index("/// has_asymmetric_signing, :318-324.")
    body = src[start:end]
    rows = {}
    for m in re.finditer(r"Suite::(\w+) => CRow \{(.*?)\n        \},", body, re.S):
        name, f = m.group(1), re.sub(r"\s+", " ", m.group(2))

        def g(key):
            mm = re.search(r"\b" + key + r": (.*?)(?:, \w+: |,\s*$)", f.rstrip(", ") + ",")
            return mm.group(1).strip()

        rows[name] = dict(
            id0=hexint(g("id0")), id1=hexint(g("id1")),
            enc=g("enc").split("::")[-1], mode=g("mode").split("::")[-1],
            key_len=int(g("key_len")), iv_len=int(g("iv_len")), tag_len=int(g("tag_len")),
            enc_kdf=g("enc_kdf").split("::")[-1], commit_kdf=g("commit_kdf"),
            asym=g("asym"), sym=g("sym"), fmt=hexint(g("fmt")), data_len=int(g("data_len")),
        )
    return rows


rs = rust_rows(CODE)
pr = proof_rows(PROOF)
check("code table: 11 variants in the Rust source", len(rs) == 11, str(len(rs)))
check("code table: 11 variants in the proof", len(pr) == 11, str(len(pr)))
check("code table: same variant names", set(rs) == set(pr), str(set(rs) ^ set(pr)))
for name in sorted(rs):
    a, b = rs[name], pr.get(name)
    if b is None:
        continue
    same = True
    detail = []
    for k in ("id0", "id1", "key_len", "iv_len", "tag_len", "fmt", "data_len"):
        if a[k] != b[k]:
            same = False
            detail.append(f"{k}: rust={a[k]} proof={b[k]}")
    for k in ("enc", "mode", "enc_kdf"):
        if a[k] != b[k]:
            same = False
            detail.append(f"{k}: rust={a[k]} proof={b[k]}")
    for k in ("commit_kdf", "asym", "sym"):
        if opt(a[k], None) != opt(b[k], None):
            same = False
            detail.append(f"{k}: rust={a[k]} proof={b[k]}")
    check("code row " + name, same, "; ".join(detail))

# ALL_SUITES order against all_at
all_src = re.findall(r"EsdkAlgorithmSuiteId::(\w+),", CODE[CODE.index("const ALL_SUITES"):CODE.index("// Ties `ALL_SUITES`")])
all_proof = re.findall(r"i == \d+ \{ Suite::(\w+) \}", PROOF[PROOF.index("pub open spec fn all_at"):PROOF.index("/// R2: same id bytes")])
all_proof.append(re.search(r"else \{ Suite::(\w+) \}\n}", PROOF[PROOF.index("pub open spec fn all_at"):]).group(1))
check("ALL_SUITES order equals all_at order", all_src == all_proof, f"{all_src} vs {all_proof}")
idx_proof = re.findall(r"Suite::(\w+) => (\d+),", PROOF[PROOF.index("pub open spec fn idx"):PROOF.index("/// ALL_SUITES[i]")])
check("idx order equals ALL_SUITES order", [n for n, _ in idx_proof] == all_src and [int(i) for _, i in idx_proof] == list(range(11)))
enum_src = re.findall(r"^    Alg\w+,", CODE[CODE.index("pub enum EsdkAlgorithmSuiteId"):CODE.index("const ALL_SUITES")], re.M)
check("enum EsdkAlgorithmSuiteId has 11 variants", len(enum_src) == 11, str(len(enum_src)))
check("AlgorithmSuiteId has only the Esdk variant (H_ONLY_ESDK)",
      len(re.findall(r"^    Esdk\(", CODE[CODE.index("pub enum AlgorithmSuiteId"):CODE.index("impl AlgorithmSuiteId")], re.M)) == 1
      and CODE[CODE.index("pub enum AlgorithmSuiteId"):CODE.index("impl AlgorithmSuiteId")].count("(") == 1 + CODE[CODE.index("pub enum AlgorithmSuiteId"):CODE.index("impl AlgorithmSuiteId")].count("derive("))
check("id_bytes is specification().id", "pub const fn id_bytes(self) -> [u8; 2] {\n        self.specification().id" in CODE)
check("from_id_bytes is ALL.iter().copied().find on id_bytes",
      "Self::ALL.iter().copied().find(|id| id.id_bytes() == bytes)" in CODE)
check("verification_key_length constants 33 and 49",
      "const VERIFICATION_KEY_LEN_P256: usize = 33;" in CODE and "const VERIFICATION_KEY_LEN_P384: usize = 49;" in CODE
      and "Some(AsymmetricSignatureAlgorithm::EcdsaP256) => Some(VERIFICATION_KEY_LEN_P256)" in CODE
      and "Some(AsymmetricSignatureAlgorithm::EcdsaP384) => Some(VERIFICATION_KEY_LEN_P384)" in CODE
      and "None => None," in CODE[CODE.index("pub const fn verification_key_length"):])
check("proof c_vk_len constants 33 and 49",
      "pub open spec fn vk_len_p256() -> usize { 33 }" in PROOF and "pub open spec fn vk_len_p384() -> usize { 49 }" in PROOF)
check("key_commitment is commit_kdf.is_some()", "self.commit_kdf.is_some()" in CODE)
import os
lits = []
for root in ("mpl/src", "esdk/src", "prim/src"):
    for d, _, fs_ in os.walk(root):
        for fn in fs_:
            if fn.endswith(".rs"):
                for n, line in enumerate(open(os.path.join(d, fn)), 1):
                    if re.search(r"\bAlgorithmSuite \{", line) and not re.search(r"(->|\bfor|\bimpl|\bstruct)\s+&?AlgorithmSuite \{", line):
                        lits.append((os.path.join(d, fn), n))
check("H_TABLE_ONLY: every `AlgorithmSuite {` literal is in algorithm_suite.rs (11 of them)",
      len(lits) == 11 and all(f == "mpl/src/structures/algorithm_suite.rs" for f, _ in lits), str(lits))

# ---------------------------------------------------------------- spec tables
ESDK_NAME = {
    "AlgAes128GcmIv12Tag16NoKdf": "ALG_AES_128_GCM_IV12_TAG16_NO_KDF",
    "AlgAes192GcmIv12Tag16NoKdf": "ALG_AES_192_GCM_IV12_TAG16_NO_KDF",
    "AlgAes256GcmIv12Tag16NoKdf": "ALG_AES_256_GCM_IV12_TAG16_NO_KDF",
    "AlgAes128GcmIv12Tag16HkdfSha256": "ALG_AES_128_GCM_IV12_TAG16_HKDF_SHA256",
    "AlgAes192GcmIv12Tag16HkdfSha256": "ALG_AES_192_GCM_IV12_TAG16_HKDF_SHA256",
    "AlgAes256GcmIv12Tag16HkdfSha256": "ALG_AES_256_GCM_IV12_TAG16_HKDF_SHA256",
    "AlgAes128GcmIv12Tag16HkdfSha256EcdsaP256": "ALG_AES_128_GCM_IV12_TAG16_HKDF_SHA256_ECDSA_P256",
    "AlgAes192GcmIv12Tag16HkdfSha384EcdsaP384": "ALG_AES_192_GCM_IV12_TAG16_HKDF_SHA384_ECDSA_P384",
    "AlgAes256GcmIv12Tag16HkdfSha384EcdsaP384": "ALG_AES_256_GCM_IV12_TAG16_HKDF_SHA384_ECDSA_P384",
    "AlgAes256GcmHkdfSha512CommitKey": "ALG_AES_256_GCM_HKDF_SHA512_COMMIT_KEY",
    "AlgAes256GcmHkdfSha512CommitKeyEcdsaP384": "ALG_AES_256_GCM_HKDF_SHA512_COMMIT_KEY_ECDSA_P384",
}


def section(title):
    i = SPEC.index("## " + title + "\n")
    j = SPEC.index("\n## ", i + 3)
    return SPEC[i:j]


def table(title):
    rows = {}
    for line in section(title).splitlines():
        if line.startswith("| ") and "---" not in line and not line.startswith("| Algorithm Suite ENUM"):
            cells = [c.strip() for c in line.strip().strip("|").split("|")]
            rows[cells[0]] = cells[1:]
    return rows


t_ids = table("Supported Algorithm Suites")
t_kdf = table("Algorithm Suites Encryption Key Derivation Settings")
t_enc = table("Algorithm Suites Encryption Settings")
t_com = table("Algorithm Suites Commit Key Derivation Settings")
t_sig = table("Algorithm Suites Signature Settings")


def sproof_rows(src):
    start = src.index("pub open spec fn spec_row(s: Suite) -> SRow {")
    end = src.index("/// A_SPEC_COPY: the ids of the 7 non-ESDK rows")
    body = src[start:end]
    rows = {}
    for m in re.finditer(r"Suite::(\w+) => SRow \{(.*?)\n        \},", body, re.S):
        rows[m.group(1)] = re.sub(r"\s+", " ", m.group(2))
    return rows


sp = sproof_rows(PROOF)
check("spec rows in the proof: 11", len(sp) == 11, str(len(sp)))
HASH = {"SHA-256": "Sha256", "SHA-384": "Sha384", "SHA-512": "Sha512"}
for name, enum in sorted(ESDK_NAME.items()):
    key = "ESDK." + enum
    f = sp[name]
    ok = True
    d = []

    def has(frag):
        global ok
        if frag not in f:
            ok = False
            d.append("missing " + frag)

    sid, fmt, dl = t_ids[key]
    has("id: 0x" + sid.replace(" ", "") + ",")
    has(f"fmt_major: {int(float(fmt))},")
    if dl == "N/A":
        has("data_len: None")
    else:
        has(f"data_len: Some({int(dl)})")
    kin, alg, h, salt, kc = t_kdf[key]
    has(f"kdf_in_bits: {kin},")
    if alg == "Identity KDF":
        has("kdf: SKdf::Identity,")
    else:
        has(f"kdf: SKdf::Hkdf(SHash::{HASH[h]}),")
    has(f"key_commitment: {'true' if kc == 'True' else 'false'},")
    ealg, mode, kb, iv, tag = t_enc[key]
    has("enc: SEnc::Aes," if ealg == "AES" else "enc: ?")
    has("mode: SMode::Gcm," if mode == "GCM" else "mode: ?")
    has(f"key_bits: {kb},")
    has(f"iv_bytes: {iv},")
    has(f"tag_bytes: {tag},")
    cin, cout, calg, chash, csalt = t_com[key]
    if cin == "N/A":
        has("commit: None,")
    else:
        has(f"commit: Some(SCommit {{ in_bits: {cin}, out_bits: {cout}, hash: SHash::{HASH[chash]} }}),")
        if calg != "HKDF":
            ok = False
            d.append("commit alg not HKDF")
    asym, sym = t_sig[key]
    if asym == "Not applicable":
        has("asym: None,")
    elif asym == "ECDSA with P-256 and SHA-256":
        has("asym: Some(SSig::EcdsaP256Sha256),")
    elif asym == "ECDSA with P-384 and SHA-384":
        has("asym: Some(SSig::EcdsaP384Sha384),")
    else:
        ok = False
    has("sym_hmac_sha384: " + ("true" if sym == "HMAC with SHA-384" else "false") + ",")
    check("spec row " + name, ok, "; ".join(d))

other = {k: v for k, v in t_ids.items() if not k.startswith("ESDK.")}
other_ids = sorted(hexint(v[0].replace(" ", "")) for v in other.values())
m = re.search(r"pub open spec fn spec_other_id\(i: int\) -> int \{(.*?)\n}", PROOF, re.S)
proof_other = sorted(hexint(x) for x in re.findall(r"\{ (0x[0-9a-fA-F]+) \}", m.group(1)))
check("spec_other_id: 7 non-ESDK ids equal the spec table", other_ids == proof_other and len(other_ids) == 7, f"{other_ids} vs {proof_other}")
check("spec table has 11 ESDK rows", len([k for k in t_ids if k.startswith("ESDK.")]) == 11)
check("spec reserved text present", "The value `00 00` is reserved\nand MUST NOT be used" in SPEC
      and "Algorithm Suite ID MUST be a unique hex value across all supported algorithm suites." in SPEC)

# ---------------------------------------------------------------- shared constants in the agent file
agent_ids = {k: hexint(v) for k, v in re.findall(r"spec const (SUITE_\w+): u16 = (0x[0-9a-fA-F]+);", AGENT)}
esdk_ids = sorted(hexint(t_ids["ESDK." + e][0].replace(" ", "")) for e in ESDK_NAME.values())
check("agent shared constants: 11 ids equal the 11 ESDK spec ids", sorted(agent_ids.values()) == esdk_ids, f"{sorted(agent_ids.values())} vs {esdk_ids}")
check("agent constants by name", all(agent_ids["SUITE_" + e[4:]] == hexint(t_ids["ESDK." + e][0].replace(" ", "")) for e in ESDK_NAME.values() if "SUITE_" + e[4:] in agent_ids) and len(agent_ids) == 11)

# ---------------------------------------------------------------- prim and esdk constants
kl = PRIM[PRIM.index("pub const fn key_length"):]
kl = kl[: kl.index("\n    }\n")]
check("prim AesGcm::key_length 16, 24, 32",
      re.findall(r"Self::(Aes\d+Gcm) => (\d+),", kl) == [("Aes128Gcm", "16"), ("Aes192Gcm", "24"), ("Aes256Gcm", "32")])
check("proof prim_key_length 16, 24, 32",
      re.findall(r"PAes::(Aes\d+Gcm) => (\d+),", PROOF) == [("Aes128Gcm", "16"), ("Aes192Gcm", "24"), ("Aes256Gcm", "32")])
fs = ECDSA[ECDSA.index("pub const fn field_size"):]
fs = fs[: fs.index("\n}\n")]
check("prim field_size 33, 49",
      re.findall(r"EcdsaSignatureAlgorithm::(EcdsaP\d+) => (\d+),", fs) == [("EcdsaP256", "33"), ("EcdsaP384", "49")])
check("proof prim_field_size 33, 49",
      re.findall(r"PCurve::(EcdsaP\d+) => (\d+),", PROOF[PROOF.index("pub open spec fn prim_field_size"):PROOF.index("/// The curve size in bits")]) == [("EcdsaP256", "33"), ("EcdsaP384", "49")])
ga = BODY[BODY.index("pub(crate) fn get_alg_suite"):]
ga = ga[: ga.index("\n}\n")]
check("esdk get_alg_suite 16/24/32 -> Aes128/192/256Gcm",
      re.findall(r"(\d+) => Ok\(AesGcm::(Aes\d+Gcm)\)", ga) == [("16", "Aes128Gcm"), ("24", "Aes192Gcm"), ("32", "Aes256Gcm")])
check("proof get_alg_suite 16/24/32",
      all(s in PROOF for s in ("if key_len == 16 { Some(PAes::Aes128Gcm) }", "else if key_len == 24 { Some(PAes::Aes192Gcm) }", "else if key_len == 32 { Some(PAes::Aes256Gcm) }")))
check("default_cmm curve map P256->P256, P384->P384",
      "AsymmetricSignatureAlgorithm::EcdsaP256 => PrimEcdsaSignatureAlgorithm::EcdsaP256" in open("mpl/src/cmm/default_cmm.rs").read()
      and "AsymmetricSignatureAlgorithm::EcdsaP384 => PrimEcdsaSignatureAlgorithm::EcdsaP384" in open("mpl/src/cmm/default_cmm.rs").read())
check("esdk suites.rs curve map",
      "Some(AsymmetricSignatureAlgorithm::EcdsaP256) => Ok(EcdsaSignatureAlgorithm::EcdsaP256)" in open("esdk/src/suites.rs").read()
      and "Some(AsymmetricSignatureAlgorithm::EcdsaP384) => Ok(EcdsaSignatureAlgorithm::EcdsaP384)" in open("esdk/src/suites.rs").read())

print(f"\n{checks - fails}/{checks} checks passed")
sys.exit(1 if fails else 0)
