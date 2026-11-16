#!/usr/bin/env python3
"""Add proof status to the three targets docs (merged, 01, 02): YAML field, table column, sections."""
import os, re
ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))
QUAL = "model level, not the shipped code, under stated hypotheses"
PS = {
    "T02": f"Partly proved ({QUAL}): 21 verified, 1 errors",
    "C01": f"Proved ({QUAL}): 40 verified, 0 errors",
    "C02": f"Proved ({QUAL}): 21 verified, 0 errors",
    "T03": f"Proved ({QUAL}): 39 verified, 0 errors",
    "T05": f"Proved ({QUAL}): 33 verified, 0 errors",
}
FILE = {
    "T02": "verus-proofs/t02_record_reconstruction.rs",
    "C01": "verus-proofs/c01_ec_roundtrip.rs",
    "C02": "verus-proofs/c02_sign_fixed_len.rs",
    "T03": "verus-proofs/t03_resolve_pinned_arn.rs",
    "T05": "verus-proofs/t05_kbkdf_fixed_info.rs",
}
NONE = "None yet"
RET = "None (retired)"

def yaml_edit(text):
    def blk(m):
        b = m.group(1)
        idm = re.search(r"\bid:\s*VR-2026-([TC]\d+)", b)
        if not idm:
            return m.group(0)
        tid = idm.group(1)
        if "proof_status:" in b:
            return m.group(0)
        if tid in PS:
            add = f'  proof_status: "{PS[tid]}"\n  proof_file: {FILE[tid]}\n'
        elif re.search(r"\n  status: Retired", b):
            add = f'  proof_status: "{RET}"\n'
        else:
            add = f'  proof_status: "{NONE}"\n'
        if re.search(r"\n  dependencies:", b):
            b = re.sub(r"(\n)(  dependencies:)", lambda mm: "\n" + add + mm.group(2), b, count=1)
        else:
            b = b.rstrip("\n") + "\n" + add
        return "```yaml\n" + b + "```"
    return re.sub(r"```yaml\n(.*?)```", blk, text, flags=re.S)

def table_edit(text, header_prefix, id_re):
    """Append a 'Proof status' column to the ranked table whose header row starts with header_prefix."""
    lines = text.split("\n")
    out = []
    i = 0
    while i < len(lines):
        l = lines[i]
        if l.startswith(header_prefix) and "Proof status" not in l:
            out.append(l + " Proof status |")
            i += 1
            out.append(lines[i] + "---|")  # separator
            i += 1
            while i < len(lines) and lines[i].startswith("|"):
                row = lines[i]
                m = re.search(id_re, row)
                tid = m.group(1) if m else None
                if "Retired" in "".join(row.split("|")[1:5]):
                    ps = RET
                else:
                    ps = PS.get(tid, NONE)
                out.append(row + f" {ps} |")
                i += 1
            continue
        out.append(l)
        i += 1
    return "\n".join(out)

SCORE_RULE = ("Scores, ranks, coverage gaps, feasibility, severity and the quick-wins list in this document record the "
              "pre-proof prioritization and were not changed by these proofs. A model-level proof is not a proof of the shipped code, "
              "and re-scoring would be arbitrary. Coverage gaps will be recalculated when a proof is linked to the shipped code "
              "(for example with `cargo verus` on the crate, or by moving the logic into `verus!`).")

INTRO = ("{SCOPE}Five targets have a Verus proof in `verus-proofs/` (HEAD `d288750`; run again with `~/verus/verus verus-proofs/<file>.rs` from the repo root, Verus 0.2026.07.12.0b42f4c). "
         "Each is a proof about a hand-written, re-typed model of the shipped Rust. None verifies the shipped code: the code is not inside `verus!`, is not compiled by Verus, "
         "and nothing detects a later edit to `mpl/` or `prim/`. The link between model and code is a correspondence table in each file header, reviewed by a human. "
         "Read every status as: the logic of the model is machine-checked; the model's fidelity to the code is audited, not checked. "
         "Sources: `verus-proofs/README.md` (T02, C01, C02) and `verus-proofs/README-t03-t05.md` (T03, T05).")

ROWS = {
    "T02": ("T02", "[`t02_record_reconstruction.rs`](../verus-proofs/t02_record_reconstruction.rs)", "`verification results:: 21 verified, 1 errors`",
            "Partly proved. The one error is the intentional G1 obligation `lemma_g1_spec_soundness_FAILS`.",
            "Verus, Z3, vstd `Seq`/`Map`/`Set` axioms; A_STR (`String` is `Seq<char>`); nine hand-copied string constants."),
    "C01": ("C01", "[`c01_ec_roundtrip.rs`](../verus-proofs/c01_ec_roundtrip.rs)", "`verification results:: 40 verified, 0 errors`",
            "Proved.",
            "A_ITER (`custom.iter()` yields each key once; precondition of every builder theorem); A_STR; A_BLD; A_DDB and A_NAME for the `theorem_prod_*` results; T02 model copied into the file."),
    "C02": ("C02", "[`c02_sign_fixed_len.rs`](../verus-proofs/c02_sign_fixed_len.rs)", "`verification results:: 21 verified, 0 errors`",
            "Proved.",
            "vstd `assume_specification` for `copy_from_slice` (A1); abstract signing closure (A3); `Backend` trait without contracts stands for aws-lc-rs (A4); ghost call log checked by hand (A5)."),
    "T03": ("T03", "[`t03_resolve_pinned_arn.rs`](../verus-proofs/t03_resolve_pinned_arn.rs)", "`verification results:: 39 verified, 0 errors`",
            "Proved. Discovery and MrDiscovery arms are out of scope (BUG-04, T17).",
            "H_ORACLE, H_BUILD, H_CALLER, A_STR, A_MR."),
    "T05": ("T05", "[`t05_kbkdf_fixed_info.rs`](../verus-proofs/t05_kbkdf_fixed_info.rs)", "`verification results:: 33 verified, 0 errors`",
            "Proved. The KBKDF output is uninterpreted, so this shows which arguments the primitive receives, not that the derived key is correct.",
            "A_KDF (uninterpreted `kbkdf_spec`), A_STD, A_LBL."),
}
STATUS_NOTE = {
    "T02": PS["T02"], "C01": PS["C01"], "C02": PS["C02"], "T03": PS["T03"], "T05": PS["T05"],
}
FIND = {
    "G1": "**G1 confirmed formally (T02).** The code accepts a branch-key record that lacks `create-time` and `hierarchy-version`: the outcome is identical with or without them (`lemma_g1_code_ignores_fields`, `lemma_g1_witness_accepted_without_fields`), and the spec property fails as `lemma_g1_spec_soundness_FAILS`. The code is more permissive than the spec, never stricter (`lemma_g1_spec_completeness`).",
    "O1": "**O1, DEV-ALIAS (T03).** Two byte-identical alias ARNs fail the code's MRK match, where the spec text matches. This is a documented deviation, stricter than the spec, and unreachable for any configuration `build()` accepts (H_BUILD).",
    "O2": "**O2 (T03).** The model of ARN validity accepts an ARN with empty partition, region and account, which is looser than the spec. It does not affect the T03 property (the KMS `KeyId` is the configured ARN either way). It is a conformance gap in config validation.",
    "F1": "**F1 (T05).** The spec does not state the KBKDF fixed-info layout `\"aws-kms-hierarchy\" || 0x00 || salt(16) || 00 00 01 00` (38 bytes, 32-byte output). This is a spec gap, not a code defect.",
    "B8": "**BUG-08 (C01).** The collision `Err` branch in `build_base` is dead if and only if A_ITER holds (a `BTreeMap` yields each key once), and live if a key repeats. Model level.",
    "C02": "**C02 assumption.** The no-partial-write claim relies on vstd's own `assume_specification` for `<[T]>::copy_from_slice`, listed in the proof's TCB.",
}

def section(which):
    ids = {"merged": ["T02", "C01", "C02", "T03", "T05"], "01": ["T02", "T03", "T05"], "02": ["C01", "C02"]}[which]
    fnd = {"merged": ["G1", "O1", "O2", "F1", "B8", "C02"], "01": ["G1", "O1", "O2", "F1"], "02": ["B8", "C02"]}[which]
    scope = {"merged": "", "01": "This file covers T02, T03 and T05; C01 and C02 are in `02-capability-driven.md`. ",
             "02": "This file covers C01 and C02; T02, T03 and T05 are in `01-threat-driven.md`. "}[which]
    s = ["## Proofs written (HEAD d288750)", "", INTRO.replace("{SCOPE}", scope), ""]
    s.append("| Target | Proof file | Result line (re-run) | Status | Assumptions |")
    s.append("|---|---|---|---|---|")
    for t in ids:
        r = ROWS[t]
        fl = r[1].replace("../verus-proofs/", "../../verus-proofs/") if which != "merged" else r[1].replace("../verus-proofs/", "../verus-proofs/")
        s.append(f"| {r[0]} | {fl} | {r[2]} | {r[3]} | {r[4]} |")
    s.append("")
    s.append("Canonical status strings (the same text is in each YAML `proof_status` field and in the `Proof status` column):")
    s.append("")
    for t in ids:
        s.append(f"- {t}: {PS[t]}")
    s.append("")
    s.append("**Scores are unchanged.** " + SCORE_RULE)
    s.append("")
    s.append("### Findings from the proofs")
    s.append("")
    for k in fnd:
        s.append(f"- {FIND[k]}")
    s.append("")
    s.append("### Next steps for the proofs")
    s.append("")
    s.append("- Link each proof to the shipped code (`cargo verus` on the crate, or move the logic into `verus!`), then recalculate its coverage gap.")
    if which in ("merged", "01"):
        s.append("- Owner decisions: enforce `create-time` and `hierarchy-version` on a read path (G1); state the KBKDF fixed-info layout in the spec (F1); decide whether config validation should reject ARNs with empty parts (O2).")
    if which in ("merged", "02"):
        s.append("- Add a CI step that runs the proof files and fails on any change to the result lines (T02 is expected to show `1 errors` until G1 is fixed).")
    s.append("")
    return "\n".join(s) + "\n"

def process(rel, which, header_prefix, id_re, marker):
    p = os.path.join(ROOT, rel)
    t = open(p).read()
    t = yaml_edit(t)
    t = table_edit(t, header_prefix, id_re)
    assert marker in t
    t = t.replace(marker, section(which) + marker, 1)
    open(p, "w").write(t)

process("docs/verification-targets.md", "merged", "| Rank | Score | Origin | Target |", r"\| [TC] \| ([TC]\d+)\b", "## 0. Methodology notes")
process("docs/verification-targets/01-threat-driven.md", "01", "| Rank | ID | Score | Origin |", r"VR-2026-([TC]\d+)", "## 0. What changed since a1e23d7 (previous refresh, kept)")
process("docs/verification-targets/02-capability-driven.md", "02", "| Rank | ID | Score | Origin |", r"VR-2026-([TC]\d+)", "## 0. What changed since a1e23d7")
