#!/usr/bin/env python3
"""Assemble verus-proofs/c04_pdk_length_invariant.rs from header.rs, the verbatim C05 block and body.rs.
Run from the repo root. The C05 block is cut from verus-proofs/c05_algorithm_suite_table.rs
(from `/// EsdkAlgorithmSuiteId, :69-92` to just before `/// has_asymmetric_signing`)."""
P = ".agents/tasks/mpl-four-proofs/c04-parts/"
src = open("verus-proofs/c05_algorithm_suite_table.rs").read()
a = src.index("/// EsdkAlgorithmSuiteId, :69-92. Same variant names as the code.")
b = src.index("/// has_asymmetric_signing, :318-324.")
blk = src[a:b].rstrip("\n") + "\n"
out = open(P + "header.rs").read()
out += "\nuse vstd::prelude::*;\n\nverus! {\n\n"
out += "// ============================================================\n"
out += "// SECTION 1: The suite table, COPIED from C05 (verus-proofs/c05_algorithm_suite_table.rs, A_TABLE_COPY)\n"
out += "// ============================================================\n\n"
out += blk
out += open(P + "body.rs").read()
open("verus-proofs/c04_pdk_length_invariant.rs", "w").write(out)
print("written", len(out.splitlines()), "lines")
