# T05 working notes: KBKDF fixed-info in `branch_key_wrap::derive_branch_key`

Target: VR-2026-T05 (score 4.32, TM-MPL-014). Repo `esdk-native-mpl`, branch `MPL-Verus`, HEAD `35f24c9`.
Proof: `esdk-native-mpl/verus-proofs/t05_kbkdf_fixed_info.rs`. Log: `.agents/tasks/verus-proofs-t03-t05/logs/t05_kbkdf_fixed_info.log`.

## Result

**Status: Proved, at model level, under the hypothesis A_KDF (the primitive's contract).**

Verus 0.2026.07.12.0b42f4c, exit 0, the whole log is one line:

```
verification results:: 33 verified, 0 errors
```

"Proved" has the same meaning as in `verus-proofs/README.md`: `0 errors` in the log; no `assume`, `admit`, `external_body`, `external`, `assume_specification` or `#[verifier...]` in the file (grep outside comments: no hits); every external assumption is listed in the file header. It does not mean the shipped code is verified. The proof is about a re-typed model.

## What is proved (proof-file line numbers)

| Name | Line | Statement |
|---|---|---|
| `lemma_constants` | 335 | 60 = 16+12+16+16; label has 17 bytes |
| `lemma_l_is_bits_of_output` | 344 | `be32(256) == [0,0,1,0]`; `256 == 8 * DERIVED_KEY_LEN` |
| `lemma_be32_value` | 354 | the 4 bytes of `be32(x)` read back to `x` (big-endian check, independent of the shifts in the exec model) |
| `lemma_fixed_info_is_nist_shape` | 384 | `fixed_info(salt) == label \|\| 0x00 \|\| salt \|\| be32(8*32)`, the shape of the prim KAT helper `build_fixed_info` |
| `theorem_fixed_info_layout` | 393 | for a 16-byte salt: info length is 38; `[0,17)` label, `[17]` = 0x00, `[18,34)` salt, `[34,38)` = 00 00 01 00 |
| `theorem_fixed_info_salt_injective` | 418 | equal info strings imply equal 16-byte salts |
| `trait Prim` (contract, TCB) | 443 | stands for `prim::kbkdf_ctr_hmac`; see assumptions |
| `u32_to_be_bytes` | 457 | model of `u32::to_be_bytes`, proved equal to the arithmetic `be32` |
| `derive_branch_key` | 485 | on Ok the key is `kbkdf_spec(Sha256, branch_key, fixed_info(salt), 32)`; every Err has kind Cryptographic |
| `array16_from_slice` | 537 | models `try_into().expect()`; requires a 16-byte slice |
| `wrap_kdf_leg` | 566 | wrap steps 1-3 plus the `salt\|\|iv\|\|version` prefix: same derivation, KDF salt = bytes 0..16 of the output, prefix is 44 bytes |
| `unwrap_kdf_leg` | 605 | `len < 60` gives Err before the primitive; `len >= 60` makes every slice/`expect` in-bounds (Verus-checked); KDF salt = `ct[0..16]` |
| `theorem_wrap_unwrap_same_kdf_input` | 651 | for any layout built from 16/12/16/ek/16: length is `60 + len(ek)`, unwrap's salt equals wrap's salt, same info, same `derived_key_spec` |
| `witness_fixed_info_concrete` | 685 | explicit 38-byte string for salt 00..0f |
| `witness_distinct_salts_distinct_info` | 706 | T2 is not vacuous |
| `witness_length_gate_boundary` | 722 | weak: only restates 60 and the 59 < 60 boundary |

### The four parts of the requested property

1. **Fixed-info = `label || 0x00 || salt || be32(256)`, fixed total length.** `theorem_fixed_info_layout`, and the exec model `derive_branch_key` builds exactly `fixed_info(salt)` with the same five calls as the shipped code (the `proof` block and `assert(info@ =~= fixed_info(salt@))` in `derive_branch_key`, proof file `:498-512`). Length 38 = 17+1+16+4. be32(256) = 00 00 01 00.
2. **Output length exactly 32.** `okm` is a `[u8; 32]`, the contract term is `kbkdf_spec(.., 32)`, and `256 = 8 * 32` (`lemma_l_is_bits_of_output`). Note the code writes the literal `256` at `:131`; nothing in the code ties it to `DERIVED_KEY_LEN`. The proof ties them for today's values. If `DERIVED_KEY_LEN` changes and `256` does not, the proof model (which copies the literal) would stay green. The coupling is a review item, not machine-enforced.
3. **(key, info) in the right order to the primitive.** The Ok-postcondition of `derive_branch_key` states `kbkdf_spec(Sha256, branch_key, fixed_info(salt), 32)`. Verus can only accept this because the call passes `branch_key` as `ikm` and `info` as `info`, in the parameter order of `Prim::kbkdf_ctr_hmac(alg, ikm, info, okm)`. That order equals the shipped signature (`prim/src/lib.rs:313-318`); that equality is a correspondence-table item (human), not machine-checked.
4. **Error and length behavior.**
   * Wrong-length salt or branch key: unrepresentable. `derive_branch_key` takes `&[u8;32]` and `&[u8;16]` (`:122-125`); `materials.branch_key()` returns `&[u8;32]` (`branch_key_materials.rs:32`). A wrong-length plaintext branch key is rejected earlier, by T02's `BadKeyLength` check in record reconstruction (`record.rs`), before any `BranchKeyMaterials` exists.
   * In unwrap, the salt comes from `ct[0..16]` after the `len >= 60` gate (`:236`). `unwrap_kdf_leg` shows the three slices and the `try_into().expect()` at `:247-256` cannot fail or panic when `len >= 60`, and that `body_offset (44) <= encrypted_key_end (len-16)`.
   * The only error of `derive_branch_key` is the primitive's error, mapped to `Kind::Cryptographic` (`:136-142`). `theorem` (in the ensures): every Err has kind Cryptographic. Whether the primitive can actually fail for a Sha256 request with a 32-byte okm is not decided: the model lets it fail arbitrarily. The documented zero-length-okm rejection (`prim/src/lib.rs:312-313`, test `test_kbkdf_ctr_hmac_empty_okm`) cannot apply because okm is 32 bytes.
   * `unwrap`, `len < 60`: Err of kind Cryptographic, and the primitive is never called (model `unwrap_kdf_leg`: `ct.len() < 60 ==> r is Err`).

## Spec-derived vs code-derived

Spec text: `spec/framework/aws-kms/aws-kms-hierarchical-keyring.md`, "Branch Key Wrapping" (`:206-222`), "Branch Key Unwrapping" (`:301-320`), "Ciphertext" (`:108-136`). There is no Appendix text on the derivation: Appendix A is the cache entry identifier, Appendix B is rotation limits.

* **Spec-derived:** HMAC SHA 256 KDF in Counter Mode; 32 byte derived key; branch key is the KDF key; 16 byte salt; label is UTF-8 "aws-kms-hierarchy"; wrap and unwrap use the same derivation; layout `salt(16) IV(12) version(16) encrypted key tag(16)`.
* **Code-derived, not in the spec:** the single `0x00` separator; the salt in the NIST *Context* position; `L = be32(256)` appended, in bits; total 38 bytes; that the primitive does not add `L` itself. The spec says only "Use the `salt` as the salt" and "as the label".
* Support for the code-derived layout outside this proof: `prim/tests/test_kbkdf_ctr_hmac.rs` vectors C.1-C.5 are ported from Dafny `TestKDF_TestVectors.dfy`, use label `aws-kms-hierarchy` (`:35`), Sha256, L=32 and the helper `build_fixed_info` (`:316-326`) = `label || 0x00 || context || be32(8*len)`; the test doc (`:21-27`) says this is how the Hierarchical Keyring assembles it. `lemma_fixed_info_is_nist_shape` shows the modeled info equals that helper's shape. That is evidence about the primitive with test-local inputs. No test checks the output of `derive_branch_key` or a wrap ciphertext against a Dafny/Java vector (grep of `mpl/tests`: no such vector; the YAML `coverage_evidence` says the same).

## Assumptions / TCB

* **A_KDF.** `kbkdf_spec` is an `uninterp spec fn` (no definition, no axiom). The trait `Prim` is a hypothesis on any implementation: on Ok, `okm == kbkdf_spec(alg, ikm, info, okm.len())`; the output length is kept. No HMAC/PRF property is used. There is no implementation of `Prim` in the file, so satisfiability is by absence of axioms, not by a witness.
* **A_STD.** `u32::to_be_bytes` is big-endian; `<[u8;N]>::try_from(&[u8])` fails iff len != N.
* **A_VSTD.** vstd specs for `Vec::{with_capacity, push, extend_from_slice}`, `Range` slicing, arrays; Verus; Z3.
* **A_LBL.** The 17 label bytes and the six numeric constants were transcribed by hand. A script compared them to `branch_key_wrap.rs`: label equal (17 bytes), `SALT_LEN`, `IV_LEN`, `VERSION_LEN`, `TAG_LEN`, `DERIVED_KEY_LEN` and the literal 256 equal.
* **A_TYP.** Fixed-size array types give the lengths. A `&mut [u8]` keeps its length (written in the `Prim` contract).
* Correspondence table in the file header: human review only.

## Model-vs-code gap

Model: `derive_branch_key<P: Prim>(&[u8;32], &[u8;16]) -> Result<[u8;32], Error>` with a local `Error {kind}`, no `Zeroizing`, `u32_to_be_bytes` re-implemented, label spelled as decimal ASCII, `&ct[end..ct.len()]` instead of `&ct[end..]`. Code: `Zeroizing<[u8;32]>`, `Error::with_cause`, `to_be_bytes`, `b"..."`. To close the gap: move the function into `verus!` or `cargo verus` on the crate; `assume_specification` for `to_be_bytes`, `Zeroizing`, `Error::with_cause`; an `external_type_specification`/`assume_specification` for `prim::kbkdf_ctr_hmac` with the contract of `Prim` (that is where the aws-lc-rs TCB would be stated). Nothing detects a later edit to `branch_key_wrap.rs`.

## Not covered

KBKDF output and PRF/HMAC security; aws-lc-rs correctness; interop with other implementations beyond the KAT evidence above; the RNG (T04); AES-GCM and the AAD (`compute_aad`, version UUID parse); zeroization; error message text; whether the primitive can fail on valid input; timing.

## Model checks (non-vacuity)

I broke the model in scratch copies under `/tmp/t05` (not in the repo). Each mutation made Verus report an error:

| Mutation | Result | Failing check |
|---|---|---|
| M1 swap `ikm` and `info` in the primitive call | 1 error | assertion in `derive_branch_key` (`kbkdf_spec` terms differ) |
| M2 `Sha256` -> `Sha384` in the call | 1 error | same assertion |
| M3 drop `info.push(0x00)` | 1 error | `info@ == fixed_info(salt@)` |
| M4 separator 0x01 | 1 error | same |
| M5 `OUTPUT_LEN_BITS` 256 -> 128 | 1 error | `lemma_l_is_bits_of_output` |
| M6 salt before label | 1 error | `info@ == fixed_info(salt@)` |
| M7 unwrap salt from `ct[1..17]` | 1 error | `salt@ == unwrap_salt(ct@)` |
| M8 unwrap length gate 59 instead of 60 | 2 errors | postcondition and slicing precondition |
| M9 label last byte `y` -> `x` | 1 error | witness (`witness_fixed_info_concrete`) |
| M10 wrap prefix `iv` before `salt` | 1 error | prefix assertion |
| M11 pass a constant salt to the KDF instead of the written one | 1 error | postcondition of `wrap_kdf_leg` |

(An earlier M2 run reported green because the textual replace hit a comment, not the call. I redid it with an anchored pattern, the row above.) These checks cover edits to the model only; they say nothing about edits to the code.

## Findings

* **F1 (spec gap, interop-relevant).** The spec does not state the KBKDF fixed-info layout. "Use the salt as the salt" has no meaning in SP 800-108 (the KDF has no salt input). The `0x00` separator, the salt-as-Context placement and the `L = 256` suffix exist only in code (`:126-132`) and in the prim test helper. The proof states the property against the code. A reader implementing from the spec alone could not reproduce the derived key. Suggest the spec add the explicit byte layout (label || 0x00 || salt || 0x00000100). Not a code defect.
* **F2 (observation).** The literal `256` at `branch_key_wrap.rs:131` is not derived from `DERIVED_KEY_LEN`. They agree today (`lemma_l_is_bits_of_output`). Not a defect.
* **F3 (observation).** No test compares `derive_branch_key` or a wrap ciphertext to a known-answer value. The primitive-level KATs use a test-local copy of the layout. So layout drift inside `derive_branch_key` would not be caught by any existing test (confirms the YAML `coverage_evidence`). This proof closes that gap only at model level.
* **F4 (YAML check).** The YAML anchors match HEAD: `derive_branch_key` at `:122`, return type `:125`, buffer `:135`, `kbkdf_ctr_hmac` call `:136`; 38 bytes confirmed; "wrap and unwrap reach the KDF only through this function" confirmed (`:175`, `:265`; sole call to `kbkdf_ctr_hmac` in `mpl/src` is `:136`). One YAML detail to adjust: the formal_spec writes `ghost_info`/`ghost_alg` ghost outputs, which is not how this proof states it. It states the primitive's arguments through the contract term `kbkdf_spec(Sha256, bk, info, 32)`.
* No defect found in the target function. The spec-faithful property that can be stated from the spec text alone (S1-S7) holds in the model; the layout properties (C1-C3) hold against the code.

## Honesty record

* One failed first attempt: a spec using `x as u8` on a value > 255 (`be32`) did not simplify (`clip`), so the first draft of `be32` was rejected. I changed the spec to arithmetic (`/` and `%`) and proved the shift/mask exec model equal to it by `bit_vector`. Nothing was weakened.
* No obligation was left failing; no lemma is a weakened form of another.
* `witness_length_gate_boundary` is a weak sanity statement; I did not count it as evidence.
