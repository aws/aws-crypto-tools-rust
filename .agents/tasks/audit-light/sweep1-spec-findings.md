# Sweep 1 (spec sweep): findings

Repo `esdk-native-mpl`, branch `MPL-Verus`, HEAD `4807e6a`. Light audit, documentation only. No code, audited document or commit was touched. Everything is in `.agents/tasks/audit-light/`.

## What was checked

- The 13 MPL framework specs named in the brief (all exist): `algorithm-suites`, `structures`, `commitment-policy`, `keyring-interface`, `raw-aes-keyring`, `aws-kms/aws-kms-hierarchical-keyring`, `aws-kms/aws-kms-mrk-match-for-decrypt`, `cmm-interface`, `default-cmm`, `cryptographic-materials-cache`, `local-cryptographic-materials-cache`, `storm-tracking-cryptographic-materials-cache`, `branch-key-store`. The other 23 spec files under `spec/framework/` (KMS keyring variants, multi-keyring, raw RSA/ECDH, caching CMM, required-EC CMM, key agreement, master keys, ...) have no code in `mpl/src` (already recorded as N12 in `docs/spec-security-analysis.md`) and are out of this sweep.
- Extraction: `sweep1_extract.py` splits each file into paragraph, list and table blocks and keeps every sentence or list item with MUST, MUST NOT, SHALL, SHOULD, SHOULD NOT or REQUIRED. Fenced code is skipped (none of the 13 files has a keyword inside a fence). Completeness check: for every file, the number of keyword occurrences in the unit text equals the number of keyword occurrences in the file outside code fences (ALG 51, STR 53, CPO 14, KRI 47, RAK 48, HKR 105, MRK 11, CMI 45, DCM 33, CMC 17, LCM 17, STC 34, BKS 173). MAY and RECOMMENDED are not extracted. All 32 SHOULD-only items are included, not only the security-relevant ones.
- Mapping: `sweep1_rules.txt` (hand-written, one rule per requirement range) joined by `sweep1_map.py`. The script resolves each code anchor by regex against the working tree and aborts if one does not resolve, so every `file:line` in the matrix was found by grep. It also checks that every threat and target ID named exists (TM-MPL-001..026; T01..T26 without T08; C01..C08 without C06).
- Code re-read in this sweep to judge status (not copied from the docs): `default_cmm.rs`, `raw_aes_keyring.rs`, `hierarchical_keyring.rs` (build, on_encrypt, on_decrypt), `branch_key_store.rs` (build, create_key_store, create_key, version_key, get_*), `kms_ops.rs`, `record.rs`, `key_store/encryption_context.rs`, `materials_checks.rs`, `commitment_policy.rs`, `encryption_materials.rs`, `local.rs`, `storm_tracking.rs` (build, classify_and_mark, wait_for_leader). Not re-read, status taken from the docs plus anchor existence: `branch_key_wrap.rs` internals, `cache_entry_identifier.rs`, `mrk_match.rs`, `prim`.
- Coverage test before calling anything a gap: grep of `docs/threat-model.md`, `docs/spec-security-analysis.md`, `docs/verification-targets.md` and both target files for the code symbols and the requirement wording.

## Counts

| Measure | Count |
|---|---|
| Requirement units extracted | 553 |
| RFC 2119 boilerplate sentence ("The key words ... RFC 2119"), excluded | 13 |
| **Examined** | **540** |
| **Mapped** (to a threat, a target, or both) | **429** (threat only 11, target only 120, both 298) |
| **Unmapped** (neither) | **111** |

Status of the 540 (E enforced 416, S structural 56, N not implemented in crate 32, X other layer or caller duty 13, P partial 12, U unenforced MUST 8, D documented deviation 3).

Why the 111 unmapped rows are unmapped:

| Reason | Rows | Meaning |
|---|---|---|
| LOWSEC | 53 | Implemented, fails closed or has no integrity consequence, no Verus value (client construction, user agent, CreateKeyStore provisioning, KMS call plumbing, result shapes) |
| NOCODE | 32 | No implementation by design: S3EC CBC/CTR suites, DBE policy, symmetric signing and intermediate key wrapping, legacy master-key-provider CMM, storm-tracking time units |
| DESC | 9 | Descriptive sentence, no testable property |
| GAP | 7 | One candidate gap (G1 below) |
| EXT | 4 | Caller or external-service duty |
| ESDK | 3 | Implemented in `esdk/`, not in the MPL |
| NOTPROV | 3 | Security-relevant but not Verus-provable per the decision aid (entropy quality, which KMS API is called) |

Per file (examined / mapped / unmapped): algorithm-suites 42/25/17, structures 46/36/10, commitment-policy 14/11/3, keyring-interface 34/28/6, raw-aes-keyring 38/38/0, hierarchical keyring 94/88/6, mrk-match 4/4/0, cmm-interface 36/32/4, default-cmm 25/15/10, cryptographic-materials-cache 10/9/1, local cache 10/10/0, storm-tracking cache 27/23/4, branch-key-store 160/110/50.

Threats hit by at least one spec row: 23 of 26. The three not hit (TM-MPL-019 Duvet, TM-MPL-024 C++ shim, TM-MPL-026 test servers) are not spec-derived. Targets hit: 31 of 32 active. T25 (shim) is not spec-derived.

Known items not reported as findings (per the brief): T25, T21, T26 staleness and the missing TM-MPL-025 target. Spec rows that touch them are mapped to those IDs in the matrix (STC-24 to TM-MPL-025, STC-10..12 and STC-18..28 to T21, CMC-011 and LCM-011 to T26).

## Candidate gaps

Two candidates. Neither is a missed threat. Neither changes an existing rating.

### G1: branch key record completeness MUST is not enforced for `create-time` and `hierarchy-version`

- Spec: `branch-key-store.md` L530 (GetActiveBranchKey), L552 (GetBranchKeyVersion), L573 (GetBeaconKey): "If the record does not contain the defined fields, this operation MUST fail." L677: the record "MUST include" `branch-key-id`, `type`, `version` (ACTIVE only), `enc`, `kms-arn`, `create-time`, `hierarchy-version`. Matrix rows BKS-097, 098, 106, 107, 114, 115, 152.
- Evidence: `record_from_ddb_item` (`key_store/branch_key_store.rs:1141`) requires only `enc` (binary) and checks attribute types. `branch_key_materials_from_authenticated_encryption_context` (`key_store/record.rs:95`) requires `type`, `version` (for ACTIVE) and `branch-key-id`. `decrypt_branch_key` (`key_store/kms_ops.rs:162`) requires `kms-arn`. `ATTR_CREATE_TIME` and `ATTR_HIERARCHY_VERSION` are used only by writers (`encryption_context.rs:67`, `:77`; `branch_key_store.rs:711`, `:1098`); `grep` finds no read-side check. Only one test fixture under `mpl/tests` mentions either attribute (`test_aws_kms_user_agent.rs`); no test omits them.
- Coverage check: not in the MUST index of `docs/spec-security-analysis.md` (its record row says "E (+ non-empty version)"); T02's formal spec (`01-threat-driven.md`, `is_Ok <==> ...`) lists `type`, `version`, `branch-key-id` and a 32-byte key only; TM-MPL-005 does not mention it.
- Why the impact is small: the KMS encryption context is built from every record attribute plus `tablename` (`kms_ops.rs:49`, used at `:170`). A record whose `create-time` or `hierarchy-version` was removed or added after encryption no longer matches the context KMS authenticated, so KMS Decrypt fails closed. Only a record that a non-conforming writer encrypted without those two attributes would be accepted. No key is exposed and no wrong key is selected.
- Proposed type: spec-deviation note (add a "U" row to the MUST index), plus an optional wording extension of T02 (`r.is_Ok()` also requires `create-time` and `hierarchy-version`; expected FAIL against current code until a check is added). Not a new threat, not a new target.
- Severity guess: Low (informational). Likelihood: Low (needs DDB write access and a record that still authenticates). Risk by the threat model's matrix: Low.
- Verus-provable: Yes. Same class as T02 (capability category 1a, exact Ok/Err characterization of a pure function over a map).

### G2: documentation error, the spec's FORBID default suite is `00 78`, not `00 14`

- Docs say the spec's default for `FORBID_ENCRYPT_ALLOW_DECRYPT` is `00 14`: `docs/threat-model.md:335`, `docs/spec-security-analysis.md:22`, `:274`, `:308`.
- Spec: `commitment-policy.md` L83 names `ESDK.ALG_AES_256_GCM_IV12_TAG16_NO_KDF`. `algorithm-suites.md` L203 gives that suite id `00 78`; `00 14` (L205) is the 128-bit NO_KDF suite. The code is consistent with this (`algorithm_suite.rs:148` is 128-bit `00 14`, `:178` is 256-bit `00 78`).
- Effect: none on any rating, threat or target. The deviation itself (`03 78` instead of `00 78`) is real, documented in code (`commitment_policy.rs:46-48`) and already in the threat model.
- Proposed type: documentation correction (4 locations).
- Severity guess: none (editorial). Likelihood: not applicable. Verus-provable: not applicable.

## Items judged NOT a gap

- STR-046 (branch key version "MUST be a version 4 UUID"): the wrap path requires a 36-character hyphenated UUID but accepts any UUID version (`branch_key_wrap.rs:92`); `BranchKeyMaterialsBuilder::build` accepts any non-empty string. No security property depends on the v4 nibble and the string is inside the KMS-authenticated context. Covered family: T10.
- STR-022 (signing key "MUST fit" the algorithm): length deliberately unchecked, documented in `encryption_materials.rs` (Dafny parity); a bad key fails at sign time in `prim`. The verification-key length is checked (STR-037).
- STR-044 (branch key only via GenerateDataKeyWithoutPlaintext): true in `kms_ops.rs:222`; which external API is called is not a Verus property (decision aid), and `docs/spec-security-analysis.md` already states it.
- KRI-009, KRI-011 ("MUST modify at least one behavior"): `check_encryption_transition` (`materials_checks.rs:72`) accepts a keyring that returns the materials unchanged when they already hold a PDK and an EDK. No key material is added, so no confidentiality or integrity effect. The built-in keyrings always modify. C07 already states what the transition does not constrain.
- KRI-017 and HKR-019 (cryptographically secure random bits): entropy quality is out of Verus scope (decision aid); all randomness goes through `prim::generate_random_bytes` (threat-model 9a).
- CMI-004 (`max_plaintext_length`), CMI-010, CMI-021, CMI-037 (PDK/EDK correspondence, RECK superset, not re-checked by `SharedCmm::send()`): already in `threat-model.md` (F10 and the TM-MPL-006 second-pass note, line 337) and in T09's scope note.
- HKR-032 (provider info is the resolved bkid), CPO-003/DCM-005 (FORBID default `03 78`), MRK-003 (identical alias ARNs return false): documented deviations, all fail closed or strengthen the suite.
- CMC-011, LCM-011 (no periodic eviction), STC-010..012 (only grace interval <= in-flight TTL enforced), STC-024 (waiter with no deadline): known (TM-MPL-015 residual and T26; TM-MPL-018, TM-MPL-025 and T21).
- HKR-092, HKR-093 (users align shared-cache identity inputs, never reuse a logical key store name): user duty, already the TM-MPL-009 residual.
- BKS-019..032, 061..068 (CreateKeyStore, CreateKey and its conditional `attribute_not_exists` writes): administrative provisioning; the conditional-write semantics are DynamoDB behavior, not Verus-provable. The authenticated-context builders these use are T01 and C01; the Discovery refusal is `configured_kms_key_arn` (`branch_key_store.rs:112`), described in TM-MPL-002.
- BKS-112..119 (GetBeaconKey): covered by C01 and T01 (`02-capability-driven.md:74` names `get_beacon_key :868`; `01-threat-driven.md:94` also names it). Beacon materials zeroize on drop (`beacon_key_materials.rs:222`, TM-MPL-015).
- BKS-004..010 (default KMS/DDB clients, user agent): region plumbing and request metadata; user agent is TM-MPL-020.
- ALG-004..009, ALG-017..023, STR-027..028, STR-040..041, CPO-012..014, DCM-019..026, STC-006..009: no code in the crate by design (S3EC, DBE, symmetric signing, intermediate key wrapping, legacy master keys, time units). The suite table and policy enum header comments state that only ESDK is implemented. If DBE or S3EC suites are added, ALG-017..023 become security-critical and need new targets.
- ALG-010, ALG-030..033: key derivation and signing are done in `esdk/` (Duvet-annotated there); the MPL side is C05 (table) and C02 (`prim` sign loop).
- STR-005..007, KRI-034, RAK-004..005: guidance to callers (what to put in the encryption context, where to hold the wrapping key, entropy of the wrapping key). Not checkable by the library.

## Remainder

Of the 540 examined rows, 429 map to a threat or target and 111 do not. The 111 are all accounted for above: 104 carry a reason code in the matrix (LOWSEC, NOCODE, DESC, EXT, ESDK, NOTPROV) and the notable ones are listed in the NOT-a-gap section and 7 are G1. No requirement was found that is security-relevant, Verus-provable, implemented in the crate and absent from both the threat model and the targets, apart from G1's two record fields.

Limits of this light sweep: "mapped" means the threat or target names the same code and property family. It does not mean the target's formal spec states the exact spec sentence (G1 is the example where a target covers the function but not one clause). Logic of `branch_key_wrap`, `cache_entry_identifier`, `mrk_match` and `prim` was not re-derived here.

Files: `sweep1-spec-matrix.md` (matrix, 540 rows), `sweep1-requirements.json`, `sweep1-matrix.json`, `sweep1-stats.json`, `sweep1_extract.py`, `sweep1_map.py`, `sweep1_anchors.py`, `sweep1_rules.txt`.
