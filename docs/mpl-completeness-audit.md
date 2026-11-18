# MPL completeness audit (light)

> Branch `MPL-Verus`, HEAD `4807e6a`. Gap check of `docs/mpl-threat-model.md` (TM-MPL-001..026) and the verification targets (T01..T26 without T08, C01..C08 without C06). It is not a re-run of the pipeline. No code and no audited document was changed, and nothing was committed. Working files for all four sweeps are in `.agents/tasks/audit-light/`.
>
> Known stale items are excluded on request and not reported again: T25, T21, T26 (scope predates the second-pass sub-surfaces), and the missing target for TM-MPL-025.

## 1. Summary

**Was any threat or target missed? No threat was missed. No new verification target is needed. One small gap remains, low impact:**

- The spec MUST "a branch key record MUST include `create-time` and `hierarchy-version`" is not enforced on read and is not in T02's formal spec or the MUST index (G1). KMS authentication makes the practical impact small.

The verification-targets documents do not mention TM-MPL-026 and still count threats as 001..024. After independent verification this is treated as the already-known staleness, not a finding (see "Editorial corrections" and "Independent verification").

| Sweep | Verdict | Examined | Mapped | Unmapped | Genuine gaps |
|---|---|---|---|---|---|
| 1. Spec MUST/SHOULD requirements (13 framework specs) | One gap (G1). One editorial error in the docs (G2). | 540 requirement units (553 extracted, 13 RFC 2119 boilerplate sentences excluded) | 429 (threat only 11, target only 120, both 298) | 111, of which 104 have a recorded reason (LOWSEC 53, NOCODE 32, DESC 9, EXT 4, ESDK 3, NOTPROV 3) and 7 are G1 | 1 (G1) |
| 2. Code surface (`mpl/src`, `prim/src`, shim FFI) | Clean | 199 sites in 6 categories | 185 | 14, all judged not a gap (section 4) | 0 |
| 3. Bug reports BUG-01..09 | Clean | 11 items (05 and 07 split into a/b) | 11 to a threat, 11 to a target | 0 (BUG-05(b) to TM-MPL-025 target is the known item) | 0 |
| 4. Threat to target, target to reference | Clean apart from known items | 26 threats; 32 active targets | 24 threats (22 with a target, 2 fully excluded: 019, 020); 32 of 32 targets have a valid reference | 2 threats: TM-MPL-025 (known), TM-MPL-026 (test-only, "no target needed" at `mpl-threat-model.md:651`; targets documents not yet updated, same staleness as the known item); 0 dangling target references | 0 |

Sweep 1 also found that 23 of 26 threats are hit by at least one spec row. The three that are not (019 Duvet, 024 C++ shim, 026 test servers) are not spec-derived.

## 2. Findings table

One genuine gap. The proposed ID column says "none" because it needs no new threat or target: it is a clause added to an existing target. TM-MPL-027.., T28.. and C09.. are not needed. (The earlier draft listed a second row, G4-1, for TM-MPL-026; independent verification moved it to the editorial table because `mpl-threat-model.md:28` and `:651` already record that it needs no target.)

| Proposed ID | Type | Evidence | Why it matters | Severity (likelihood) | Verus-provable? | Recommended action |
|---|---|---|---|---|---|---|
| G1: none (extend T02's formal spec; add a "U" row to the MUST index) | Missed target (partial: one spec clause not in an existing target) | Spec: `spec/framework/branch-key-store.md:530`, `:552`, `:573` ("If the record does not contain the defined fields, this operation MUST fail") and `:677`, `:688-691` (record "MUST include" `create-time` and `hierarchy-version`). Code: `record_from_ddb_item` (`mpl/src/key_store/branch_key_store.rs:1141-1200`) requires only `enc` and checks attribute types. `branch_key_materials_from_authenticated_encryption_context` (`key_store/record.rs:95`) requires `type`, `version` (ACTIVE only), `branch-key-id` and a 32-byte key (`:164`). `decrypt_branch_key` (`key_store/kms_ops.rs:162`, `:172`) requires `kms-arn`. `grep` over `mpl/src` finds `ATTR_CREATE_TIME` and `ATTR_HIERARCHY_VERSION` only on write paths (`branch_key_store.rs:711`, `:1098`; `encryption_context.rs:67`, `:77`). No test builds a record without them. Not covered: no match in `docs/mpl-spec-security-analysis.md` (record row at `:366` says "E (+ non-empty version)"); T02's `is_Ok <==>` spec (`01-threat-driven.md:160`) lists only `type`; T01 (`:95-112`) proves round-trip, not completeness; `mpl-threat-model.md:325` (TM-MPL-005) does not mention it. | An unenforced MUST (spec deviation) is missing from the deviation index. | Low. Likelihood Low. Mitigating fact: the KMS encryption context is built from every record attribute (`kms_ops.rs:49`), so a record altered after encryption to drop or add these fields fails KMS Decrypt. Only a record from a non-conforming writer that never had the fields would be accepted. No key is exposed and no wrong key is selected. | Yes, category 1a (exact Ok/Err characterization of a pure function over a map), same class as T02. Expected FAIL against current code until a check is added. | Add the spec clause to the MUST index as "U". Optionally extend T02 so that `r.is_Ok()` also requires `create-time` and `hierarchy-version`, or state the completeness check on `record_from_ddb_item` (T01), because that function, not T02's, is where the spec says the operation "MUST fail". Not a new threat, not a new target. |

Evidence for G1 was re-read in this audit (file:line checked with `grep -n` / `sed -n`). The statement that a missing field "fails KMS Decrypt" for tampered records follows from `build_authenticated_encryption_context` taking every non-`enc` attribute; it was read, not tested against live KMS.

### Editorial corrections noted (not coverage gaps)

| ID | Where | What is wrong | Fix |
|---|---|---|---|
| G2 | `docs/mpl-threat-model.md:335`; `docs/mpl-spec-security-analysis.md:22`, `:274`, `:308` | The docs say the spec's default suite for `FORBID_ENCRYPT_ALLOW_DECRYPT` is `00 14`. `spec/framework/commitment-policy.md:83` names `ESDK.ALG_AES_256_GCM_IV12_TAG16_NO_KDF`, and `spec/framework/algorithm-suites.md:203` gives that suite id `00 78`. `00 14` (`:205`) is the 128-bit suite. Code agrees with the spec tables: `mpl/src/structures/algorithm_suite.rs:148` is `00 14` (128-bit), `:178` is `00 78` (256-bit). The deviation itself is real and documented (`03 78` at `algorithm_suite.rs:263`; `commitment_policy.rs:46-48`). | Replace `00 14` with `00 78` in the four places. No rating, threat or target changes. |
| G4-1 | `docs/mpl-verification-targets.md:4`, `docs/mpl-verification-targets/01-threat-driven.md:4`, `:1294` | The targets documents cite "TM-MPL-001..024" and do not mention TM-MPL-026 (no target, no exclusion row). `mpl-threat-model.md:28` and `:651` already state it is test-only and needs no target. Code matches the threat text (`mpl/test-server/src/main.rs:26-27` binds `127.0.0.1`, no auth). Not a coverage gap: no property is missing. | In the same refresh as the TM-MPL-025 target, add a "fully excluded" row (test-only, operational; mitigation `mpl-threat-model.md:555`) and update the "001..024" totals. |

## 3. Coverage matrices

Full matrices are in `.agents/tasks/audit-light/`: `sweep1-spec-matrix.md` (540 rows), `sweep2-code-matrix.md` (199 sites), `sweep3-bugs.md`, `sweep4-threat-target.md`. Compact views follow.

### 3a. Spec requirement to threat / target (per spec file)

Rows include the 13 boilerplate rows, so unmapped here is 124, not 111.

| Spec file (`spec/framework/`) | Rows | Mapped | Unmapped | Main threats | Main targets |
|---|---|---|---|---|---|
| algorithm-suites | 43 | 25 | 18 | 006 | C05, C07, C02, C03, C04 |
| structures | 47 | 36 | 11 | 006, 013, 015, 017, 005, 021 | C07, T12, T15, T26, C01 |
| commitment-policy | 14 | 11 | 3 | 006, 008 | T09 |
| keyring-interface | 35 | 28 | 7 | 001, 013, 017 | C07, C04, T24, T04, T20 |
| raw-aes-keyring | 40 | 38 | 2 | 011, 023, 001, 015 | T07, T20, C07, T15, T24 |
| aws-kms-hierarchical-keyring | 95 | 88 | 7 | 009, 010, 014, 012, 003, 005 | T13, T14, T04, T05, T19 |
| aws-kms-mrk-match-for-decrypt | 5 | 4 | 1 | 004 | T11 |
| cmm-interface | 37 | 32 | 5 | 006, 017 | C07, T09, T12 |
| default-cmm | 26 | 15 | 11 | 006, 008, 023 | T09, C07, T16 |
| cryptographic-materials-cache | 11 | 9 | 2 | 010, 022, 015 | T23, T14, C08 |
| local-cryptographic-materials-cache | 11 | 10 | 1 | 010, 022, 015, 023 | T23, T26 |
| storm-tracking-cryptographic-materials-cache | 28 | 23 | 5 | 018, 023, 025 (known) | T21, T06 |
| branch-key-store | 161 | 110 | 51 | 005, 002, 016, 004, 007 | T01, C01, T03, T02, T18 |

The other 23 spec files under `spec/framework/` have no code in `mpl/src` (already recorded in `docs/mpl-spec-security-analysis.md`) and were out of this sweep.

Status of the 540 examined units: enforced 416, structural 56, not implemented in the crate 32, other layer or caller duty 13, partial 12, unenforced MUST 8, documented deviation 3.

### 3b. Bug to threat / target

| Bug | Status on main | Threat | Target |
|---|---|---|---|
| BUG-01 TTL overflow panic | Open | 018, 023 | T06 |
| BUG-02 PDK length | Fixed | 006, 023 | C04 |
| BUG-03 EC decode unsorted | Fixed | 013 | T15 |
| BUG-04 MRDiscovery region rewrite | Open | 007 | T17 |
| BUG-05(a) ECDSA keygen `.expect` | Open | 023 | T16 (expected unprovable) |
| BUG-05(b) 44 to 59-byte EDK | Open (likely not a bug) | 023, 025 | T16; TM-MPL-025 target is the known item |
| BUG-06 cache id with NUL | Open | 009, 010, 003 | T13, T19 |
| BUG-07(a) `aes_encrypt` plaintext on Err | Open | 015 | T26 (known stale), T07 |
| BUG-07(b) `aes_decrypt` guard | Open | 023 | C03 |
| BUG-08 dead branch in `build_base` | Open (informational) | 005 | C01(c) |
| BUG-09 TTL admits ttl + 1 s | Fixed | 010 | T14 |

### 3c. Threat to target

| Threat | Target(s) | | Threat | Target(s) |
|---|---|---|---|---|
| TM-MPL-001 | T20, T24 | | TM-MPL-014 | T05 |
| 002 | T01, T03 | | 015 | T26 (stale, known) |
| 003 | T19 | | 016 | T18 |
| 004 | T11 | | 017 | T12, T15 |
| 005 | T01, T02 | | 018 | T06, T21 (stale, known) |
| 006 | T09 | | 019 | excluded (process, Duvet) |
| 007 | T17 | | 020 | excluded (operational) |
| 008 | T09 | | 021 | T22 |
| 009 | T13 | | 022 | T06, T23 |
| 010 | T13, T14 | | 023 | T06, T16, T20 |
| 011 | T07, T20 | | 024 | T25 (stale, known) |
| 012 | T04 | | 025 | none (known item) |
| 013 | T10, T15 | | **026** | **none; test-only, "no target needed" (`mpl-threat-model.md:651`); targets docs not updated (G4-1, editorial)** |

All 32 active targets cite threat or capability references that exist. No active target depends on retired T08 or C06.

## 4. Items examined and judged NOT a gap

Spec sweep:

- STR-046 (branch key version "MUST be a version 4 UUID"): code accepts any UUID version, but nothing depends on the v4 nibble and the string is inside the KMS-authenticated context (family T10).
- STR-022 (signing key "MUST fit" the algorithm): length deliberately unchecked (Dafny parity); a bad key fails at sign time in `prim`.
- STR-044 (branch key only via `GenerateDataKeyWithoutPlaintext`): true at `kms_ops.rs:222`; which API is called is not a Verus property.
- KRI-009, KRI-011 ("MUST modify at least one behavior"): an unchanged-materials keyring adds no key material, so no confidentiality or integrity effect; C07 states what the transition does not constrain.
- KRI-017, HKR-019 (cryptographically secure random bits): entropy quality is outside Verus; all randomness goes through `prim::generate_random_bytes`.
- CMI-004, CMI-010, CMI-021, CMI-037 (PDK/EDK correspondence, RECK superset): already in `mpl-threat-model.md` (F10, TM-MPL-006 second-pass note) and T09's scope note.
- HKR-032, CPO-003/DCM-005 (`03 78` default), MRK-003: documented deviations that fail closed or strengthen the suite.
- CMC-011, LCM-011, STC-010..012, STC-024: known items (TM-MPL-015 residual and T26; TM-MPL-018, 025 and T21).
- HKR-092, HKR-093 (users align shared-cache identity inputs): user duty, already the TM-MPL-009 residual.
- BKS-019..032, 061..068 (CreateKeyStore, CreateKey): administrative provisioning; conditional-write semantics are DynamoDB behavior, not Verus-provable.
- BKS-112..119 (GetBeaconKey): covered by C01 and T01.
- BKS-004..010 (default clients, user agent): plumbing; user agent is TM-MPL-020.
- ALG-004..009, 017..023, STR-027..028, 040..041, CPO-012..014, DCM-019..026, STC-006..009: no code in the crate by design (S3EC, DBE, symmetric signing, legacy master keys). If DBE or S3EC suites are added, ALG-017..023 become security-critical and need new targets.
- ALG-010, ALG-030..033: key derivation and signing are in `esdk/`; the MPL side is C05 and C02.
- STR-005..007, KRI-034, RAK-004..005: guidance to callers, not checkable by the library.

Code sweep (N1..N14):

- N1 shim `lib.rs:164`, `:1086`, `:1716` unwrap/expect: not input-dependent; availability only; ESDK-shim plumbing outside TM-024's handle scope.
- N2 shim `lib.rs:1728-1730`, `:782`: safe by construction (loop guard `:1715`; fixed-size array).
- N3 `get_beacon_key` has no length check (`branch_key_store.rs:868-898`): the spec defines no beacon-key length; the plaintext comes from a KMS-authenticated record; consumer is outside this repo.
- N4 DynamoDB `DescribeTable` / `CreateTable` (`branch_key_store.rs:464`, `:506`): operator provisioning, no integrity consequence.
- N5 `Uuid::new_v4()` (`branch_key_store.rs:415`, `:556-557`, `:703`): documented as non-secret (`mpl-threat-model.md:473`); uniqueness enforced by `attribute_not_exists` conditions.
- N6 shim calls to ESDK `encrypt` / `decrypt` (`lib.rs:1292`, `:1334`): ESDK message layer.
- N7 ESDK plaintext freed without wipe in the shim (`lib.rs:1358`; `EncryptionSDK.cpp:285-287`): caller-owned message plaintext, not MPL key material.
- N8 shim loops (`lib.rs:568`, `:1470`, `:1715`, `:1922`): bounded by error-chain depth, caller input and channel chunks.
- N9 raw-AES `on_decrypt` one AES-GCM per matching EDK (`raw_aes_keyring.rs:448`): local linear cost, no external call.
- N10 error text from record-sourced strings (`kms_ops.rs:108`, `:125`, others): needs DDB write access; TM-021 records that callers must not echo errors.
- N11 `contains_all` O(n·m) (`materials_checks.rs:208`): runs on encrypt-path transitions with keyring-sourced EDKs only.
- N12 future-timestamp in-flight mark kept (`storm_tracking.rs:253-254`): already finding F5 under TM-018 / T21.
- N13 RECK subset-of-EC check (`decryption_materials.rs:306-316`): runtime-enforced, fails closed; in T12/C07.
- N14 `parse_arn` / MRK `split(':')` (`kms_config.rs:32`, `mrk_match.rs:38-63`): recorded in T11's rationale; 7-segment input fails closed.

Bug and threat-target sweeps:

- BUG-02, BUG-07(b), BUG-08 map only to capability targets (C04, C03, C01) with no `threat_references`: allowed by design (`02-capability-driven.md:6`); the threat link exists in `mpl-threat-model.md:80-94`.
- BUG-02, BUG-03, BUG-09 are fixed on main and each keeps a regression target (C04, T15, T14).
- Bug reports cite TM IDs that differ from the threat-model map (BUG-07 cites 011; BUG-03 cites 013 and 017; BUG-01 adds 022; BUG-02 and BUG-08 cite none): old-report inconsistencies; every cited ID exists, and `mpl-threat-model.md:80-94` is the current mapping.
- BUG-06 was rated Low in the bug report when this audit ran, against TM-MPL-009/010 High: resolved, because the owner raised BUG-06 from Low to High after the main re-check (see section 7).
- Capability targets with empty `threat_references`; C06's block mentioning TM-MPL-010 (retired, ID exists); T08 and C06 appearing only in retirement rows: not dangling.
- The §4 STRIDE table of `mpl-verification-targets.md` counting 24 threats: same staleness as G4-1 and the known TM-MPL-025 item; fixed by the same edit.

## 5. Method and limits

**Scripted** (scripts are in `.agents/tasks/audit-light/`):
- Sweep 1: `sweep1_extract.py` extracted every sentence or list item with MUST / MUST NOT / SHALL / SHOULD / SHOULD NOT / REQUIRED from the 13 specs (keyword counts per file were checked against the source). `sweep1_map.py` joined these with hand-written rules in `sweep1_rules.txt` and resolved each code anchor by regex against the tree.
- Sweep 2: `sweep2_scan.sh` listed `unwrap`/`expect`/`panic!`, indexing, arithmetic, copy/cast, external calls, secret-bearing names, error formatting and loops in non-test code. `sweep2_cov.sh` grepped the five audited documents for each unmapped site.
- Sweep 3 and 4: `sweep34_targets.py` split the two target files into YAML blocks and listed threat references, capability references and bug mentions.
- In this consolidation: a script checked all 958 `file.rs:line` citations in the six sweep outputs against the tree. Every file resolved and every line number was within the file length (0 failures). Eight random cites were read and matched their descriptions. The per-file unmapped counts in 3a add up to 124 (111 plus 13 boilerplate rows), matching sweep 1's totals. `git status` shows only the new files under `.agents/tasks/audit-light/` and this report.

**Read by hand:**
- Sweep 1: the mapping rules, plus `default_cmm.rs`, `raw_aes_keyring.rs`, `hierarchical_keyring.rs`, `branch_key_store.rs`, `kms_ops.rs`, `record.rs`, `key_store/encryption_context.rs`, `materials_checks.rs`, `commitment_policy.rs`, `encryption_materials.rs`, `local.rs`, `storm_tracking.rs`.
- Sweep 2: every flagged site the scripts could not settle (the long list is in `sweep2-code-findings.md`).
- Consolidation: I re-read the code and spec lines behind G1, G2 and G4-1 myself (`record_from_ddb_item`, `record.rs:95-175`, `decrypt_branch_key`, spec lines 528-531, 550-553, 571-574, 675-691 of `branch-key-store.md`, the suite tables in both spec files, `algorithm_suite.rs`, `commitment_policy.rs`, the four `test-server/src/main.rs` bind lines) and grepped the threat model, spec analysis and both target files for each.

**Corrections to sweep output made here:** sweep 4 cites the loopback bind at `mpl/test-server/src/main.rs:24-25`; the correct lines are `:26-27` (the threat model is right). Sweep 1 says only one test fixture mentions `create-time` / `hierarchy-version`; `mpl/tests/test_key_store_record.rs`, `test_key_store_encryption_context.rs` and `test_aws_kms_user_agent.rs` mention them, but none builds a record that omits them, so the finding stands.

**Not covered:**
- "Mapped" means a threat or target names the same code and property family. It does not mean the target's formal spec states each spec sentence (G1 is the example).
- Not re-derived: logic of `branch_key_wrap`, `cache_entry_identifier`, `mrk_match` and `prim` in sweep 1 (status taken from the docs plus anchor existence; sweep 2 did read parts of them).
- MAY and RECOMMENDED requirements were not extracted. The 23 spec files without code in `mpl/src` were not examined.
- Test code, generated error types, and the shim beyond `unsafe`/FFI and panic sites were not scanned.
- Unmapped rows with reason LOWSEC (53) were judged by reason code, not individually re-read in this consolidation.
- No proof was run, and no behavior (for example KMS failing on a tampered record) was tested at runtime.
- Whether the threat model's ratings are right was not re-assessed.

## 6. Independent verification

A second agent re-checked this report with shell access (grep, sed, git, small scripts) against HEAD `4807e6a`. Result: no threat or target was missed. One finding row was removed (G4-1), line cites were corrected, and nothing else changed.

**Findings re-checked**
- G1: spec lines `branch-key-store.md:530`, `:552`, `:573`, `:677-691` read and match. `record_from_ddb_item` (`branch_key_store.rs:1141-1200`) requires only `enc`. `record.rs:95-175` requires `type`, `version` (ACTIVE), `branch-key-id`, 32-byte key. `ATTR_CREATE_TIME` and `ATTR_HIERARCHY_VERSION` appear in `mpl/src` only on write paths (`branch_key_store.rs:711`, `:1098`; `encryption_context.rs:67`, `:77`). `grep` for `create-time`, `hierarchy-version`, "defined fields" and "record format" over `mpl-threat-model.md`, `mpl-spec-security-analysis.md`, `mpl-verification-targets.md`, `mpl-verification-targets/*.md`, `mpl-bug-reports` and `chorus` finds no coverage of the read-side requirement (TM-MPL-005, T01 and T02 do not state it). Severity Low and "Verus-provable: yes, category 1a" are consistent with `mpl-verus-capabilities.md`. Corrections: `kms_ops.rs:170` is `:172`; the action now also names `record_from_ddb_item` (T01), because that is where the spec says the operation fails.
- G4-1: evidence is real, but it is not new. `mpl-threat-model.md:28` and `:651` already list TM-MPL-026 as "test-only; no target needed" in the "Impact on verification targets" table, and the stale "001..024" header is the known staleness behind the TM-MPL-025 item. Moved from the findings table to the editorial table.
- G2: confirmed (`commitment-policy.md:83` names `..._NO_KDF`, `algorithm-suites.md:203` gives it `00 78`; the pinned spec under `.agents/tasks/pipeline-rerun-620771c/spec-pinned` says the same; the four doc locations say `00 14`). Editorial only.

**Mapped entries spot-checked (code line opened, threat or target read)**
- Spec sweep: HKR-032 (`hierarchical_keyring.rs:722`, T19/TM-003), HKR-072 (`branch_key_wrap.rs:61`, T10/TM-013), BKS-040 (`kms_ops.rs:222`, T03/TM-002), BKS-153 (`record.rs:112`, `:145`, T02/TM-005), DCM-016 (`default_cmm.rs:183`, T09), STR-010 (`encryption_context.rs:91`, `:145`, T15), STR-018 (`materials_checks.rs:51`, C07), STR-045 (`record.rs:164`, T02), ALG-043 (`algorithm_suite.rs:432`, C05), STC-004 (`storm_tracking.rs:606`, T21), CMI-004 (`types.rs:66`, F10 at `mpl-threat-model.md:499`), RAK-012 (`raw_aes_keyring.rs:399`, `:535`).
- Code sweep: E3 (`hierarchical_keyring.rs:901`), E22 (`branch_key_wrap.rs:236`), S9 (`:274`), S11 (`prim/src/lib.rs:185`), S12 (`prim/src/ecdsa.rs:382-392`), X1 (`branch_key_store.rs:155`), X13 (`prim/src/lib.rs:129`), 2c sites `hierarchical_keyring.rs:702`, `:945`, `storm_tracking.rs:333`, `:680` (listed in T06 at `01-threat-driven.md:389-391`), `cmc/entry.rs:213-214`, `raw_aes_keyring.rs:458-469`. The 14 panic sites match an independent grep. No `unsafe` block in `mpl/src` or `prim/src` (grep).
- Bug sweep: all 11 statuses compared with `RECHECK-main-620771c.md` and the table at `mpl-threat-model.md:80-94` (match).
- Threat to target: threat-to-target table in section 3c regenerated from the targets' summary tables; identical. No target depends on T08 or C06.
- Weak but not wrong mappings (the matrix files were not edited): HKR-056 (cache miss falls back to the key store) is mapped to T01, which covers record and EC builders, not the keyring fallback; T19 (`decrypt_edk_at_version`) and T14 are the closer targets. RAK-012 (generate PDK when absent) is mapped to T07; C04 (`generate_random_data_key` length) is the closer target. Both properties are covered by an existing target, so neither is a gap.

**Judged "NOT a gap" items spot-checked**
- STR-046: `uuid_str_to_16_bytes` (`branch_key_wrap.rs:92-110`) accepts any UUID version; nothing depends on v4; holds.
- STR-022: `encryption_materials.rs:401` comment says the signing key length is deliberately not validated; holds.
- N3: no beacon key length requirement exists in `spec/framework/structures.md` (only the branch key has "MUST be 32 bytes", `:395`); `get_beacon_key` (`branch_key_store.rs:868-898`) reads a KMS-authenticated record; holds.
- N5: `Uuid::new_v4()` ids documented as non-secret at `mpl-threat-model.md:473`; holds.
- N12: `storm_tracking.rs:253-254` (`map_or(true, ..)` keeps a future mark) is F5 at `mpl-threat-model.md:494`, under TM-018; holds.
- N14: `mrk_match.rs:38-63` guards every `pa[5]` index with `segments.len() == 6`, and T11/T16 cover it; holds.
- N7 and N1/N2: the shim frees user plaintext in `RustBufferDeleter` (`EncryptionSDK.cpp:285-287`) and the shim `unwrap`/`expect` sites do not depend on input (`lib.rs:164`, `:1716`, `:1728-1730`); holds.

**Counts recomputed with scripts**
- Sweep 1: parsed `sweep1-spec-matrix.md`: 540 rows; categories a 11, b 120, ab 298, c 111 (mapped 429); c reasons LOWSEC 53, NOCODE 32, DESC 9, EXT 4, ESDK 3, NOTPROV 3, GAP 7 (104 + 7 = 111); statuses E 416, S 56, N 32, X 13, P 12, U 8, D 3. The 8 U rows are the 7 G1 rows plus CMI-004. Per-file rows plus one boilerplate row each add to 553; per-file unmapped counts in 3a add to 124. 23 of 26 threats appear in the threat column; 019, 024, 026 do not.
- Sweep 2: site counts per category (25, 110, 16, 18, 13, 17) add to 199; mapped 185; unmapped 14. The 110 sites in category 2 are 14 + 43 + 31 + 22; the 9 unmapped are the shim sites.
- Sweep 4: 32 active targets found in the two summary tables; 22 threats with a target, 019 and 020 excluded, 025 and 026 without a target.

**Done criteria**
- `git diff --quiet HEAD -- mpl prim esdk docs/mpl-threat-model.md docs/mpl-spec-security-analysis.md docs/mpl-verification-targets.md docs/mpl-verification-targets docs/chorus docs/mpl-bug-reports` succeeds.
- `git status --short` shows only `?? .agents/tasks/audit-light/` and `?? docs/mpl-completeness-audit.md`.

**Weakest existing coverage seen** (no change requested): T01 as the only target for the read side of the key-store record (no completeness check, G1); T21 and T26 (known stale); TM-MPL-008 and TM-MPL-014, each backed by a single target (T09, T05).

## 7. Resolution status

Added after the targets refresh at HEAD `9955ecd`. The findings above are unchanged; this section records what was done about them. Line numbers refer to the working tree after the C03 status update (the update commit on top of HEAD `b94c871`): the targets documents gained a "Proofs written" section after the refresh and the C03 record after that, so the cited lines below them moved (checked against the files).

| Item | Status | Where |
|---|---|---|
| G1 (record MUST include `create-time` and `hierarchy-version`) | Applied to T02. No new target and no new threat. Expected FAIL against current code. **Confirmed formally by the T02 proof (code accepts a record lacking `create-time` and `hierarchy-version`)**: T02 is Partly proved (model level, not the shipped code, under stated hypotheses): 21 verified, 1 errors; the one error is the intentional G1 obligation `lemma_g1_spec_soundness_FAILS`, and `lemma_g1_code_ignores_fields` and `lemma_g1_witness_accepted_without_fields` show the outcome is identical with or without the two fields (`verus-proofs/t02_record_reconstruction.rs`). The proof is of a model, not the shipped code. The code is still unchanged and the gap is still open for the owner | `docs/mpl-verification-targets/01-threat-driven.md`: refresh table `:20`, ranked summary `:118`, T02 property text `:228-230`, formal spec `:242` (`// G1: FAILS today`), trace `:259`, coverage evidence `:266`, evidence `:272`. `docs/mpl-verification-targets.md`: refresh table `:17`, ranked summary `:167`, T02 YAML `:246`, `:252`, `:254`, coverage table `:576`, findings `:670` |
| G2 (default suite id `00 14` should be `00 78`) | Fixed in commit `9955ecd` | Commit `9955ecd` (`mpl-threat-model.md`, `mpl-spec-security-analysis.md`) |
| G4-1 (targets documents cite TM-MPL-001..024 and omit TM-MPL-026) | Applied in the targets documents. Threat range is now 001..026 and TM-MPL-026 has a "fully excluded" row | `mpl-verification-targets.md`: header `:4`, refresh `:9`, `:26`, STRIDE table `:609-623` (26 threats), section 6 row for TM-MPL-026 `:647`. `01-threat-driven.md`: header `:4`, `:10`, section 4 row for TM-MPL-026 `:1560`, accounting `:1626`, `:1628` |
| BUG-06 severity | Aligned. The bug report now rates BUG-06 High, consistent with TM-MPL-009 and TM-MPL-010 (High). This was the owner's decision: raised from Low after the main re-check | `docs/mpl-threat-model.md` closing note; `docs/mpl-bug-reports/BUG-06-cache-identifier-not-injective-with-nul.md` ("Severity decision"), `docs/mpl-bug-reports/README.md`, the addendum of `docs/mpl-bug-reports/RECHECK-main-620771c.md` and both `docs/chorus/` editions |
| TM-MPL-025 (the "known item" in sections 2, 3b and 3c) | Applied. New target T27 (3.78, provisional); no threat rating changed | `docs/mpl-verification-targets.md` section 1 (rank 14) and `docs/mpl-verification-targets/01-threat-driven.md`; the bug reports now name T27 for BUG-05(b) |

| BUG-10 (added after the audit) | Recorded by content: BUG-10 maps to TM-MPL-015 -> T26. The audit's section 3b predates it and is unchanged. The site was already a known residual of TM-MPL-015 and T26 (F1, F3), so there is no new target and no new threat, and no score or rating changed | `docs/mpl-bug-reports/BUG-10-raw-aes-on-decrypt-unwiped-data-key.md`; T26 `related_bugs` and `scope_note` in `docs/mpl-verification-targets/01-threat-driven.md` and `docs/mpl-verification-targets.md`; the TM-MPL-015 residual exposures and the bug to threat table in `docs/mpl-threat-model.md` |
| C03 proof status (added after the audit) | Recorded. C03 status: Partly proved (in-crate, on the shipped prim code, on branch Mahnush_Verus, not on this branch, under trusted aws-lc-rs assumptions A1-A20): 18 verified, 0 errors (`verification results:: 18 verified, 0 errors` at `8d6381e`, branch `Mahnush_Verus`, PR #103). C02 is partly superseded by VR-008 (in-crate, on the shipped prim code, on branch Mahnush_Verus, not on this branch): retry bound, termination, guarded copy, and its model-level status (21 verified, 0 errors) is unchanged. The audit's findings and tables are unchanged: section 3b still lists BUG-07(b) -> C03 and BUG-07(a) -> T26, T07 | "Proofs written" in `docs/mpl-verification-targets.md`, `docs/mpl-verification-targets/02-capability-driven.md`; `docs/mpl-threat-model.md` "Proof status" |
The one statement in this audit that labelled BUG-06 as "Low in the bug report" is the bullet in section 4 (bug and threat-target sweeps). It was reworded to point to this section, because it is a severity label for the bug report. The BUG-06 row in section 3b gives no severity and was not changed. Section 2 and section 6 do not mention the BUG-06 severity.

Note (2026-11-17): the Chorus review edition of the threat model (`docs/chorus/MPL-Threat-Model.md` and `.docx`) and the Word copy of the bug reports (`docs/chorus/MPL-Bug-Reports.docx`) were removed after an internal lookup showed that Chorus takes Markdown natively and has no Word import (see `.agents/tasks/chorus-lookup/cli-output.txt`). The source of truth for the threat model is `docs/mpl-threat-model.md`; `docs/chorus/MPL-Bug-Reports.md` is the only file left in `docs/chorus/`. Rows above that cite the removed files describe the state when each check ran.
