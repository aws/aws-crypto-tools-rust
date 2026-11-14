# Threat-Driven Verus Verification Targets — AWS MPL (native Rust)

> Pipeline artifact — Stage 3, Step 1 of 4 (threat-driven entry path). **Refreshed for main `620771c`** (branch `MPL-Verus`; `mpl/`, `prim/`, `esdk/` identical to `origin/main` `620771c`). The previous version analyzed `a1e23d7`.
> Inputs: `docs/threat-model.md` (TM-MPL-001..024), `docs/spec-security-analysis.md`, `docs/bug-reports/RECHECK-main-620771c.md`, `.agents/tasks/pipeline-rerun-620771c/scope.md`, `mpl/src`, `prim/src`, `mpl/tests`, `prim/tests`, `esdk/shims/aws-esdk-cpp/src`.
> Methodology: `.kiro/agents/verification-recommender.md`, `.kiro/agents/ai-verification-pipeline.md`, `.kiro/agents/verus-capabilities.md`.
> Every target has `origin: threat-driven`. Every `file:line` below was re-checked on HEAD in this step (see `.agents/tasks/pipeline-rerun-620771c/stage3-notes.md`).

## 0. What changed since a1e23d7

| ID | Change | Old score | New score | Reason |
|---|---|---|---|---|
| T08 | **Retired** | 3.84 | — | Its code is gone. The `unsafe { write_volatile }` loop in `PlaintextDataKey::zeroize` was replaced by `#[derive(Clone, Zeroize, ZeroizeOnDrop)]` (`mpl/src/structures/algorithm_suite.rs:505`, commit a864ad8 / #131). A search for `\bunsafe\b` in `mpl/src` and `prim/src` finds nothing. TM-MPL-015 is now covered by the new T26. |
| T26 | **New** (TM-MPL-015 residual) | — | 3.20 | Secret buffers on transient and error paths that are not wiped. Replaces T08 as the TM-MPL-015 target. |
| T25 | **New** (TM-MPL-024) | — | 1.44 | C++ shim raw-handle dereferences (`esdk/shims/aws-esdk-cpp/src/lib.rs:715`, `:728`, `:1564-1565`, `:1655`). |
| T13 | Rescored | 2.52 | 4.41 | TM-MPL-009 Likelihood Low → Medium (BUG-06 confirmed end to end). Feasibility 0.4 → 0.7. |
| T14 | Rescored | 2.52 | 3.78 | TM-MPL-010 Likelihood Low → Medium (feasibility 0.7). BUG-09 fixed plus regression test, so gap 0.7 → 0.6. |
| T09 | Rescored | 3.20 | 2.56 | Gap 0.5 → 0.4. The keyring "suite unchanged" frame that T09 assumed is now enforced at runtime by `check_encryption_transition` / `check_decryption_transition` and tested in `test_materials_checks.rs`. |
| T15 | Rescored | 2.40 | 1.92 | BUG-03 fixed: `from_bytes` rejects out-of-order and duplicate keys and invalid UTF-8. Gap 0.5 → 0.4. The expected counterexample is gone; the proof should now verify. |
| T21 | Rescored | 1.68 | 1.96 | Gap 0.6 → 0.7. `StormTrackingCmcBuilder::build` no longer enforces the spec ordering, and `test_durations_are_stored_exactly` asserts the regressed contract. Property (a) is now expected to FAIL. |
| others | Location / name updates only | | unchanged | `keystore/` → `key_store/`, `resolve_keystore_arn` → `resolve_key_store_arn`, `BranchKeyStore` → `DynamoDbKeyStore`, `HierarchicalKeyring::new` → `HierarchicalKeyringBuilder::build`, `RawAesKeyring::new` → `RawAesKeyringBuilder::build`, `ValidatedConfig::from_raw` → `StormTrackingCmcBuilder::build`, `EncryptionContext::{serialize,deserialize}` → `{to_bytes,from_bytes}`, `ttl_seconds: u64` → `ttl: Duration`, error kinds now `crate::error::Kind`. |

Retired threats: none (threat model: "Retired: none"). No active target cites retired code.

## 0.1 Repo facts re-confirmed for this step

- **No `unsafe` in `mpl/src` or `prim/src`.** `\bunsafe\b` has no match (the lint name `unsafe_op_in_unsafe_fn` at `prim/src/lib.rs:33` is one identifier). The only `unsafe` reaching MPL objects is in the C++ shim (`esdk/shims/aws-esdk-cpp/src/lib.rs:728`, `:1564`, `:1565`, `:1655`), which is T25.
- **No raw C FFI in `mpl`/`prim`.** `prim` still calls aws-lc-rs only through its safe API.
- **Duvet:** one annotation block in `mpl/`/`prim/` (`mpl/src/cmc/entry.rs:201-205`, `cryptographic-materials-cache.md#usage-metadata`, `type=implication`). No Duvet config covers MPL sources, so it is not checked. Coverage gaps below are justified by named tests only. Tests lower a gap but never close it.
- **Bugs:** open BUG-01, 04, 05(a), 05(b), 06, 07(a/b), 08. Fixed BUG-02, 03, 09 (`e9bde48`).
- **CVE-2026-6550 / GHSA-v638-38fc-rhfv is verified** by the threat model ([GitHub advisory](https://github.com/advisories/GHSA-v638-38fc-rhfv), [NVD](https://nvd.nist.gov/vuln/detail/CVE-2026-6550), [AWS bulletin 2026-017-aws](https://aws.amazon.com/security/security-bulletins/2026-017-aws/)). It concerns a shared caching CMM in the Python ESDK. This repo has no caching CMM (`mpl/src/cmm/` = `default_cmm.rs`, `fluent_builders.rs`, `mod.rs`, `types.rs`), so it does not raise any feasibility score here. It is recorded as a future-work note on T14. Content was rephrased for compliance with licensing restrictions.

## 1. Scoring conventions (applied uniformly)

`Priority = Severity × Coverage_Gap × Feasibility × Blast_Radius`

| Factor | Rule |
|---|---|
| Severity (1–4) | From the threat-model risk matrix for the target's **primary** threat: Critical=4, High=3, Medium=2, Low=1. Same severity for a threat in every target that cites it. |
| Feasibility (0–1) | From the primary threat's Likelihood: **Low → 0.4, Medium → 0.7**. |
| Blast_Radius (1–4) | 4 = every MPL consumer / every hierarchical-keyring, key-store or CMM user. 3 = widely used but feature-specific (raw AES keyring, shared cache, VersionKey). 2 = opt-in configuration or a single integration surface (storm-tracking cache, Discovery/MRDiscovery, the C++ shim). 1 = narrow. |
| Coverage_Gap (0–1) | 1.0 = no test exercises the property. 0.9 = only tests that cannot detect a defect. 0.8 = some unit tests, or private code exercised only by live-AWS tests. 0.7 = direct unit tests including negative cases. 0.6 = broad example tests of most branches. 0.5 = near-exhaustive tests over a small finite domain. **0.4 (new level) = near-exhaustive tests plus a runtime check that enforces the same property on the production path.** |

Ties: higher severity, then target ID.

Proof-technique notes (unchanged): pure fragments must be extracted from `async fn`s during the proof stage (behavior-preserving, not done here). External crates (`uuid`, `lru`, `zeroize`, `aws-lc-rs`, `std::time::SystemTime`, `core::fmt`, `cxx`) need Verus external specifications, which are trusted (TCB) and must never be used as `assume` to force a pass. Verification claims must name the Cargo feature set (`kms`, `ddb`, `default-aws-sdk-clients`, `rt-tokio`, `test-utils`, `fips`).

## 2. Summary table (ranked)

| Rank | ID | Score | Origin | Target | Property | Agent | Ref | Effort |
|---|---|---|---|---|---|---|---|---|
| 1 | VR-2026-T01 | 8.96 | T | key-store auth-EC builders (`build_authenticated_encryption_context`, `DynamoDbKeyStore::build_auth_ec`, `item_from_ec_and_enc`, `record_from_ddb_item`) | Write-time EC == KMS-AAD EC == reconstruction EC | verus-header-parsing-proofs | TM-MPL-005, TM-MPL-002 | 2 weeks |
| 2 | VR-2026-T02 | 6.72 | T | `record::branch_key_materials_from_authenticated_encryption_context` | Exact Ok/Err characterization | verus-header-parsing-proofs | TM-MPL-005 | 1 week (quick win) |
| 3 | VR-2026-T03 | 5.12 | T | `kms_ops::resolve_key_store_arn` (pinned modes) | KMS KeyId is always the configured ARN | verus-header-parsing-proofs | TM-MPL-002 | 1 day |
| 4 | VR-2026-T04 | 4.48 | T | `branch_key_wrap::wrap` | Fresh 16 B salt + 12 B IV per call, exact 60+n layout | verus-unsafe-ffi-safety | TM-MPL-012 | 1 week |
| 5 | VR-2026-T13 | 4.41 | T | `cache_entry_identifier::build_cache_identifier` + keyring inputs | Exact preimage; scope separation; injective iff fields NUL-free (BUG-06 counterexample otherwise) | verus-header-parsing-proofs | TM-MPL-009, TM-MPL-010 | 1 week |
| 6 | VR-2026-T05 | 4.32 | T | `branch_key_wrap::derive_branch_key` | KBKDF fixed-info = label‖0x00‖salt‖be32(256), 32 B out | verus-header-parsing-proofs | TM-MPL-014 | 1 day |
| 7 | VR-2026-T06 | 4.20 | T | `SystemTime + Duration` sites (keyring, storm tracking) | No overflow panic for any accepted config (expected FAIL, BUG-01) | verus-zero-panic | TM-MPL-018, TM-MPL-022, TM-MPL-023 | 1 week |
| 8 | VR-2026-T07 | 3.84 | T | `RawAesKeyring` wrap/unwrap + `prim::aes_{en,de}crypt` | Fresh 12 B IV per call; length preconditions | verus-unsafe-ffi-safety | TM-MPL-011 | 1 week |
| 9 | VR-2026-T14 | 3.78 | T | `as_branch_key_materials`, `cache_entry_within_limits`, `generate_partition_id` | Only BranchKey entries used; exact `Duration` TTL gate; v4 partition id | verus-header-parsing-proofs | TM-MPL-010 | 1 week |
| 10 | VR-2026-T26 | 3.20 | T | Transient / error-path secret buffers (raw-AES decrypt buffer, `prim::aes_encrypt` output on `Err`, `unwrap` output, KMS plaintext) | Every secret buffer is wiped or moved into a `ZeroizeOnDrop` type on every exit path (expected FAIL, BUG-07a) | verus-unsafe-ffi-safety | TM-MPL-015 | 2 weeks |
| 11 | VR-2026-T10 | 2.88 | T | `compute_aad`, `uuid_str_to_16_bytes`, `uuid_16_bytes_to_str` | AAD layout exact; UUID round trip | verus-header-parsing-proofs | TM-MPL-013 | 1 week |
| 12 | VR-2026-T11 | 2.88 | T | `aws_kms_mrk_match_for_decrypt`, `is_arn_compatible` | Match iff identical or MRKs equal except region; aliases rejected | verus-header-parsing-proofs | TM-MPL-004 | 2 weeks |
| 13 | VR-2026-T12 | 2.88 | T | `default_cmm::merge_reproduced_encryption_context` | Merged EC = union on agreement; nothing dropped | verus-header-parsing-proofs | TM-MPL-017 | 1 week |
| 14 | VR-2026-T09 | 2.56 | T | `CommitmentPolicy::*`, `DefaultCmm`, transition-check frame | Allow-tables match spec; CMM gates encrypt/decrypt | verus-header-parsing-proofs | TM-MPL-006, TM-MPL-008 | 1 week |
| 15 | VR-2026-T16 | 2.24 | T | malformed-input panic sites (`unwrap`, `try_decrypt_edk`, raw-AES decrypt, `from_bytes`, MRK `pa[5]`, `.expect`s) | No panic on any malformed EDK/EC/ARN input | verus-zero-panic | TM-MPL-023 | 1 week |
| 16 | VR-2026-T21 | 1.96 | T | `cmc/storm_tracking.rs` | Builder enforces spec ordering (expected FAIL); `\|inflight\| ≤ fan_out`; ≤ 1 leader per grace interval | verus-zero-panic (+ concurrency specialist) | TM-MPL-018 | 1 month |
| 17 | VR-2026-T15 | 1.92 | T | `EncryptionContext::{to_bytes, from_bytes}` | Canonical codec; `from_bytes(b) = Ok(ec) ⇒ to_bytes(ec) = b` | verus-header-parsing-proofs | TM-MPL-013, TM-MPL-017 | 2 weeks |
| 18 | VR-2026-T17 | 1.92 | T | `resolve_key_store_arn` (Discovery/MRDiscovery), `reject_alias_arn`, `rewrite_arn_region`, `parse_arn` | Alias rejection; region-only rewrite of MRK ARNs (expected FAIL, BUG-04) | verus-header-parsing-proofs | TM-MPL-007 | 1 week |
| 19 | VR-2026-T18 | 1.92 | T | `<Builtin<DynamoDbKeyStore> as KeyStore>::version_key` EC derivation | New ACTIVE/DECRYPT_ONLY ECs preserve id/arn/hv/tablename/custom EC | verus-header-parsing-proofs | TM-MPL-016 | 1 week |
| 20 | VR-2026-T19 | 1.92 | T | `HierarchicalKeyring` bkid binding (`resolve_branch_key_id`, `on_encrypt`, `on_decrypt`, `try_decrypt_edk`, `decrypt_edk_at_version`) | Only matching provider-id + bkid EDKs attempted; bkid bound everywhere | verus-header-parsing-proofs | TM-MPL-003 | 1 week |
| 21 | VR-2026-T20 | 1.68 | T | `RawAesKeyring::{serialize_provider_info, decryptable_edk_iv}` | Provider-info codec round trip, total | verus-header-parsing-proofs | TM-MPL-023, TM-MPL-011, TM-MPL-001 | 1 week |
| 22 | VR-2026-T22 | 1.60 | T | `Debug` impls of secret-bearing types + error `DataKeyInfo` | Output independent of secret bytes | verus-unsafe-ffi-safety | TM-MPL-021 | 1 week |
| 23 | VR-2026-T25 | 1.44 | T | C++ shim handle boundary (`require_handle`, nullable client/cache handles) | Every raw-handle deref is preceded by a null check; null → error or default | verus-unsafe-ffi-safety | TM-MPL-024 | 1 week |
| 24 | VR-2026-T23 | 1.26 | T | `cmc/local.rs` `LocalCmc` | `len ≤ entry_capacity`; get never returns expired; prune safe | verus-zero-panic | TM-MPL-022 | 2 weeks |
| 25 | VR-2026-T24 | 1.20 | T | `RawAesKeyringBuilder::build` | No built keyring has namespace prefixed `aws-kms` | verus-header-parsing-proofs | TM-MPL-001 | 1 day |
| — | VR-2026-T08 | Retired | T | ~~`PlaintextDataKey::zeroize` unsafe loop~~ | — | — | (was TM-MPL-015) | — |

25 active threat-driven targets, 1 retired. Quick win (score > 6.0 and effort ≤ 1 week): **VR-2026-T02** only. T01 scores higher but needs 2 weeks.

## 3. Detailed recommendations (YAML)

```yaml
recommendation:
  id: VR-2026-T01
  rank: 1
  priority_score: 8.96
  origin: threat-driven
  target:
    crate: aws-crypto-mpl
    file: mpl/src/key_store/kms_ops.rs; mpl/src/key_store/branch_key_store.rs; mpl/src/key_store/record.rs
    function: >
      kms_ops::build_authenticated_encryption_context (kms_ops.rs:49, KMS Decrypt AAD, called at :170);
      DynamoDbKeyStore::build_auth_ec (branch_key_store.rs:132; reconstruction in get_active_branch_key :792,
      get_branch_key_version :827, get_beacon_key :868, and the VersionKey ReEncrypt EC at :671);
      item_from_ec_and_enc (:1089, write) / record_from_ddb_item (:1141, read);
      record::encryption_context_from_item (record.rs:37) / to_attribute_map (:61) — both #[cfg(feature = "test-utils")]
  property: >
    The builders that produce the authenticated EC agree exactly with the spec definition
    (every item attribute except `enc`, plus `tablename` = configured logical key store name),
    and a stored item read back (item_from_ec_and_enc → DDB → record_from_ddb_item → build_auth_ec)
    reproduces exactly the EC KMS authenticated at write time: no attribute dropped, added or
    altered, Number attributes round-trip as the same decimal string.
  formal_spec: |
    spec fn auth_ec(attrs: Map<Seq<char>,Seq<char>>, n: Seq<char>) -> Map<Seq<char>,Seq<char>>
        { attrs.remove("enc"@).insert("tablename"@, n) }
    fn build_authenticated_encryption_context(a, n) -> (ec) ensures ec@ == auth_ec(a@, n@)
    fn build_auth_ec(&self, r) -> (ec)
        requires !r.attributes@.contains_key("enc"@)
        ensures ec@ == auth_ec(r.attributes@, self.inner.logical_key_store_name@)
    // write→read (AttributeValue modeled as S | N | B):
    requires ec@["tablename"@] == n@ && !ec@.contains_key("enc"@)
    ensures record_from_ddb_item(item_from_ec_and_enc(ec, enc)) == Ok(r) && r.enc@ == enc@ && auth_ec(r.attributes@, n@) == ec@
  tool: Verus
  agent: verus-header-parsing-proofs
  estimated_effort: 2 weeks
  threat_references:
    - {id: TM-MPL-005, category: Tampering, description: "Branch-key record substitution; residual = reconstructed EC must exactly match write-time EC"}
    - {id: TM-MPL-002, category: Spoofing, description: "Forged record decrypts under attacker-influenced key; EC binding makes forgery detectable"}
  trace_to_spec: >
    spec/framework/branch-key-store.md#encryption-context, #authenticating-a-keystore-item,
    #aws-kms-branch-key-decryption, #record-format, #writing-branch-key-and-beacon-key-to-keystore
  coverage_gap: 0.8
  coverage_evidence: >
    mpl/tests/test_key_store_record.rs::item_encryption_context_round_trips (:306) covers only the
    test-utils record.rs helpers, which production never calls. The production builders are private
    and are reached only by the live-AWS tests in mpl/tests/test_key_store_branch_key_store_integ.rs.
    Unchanged since a1e23d7.
  rationale: |
    KMS EC-as-AAD is the only integrity control on DynamoDB records. Equality depends on separately
    written builders plus an S/N AttributeValue round trip. Still the top residual of TM-MPL-005.
    Needs pure helpers extracted for the AttributeValue mapping and an abstract model of
    aws_sdk_dynamodb::AttributeValue (TCB). A user-supplied KeyStore is outside this proof (TB7).
  scoring:
    severity: 4        # TM-MPL-005 Critical
    coverage_gap: 0.8
    feasibility: 0.7   # TM-MPL-005 Likelihood Medium
    blast_radius: 4
    product: "4 × 0.8 × 0.7 × 4 = 8.96"
  quick_win: false     # 2 weeks
  dependencies: []
```

```yaml
recommendation:
  id: VR-2026-T02
  rank: 2
  priority_score: 6.72
  origin: threat-driven
  target:
    crate: aws-crypto-mpl
    file: mpl/src/key_store/record.rs
    function: branch_key_materials_from_authenticated_encryption_context (:95); custom_encryption_context_from_authenticated_encryption_context (:79); malformed (:188)
  property: >
    Returns Ok(materials) exactly when the EC has a valid `type` ("branch:ACTIVE" with a `version`
    strictly extending "branch:version:", or a type strictly extending "branch:version:"), a
    `branch-key-id`, and the plaintext is 32 bytes. Output fields are then exactly determined.
    Every other input yields Err with Kind::InvalidMaterials.
  formal_spec: |
    fn branch_key_materials_from_authenticated_encryption_context(ec, pt) -> (r)
      ensures r.is_Ok() <==> ec@.contains_key("type"@)
                && (ec@["type"@] == "branch:ACTIVE"@ ==> ec@.contains_key("version"@))
                && strict_prefix("branch:version:"@, ver_src(ec@))
                && ec@.contains_key("branch-key-id"@) && pt@.len() == 32
      ensures r matches Ok(m) ==> m.branch_key@ == pt@ && m.branch_key_id@ == ec@["branch-key-id"@]
                && m.branch_key_version@ == ver_src(ec@).subrange(15, ver_src(ec@).len() as int)
                && m.encryption_context@ == custom(ec@)
      ensures r matches Err(e) ==> e.kind() == Kind::InvalidMaterials
  tool: Verus
  agent: verus-header-parsing-proofs
  estimated_effort: 1 week
  threat_references:
    - {id: TM-MPL-005, category: Tampering, description: "Reconstruction must not accept a mis-typed or mis-versioned record"}
  trace_to_spec: >
    spec/framework/branch-key-store.md#branch-key-materials-from-authenticated-encryption-context,
    #custom-encryption-context-from-authenticated-encryption-context
  coverage_gap: 0.6
  coverage_evidence: >
    mpl/tests/test_key_store_record.rs (23 tests): branch-type, version, beacon, wrong-length
    (materials_branch_key_rejects_wrong_length :169) and custom-EC extraction cases.
  rationale: |
    Final decode of KMS-authenticated data into the materials every hierarchical wrap/unwrap uses.
    Straight-line Map code. The decrypted key is now held in Zeroizing during parsing (record.rs:100),
    which does not change the functional property. Paired with T01 it closes
    "authenticated bytes → correct materials".
  scoring:
    severity: 4
    coverage_gap: 0.6
    feasibility: 0.7
    blast_radius: 4
    product: "4 × 0.6 × 0.7 × 4 = 6.72"
  quick_win: true      # score > 6.0, effort ≤ 1 week
  dependencies: []
```

```yaml
recommendation:
  id: VR-2026-T03
  rank: 3
  priority_score: 5.12
  origin: threat-driven
  target:
    crate: aws-crypto-mpl
    file: mpl/src/key_store/kms_ops.rs (+ caller decrypt_branch_key :162; version_key in branch_key_store.rs:641)
    function: resolve_key_store_arn (:88; KmsKeyArn / KmsMrKeyArn arms :94-95, compatibility check :105, Ok :113)
  property: >
    In single-key modes the KeyId sent to KMS Decrypt/ReEncrypt is always the CONFIGURED ARN, never
    the record's `kms-arn`. Success iff the record ARN is compatible (byte-equal for KmsKeyArn,
    MRK-match for KmsMrKeyArn); otherwise Err with Kind::Validation. decrypt_branch_key passes only
    this value as key_id (:179, :183).
  formal_spec: |
    fn resolve_key_store_arn(c, rec, bkid) -> (r: Result<String, Error>)
      requires c is KmsKeyArn || c is KmsMrKeyArn
      ensures r matches Ok(k) ==> k@ == configured(c)@
      ensures r.is_Ok() <==> compat_spec(c, rec@)
      ensures r matches Err(e) ==> e.kind() == Kind::Validation
  tool: Verus
  agent: verus-header-parsing-proofs
  estimated_effort: 1 day
  threat_references:
    - {id: TM-MPL-002, category: Spoofing, description: "Forged record decrypts under attacker-influenced KMS key — pinned-mode slice"}
  trace_to_spec: "spec/framework/branch-key-store.md#aws-kms-branch-key-decryption, #aws-key-arn-compatibility"
  coverage_gap: 0.8
  coverage_evidence: >
    resolve_key_store_arn is pub(crate) with no direct unit test. The compatibility predicate is
    tested in mpl/tests/test_key_store_kms_config.rs (22 tests). End-to-end coverage is live-AWS only.
  rationale: "Code-level control for Critical TM-MPL-002; cheap because the property is 'returns the configured string'. Logic unchanged since a1e23d7 (renamed)."
  scoring:
    severity: 4        # TM-MPL-002 Critical
    coverage_gap: 0.8
    feasibility: 0.4   # Low
    blast_radius: 4
    product: "4 × 0.8 × 0.4 × 4 = 5.12"
  quick_win: false
  dependencies: [VR-2026-T11]   # soft: gives compat_spec its MRK meaning
```

```yaml
recommendation:
  id: VR-2026-T04
  rank: 4
  priority_score: 4.48
  origin: threat-driven
  target:
    crate: aws-crypto-mpl
    file: mpl/src/aws_kms/branch_key_wrap.rs
    function: wrap (:157; salt draw :164, IV draw :170)
  property: >
    Fresh local 16-byte salt and 12-byte IV per call, each filled by one successful RNG call before
    use, no cross-call state. Output is exactly salt‖iv‖uuid_bytes(version)‖ct‖tag with
    |output| = 60 + |pt|. aws-lc-rs preconditions hold (key 32 bytes, IV 12). On Err the partially
    built output is dropped and never returned.
  formal_spec: |
    fn wrap(m, ec, pt) -> (r)
      ensures r matches Ok(out) ==> out@.len() == 60 + pt@.len()
        && out@.subrange(0,16) == ghost_salt_draw@ && out@.subrange(16,28) == ghost_iv_draw@
        && out@.subrange(28,44) == uuid_bytes(m.branch_key_version@)
        && out@.subrange(44, out@.len() as int) == gcm_seal_spec(kdf(m.branch_key@, ghost_salt_draw@), ghost_iv_draw@, compute_aad_spec(m, ec), pt@)
  tool: Verus
  agent: verus-unsafe-ffi-safety
  estimated_effort: 1 week
  threat_references:
    - {id: TM-MPL-012, category: Elevation of Privilege, description: "AES-GCM salt/IV reuse in branch-key wrap — lengths and fresh-per-call structure"}
  trace_to_spec: "spec/framework/aws-kms/aws-kms-hierarchical-keyring.md#branch-key-wrapping, #ciphertext"
  coverage_gap: 0.7
  coverage_evidence: >
    mpl/tests/test_aws_kms_hierarchical_keyring.rs: wrap_ciphertext_layout_lengths_match_spec (:939),
    wrap_two_calls_produce_distinct_ciphertexts (:1168), unwrap_too_short_ciphertext_returns_error (:1187), round trips.
  rationale: "prim uses Nonce::try_assume_unique_for_key, so nonce discipline is on the caller. Structural half provable; the 224-bit collision bound is excluded."
  scoring:
    severity: 4
    coverage_gap: 0.7
    feasibility: 0.4
    blast_radius: 4
    product: "4 × 0.7 × 0.4 × 4 = 4.48"
  quick_win: false
  dependencies: [VR-2026-T05, VR-2026-T10]
```

```yaml
recommendation:
  id: VR-2026-T13
  rank: 5
  priority_score: 4.41
  origin: threat-driven
  target:
    crate: aws-crypto-mpl
    file: mpl/src/aws_kms/cache_entry_identifier.rs; mpl/src/aws_kms/hierarchical_keyring.rs
    function: >
      build_cache_identifier (cache_entry_identifier.rs:35; preimage :42-60; .expect :64);
      call sites HierarchicalKeyring on_encrypt (:665) and decrypt_edk_at_version (:908);
      field sources: partition id (:595-599, raw caller bytes or generate_partition_id :626),
      logical name from the key store (:605), bkid from config or supplier (resolve_branch_key_id :831)
  property: >
    The SHA-384 preimage is exactly 0x02‖0x00‖scope‖0x00‖partition‖0x00‖logicalName‖0x00‖bkid[‖0x00‖version].
    Encrypt and decrypt scopes never share a preimage. The preimage is injective in
    (partition, logicalName, bkid, version) WHEN those fields contain no 0x00 byte; without that
    precondition injectivity is FALSE (BUG-06). The internal `.expect` is unreachable.
  formal_spec: |
    spec fn pre(s, p, n, b, v) -> Seq<u8>
      { seq![0x02, 0x00, s, 0x00] + p + seq![0x00] + n + seq![0x00] + b + match v { Some(x) => seq![0x00] + x, None => seq![] } }
    fn build_cache_identifier(s, p, n, b, v) -> (out: [u8; 48]) ensures out@ == sha384_spec(pre(s, p@, n@, b@, v@))
    proof fn scope_separation(..) requires s1 != s2 ensures pre(s1, ..) != pre(s2, ..)
    proof fn injective_nul_free(..) requires no_nul(p1) && no_nul(n1) && no_nul(b1) && no_nul_opt(v1) && (same for 2)
                                             && pre(s,p1,n1,b1,v1) == pre(s,p2,n2,b2,v2)
                                    ensures p1 == p2 && n1 == n2 && b1 == b2 && v1 == v2
    // EXPECTED COUNTEREXAMPLE without no_nul (BUG-06, do not axiomatize away):
    //   (p="tenant\0x", n="L") vs (p="tenant", n="x\0L"), same bkid → equal preimages
  tool: Verus
  agent: verus-header-parsing-proofs
  estimated_effort: 1 week
  threat_references:
    - {id: TM-MPL-009, category: Elevation of Privilege, description: "Cache-identifier collision returns wrong branch-key materials (BUG-06 confirmed on main)"}
    - {id: TM-MPL-010, category: Information Disclosure / EoP, description: "Shared-cache confusion"}
  trace_to_spec: >
    spec/framework/aws-kms/aws-kms-hierarchical-keyring.md#appendix-a-cache-entry-identifier-formulas, #partition-id
  coverage_gap: 0.7
  coverage_evidence: >
    mpl/tests/test_aws_kms_hierarchical_keyring.rs: cache_entry_identifier_for_encrypt_matches_manual_sha384 (:647),
    ..._for_decrypt_matches_manual_sha384 (:680), ..._encrypt_and_decrypt_differ_for_same_inputs (:708),
    ..._distinct_branch_key_ids_produce_distinct_outputs (:736), ..._distinct_versions_produce_distinct_outputs (:770).
    No NUL-in-field case (BUG-06 has no regression test in mpl/tests).
  rationale: |
    Rescored: TM-MPL-009 Likelihood is now Medium because BUG-06 is a confirmed open defect (RECHECK:
    keyring B served key store A's branch key; key store B called 0 times). cache_entry_identifier.rs
    is unchanged since a1e23d7. The proof gives the exact injectivity boundary and the counterexample.
    A fix (reject 0x00 at build/resolve time, or length-prefix with a spec change) is an owner decision;
    once a NUL check exists at the call sites, `no_nul` becomes a provable precondition. SHA-384
    collision resistance is excluded.
  scoring:
    severity: 3        # TM-MPL-009 High
    coverage_gap: 0.7
    feasibility: 0.7   # TM-MPL-009 Likelihood Medium (was Low)
    blast_radius: 3    # matters for shared caches
    product: "3 × 0.7 × 0.7 × 3 = 4.41"
  quick_win: false
  dependencies: []
```

```yaml
recommendation:
  id: VR-2026-T05
  rank: 6
  priority_score: 4.32
  origin: threat-driven
  target:
    crate: aws-crypto-mpl
    file: mpl/src/aws_kms/branch_key_wrap.rs
    function: derive_branch_key (private, :122; returns Zeroizing<[u8; 32]> :125, buffer :135, kbkdf_ctr_hmac call :136)
  property: >
    Fixed-info is exactly "aws-kms-hierarchy"(17) ‖ 0x00 ‖ salt(16) ‖ 0x00000100 (38 bytes),
    PRF HMAC-SHA-256, IKM the 32-byte branch key, OKM 32 bytes. wrap and unwrap reach the KDF only
    through this function.
  formal_spec: |
    fn derive_branch_key(bk: &[u8;32], salt: &[u8;16]) -> (r: Result<Zeroizing<[u8;32]>, Error>)
      ensures ghost_info@ == b"aws-kms-hierarchy"@ + seq![0x00u8] + salt@ + seq![0x00u8, 0x00, 0x01, 0x00]
           && ghost_info@.len() == 38 && ghost_alg == DigestAlg::Sha256 && ghost_okm_len == 32
      ensures r matches Ok(k) ==> (*k)@ == kbkdf_ctr_hmac_spec(Sha256, bk@, ghost_info@, 32)   // uninterpreted, TCB
  tool: Verus
  agent: verus-header-parsing-proofs
  estimated_effort: 1 day
  threat_references:
    - {id: TM-MPL-014, category: Elevation of Privilege, description: "KBKDF fixed-info / L-value misuse weakens branch-key derivation"}
  trace_to_spec: "spec/framework/aws-kms/aws-kms-hierarchical-keyring.md#branch-key-wrapping; NIST SP 800-108 §4.1"
  coverage_gap: 0.9
  coverage_evidence: >
    Round trips in test_aws_kms_hierarchical_keyring.rs use the same function on both sides, so
    layout drift is undetected. prim/tests/test_kbkdf_ctr_hmac.rs::test_kbkdf_ctr_hmac_raw_vectors (:329) tests only the primitive.
  rationale: "Interop-breaking, possibly weakening, invisible to self-consistent tests. Output now Zeroizing (daac26c), which does not change the layout property."
  scoring:
    severity: 3
    coverage_gap: 0.9
    feasibility: 0.4
    blast_radius: 4
    product: "3 × 0.9 × 0.4 × 4 = 4.32"
  quick_win: false
  dependencies: []
```

```yaml
recommendation:
  id: VR-2026-T06
  rank: 7
  priority_score: 4.20
  origin: threat-driven
  target:
    crate: aws-crypto-mpl
    file: mpl/src/aws_kms/hierarchical_keyring.rs; mpl/src/cmc/storm_tracking.rs
    function: >
      on_encrypt `now + self.inner.ttl` (hierarchical_keyring.rs:702); decrypt_edk_at_version `now + self.inner.ttl` (:945);
      StormTrackingCmc::classify_and_mark `now + self.inner.in_flight_ttl` (storm_tracking.rs:333);
      within_grace_interval `inflight + grace_interval` (:680);
      bounds would live in HierarchicalKeyringBuilder::build (:535; only ttl.is_zero() at :547) and
      StormTrackingCmcBuilder::build (:606; no upper bounds)
  property: >
    No `SystemTime + Duration` addition panics for any configuration the builders accept.
    EXPECTED TO FAIL as written (BUG-01 open): ttl is now a Duration, so Duration::MAX (or any value
    past the platform SystemTime range) is accepted and std's Add panics on overflow.
  formal_spec: |
    // SystemTime::add(t, d) requires st_add_ok(t, d)   (TCB external spec)
    fn HierarchicalKeyringBuilder::build(self) -> (r) ensures r matches Ok(k) ==> k.ttl() <= MAX_TTL
    fn StormTrackingCmcBuilder::build(self) -> (r) ensures r matches Ok(c) ==> c.grace_interval() <= MAX_D && c.in_flight_ttl() <= MAX_D
    // add sites verify only once those bounds exist (or the adds become checked_add mapped to an error)
  tool: Verus
  agent: verus-zero-panic
  estimated_effort: 1 week
  threat_references:
    - {id: TM-MPL-018, category: Denial of Service, description: "Storm-tracking mis-configuration causes failures — here a process panic"}
    - {id: TM-MPL-022, category: Denial of Service, description: "Cache configuration → availability"}
    - {id: TM-MPL-023, category: Denial of Service, description: "Panic instead of error (config-driven)"}
  trace_to_spec: >
    spec/framework/aws-kms/aws-kms-hierarchical-keyring.md#cache-limit-ttl;
    spec/framework/storm-tracking-cryptographic-materials-cache.md#grace-interval, #inflight-ttl
  coverage_gap: 1.0
  coverage_evidence: >
    No large-Duration test: a search for u64::MAX / Duration::MAX in the hierarchical and storm-tracking
    tests finds none (scope). Sub-second tests (build_with_sub_second_ttl_keeps_it_exactly :225) use small values.
  rationale: "BUG-01 confirmed still present by RECHECK. Choosing a bound is an owner decision; Verus closes it afterwards."
  scoring:
    severity: 2        # TM-MPL-018 Medium
    coverage_gap: 1.0
    feasibility: 0.7   # TM-MPL-018 Likelihood Medium
    blast_radius: 3
    product: "2 × 1.0 × 0.7 × 3 = 4.20"
  quick_win: false
  dependencies: []
```

```yaml
recommendation:
  id: VR-2026-T07
  rank: 8
  priority_score: 3.84
  origin: threat-driven
  target:
    crate: aws-crypto-mpl + aws-mpl-primitives
    file: mpl/src/keyring/raw_aes_keyring.rs; prim/src/lib.rs
    function: >
      RawAesKeyringBuilder::build (:350); RawAesKeyring::wrap_data_key (:146; IV :152, aes_encrypt call :163);
      <Builtin<RawAesKeyring> as Keyring>::on_encrypt (:399) / on_decrypt (:422; aes_decrypt call :472);
      prim::aes_encrypt (lib.rs:175) / aes_decrypt (:206)
  property: >
    (a) |wrapping_key| == wrapping_alg key length for every built keyring. (b) wrap_data_key allocates
    a fresh 12-byte IV per call, filled by one RNG call, never stored in self; the same bytes are the
    GCM nonce and the provider-info IV. (c) Every aes_encrypt/aes_decrypt call meets the aws-lc-rs
    preconditions (key length, |iv| == 12, |tag| == 16, |pt| == |ct|), so the only aes_decrypt Err is an
    authentication failure. (d) Ok ⇒ |EDK.ciphertext| == |pdk| + 16.
  formal_spec: |
    spec fn inv(k) -> bool { k.inner.wrapping_key@.len() == k.inner.wrapping_alg.key_len() }
    fn build(self) -> (r) ensures r matches Ok(k) ==> inv(k)
    fn wrap_data_key(&self, pdk, aad) -> (r) requires inv(*self)
      ensures r matches Ok(e) ==> e.ciphertext@.len() == pdk@.len() + 16
           && e.key_provider_info@.subrange(|name|+8, |name|+20) == ghost_iv_draw@
  tool: Verus
  agent: verus-unsafe-ffi-safety
  estimated_effort: 1 week
  threat_references:
    - {id: TM-MPL-011, category: Elevation of Privilege, description: "AES-GCM IV reuse in raw-AES keyring — length + fresh-per-call structure"}
  trace_to_spec: "spec/framework/raw-aes-keyring.md#onencrypt, #ondecrypt, #iv, #wrapping-algorithm, #wrapping-key"
  coverage_gap: 0.8
  coverage_evidence: >
    mpl/tests/test_raw_aes_keyring.rs (25 tests, incl. test_encrypted_data_key_wire_format :406);
    prim/tests/test_aes.rs (bad key/IV length, test_aes_decrypt_output_buffer_too_small :138).
    Still no two-call IV-distinctness test (scope).
  rationale: "Unchanged logic; locations moved into the builder and wrap_data_key. The BUG-07a plaintext residue on aes_encrypt Err is now tracked in T26."
  scoring:
    severity: 4
    coverage_gap: 0.8
    feasibility: 0.4
    blast_radius: 3
    product: "4 × 0.8 × 0.4 × 3 = 3.84"
  quick_win: false
  dependencies: [VR-2026-T20]
```

```yaml
recommendation:
  id: VR-2026-T14
  rank: 9
  priority_score: 3.78
  origin: threat-driven
  target:
    crate: aws-crypto-mpl
    file: mpl/src/aws_kms/hierarchical_keyring.rs
    function: >
      as_branch_key_materials (:1000); cache_entry_within_limits (:989; `elapsed <= ttl` :994);
      generate_partition_id (:626); cache puts in on_encrypt (:700) and decrypt_edk_at_version (:943)
  property: >
    (a) The keyring only puts CachedMaterials::BranchKey; any other variant read back yields Err.
    (b) A cached entry is used only if elapsed(now, creation_time) ≤ ttl, compared as full Durations
    (clock-skew Err mapped to 0). (c) The default partition id is 16 bytes with the v4 version nibble and
    RFC 4122 variant. (d) Cached entries carry no suite or commitment state.
  formal_spec: |
    fn as_branch_key_materials(e) -> (r) ensures r.is_Ok() <==> e.materials() is BranchKey
    fn cache_entry_within_limits(e, ttl: Duration) -> (r: bool) ensures r <==> elapsed_sat(ghost_now, e.creation_time()) <= ttl
    fn generate_partition_id() -> (r) ensures r matches Ok(v) ==> v@.len() == 16 && (v@[6] >> 4) == 4 && (v@[8] >> 6) == 2
  tool: Verus
  agent: verus-header-parsing-proofs
  estimated_effort: 1 week
  threat_references:
    - {id: TM-MPL-010, category: Information Disclosure / EoP, description: "Shared-cache confusion"}
  trace_to_spec: >
    spec/framework/aws-kms/aws-kms-hierarchical-keyring.md#partition-id, #cache-limit-ttl, #shared-cache-considerations
  coverage_gap: 0.6
  coverage_evidence: >
    mpl/tests/test_aws_kms_hierarchical_keyring.rs: partition_id_default_is_16_byte_v4_uuid (:289),
    build_with_shared_cache_round_trips_provided_cache (:484), BUG-09 regression
    on_encrypt_ttl_compares_the_full_duration (:1547). No test injects a wrong-kind cache entry.
  rationale: |
    Rescored: TM-MPL-010 Likelihood Medium (feasibility 0.7). BUG-09 is fixed, so (b) is now expected to
    verify exactly (the old "ttl + 1 s" truncation note is withdrawn). The default partition id can
    contain 0x00, which links to T13. Future work: if a caching CMM is added, its cache id must bind the
    commitment policy or suite (CVE-2026-6550 class); that would be a new target.
  scoring:
    severity: 3        # TM-MPL-010 High
    coverage_gap: 0.6
    feasibility: 0.7   # Likelihood Medium (was Low)
    blast_radius: 3
    product: "3 × 0.6 × 0.7 × 3 = 3.78"
  quick_win: false
  dependencies: [VR-2026-T13]
```

```yaml
recommendation:
  id: VR-2026-T26
  rank: 10
  priority_score: 3.20
  origin: threat-driven
  target:
    crate: aws-crypto-mpl + aws-mpl-primitives
    file: mpl/src/keyring/raw_aes_keyring.rs; prim/src/lib.rs; mpl/src/aws_kms/branch_key_wrap.rs; mpl/src/aws_kms/hierarchical_keyring.rs; mpl/src/key_store/kms_ops.rs
    function: >
      <Builtin<RawAesKeyring> as Keyring>::on_decrypt (plaintext buffer `vec![0u8; ..]` :471, aes_decrypt-Err path, wrong-length path :489);
      RawAesKeyring::wrap_data_key (`ciphertext` Vec :162 receiving plaintext from aes_encrypt :163);
      prim::aes_encrypt (plaintext copied :185 before the key/nonce checks that can return Err, :188);
      branch_key_wrap::unwrap (:230, returns Vec<u8>) → HierarchicalKeyring::on_decrypt (:767, PlaintextDataKey::new);
      kms_ops::decrypt_branch_key (KMS plaintext Blob `.into_inner()`, returned Vec) → record.rs:100 Zeroizing
  property: >
    For each listed function and every exit path (Ok, every Err, every `?`), each heap buffer that has
    held plaintext key bytes is either moved into a ZeroizeOnDrop / Zeroizing owner or zeroized before it
    is dropped. EXPECTED TO FAIL on at least: (F1) raw-AES on_decrypt drops `plaintext_dk` unwiped on the
    aes_decrypt-Err and wrong-length paths; (F2) BUG-07a, prim::aes_encrypt leaves plaintext in the
    caller's buffer on Err and wrap_data_key drops it unwiped; (F3) unwrap's returned Vec and the KMS
    plaintext Vec are plain Vec<u8> between producer and wrapper.
  formal_spec: |
    // ghost: secret(buf) set when key bytes are written; wiped(buf) set by Zeroize::zeroize or by moving buf
    // into a ZeroizeOnDrop type (zeroize crate drop semantics = TCB external spec)
    spec fn clean_exit(bufs: Set<BufId>) -> bool { forall|b| bufs.contains(b) && secret(b) ==> wiped(b) || moved_to_zod(b) }
    fn on_decrypt(&self, input) -> (r) ensures clean_exit(ghost_local_bufs)        // expected: FAILS (F1)
    fn aes_encrypt(alg, iv, key, msg, aad, ct) -> (r) ensures r.is_Err() ==> ct@ == old(ct)@   // expected: FAILS (F2, BUG-07a)
    fn unwrap(m, ec, ct) -> (r) ensures r matches Ok(v) ==> caller_obligation_wrap(v)          // discharged at hierarchical_keyring.rs:767
  tool: Verus
  agent: verus-unsafe-ffi-safety
  estimated_effort: 2 weeks
  threat_references:
    - {id: TM-MPL-015, category: Information Disclosure, description: "Secret material not zeroized — transient and error-path copies (residual after zeroize-on-drop)"}
  trace_to_spec: "spec/framework/structures.md#plaintext-data-key ('kept secret'); no clause mandates zeroization — baseline assurance"
  coverage_gap: 1.0
  coverage_evidence: >
    Zeroize tests cover the types only (test_encryption_materials.rs::test_plaintext_data_key_zeroize :248,
    test_decryption_materials.rs::test_plaintext_data_key_zeroize_decryption :228). No test checks the
    transient or error-path buffers listed here.
  rationale: |
    Replaces retired T08. The long-lived secret types now zeroize on drop, so TM-MPL-015 was lowered to
    Medium/Low; what remains is exactly these transient sites (threat model §8 TM-MPL-015 residuals,
    spec-security-analysis.md). Verus does not model Drop natively, so the proof needs ghost "secret /
    wiped" state over local buffers; that is why the effort is 2 weeks. Fixes (Zeroizing buffers;
    truncate or wipe the output on aes_encrypt Err) change behavior and are owner decisions.
    Excluded: Vec reallocation copies, allocator/OS residency, the cache holding branch keys for the TTL by design.
  scoring:
    severity: 2        # TM-MPL-015 Medium (was High)
    coverage_gap: 1.0
    feasibility: 0.4   # Low
    blast_radius: 4
    product: "2 × 1.0 × 0.4 × 4 = 3.20"
  quick_win: false
  dependencies: []
```

```yaml
recommendation:
  id: VR-2026-T10
  rank: 11
  priority_score: 2.88
  origin: threat-driven
  target:
    crate: aws-crypto-mpl
    file: mpl/src/aws_kms/branch_key_wrap.rs; mpl/src/aws_kms/hierarchical_keyring.rs
    function: compute_aad (branch_key_wrap.rs:61); uuid_str_to_16_bytes (:92, private); uuid_16_bytes_to_str (hierarchical_keyring.rs:644, private)
  property: >
    compute_aad returns Ok exactly when the version is a 36-char canonical UUID and the EC is
    serializable; the AAD is then "aws-kms-hierarchy" ‖ utf8(bkid) ‖ uuid_bytes(version) ‖ to_bytes(ec).
    For a fixed bkid, (version, ec) ↦ AAD is injective. For every 16-byte b,
    uuid_str_to_16_bytes(uuid_16_bytes_to_str(b)) == Ok(b).
  formal_spec: |
    fn compute_aad(bkid, ver, ec) -> (r) ensures r.is_Ok() <==> canonical_uuid(ver@) && serializable(ec@)
      ensures r matches Ok(a) ==> a@ == "aws-kms-hierarchy"@ + bkid@ + uuid_bytes(ver@) + ser(ec@)
    proof fn aad_injective_fixed_bkid(..) ensures uuid_bytes(v1@) == uuid_bytes(v2@) && e1@ == e2@   // uses T15
    proof fn uuid_round_trip(b: [u8;16]) ensures uuid_str_to_16_bytes(&uuid_16_bytes_to_str(&b), _) == Ok(b)
  tool: Verus
  agent: verus-header-parsing-proofs
  estimated_effort: 1 week
  threat_references:
    - {id: TM-MPL-013, category: Tampering, description: "Branch-key wrap/unwrap AAD constructed inconsistently"}
  trace_to_spec: "spec/framework/aws-kms/aws-kms-hierarchical-keyring.md#branch-key-wrapping-and-unwrapping-aad"
  coverage_gap: 0.6
  coverage_evidence: "mpl/tests/test_aws_kms_hierarchical_keyring.rs: compute_aad_layout_for_known_inputs (:826) and mismatch/round-trip tests."
  rationale: "Expected: cross-bkid injectivity is false (no length prefix; spec layout), harmless because each AAD is used under its own branch key. Unchanged since a1e23d7."
  scoring:
    severity: 3
    coverage_gap: 0.6
    feasibility: 0.4
    blast_radius: 4
    product: "3 × 0.6 × 0.4 × 4 = 2.88"
  quick_win: false
  dependencies: [VR-2026-T15]
```

```yaml
recommendation:
  id: VR-2026-T11
  rank: 12
  priority_score: 2.88
  origin: threat-driven
  target:
    crate: aws-crypto-mpl
    file: mpl/src/aws_kms/mrk_match.rs; mpl/src/key_store/kms_config.rs
    function: aws_kms_mrk_match_for_decrypt (mrk_match.rs:24); is_multi_region_arn (:52); is_alias_arn (:62); is_arn_compatible (kms_config.rs:86); parse_arn (:31)
  property: >
    True exactly when neither input is an alias ARN and either the inputs are identical, or both are MRK
    ARNs (6 ':'-segments, "arn", service "kms", resource "key/mrk-…") equal on partition, service,
    account, resource type and id, region the only possible difference. Symmetric. is_arn_compatible
    is byte-equality for KmsKeyArn, the MRK match for KmsMrKeyArn, true for Discovery modes.
  formal_spec: |
    fn aws_kms_mrk_match_for_decrypt(a, b) -> (r: bool)
      ensures r <==> !is_alias(a@) && !is_alias(b@) && (a@ == b@ || (is_mrk(a@) && is_mrk(b@) && same_except_region(a@, b@)))
      ensures r == aws_kms_mrk_match_for_decrypt_spec(b@, a@)
  tool: Verus
  agent: verus-header-parsing-proofs
  estimated_effort: 2 weeks
  threat_references:
    - {id: TM-MPL-004, category: Tampering, description: "ARN/MRK match accepts a non-matching key ARN"}
  trace_to_spec: "spec/framework/aws-kms/aws-kms-mrk-match-for-decrypt.md#implementation; spec/framework/branch-key-store.md#aws-key-arn-compatibility"
  coverage_gap: 0.6
  coverage_evidence: "mpl/tests/test_aws_kms_mrk_match.rs (incl. identical_aliases_return_false :32); mpl/tests/test_key_store_kms_config.rs."
  rationale: "Parser inconsistency to settle: mrk_match uses split(':') (exactly 6) while parse_arn uses splitn(6, ':'). Unchanged logic."
  scoring:
    severity: 3
    coverage_gap: 0.6
    feasibility: 0.4
    blast_radius: 4
    product: "3 × 0.6 × 0.4 × 4 = 2.88"
  quick_win: false
  dependencies: []
```

```yaml
recommendation:
  id: VR-2026-T12
  rank: 13
  priority_score: 2.88
  origin: threat-driven
  target:
    crate: aws-crypto-mpl
    file: mpl/src/cmm/default_cmm.rs
    function: merge_reproduced_encryption_context (:273, private); call in decrypt_materials (:177, call :198)
  property: >
    No reproduced EC → (message EC, ∅). Otherwise Ok exactly when both agree on every shared key; then
    ec = m ∪ r, m ⊆ ec, required keys = dom(r) \ dom(m) ⊆ dom(ec). The EC given to the keyring is
    exactly the merged map.
  formal_spec: |
    fn merge_reproduced_encryption_context(m, r) -> (res)
      ensures r is None ==> res == Ok((*m, empty))
      ensures r matches Some(rr) ==> (res.is_Ok() <==> forall|k| m@.contains_key(k) && rr@.contains_key(k) ==> m@[k] == rr@[k])
      ensures res matches Ok((ec, req)) && r matches Some(rr) ==> ec@ == m@.union_prefer_right(rr@) && req@ == rr@.dom().difference(m@.dom())
  tool: Verus
  agent: verus-header-parsing-proofs
  estimated_effort: 1 week
  threat_references:
    - {id: TM-MPL-017, category: Tampering, description: "Reproduced-EC merge drops or alters bound context"}
  trace_to_spec: "spec/framework/cmm-interface.md#decrypt-materials; spec/framework/default-cmm.md#decrypt-materials"
  coverage_gap: 0.6
  coverage_evidence: "mpl/tests/test_default_cmm.rs reproduced-EC tests (e.g. test_decrypt_materials_reproduced_ec_mismatched_values_fails :538)."
  rationale: "The transition checks now stop a keyring from altering the EC afterwards (C07), but the merge itself is still the only guard that decrypt AAD equals encrypt AAD."
  scoring:
    severity: 3
    coverage_gap: 0.6
    feasibility: 0.4
    blast_radius: 4
    product: "3 × 0.6 × 0.4 × 4 = 2.88"
  quick_win: false
  dependencies: []
```

```yaml
recommendation:
  id: VR-2026-T09
  rank: 14
  priority_score: 2.56
  origin: threat-driven
  target:
    crate: aws-crypto-mpl
    file: mpl/src/structures/commitment_policy.rs; mpl/src/cmm/default_cmm.rs; mpl/src/structures/materials_checks.rs
    function: >
      CommitmentPolicy::{default_algorithm_suite_id (:43), allows_for_encrypt (:62), allows_for_decrypt (:77)};
      AlgorithmSuiteId::specification / key_commitment; DefaultCmm get_encryption_materials (:85, gate :97) /
      decrypt_materials (:177, gate :184); suite frame enforced by check_encryption_transition (materials_checks.rs:72) /
      check_decryption_transition (:117)
  property: >
    key_commitment() holds exactly for 0x0478 and 0x0578. The allow-tables match commitment-policy.md for
    3 policies × 11 suites, and each policy's default suite is encrypt-allowed (FORBID default is now
    0x0378, a documented deviation from the spec's 0x0014 that is still non-committing).
    get_encryption_materials returns Ok only with an encrypt-allowed suite; decrypt_materials returns Err
    without calling the keyring when the suite is not decrypt-allowed.
  formal_spec: |
    ensures p.allows_for_encrypt(id) <==> match p { Esdk(ForbidEncryptAllowDecrypt) => !committing(id), _ => committing(id) }
    ensures p.allows_for_decrypt(id) <==> match p { Esdk(RequireEncryptRequireDecrypt) => committing(id), _ => true }
    ensures p.allows_for_encrypt(p.default_algorithm_suite_id())
    fn get_encryption_materials(..) -> (r) ensures r matches Ok(o) ==> policy.allows_for_encrypt(o.materials.algorithm_suite_id())
    // keyring frame now a lemma of C07: check_encryption_transition Ok ⇒ suite unchanged
  tool: Verus
  agent: verus-header-parsing-proofs
  estimated_effort: 1 week
  threat_references:
    - {id: TM-MPL-006, category: Elevation of Privilege, description: "Algorithm-suite downgrade / commitment-policy bypass"}
    - {id: TM-MPL-008, category: Elevation of Privilege, description: "Non-committing suite reuse (Invisible Salamanders) — code-gate slice"}
  trace_to_spec: "spec/framework/commitment-policy.md; spec/framework/default-cmm.md#get-encryption-materials, #decrypt-materials"
  coverage_gap: 0.4
  coverage_evidence: >
    mpl/tests/test_commitment_policy.rs (full policy × suite table); mpl/tests/test_default_cmm.rs
    (e.g. test_decrypt_materials_unsupported_suite_for_policy_fails :382); mpl/tests/test_materials_checks.rs
    on_encrypt_rejects_a_changed_algorithm_suite (:271). The runtime transition check enforces the frame on every send().
  rationale: |
    Rescored (gap 0.5 → 0.4): the "keyring preserves the suite" assumption is now a runtime check on every
    fluent path, so a third-party keyring can no longer break the CMM postcondition through SharedKeyring.
    SharedCmm::send() checks completeness only, not the policy; the ESDK re-checks (esdk/src/materials.rs).
  scoring:
    severity: 4        # TM-MPL-006 Critical
    coverage_gap: 0.4
    feasibility: 0.4
    blast_radius: 4
    product: "4 × 0.4 × 0.4 × 4 = 2.56"
  quick_win: false
  dependencies: [VR-2026-C07]   # soft: frame lemma
```

```yaml
recommendation:
  id: VR-2026-T16
  rank: 15
  priority_score: 2.24
  origin: threat-driven
  target:
    crate: aws-crypto-mpl
    file: >
      mpl/src/aws_kms/branch_key_wrap.rs; mpl/src/aws_kms/hierarchical_keyring.rs; mpl/src/keyring/raw_aes_keyring.rs;
      mpl/src/structures/encryption_context.rs; mpl/src/aws_kms/mrk_match.rs; mpl/src/aws_kms/cache_entry_identifier.rs;
      mpl/src/cmm/default_cmm.rs; mpl/src/key_store/branch_key_store.rs; mpl/src/aws_kms/user_agent.rs
    function: >
      unwrap (guard :236, .expect :249/:252/:256); try_decrypt_edk (guard :879, .expect :892);
      on_decrypt UTF-8 filter (hierarchical :734); raw-AES on_decrypt split_at (:469) / decryptable_edk_iv split_at (:201/:206/:212);
      EncryptionContext::from_bytes (:145, offset arithmetic :166-197); aws_kms_mrk_match_for_decrypt pa[5]/pb[5] (:40-41);
      build_cache_identifier .expect (:64); DefaultCmm .expect (:123) and ecdsa_generate_keypair .expect (:138, BUG-05a);
      version_key `new_decrypt_only_ec[ATTR_TYPE]` (:719); user_agent_override .expect (user_agent.rs:17)
  property: >
    For every input (EDK ciphertext, provider info, serialized EC bytes, ARN strings) these paths return
    and never panic: each slice/index is preceded by a guard implying it is in range, each try_into
    length is exact, offset arithmetic cannot overflow.
  formal_spec: |
    fn unwrap(m, ec, ct) -> (r)          // total; ct.len() >= 60 ⇒ all slices in range
    fn try_decrypt_edk(..)               // ct.len() >= 44 ⇒ [28..44] has len 16
    fn from_bytes(b) -> (r)              // loop inv: offset <= b.len()
    fn aws_kms_mrk_match_for_decrypt(a, b) -> (r)   // is_multi_region_arn(x) ⇒ 6 segments ⇒ index 5 valid
    // EXPECTED-UNPROVABLE (report, do not axiomatize): default_cmm.rs:138 ecdsa_generate_keypair(..).expect (BUG-05a)
  tool: Verus
  agent: verus-zero-panic
  estimated_effort: 1 week
  threat_references:
    - {id: TM-MPL-023, category: Denial of Service, description: "Malformed EDK/ciphertext triggers panic instead of error"}
  trace_to_spec: "spec/framework/aws-kms/aws-kms-hierarchical-keyring.md#ondecrypt; spec/framework/raw-aes-keyring.md#ondecrypt; spec/framework/structures.md#serialization"
  coverage_gap: 0.7
  coverage_evidence: >
    unwrap_too_short_ciphertext_returns_error (:1187), on_decrypt_skips_edks_with_non_utf8_provider_info (:1841);
    test_raw_aes_keyring.rs negative provider-info tests; test_encryption_context.rs insufficient-bytes tests; test_aws_kms_mrk_match.rs.
  rationale: |
    The old key-store client `.expect` sites are gone (clients are non-Option after build, branch_key_store.rs:101-108).
    The storm-tracking `.expect`s (:199, :213, :227) are test-utils introspection accessors and out of scope.
    BUG-05(b) observation stands: a 44–59-byte EDK costs one cache/key-store lookup before unwrap rejects it.
  scoring:
    severity: 2        # TM-MPL-023 Medium
    coverage_gap: 0.7
    feasibility: 0.4
    blast_radius: 4
    product: "2 × 0.7 × 0.4 × 4 = 2.24"
  quick_win: false
  dependencies: []
```

```yaml
recommendation:
  id: VR-2026-T21
  rank: 16
  priority_score: 1.96
  origin: threat-driven
  target:
    crate: aws-crypto-mpl
    file: mpl/src/cmc/storm_tracking.rs
    function: >
      StormTrackingCmcBuilder::build (:606; checks :613, :616, :619, :622); StormTrackingCmc::{state_locked (:239),
      classify_and_mark (:264), wait_for_leader (:360)}; Cmc::put_cache_entry impl (inner put before clearing in-flight);
      within_grace_period (:661); within_grace_interval (:675)
  property: >
    (a) build returns Ok exactly when the spec constraints hold: fan_out ≥ 1, in_flight_ttl > 0, sleep > 0,
    grace_interval ≤ in_flight_ttl, AND grace_interval ≤ grace_period, in_flight_ttl ≤ grace_period, grace
    period and grace interval ≥ the spec minimum. EXPECTED TO FAIL: build no longer checks the
    grace_period orderings or minimums (mitigation regressed). (b) Under the mutex every production state
    step preserves |inflight| ≤ fan_out. (c) A key already in flight yields a new leader only after its grace
    interval. (d) put_cache_entry writes the inner cache before clearing the mark. (e) within_grace_* match
    the spec formulas. (f) A poisoned lock maps to Kind::Internal, never a panic.
  formal_spec: |
    fn build(self) -> (r) ensures r.is_Ok() <==> fo >= 1 && !it.is_zero() && !sl.is_zero() && gi <= it
                                              && gi <= gp && it <= gp && gp >= MIN && gi >= MIN   // FAILS today
    spec fn inv(s, fo) -> bool { s.inflight@.len() <= fo }
    fn classify_and_mark(&self, s, id, cached, now) -> (r) requires inv(*old(s), self.fan_out) ensures inv(*s, self.fan_out)
    fn within_grace_interval(t, now, gi) -> (r) requires st_add_ok(t, gi) ensures r <==> now < t + gi   // see T06
  tool: Verus
  agent: verus-zero-panic   # sequential slice; cat-4 interleavings → concurrency specialist
  estimated_effort: 1 month
  threat_references:
    - {id: TM-MPL-018, category: Denial of Service, description: "Storm-tracking misconfiguration or logic error"}
  trace_to_spec: "spec/framework/storm-tracking-cryptographic-materials-cache.md#initialization, #in-flight, #putcacheentry, #within-grace-period, #within-grace-interval"
  coverage_gap: 0.7
  coverage_evidence: >
    mpl/tests/test_storm_tracking_cmc.rs (33 tests, was 38): test_within_grace_interval_matches_spec_formula (:545),
    test_sub_second_grace_period_is_honored (:283), test_concurrent_gets_on_same_key_coalesce_to_one_refresh (:1295).
    test_durations_are_stored_exactly (:388) asserts grace_period = 0 is accepted, i.e. the tests encode the regressed contract.
  rationale: "Rescored (gap 0.6 → 0.7) because the spec-ordering tests are gone and (a) now has a known counterexample. Liveness and the Tokio-only runtime are excluded."
  scoring:
    severity: 2
    coverage_gap: 0.7
    feasibility: 0.7   # TM-MPL-018 Likelihood Medium
    blast_radius: 2    # storm-tracking cache (now also the DefaultCmc default with rt-tokio)
    product: "2 × 0.7 × 0.7 × 2 = 1.96"
  quick_win: false
  dependencies: [VR-2026-T06]
```

```yaml
recommendation:
  id: VR-2026-T15
  rank: 17
  priority_score: 1.92
  origin: threat-driven
  target:
    crate: aws-crypto-mpl
    file: mpl/src/structures/encryption_context.rs
    function: EncryptionContext::to_bytes (:91); EncryptionContext::from_bytes (:145; duplicate / order checks :198-211); utf8 (:231)
  property: >
    to_bytes returns Ok exactly when |ec| ≤ 65535 and every key and value ≤ 65535 bytes; then it emits the
    sorted spec layout. to_bytes is injective, from_bytes(to_bytes(ec)) == Ok(ec), and (now that BUG-03 is
    fixed) from_bytes(b) == Ok(ec) ⇒ to_bytes(ec) == Ok(b): accepted bytes are canonical.
  formal_spec: |
    fn to_bytes(&self) -> (r) ensures r matches Ok(b) ==> b@ == ser(self@)
    proof fn ser_injective(m1, m2) requires ser(m1) == ser(m2) ensures m1 == m2
    fn from_bytes(b) -> (r) ensures r matches Ok(ec) ==> ser(ec@) == b@      // expected to VERIFY on 620771c
    // open question for the owner, not a proof failure: from_bytes accepts empty keys (test :468)
  tool: Verus
  agent: verus-header-parsing-proofs
  estimated_effort: 2 weeks
  threat_references:
    - {id: TM-MPL-013, category: Tampering, description: "AAD consistency depends on EC serialization determinism"}
    - {id: TM-MPL-017, category: Tampering, description: "Bound context must survive the round trip"}
  trace_to_spec: "spec/framework/structures.md#serialization"
  coverage_gap: 0.4
  coverage_evidence: >
    mpl/tests/test_encryption_context.rs (45 tests, was 37): test_round_trip_preserves_all_entries (:79),
    test_out_of_order_keys_rejected_on_deserialize (:68), invalid-UTF-8 tests (:502-533),
    test_deserialize_accepts_empty_key_length_currently_unenforced (:468). from_bytes now enforces order, uniqueness and UTF-8 at runtime.
  rationale: "Rescored after BUG-03 fix: the previous expected counterexample no longer exists, so the non-malleability theorem becomes the goal."
  scoring:
    severity: 3        # TM-MPL-013 High
    coverage_gap: 0.4
    feasibility: 0.4
    blast_radius: 4
    product: "3 × 0.4 × 0.4 × 4 = 1.92"
  quick_win: false
  dependencies: []
```

```yaml
recommendation:
  id: VR-2026-T17
  rank: 18
  priority_score: 1.92
  origin: threat-driven
  target:
    crate: aws-crypto-mpl
    file: mpl/src/key_store/kms_ops.rs; mpl/src/key_store/kms_config.rs
    function: resolve_key_store_arn Discovery arm (:96-98) / MrDiscovery arm (:100-102); reject_alias_arn (:118); rewrite_arn_region (:144); parse_arn (kms_config.rs:31)
  property: >
    Discovery: Ok(record ARN) exactly when parse_arn succeeds and resource_type ≠ "alias".
    MrDiscovery: the region is rewritten only for MRK ARNs ("key/mrk-"), per branch-key-store.md#mrdiscovery.
    EXPECTED TO FAIL (BUG-04 open): rewrite_arn_region rewrites every non-alias ARN, including
    single-Region keys; it fails closed at KMS.
  formal_spec: |
    fn resolve_key_store_arn(c, rec, bkid) -> (r)
      ensures c is Discovery ==> (r.is_Ok() <==> parse_arn_spec(rec@) matches Ok(p) && p.resource_type@ != "alias"@)
      ensures c matches MrDiscovery(m) && r matches Ok(k) ==>
                (is_mrk(rec@) ==> parse_arn_spec(k@) == Ok(parse_arn_spec(rec@)->Ok_0.with_region(m.region@)))
             && (!is_mrk(rec@) ==> k@ == rec@)          // FAILS today (BUG-04)
    proof fn parse_format_round_trip(p) requires well_formed(p) ensures parse_arn_spec(format_spec(p)) == Ok(p)
  tool: Verus
  agent: verus-header-parsing-proofs
  estimated_effort: 1 week
  threat_references:
    - {id: TM-MPL-007, category: Elevation of Privilege, description: "Discovery/MRDiscovery decrypts under an alias or attacker-region key"}
  trace_to_spec: "spec/framework/branch-key-store.md#discovery, #mrdiscovery, #aws-kms-branch-key-decryption"
  coverage_gap: 0.8
  coverage_evidence: >
    test_key_store_kms_config.rs parse_arn tests; test_key_store_branch_key_store.rs new_with_mr_discovery_config_succeeds (:245)
    and discovery create/version rejection tests. reject_alias_arn and rewrite_arn_region are private with no unit test; no non-MRK MRDiscovery test.
  rationale: "BUG-04 confirmed by RECHECK; the proof both documents the deviation and verifies the fix once an `mrk-` check is added."
  scoring:
    severity: 3
    coverage_gap: 0.8
    feasibility: 0.4
    blast_radius: 2    # opt-in Discovery / MRDiscovery
    product: "3 × 0.8 × 0.4 × 2 = 1.92"
  quick_win: false
  dependencies: []
```

```yaml
recommendation:
  id: VR-2026-T18
  rank: 19
  priority_score: 1.92
  origin: threat-driven
  target:
    crate: aws-crypto-mpl
    file: mpl/src/key_store/branch_key_store.rs
    function: >
      <Builtin<DynamoDbKeyStore> as KeyStore>::version_key (:641) — authentication ReEncrypt with old_active_ec
      (:671, :678) and the inline EC derivation (:706-722); conditional writes (:743, :752)
  property: >
    New DECRYPT_ONLY EC = old minus `version`, type = "branch:version:"+v, create-time = ts. New ACTIVE EC =
    DECRYPT_ONLY with version = "branch:version:"+v and type = "branch:ACTIVE". Both preserve branch-key-id,
    kms-arn, hierarchy-version, tablename and every `aws-crypto-ec:` entry, and agree with
    key_store::encryption_context::{decrypt_only,active}_encryption_context for the same inputs.
  formal_spec: |
    fn derive_version_ecs(old, v, ts) -> (r) requires old@["type"@] == "branch:ACTIVE"@
      ensures r.0@ == old@.remove("version"@).insert("type"@, "branch:version:"@ + v@).insert("create-time"@, ts@)
      ensures r.1@ == r.0@.insert("version"@, "branch:version:"@ + v@).insert("type"@, "branch:ACTIVE"@)
  tool: Verus
  agent: verus-header-parsing-proofs
  estimated_effort: 1 week
  threat_references:
    - {id: TM-MPL-016, category: Tampering, description: "VersionKey optimistic-lock bypass — EC derivation + self-authentication slice"}
  trace_to_spec: "spec/framework/branch-key-store.md#versionkey, #authenticating-a-keystore-item"
  coverage_gap: 0.8
  coverage_evidence: "test_key_store_branch_key_store.rs (version_key dispatch / discovery rejection); live-AWS integ only for the derivation; test_key_store_encryption_context.rs::active_is_decrypt_only_with_type_and_version_overrides (:214) covers the other module."
  rationale: "version_key still builds the new ECs inline. DDB transaction semantics excluded."
  scoring:
    severity: 2
    coverage_gap: 0.8
    feasibility: 0.4
    blast_radius: 3
    product: "2 × 0.8 × 0.4 × 3 = 1.92"
  quick_win: false
  dependencies: [VR-2026-T01]
```

```yaml
recommendation:
  id: VR-2026-T19
  rank: 20
  priority_score: 1.92
  origin: threat-driven
  target:
    crate: aws-crypto-mpl
    file: mpl/src/aws_kms/hierarchical_keyring.rs
    function: >
      resolve_branch_key_id (:831); on_decrypt filter (:734, bkid compare :760); try_decrypt_edk (:867) →
      decrypt_edk_at_version (:901, cache id :908); on_encrypt EDK provider info (:722); BranchKeyIdSupplier trait (:187)
  property: >
    Static id configured ⇒ resolve returns exactly it. on_decrypt attempts an EDK only if provider id ==
    "aws-kms-hierarchy" and utf8(provider info) == resolved bkid. The key-store/cache query uses that bkid and
    the version decoded from ct[28..44]. on_encrypt emits provider info = resolved bkid bytes.
  formal_spec: |
    fn on_decrypt(&self, input) -> (r) ensures forall|e| ghost_attempted.contains(e) ==> e.key_provider_id@ == "aws-kms-hierarchy"@
              && utf8_decode(e.key_provider_info@) == Some(ghost_bkid@)
    fn on_encrypt(&self, input) -> (r) ensures r matches Ok(o) ==> o.materials.edks@.last().key_provider_info@ == ghost_bkid@.as_bytes()
  tool: Verus
  agent: verus-header-parsing-proofs
  estimated_effort: 1 week
  threat_references:
    - {id: TM-MPL-003, category: Spoofing, description: "Malicious supplier returns attacker-chosen id — the id is bound consistently"}
  trace_to_spec: "spec/framework/aws-kms/aws-kms-hierarchical-keyring.md#onencrypt, #ondecrypt, #branch-key-supplier"
  coverage_gap: 0.6
  coverage_evidence: "on_decrypt_skips_edks_with_wrong_branch_key_id (:1872), ..._non_utf8_provider_info (:1841), on_encrypt/on_decrypt_uses_branch_key_id_supplier_when_configured (:1640, :2161)."
  rationale: "Observation stands: the returned materials' bkid/version are not compared with the request (TB7); decrypt fails closed through the AAD. A supplier returning NUL-containing ids is a BUG-06 path (T13)."
  scoring:
    severity: 2
    coverage_gap: 0.6
    feasibility: 0.4
    blast_radius: 4
    product: "2 × 0.6 × 0.4 × 4 = 1.92"
  quick_win: false
  dependencies: [VR-2026-T13]
```

```yaml
recommendation:
  id: VR-2026-T20
  rank: 21
  priority_score: 1.68
  origin: threat-driven
  target:
    crate: aws-crypto-mpl
    file: mpl/src/keyring/raw_aes_keyring.rs
    function: RawAesKeyring::serialize_provider_info (:129); RawAesKeyring::decryptable_edk_iv (:191)
  property: >
    serialize_provider_info(iv) = key_name ‖ be32(128) ‖ be32(12) ‖ iv. decryptable_edk_iv returns Some(iv)
    exactly when provider id == namespace and info has that shape for a 12-byte iv. Round trip holds. Total.
  formal_spec: |
    fn serialize_provider_info(&self, iv) -> (r) requires iv@.len() == 12 ensures r@ == info(self.key_name@, iv@)
    fn decryptable_edk_iv(&self, e) -> (r) ensures r matches Some(iv) <==> e.key_provider_id@ == self.key_namespace@
              && iv@.len() == 12 && e.key_provider_info@ == info(self.key_name@, iv@)
  tool: Verus
  agent: verus-header-parsing-proofs
  estimated_effort: 1 week
  threat_references:
    - {id: TM-MPL-023, category: Denial of Service, description: "Malformed provider info rejected, not panic"}
    - {id: TM-MPL-011, category: Elevation of Privilege, description: "Decryptor uses exactly the encryptor's IV"}
    - {id: TM-MPL-001, category: Spoofing, description: "Provider-id filter on decrypt"}
  trace_to_spec: "spec/framework/raw-aes-keyring.md#key-provider-information, #ondecrypt"
  coverage_gap: 0.7
  coverage_evidence: "test_raw_aes_keyring.rs: test_encrypted_data_key_wire_format (:406) and provider-info / short-ciphertext negative tests (:619, :658, :696)."
  rationale: "Small binary codec; parser half of T07. Unchanged."
  scoring:
    severity: 2
    coverage_gap: 0.7
    feasibility: 0.4
    blast_radius: 3
    product: "2 × 0.7 × 0.4 × 3 = 1.68"
  quick_win: false
  dependencies: []
```

```yaml
recommendation:
  id: VR-2026-T22
  rank: 22
  priority_score: 1.60
  origin: threat-driven
  target:
    crate: aws-crypto-mpl + aws-mpl-primitives
    file: mpl/src/structures/{algorithm_suite.rs, branch_key_materials.rs, beacon_key_materials.rs, encrypted_data_key.rs}; mpl/src/keyring/raw_aes_keyring.rs; prim/src/ecdsa.rs
    function: >
      Debug for PlaintextDataKey, SigningKey, SymmetricSigningKey (algorithm_suite.rs), BranchKeyMaterials, BeaconKeyMaterials,
      RawAesKeyring (raw_aes_keyring.rs:81), SignatureKeyPair (ecdsa.rs:336); derived Debug of materials / CacheEntry;
      DataKeyInfo attached to errors (Error::with_encrypted_data_keys)
  property: >
    Noninterference: each Debug output, and each error's attached DataKeyInfo, depends only on non-secret
    fields and never on secret bytes or EDK ciphertext.
  formal_spec: |
    proof fn pdk_redacted(k1, k2) requires k1.len() == k2.len() ensures fmt_spec(PlaintextDataKey(k1)) == fmt_spec(PlaintextDataKey(k2))
    proof fn data_key_info_no_ciphertext(e1, e2) requires same_provider(e1, e2) ensures DataKeyInfo::from(e1) == DataKeyInfo::from(e2)
  tool: Verus
  agent: verus-unsafe-ffi-safety
  estimated_effort: 1 week
  threat_references:
    - {id: TM-MPL-021, category: Information Disclosure, description: "Secret bytes leak via Debug/error/log formatting"}
  trace_to_spec: "baseline assurance, no single clause"
  coverage_gap: 0.5
  coverage_evidence: "test_algorithm_suite.rs::test_plaintext_data_key_debug_redacts (:21) and siblings; test_raw_aes_keyring.rs::test_debug_does_not_leak_the_wrapping_key (:827); prim/tests/test_ecdsa.rs."
  rationale: "Previous residual closed in code; the proof upgrades substring tests to an all-values guarantee and now also covers the new error model."
  scoring:
    severity: 2
    coverage_gap: 0.5
    feasibility: 0.4
    blast_radius: 4
    product: "2 × 0.5 × 0.4 × 4 = 1.60"
  quick_win: false
  dependencies: []
```

```yaml
recommendation:
  id: VR-2026-T25
  rank: 23
  priority_score: 1.44
  origin: threat-driven
  target:
    crate: aws-esdk-cpp shim (esdk/shims/aws-esdk-cpp, outside mpl/ and prim/)
    file: esdk/shims/aws-esdk-cpp/src/lib.rs
    function: >
      require_handle (:715; null check :720; `unsafe { &*ptr }` :728); key-store builder nullable client handles
      (`unsafe { input.kms_client.as_ref() }` :1564, `ddb_client` :1565); hierarchical keyring nullable cache handle (:1655);
      into_keyring_handle (:2054, Box::into_raw)
  property: >
    Every raw-handle dereference in the shim is dominated by a null check; a null required handle yields a
    Validation error and never a dereference; a null optional handle yields None (core default); no handle
    is dereferenced after the shim itself frees it. The validity of a NON-null C++-supplied pointer is a
    caller precondition (spec shim.md#handles-and-lifetimes), modeled as a trusted PointsTo permission
    at the FFI boundary — it is not proven.
  formal_spec: |
    fn require_handle<T>(ptr: *const T, name, op) -> (r: Result<&T, String>)
      requires ptr != null ==> ffi_valid(ptr)          // TCB: caller lifetime contract (shim.md#handles-and-lifetimes)
      ensures ptr == null <==> r.is_Err()
      ensures r matches Ok(x) ==> addr_of(x) == ptr
    // each `unsafe` site: ghost proof that the deref is reached only on a non-null pointer, under the same requires
  tool: Verus
  agent: verus-unsafe-ffi-safety
  estimated_effort: 1 week
  threat_references:
    - {id: TM-MPL-024, category: Elevation of Privilege / Tampering, description: "C++ shim dereferences a dangling or forged handle to an MPL object"}
  trace_to_spec: "spec/shim/shim.md#handles-and-lifetimes (annotated at lib.rs:718-719); spec/shim/esdk-shim.md#create-hierarchical-keyring"
  coverage_gap: 0.6
  coverage_evidence: >
    esdk/shims/aws-esdk-cpp/src/tests.rs: require_handle_rejects_null_and_borrows_non_null (:715),
    encrypt_rejects_null_keyring (:733), decrypt_rejects_null_keyring (:746),
    create_hierarchical_keyring_rejects_null_key_store (:791). Dangling / forged handles are not testable.
  rationale: |
    New threat (e9bde48 retargeted the shim onto the native MPL). It is the only `unsafe` reaching MPL key
    material. The provable slice is small (null-dominance and no self-use-after-free); the dangerous part,
    a dangling or type-confused non-null pointer from C++, is excluded as a caller obligation. Owner: the shim.
    Suggested hardening (owner decision): generation-checked handles instead of raw pointers.
  scoring:
    severity: 3        # TM-MPL-024 High
    coverage_gap: 0.6
    feasibility: 0.4   # Likelihood Low
    blast_radius: 2    # C++ shim consumers only
    product: "3 × 0.6 × 0.4 × 2 = 1.44"
  quick_win: false
  dependencies: []
```

```yaml
recommendation:
  id: VR-2026-T23
  rank: 24
  priority_score: 1.26
  origin: threat-driven
  target:
    crate: aws-crypto-mpl
    file: mpl/src/cmc/local.rs
    function: LocalCmc::{with_clock (:83), get_fresh (:131), prune_tail (:166; min at :167)}; Cmc impl put_cache_entry (:280), get_cache_entry (:302), delete_cache_entry (:311)
  property: >
    inner is None exactly when entry_capacity == 0, else len ≤ entry_capacity after every operation. get never
    returns an entry with expiry_time ≤ now. prune_tail scans min(tail, len) entries. A poisoned lock is Err.
  formal_spec: |
    spec fn inv(c) -> bool { (c.store is None <==> c.entry_capacity == 0) && (c.store matches Some(l) ==> l@.len() <= c.entry_capacity) }
    fn put_cache_entry(&self, i) -> (r) requires inv(*self) ensures inv(*self)
    fn get_cache_entry(&self, i) -> (r) ensures r matches Ok(o) && o.entry matches Some(e) ==> e.expiry_time() > ghost_now
  tool: Verus
  agent: verus-zero-panic
  estimated_effort: 2 weeks
  threat_references:
    - {id: TM-MPL-022, category: Denial of Service, description: "Cache exhaustion / eviction thrash — capacity + TTL invariants"}
  trace_to_spec: "spec/framework/local-cryptographic-materials-cache.md#entry-capacity, #put-cache-entry, #get-cache-entry, #pruning"
  coverage_gap: 0.6
  coverage_evidence: "test_local_cmc.rs (20 tests): test_capacity_invariant_holds_after_put_returns (:299), test_pruning_evicts_all_ttl_expired_in_tail (:428). The four new tests are usage-metadata tests (C08)."
  rationale: "Foundation for StormTrackingCmc/DefaultCmc (T21). The default cache is now DefaultCmc over this LRU."
  scoring:
    severity: 1        # TM-MPL-022 Low
    coverage_gap: 0.6
    feasibility: 0.7   # Likelihood Medium
    blast_radius: 3
    product: "1 × 0.6 × 0.7 × 3 = 1.26"
  quick_win: false
  dependencies: []
```

```yaml
recommendation:
  id: VR-2026-T24
  rank: 25
  priority_score: 1.20
  origin: threat-driven
  target:
    crate: aws-crypto-mpl
    file: mpl/src/keyring/raw_aes_keyring.rs
    function: RawAesKeyringBuilder::build (:350; prefix check :360 against RESERVED_KEY_NAMESPACE_PREFIX :52); on_encrypt provider id
  property: "build returns Err for every namespace starting with \"aws-kms\", so no built keyring or emitted EDK has such a provider id."
  formal_spec: |
    fn build(self) -> (r) ensures starts_with(ns@, "aws-kms"@) ==> r.is_Err()
                          ensures r matches Ok(k) ==> !starts_with(k.key_namespace()@, "aws-kms"@)
  tool: Verus
  agent: verus-header-parsing-proofs
  estimated_effort: 1 day
  threat_references:
    - {id: TM-MPL-001, category: Spoofing, description: "Raw-AES EDK impersonates an AWS KMS keyring"}
  trace_to_spec: "spec/framework/raw-aes-keyring.md#initialization"
  coverage_gap: 0.5
  coverage_evidence: "test_raw_aes_keyring.rs::test_build_rejects_reserved_aws_kms_key_namespace (:769) and siblings."
  rationale: "Trivial, well tested; kept so TM-MPL-001 has a proof-grade closure. The check moved from new() into build()."
  scoring:
    severity: 2
    coverage_gap: 0.5
    feasibility: 0.4
    blast_radius: 3
    product: "2 × 0.5 × 0.4 × 3 = 1.20"
  quick_win: false
  dependencies: []
```

```yaml
recommendation:
  id: VR-2026-T08
  status: Retired
  retired_in: 620771c refresh
  previous_score: 3.84
  origin: threat-driven
  former_target: "PlaintextDataKey::zeroize — the unsafe write_volatile loop (was mpl/src/structures/algorithm_suite.rs:439 at a1e23d7)"
  reason: >
    Code gone. a864ad8 (#131) replaced the hand-written unsafe loop with
    #[derive(Clone, Zeroize, ZeroizeOnDrop)] on PlaintextDataKey (algorithm_suite.rs:505); SigningKey (:571)
    and SymmetricSigningKey (:655) got the same derive. `\bunsafe\b` has no match in mpl/src or prim/src.
    The zeroize crate's own implementation is third-party (TCB).
  successor: VR-2026-T26 (TM-MPL-015 residual: transient and error-path buffers)
  threat_references_at_retirement: [TM-MPL-015]   # threat still active; now mapped to T26
```

## 4. Excluded (not Verus-provable, or not present in this repo)

**Fully excluded** = no provable code slice. **Partial** = the slice is a target above; only the listed remainder is excluded.

| Threat | Scope | Excluded part | Reason |
|---|---|---|---|
| TM-MPL-019 | **Fully excluded** | Missing Duvet coverage (1 annotation, no MPL config); spec floats on `master` (#91) | Process / traceability tooling; no code property |
| TM-MPL-020 | **Fully excluded** | No audit binding between MPL operations and KMS/DDB calls | Operational control (CloudTrail; user agent `AwsCryptographicMPL-Rust/<version>` at `aws_kms/user_agent.rs:16-19`) |
| TM-MPL-001 | Partial (→ T24, T20) | Downstream case-insensitive provider-id trust | Other components |
| TM-MPL-002 | Partial (→ T03, T01) | KMS key policy / grants; KMS enforcing EC-as-AAD; Discovery trusting the record ARN | External service; configuration |
| TM-MPL-003 | Partial (→ T19) | Correctness of a caller-supplied `BranchKeyIdSupplier` | Caller code |
| TM-MPL-004 | Partial (→ T11) | KMS guarantee that MRK replicas share key material | External service |
| TM-MPL-005 | Partial (→ T01, T02) | Rollback/replay of an older authentic record; AEAD integrity; user-supplied `KeyStore` output (TB7) | Storage freshness; crypto hardness; trusted caller code |
| TM-MPL-006 | Partial (→ T09) | Cryptographic security of key commitment; ESDK message-level checks | Crypto hardness; out of MPL scope |
| TM-MPL-007 | Partial (→ T17) | KMS regional availability; KMS rejecting wrong-region ARNs | External service |
| TM-MPL-008 | Partial (→ T09) | Invisible-Salamanders resistance of commit-key suites; future caching CMM (CVE-2026-6550 class) | Crypto hardness; code does not exist |
| TM-MPL-009 | Partial (→ T13) | SHA-384 collision resistance; operators reusing a logical name across stores | Crypto hardness; unenforceable config MUST |
| TM-MPL-010 | Partial (→ T14, T13) | Partition-id randomness; operator choice to share; user `Cmc` returning arbitrary entries or `grace_period() = None` (`cmc/mod.rs`) | Probabilistic; operational; trusted caller code |
| TM-MPL-011 | Partial (→ T07, T20) | CSPRNG quality; 96-bit nonce birthday bound | Probabilistic |
| TM-MPL-012 | Partial (→ T04) | 224-bit salt‖IV collision bound; rotation cadence | Probabilistic + operational |
| TM-MPL-013 | Partial (→ T10, T15) | GCM's cryptographic binding of AAD | Crypto hardness |
| TM-MPL-014 | Partial (→ T05) | HMAC-SHA-256 PRF security; aws-lc-rs KBKDF correctness | Crypto hardness / third-party |
| TM-MPL-015 | Partial (→ T26) | `Vec` reallocation copies; allocator/OS residency (heap, swap, core dumps); aws-lc internal buffers; cache holding branch keys for the TTL by design; `zeroize` crate internals | Outside Verus's memory model or by design; third-party TCB |
| TM-MPL-016 | Partial (→ T18) | DynamoDB `TransactWriteItems` atomicity and condition evaluation | External service |
| TM-MPL-017 | Fully targeted (→ T12, T15) | — | — |
| TM-MPL-018 | Partial (→ T21, T06) | Liveness under a real scheduler; Tokio-only runtime; wall clock | Deployment constraints |
| TM-MPL-021 | Partial (→ T22) | What applications log; AWS SDK error-cause contents | External code |
| TM-MPL-022 | Partial (→ T23, T06) | KMS throttling under eviction thrash; capacity sizing | Performance / operations |
| TM-MPL-023 | Partial (→ T16, T20, T06) | `ecdsa_generate_keypair(..).expect` success (BUG-05a) | Needs an unjustified "always Ok" axiom; kept in T16 as an expected-unprovable finding |
| TM-MPL-024 | Partial (→ T25) | Validity / lifetime / type of a non-null C++-supplied pointer; C++ caller code; `cxx` bridge internals | Caller obligation across FFI; third-party TCB |

## 5. Corrections and notes against the threat model

| # | Threat-model text | Reality on 620771c | Effect |
|---|---|---|---|
| C1 | TM-MPL-023 listed `branch_key_wrap.rs:240` as the 60-byte guard | The guard is at `branch_key_wrap.rs:236` (`if ciphertext.len() < FIXED_OVERHEAD_LEN`); `:240` is inside the error message | T16 cites `:236`. **Resolved** in the verification pass: the threat model now cites `:236` |
| C2 | TM-MPL-015 mitigation lines in `branch_key_materials.rs` / `beacon_key_materials.rs` | Re-checked with `sed -n` in the verification pass: `branch_key_materials.rs:205` is `impl Drop for BranchKeyMaterials`, `beacon_key_materials.rs:221-235` are the `Drop` / `ZeroizeOnDrop` impls. No active target cites them | none |

New / still-open findings recorded in targets and **not changed** (owner decisions): T06 (BUG-01), T13 (BUG-06), T17 (BUG-04), T16 (BUG-05a/b), T21 (storm-tracking spec ordering regressed), T26 (BUG-07a and unwiped decrypt buffers), C01(c) (BUG-08 dead branch).

## 6. Accounting — every threat mapped

| Threat | Severity / Likelihood | Target(s) | Exclusion |
|---|---|---|---|
| TM-MPL-001 | Medium / Low | T24, T20 | Partial |
| TM-MPL-002 | Critical / Low | T03, T01 | Partial |
| TM-MPL-003 | Medium / Low | T19 | Partial |
| TM-MPL-004 | High / Low | T11 | Partial |
| TM-MPL-005 | Critical / Medium | T01, T02 | Partial |
| TM-MPL-006 | Critical / Low | T09 | Partial |
| TM-MPL-007 | High / Low | T17 | Partial |
| TM-MPL-008 | High / Low | T09 | Partial |
| TM-MPL-009 | High / **Medium** | T13 | Partial |
| TM-MPL-010 | High / **Medium** | T14, T13 | Partial |
| TM-MPL-011 | Critical / Low | T07, T20 | Partial |
| TM-MPL-012 | Critical / Low | T04 | Partial |
| TM-MPL-013 | High / Low | T10, T15 | Partial |
| TM-MPL-014 | High / Low | T05 | Partial |
| TM-MPL-015 | **Medium** / Low | **T26** (T08 retired) | Partial |
| TM-MPL-016 | Medium / Low | T18 | Partial |
| TM-MPL-017 | High / Low | T12, T15 | None |
| TM-MPL-018 | Medium / Medium | T21, T06 | Partial |
| TM-MPL-019 | Medium / Medium | — | **Fully excluded** |
| TM-MPL-020 | Low / Low | — | **Fully excluded** |
| TM-MPL-021 | Medium / Low | T22 | Partial |
| TM-MPL-022 | Low / Medium | T23, T06 | Partial |
| TM-MPL-023 | Medium / Low | T16, T20, T06 | Partial |
| TM-MPL-024 | High / Low | **T25** (new) | Partial |

Totals: **25 active threat-driven targets** (T01–T07, T09–T26) plus **1 retired** (T08). All 24 threat IDs TM-MPL-001..024 are accounted for: 22 have at least one active target, 2 are fully excluded (019, 020), 1 is fully targeted (017), 21 carry partial exclusions. No active target cites a retired threat (there are none) or retired code.
