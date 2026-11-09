# Threat-Driven Verus Verification Targets — AWS MPL (native Rust)

> Pipeline artifact — Stage 3, Step 1 of 4 (threat-driven entry path).
> Inputs: `docs/threat-model.md` (TM-MPL-001..023), `docs/spec-security-analysis.md`, `mpl/src`, `prim/src`, `mpl/tests`, `prim/tests`, `spec/framework/*.md`.
> Methodology: `.kiro/agents/verification-recommender.md`, `.kiro/agents/ai-verification-pipeline.md`, `.kiro/agents/verus-capabilities.md` (Provable vs. Not-Here decision aid).
> Every target below has `origin: threat-driven`. Capability-driven targets are a separate step.

## 0. Repo facts re-confirmed for this step

- **Exactly one `unsafe` block**: `mpl/src/structures/algorithm_suite.rs:439`, inside `PlaintextDataKey::zeroize` (a `core::ptr::write_volatile(ptr.add(i), 0u8)` loop). A search for `unsafe` across `mpl/src` and `prim/src` finds only that block plus `prim/src/lib.rs:30`, which is the lint name `unsafe_op_in_unsafe_fn` and not code.
- **No raw C FFI.** `prim` calls `aws-lc-rs` only through its safe API (`UnboundKey`, `LessSafeKey`, `Nonce::try_assume_unique_for_key`, `hmac::sign`, `digest::digest`, `kdf::kbkdf_ctr_hmac`, `EcdsaKeyPair`, `rand::fill`). There is no `extern "C"`, no `*mut u8` passed to C, and no `set_len`.
- **No Duvet annotations on this branch.** `mpl/src`, `mpl/tests`, `prim/src` and `prim/tests` contain no `//=` / `//#` annotations. The only textual hit is prose inside a normal `//` comment at `mpl/tests/test_local_cmc.rs:303`. So every coverage-gap reduction below is justified only by named tests in `mpl/tests/*.rs` and `prim/tests/*.rs`.
- **`PlaintextDataKey::zeroize` has zero call sites in `mpl/src`.** Only the tests call it: `test_encryption_materials.rs::test_plaintext_data_key_zeroize` and `test_decryption_materials.rs::test_plaintext_data_key_zeroize_decryption`. No `Drop` impl exists anywhere in `mpl/src` or `prim/src`.
- **Advisory CVE-2026-6550 / GHSA-v638-38fc-rhfv stays UNVERIFIED** here, as the threat model marks it. A web search in this step returned pages that look related: a [GitHub advisory](https://github.com/advisories/GHSA-v638-38fc-rhfv), an [NVD entry](https://nvd.nist.gov/vuln/detail/CVE-2026-6550) and an [AWS bulletin](https://aws.amazon.com/security/security-bulletins/2026-017-aws/). They describe a shared-key-cache commitment bypass in the caching layer of the *Python* ESDK (content rephrased for compliance with licensing restrictions). This step did not validate those pages. No score below depends on the identifier. Also, this repo has **no caching CMM** (see Correction C4), so that advisory's code surface has no direct counterpart here.

## 1. Scoring conventions (applied uniformly)

`Priority = Severity × Coverage_Gap × Feasibility × Blast_Radius`

| Factor | Rule used in this document |
|---|---|
| Severity (1–4) | Comes from the threat-model risk matrix for the target's **primary** threat: Critical=4, High=3, Medium=2, Low=1. Each threat keeps the same severity in every target that cites it. |
| Feasibility (0–1) | Comes from the threat-model Likelihood of the primary threat: **Low → 0.4, Medium → 0.7**. The same mapping is used everywhere. |
| Blast_Radius (1–4) | 4 = a path every MPL consumer or every hierarchical-keyring/keystore/CMM user goes through. 3 = a widely used but feature-specific path (raw AES keyring, cache-identifier/shared cache, keystore VersionKey). 2 = an opt-in configuration (storm-tracking cache, Discovery/MRDiscovery). 1 = narrow. |
| Coverage_Gap (0–1) | 1.0 = no test exercises the property. 0.9 = only tests that cannot detect a defect (for example a symmetric round-trip). 0.8 = some unit tests, or private code exercised only by live-AWS integration tests. 0.7 = direct unit tests including negative cases. 0.6 = broad example-based tests of most branches. 0.5 = near-exhaustive tests over a small finite domain. Tests lower the gap but never close it. |

Product arithmetic is exact. Each YAML block shows `S × G × F × B = score`.

Proof-technique notes that apply to many targets:
- Several properties live inside `async fn`s that call AWS SDK clients (`on_encrypt`, `version_key`, ...). To verify them, the **pure fragment** has to be extracted into a helper function. That is a behavior-preserving refactor done during the proof stage. It is noted per target and not done here.
- External crates (`uuid`, `lru`, `aws-lc-rs`, `std::time::SystemTime`, `core::fmt`) need Verus external specifications. Those become **trusted assumptions (TCB)** and must be listed in each proof. They must never be used as `external_body` / `assume` to force a pass (`verus` skill soundness rules).

## 2. Summary table (ranked)

| Rank | ID | Score | Origin | Target | Property | Agent | Ref | Effort |
|---|---|---|---|---|---|---|---|---|
| 1 | VR-2026-T01 | 8.96 | T | keystore EC builders (`build_authenticated_encryption_context`, `BranchKeyStore::build_auth_ec`, `item_from_ec_and_enc`, `record_from_ddb_item`) | Write-time EC == KMS-AAD EC == reconstruction EC (round-trip) | verus-header-parsing-proofs | TM-MPL-005, TM-MPL-002 | 2 weeks |
| 2 | VR-2026-T02 | 6.72 | T | `record::branch_key_materials_from_authenticated_encryption_context` | Exact Ok/Err characterization of reconstruction | verus-header-parsing-proofs | TM-MPL-005 | 1 week (quick win) |
| 3 | VR-2026-T03 | 5.12 | T | `kms_ops::resolve_keystore_arn` (pinned modes) | KMS KeyId is always the configured ARN | verus-header-parsing-proofs | TM-MPL-002 | 1 day |
| 4 | VR-2026-T04 | 4.48 | T | `branch_key_wrap::wrap` | Fresh-per-call 16B salt + 12B IV, exact 60+n layout, AES-256 preconditions | verus-unsafe-ffi-safety | TM-MPL-012 | 1 week |
| 5 | VR-2026-T05 | 4.32 | T | `branch_key_wrap::derive_branch_key` | KBKDF fixed-info = label‖0x00‖salt‖be32(256), 32B out | verus-header-parsing-proofs | TM-MPL-014 | 1 day |
| 6 | VR-2026-T06 | 4.20 | T | `SystemTime + Duration` sites in hierarchical keyring + storm tracking | No overflow panic for any accepted config (expected to FAIL as written) | verus-zero-panic | TM-MPL-018, TM-MPL-022, TM-MPL-023 | 1 week |
| 7 | VR-2026-T07 | 3.84 | T | `RawAesKeyring::{new,on_encrypt,on_decrypt}` + `prim::aes_{en,de}crypt` | Fresh 12B IV per call; key/IV/tag/output length preconditions | verus-unsafe-ffi-safety | TM-MPL-011 | 1 week |
| 8 | VR-2026-T08 | 3.84 | T | `PlaintextDataKey::zeroize` (the one unsafe block) | In-bounds volatile writes; post-state all zero, len unchanged | verus-unsafe-ffi-safety | TM-MPL-015 | 1 week |
| 9 | VR-2026-T09 | 3.20 | T | `CommitmentPolicy::*`, `AlgorithmSuiteId::specification`, `DefaultCmm` | Policy allow-tables match spec; CMM gates encrypt/decrypt | verus-header-parsing-proofs | TM-MPL-006, TM-MPL-008 | 1 week |
| 10 | VR-2026-T10 | 2.88 | T | `branch_key_wrap::compute_aad`, `uuid_str_to_16_bytes`, `uuid_16_bytes_to_str` | AAD layout exact; UUID byte/string round-trip; wrap/unwrap symmetry | verus-header-parsing-proofs | TM-MPL-013 | 1 week |
| 11 | VR-2026-T11 | 2.88 | T | `aws_kms_mrk_match_for_decrypt`, `is_arn_compatible` | Match iff identical or MRKs equal except region; aliases rejected | verus-header-parsing-proofs | TM-MPL-004 | 2 weeks |
| 12 | VR-2026-T12 | 2.88 | T | `default_cmm::merge_reproduced_encryption_context` | Merged EC = union on agreement; nothing dropped/altered; RECK = new keys | verus-header-parsing-proofs | TM-MPL-017 | 1 week |
| 13 | VR-2026-T13 | 2.52 | T | `cache_entry_identifier::build_cache_identifier` | Exact preimage; scope separation; injectivity under NUL-free precondition | verus-header-parsing-proofs | TM-MPL-009, TM-MPL-010 | 1 week |
| 14 | VR-2026-T14 | 2.52 | T | `as_branch_key_materials`, `generate_partition_id`, `cache_entry_within_limits` | Only BranchKey entries consumed; v4 16B partition id; TTL gate | verus-header-parsing-proofs | TM-MPL-010 | 1 week |
| 15 | VR-2026-T15 | 2.40 | T | `EncryptionContext::{serialize,deserialize}` | deserialize∘serialize = id; serialize injective (unsorted-accept counterexample expected) | verus-header-parsing-proofs | TM-MPL-013, TM-MPL-017 | 2 weeks |
| 16 | VR-2026-T16 | 2.24 | T | `unwrap`, `try_decrypt_edk`, raw-AES decrypt, EC `deserialize`, MRK `pa[5]`, `.expect` sites | No panic on any malformed EDK/EC/ARN input | verus-zero-panic | TM-MPL-023 | 1 week |
| 17 | VR-2026-T17 | 1.92 | T | `resolve_keystore_arn` (Discovery/MRDiscovery), `reject_alias_arn`, `rewrite_arn_region`, `parse_arn` | Alias rejection; parse∘format round-trip; region-only rewrite | verus-header-parsing-proofs | TM-MPL-007 | 1 week |
| 18 | VR-2026-T18 | 1.92 | T | `<BranchKeyStore as Keystore>::version_key` (EC derivation fragment) | New ACTIVE/DECRYPT_ONLY ECs preserve id/arn/hv/tablename/custom EC | verus-header-parsing-proofs | TM-MPL-016 | 1 week |
| 19 | VR-2026-T19 | 1.92 | T | `HierarchicalKeyring::{resolve_branch_key_id,on_encrypt,on_decrypt,try_decrypt_edk}` | Only EDKs with matching provider-id and bkid are attempted; bkid bound everywhere | verus-header-parsing-proofs | TM-MPL-003 | 1 week |
| 20 | VR-2026-T20 | 1.68 | T | `RawAesKeyring::{serialize_provider_info,decryptable_edk_iv}` | Provider-info codec round-trip, exact 12B IV, total | verus-header-parsing-proofs | TM-MPL-023, TM-MPL-011, TM-MPL-001 | 1 week |
| 21 | VR-2026-T21 | 1.68 | T | `cmc/storm_tracking.rs` (`ValidatedConfig::from_raw`, `classify_and_mark`, `wait_for_leader`, `put_cache_entry`) | Config bounds; `|inflight| ≤ fan_out`; ≤1 new leader per key per grace interval | verus-zero-panic (+ concurrency specialist) | TM-MPL-018 | 1 month |
| 22 | VR-2026-T22 | 1.60 | T | Debug impls of secret-bearing types | Debug output independent of secret bytes | verus-unsafe-ffi-safety | TM-MPL-021 | 1 week |
| 23 | VR-2026-T23 | 1.26 | T | `cmc/local.rs` `LocalCmc` | `len ≤ entry_capacity`; get never returns expired; prune arithmetic safe | verus-zero-panic | TM-MPL-022 | 2 weeks |
| 24 | VR-2026-T24 | 1.20 | T | `RawAesKeyring::new` | No constructed keyring has namespace prefixed `aws-kms` | verus-header-parsing-proofs | TM-MPL-001 | 1 day |

Ties are broken by higher severity, then by target ID (T-number). Quick win (score > 6.0 and effort ≤ 1 week): **VR-2026-T02** only. T01 scores higher but needs 2 weeks.

## 3. Detailed recommendations (YAML)

```yaml
recommendation:
  id: VR-2026-T01
  rank: 1
  priority_score: 8.96
  origin: threat-driven
  target:
    crate: aws-crypto-mpl
    file: mpl/src/keystore/kms_ops.rs; mpl/src/keystore/branch_key_store.rs; mpl/src/keystore/record.rs
    function: >
      kms_ops::build_authenticated_encryption_context (KMS Decrypt AAD);
      BranchKeyStore::build_auth_ec (private; reconstruction + VersionKey ReEncrypt EC);
      branch_key_store::item_from_ec_and_enc (write) / record_from_ddb_item (read);
      record::encryption_context_from_item / record::to_attribute_map (pub inverse pair)
  property: >
    Three separately written builders produce the authenticated EC: one for the KMS AAD,
    one for reconstruction/ReEncrypt, and the record.rs helpers. They must agree exactly
    with the spec definition: every item attribute except `enc`, plus
    `tablename` = configured logical keystore name. Also, reading back a stored item
    (item_from_ec_and_enc → DDB → record_from_ddb_item → build_auth_ec) must reproduce
    exactly the EC that KMS authenticated at write time. No attribute may be dropped,
    added or altered, and a Number attribute (hierarchy-version) must round-trip as the
    same decimal string.
  formal_spec: |
    spec fn auth_ec(attrs: Map<Seq<char>,Seq<char>>, n: Seq<char>) -> Map<Seq<char>,Seq<char>>
        { attrs.remove("enc"@).insert("tablename"@, n) }
    // (a) builder agreement
    fn build_authenticated_encryption_context(a: &BTreeMap<String,String>, n: &str) -> (ec: BTreeMap<String,String>)
        ensures ec@ == auth_ec(a@, n@)
    fn build_auth_ec(&self, r: &EncryptedRecord) -> (ec: BTreeMap<String,String>)
        requires !r.attributes@.contains_key("enc"@)          // postcondition of record_from_ddb_item
        ensures ec@ == auth_ec(r.attributes@, self.config.logical_keystore_name@)
    fn encryption_context_from_item(r: &EncryptedRecord, n: &str) -> (ec: BTreeMap<String,String>)
        ensures ec@ == auth_ec(r.attributes@, n@)
    // (b) production write→read round trip (AttributeValue modeled as S(str) | N(str) | B(bytes))
    requires ec@.contains_key("tablename"@) && ec@["tablename"@] == n@ && !ec@.contains_key("enc"@)
    ensures  record_from_ddb_item(item_from_ec_and_enc(ec, enc)) == Ok(r)
          && r.enc@ == enc@ && auth_ec(r.attributes@, n@) == ec@
    // (c) record.rs inverse pair (same requires)
    ensures encryption_context_from_item(&to_attribute_map(ec, enc), n)@ == ec@
  tool: Verus
  agent: verus-header-parsing-proofs
  estimated_effort: 2 weeks
  threat_references:
    - id: TM-MPL-005
      category: Tampering
      description: "Branch-key record substitution; residual = reconstructed EC must exactly match write-time EC"
    - id: TM-MPL-002
      category: Spoofing
      description: "Forged record decrypts under attacker-influenced key; EC binding is what makes forgery detectable"
  trace_to_spec: >
    spec/framework/branch-key-store.md#encryption-context, #authenticating-a-keystore-item,
    #aws-kms-branch-key-decryption, #record-format, #writing-branch-key-and-beacon-key-to-keystore
  coverage_gap: 0.8
  coverage_evidence: >
    mpl/tests/test_keystore_record.rs (item_encryption_context_round_trips,
    encryption_context_from_item_adds_tablename_and_ignores_enc_attribute,
    additional_item_attributes_are_carried_verbatim) covers ONLY the record.rs helpers,
    and production code never calls those. The production builders (build_auth_ec,
    item_from_ec_and_enc, record_from_ddb_item) are private and are exercised only by
    live-AWS tests in mpl/tests/test_keystore_branch_key_store_integ.rs
    (integ_create_key_round_trips, integ_version_key_round_trips,
    integ_get_active_key_wrong_logical_name_fails_at_kms).
  rationale: |
    KMS EC-as-AAD is the only integrity control on DynamoDB records (TA1). The threat
    model's residual is that it "relies on reconstructed EC exactly matching write-time
    EC". In the code that equality depends on three independent builders agreeing, plus
    an S/N AttributeValue round-trip. None of this is proven, and the production path is
    covered only by integration tests. Proving it also shows that a tamperer-added
    `tablename` attribute is always overwritten by the configured name (insert-overrides).
    Needs: extraction of the AttributeValue mapping into pure helpers, and an abstract
    model of aws_sdk_dynamodb::AttributeValue (TCB).
  scoring:
    severity: 4        # TM-MPL-005 Critical
    coverage_gap: 0.8
    feasibility: 0.7   # TM-MPL-005 Likelihood Medium
    blast_radius: 4    # every hierarchical-keyring / keystore consumer
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
    file: mpl/src/keystore/record.rs
    function: branch_key_materials_from_authenticated_encryption_context; custom_encryption_context_from_authenticated_encryption_context
  property: >
    Reconstruction returns Ok(materials) exactly when the authenticated EC has a valid
    `type` and a 32-byte plaintext. Valid means either "branch:ACTIVE" with a `version`
    that strictly extends "branch:version:", or a type that itself strictly extends
    "branch:version:"; `branch-key-id` must also be present. The output fields are then
    exactly determined: key = plaintext, id = ec["branch-key-id"], version = suffix after
    the prefix, EC = the `aws-crypto-ec:`-prefixed entries with the prefix stripped.
    Every other input yields Err(RecordMalformed).
  formal_spec: |
    spec fn strict_prefix(p: Seq<char>, s: Seq<char>) -> bool { s.len() > p.len() && s.subrange(0, p.len() as int) == p }
    spec fn ver_src(ec) -> Seq<char> { if ec["type"@] == "branch:ACTIVE"@ { ec["version"@] } else { ec["type"@] } }
    spec fn custom(ec) -> Map<Seq<u8>,Seq<u8>> // { utf8(k) ↦ utf8(ec["aws-crypto-ec:"+k]) | "aws-crypto-ec:"+k ∈ dom(ec) }
    fn branch_key_materials_from_authenticated_encryption_context(ec: &BTreeMap<String,String>, pt: Vec<u8>)
        -> (r: Result<BranchKeyMaterials, KeystoreError>)
      ensures r.is_Ok() <==> ec@.contains_key("type"@)
                && (ec@["type"@] == "branch:ACTIVE"@ ==> ec@.contains_key("version"@))
                && strict_prefix("branch:version:"@, ver_src(ec@))
                && ec@.contains_key("branch-key-id"@) && pt@.len() == 32
      ensures r matches Ok(m) ==> m.branch_key@ == pt@ && m.branch_key_id@ == ec@["branch-key-id"@]
                && m.branch_key_version@ == ver_src(ec@).subrange(15, ver_src(ec@).len() as int)
                && m.encryption_context@ == custom(ec@)
      ensures r matches Err(e) ==> e.kind == KeystoreErrorKind::RecordMalformed
  tool: Verus
  agent: verus-header-parsing-proofs
  estimated_effort: 1 week
  threat_references:
    - id: TM-MPL-005
      category: Tampering
      description: "Branch-key record substitution; reconstruction must not accept a mis-typed or mis-versioned record"
  trace_to_spec: >
    spec/framework/branch-key-store.md#branch-key-materials-from-authenticated-encryption-context,
    #custom-encryption-context-from-authenticated-encryption-context
  coverage_gap: 0.6
  coverage_evidence: >
    mpl/tests/test_keystore_record.rs: materials_reconstruction_rejects_invalid_type_value,
    materials_reconstruction_rejects_beacon_type, materials_reconstruction_branch_active_uses_version_attribute,
    materials_reconstruction_branch_active_rejects_missing_version, materials_reconstruction_branch_version_uses_type_value,
    materials_branch_key_rejects_wrong_length, materials_reconstruction_rejects_bare_version_prefix_type,
    materials_reconstruction_rejects_active_with_bare_version_attribute, custom_ec_extraction_strips_prefix,
    custom_ec_extraction_ignores_non_prefixed_keys. Broad example coverage of the branches.
  rationale: |
    This is the final decode of KMS-authenticated data into the materials every
    hierarchical wrap/unwrap uses. Its Ok/Err boundary is the type/version validation
    gate. It is a single straight-line function over a Map with no I/O, which is
    Verus-friendly. Paired with T01 it closes "authenticated bytes → correct materials".
  scoring:
    severity: 4        # TM-MPL-005 Critical
    coverage_gap: 0.6
    feasibility: 0.7   # Medium
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
    file: mpl/src/keystore/kms_ops.rs (+ caller decrypt_branch_key; version_key in branch_key_store.rs)
    function: resolve_keystore_arn (KmsKeyArn / KmsMrKeyArn arms)
  property: >
    In single-key modes the KeyId sent to KMS Decrypt/ReEncrypt is always the CONFIGURED
    ARN, never the record's `kms-arn`. The call succeeds only if the record ARN is
    compatible (byte-equal for KmsKeyArn, MRK-match for KmsMrKeyArn) and otherwise fails
    with Authentication. decrypt_branch_key has no other KeyId source.
  formal_spec: |
    fn resolve_keystore_arn(c: &KmsConfiguration, rec: &str) -> (r: Result<String, KeystoreError>)
      requires c matches KmsConfiguration::KmsKeyArn(_) || c matches KmsConfiguration::KmsMrKeyArn(_)
      ensures r matches Ok(k) ==> k@ == configured(c)@
      ensures r.is_Ok() <==> compat_spec(c, rec@)   // KmsKeyArn: configured@ == rec@ ; KmsMrKeyArn: mrk_match_spec(configured@, rec@)
      ensures r matches Err(e) ==> e.kind == KeystoreErrorKind::Authentication
    // decrypt_branch_key: key_id passed to kms_client.decrypt() == resolve_keystore_arn(..)->Ok_0
  tool: Verus
  agent: verus-header-parsing-proofs
  estimated_effort: 1 day
  threat_references:
    - id: TM-MPL-002
      category: Spoofing
      description: "Forged record decrypts under attacker-influenced KMS key (key-id confusion) — provable slice: pinned modes"
  trace_to_spec: "spec/framework/branch-key-store.md#aws-kms-branch-key-decryption, #aws-key-arn-compatibility"
  coverage_gap: 0.8
  coverage_evidence: >
    resolve_keystore_arn is pub(crate) and has no direct unit test. The compat predicate
    is unit-tested in mpl/tests/test_keystore_kms_config.rs (kms_key_arn_compatible_only_when_byte_equal,
    kms_key_arn_incompatible_with_different_region, kms_mr_key_arn_compatible_with_same_key_different_region,
    kms_mr_key_arn_incompatible_with_different_account). End-to-end coverage is live-AWS only:
    test_aws_kms_hierarchical_keyring_integ.rs::integ_pinned_keystore_rejects_a_branch_key_under_another_kms_key,
    test_keystore_branch_key_store_integ.rs::integ_get_active_key_with_arn_disagreement_fails,
    integ_get_active_kmskeyarn_west_fetches_east_branch_fails.
  rationale: |
    This is the code-level control for Critical TM-MPL-002. It is cheap to prove because
    the property is "returns the configured string". The MRK predicate can be left as an
    uninterpreted spec fn here and discharged by T11. KMS key policy itself is excluded.
  scoring:
    severity: 4        # TM-MPL-002 Critical
    coverage_gap: 0.8
    feasibility: 0.4   # Low
    blast_radius: 4
    product: "4 × 0.8 × 0.4 × 4 = 5.12"
  quick_win: false     # score < 6.0 (cheap, though)
  dependencies: [VR-2026-T11]   # soft: only to give compat_spec its MRK meaning
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
    function: wrap
  property: >
    Each invocation allocates fresh local `salt: [u8;16]` and `iv: [u8;12]`. Each is
    filled by exactly one successful generate_random_bytes call before it is first read,
    and no state carries across calls (wrap takes &BranchKeyMaterials and reads no
    static). The IV passed to aes_encrypt is byte-identical to output[16..28]. The output
    is exactly salt‖iv‖uuid_bytes(version)‖ct‖tag, with |output| = 60 + |pt|. The
    aws-lc-rs safe-wrapper preconditions hold: key length 32 == AesGcm::Aes256Gcm.key_len()
    and |iv| == 12, so the only possible Err is entropy/AAD failure. On Err the partially
    built `output`, which holds plaintext bytes (see T07 note), is dropped and never returned.
  formal_spec: |
    fn wrap(m: &BranchKeyMaterials, ec: &EncryptionContext, pt: &[u8]) -> (r: Result<Vec<u8>, MaterialsError>)
      ensures r matches Ok(out) ==>
           out@.len() == 60 + pt@.len()
        && out@.subrange(0,16)  == ghost_salt_draw@        // bytes from THIS call's 1st RNG fill
        && out@.subrange(16,28) == ghost_iv_draw@          // bytes from THIS call's 2nd RNG fill
        && out@.subrange(28,44) == uuid_bytes(m.branch_key_version@)
        && out@.subrange(44, out@.len() as int) == gcm_seal_spec(kdf(m.branch_key@, ghost_salt_draw@), ghost_iv_draw@,
                                                    compute_aad_spec(m, ec), pt@)
      // call-site obligations (safe-wrapper preconditions)
      // aes_encrypt(alg=Aes256Gcm, iv, key, ..): iv@.len()==12 && key@.len()==32
    // generate_random_bytes external spec: ensures r.is_Ok() ==> buf@ == rng_draw(ghost call id)  (randomness NOT modeled)
  tool: Verus
  agent: verus-unsafe-ffi-safety
  estimated_effort: 1 week
  threat_references:
    - id: TM-MPL-012
      category: Elevation of Privilege
      description: "AES-GCM salt/IV reuse in branch-key wrap — provable slice: lengths and fresh-per-call structure"
  trace_to_spec: "spec/framework/aws-kms/aws-kms-hierarchical-keyring.md#branch-key-wrapping, #ciphertext"
  coverage_gap: 0.7
  coverage_evidence: >
    mpl/tests/test_aws_kms_hierarchical_keyring.rs: wrap_ciphertext_layout_lengths_match_spec,
    wrap_two_calls_produce_distinct_ciphertexts, wrap_then_unwrap_with_tampered_iv_fails,
    wrap_unwrap_round_trip_recovers_plaintext, wrap_then_unwrap_with_smaller_plaintext_round_trips.
  rationale: |
    The probabilistic half of TM-MPL-012 (224-bit collision bound) is excluded. The
    structural half is that a fresh salt/IV is drawn per call, used once, never cached,
    and laid out at the right offsets. That half is fully provable and is load-bearing,
    because prim uses Nonce::try_assume_unique_for_key, which puts nonce discipline on
    the caller.
  scoring:
    severity: 4        # TM-MPL-012 Critical
    coverage_gap: 0.7
    feasibility: 0.4   # Low
    blast_radius: 4
    product: "4 × 0.7 × 0.4 × 4 = 4.48"
  quick_win: false
  dependencies: [VR-2026-T05, VR-2026-T10]
```

```yaml
recommendation:
  id: VR-2026-T05
  rank: 5
  priority_score: 4.32
  origin: threat-driven
  target:
    crate: aws-crypto-mpl
    file: mpl/src/aws_kms/branch_key_wrap.rs
    function: derive_branch_key (private)
  property: >
    The fixed-info passed to prim::kbkdf_ctr_hmac is exactly
    "aws-kms-hierarchy"(17) ‖ 0x00 ‖ salt(16) ‖ 0x00000100 (L = 256 bits, big-endian),
    38 bytes in total. The PRF is HMAC-SHA-256 (DigestAlg::Sha256), the IKM is the 32-byte
    branch key, and the OKM buffer is exactly 32 bytes. wrap and unwrap reach the KDF
    only through this one function.
  formal_spec: |
    fn derive_branch_key(bk: &[u8;32], salt: &[u8;16]) -> (r: Result<[u8;32], MaterialsError>)
      ensures ghost_info@ == b"aws-kms-hierarchy"@ + seq![0x00u8] + salt@ + seq![0x00u8, 0x00, 0x01, 0x00]
           && ghost_info@.len() == 38 && ghost_alg == DigestAlg::Sha256 && ghost_ikm@ == bk@ && ghost_okm_len == 32
      ensures r matches Ok(k) ==> k@ == kbkdf_ctr_hmac_spec(Sha256, bk@, ghost_info@, 32)  // uninterpreted, trusted (aws-lc-rs)
  tool: Verus
  agent: verus-header-parsing-proofs
  estimated_effort: 1 day
  threat_references:
    - id: TM-MPL-014
      category: Elevation of Privilege
      description: "KBKDF fixed-info / L-value misuse weakens branch-key derivation"
  trace_to_spec: >
    spec/framework/aws-kms/aws-kms-hierarchical-keyring.md#branch-key-wrapping (KDF step),
    #branch-key-unwrapping; NIST SP 800-108 §4.1
  coverage_gap: 0.9
  coverage_evidence: >
    No test in mpl/tests checks the derived key or the info layout (derive_branch_key is
    private). The wrap/unwrap round-trip tests in test_aws_kms_hierarchical_keyring.rs run
    the SAME derive_branch_key on both sides, so a layout drift would still round-trip and
    go undetected. prim/tests/test_kbkdf_ctr_hmac.rs (test_kbkdf_ctr_hmac_raw_vectors,
    test_kbkdf_ctr_hmac_purpose_nonce_vectors) validates only the primitive, using its own
    test-side build_fixed_info helper.
  rationale: |
    A layout error here is interop-breaking and possibly weakening, and it is invisible to
    the self-consistent tests. The proof is straight-line Seq concatenation, so it is a
    1-day job with high assurance per hour.
  scoring:
    severity: 3        # TM-MPL-014 High
    coverage_gap: 0.9
    feasibility: 0.4   # Low
    blast_radius: 4
    product: "3 × 0.9 × 0.4 × 4 = 4.32"
  quick_win: false     # score < 6.0, but lowest-effort target in the list
  dependencies: []
```

```yaml
recommendation:
  id: VR-2026-T06
  rank: 6
  priority_score: 4.20
  origin: threat-driven
  target:
    crate: aws-crypto-mpl
    file: mpl/src/aws_kms/hierarchical_keyring.rs; mpl/src/cmc/storm_tracking.rs
    function: >
      HierarchicalKeyring::on_encrypt (line 342) and try_decrypt_edk (line 585):
      `now + Duration::from_secs(self.ttl_seconds)`; storm_tracking::within_grace_interval:
      `inflight + grace_interval`; StormTrackingCmc::classify_and_mark: `now + self.inflight_ttl`;
      bounds would live in HierarchicalKeyring::new / ValidatedConfig::from_raw
  property: >
    No `SystemTime + Duration` addition can panic for any configuration the constructors
    accept. EXPECTED OUTCOME: the proof obligation FAILS as written.
    HierarchicalKeyring::new only checks ttl_seconds > 0, and from_raw only enforces lower
    bounds and grace_interval ≤ inflight_ttl ≤ grace_period, so for example
    ttl_seconds = u64::MAX is accepted. std's `impl Add<Duration> for SystemTime` panics
    on overflow ("overflow when adding duration to instant"), so the first cache put
    aborts. (This comes from reading std's Add impl. It was not executed in this step.)
  formal_spec: |
    // model SystemTime as (secs: i64, nanos: u32); external spec (TCB):
    //   SystemTime::add(t, d) requires st_add_ok(t, d)   where st_add_ok ⇔ t.secs + d.secs (+carry) <= i64::MAX
    fn new(.., ttl_seconds: u64, ..) -> (r: Result<Self, MaterialsError>)
      ensures r matches Ok(k) ==> k.ttl_seconds <= MAX_TTL      // MAX_TTL: forall now <= NOW_MAX: st_add_ok(now, from_secs(MAX_TTL))
    fn from_raw(..) -> (r: Result<ValidatedConfig, CmcError>)
      ensures r matches Ok(c) ==> c.grace_interval <= MAX_D && c.inflight_ttl <= MAX_D
    // add sites: requires now <= NOW_MAX  ⇒  verifies only once the bounds above exist
  tool: Verus
  agent: verus-zero-panic
  estimated_effort: 1 week
  threat_references:
    - id: TM-MPL-018
      category: Denial of Service
      description: "Storm-tracking mis-configuration causes failures — here a process panic"
    - id: TM-MPL-022
      category: Denial of Service
      description: "Cache configuration → availability"
    - id: TM-MPL-023
      category: Denial of Service
      description: "Panic instead of error (config-driven rather than ciphertext-driven)"
  trace_to_spec: >
    spec/framework/aws-kms/aws-kms-hierarchical-keyring.md#cache-limit-ttl;
    spec/framework/storm-tracking-cryptographic-materials-cache.md#grace-interval, #inflight-ttl, #within-grace-interval
  coverage_gap: 1.0
  coverage_evidence: >
    No test uses large TTL/grace values. test_aws_kms_hierarchical_keyring.rs
    (new_with_zero_ttl_returns_validation_error, new_with_positive_ttl_succeeds) and
    test_storm_tracking_cmc.rs config tests use small values only. A grep for u64::MAX in
    mpl/tests finds nothing (the only usize::MAX hit is a comment in test_local_cmc.rs).
  rationale: |
    This is a real latent panic that the threat model did not list. Fixing it (an upper
    bound in new/from_raw, or checked_add mapped to an error) changes observable behavior
    because new inputs get rejected. That is a product decision for the owner. Per the
    workflow rules it is recorded here, not changed. The proof target is still worth
    scoping: once the owner picks a bound, Verus closes it.
  scoring:
    severity: 2        # TM-MPL-018 Medium
    coverage_gap: 1.0
    feasibility: 0.7   # TM-MPL-018 Likelihood Medium
    blast_radius: 3    # every hierarchical keyring (ttl) and every storm-tracking cache
    product: "2 × 1.0 × 0.7 × 3 = 4.20"
  quick_win: false
  dependencies: []
```

```yaml
recommendation:
  id: VR-2026-T07
  rank: 7
  priority_score: 3.84
  origin: threat-driven
  target:
    crate: aws-crypto-mpl + aws-mpl-primitives
    file: mpl/src/keyring/raw_aes_keyring.rs; prim/src/lib.rs
    function: RawAesKeyring::new; <RawAesKeyring as Keyring>::on_encrypt / on_decrypt; prim::aes_encrypt / aes_decrypt
  property: >
    (a) Struct invariant from new: |wrapping_key| == wrapping_alg.key_len().
    (b) on_encrypt allocates a fresh `iv` Vec of exactly 12 bytes per invocation. It is
    written by one successful generate_random_bytes before use and is never stored in
    `self` (&self, no interior mutability). The same bytes are both the GCM nonce and the
    provider-info IV.
    (c) Every aes_encrypt/aes_decrypt call meets the aws-lc-rs safe-wrapper preconditions:
    |key| == alg.key_len(), |iv| == 12, |tag| == 16, |plain_text| == |cipher_text|. So the
    only Err from aes_decrypt is an authentication failure.
    (d) Exact output sizing: on Ok, |EDK.ciphertext| == |pdk| + 16.
    (e) On aes_encrypt Err, the caller drops the output buffer without returning it.
    prim::aes_encrypt has already appended the plaintext to it at that point.
  formal_spec: |
    spec fn inv(k: RawAesKeyring) -> bool { k.wrapping_key@.len() == k.wrapping_alg.key_len() as nat }
    fn new(ns, name, key: Vec<u8>, alg: AesGcm) -> (r: Result<Self, MaterialsError>)  ensures r matches Ok(k) ==> inv(k)
    fn aes_encrypt(alg, iv: &[u8], key: &[u8], msg: &[u8], aad: &[u8], ct: &mut Vec<u8>) -> (r: Result<(), Error>)
      ensures (iv@.len() == 12 && key@.len() == alg.key_len()) ==> r.is_Ok()          // modulo seal failure axiom (TCB)
      ensures r.is_Ok() ==> ct@.len() == old(ct)@.len() + msg@.len() + 16
    fn on_encrypt(&self, m) -> (r)  requires inv(*self)
      ensures r matches Ok(m2) ==> let e = m2.edks@.last();
           e.ciphertext@.len() == pdk@.len() + 16
        && e.key_provider_info@.subrange(|name|+8, |name|+20) == ghost_iv_draw@ && ghost_iv_draw@.len() == 12
    fn on_decrypt(&self, m, edks) requires inv(*self)
      // each aes_decrypt call: iv@.len()==12 && tag@.len()==16 && plain@.len()==ct@.len() && key@.len()==alg.key_len()
  tool: Verus
  agent: verus-unsafe-ffi-safety
  estimated_effort: 1 week
  threat_references:
    - id: TM-MPL-011
      category: Elevation of Privilege
      description: "AES-GCM IV reuse in raw-AES keyring — provable slice: length + fresh-per-call structure"
  trace_to_spec: "spec/framework/raw-aes-keyring.md#onencrypt, #ondecrypt, #iv, #wrapping-algorithm, #wrapping-key"
  coverage_gap: 0.8
  coverage_evidence: >
    mpl/tests/test_raw_aes_keyring.rs: test_encrypted_data_key_wire_format, test_round_trip_every_wrapping_algorithm,
    test_new_rejects_wrapping_key_length_mismatch, test_new_accepts_every_wrapping_key_length,
    test_on_decrypt_rejects_tampered_iv. prim/tests/test_aes.rs: test_aes_encrypt_bad_key_length,
    test_aes_encrypt_bad_iv_length, test_aes_decrypt_bad_key_length, test_aes_decrypt_bad_iv_length,
    test_aes_decrypt_output_buffer_too_small. No test checks that two on_encrypt calls use distinct IVs.
  rationale: |
    prim does not length-check key or IV itself. It relies on UnboundKey::new and
    Nonce::try_assume_unique_for_key returning Err, and it does not check the tag length
    in aes_decrypt. So the preconditions must be upheld by the callers, and proving the
    callers do so is exactly the safe-wrapper slice. Observation (not changed): on any Err
    after `extend_from_slice(message)`, aes_encrypt leaves plaintext in the caller's
    buffer. Both MPL callers drop that buffer, and (e) proves it. Changing prim's API
    contract would be a behavior change for the owner.
  scoring:
    severity: 4        # TM-MPL-011 Critical
    coverage_gap: 0.8
    feasibility: 0.4   # Low
    blast_radius: 3    # raw-AES keyring users
    product: "4 × 0.8 × 0.4 × 3 = 3.84"
  quick_win: false
  dependencies: [VR-2026-T20]
```

```yaml
recommendation:
  id: VR-2026-T08
  rank: 8
  priority_score: 3.84
  origin: threat-driven
  target:
    crate: aws-crypto-mpl
    file: mpl/src/structures/algorithm_suite.rs
    function: PlaintextDataKey::zeroize (the repository's only unsafe block, line 439)
  property: >
    Every `ptr.add(i)` with 0 ≤ i < len stays inside the Vec's initialized allocation
    (len ≤ capacity, no reallocation during the loop). Each write_volatile writes one
    valid u8. On return, len is unchanged and every byte is 0, so no residual key
    material remains in the Vec's current buffer.
  formal_spec: |
    pub fn zeroize(&mut self)
      ensures self.0@.len() == old(self).0@.len()
           && forall|j: int| 0 <= j < self.0@.len() ==> self.0@[j] == 0u8
    // loop invariant: 0 <= i <= len; len == self.0@.len(); ptr == self.0.as_mut_ptr() (no realloc);
    //   forall j < i: self.0@[j] == 0;  forall i <= j < len: self.0@[j] == old(self).0@[j]
    // per iteration: points_to permission for byte i (vstd raw_ptr); ptr.add(i) in-bounds since i < len <= cap
  tool: Verus
  agent: verus-unsafe-ffi-safety
  estimated_effort: 1 week
  threat_references:
    - id: TM-MPL-015
      category: Information Disclosure
      description: "Secret material not zeroized — provable slice: the zeroize loop is complete + in-bounds"
  trace_to_spec: "spec/framework/structures.md (Plaintext Data Key, lines 223/319) — no clause mandates zeroization; baseline assurance"
  coverage_gap: 0.8
  coverage_evidence: >
    mpl/tests/test_encryption_materials.rs::test_plaintext_data_key_zeroize and
    mpl/tests/test_decryption_materials.rs::test_plaintext_data_key_zeroize_decryption check the
    visible post-state on one small key. Tests cannot establish pointer in-bounds soundness
    for all lengths.
  rationale: |
    This is the one unsafe block, and the capability map calls it the single highest-value
    low-level proof. Important caveat: zeroize has NO call sites in mpl/src. The proof
    establishes that the primitive is sound and complete. It does NOT mitigate TM-MPL-015
    at runtime (see Excluded, TM-MPL-015 rest). Trusted: external specs for
    Vec::as_mut_ptr / ptr::write_volatile (PointsTo model). Compiler non-elision of
    volatile writes is a language guarantee, not something Verus proves.
  scoring:
    severity: 3        # TM-MPL-015 High
    coverage_gap: 0.8
    feasibility: 0.4   # Low
    blast_radius: 4
    product: "3 × 0.8 × 0.4 × 4 = 3.84"
  quick_win: false
  dependencies: []
```

```yaml
recommendation:
  id: VR-2026-T09
  rank: 9
  priority_score: 3.20
  origin: threat-driven
  target:
    crate: aws-crypto-mpl
    file: mpl/src/structures/commitment_policy.rs; mpl/src/structures/algorithm_suite.rs; mpl/src/cmm/default_cmm.rs
    function: >
      CommitmentPolicy::{allows_for_encrypt, allows_for_decrypt, default_algorithm_suite_id};
      AlgorithmSuiteId::specification; AlgorithmSuite::key_commitment;
      DefaultCmm::{get_encryption_materials, decrypt_materials}
  property: >
    key_commitment() holds exactly for suites 0x0478 and 0x0578. The allow-tables match
    commitment-policy.md for all 3 policies × 11 suites, and each policy's default suite
    is encrypt-allowed. get_encryption_materials returns Ok only with an
    encrypt-allowed suite. decrypt_materials returns Err and never invokes the keyring
    when the suite is not decrypt-allowed. The in-repo keyrings (RawAes, Hierarchical)
    never change algorithm_suite_id between their input and output materials.
  formal_spec: |
    spec fn committing(id: AlgorithmSuiteId) -> bool
      { id == AlgAes256GcmHkdfSha512CommitKey || id == AlgAes256GcmHkdfSha512CommitKeyEcdsaP384 }
    ensures id.specification().key_commitment() <==> committing(id)
    ensures p.allows_for_encrypt(id) <==> match p { Esdk(ForbidEncryptAllowDecrypt) => !committing(id), _ => committing(id) }
    ensures p.allows_for_decrypt(id) <==> match p { Esdk(RequireEncryptRequireDecrypt) => committing(id), _ => true }
    ensures p.allows_for_encrypt(p.default_algorithm_suite_id())
    fn get_encryption_materials(&self, req) -> (r)  // keyring := RawAes | Hierarchical
      ensures r matches Ok(m) ==> req.commitment_policy().allows_for_encrypt(m.algorithm_suite_id())
    fn decrypt_materials(&self, req) -> (r)
      ensures !req.commitment_policy().allows_for_decrypt(req.algorithm_suite_id()) ==> r.is_Err() && !ghost_keyring_called
    // keyring frame: on_encrypt/on_decrypt Ok(m2) ==> m2.algorithm_suite_id() == m.algorithm_suite_id()
  tool: Verus
  agent: verus-header-parsing-proofs
  estimated_effort: 1 week
  threat_references:
    - id: TM-MPL-006
      category: Elevation of Privilege
      description: "Algorithm-suite downgrade / commitment-policy bypass"
    - id: TM-MPL-008
      category: Elevation of Privilege
      description: "Non-committing suite reused where commitment expected (Invisible Salamanders) — code-gate slice"
  trace_to_spec: >
    spec/framework/commitment-policy.md#supported-commitment-policy-enum (+ per-policy sections);
    spec/framework/default-cmm.md#get-encryption-materials, #decrypt-materials;
    spec/framework/algorithm-suites.md#algorithm-suites-commit-key-derivation-settings
  coverage_gap: 0.5
  coverage_evidence: >
    mpl/tests/test_commitment_policy.rs (11 tests enumerating the full policy × suite table),
    mpl/tests/test_default_cmm.rs (test_get_encryption_materials_unsupported_suite_for_policy_fails,
    test_decrypt_materials_unsupported_suite_for_policy_fails, test_get_encryption_materials_no_suite_uses_commitment_policy_default,
    test_get_encryption_materials_returns_same_suite_when_request_specifies_one), mpl/tests/test_algorithm_suite_id.rs.
    The domain is finite and close to exhaustively tested, which is why the gap is the lowest in the list.
  rationale: |
    Critical severity, but the code is a small const table that the tests already cover
    nearly exhaustively. The proof's value is regression-proofing plus the CMM-level
    statement that the keyring is not called on a disallowed suite. Caveat: DefaultCmm
    does not re-check the suite after the keyring returns, so the CMM postcondition holds
    only for keyrings that preserve the suite id. That is provable for the two in-repo
    keyrings and is an assumption for third-party Keyring impls.
  scoring:
    severity: 4        # TM-MPL-006 Critical
    coverage_gap: 0.5
    feasibility: 0.4   # Low
    blast_radius: 4
    product: "4 × 0.5 × 0.4 × 4 = 3.20"
  quick_win: false
  dependencies: []
```

```yaml
recommendation:
  id: VR-2026-T10
  rank: 10
  priority_score: 2.88
  origin: threat-driven
  target:
    crate: aws-crypto-mpl
    file: mpl/src/aws_kms/branch_key_wrap.rs; mpl/src/aws_kms/hierarchical_keyring.rs
    function: compute_aad; uuid_str_to_16_bytes (private); uuid_16_bytes_to_str (private); wrap/unwrap call sites
  property: >
    compute_aad returns Ok exactly when the version is a 36-char canonical hyphenated UUID
    and the EC is serializable. The AAD is then exactly
    "aws-kms-hierarchy" ‖ utf8(bkid) ‖ uuid_bytes(version) ‖ serialize(ec).
    For a fixed bkid, the map (version bytes, ec) ↦ AAD is injective.
    The two version representations round-trip: for every 16-byte b,
    uuid_str_to_16_bytes(uuid_16_bytes_to_str(b)) == Ok(b). wrap and unwrap pass
    identical (materials.branch_key_id, materials.branch_key_version, ec) arguments.
  formal_spec: |
    fn compute_aad(bkid: &str, ver: &str, ec: &EncryptionContext) -> (r: Result<Vec<u8>, MaterialsError>)
      ensures r.is_Ok() <==> canonical_uuid(ver@) && serializable(ec@)
      ensures r matches Ok(a) ==> a@ == "aws-kms-hierarchy"@.as_bytes() + bkid@.as_bytes() + uuid_bytes(ver@) + ser(ec@)
    proof fn aad_injective_fixed_bkid(b, v1, e1, v2, e2)
      requires compute_aad(b,v1,e1) == Ok(a) && compute_aad(b,v2,e2) == Ok(a)
      ensures uuid_bytes(v1@) == uuid_bytes(v2@) && e1@ == e2@                    // uses T15 ser-injectivity
    proof fn uuid_round_trip(b: [u8;16]) ensures uuid_str_to_16_bytes(&uuid_16_bytes_to_str(&b)) == Ok(b)
  tool: Verus
  agent: verus-header-parsing-proofs
  estimated_effort: 1 week
  threat_references:
    - id: TM-MPL-013
      category: Tampering
      description: "Branch-key wrap/unwrap AAD constructed inconsistently"
  trace_to_spec: "spec/framework/aws-kms/aws-kms-hierarchical-keyring.md#branch-key-wrapping-and-unwrapping-aad"
  coverage_gap: 0.6
  coverage_evidence: >
    mpl/tests/test_aws_kms_hierarchical_keyring.rs: compute_aad_layout_for_known_inputs,
    compute_aad_appends_serialized_encryption_context, compute_aad_fails_when_encryption_context_value_too_large,
    wrap_then_unwrap_with_different_aad_branch_key_id_fails, wrap_then_unwrap_with_different_encryption_context_fails,
    on_decrypt_calls_keystore_get_branch_key_version_with_uuid_from_ciphertext.
  rationale: |
    The AAD is the only binding of a wrapped data key to (bkid, version, EC). Expected
    finding: injectivity ACROSS different bkids is not provable and a counterexample
    exists, because bkid has no length prefix and bytes can shift between bkid and the
    16-byte version. That is a property of the spec-defined layout, not a code defect.
    It is harmless in practice because each AAD is used under a key derived from that
    bkid's own branch key. Also noted: unwrap ignores the on-wire version bytes (`_version`)
    and binds the materials' version through the AAD, which fails closed. Trusted:
    external specs for uuid::Uuid::{parse_str, from_bytes, hyphenated}.
  scoring:
    severity: 3        # TM-MPL-013 High
    coverage_gap: 0.6
    feasibility: 0.4   # Low
    blast_radius: 4
    product: "3 × 0.6 × 0.4 × 4 = 2.88"
  quick_win: false
  dependencies: [VR-2026-T15]
```

```yaml
recommendation:
  id: VR-2026-T11
  rank: 11
  priority_score: 2.88
  origin: threat-driven
  target:
    crate: aws-crypto-mpl
    file: mpl/src/aws_kms/mrk_match.rs; mpl/src/keystore/kms_config.rs
    function: aws_kms_mrk_match_for_decrypt; is_multi_region_arn; is_alias_arn; is_arn_compatible
  property: >
    The function returns true exactly when neither input is an alias ARN and either the
    inputs are identical, or both are MRK ARNs (6 ':'-segments, "arn", service "kms",
    resource "key/mrk-…") that agree on partition, service, account, resource type and
    resource id, with region the only possible difference. The relation is symmetric.
    is_arn_compatible is byte-equality for KmsKeyArn, the MRK match for KmsMrKeyArn, and
    true for the Discovery modes.
  formal_spec: |
    spec fn segs(s: Seq<char>) -> Seq<Seq<char>>    // split_spec(s, ':')
    spec fn is_mrk(s)   = segs(s).len()==6 && segs(s)[0]=="arn"@ && segs(s)[2]=="kms"@ && starts_with(segs(s)[5], "key/mrk-"@)
    spec fn is_alias(s) = segs(s).len()==6 && segs(s)[0]=="arn"@ && segs(s)[2]=="kms"@ && starts_with(segs(s)[5], "alias/"@)
    fn aws_kms_mrk_match_for_decrypt(a: &str, b: &str) -> (r: bool)
      ensures r <==> !is_alias(a@) && !is_alias(b@) && (a@ == b@ || (is_mrk(a@) && is_mrk(b@)
               && segs(a@)[1]==segs(b@)[1] && segs(a@)[2]==segs(b@)[2] && segs(a@)[4]==segs(b@)[4]
               && split_once(segs(a@)[5], '/') == split_once(segs(b@)[5], '/')))
      ensures r == aws_kms_mrk_match_for_decrypt_spec(b@, a@)        // symmetry
    fn is_arn_compatible(c, s) -> (r: bool)
      ensures match c { KmsKeyArn(x) => r == (x@ == s@), KmsMrKeyArn(x) => r == mrk_spec(x@, s@), _ => r }
  tool: Verus
  agent: verus-header-parsing-proofs
  estimated_effort: 2 weeks
  threat_references:
    - id: TM-MPL-004
      category: Tampering
      description: "ARN/MRK match logic accepts a non-matching key ARN"
  trace_to_spec: >
    spec/framework/aws-kms/aws-kms-mrk-match-for-decrypt.md#implementation;
    spec/framework/aws-kms/aws-kms-key-arn.md (identifying an MRK); spec/framework/branch-key-store.md#aws-key-arn-compatibility
  coverage_gap: 0.6
  coverage_evidence: >
    mpl/tests/test_aws_kms_mrk_match.rs (17 tests, including identical_aliases_return_false,
    mrk_arns_same_key_different_region_return_true, mrk_arns_different_account/resource/partition/service_return_false,
    malformed_arn_and_mrk_arn_return_false); mpl/tests/test_keystore_kms_config.rs
    (kms_key_arn_compatible_only_when_byte_equal, kms_mr_key_arn_compatible_with_same_key_different_region,
    kms_mr_key_arn_incompatible_with_different_account, discovery_compatible_with_any_arn).
  rationale: |
    The threat model itself calls this ad-hoc string parsing a "strong verification
    candidate". Two points to settle in the proof. First, the documented deviation that
    aliases are rejected even when byte-identical. Second, a parser inconsistency:
    mrk_match uses split(':') (exactly 6 segments) while kms_config::parse_arn uses
    splitn(6, ':'), so a resource containing ':' parses as an ARN but is never an MRK.
    Neither is a known exploit; the proof makes both explicit. Modelling str::split over
    Seq<char> is the main cost. The `pa[5]` panic-freedom slice is in T16.
  scoring:
    severity: 3        # TM-MPL-004 High
    coverage_gap: 0.6
    feasibility: 0.4   # Low
    blast_radius: 4
    product: "3 × 0.6 × 0.4 × 4 = 2.88"
  quick_win: false
  dependencies: []
```

```yaml
recommendation:
  id: VR-2026-T12
  rank: 12
  priority_score: 2.88
  origin: threat-driven
  target:
    crate: aws-crypto-mpl
    file: mpl/src/cmm/default_cmm.rs
    function: merge_reproduced_encryption_context (private); DefaultCmm::decrypt_materials (call site)
  property: >
    With no reproduced EC, the result is (message EC, ∅). Otherwise the result is Ok
    exactly when the two contexts agree on every shared key. On Ok, ec = m ∪ r, m is a
    submap of ec (nothing dropped or altered), required keys = dom(r) \ dom(m), and the
    required keys are a subset of dom(ec). On Err, the kind is
    EncryptionContextValueMismatch. The EC handed to keyring.on_decrypt is exactly the
    merged map.
  formal_spec: |
    fn merge_reproduced_encryption_context(m: &EncryptionContext, r: Option<&EncryptionContext>)
        -> (res: Result<(EncryptionContext, BTreeSet<Vec<u8>>), MaterialsError>)
      ensures r is None ==> res == Ok((*m, BTreeSet::empty()))
      ensures r matches Some(rr) ==> (res.is_Ok() <==>
                forall|k| m@.contains_key(k) && rr@.contains_key(k) ==> m@[k] == rr@[k])
      ensures res matches Ok((ec, req)) && r matches Some(rr) ==>
                ec@ == m@.union_prefer_right(rr@) && m@.submap_of(ec@)
             && req@ == rr@.dom().difference(m@.dom()) && req@.subset_of(ec@.dom())
      ensures res matches Err(e) ==> e.kind == MaterialsErrorKind::EncryptionContextValueMismatch
  tool: Verus
  agent: verus-header-parsing-proofs
  estimated_effort: 1 week
  threat_references:
    - id: TM-MPL-017
      category: Tampering
      description: "Encryption-context / reproduced-EC merge lets attacker drop or alter bound context"
  trace_to_spec: "spec/framework/cmm-interface.md#decrypt-materials; spec/framework/default-cmm.md#decrypt-materials"
  coverage_gap: 0.6
  coverage_evidence: >
    mpl/tests/test_default_cmm.rs: test_decrypt_materials_reproduced_ec_matching_values_succeeds,
    test_decrypt_materials_reproduced_ec_mismatched_values_fails, test_decrypt_materials_reproduced_ec_key_only_in_reproduced_is_appended,
    test_decrypt_materials_appends_reproduced_only_pairs_to_the_keyring_context,
    test_decrypt_materials_appends_when_reproduced_context_is_disjoint, test_decrypt_materials_appends_every_pair_when_message_context_is_empty,
    test_decrypt_materials_conflicting_reproduced_value_does_not_call_the_keyring, test_decrypt_materials_without_reproduced_context_is_unchanged.
  rationale: |
    The threat model calls this merge the sole guard that the decryptor's AAD equals the
    encryptor's. It is a pure Map function and a textbook 1b (abstract refinement) proof.
  scoring:
    severity: 3        # TM-MPL-017 High
    coverage_gap: 0.6
    feasibility: 0.4   # Low
    blast_radius: 4
    product: "3 × 0.6 × 0.4 × 4 = 2.88"
  quick_win: false
  dependencies: []
```

```yaml
recommendation:
  id: VR-2026-T13
  rank: 13
  priority_score: 2.52
  origin: threat-driven
  target:
    crate: aws-crypto-mpl
    file: mpl/src/aws_kms/cache_entry_identifier.rs
    function: build_cache_identifier
  property: >
    The SHA-384 preimage is exactly
    0x02‖0x00‖scope‖0x00‖partition‖0x00‖logicalName‖0x00‖bkid[‖0x00‖version].
    Encrypt (0x01) and decrypt (0x02) scopes never share a preimage, because scope sits at
    fixed offset 2. The preimage is injective in (partition, logicalName, bkid, version)
    whenever those fields contain no 0x00 byte. The internal `.expect` is unreachable
    because |output| == 48 == Sha384.output_len().
  formal_spec: |
    spec fn pre(s: u8, p: Seq<u8>, n: Seq<u8>, b: Seq<u8>, v: Option<Seq<u8>>) -> Seq<u8>
      { seq![0x02, 0x00, s, 0x00] + p + seq![0x00] + n + seq![0x00] + b
        + match v { Some(x) => seq![0x00] + x, None => seq![] } }
    fn build_cache_identifier(s, p, n, b, v) -> (out: [u8; 48])
      ensures out@ == sha384_spec(pre(s, p@, n@.as_bytes(), b@.as_bytes(), v.map(|x| x@.as_bytes())))   // sha384 uninterpreted
    proof fn scope_separation(s1, s2, ..) requires s1 != s2 ensures pre(s1, ..) != pre(s2, ..)
    proof fn injective_nul_free(..)
      requires no_nul(p1) && no_nul(n1) && no_nul(b1) && no_nul_opt(v1) && (same for 2) && pre(s,p1,n1,b1,v1) == pre(s,p2,n2,b2,v2)
      ensures p1 == p2 && n1 == n2 && b1 == b2 && v1 == v2
  tool: Verus
  agent: verus-header-parsing-proofs
  estimated_effort: 1 week
  threat_references:
    - id: TM-MPL-009
      category: Elevation of Privilege
      description: "Cache-identifier collision returns wrong branch-key materials — separator/domain-separation slice"
    - id: TM-MPL-010
      category: Information Disclosure / EoP
      description: "Shared-cache confusion"
  trace_to_spec: "spec/framework/aws-kms/aws-kms-hierarchical-keyring.md#appendix-a-cache-entry-identifier-formulas"
  coverage_gap: 0.7
  coverage_evidence: >
    mpl/tests/test_aws_kms_hierarchical_keyring.rs: cache_entry_identifier_for_encrypt_matches_manual_sha384,
    cache_entry_identifier_for_decrypt_matches_manual_sha384, cache_entry_identifier_encrypt_and_decrypt_differ_for_same_inputs,
    cache_entry_identifier_distinct_branch_key_ids_produce_distinct_outputs,
    cache_entry_identifier_distinct_versions_produce_distinct_outputs.
  rationale: |
    Expected finding: unconditional injectivity is FALSE. The default partition id is 16
    random bytes that may contain 0x00, and a caller-supplied partition id, logical name
    or bkid may contain NUL. For example, (p="a\0b", n="c") and (p="a", n="b\0c") give the
    same preimage. The layout is spec-mandated (Appendix A), and exploiting it requires
    control of operator configuration (TA3 co-tenant). So this is a spec-level observation
    for the threat-model owner, not a code change. SHA-384 collision resistance is excluded.
  scoring:
    severity: 3        # TM-MPL-009 High
    coverage_gap: 0.7
    feasibility: 0.4   # Low
    blast_radius: 3    # collisions matter for shared caches
    product: "3 × 0.7 × 0.4 × 3 = 2.52"
  quick_win: false
  dependencies: []
```

```yaml
recommendation:
  id: VR-2026-T14
  rank: 14
  priority_score: 2.52
  origin: threat-driven
  target:
    crate: aws-crypto-mpl
    file: mpl/src/aws_kms/hierarchical_keyring.rs
    function: as_branch_key_materials; cache_entry_within_limits; generate_partition_id; cache paths of on_encrypt / try_decrypt_edk
  property: >
    (a) The keyring only ever puts CachedMaterials::BranchKey. When reading, any other
    variant yields Err and is never coerced.
    (b) A cached entry is used only if elapsed(now, creation_time) ≤ ttl_seconds, with a
    clock-skew Err mapped to 0.
    (c) The default partition id is exactly 16 bytes with the v4 version nibble
    (b[6] >> 4 == 4) and the RFC 4122 variant (b[8] >> 6 == 0b10).
    (d) Cached entries carry no suite or commitment state; commitment is decided per call
    in DefaultCmm. This repo has no caching CMM, so a cached entry cannot carry a
    non-committing suite decision across keyrings.
  formal_spec: |
    fn as_branch_key_materials(e: &CacheEntry) -> (r: Result<&BranchKeyMaterials, MaterialsError>)
      ensures r.is_Ok() <==> e.materials is BranchKey
      ensures r matches Ok(b) ==> *b == e.materials->BranchKey_0
    fn cache_entry_within_limits(e: &CacheEntry, ttl: u64) -> (r: bool)
      ensures r <==> elapsed_secs_sat(ghost_now, e.creation_time) <= ttl
    fn generate_partition_id() -> (r: Result<Vec<u8>, MaterialsError>)
      ensures r matches Ok(v) ==> v@.len() == 16 && (v@[6] >> 4u8) == 4 && (v@[8] >> 6u8) == 2
    // on_encrypt / try_decrypt_edk: every put_cache_entry argument has materials is BranchKey
  tool: Verus
  agent: verus-header-parsing-proofs
  estimated_effort: 1 week
  threat_references:
    - id: TM-MPL-010
      category: Information Disclosure / EoP
      description: "Shared-cache confusion; commitment bypass via cache (advisory class; identifier unverified)"
  trace_to_spec: >
    spec/framework/aws-kms/aws-kms-hierarchical-keyring.md#partition-id, #cache-limit-ttl,
    #shared-cache-considerations
  coverage_gap: 0.7
  coverage_evidence: >
    mpl/tests/test_aws_kms_hierarchical_keyring.rs: partition_id_default_is_16_byte_v4_uuid,
    partition_id_default_two_calls_are_distinct, partition_id_provided_is_utf8_round_tripped,
    new_with_shared_cache_round_trips_provided_arc, on_encrypt_caches_branch_key_materials_after_keystore_call,
    on_decrypt_caches_branch_key_after_keystore_call; live-AWS
    test_aws_kms_hierarchical_keyring_integ.rs::integ_shared_cache_with_* (4 tests). No test injects a wrong-kind cache entry.
  rationale: |
    This is the provable part of the shared-cache threat: kind-checking, TTL gating and
    partition-id structure. Partition-id randomness and the operator's choice to share
    are excluded. Trusted: uuid::Builder::from_random_bytes external spec.
  scoring:
    severity: 3        # TM-MPL-010 High
    coverage_gap: 0.7
    feasibility: 0.4   # Low
    blast_radius: 3
    product: "3 × 0.7 × 0.4 × 3 = 2.52"
  quick_win: false
  dependencies: [VR-2026-T13]
```

```yaml
recommendation:
  id: VR-2026-T15
  rank: 15
  priority_score: 2.40
  origin: threat-driven
  target:
    crate: aws-crypto-mpl
    file: mpl/src/structures/encryption_context.rs
    function: EncryptionContext::serialize; EncryptionContext::deserialize
  property: >
    serialize returns Ok exactly when |ec| ≤ 65535 and every key and value is at most
    65535 bytes. On Ok it produces the spec layout: empty → []; otherwise be16(count),
    then for each entry in ascending key order be16(|k|)‖k‖be16(|v|)‖v. serialize is
    injective. deserialize(serialize(ec)) == Ok(ec). deserialize rejects count 0, trailing
    bytes, truncation and duplicate keys.
  formal_spec: |
    spec fn ser(m: Map<Seq<u8>,Seq<u8>>) -> Seq<u8>       // sorted-by-key layout per structures.md#serialization
    fn serialize(&self) -> (r: Result<Vec<u8>, MaterialsError>)
      ensures r.is_Ok() <==> self@.len() <= 0xFFFF && forall|k| self@.contains_key(k) ==> k.len() <= 0xFFFF && self@[k].len() <= 0xFFFF
      ensures r matches Ok(b) ==> b@ == ser(self@)
    proof fn ser_injective(m1, m2) requires ser(m1) == ser(m2) ensures m1 == m2
    proof fn round_trip(ec) requires ec.serialize() == Ok(b) ensures EncryptionContext::deserialize(&b) == Ok(ec)
    // EXPECTED COUNTEREXAMPLE (do not "fix" in the proof):
    //   deserialize(b) == Ok(ec) ==> ser(ec@) == b@   FAILS for b with entries out of ascending key order
  tool: Verus
  agent: verus-header-parsing-proofs
  estimated_effort: 2 weeks
  threat_references:
    - id: TM-MPL-013
      category: Tampering
      description: "AAD consistency depends on EC serialization determinism"
    - id: TM-MPL-017
      category: Tampering
      description: "Bound context must survive round-trip"
  trace_to_spec: "spec/framework/structures.md#serialization (Key Value Pair Count / Key Value Pair Entries)"
  coverage_gap: 0.5
  coverage_evidence: >
    mpl/tests/test_encryption_context.rs (37 tests), including test_round_trip_preserves_all_entries,
    test_serialize_produces_known_bytes, test_deserialize_known_bytes_produces_expected_context,
    test_multiple_entries_serialized_in_sorted_order, test_duplicate_key_rejected_on_deserialize,
    test_deserialize_rejects_trailing_bytes, test_key_value_pair_count_must_be_greater_than_zero,
    test_serialize_accepts_max_u16_{key_length,value_length,entry_count}, test_serialize_rejects_too_many_entries.
  rationale: |
    serialize feeds every AAD (raw AES and hierarchical). It follows the Vest
    round-trip/non-malleability shape (methodology only). Expected finding: structures.md
    says entries MUST be sorted ascending, but deserialize does not check order, because
    BTreeMap reorders. So several byte strings decode to one context, and
    serialize∘deserialize ≠ id. deserialize also does not validate UTF-8 (the test names
    `*_currently_unenforced` show the team knows about some of these gaps). deserialize
    has no call site in mpl/src (public API for downstream parsers). Whether to reject
    unsorted input is a product decision, so it is recorded and not changed.
  scoring:
    severity: 3        # TM-MPL-013 High
    coverage_gap: 0.5
    feasibility: 0.4   # Low
    blast_radius: 4
    product: "3 × 0.5 × 0.4 × 4 = 2.40"
  quick_win: false
  dependencies: []
```

```yaml
recommendation:
  id: VR-2026-T16
  rank: 16
  priority_score: 2.24
  origin: threat-driven
  target:
    crate: aws-crypto-mpl
    file: >
      mpl/src/aws_kms/branch_key_wrap.rs; mpl/src/aws_kms/hierarchical_keyring.rs; mpl/src/keyring/raw_aes_keyring.rs;
      mpl/src/structures/encryption_context.rs; mpl/src/aws_kms/mrk_match.rs; mpl/src/aws_kms/cache_entry_identifier.rs;
      mpl/src/cmm/default_cmm.rs; mpl/src/keystore/branch_key_store.rs
    function: >
      unwrap (3× .expect + slicing); HierarchicalKeyring::try_decrypt_edk (.expect on [28..44]);
      HierarchicalKeyring::on_decrypt (from_utf8); RawAesKeyring::on_decrypt (split_at) / decryptable_edk_iv (split_at, try_into);
      EncryptionContext::deserialize (indexing, offset arithmetic); aws_kms_mrk_match_for_decrypt (pa[5]/pb[5]);
      build_cache_identifier (.expect); DefaultCmm::get_encryption_materials (2× .expect);
      BranchKeyStore::{kms_client, ddb_client} (.expect, lines 172/181); version_key (`new_decrypt_only_ec[ATTR_TYPE]`)
  property: >
    For every input (EDK ciphertext, key_provider_info, serialized EC bytes, ARN strings)
    these paths return Ok/Err/bool and never panic. Each slice and index is preceded by a
    guard that implies it is in range, each try_into length is exact, and the offset
    arithmetic cannot overflow.
  formal_spec: |
    fn unwrap(m, ec, ct: &[u8]) -> (r)            // no requires: total
      // ct.len() >= 60 ⇒ [0..16],[16..28],[28..44],[44..len-16],[len-16..] in range; try_into lengths 16/12/16 exact
    fn try_decrypt_edk(..)                         // ct.len() >= 44 ⇒ [28..44] has len 16
    fn deserialize(b: &[u8]) -> (r)                // loop inv: 2 <= offset <= b.len(); offset+2 cannot overflow (b.len() <= isize::MAX)
    fn decryptable_edk_iv(&self, edk) -> (r)       // info.len() == |name|+20 ⇒ split_at(|name|), split_at(4), split_at(4) in range
    fn aws_kms_mrk_match_for_decrypt(a, b) -> (r)  // is_multi_region_arn(x) ⇒ segs(x).len() == 6 ⇒ index 5 valid
    fn build_cache_identifier(..)                  // output.len() == 48 == Sha384.output_len() ⇒ digest Ok (TCB: aws-lc output_len)
    // EXPECTED-UNPROVABLE obligation (report, do not axiomatize):
    //   default_cmm.rs:115  ecdsa_generate_keypair(alg).expect(..) — keygen/encoding can return Err (e.g. RNG failure)
  tool: Verus
  agent: verus-zero-panic
  estimated_effort: 1 week
  threat_references:
    - id: TM-MPL-023
      category: Denial of Service
      description: "Malformed EDK/ciphertext triggers panic instead of error"
  trace_to_spec: >
    spec/framework/aws-kms/aws-kms-hierarchical-keyring.md#ondecrypt, #branch-key-unwrapping;
    spec/framework/raw-aes-keyring.md#ondecrypt; spec/framework/structures.md#serialization
  coverage_gap: 0.7
  coverage_evidence: >
    test_aws_kms_hierarchical_keyring.rs: unwrap_too_short_ciphertext_returns_error, on_decrypt_skips_edks_with_non_utf8_provider_info;
    test_raw_aes_keyring.rs: test_on_decrypt_rejects_ciphertext_shorter_than_the_tag,
    test_on_decrypt_rejects_provider_info_with_wrong_tag_length, test_on_decrypt_rejects_provider_info_with_wrong_iv_length;
    test_encryption_context.rs: test_deserialize_insufficient_bytes_for_{count,key_length,key,value_length,value};
    test_aws_kms_mrk_match.rs: malformed_arn_and_mrk_arn_return_false.
  rationale: |
    The threat model's residual is that the `expect`s rely on the length checks before
    them. Verus turns that into a theorem for every input. The `ecdsa_generate_keypair`
    `.expect` is a real reachable abort on keygen failure. Mapping it to an error changes
    the failure mode, so it is flagged for the owner. Observation (DoS amplification, not
    a panic): an EDK of 44–59 bytes passes try_decrypt_edk's guard and triggers a
    cache/keystore lookup, possibly KMS+DDB calls, before unwrap rejects it as too short.
  scoring:
    severity: 2        # TM-MPL-023 Medium
    coverage_gap: 0.7
    feasibility: 0.4   # Low
    blast_radius: 4
    product: "2 × 0.7 × 0.4 × 4 = 2.24"
  quick_win: false
  dependencies: []
```

```yaml
recommendation:
  id: VR-2026-T17
  rank: 17
  priority_score: 1.92
  origin: threat-driven
  target:
    crate: aws-crypto-mpl
    file: mpl/src/keystore/kms_ops.rs; mpl/src/keystore/kms_config.rs
    function: resolve_keystore_arn (Discovery / MrDiscovery arms); reject_alias_arn; rewrite_arn_region; parse_arn
  property: >
    In Discovery, the result is Ok(record ARN) exactly when parse_arn succeeds and
    resource_type ≠ "alias". In MrDiscovery, parse_arn(result) equals parse_arn(record)
    with only the region replaced. parse/format round-trip: for every well-formed ArnParts
    p (no ':' in partition/service/region/account, no '/' in resource_type),
    parse_arn(format(p)) == Ok(p).
  formal_spec: |
    fn resolve_keystore_arn(c, rec) -> (r)
      ensures c is Discovery ==> (r.is_Ok() <==> parse_arn_spec(rec@) matches Ok(p) && p.resource_type@ != "alias"@)
                              && (r matches Ok(k) ==> k@ == rec@)
      ensures c matches MrDiscovery{region} && r matches Ok(k) ==>
                parse_arn_spec(k@) == Ok(parse_arn_spec(rec@)->Ok_0.with_region(region@))
    proof fn parse_format_round_trip(p: ArnParts) requires well_formed(p) ensures parse_arn_spec(format_spec(p)) == Ok(p)
  tool: Verus
  agent: verus-header-parsing-proofs
  estimated_effort: 1 week
  threat_references:
    - id: TM-MPL-007
      category: Elevation of Privilege
      description: "Discovery/MRDiscovery decrypts under an alias or attacker-region MRK"
  trace_to_spec: "spec/framework/branch-key-store.md#discovery, #mrdiscovery, #aws-kms-branch-key-decryption"
  coverage_gap: 0.8
  coverage_evidence: >
    mpl/tests/test_keystore_kms_config.rs: parse_arn_extracts_all_six_segments, parse_arn_rejects_too_few_segments,
    parse_arn_rejects_missing_resource_slash, parse_arn_rejects_empty_string, parse_arn_rejects_non_arn_prefix.
    reject_alias_arn and rewrite_arn_region are private with no unit test. Live-AWS only:
    test_aws_kms_hierarchical_keyring_integ.rs integ_discovery_keystore_*, integ_mr_discovery_keystore_*.
  rationale: |
    Expected finding: the spec says "Any MRK ARN discovered will be changed to this
    region", but the code rewrites the region of EVERY non-alias record ARN, including
    single-Region keys. A rewritten single-Region key id fails at KMS, which is fail
    closed (availability, not confidentiality). It still deviates from the spec and should
    be confirmed with the owner. Also noted: Discovery does not check service == "kms";
    KMS rejects other ARNs.
  scoring:
    severity: 3        # TM-MPL-007 High
    coverage_gap: 0.8
    feasibility: 0.4   # Low
    blast_radius: 2    # opt-in Discovery / MRDiscovery
    product: "3 × 0.8 × 0.4 × 2 = 1.92"
  quick_win: false
  dependencies: []
```

```yaml
recommendation:
  id: VR-2026-T18
  rank: 18
  priority_score: 1.92
  origin: threat-driven
  target:
    crate: aws-crypto-mpl
    file: mpl/src/keystore/branch_key_store.rs
    function: <BranchKeyStore as Keystore>::version_key — EC-derivation fragment (to be extracted as a pure helper for the proof)
  property: >
    Given the old ACTIVE EC: the new DECRYPT_ONLY EC = old minus `version`, with
    type = "branch:version:"+v and create-time = ts. The new ACTIVE EC = DECRYPT_ONLY with
    version = "branch:version:"+v and type = "branch:ACTIVE". Both preserve branch-key-id,
    kms-arn, hierarchy-version, tablename and every `aws-crypto-ec:` entry. The result
    agrees with keystore::encryption_context::{decrypt_only,active}_encryption_context for
    the same inputs. The old record is authenticated by ReEncrypt with source EC ==
    destination EC == the reconstructed old EC.
  formal_spec: |
    fn derive_version_ecs(old: &BTreeMap<String,String>, v: &str, ts: String) -> (r: (BTreeMap<..>, BTreeMap<..>))
      requires old@["type"@] == "branch:ACTIVE"@
      ensures r.0@ == old@.remove("version"@).insert("type"@, "branch:version:"@ + v@).insert("create-time"@, ts@)
      ensures r.1@ == r.0@.insert("version"@, "branch:version:"@ + v@).insert("type"@, "branch:ACTIVE"@)
      ensures forall|k| preserved(k) ==> r.0@[k] == old@[k] && r.1@[k] == old@[k]
        // preserved(k) := k ∈ {branch-key-id, kms-arn, hierarchy-version, tablename} || starts_with(k, "aws-crypto-ec:")
  tool: Verus
  agent: verus-header-parsing-proofs
  estimated_effort: 1 week
  threat_references:
    - id: TM-MPL-016
      category: Tampering
      description: "VersionKey optimistic-lock bypass / version race — provable slice: EC derivation + self-authentication"
  trace_to_spec: >
    spec/framework/branch-key-store.md#versionkey, #authenticating-a-keystore-item,
    #active-encryption-context, #decrypt_only-encryption-context
  coverage_gap: 0.8
  coverage_evidence: >
    mpl/tests/test_keystore_branch_key_store.rs: version_key_dispatches_to_dynamodb, version_key_with_discovery_config_fails;
    live-AWS test_keystore_branch_key_store_integ.rs::integ_version_key_round_trips.
    mpl/tests/test_keystore_encryption_context.rs::active_is_decrypt_only_with_type_and_version_overrides covers only the
    builder module, not version_key's own inline derivation.
  rationale: |
    version_key builds the new contexts inline instead of reusing the builder module, so
    agreement between the two is unproven. DynamoDB transaction and ConditionExpression
    semantics are excluded (external service).
  scoring:
    severity: 2        # TM-MPL-016 Medium
    coverage_gap: 0.8
    feasibility: 0.4   # Low
    blast_radius: 3
    product: "2 × 0.8 × 0.4 × 3 = 1.92"
  quick_win: false
  dependencies: [VR-2026-T01]
```

```yaml
recommendation:
  id: VR-2026-T19
  rank: 19
  priority_score: 1.92
  origin: threat-driven
  target:
    crate: aws-crypto-mpl
    file: mpl/src/aws_kms/hierarchical_keyring.rs
    function: HierarchicalKeyring::{resolve_branch_key_id, on_encrypt, on_decrypt, try_decrypt_edk}
  property: >
    With a static id configured, resolve_branch_key_id returns exactly that id. on_decrypt
    passes an EDK to try_decrypt_edk only if key_provider_id == "aws-kms-hierarchy" and
    utf8(key_provider_info) == the resolved bkid. try_decrypt_edk queries the
    cache/keystore with that same bkid and with the version decoded from ct[28..44].
    on_encrypt emits an EDK whose provider-id is "aws-kms-hierarchy" and whose provider-info
    is the resolved bkid's bytes.
  formal_spec: |
    fn resolve_branch_key_id(&self, ec) -> (r) ensures self.branch_key_id matches Some(id) ==> r == Ok(id)
    fn on_decrypt(&self, m, edks) -> (r)
      ensures forall|e| ghost_attempted.contains(e) ==> e.key_provider_id@ == "aws-kms-hierarchy"@
                && utf8_decode(e.key_provider_info@) == Some(ghost_bkid@)
    fn try_decrypt_edk(&self, m, e, bkid) -> (r)
      ensures ghost_keystore_args == (bkid@, uuid_str(e.ciphertext@.subrange(28,44)))
           && ghost_cache_id == build_cache_identifier_spec(0x02, self.partition_id_bytes@, self.logical_keystore_name@, bkid@, Some(..))
    fn on_encrypt(&self, m) -> (r)
      ensures r matches Ok(m2) ==> m2.edks@.last().key_provider_id@ == "aws-kms-hierarchy"@
           && m2.edks@.last().key_provider_info@ == ghost_bkid@.as_bytes()
  tool: Verus
  agent: verus-header-parsing-proofs
  estimated_effort: 1 week
  threat_references:
    - id: TM-MPL-003
      category: Spoofing
      description: "Malicious branch-key supplier returns attacker-chosen id — provable slice: the id is bound consistently"
  trace_to_spec: >
    spec/framework/aws-kms/aws-kms-hierarchical-keyring.md#onencrypt, #ondecrypt, #branch-key-supplier
  coverage_gap: 0.6
  coverage_evidence: >
    mpl/tests/test_aws_kms_hierarchical_keyring.rs: on_decrypt_skips_edks_with_wrong_provider_id,
    on_decrypt_skips_edks_with_non_utf8_provider_info, on_decrypt_skips_edks_with_wrong_branch_key_id,
    on_encrypt_uses_branch_key_supplier_when_configured, on_decrypt_uses_branch_key_supplier_when_configured,
    on_decrypt_calls_keystore_get_branch_key_version_with_uuid_from_ciphertext.
  rationale: |
    The threat model's mitigation claim is that "the chosen id is bound into cache-id and
    AAD". This target proves the code-side half. The supplier's own correctness is
    caller code and is excluded. Observation: on_encrypt does not assert
    bkm.branch_key_id == the resolved bkid, while the AAD uses bkm.branch_key_id(). A
    mismatched keystore or cache answer therefore produces an EDK that cannot be
    decrypted (fail closed, availability only). Needs the pure filter/binding logic
    extracted out of the async fns.
  scoring:
    severity: 2        # TM-MPL-003 Medium
    coverage_gap: 0.6
    feasibility: 0.4   # Low
    blast_radius: 4
    product: "2 × 0.6 × 0.4 × 4 = 1.92"
  quick_win: false
  dependencies: [VR-2026-T13]
```

```yaml
recommendation:
  id: VR-2026-T20
  rank: 20
  priority_score: 1.68
  origin: threat-driven
  target:
    crate: aws-crypto-mpl
    file: mpl/src/keyring/raw_aes_keyring.rs
    function: RawAesKeyring::serialize_provider_info; RawAesKeyring::decryptable_edk_iv
  property: >
    serialize_provider_info(iv) = key_name ‖ be32(128) ‖ be32(12) ‖ iv. decryptable_edk_iv
    returns Some(iv) exactly when the provider id equals the namespace and the info has
    that shape for some 12-byte iv, and it then returns exactly those 12 bytes. Round
    trip: decryptable_edk_iv(EDK{namespace, serialize_provider_info(iv), _}) == Some(iv).
    Total, with no panic.
  formal_spec: |
    spec fn info(name: Seq<u8>, iv: Seq<u8>) -> Seq<u8> { name + be32(128) + be32(12) + iv }
    fn serialize_provider_info(&self, iv: &[u8]) -> (r: Vec<u8>)
      requires iv@.len() == 12  ensures r@ == info(self.key_name@.as_bytes(), iv@)
    fn decryptable_edk_iv(&self, e: &EncryptedDataKey) -> (r: Option<&[u8]>)
      ensures r matches Some(iv) <==> e.key_provider_id@ == self.key_namespace@ && iv@.len() == 12
                && e.key_provider_info@ == info(self.key_name@.as_bytes(), iv@)
    proof fn round_trip(k, iv) requires iv@.len() == 12
      ensures k.decryptable_edk_iv(&EDK::new(k.key_namespace, k.serialize_provider_info(iv), ct)) == Some(iv)
  tool: Verus
  agent: verus-header-parsing-proofs
  estimated_effort: 1 week
  threat_references:
    - id: TM-MPL-023
      category: Denial of Service
      description: "Malformed EDK (provider info) must be rejected, not panic"
    - id: TM-MPL-011
      category: Elevation of Privilege
      description: "Decryptor must use exactly the IV the encryptor drew"
    - id: TM-MPL-001
      category: Spoofing
      description: "Provider-id filter on decrypt"
  trace_to_spec: "spec/framework/raw-aes-keyring.md#key-provider-information, #ondecrypt"
  coverage_gap: 0.7
  coverage_evidence: >
    mpl/tests/test_raw_aes_keyring.rs: test_encrypted_data_key_wire_format, test_on_decrypt_key_name_mismatch,
    test_on_decrypt_rejects_provider_info_with_wrong_tag_length, test_on_decrypt_rejects_provider_info_with_wrong_iv_length,
    test_on_decrypt_skips_edk_with_wrong_key_provider_id.
  rationale: "Small binary codec and a clean Vest-style round-trip. It is the parser half of T07."
  scoring:
    severity: 2        # TM-MPL-023 Medium
    coverage_gap: 0.7
    feasibility: 0.4   # Low
    blast_radius: 3    # raw-AES keyring users
    product: "2 × 0.7 × 0.4 × 3 = 1.68"
  quick_win: false
  dependencies: []
```

```yaml
recommendation:
  id: VR-2026-T21
  rank: 21
  priority_score: 1.68
  origin: threat-driven
  target:
    crate: aws-crypto-mpl
    file: mpl/src/cmc/storm_tracking.rs
    function: ValidatedConfig::from_raw; StormTrackingCmc::{classify_and_mark, wait_for_leader, state_locked, put_cache_entry}; within_grace_period; within_grace_interval
  property: >
    from_raw returns Ok exactly when every knob is ≥ 1 and
    grace_interval ≤ inflight_ttl ≤ grace_period. Under the mutex every production state
    step preserves |inflight| ≤ fan_out (test-utils mark_inflight is excluded).
    Ready(None) marks the key in-flight at `now`. A key already in flight yields a new
    leader only after its grace interval has elapsed, so there is at most one new leader
    per key per grace interval. A cache hit never returns a different entry.
    put_cache_entry writes the inner cache before clearing the in-flight mark.
    within_grace_* match the spec formulas. wait_for_leader returns Err only once a
    Some(deadline) has passed.
  formal_spec: |
    fn from_raw(gp, gi, fo, it, sm, tu) -> (r)
      ensures r.is_Ok() <==> gp >= 1 && gi >= 1 && it >= 1 && fo >= 1 && sm >= 1
                          && d(gi) <= d(gp) && d(it) <= d(gp) && d(gi) <= d(it)
    spec fn inv(s: StormTrackingState, fo: usize) -> bool { s.inflight@.len() <= fo }
    fn classify_and_mark(&self, s: &mut StormTrackingState, id, cached, now) -> (r)
      requires inv(*old(s), self.fan_out)
      ensures inv(*s, self.fan_out)
      ensures r matches Ok(Ready(None)) ==> s.inflight@[id@] == now
      ensures r matches Ok(Ready(None)) && old(s).inflight@.contains_key(id@)
                ==> !within_grace_interval_spec(old(s).inflight@[id@], now, self.grace_interval)
      ensures cached matches Some(e) && r matches Ok(Ready(Some(x))) ==> x == e
    fn within_grace_period(exp, now, gp) -> (r) ensures r <==> sat_sub(exp, gp) <= now
    fn within_grace_interval(t, now, gi) -> (r) requires st_add_ok(t, gi) ensures r <==> now < t + gi   // see T06
  tool: Verus
  agent: verus-zero-panic   # safety/no-panic + sequential state machine; concurrency (cat. 4a/4b ghost permissions) → specialist
  estimated_effort: 1 month
  threat_references:
    - id: TM-MPL-018
      category: Denial of Service
      description: "Storm-tracking mis-configuration or logic error causes stampede / deadlock / InFlightTTL failures"
  trace_to_spec: >
    spec/framework/storm-tracking-cryptographic-materials-cache.md#initialization, #in-flight, #putcacheentry,
    #within-grace-period, #within-grace-interval, #getcacheentry
  coverage_gap: 0.6
  coverage_evidence: >
    mpl/tests/test_storm_tracking_cmc.rs (~40 tests), including test_grace_interval_must_not_exceed_grace_period,
    test_inflight_ttl_must_not_exceed_grace_period, test_grace_interval_must_not_exceed_inflight_ttl,
    test_fan_out_zero_is_rejected, test_get_hit_within_grace_inflight_within_interval_returns_entry,
    test_get_hit_returns_entry_when_fanout_saturated, test_put_clears_inflight_bit, test_block_miss_inflight_deadline_fires_when_exceeded,
    test_concurrent_gets_on_same_key_coalesce_to_one_refresh, test_within_grace_{period,interval}_matches_spec_formula.
  rationale: |
    The threat model calls this an intricate state machine and a "strong verification
    target". From reading the code, the |inflight| ≤ fan_out invariant is expected to
    hold on every production path. The atomic, under-lock classification is provable
    sequentially. Interleaving-level properties across the two mutexes (LocalCmc and
    storm state) need tracked ghost state and are flagged for a concurrency specialist.
    Liveness, and the Tokio-only runtime requirement, are excluded.
  scoring:
    severity: 2        # TM-MPL-018 Medium
    coverage_gap: 0.6
    feasibility: 0.7   # Medium
    blast_radius: 2    # opt-in storm-tracking cache
    product: "2 × 0.6 × 0.7 × 2 = 1.68"
  quick_win: false
  dependencies: [VR-2026-T06]
```

```yaml
recommendation:
  id: VR-2026-T22
  rank: 22
  priority_score: 1.60
  origin: threat-driven
  target:
    crate: aws-crypto-mpl + aws-mpl-primitives
    file: mpl/src/structures/{algorithm_suite.rs, branch_key_materials.rs, beacon_key_materials.rs}; mpl/src/keyring/raw_aes_keyring.rs; prim/src/ecdsa.rs
    function: >
      Debug for PlaintextDataKey, SigningKey, SymmetricSigningKey, BranchKeyMaterials, BeaconKeyMaterials,
      RawAesKeyring, prim::SignatureKeyPair; derived Debug of EncryptionMaterials, DecryptionMaterials,
      CachedMaterials, CacheEntry (composition)
  property: >
    Noninterference: each Debug output depends only on non-secret fields (lengths, ids,
    EC) and never on secret bytes. Two values that differ only in secret bytes of the
    same length format identically. The derived Debug impls of the containers reach
    secret fields only through those redacting impls.
  formal_spec: |
    // core::fmt modeled by an external spec (TCB): fmt_spec(v) -> Seq<char>
    proof fn pdk_redacted(k1: Seq<u8>, k2: Seq<u8>) requires k1.len() == k2.len()
      ensures fmt_spec(PlaintextDataKey(k1)) == fmt_spec(PlaintextDataKey(k2))
    // same shape for SigningKey, SymmetricSigningKey; BranchKeyMaterials (branch_key);
    // BeaconKeyMaterials (beacon_key, hmac_keys values); RawAesKeyring (wrapping_key); SignatureKeyPair (signing_key)
    proof fn materials_redacted(m1, m2) requires differ_only_in_secrets(m1, m2) ensures fmt_spec(m1) == fmt_spec(m2)
  tool: Verus
  agent: verus-unsafe-ffi-safety
  estimated_effort: 1 week
  threat_references:
    - id: TM-MPL-021
      category: Information Disclosure
      description: "Secret bytes leak via Debug/error/log formatting"
  trace_to_spec: "baseline assurance, no single clause (structures.md defines these fields as secret)"
  coverage_gap: 0.5
  coverage_evidence: >
    mpl/tests/test_algorithm_suite.rs (test_plaintext_data_key_debug_redacts, test_signing_key_debug_redacts,
    test_symmetric_signing_key_debug_redacts), test_branch_key_materials.rs::test_debug_redacts_branch_key,
    test_beacon_key_materials.rs::test_debug_redacts_secret_material, test_raw_aes_keyring.rs::test_debug_does_not_leak_the_wrapping_key,
    test_encryption_materials.rs::{test_signing_key_debug_redacted, test_symmetric_signing_key_debug_redacted},
    prim/tests/test_ecdsa.rs::test_signature_key_pair_debug_redacts_signing_key.
  rationale: |
    The threat model's residual ("confirm PlaintextDataKey/SigningKey Debug redaction") is
    already resolved in code (see Correction C7). The proof turns the substring tests into
    a guarantee that holds for all values and that also covers the derived container
    impls. prim::Prk derives Debug over aws_lc_rs::hkdf::Prk. In the aws-lc-rs 1.17.1
    source in the local cargo registry, that impl prints only algorithm and mode. mpl pins
    =1.17.0, which was not separately checked. Treat it as trusted.
  scoring:
    severity: 2        # TM-MPL-021 Medium
    coverage_gap: 0.5
    feasibility: 0.4   # Low
    blast_radius: 4
    product: "2 × 0.5 × 0.4 × 4 = 1.60"
  quick_win: false
  dependencies: []
```

```yaml
recommendation:
  id: VR-2026-T23
  rank: 23
  priority_score: 1.26
  origin: threat-driven
  target:
    crate: aws-crypto-mpl
    file: mpl/src/cmc/local.rs
    function: LocalCmc::{with_clock_impl, put_cache_entry, get_cache_entry, prune_tail, delete_cache_entry}
  property: >
    inner is None exactly when entry_capacity == 0, and otherwise len ≤ entry_capacity
    after every operation. get never returns an entry with expiry_time ≤ now. prune_tail
    scans exactly min(tail, len) LRU entries, with no underflow and no panic. A poisoned
    lock surfaces as Err, never as a panic.
  formal_spec: |
    spec fn inv(c: LocalCmc) -> bool { (c.inner is None <==> c.entry_capacity == 0)
                                    && (c.inner matches Some(l) ==> l@.len() <= c.entry_capacity) }
    fn put_cache_entry(&self, id, e) -> (r) requires inv(*self) ensures inv(*self)
    fn get_cache_entry(&self, id) -> (r) requires inv(*self)
      ensures inv(*self) && (r matches Ok(Some(e)) ==> e.expiry_time > ghost_now)
    // lru::LruCache external spec (TCB): put evicts LRU when len == cap; peek/get/pop model a Map + order Seq
  tool: Verus
  agent: verus-zero-panic
  estimated_effort: 2 weeks
  threat_references:
    - id: TM-MPL-022
      category: Denial of Service
      description: "Cache exhaustion / eviction thrash forces KMS-call storm — provable slice: capacity + TTL invariants"
  trace_to_spec: >
    spec/framework/local-cryptographic-materials-cache.md#entry-capacity, #entry-pruning-tail-size,
    #put-cache-entry, #get-cache-entry, #pruning
  coverage_gap: 0.6
  coverage_evidence: >
    mpl/tests/test_local_cmc.rs: test_capacity_invariant_holds_after_put_returns, test_put_over_capacity_evicts_lru,
    test_initialization_accepts_zero_and_max_capacity, test_get_drops_ttl_expired_entry, test_get_at_exact_expiry_returns_none,
    test_pruning_evicts_all_ttl_expired_in_tail, test_pruning_does_not_evict_outside_tail,
    test_get_evicts_expired_entry_outside_tail_window, test_concurrent_put_atomic_visibility.
  rationale: "Low severity. Worth doing mainly because StormTrackingCmc (T21) is built on it. KMS throttling itself is excluded."
  scoring:
    severity: 1        # TM-MPL-022 Low
    coverage_gap: 0.6
    feasibility: 0.7   # TM-MPL-022 Likelihood Medium
    blast_radius: 3
    product: "1 × 0.6 × 0.7 × 3 = 1.26"
  quick_win: false
  dependencies: []
```

```yaml
recommendation:
  id: VR-2026-T24
  rank: 24
  priority_score: 1.20
  origin: threat-driven
  target:
    crate: aws-crypto-mpl
    file: mpl/src/keyring/raw_aes_keyring.rs
    function: RawAesKeyring::new; <RawAesKeyring as Keyring>::on_encrypt (provider-id of emitted EDK)
  property: >
    new returns Err for every namespace that starts with "aws-kms". So every constructed
    keyring, and every EDK it emits (key_provider_id == key_namespace), has a
    provider-id that does not start with "aws-kms". That covers the "aws-kms",
    "aws-kms-hierarchy", "aws-kms-rsa" and "aws-kms-ecdh" ids.
  formal_spec: |
    fn new(ns, name, key, alg) -> (r: Result<Self, MaterialsError>)
      ensures starts_with(ns@, "aws-kms"@) ==> r.is_Err()
      ensures r matches Ok(k) ==> !starts_with(k.key_namespace@, "aws-kms"@)
    fn on_encrypt(&self, m) -> (r) ensures r matches Ok(m2) ==> m2.edks@.last().key_provider_id@ == self.key_namespace@
  tool: Verus
  agent: verus-header-parsing-proofs
  estimated_effort: 1 day
  threat_references:
    - id: TM-MPL-001
      category: Spoofing
      description: "Raw-AES keyring emits EDK whose key-provider-id impersonates an AWS KMS keyring"
  trace_to_spec: "spec/framework/raw-aes-keyring.md#initialization"
  coverage_gap: 0.5
  coverage_evidence: >
    mpl/tests/test_raw_aes_keyring.rs: test_new_rejects_reserved_aws_kms_key_namespace,
    test_new_rejects_key_provider_ids_of_the_aws_kms_keyrings, test_new_accepts_the_raw_ecdh_key_provider_id,
    test_encrypted_data_key_wire_format.
  rationale: |
    A trivial, well-tested property, kept so that TM-MPL-001 has a proof-grade closure.
    The "prefix heuristic only" residual stays a design note: case-variant namespaces
    such as "AWS-KMS" are accepted, but KMS keyrings compare provider-ids exactly, so they
    do not impersonate.
  scoring:
    severity: 2        # TM-MPL-001 Medium
    coverage_gap: 0.5
    feasibility: 0.4   # Low
    blast_radius: 3
    product: "2 × 0.5 × 0.4 × 3 = 1.20"
  quick_win: false
  dependencies: []
```

## 4. Excluded (not Verus-provable, or not present in this repo)

Each item is classified with the `verus-capabilities.md` decision aid. **Fully excluded** means the threat has no provable code slice. **Partial** means the provable slice became a target above and only the remainder is excluded.

| Threat | Scope | Excluded part | Reason |
|---|---|---|---|
| TM-MPL-019 | **Fully excluded** | Missing Duvet coverage lets a spec MUST regress | Process / traceability item. Adding `//=` annotations is tooling work with no code property to prove. The targets above already cite spec sections by hand. |
| TM-MPL-020 | **Fully excluded** | No audit binding between MPL operations and KMS/DDB calls | Repudiation / operational control (CloudTrail, user-agent). There is no behavior in `mpl/src` to prove. |
| TM-MPL-001 | Partial (→ T24, T20) | Whether downstream consumers trust provider-ids case-insensitively | Behavior of other components. Design note only. |
| TM-MPL-002 | Partial (→ T03, T01) | KMS key policy / grants; KMS correctly enforcing EC-as-AAD; Discovery mode trusting the record's `kms-arn` by design | External-service policy (decision aid: "No — external service"). Discovery trust is a configuration choice. |
| TM-MPL-003 | Partial (→ T19) | Correctness / honesty of the caller-supplied `BranchKeySupplier` | Caller code outside the crate. The trait is open. |
| TM-MPL-004 | Partial (→ T11) | KMS-side guarantee that same-id MRK replicas share key material | External service semantics. |
| TM-MPL-005 | Partial (→ T01, T02) | Rollback / replay of an older but authentic record by a DDB writer; cryptographic integrity of KMS ciphertext under EC | Storage freshness is not enforced by MPL code and is a storage/design responsibility. AEAD integrity is cryptographic hardness. |
| TM-MPL-006 | Partial (→ T09) | Cryptographic security of key commitment; ESDK message-level commitment verification | Crypto hardness. Message format is out of MPL scope per the threat model. |
| TM-MPL-007 | Partial (→ T17) | KMS regional replica availability; KMS rejecting non-KMS / wrong-region ARNs | External service. |
| TM-MPL-008 | Partial (→ T09) | Invisible-Salamanders resistance of the HKDF-SHA512 commit-key suites | Cryptographic hardness (decision aid: "No"). |
| TM-MPL-009 | Partial (→ T13) | SHA-384 collision / second-preimage resistance; operator never configuring two physical stores with one logical name | Crypto hardness. The configuration MUST is documented but not enforceable in code. |
| TM-MPL-010 | Partial (→ T13, T14) | Partition-id randomness; operator choice to share partition ids; the CVE-2026-6550 / GHSA-v638-38fc-rhfv advisory (**identifier unverified**) | Probabilistic plus operational. The repo has no caching CMM, so the advisory's caching-layer surface is absent here (Correction C4). |
| TM-MPL-011 | Partial (→ T07, T20) | CSPRNG quality and 96-bit random-nonce uniqueness (birthday bound) | Probabilistic secrecy / RNG responsibility (decision aid: "No — probabilistic"). |
| TM-MPL-012 | Partial (→ T04) | 224-bit salt‖IV collision bound; yearly rotation cadence | Probabilistic plus operational. |
| TM-MPL-013 | Partial (→ T10, T15) | GCM's cryptographic binding of AAD | Crypto hardness. The layout/consistency slice is fully targeted. |
| TM-MPL-014 | Partial (→ T05) | PRF security of HMAC-SHA-256 KBKDF; correctness of aws-lc-rs's KBKDF implementation | Crypto hardness / third-party (prim vectors in `prim/tests/test_kbkdf_ctr_hmac.rs` test it, but it is outside this repo's proof scope). |
| TM-MPL-015 | Partial (→ T08) | Secret residency in freed heap, swap and core dumps; copies made by `Clone` (BranchKeyMaterials in the cache, PlaintextDataKey), `Vec` reallocation, and aws-lc internal buffers; **absence of any Drop-driven zeroization** for BranchKeyMaterials, SigningKey, SymmetricSigningKey, derived-key locals, `RawAesKeyring.wrapping_key`, and PlaintextDataKey itself | No code exists to verify. Verus would only confirm the absence, and the fix is a design change for the owner. Allocator/OS memory is outside Verus's model. Volatile non-elision is a language guarantee and is trusted. |
| TM-MPL-016 | Partial (→ T18) | DynamoDB `TransactWriteItems` atomicity and `ConditionExpression` evaluation (`attribute_exists … AND #enc = :encOld`) | External-service semantics. |
| TM-MPL-017 | — (fully targeted → T12, T15) | — | Nothing excluded. |
| TM-MPL-018 | Partial (→ T21, T06) | Liveness under a real async scheduler; the Tokio-only runtime requirement (`tokio::time::sleep` panics under other executors); wall-clock behavior | Liveness and runtime environment are deployment constraints, not functional properties of the code. |
| TM-MPL-021 | Partial (→ T22) | What applications log; contents of AWS SDK error causes carried by `KeystoreError` | External code. |
| TM-MPL-022 | Partial (→ T23, T06) | KMS throttling / call-rate behavior under eviction thrash; capacity sizing | Performance/availability and operations. |
| TM-MPL-023 | Partial (→ T16, T20, T06) | `ecdsa_generate_keypair(..).expect` success depends on aws-lc-rs keygen never failing | Cannot be discharged without an unjustified "always Ok" axiom. Kept inside T16 as an expected-unprovable obligation (a finding), not hidden. |

## 5. Corrections to the threat model (names and facts verified against code)

| # | Threat-model text | Reality in this branch | Effect on targets |
|---|---|---|---|
| C1 | TM-MPL-004 component "`mrk_match`" | The function is `aws_kms_mrk_match_for_decrypt` in `mpl/src/aws_kms/mrk_match.rs`, with private helpers `is_multi_region_arn` / `is_alias_arn`. `is_arn_compatible` is in `mpl/src/keystore/kms_config.rs`, as stated. | T11 uses the real names. |
| C2 | TM-MPL-009 / §6 DFD: "`cache_id = SHA384(0x02\|0x01\|partition\|logicalName\|bkid)`", decrypt "`…\|bkid\|version`" | The real preimage has NUL separators: `0x02‖0x00‖scope‖0x00‖partition‖0x00‖logicalName‖0x00‖bkid[‖0x00‖version]`. On decrypt, `version` is the 36-char hyphenated UTF-8 **string** (`uuid_16_bytes_to_str`), not the 16 raw bytes. The function is `cache_entry_identifier::build_cache_identifier`. | T13 uses the real layout. |
| C3 | TM-MPL-005 mitigation cites only `kms_ops::build_authenticated_encryption_context` | That function builds the KMS Decrypt AAD only. Reconstruction (`get_active_branch_key` / `get_branch_key_version` / `get_beacon_key`) and VersionKey's ReEncrypt use a **separate private** `BranchKeyStore::build_auth_ec`. The pub `record::encryption_context_from_item` / `to_attribute_map` are **not on the production path**: production writes with private `item_from_ec_and_enc` and reads with `record_from_ddb_item`. | T01 covers all builders. |
| C4 | TM-MPL-006 component list includes "`cmc`" ("bypass commitment via cache") | `mpl/src/cmm/` contains only `DefaultCmm`. There is **no caching CMM**. The only cache consumer is `HierarchicalKeyring`, and it stores only `CachedMaterials::BranchKey`. `CachedMaterials::Encryption/Decryption` have no producer in `mpl/src`. | T09 and T14 scope accordingly. |
| C5 | TM-MPL-016 "`branch_key_store::version_key`" | The real item is the trait impl `<BranchKeyStore as Keystore>::version_key` in `mpl/src/keystore/branch_key_store.rs`. It builds the new ECs inline rather than through `keystore/encryption_context.rs`. | T18. |
| C6 | TM-MPL-015 "PlaintextDataKey (has manual `zeroize`, not Drop-driven)" | Confirmed, and stronger: `zeroize` has **zero call sites in `mpl/src`**, only the two tests call it. No `Drop` impl exists in `mpl/src` or `prim/src`. | T08 proves the primitive. The runtime gap is excluded. |
| C7 | TM-MPL-021 residual "confirm `PlaintextDataKey`/`SigningKey` Debug redaction" | Resolved: both have custom redacting `Debug` impls (`algorithm_suite.rs`), as do `SymmetricSigningKey`, `BranchKeyMaterials`, `BeaconKeyMaterials`, `RawAesKeyring` and `prim::SignatureKeyPair`. They are tested in `test_algorithm_suite.rs`, `test_branch_key_materials.rs`, `test_beacon_key_materials.rs`, `test_raw_aes_keyring.rs` and `prim/tests/test_ecdsa.rs`. | T22 upgrades the tests to a proof. |
| C8 | TM-MPL-023 mitigation lists only unwrap / `try_decrypt_edk` / `uuid_str_to_16_bytes` | Other panic sites exist: `.expect` in `cache_entry_identifier.rs:64` (provably unreachable); `default_cmm.rs:100` (unreachable) and `default_cmm.rs:115` (`ecdsa_generate_keypair` — **reachable on keygen failure**); `branch_key_store.rs:172/181` (construction invariant); `mrk_match.rs` `pa[5]` (guarded); and the config-driven `SystemTime + Duration` overflow (T06), which the threat model does not list. The `.expect("lock poisoned")` calls in `storm_tracking.rs:323–342` are behind the `test-utils` feature and not in production. | T16, T06. |
| C9 | §2 diagram "aws-lc-rs FFI (unsafe edge…)"; §5 TB5 | No FFI or unsafe code exists in this repo's sources at that edge. Any FFI is inside the third-party `aws-lc-rs`/`aws-lc-sys`. `prim` does not itself length-check AES key/IV/tag. It relies on aws-lc-rs returning `Err`. | T07 targets the caller-side preconditions. |
| C10 | TM-MPL-013 "version parsed strictly as 36-char canonical UUID" | Correct. The parser is the private `branch_key_wrap::uuid_str_to_16_bytes`. Its inverse on the decrypt path is the private `hierarchical_keyring::uuid_16_bytes_to_str`. `unwrap` does not compare the on-wire version bytes (`_version`) against the materials; the binding is via the AAD. | T10. |
| C11 | Header note: there are no Duvet annotations | Confirmed. The one `//= type=test` string (`mpl/tests/test_local_cmc.rs:303`) is prose inside an ordinary comment. | Coverage gaps cite tests only. |
| C12 | Advisory CVE-2026-6550 / GHSA-v638-38fc-rhfv | Still **unverified** in this document (see §0). It does not affect any score. | — |

New findings outside the threat model, each recorded in its target and **not changed** because each fix is a behavior or product decision:
- T06: `SystemTime + Duration` overflow panic for large accepted TTL/grace values.
- T15: `EncryptionContext::deserialize` accepts unsorted entries, which contradicts `structures.md#serialization`.
- T17: MRDiscovery rewrites the region of non-MRK ARNs too; the spec says MRK ARNs only.
- T16: a 44–59-byte hierarchical EDK triggers a keystore lookup before it is rejected.
- T07: `prim::aes_encrypt` leaves plaintext in the caller's buffer on `Err`. MPL callers drop it.
- T13: the cache-id preimage is not injective when fields contain NUL.

## 6. Accounting — every threat mapped

| Threat | Severity / Likelihood | Target(s) | Exclusion |
|---|---|---|---|
| TM-MPL-001 | Medium / Low | VR-2026-T24, VR-2026-T20 | Partial (consumer provider-id trust) |
| TM-MPL-002 | Critical / Low | VR-2026-T03, VR-2026-T01 | Partial (KMS policy, Discovery trust) |
| TM-MPL-003 | Medium / Low | VR-2026-T19 | Partial (supplier code) |
| TM-MPL-004 | High / Low | VR-2026-T11 | Partial (KMS MRK semantics) |
| TM-MPL-005 | Critical / Medium | VR-2026-T01, VR-2026-T02 | Partial (rollback/replay, AEAD) |
| TM-MPL-006 | Critical / Low | VR-2026-T09 | Partial (commitment crypto) |
| TM-MPL-007 | High / Low | VR-2026-T17 | Partial (KMS regional) |
| TM-MPL-008 | High / Low | VR-2026-T09 | Partial (Invisible Salamanders crypto) |
| TM-MPL-009 | High / Low | VR-2026-T13 | Partial (SHA-384, logical-name discipline) |
| TM-MPL-010 | High / Low | VR-2026-T14, VR-2026-T13 | Partial (randomness, sharing choice, unverified advisory) |
| TM-MPL-011 | Critical / Low | VR-2026-T07, VR-2026-T20 | Partial (CSPRNG / birthday bound) |
| TM-MPL-012 | Critical / Low | VR-2026-T04 | Partial (collision bound, rotation) |
| TM-MPL-013 | High / Low | VR-2026-T10, VR-2026-T15 | Partial (GCM AAD crypto) |
| TM-MPL-014 | High / Low | VR-2026-T05 | Partial (PRF security, aws-lc KBKDF) |
| TM-MPL-015 | High / Low | VR-2026-T08 | Partial (no Drop zeroization; heap/swap residency) |
| TM-MPL-016 | Medium / Low | VR-2026-T18 | Partial (DDB transaction semantics) |
| TM-MPL-017 | High / Low | VR-2026-T12, VR-2026-T15 | None |
| TM-MPL-018 | Medium / Medium | VR-2026-T21, VR-2026-T06 | Partial (liveness, Tokio runtime) |
| TM-MPL-019 | Medium / Medium | — | **Fully excluded** (process) |
| TM-MPL-020 | Low / Low | — | **Fully excluded** (audit / operational) |
| TM-MPL-021 | Medium / Low | VR-2026-T22 | Partial (app logging, SDK error causes) |
| TM-MPL-022 | Low / Medium | VR-2026-T23, VR-2026-T06 | Partial (KMS throttling, sizing) |
| TM-MPL-023 | Medium / Low | VR-2026-T16, VR-2026-T20, VR-2026-T06 | Partial (keygen `.expect` kept as finding) |

Totals: **24 threat-driven targets** (VR-2026-T01..T24). **2 threats fully excluded** (TM-MPL-019, TM-MPL-020). **20 threats with partial exclusion notes.** **1 threat fully targeted** (TM-MPL-017). All 23 threat IDs TM-MPL-001..TM-MPL-023 are accounted for. 21 have at least one target.
