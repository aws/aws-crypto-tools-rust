# Verus Verification Targets — AWS Cryptographic Material Providers Library (native Rust)

> Pipeline artifact — Stage 3, Step 3 of 4 (merge, rank, assemble).
> Inputs: `docs/verification-targets/01-threat-driven.md` (VR-2026-T01..T24), `docs/verification-targets/02-capability-driven.md` (VR-2026-C01..C06), `docs/threat-model.md` (TM-MPL-001..023, STRIDE categories), `.kiro/agents/verification-recommender.md` (formula, YAML shape, Rules).
> Full per-target YAML for every target (including those not repeated in §2) lives in the two intermediate files. This document is the consolidated, ranked view.

## 0. Methodology notes

- **Formula.** `Priority = Severity × Coverage_Gap × Feasibility × Blast_Radius`. Every score below was recomputed from its stated factors. All 30 products match the intermediate files; no arithmetic errors were found. One wording fix was made in 01: its tie-break rule now reads "then by target ID", which is what its table already did.
- **Two feasibility scales.** Threat-driven targets take Severity and Feasibility from the threat model (Critical=4/High=3/Medium=2/Low=1; Likelihood Low→0.4, Medium→0.7), so a threat has the same severity in every target that cites it. Capability-driven targets have no threat. Their Severity is the consequence of the latent defect the proof rules out, and Feasibility is reachability (1.0 = must hold for all inputs of a public function, 0.7 = caller-chosen config/input, 0.4 = only if constant data or an internal invariant regresses). See 02 §1.
- **Combined tie-break.** Score descending, then higher severity, then origin (T before C), then target ID.
- **No Duvet annotations on this branch.** No `//=` line exists in `mpl/src`, `mpl/tests`, `prim/src` or `prim/tests`. The only textual hit is prose in an ordinary comment at `mpl/tests/test_local_cmc.rs:303`. Every coverage gap is justified only by named tests in `mpl/tests/*.rs` and `prim/tests/*.rs`. Tests lower a gap but never close it.
- **Exactly one `unsafe` block**: `PlaintextDataKey::zeroize` at `mpl/src/structures/algorithm_suite.rs:439` (a `write_volatile(ptr.add(i), 0)` loop). The other textual hit, `prim/src/lib.rs:30`, is the lint name `unsafe_op_in_unsafe_fn`. `zeroize` has zero call sites in `mpl/src`; only two tests call it.
- **No raw C FFI.** `prim` reaches aws-lc-rs only through its safe API (`UnboundKey`, `LessSafeKey`, `Nonce::try_assume_unique_for_key`, `hmac::sign`, `digest::digest`, `kdf::kbkdf_ctr_hmac`, `EcdsaKeyPair`, `rand::fill`). No `extern "C"`, no raw pointers handed to C, no `set_len`. No `UnsafeCell`/`Cell`/`RefCell`/atomics/`RwLock`; only `std::sync::Mutex`. aws-lc-rs internals are trusted (TCB).
- **CVE-2026-6550 / GHSA-v638-38fc-rhfv is unverified.** The threat model flags the identifier as unconfirmed, and Step 1 did not validate the pages it found. No score depends on it. The repo has no caching CMM, so the advisory's caching-layer surface has no direct counterpart here.
- **Overlap handling.** Capability candidates already scoped by a threat-driven target (e.g. `zeroize` → T08, EC codec → T15/T16, TTL arithmetic → T06) were not re-issued (02 §4). T08 keeps its threat-driven severity 3 (TM-MPL-015) so that it is not double-counted, even though the capability view rates an out-of-bounds raw write as severity 4.
- **No source changes.** Findings that need a behavior change (§7) are recorded for the owner, not fixed.

## 1. Combined ranked summary

| Rank | Score | Origin | Target | Property | Agent | Ref | Effort |
|---|---|---|---|---|---|---|---|
| 1 | 8.96 | T | T01 keystore EC builders (`build_authenticated_encryption_context`, `BranchKeyStore::build_auth_ec`, `item_from_ec_and_enc`, `record_from_ddb_item`) | Write-time EC == KMS-AAD EC == reconstruction EC (round trip) | verus-header-parsing-proofs | TM-MPL-005, TM-MPL-002 | 2 weeks |
| 2 | 6.72 | T | T02 `record::branch_key_materials_from_authenticated_encryption_context` | Exact Ok/Err characterization of reconstruction | verus-header-parsing-proofs | TM-MPL-005 | 1 week |
| 3 | 6.72 | C | C01 `keystore/encryption_context.rs` builders ∘ `keystore/record.rs` reconstruction | CreateKey ECs reconstruct to exactly (id, version, custom EC); collision branch dead; record→EC→record inverse | verus-header-parsing-proofs | cap:cat1 (1c) | 1 week |
| 4 | 6.40 | C | C02 `prim::ecdsa` `sign_fixed_len`, `check_sig_len`, `ecdsa_sign*`, `ecdsa_verify*` | ≤ 128 `sign_once` calls; no panic; buffer written only with exact-length candidate | verus-zero-panic | cap:cat2 (2d) | 1 week |
| 5 | 5.60 | C | C03 `prim::{hmac, digest, aes_encrypt, aes_decrypt, hkdf*, kbkdf_ctr_hmac}`, `DigestContext::finish` | No panic on any input; exact Ok/Err length contract | verus-zero-panic | cap:cat2 (2a/2d) | 1 week |
| 6 | 5.60 | C | C04 PDK producers (`RawAesKeyring`/`HierarchicalKeyring` `on_encrypt`/`on_decrypt`, `generate_random_data_key`, materials `new`) | Every PDK length = suite `encryption_key_length` (expected to FAIL on two paths) | verus-header-parsing-proofs | cap:cat1 (1a) | 1 week |
| 7 | 5.12 | T | T03 `kms_ops::resolve_keystore_arn` (pinned modes) | KMS KeyId is always the configured ARN | verus-header-parsing-proofs | TM-MPL-002 | 1 day |
| 8 | 4.48 | T | T04 `branch_key_wrap::wrap` | Fresh-per-call 16B salt + 12B IV, exact 60+n layout, AES-256 preconditions | verus-unsafe-ffi-safety | TM-MPL-012 | 1 week |
| 9 | 4.32 | T | T05 `branch_key_wrap::derive_branch_key` | KBKDF fixed-info = label‖0x00‖salt‖be32(256), 32B out | verus-header-parsing-proofs | TM-MPL-014 | 1 day |
| 10 | 4.20 | T | T06 `SystemTime + Duration` sites (hierarchical keyring, storm tracking) | No overflow panic for any accepted config (expected to FAIL as written) | verus-zero-panic | TM-MPL-018, TM-MPL-022, TM-MPL-023 | 1 week |
| 11 | 3.84 | T | T07 `RawAesKeyring::{new,on_encrypt,on_decrypt}` + `prim::aes_{en,de}crypt` | Fresh 12B IV per call; key/IV/tag/output length preconditions | verus-unsafe-ffi-safety | TM-MPL-011 | 1 week |
| 12 | 3.84 | T | T08 `PlaintextDataKey::zeroize` (the one unsafe block) | In-bounds volatile writes; post-state all zero, len unchanged | verus-unsafe-ffi-safety | TM-MPL-015 | 1 week |
| 13 | 3.20 | T | T09 `CommitmentPolicy::*`, `AlgorithmSuiteId::specification`, `DefaultCmm` | Policy allow-tables match spec; CMM gates encrypt/decrypt | verus-header-parsing-proofs | TM-MPL-006, TM-MPL-008 | 1 week |
| 14 | 2.88 | T | T10 `compute_aad`, `uuid_str_to_16_bytes`, `uuid_16_bytes_to_str` | AAD layout exact; UUID round trip; wrap/unwrap symmetry | verus-header-parsing-proofs | TM-MPL-013 | 1 week |
| 15 | 2.88 | T | T11 `aws_kms_mrk_match_for_decrypt`, `is_arn_compatible` | Match iff identical or MRKs equal except region; aliases rejected | verus-header-parsing-proofs | TM-MPL-004 | 2 weeks |
| 16 | 2.88 | T | T12 `default_cmm::merge_reproduced_encryption_context` | Merged EC = union on agreement; nothing dropped/altered | verus-header-parsing-proofs | TM-MPL-017 | 1 week |
| 17 | 2.52 | T | T13 `cache_entry_identifier::build_cache_identifier` | Exact preimage; scope separation; injective under NUL-free precondition | verus-header-parsing-proofs | TM-MPL-009, TM-MPL-010 | 1 week |
| 18 | 2.52 | T | T14 `as_branch_key_materials`, `generate_partition_id`, `cache_entry_within_limits` | Only BranchKey entries consumed; v4 16B partition id; TTL gate | verus-header-parsing-proofs | TM-MPL-010 | 1 week |
| 19 | 2.40 | T | T15 `EncryptionContext::{serialize,deserialize}` | deserialize∘serialize = id; serialize injective (unsorted-accept counterexample expected) | verus-header-parsing-proofs | TM-MPL-013, TM-MPL-017 | 2 weeks |
| 20 | 2.40 | C | C05 `AlgorithmSuiteId::specification`, `id_bytes`, `verification_key_length` | Suite table refines spec; ids injective, never `00 00`; cross-crate length agreement | verus-header-parsing-proofs | cap:cat1 (1a) | 1 day |
| 21 | 2.24 | T | T16 `unwrap`, `try_decrypt_edk`, raw-AES decrypt, EC `deserialize`, MRK `pa[5]`, `.expect` sites | No panic on any malformed EDK/EC/ARN input | verus-zero-panic | TM-MPL-023 | 1 week |
| 22 | 1.96 | C | C06 `HierarchicalKeyring::new` grace-vs-TTL check | Integer-division check accepts exactly `grace < ttl`; no overflow, non-zero divisor | verus-zero-panic | cap:cat2 (2b/2c) | 1 day |
| 23 | 1.92 | T | T17 `resolve_keystore_arn` (Discovery/MRDiscovery), `reject_alias_arn`, `rewrite_arn_region`, `parse_arn` | Alias rejection; parse∘format round trip; region-only rewrite | verus-header-parsing-proofs | TM-MPL-007 | 1 week |
| 24 | 1.92 | T | T18 `<BranchKeyStore as Keystore>::version_key` (EC derivation) | New ACTIVE/DECRYPT_ONLY ECs preserve id/arn/hv/tablename/custom EC | verus-header-parsing-proofs | TM-MPL-016 | 1 week |
| 25 | 1.92 | T | T19 `HierarchicalKeyring::{resolve_branch_key_id,on_encrypt,on_decrypt,try_decrypt_edk}` | Only matching provider-id + bkid EDKs attempted; bkid bound everywhere | verus-header-parsing-proofs | TM-MPL-003 | 1 week |
| 26 | 1.68 | T | T20 `RawAesKeyring::{serialize_provider_info,decryptable_edk_iv}` | Provider-info codec round trip, exact 12B IV, total | verus-header-parsing-proofs | TM-MPL-023, TM-MPL-011, TM-MPL-001 | 1 week |
| 27 | 1.68 | T | T21 `cmc/storm_tracking.rs` | Config bounds; `\|inflight\| ≤ fan_out`; ≤ 1 new leader per key per grace interval | verus-zero-panic (+ concurrency specialist) | TM-MPL-018 | 1 month |
| 28 | 1.60 | T | T22 Debug impls of secret-bearing types | Debug output independent of secret bytes | verus-unsafe-ffi-safety | TM-MPL-021 | 1 week |
| 29 | 1.26 | T | T23 `cmc/local.rs` `LocalCmc` | `len ≤ entry_capacity`; get never returns expired; prune arithmetic safe | verus-zero-panic | TM-MPL-022 | 2 weeks |
| 30 | 1.20 | T | T24 `RawAesKeyring::new` | No constructed keyring has namespace prefixed `aws-kms` | verus-header-parsing-proofs | TM-MPL-001 | 1 day |

Totals: 30 targets, 24 threat-driven (T01–T24) and 6 capability-driven (C01–C06). Agent routing: verus-header-parsing-proofs ×19, verus-zero-panic ×7, verus-unsafe-ffi-safety ×4.

## 2. Detailed recommendations (YAML)

The ten highest-ranked targets, plus T08 (the repository's only `unsafe` block, which the recommender Rules say to prioritize). That is 7 threat-driven and 4 capability-driven. `rank` is the combined rank from §1. Formal specs are condensed; the full versions are in 01 §3 and 02 §3.

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
      kms_ops::build_authenticated_encryption_context; BranchKeyStore::build_auth_ec (private);
      branch_key_store::item_from_ec_and_enc / record_from_ddb_item (private);
      record::encryption_context_from_item / record::to_attribute_map
  property: >
    The three independently written authenticated-EC builders agree exactly with the spec
    definition (every item attribute except `enc`, plus `tablename` = configured logical
    keystore name). A stored item read back (item_from_ec_and_enc → DDB → record_from_ddb_item
    → build_auth_ec) reproduces exactly the EC KMS authenticated at write time: no attribute
    dropped, added or altered, and Number attributes round-trip as the same decimal string.
  formal_spec: |
    spec fn auth_ec(attrs: Map<Seq<char>,Seq<char>>, n: Seq<char>) -> Map<Seq<char>,Seq<char>>
        { attrs.remove("enc"@).insert("tablename"@, n) }
    fn build_authenticated_encryption_context(a, n) -> (ec) ensures ec@ == auth_ec(a@, n@)
    fn build_auth_ec(&self, r) -> (ec)
        requires !r.attributes@.contains_key("enc"@)
        ensures ec@ == auth_ec(r.attributes@, self.config.logical_keystore_name@)
    // write→read: requires ec@["tablename"@] == n@ && !ec@.contains_key("enc"@)
    ensures record_from_ddb_item(item_from_ec_and_enc(ec, enc)) == Ok(r)
         && r.enc@ == enc@ && auth_ec(r.attributes@, n@) == ec@
  tool: Verus
  agent: verus-header-parsing-proofs
  estimated_effort: 2 weeks
  threat_references:
    - id: TM-MPL-005
      category: Tampering
      description: "Branch-key record substitution; residual = reconstructed EC must exactly match write-time EC"
    - id: TM-MPL-002
      category: Spoofing
      description: "Forged record decrypts under attacker-influenced key; EC binding makes forgery detectable"
  trace_to_spec: >
    spec/framework/branch-key-store.md#encryption-context, #authenticating-a-keystore-item,
    #aws-kms-branch-key-decryption, #record-format, #writing-branch-key-and-beacon-key-to-keystore
  coverage_gap: 0.8
  coverage_evidence: >
    test_keystore_record.rs covers only the record.rs helpers, which production never calls.
    The production builders are private and are exercised only by live-AWS tests in
    test_keystore_branch_key_store_integ.rs.
  rationale: |
    KMS EC-as-AAD is the only integrity control on DynamoDB records. Equality depends on three
    builders agreeing plus an S/N AttributeValue round trip; none of it is proven. Needs pure
    helpers extracted for the AttributeValue mapping and an abstract model of
    aws_sdk_dynamodb::AttributeValue (TCB).
  scoring:
    severity: 4        # TM-MPL-005 Critical
    coverage_gap: 0.8
    feasibility: 0.7   # TM-MPL-005 Likelihood Medium
    blast_radius: 4    # every hierarchical-keyring / keystore consumer
    product: "4 × 0.8 × 0.7 × 4 = 8.96"
  quick_win: false     # score > 6.0 but effort 2 weeks
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
    Returns Ok(materials) exactly when the EC has a valid `type` ("branch:ACTIVE" with a
    `version` strictly extending "branch:version:", or a type strictly extending
    "branch:version:"), a `branch-key-id`, and the plaintext is 32 bytes. Output fields are then
    exactly determined; every other input yields Err(RecordMalformed).
  formal_spec: |
    fn branch_key_materials_from_authenticated_encryption_context(ec, pt) -> (r)
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
      description: "Reconstruction must not accept a mis-typed or mis-versioned record"
  trace_to_spec: >
    spec/framework/branch-key-store.md#branch-key-materials-from-authenticated-encryption-context,
    #custom-encryption-context-from-authenticated-encryption-context
  coverage_gap: 0.6
  coverage_evidence: >
    test_keystore_record.rs: ten materials_reconstruction_* / custom_ec_extraction_* tests give
    broad example coverage of the branches.
  rationale: |
    Final decode of KMS-authenticated data into the materials every hierarchical wrap/unwrap
    uses. Straight-line Map code with no I/O. Paired with T01 it closes
    "authenticated bytes → correct materials".
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
  id: VR-2026-C01
  rank: 3
  priority_score: 6.72
  origin: capability-driven
  target:
    crate: aws-crypto-mpl
    file: mpl/src/keystore/encryption_context.rs; mpl/src/keystore/record.rs
    function: >
      encryption_context::{build_base, decrypt_only_encryption_context, active_encryption_context,
      beacon_key_encryption_context}; record::{branch_key_materials_from_authenticated_encryption_context,
      custom_encryption_context_from_authenticated_encryption_context, encryption_context_from_item, to_attribute_map}
  property: >
    (a) For every accepted CreateKey input, reconstructing an ACTIVE or DECRYPT_ONLY EC with a
    32-byte plaintext returns materials with exactly the input's branch-key-id, version and
    custom EC; a beacon EC returns Err(RecordMalformed). (b) Prefixing and stripping of
    `aws-crypto-ec:` are exact inverses. (c) The "collides after prefixing" Err in build_base is
    unreachable. (d) to_attribute_map(encryption_context_from_item(r, n), r.enc) == r iff r has
    no "tablename"/"enc" attribute.
  formal_spec: |
    proof fn builder_reconstruction_round_trip(input, v, pt)
      requires input.branch_key_id@.len() > 0, v.len() > 0, pt.len() == 32, utf8_ok(custom(input))
      ensures  forall|ec| active_encryption_context(&input, v) == Ok(ec) || decrypt_only_encryption_context(&input, v) == Ok(ec)
                 ==> branch_key_materials_from_authenticated_encryption_context(&ec, pt) matches Ok(m)
                     && m.branch_key_id@ == input.branch_key_id@ && m.branch_key_version@ == v
                     && m.encryption_context@ == custom_or_empty(input)@
    fn build_base(input, t) -> (r)
      ensures r matches Ok(ec) ==> custom_encryption_context_from_authenticated_encryption_context(&ec)@ == custom_or_empty(input)@
      ensures r matches Err(e) ==> !(e.message@.contains("collides"@))
    proof fn record_reverse(r, n)
      ensures (to_attribute_map(&encryption_context_from_item(&r, n), r.enc) == r)
              <==> (!r.attributes@.contains_key("tablename"@) && !r.attributes@.contains_key("enc"@))
  tool: Verus
  agent: verus-header-parsing-proofs
  estimated_effort: 1 week
  threat_references: []
  capability_reference:
    category: 1          # Functional correctness — 1c round trip, 1b Map refinement
    invariant: >
      Keystore EC builders and the reconstruction decoder are exact inverses on
      (branch-key-id, version, custom EC); the collision-error branch is dead; record↔EC
      conversion is the identity off the reserved "tablename"/"enc" keys.
  trace_to_spec: >
    spec/framework/branch-key-store.md#encryption-context, #active-encryption-context,
    #decrypt_only-encryption-context, #beacon-key-encryption-context, #record-format
  coverage_gap: 0.8
  coverage_evidence: >
    test_keystore_encryption_context.rs tests builders alone; test_keystore_record.rs tests
    reconstruction on hand-built maps. No test composes them, reaches the collision branch, or
    covers record→EC→record.
  rationale: |
    Production pair: create_key builds the ECs and the get_* paths reconstruct them. A silent
    mismatch returns materials whose custom EC differs from what was stored, and no
    cryptographic check catches it because stripping happens after KMS authentication.
  scoring:
    severity: 3          # silently wrong key identity / custom EC on returned materials
    coverage_gap: 0.8
    feasibility: 0.7     # reachable via caller-supplied CreateKey custom EC and version
    blast_radius: 4
    product: "3 × 0.8 × 0.7 × 4 = 6.72"
  quick_win: true
  dependencies: [VR-2026-T02]   # soft: reuses T02's decoder spec
```

```yaml
recommendation:
  id: VR-2026-C02
  rank: 4
  priority_score: 6.40
  origin: capability-driven
  target:
    crate: aws-mpl-primitives
    file: prim/src/ecdsa.rs
    function: sign_fixed_len (private); check_sig_len (private); ecdsa_sign; ecdsa_sign_digest; ecdsa_verify; ecdsa_verify_context; signature_len
  property: >
    sign_fixed_len calls sign_once at most MAX_SIGN_ATTEMPTS (128) times and always returns;
    copy_from_slice runs only on an exact-length candidate. On Err the caller's buffer is
    unmodified. ecdsa_sign / ecdsa_sign_digest return Err unless |signature| == signature_len(alg)
    and never panic. ecdsa_verify / ecdsa_verify_context never return Err.
  formal_spec: |
    fn sign_fixed_len(signature: &mut [u8], sign_once) -> (r: Result<(), Error>)
      ensures ghost_calls <= 128
      ensures r.is_Ok() ==> exists|i| 0 <= i < ghost_calls && ghost_cand[i]@.len() == old(signature)@.len()
                              && signature@ == ghost_cand[i]@
      ensures r.is_Err() ==> signature@ == old(signature)@
    fn check_sig_len(alg, s) -> (r) ensures r.is_Ok() <==> s@.len() == signature_len(alg)
    fn ecdsa_sign(alg, key, msg, signature) -> (r) ensures r.is_Ok() ==> signature@.len() == signature_len(alg)
    fn ecdsa_verify(alg, key, msg, sig) -> (r) ensures r.is_Ok()
  tool: Verus
  agent: verus-zero-panic
  estimated_effort: 1 week
  threat_references: []
  capability_reference:
    category: 2          # Zero-panic — 2d total error handling + bounded termination
    invariant: >
      The ECDSA signing retry loop terminates after ≤ 128 attempts on every input, never
      panics, and writes the caller's buffer only with an exact-length DER signature.
  trace_to_spec: "spec/framework/algorithm-suites.md#asymmetric-signature-algorithm; baseline assurance, no single MPL clause"
  coverage_gap: 0.8
  coverage_evidence: >
    prim/tests/test_ecdsa.rs covers buffer-length rejection, 71/103-byte lengths, bad keys and
    round trips. sign_fixed_len's oracle cannot be injected, so no test reaches retry
    exhaustion, the termination bound, or "buffer untouched on Err".
  rationale: |
    A loop whose exit depends on randomized output is a classic latent hang. The ESDK signs
    every signing-suite message through ecdsa_sign_digest, and 0x0578 (ECDSA P-384) is the
    default suite of both REQUIRE_* policies. Excluded: the 2^-128 exhaustion probability.
  scoring:
    severity: 2          # hang or panic → DoS
    coverage_gap: 0.8
    feasibility: 1.0     # must hold for all inputs and oracles
    blast_radius: 4      # every ESDK signing-suite encrypt
    product: "2 × 0.8 × 1.0 × 4 = 6.40"
  quick_win: true
  dependencies: []
```

```yaml
recommendation:
  id: VR-2026-C03
  rank: 5
  priority_score: 5.60
  origin: capability-driven
  target:
    crate: aws-mpl-primitives
    file: prim/src/lib.rs; prim/src/ecdsa.rs; prim/src/hkdf.rs
    function: hmac; digest; aes_encrypt; aes_decrypt; kbkdf_ctr_hmac; DigestContext::finish; hkdf; hkdf_no_salt; hkdf_expand
  property: >
    No listed function panics for any argument values. hmac/digest/finish return Err unless
    |out| equals the algorithm output length, and only then copy. aes_encrypt's
    `&mut cipher_text[old_size..]` is in range and Ok ⇒ |ct| = old + |msg| + 16. aes_decrypt
    Ok ⇒ |pt| == |ct|. hkdf_no_salt's `&salt[..sz]` is in range (sz ≤ 64). hkdf/hkdf_expand
    Ok ⇒ |okm| ∈ {16, 24, 32}.
  formal_spec: |
    proof fn output_len_agrees(a: DigestAlg) ensures a.output_len() == get_digest_alg(a).output_len()
    fn hmac(alg, key, msg, out) -> (r) ensures r.is_Ok() <==> out@.len() == alg.output_len()
    fn digest(alg, data, out) -> (r) ensures r.is_Ok() <==> out@.len() == alg.output_len()
    fn aes_encrypt(alg, iv, key, msg, aad, ct) -> (r)
      ensures r.is_Ok() ==> ct@.len() == old(ct)@.len() + msg@.len() + 16
    fn aes_decrypt(alg, key, ct, tag, iv, aad, pt) -> (r)
      ensures r.is_Ok() ==> pt@.len() == ct@.len()
    fn hkdf(alg, salt, ikm, info, okm) -> (r) ensures r.is_Ok() ==> okm@.len() == 16 || okm@.len() == 24 || okm@.len() == 32
    // TCB: aws-lc-rs safe-API output lengths; open_separate_gather rejects |pt| != |ct|
  tool: Verus
  agent: verus-zero-panic
  estimated_effort: 1 week
  threat_references: []
  capability_reference:
    category: 2          # Zero-panic — 2a slice bounds, 2d length-checked copy_from_slice
    invariant: >
      No reachable panic path in the prim crypto wrappers; each wrapper's Ok implies an exact
      output length (decrypt: |pt| == |ct|).
  trace_to_spec: "supports spec/framework/algorithm-suites.md lengths; baseline assurance, no single clause"
  coverage_gap: 0.7
  coverage_evidence: >
    prim/tests/test_hmac.rs, test_digest.rs, test_aes.rs, test_hkdf.rs, test_kbkdf_ctr_hmac.rs
    have direct negative-length tests. Gaps: no wrong-length buffer to DigestContext::finish
    (test_ecdsa.rs), no aes_decrypt buffer longer than the ciphertext.
  rationale: |
    One proof covers every MPL and ESDK caller. Expected finding: prim's guard rejects only
    |pt| < |ct|; any mismatch is rejected inside aws-lc-rs. Safe, but the safety comes from the
    callee, not prim. Foundational for T04, T05, T07, T13.
  scoring:
    severity: 2          # panic → DoS
    coverage_gap: 0.7
    feasibility: 1.0     # all inputs of public functions
    blast_radius: 4      # every MPL keyring + ESDK body/header/KDF/signature paths
    product: "2 × 0.7 × 1.0 × 4 = 5.60"
  quick_win: false       # score < 6.0
  dependencies: []
```

```yaml
recommendation:
  id: VR-2026-C04
  rank: 6
  priority_score: 5.60
  origin: capability-driven
  target:
    crate: aws-crypto-mpl
    file: mpl/src/keyring/raw_aes_keyring.rs; mpl/src/aws_kms/hierarchical_keyring.rs; mpl/src/structures/encryption_materials.rs; mpl/src/structures/decryption_materials.rs
    function: >
      <RawAesKeyring as Keyring>::{on_encrypt, on_decrypt}; <HierarchicalKeyring as Keyring>::{on_encrypt, on_decrypt};
      HierarchicalKeyring::try_decrypt_edk; generate_random_data_key (×2); EncryptionMaterials::new; DecryptionMaterials::new
  property: >
    pdk_ok(m): a present plaintext data key has length == suite encryption_key_length.
    EXPECTED TO FAIL on two paths: (F1) HierarchicalKeyring::on_decrypt accepts any unwrapped
    length; (F2) the material constructors never check, and both on_encrypt paths pass an
    incoming PDK through unchanged. RawAesKeyring::on_decrypt verifies unconditionally; both
    on_encrypt paths verify with `requires pdk_ok(input)`.
  formal_spec: |
    spec fn pdk_ok_e(m) -> bool { m.plaintext_data_key matches Some(k) ==> k@.len() == m.algorithm_suite_id.specification().encryption_key_length() }
    fn generate_random_data_key(s) -> (r) ensures r matches Ok(k) ==> k@.len() == s.encryption_key_length()
    fn <RawAesKeyring>::on_decrypt(&self, m, edks) -> (r) ensures r matches Ok(m2) ==> pdk_ok_d(m2)          // VERIFIES
    fn <HierarchicalKeyring>::on_decrypt(&self, m, edks) -> (r) ensures r matches Ok(m2) ==> pdk_ok_d(m2)    // FAILS (F1)
    fn EncryptionMaterials::new(.., pdk, ..) -> (r) ensures r matches Ok(m) ==> pdk_ok_e(m)                  // FAILS (F2)
  tool: Verus
  agent: verus-header-parsing-proofs
  estimated_effort: 1 week
  threat_references: []
  capability_reference:
    category: 1          # Functional correctness — 1a struct invariant / pre-post adherence
    invariant: >
      Every plaintext data key an in-repo keyring or materials constructor emits has exactly
      the algorithm suite's encryption-key length.
  trace_to_spec: >
    spec/framework/keyring-interface.md#generate-data-key; spec/framework/structures.md#plaintext-data-key;
    spec/framework/algorithm-suites.md#encryption-key-length
  coverage_gap: 1.0
  coverage_evidence: >
    No wrong-length PDK test at any producer: test_raw_aes_keyring.rs never reaches the
    "decrypted data key is N bytes" branch; test_aws_kms_hierarchical_keyring.rs has no
    decrypted-length test; test_encryption_materials.rs / test_decryption_materials.rs test
    other invariants; test_default_cmm.rs mocks always size PDKs correctly.
  rationale: |
    The ESDK re-checks PDK length before key derivation (esdk/src/key_derivation.rs:87, 190),
    so for the ESDK a violation fails closed; hence severity 2. Adding checks would reject
    inputs accepted today, which is an owner decision.
  scoring:
    severity: 2          # spec-MUST violation at MPL boundary; ESDK rejects later
    coverage_gap: 1.0
    feasibility: 0.7     # caller-supplied PDK / authorized encryptor's wrapped length
    blast_radius: 4
    product: "2 × 1.0 × 0.7 × 4 = 5.60"
  quick_win: false
  dependencies: []
```

```yaml
recommendation:
  id: VR-2026-T03
  rank: 7
  priority_score: 5.12
  origin: threat-driven
  target:
    crate: aws-crypto-mpl
    file: mpl/src/keystore/kms_ops.rs
    function: resolve_keystore_arn (KmsKeyArn / KmsMrKeyArn arms); caller decrypt_branch_key
  property: >
    In single-key modes the KeyId sent to KMS is always the configured ARN, never the
    record's `kms-arn`. Success iff the record ARN is compatible (byte-equal / MRK-match);
    otherwise Err(Authentication).
  formal_spec: |
    fn resolve_keystore_arn(c, rec) -> (r)
      requires c is KmsKeyArn || c is KmsMrKeyArn
      ensures r matches Ok(k) ==> k@ == configured(c)@
      ensures r.is_Ok() <==> compat_spec(c, rec@)
      ensures r matches Err(e) ==> e.kind == KeystoreErrorKind::Authentication
  tool: Verus
  agent: verus-header-parsing-proofs
  estimated_effort: 1 day
  threat_references:
    - id: TM-MPL-002
      category: Spoofing
      description: "Forged record decrypts under attacker-influenced KMS key — pinned-mode slice"
  trace_to_spec: "spec/framework/branch-key-store.md#aws-kms-branch-key-decryption, #aws-key-arn-compatibility"
  coverage_gap: 0.8
  coverage_evidence: >
    No direct unit test (pub(crate)). Compat predicate tested in test_keystore_kms_config.rs;
    end-to-end only live-AWS in test_aws_kms_hierarchical_keyring_integ.rs and
    test_keystore_branch_key_store_integ.rs.
  rationale: "Code-level control for Critical TM-MPL-002; cheap because the property is 'returns the configured string'."
  scoring:
    severity: 4        # TM-MPL-002 Critical
    coverage_gap: 0.8
    feasibility: 0.4   # Low
    blast_radius: 4
    product: "4 × 0.8 × 0.4 × 4 = 5.12"
  quick_win: false     # score < 6.0
  dependencies: [VR-2026-T11]   # soft
```

```yaml
recommendation:
  id: VR-2026-T04
  rank: 8
  priority_score: 4.48
  origin: threat-driven
  target:
    crate: aws-crypto-mpl
    file: mpl/src/aws_kms/branch_key_wrap.rs
    function: wrap
  property: >
    Fresh local 16-byte salt and 12-byte IV per call, each filled by one successful RNG call
    before use, no cross-call state. Output is exactly salt‖iv‖uuid_bytes(version)‖ct‖tag with
    |output| = 60 + |pt|. aws-lc-rs preconditions hold (key 32 bytes, IV 12). On Err the
    partially built output is dropped.
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
    - id: TM-MPL-012
      category: Elevation of Privilege
      description: "AES-GCM salt/IV reuse in branch-key wrap — lengths and fresh-per-call structure"
  trace_to_spec: "spec/framework/aws-kms/aws-kms-hierarchical-keyring.md#branch-key-wrapping, #ciphertext"
  coverage_gap: 0.7
  coverage_evidence: >
    test_aws_kms_hierarchical_keyring.rs: wrap layout lengths, two calls distinct, tampered IV,
    round trips.
  rationale: |
    prim uses Nonce::try_assume_unique_for_key, which puts nonce discipline on the caller.
    The structural half is fully provable; the 224-bit collision bound is excluded.
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
  rank: 9
  priority_score: 4.32
  origin: threat-driven
  target:
    crate: aws-crypto-mpl
    file: mpl/src/aws_kms/branch_key_wrap.rs
    function: derive_branch_key (private)
  property: >
    Fixed-info is exactly "aws-kms-hierarchy"(17) ‖ 0x00 ‖ salt(16) ‖ 0x00000100 (38 bytes),
    PRF HMAC-SHA-256, IKM the 32-byte branch key, OKM 32 bytes. wrap and unwrap reach the KDF
    only through this function.
  formal_spec: |
    fn derive_branch_key(bk: &[u8;32], salt: &[u8;16]) -> (r)
      ensures ghost_info@ == b"aws-kms-hierarchy"@ + seq![0x00u8] + salt@ + seq![0x00u8, 0x00, 0x01, 0x00]
           && ghost_info@.len() == 38 && ghost_alg == DigestAlg::Sha256 && ghost_okm_len == 32
      ensures r matches Ok(k) ==> k@ == kbkdf_ctr_hmac_spec(Sha256, bk@, ghost_info@, 32)   // uninterpreted, TCB
  tool: Verus
  agent: verus-header-parsing-proofs
  estimated_effort: 1 day
  threat_references:
    - id: TM-MPL-014
      category: Elevation of Privilege
      description: "KBKDF fixed-info / L-value misuse weakens branch-key derivation"
  trace_to_spec: "spec/framework/aws-kms/aws-kms-hierarchical-keyring.md#branch-key-wrapping; NIST SP 800-108 §4.1"
  coverage_gap: 0.9
  coverage_evidence: >
    Round trips in test_aws_kms_hierarchical_keyring.rs use the same function on both sides, so
    layout drift goes undetected. prim/tests/test_kbkdf_ctr_hmac.rs tests only the primitive.
  rationale: "Interop-breaking, possibly weakening, invisible to self-consistent tests; straight-line Seq concatenation."
  scoring:
    severity: 3        # TM-MPL-014 High
    coverage_gap: 0.9
    feasibility: 0.4   # Low
    blast_radius: 4
    product: "3 × 0.9 × 0.4 × 4 = 4.32"
  quick_win: false     # score < 6.0
  dependencies: []
```

```yaml
recommendation:
  id: VR-2026-T06
  rank: 10
  priority_score: 4.20
  origin: threat-driven
  target:
    crate: aws-crypto-mpl
    file: mpl/src/aws_kms/hierarchical_keyring.rs; mpl/src/cmc/storm_tracking.rs
    function: >
      HierarchicalKeyring::on_encrypt / try_decrypt_edk (`now + Duration::from_secs(ttl)`);
      storm_tracking::within_grace_interval; StormTrackingCmc::classify_and_mark;
      bounds would live in HierarchicalKeyring::new / ValidatedConfig::from_raw
  property: >
    No `SystemTime + Duration` addition panics for any accepted configuration. EXPECTED TO FAIL
    as written: new only checks ttl_seconds > 0 and from_raw only enforces lower bounds and
    ordering, so e.g. ttl_seconds = u64::MAX is accepted and std's Add panics on overflow
    (from reading std; not executed).
  formal_spec: |
    // SystemTime::add(t, d) requires st_add_ok(t, d)   (TCB external spec)
    fn new(.., ttl_seconds: u64, ..) -> (r) ensures r matches Ok(k) ==> k.ttl_seconds <= MAX_TTL
    fn from_raw(..) -> (r) ensures r matches Ok(c) ==> c.grace_interval <= MAX_D && c.inflight_ttl <= MAX_D
    // add sites verify only once those bounds exist
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
      description: "Panic instead of error (config-driven)"
  trace_to_spec: >
    spec/framework/aws-kms/aws-kms-hierarchical-keyring.md#cache-limit-ttl;
    spec/framework/storm-tracking-cryptographic-materials-cache.md#grace-interval, #inflight-ttl
  coverage_gap: 1.0
  coverage_evidence: >
    test_aws_kms_hierarchical_keyring.rs and test_storm_tracking_cmc.rs use small values only;
    no u64::MAX in mpl/tests.
  rationale: "Real latent panic not in the threat model. Choosing a bound is an owner decision; Verus closes it afterwards."
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
  id: VR-2026-T08
  rank: 12
  priority_score: 3.84
  origin: threat-driven
  target:
    crate: aws-crypto-mpl
    file: mpl/src/structures/algorithm_suite.rs
    function: PlaintextDataKey::zeroize (the repository's only unsafe block, line 439)
  property: >
    Every ptr.add(i), 0 ≤ i < len, stays inside the Vec's initialized allocation with no
    reallocation during the loop; each write_volatile writes one u8; on return len is
    unchanged, as_ptr() is unchanged, and every byte is 0.
  formal_spec: |
    pub fn zeroize(&mut self)
      ensures self.0@.len() == old(self).0@.len()
           && forall|j: int| 0 <= j < self.0@.len() ==> self.0@[j] == 0u8
    // loop inv: 0 <= i <= len; ptr == self.0.as_mut_ptr(); forall j < i: self.0@[j] == 0;
    //           forall i <= j < len: self.0@[j] == old(self).0@[j]; points_to for byte i (vstd raw_ptr)
  tool: Verus
  agent: verus-unsafe-ffi-safety
  estimated_effort: 1 week
  threat_references:
    - id: TM-MPL-015
      category: Information Disclosure
      description: "Secret material not zeroized — the zeroize loop is complete and in-bounds"
  capability_overlap: "cat3a (+2a) per 02 §4; capability severity would be 4, kept at 3 to avoid double counting"
  trace_to_spec: "spec/framework/structures.md (Plaintext Data Key); no clause mandates zeroization — baseline assurance"
  coverage_gap: 0.8
  coverage_evidence: >
    test_encryption_materials.rs::test_plaintext_data_key_zeroize and
    test_decryption_materials.rs::test_plaintext_data_key_zeroize_decryption check one small key.
  rationale: |
    Only unsafe block in the repo. zeroize has no call sites in mpl/src, so the proof shows the
    primitive is sound; it does not mitigate TM-MPL-015 at runtime. Trusted: Vec::as_mut_ptr /
    write_volatile external specs; volatile non-elision is a language guarantee.
  scoring:
    severity: 3        # TM-MPL-015 High
    coverage_gap: 0.8
    feasibility: 0.4   # Low
    blast_radius: 4
    product: "3 × 0.8 × 0.4 × 4 = 3.84"
  quick_win: false
  dependencies: []
```

## 3. Coverage-gap analysis

No Verus proof exists for any target, and there are no Duvet annotations, so "existing tests" below are the only evidence. Files are under `mpl/tests/` unless prefixed `prim/tests/`. "integ" marks live-AWS tests that do not run in unit CI.

| Target | Existing tests (file) | Gap | Justification |
|---|---|---|---|
| T01 keystore EC builders | test_keystore_record.rs; test_keystore_branch_key_store_integ.rs (integ) | 0.8 | Unit tests cover only the non-production record.rs helpers; private production builders are reached only by integ tests |
| T02 materials reconstruction | test_keystore_record.rs | 0.6 | Broad example tests of every branch, including negatives |
| C01 builder ∘ reconstruction | test_keystore_encryption_context.rs; test_keystore_record.rs | 0.8 | Each half tested alone; no composition, collision branch or record→EC→record test |
| C02 ECDSA retry loop | prim/tests/test_ecdsa.rs | 0.8 | Private oracle not injectable; retry exhaustion and no-partial-write untested |
| C03 prim wrappers panic-freedom | prim/tests/test_hmac.rs, test_digest.rs, test_aes.rs, test_hkdf.rs, test_kbkdf_ctr_hmac.rs, test_ecdsa.rs | 0.7 | Direct negative-length tests; no wrong-length `finish` buffer, no over-long decrypt buffer |
| C04 PDK length invariant | test_raw_aes_keyring.rs; test_aws_kms_hierarchical_keyring.rs; test_encryption_materials.rs; test_decryption_materials.rs; test_default_cmm.rs | 1.0 | None exercises a wrong-length PDK at any producer |
| T03 pinned KMS KeyId | test_keystore_kms_config.rs; test_aws_kms_hierarchical_keyring_integ.rs, test_keystore_branch_key_store_integ.rs (integ) | 0.8 | Function has no unit test; predicate tested, end-to-end only integ |
| T04 wrap layout / fresh IV | test_aws_kms_hierarchical_keyring.rs | 0.7 | Layout, distinctness and tamper tests exist |
| T05 KBKDF fixed-info | test_aws_kms_hierarchical_keyring.rs; prim/tests/test_kbkdf_ctr_hmac.rs | 0.9 | Self-consistent round trips cannot detect layout drift; prim vectors test only the primitive |
| T06 SystemTime overflow | test_aws_kms_hierarchical_keyring.rs; test_storm_tracking_cmc.rs | 1.0 | Small TTL/grace values only; no large-value test |
| T07 raw-AES IV + preconditions | test_raw_aes_keyring.rs; prim/tests/test_aes.rs | 0.8 | Length/tamper tests; no two-call IV-distinctness test |
| T08 zeroize | test_encryption_materials.rs; test_decryption_materials.rs | 0.8 | Post-state on one small key; pointer soundness for all lengths untestable |
| T09 commitment policy / CMM gate | test_commitment_policy.rs; test_default_cmm.rs; test_algorithm_suite_id.rs | 0.5 | Finite domain, near-exhaustively tested |
| T10 AAD + UUID round trip | test_aws_kms_hierarchical_keyring.rs | 0.6 | Known-input layout and mismatch tests |
| T11 MRK match | test_aws_kms_mrk_match.rs; test_keystore_kms_config.rs | 0.6 | 17 example tests plus compat tests |
| T12 reproduced-EC merge | test_default_cmm.rs | 0.6 | Eight example tests over match/mismatch/disjoint/empty |
| T13 cache identifier | test_aws_kms_hierarchical_keyring.rs | 0.7 | Manual-SHA384 and distinctness tests; no NUL-separator case |
| T14 cache kind / TTL / partition id | test_aws_kms_hierarchical_keyring.rs; test_aws_kms_hierarchical_keyring_integ.rs (integ) | 0.7 | Partition-id and caching tests; no wrong-kind entry injected |
| T15 EC serialize/deserialize | test_encryption_context.rs | 0.5 | 37 tests including round trip, layout and bounds |
| C05 suite table | test_algorithm_suite_id.rs | 0.5 | 20 tests enumerate the finite domain; cross-crate agreement untested |
| T16 malformed-input panic-freedom | test_aws_kms_hierarchical_keyring.rs; test_raw_aes_keyring.rs; test_encryption_context.rs; test_aws_kms_mrk_match.rs | 0.7 | Direct truncation/malformed tests; cannot cover all inputs |
| C06 grace-vs-TTL check | test_aws_kms_hierarchical_keyring.rs | 0.7 | Seconds boundary tested; no Milliseconds boundary test |
| T17 Discovery / MRDiscovery ARN | test_keystore_kms_config.rs; test_aws_kms_hierarchical_keyring_integ.rs (integ) | 0.8 | parse_arn unit-tested; reject_alias_arn / rewrite_arn_region private and untested |
| T18 version_key EC derivation | test_keystore_branch_key_store.rs; test_keystore_encryption_context.rs; test_keystore_branch_key_store_integ.rs (integ) | 0.8 | Inline derivation only reached by integ; builder tests cover a different module |
| T19 bkid binding | test_aws_kms_hierarchical_keyring.rs | 0.6 | Skip-filter and supplier tests |
| T20 provider-info codec | test_raw_aes_keyring.rs | 0.7 | Wire-format and wrong-length negative tests |
| T21 storm tracking | test_storm_tracking_cmc.rs | 0.6 | ~40 tests including config bounds and concurrency coalescing |
| T22 Debug redaction | test_algorithm_suite.rs; test_branch_key_materials.rs; test_beacon_key_materials.rs; test_raw_aes_keyring.rs; test_encryption_materials.rs; prim/tests/test_ecdsa.rs | 0.5 | Substring redaction test for every secret-bearing type |
| T23 LocalCmc | test_local_cmc.rs | 0.6 | Capacity, TTL, pruning and concurrency tests |
| T24 reserved namespace | test_raw_aes_keyring.rs | 0.5 | Reserved-prefix rejection tests for every KMS provider id |

## 4. Risk summary by STRIDE category

Threat counts and categories come from `docs/threat-model.md` §7. "Verified" is 0 everywhere: no Verus proof exists yet. "With target" means at least one provable slice is scoped.

| Category | Threats | Verified | With target | Fully excluded | Targets | Top-priority target |
|---|---|---|---|---|---|---|
| Spoofing | 3 (001, 002, 003) | 0 | 3 | 0 | T01, T03, T19, T20, T24 | T01 (8.96, via TM-MPL-002); top primary-002 target T03 (5.12) |
| Tampering | 5 (004, 005, 013, 016, 017) | 0 | 5 | 0 | T01, T02, T10, T11, T12, T15, T18 | T01 (8.96) — keystore EC round trip |
| Repudiation | 1 (020) | 0 | 0 | 1 | — | — (operational audit control) |
| Information Disclosure | 3 (010, 015, 021) | 0 | 3 | 0 | T08, T13, T14, T22 | T08 (3.84) — zeroize unsafe block |
| Denial of Service | 3 (018, 022, 023) | 0 | 3 | 0 | T06, T16, T20, T21, T23 | T06 (4.20) — SystemTime overflow panic |
| Elevation of Privilege | 8 (006, 007, 008, 009, 011, 012, 014, 019) | 0 | 7 | 1 (019) | T04, T05, T07, T09, T13, T17, T20 | T04 (4.48) — wrap salt/IV structure |
| **Total** | **23** | **0** | **21** | **2** | 24 threat-driven targets | |

Capability-driven targets carry no threat, so they are not counted above. By the consequence they rule out, their closest STRIDE categories are: Tampering/integrity — C01 (6.72), C04 (5.60), C05 (2.40); Denial of Service — C02 (6.40), C03 (5.60), C06 (1.96). This mapping is advisory only.

## 5. Quick wins (score > 6.0 AND effort ≤ 1 week)

| Rank | Target | Score | Effort | Origin |
|---|---|---|---|---|
| 2 | VR-2026-T02 `branch_key_materials_from_authenticated_encryption_context` exact Ok/Err | 6.72 | 1 week | T |
| 3 | VR-2026-C01 keystore EC builder ∘ reconstruction round trip | 6.72 | 1 week | C |
| 4 | VR-2026-C02 `prim::ecdsa` bounded retry, no panic, no partial write | 6.40 | 1 week | C |

Only these three qualify. T01 (8.96) is excluded because it needs 2 weeks. Cheap targets below the threshold, such as T03 (5.12, 1 day) and T05 (4.32, 1 day), are not quick wins under this rule.

## 6. Out of scope / not Verus-provable

Carried over from Step 1 (01 §4). **Fully excluded** threats have no provable code slice. **Partial** threats have a targeted slice; only the listed remainder is excluded.

| Threat | Scope | Excluded part | Reason |
|---|---|---|---|
| TM-MPL-019 | Fully excluded | Missing Duvet coverage lets a spec MUST regress | Process / traceability tooling; no code property to prove |
| TM-MPL-020 | Fully excluded | No audit binding between MPL operations and KMS/DDB calls | Repudiation / operational control (CloudTrail, user-agent); no behavior in `mpl/src` |
| TM-MPL-001 | Partial (→ T24, T20) | Whether downstream consumers trust provider-ids case-insensitively | Other components' behavior |
| TM-MPL-002 | Partial (→ T03, T01) | KMS key policy / grants; KMS enforcing EC-as-AAD; Discovery trusting the record's `kms-arn` | External-service policy; configuration choice |
| TM-MPL-003 | Partial (→ T19) | Correctness of the caller-supplied `BranchKeySupplier` | Caller code outside the crate |
| TM-MPL-004 | Partial (→ T11) | KMS guarantee that MRK replicas share key material | External service semantics |
| TM-MPL-005 | Partial (→ T01, T02) | Rollback / replay of an older authentic record; AEAD integrity of KMS ciphertext | Storage freshness not enforced in MPL; crypto hardness |
| TM-MPL-006 | Partial (→ T09) | Cryptographic security of key commitment; ESDK message-level verification | Crypto hardness; message format out of MPL scope |
| TM-MPL-007 | Partial (→ T17) | KMS regional replica availability; KMS rejecting non-KMS / wrong-region ARNs | External service |
| TM-MPL-008 | Partial (→ T09) | Invisible-Salamanders resistance of the commit-key suites | Crypto hardness |
| TM-MPL-009 | Partial (→ T13) | SHA-384 collision resistance; operators never reusing a logical name across stores | Crypto hardness; unenforceable config MUST |
| TM-MPL-010 | Partial (→ T13, T14) | Partition-id randomness; operator choice to share; CVE-2026-6550 / GHSA-v638-38fc-rhfv (unverified) | Probabilistic + operational; no caching CMM here |
| TM-MPL-011 | Partial (→ T07, T20) | CSPRNG quality; 96-bit nonce birthday bound | Probabilistic secrecy |
| TM-MPL-012 | Partial (→ T04) | 224-bit salt‖IV collision bound; rotation cadence | Probabilistic + operational |
| TM-MPL-013 | Partial (→ T10, T15) | GCM's cryptographic binding of AAD | Crypto hardness |
| TM-MPL-014 | Partial (→ T05) | HMAC-SHA-256 PRF security; aws-lc-rs KBKDF correctness | Crypto hardness / third-party |
| TM-MPL-015 | Partial (→ T08) | Heap/swap/core-dump residency; `Clone` and reallocation copies; aws-lc buffers; absence of any Drop-driven zeroization | No code to verify; fix is a design change; allocator/OS outside Verus's model |
| TM-MPL-016 | Partial (→ T18) | DynamoDB `TransactWriteItems` atomicity and `ConditionExpression` evaluation | External-service semantics |
| TM-MPL-017 | Fully targeted (→ T12, T15) | — | Nothing excluded |
| TM-MPL-018 | Partial (→ T21, T06) | Liveness under a real scheduler; Tokio-only runtime; wall-clock behavior | Deployment constraints, not functional properties |
| TM-MPL-021 | Partial (→ T22) | What applications log; AWS SDK error-cause contents | External code |
| TM-MPL-022 | Partial (→ T23, T06) | KMS throttling under eviction thrash; capacity sizing | Performance / operations |
| TM-MPL-023 | Partial (→ T16, T20, T06) | `ecdsa_generate_keypair(..).expect` success | Needs an unjustified "always Ok" axiom; kept in T16 as an expected-unprovable finding |

Capability candidates rejected in Step 2 (02 §5), summarized: cache usage-counter arithmetic (none exists); constant-time behavior (timing not modeled); RNG output quality and uniqueness; ECDSA exhaustion probability; primitive cryptographic security; error-chain termination over third-party `dyn Error`; raw C-FFI soundness (no raw FFI here); interior-mutability / custom-lock proofs (none exist); trivial constant matches; total `Duration` constructors; Drop-driven zeroization (no code); Tokio executor requirement; allocator failure.

## 7. Findings recorded, not changed

Each needs an owner decision because the fix changes observable behavior.

- T06: `SystemTime + Duration` overflow panic for large accepted TTL / grace values.
- C04-F1: `HierarchicalKeyring::on_decrypt` accepts an unwrapped PDK of any length. C04-F2: material constructors do not enforce the PDK-length MUST.
- T15: `EncryptionContext::deserialize` accepts unsorted entries, contrary to `structures.md#serialization`.
- T17: MRDiscovery rewrites the region of non-MRK ARNs too.
- T16: `default_cmm.rs:115` `ecdsa_generate_keypair(..).expect` aborts on keygen failure; a 44–59-byte hierarchical EDK triggers a keystore lookup before rejection.
- T13: cache-id preimage is not injective when fields contain NUL (spec-mandated layout).
- T07 / C03: `prim::aes_encrypt` leaves plaintext in the caller's buffer on `Err`; `prim::aes_decrypt`'s guard is weaker than its callee's check.
- C01(c): the custom-EC collision `Err` in `build_base` is dead code.
- T14: `cache_entry_within_limits` admits up to `ttl + 1 s` (truncation), observable only with a `Shared` cache that ignores expiry.
