# Capability-Driven Verus Verification Targets — AWS MPL (native Rust)

> Pipeline artifact — Stage 3, Step 2 of 4 (capability-driven entry path, the Stage 2' sweep).
> Inputs: `mpl/src`, `prim/src`, `mpl/tests`, `prim/tests`, `spec/framework/*.md`, and Step 1 output `docs/verification-targets/01-threat-driven.md` (VR-2026-T01..T24).
> Methodology: `.kiro/agents/ai-verification-pipeline.md` (Stage 2'), `.kiro/agents/verus-capabilities.md` (categories 1–4 and the Provable vs. Not-Here decision aid), `.kiro/agents/verification-recommender.md` (formula, YAML shape, Rules), and the three proof-agent scopes (`verus-header-parsing-proofs`, `verus-zero-panic`, `verus-unsafe-ffi-safety`).
> Every target below has `origin: capability-driven` and a `capability_reference` in place of a threat. A candidate that Step 1 already covers is **not** repeated as a target. It appears in §4 "Overlaps with Step 1" with what the capability view adds.

## 0. Repo facts re-confirmed for this step

- **Exactly one `unsafe` block.** A search for `unsafe` across `mpl/src` and `prim/src` returns `mpl/src/structures/algorithm_suite.rs:439` (inside `PlaintextDataKey::zeroize`, a `core::ptr::write_volatile(ptr.add(i), 0u8)` loop) and `prim/src/lib.rs:30`. The second hit is the lint name `unsafe_op_in_unsafe_fn`, not code.
- **No raw C FFI.** `prim` reaches `aws-lc-rs` only through its safe API. There is no `extern "C"`, no raw pointer handed to C, and no `set_len`. A search for `UnsafeCell|RefCell|Cell<|Atomic*|RwLock` in `mpl/src` and `prim/src` finds nothing. The only synchronization is `std::sync::Mutex` (`cmc/local.rs`, `cmc/storm_tracking.rs`).
- **No Duvet annotations.** No line in `mpl/src`, `mpl/tests`, `prim/src` or `prim/tests` starts with `//=`. Every coverage-gap figure below is justified only by named tests.
- **`prim` is shared with the ESDK.** Besides `mpl/src` (`raw_aes_keyring.rs`, `branch_key_wrap.rs`, `cache_entry_identifier.rs`, `hierarchical_keyring.rs`, `default_cmm.rs`), `esdk/src` calls `aes_encrypt`/`aes_decrypt`, `digest`, `hkdf`/`hkdf_extract`/`hkdf_expand`, `DigestContext`, `ecdsa_sign_digest` and `ecdsa_verify_context` (confirmed by grep in `esdk/src`). One `prim` proof therefore protects both crates.
- **Advisory CVE-2026-6550 / GHSA-v638-38fc-rhfv stays UNVERIFIED.** No target or score in this document depends on it.
- **Out of scope throughout:** cryptographic hardness (AES-GCM, ECDSA, HMAC, HKDF, KBKDF, SHA-2), KMS/DynamoDB policy and semantics, and probabilistic secrecy (entropy, nonce-collision bounds, the ECDSA retry success probability).

## 1. Scoring conventions for capability-driven targets

`Priority = Severity × Coverage_Gap × Feasibility × Blast_Radius`. Products are exact and shown as `S × G × F × B = score`.

| Factor | Rule used in this document |
|---|---|
| Severity (1–4) | The consequence of the latent defect the proof rules out, not a threat rating. 4 = memory corruption / secret disclosure. 3 = silently wrong key material, key identity or suite parameters (integrity or weakened crypto). 2 = process panic, hang, or fail-closed availability loss / spec-MUST violation that downstream rejects. 1 = cosmetic or diagnostic. |
| Coverage_Gap (0–1) | Same scale as Step 1. 1.0 = no test exercises the property. 0.9 = only tests that cannot detect a defect. 0.8 = some unit tests, or the property's key path is untestable without injection. 0.7 = direct unit tests including negative cases. 0.6 = broad example-based tests. 0.5 = near-exhaustive tests over a small finite domain. |
| Feasibility (0–1) | How likely the latent defect is reachable on some input. Per `ai-verification-pipeline.md` Stage 3: **1.0** = must hold for every argument of a public function (total panic-freedom, termination). **0.7** = reachable only through caller-chosen configuration or API inputs on a specific path. **0.4** = reachable only if constant data or an internal invariant regresses. |
| Blast_Radius (1–4) | Same scale as Step 1. 4 = every MPL consumer, every keystore/hierarchical user, or a `prim` function the ESDK also calls. 3 = widely used but feature-specific. 2 = opt-in configuration. 1 = narrow. |

Ties are broken by higher severity, then higher feasibility, then id. A quick win has score > 6.0 and effort ≤ 1 week.

## 2. Summary table (ranked)

| Rank | ID | Score | Origin | Target | Property | Agent | Ref | Effort |
|---|---|---|---|---|---|---|---|---|
| 1 | VR-2026-C01 | 6.72 | C | `keystore/encryption_context.rs` builders ∘ `keystore/record.rs` reconstruction | CreateKey ECs reconstruct to exactly (id, version, custom EC); collision branch is dead; record→EC→record inverse | verus-header-parsing-proofs | cap:cat1 (1c) | 1 week (quick win) |
| 2 | VR-2026-C02 | 6.40 | C | `prim::ecdsa` `sign_fixed_len`, `check_sig_len`, `ecdsa_sign`, `ecdsa_sign_digest`, `ecdsa_verify*` | ≤ 128 `sign_once` calls; no panic; buffer written only with an exact-length candidate | verus-zero-panic | cap:cat2 (2d) | 1 week (quick win) |
| 3 | VR-2026-C03 | 5.60 | C | `prim::{hmac, digest, aes_encrypt, aes_decrypt}`, `DigestContext::finish`, `prim::{hkdf, hkdf_no_salt, hkdf_expand, kbkdf_ctr_hmac}` | No panic on any input; exact Ok/Err length contract | verus-zero-panic | cap:cat2 (2a/2d) | 1 week |
| 4 | VR-2026-C04 | 5.60 | C | Plaintext-data-key producers: `RawAesKeyring` / `HierarchicalKeyring` `on_encrypt`/`on_decrypt`, `generate_random_data_key` (×2), `EncryptionMaterials::new`, `DecryptionMaterials::new` | Every materials PDK has length = suite `encryption_key_length` (expected to FAIL on two paths) | verus-header-parsing-proofs | cap:cat1 (1a) | 1 week |
| 5 | VR-2026-C05 | 2.40 | C | `AlgorithmSuiteId::specification`, `id_bytes`, `AlgorithmSuite::verification_key_length` | Full suite table refines `algorithm-suites.md`; ids injective, never `00 00`; cross-crate length agreement | verus-header-parsing-proofs | cap:cat1 (1a) | 1 day |
| 6 | VR-2026-C06 | 1.96 | C | `HierarchicalKeyring::new` (storm-tracking grace-vs-TTL check) | Integer-division check accepts exactly `grace < ttl`; no overflow, non-zero divisor | verus-zero-panic | cap:cat2 (2b/2c) | 1 day |

Quick wins: **VR-2026-C01** and **VR-2026-C02**.

Foundational targets (the Stage 2' quality check "would proving it reduce the gap for several threat-driven targets?"): C03 is assumed by T04, T05, T07 and T13, which all call into `prim`. C01 links T01 and T02 into an end-to-end CreateKey → Get statement and is reused by T18.

## 3. Detailed recommendations (YAML)

```yaml
recommendation:
  id: VR-2026-C01
  rank: 1
  priority_score: 6.72
  origin: capability-driven
  target:
    crate: aws-crypto-mpl
    file: mpl/src/keystore/encryption_context.rs; mpl/src/keystore/record.rs
    function: >
      encryption_context::{build_base (private), decrypt_only_encryption_context, active_encryption_context,
      beacon_key_encryption_context}; record::{branch_key_materials_from_authenticated_encryption_context,
      custom_encryption_context_from_authenticated_encryption_context, encryption_context_from_item, to_attribute_map}
  property: >
    (a) Builder→reconstruction round trip. Take any EncryptionContextInput with a
    non-empty branch_key_id, a non-empty version v, and a custom EC C whose keys and
    values are valid UTF-8, and let both builders return Ok. Then reconstruction of
    active_encryption_context(input, v) or decrypt_only_encryption_context(input, v)
    with a 32-byte plaintext pt returns Ok(m), where m.branch_key = pt,
    m.branch_key_id = input.branch_key_id, m.branch_key_version = v, and
    m.encryption_context = C byte for byte. For any 32-byte pt, reconstruction of
    beacon_key_encryption_context(input) returns Err(RecordMalformed).
    (b) custom_encryption_context_from_authenticated_encryption_context(build_base(input, t)) == C
    for every accepted input, so prefixing and stripping are exact inverses.
    (c) Dead branch: the "collides with an existing encryption context entry after
    prefixing" Err in build_base (encryption_context.rs:111–123) is unreachable. None of the
    six base keys starts with "aws-crypto-ec:", strict UTF-8 decoding is injective, and C
    has unique keys.
    (d) Record codec reverse direction: to_attribute_map(encryption_context_from_item(r, n), r.enc) == r
    exactly when r.attributes has neither a "tablename" nor an "enc" key. A stored
    "tablename" attribute is otherwise overwritten by n and then dropped.
  formal_spec: |
    spec fn pre(s: Seq<char>) -> Seq<char> { "aws-crypto-ec:"@ + s }
    spec fn utf8_ok(c: Map<Seq<u8>,Seq<u8>>) -> bool { forall|k| c.contains_key(k) ==> valid_utf8(k) && valid_utf8(c[k]) }
    proof fn builder_reconstruction_round_trip(input: EncryptionContextInput, v: Seq<char>, pt: Seq<u8>)
      requires input.branch_key_id@.len() > 0, v.len() > 0, pt.len() == 32,
               input.custom_ec matches Some(c) ==> utf8_ok(c@)
      ensures  forall|ec| active_encryption_context(&input, v) == Ok(ec) || decrypt_only_encryption_context(&input, v) == Ok(ec)
                 ==> branch_key_materials_from_authenticated_encryption_context(&ec, pt) matches Ok(m)
                     && m.branch_key@ == pt && m.branch_key_id@ == input.branch_key_id@
                     && m.branch_key_version@ == v && m.encryption_context@ == custom_or_empty(input)@
      ensures  beacon_key_encryption_context(&input) matches Ok(ec)
                 ==> branch_key_materials_from_authenticated_encryption_context(&ec, pt) matches Err(e)
                     && e.kind == KeystoreErrorKind::RecordMalformed
    fn build_base(input: &EncryptionContextInput, t: &str) -> (r: Result<BTreeMap<String,String>, KeystoreError>)
      ensures r matches Ok(ec) ==> custom_encryption_context_from_authenticated_encryption_context(&ec)@ == custom_or_empty(input)@
      ensures r matches Err(e) ==> !(e.message@.contains("collides"@))      // (c): collision Err never produced
    proof fn record_reverse(r: EncryptedRecord, n: Seq<char>)
      ensures (to_attribute_map(&encryption_context_from_item(&r, n), r.enc) == r)
              <==> (!r.attributes@.contains_key("tablename"@) && !r.attributes@.contains_key("enc"@))
  tool: Verus
  agent: verus-header-parsing-proofs
  estimated_effort: 1 week
  threat_references: []
  capability_reference:
    category: 1          # Functional correctness — 1c round-trip, 1b Map refinement
    invariant: >
      For every accepted CreateKey input, the keystore EC builders and the reconstruction
      decoder are exact inverses on (branch-key-id, version, custom EC). The builder's
      collision-error branch is dead code, and record↔EC conversion is the identity off
      the reserved "tablename"/"enc" keys.
  trace_to_spec: >
    spec/framework/branch-key-store.md#encryption-context, #active-encryption-context,
    #decrypt_only-encryption-context, #beacon-key-encryption-context,
    #branch-key-materials-from-authenticated-encryption-context,
    #custom-encryption-context-from-authenticated-encryption-context, #record-format
  coverage_gap: 0.8
  coverage_evidence: >
    Each half is tested in isolation, and no test composes them.
    mpl/tests/test_keystore_encryption_context.rs tests the builders alone:
    custom_ec_keys_are_prefixed_with_aws_crypto_ec, custom_ec_values_are_preserved,
    active_is_decrypt_only_with_type_and_version_overrides, non_utf8_custom_ec_key_is_rejected,
    distinct_non_utf8_custom_ec_keys_do_not_collapse, empty_version_is_rejected_for_{decrypt_only,active}.
    mpl/tests/test_keystore_record.rs tests reconstruction on hand-built maps from
    make_authenticated_ec, not builder output:
    record_format_optional_custom_ec_round_trips, custom_ec_extraction_strips_prefix,
    materials_reconstruction_branch_active_uses_version_attribute, materials_reconstruction_branch_version_uses_type_value,
    and item_encryption_context_round_trips (EC→record→EC direction only).
    No test reaches the collision branch (a grep for "collides" in mpl/tests finds only comments).
    No test covers the record→EC→record direction.
  rationale: |
    This is the Vest-style round-trip shape (methodology only) applied to the keystore's
    string-map codec. It is the production pair: BranchKeyStore::create_key builds the
    three ECs (branch_key_store.rs:367–369), and the three get_* paths reconstruct them
    (branch_key_store.rs:566, 588, 609). A silent mismatch would hand back materials whose
    custom EC differs from what the caller stored, and no cryptographic check catches
    that, because the stripping happens after KMS authentication. T02 characterizes the
    decoder and T01 the DDB item codec. Neither states the composition. Expected outcome:
    (a)–(d) verify. (c) is a dead-code finding: the guard is harmless, but the proof shows
    it can be removed or turned into a debug_assert! (owner's choice, not changed here).
    Trusted: an external spec for str::from_utf8 injectivity and String formatting
    (format! modeled as Seq concatenation).
  scoring:
    severity: 3          # silently wrong key identity / custom EC on returned materials
    coverage_gap: 0.8
    feasibility: 0.7     # reachable through caller-supplied CreateKey custom EC and version
    blast_radius: 4      # every keystore / hierarchical-keyring consumer
    product: "3 × 0.8 × 0.7 × 4 = 6.72"
  quick_win: true        # score > 6.0, effort ≤ 1 week
  dependencies: [VR-2026-T02]   # soft: reuses T02's decoder spec instead of re-deriving it
```

```yaml
recommendation:
  id: VR-2026-C02
  rank: 2
  priority_score: 6.40
  origin: capability-driven
  target:
    crate: aws-mpl-primitives
    file: prim/src/ecdsa.rs
    function: >
      sign_fixed_len (private, line 177); check_sig_len (private, line 197); ecdsa_sign (221);
      ecdsa_sign_digest (250); ecdsa_verify (279); ecdsa_verify_context (302); signature_len (155)
  property: >
    sign_fixed_len calls sign_once at most MAX_SIGN_ATTEMPTS (= 128) times and always
    returns. copy_from_slice (ecdsa.rs:185) runs only when the candidate length equals
    signature.len(), so it cannot panic. On Ok, signature holds exactly the bytes of one
    candidate. On Err, either sign_once failed or 128 candidates were all the wrong length,
    and signature is unmodified (never partially written). ecdsa_sign and
    ecdsa_sign_digest return Err unless |signature| == signature_len(alg) (71 for P-256,
    103 for P-384), and they never panic for any key, message or buffer. ecdsa_verify and
    ecdsa_verify_context never return Err, as their docs claim.
  formal_spec: |
    // sign_once modeled as an abstract oracle; ghost counter `calls` (closure refactored to a trait
    // object or explicit oracle parameter for Verus — behavior-preserving, proof-stage only)
    fn sign_fixed_len(signature: &mut [u8], sign_once: impl FnMut() -> Result<Signature, Error>) -> (r: Result<(), Error>)
      ensures ghost_calls <= 128
      ensures r.is_Ok() ==> exists|i: int| 0 <= i < ghost_calls && ghost_cand[i]@.len() == old(signature)@.len()
                              && signature@ == ghost_cand[i]@
      ensures r.is_Err() ==> signature@ == old(signature)@
    // loop: for _ in 0..MAX_SIGN_ATTEMPTS  invariant k <= 128, ghost_calls == k, signature@ == old(signature)@
    fn check_sig_len(alg, s: &[u8]) -> (r) ensures r.is_Ok() <==> s@.len() == signature_len(alg)
    fn ecdsa_sign(alg, key, msg, signature: &mut [u8]) -> (r: Result<(), Error>)
      ensures r.is_Ok() ==> signature@.len() == signature_len(alg)        // no requires: total
    fn ecdsa_verify(alg, key, msg, sig) -> (r: Result<bool, Error>) ensures r.is_Ok()
    fn ecdsa_verify_context(alg, key, ctx, sig) -> (r: Result<bool, Error>) ensures r.is_Ok()
  tool: Verus
  agent: verus-zero-panic
  estimated_effort: 1 week
  threat_references: []
  capability_reference:
    category: 2          # Zero-panic — 2d total error handling, plus bounded termination
    invariant: >
      The ECDSA signing retry loop terminates after at most 128 attempts on every input,
      never panics, and writes the caller's buffer only with an exact-length DER signature.
  trace_to_spec: >
    spec/framework/algorithm-suites.md#asymmetric-signature-algorithm (fixed-length signature use in ESDK);
    baseline assurance, no single MPL clause
  coverage_gap: 0.8
  coverage_evidence: >
    prim/tests/test_ecdsa.rs: test_ecdsa_sign_rejects_wrong_length_buffer,
    test_ecdsa_sign_digest_rejects_wrong_length_buffer, test_ecdsa_p256_signature_length_is_71,
    test_ecdsa_p384_signature_length_is_103, test_ecdsa_sign_with_bad_private_key,
    test_ecdsa_sign_digest_with_bad_private_key, test_ecdsa_p256_round_trip_and_tamper,
    test_ecdsa_p384_round_trip_and_tamper. sign_fixed_len is private and its oracle cannot be
    injected, so no test exercises the retry-exhaustion path, the termination bound, or the
    "buffer untouched on Err" property (a grep for sign_fixed_len / MAX_SIGN_ATTEMPTS in the
    test trees finds nothing).
  rationale: |
    A loop whose exit depends on randomized output is the classic latent hang. Here it is
    bounded syntactically, and the proof makes that bound and the "no partial write"
    behavior a theorem. The ESDK signs every message under a signing suite through
    ecdsa_sign_digest. CommitmentPolicy::default_algorithm_suite_id for both REQUIRE_*
    policies is 0x0578 (ECDSA P-384), so this is on the default encrypt path.
    Excluded: the 2^-128 exhaustion probability argued in the MAX_SIGN_ATTEMPTS doc comment
    (probabilistic) and ECDSA security. Trusted (TCB): aws-lc-rs EcdsaKeyPair::{sign,
    sign_digest}, from_private_key_der and UnparsedPublicKey::verify* return Result and
    never panic. The verus-zero-panic agent's sample (a `while i < 128` with `decreases`) is
    the right pattern.
  scoring:
    severity: 2          # hang or panic → DoS
    coverage_gap: 0.8
    feasibility: 1.0     # termination and panic-freedom must hold for all inputs and oracles
    blast_radius: 4      # every ESDK signing-suite encrypt (default suite of REQUIRE_* policies)
    product: "2 × 0.8 × 1.0 × 4 = 6.40"
  quick_win: true        # score > 6.0, effort ≤ 1 week
  dependencies: []
```

```yaml
recommendation:
  id: VR-2026-C03
  rank: 3
  priority_score: 5.60
  origin: capability-driven
  target:
    crate: aws-mpl-primitives
    file: prim/src/lib.rs; prim/src/ecdsa.rs; prim/src/hkdf.rs
    function: >
      hmac (lib.rs:261); digest (292); aes_encrypt (197); aes_decrypt (227); kbkdf_ctr_hmac (333);
      DigestContext::finish (ecdsa.rs:79); hkdf (hkdf.rs:43); hkdf_no_salt (71); hkdf_expand (96)
  property: >
    No function in this list panics for any argument values.
    hmac / digest / DigestContext::finish: each returns Err unless |out| equals the
    algorithm's output length, and only then runs copy_from_slice
    (lib.rs:280, 305; ecdsa.rs:87). On Ok, out holds exactly the tag or digest. The two
    `match alg` tables in hmac (digest algorithm and HMAC algorithm) agree, and
    DigestAlg::output_len(a) == get_digest_alg(a).output_len() for all three variants.
    aes_encrypt: `&mut cipher_text[old_size..]` (lib.rs:208) is in range. On Ok,
    |cipher_text| = old + |message| + 16.
    aes_decrypt: on Ok, |plain_text| == |cipher_text| (equality, not ≥).
    hkdf_no_salt: `&salt[..sz]` (hkdf.rs:79) is in range because sz ≤ 64.
    hkdf / hkdf_expand: Ok ⇒ |okm| ∈ {16, 24, 32}.
    kbkdf_ctr_hmac: total (returns Err, never panics).
  formal_spec: |
    // TCB external specs (aws-lc-rs 1.17.x safe API):
    //   digest::digest(a, d).as_ref().len() == a.output_len();  Context::finish().as_ref().len() == ctx.algorithm().output_len()
    //   hmac::sign(Key(HMAC_SHAx), m).as_ref().len() == SHAx.output_len()
    //   LessSafeKey::open_separate_gather(.., ct, tag, pt) returns Err when pt.len() != ct.len()   (read in aws-lc-rs 1.17.1
    //     src/aead/unbound_key.rs `open_separate_gather_impl`; mpl pins =1.17.0, prim requires ^1.15.4 — re-check per pin)
    //   UnboundKey::new / Nonce::try_assume_unique_for_key / seal_in_place_separate_tag / Okm::fill: Result, never panic
    proof fn output_len_agrees(a: DigestAlg) ensures a.output_len() == get_digest_alg(a).output_len()
    fn hmac(alg, key: &[u8], msg: &[u8], out: &mut [u8]) -> (r: Result<(), Error>)
      ensures r.is_Ok() <==> out@.len() == alg.output_len()          // no requires
      ensures r.is_Ok() ==> out@ == hmac_spec(alg, key@, msg@)       // hmac_spec uninterpreted
    fn digest(alg, data, out) -> (r) ensures r.is_Ok() <==> out@.len() == alg.output_len()
    fn finish(self, out: &mut [u8]) -> (r) ensures r.is_Ok() <==> out@.len() == self.output_len_spec()
    fn aes_encrypt(alg, iv, key, msg, aad, ct: &mut Vec<u8>) -> (r)
      ensures r.is_Ok() ==> ct@.len() == old(ct)@.len() + msg@.len() + 16
      ensures r.is_Err() ==> ct@.len() == old(ct)@.len() || ct@ == old(ct)@ + msg@   // documents plaintext residue on Err
    fn aes_decrypt(alg, key, ct, tag, iv, aad, pt: &mut [u8]) -> (r)
      ensures r.is_Ok() ==> pt@.len() == ct@.len()
      ensures pt@.len() != ct@.len() ==> r.is_Err()
    fn hkdf_no_salt(alg, ikm, info, okm) -> (r)   // default_salt_size(alg) <= MAX_SALT_SIZE == 64 ⇒ slice in range
    fn hkdf(alg, salt, ikm, info, okm) -> (r) ensures r.is_Ok() ==> okm@.len() == 16 || okm@.len() == 24 || okm@.len() == 32
  tool: Verus
  agent: verus-zero-panic
  estimated_effort: 1 week
  threat_references: []
  capability_reference:
    category: 2          # Zero-panic — 2a slice bounds, 2d length-checked copy_from_slice totality
    invariant: >
      No reachable panic path in the prim crypto wrappers for any argument values. Each
      wrapper's Ok result implies an exact output length (decrypt: |pt| == |ct|).
  trace_to_spec: >
    supports spec/framework/algorithm-suites.md (key / IV / tag / digest lengths) and
    spec/framework/transitive-requirements.md; baseline assurance, no single clause
  coverage_gap: 0.7
  coverage_evidence: >
    prim/tests/test_hmac.rs::test_hmac_rejects_wrong_length_output_buffer;
    prim/tests/test_digest.rs::{test_digest_rejects_wrong_length_output_buffer, test_digest_alg_output_len};
    prim/tests/test_aes.rs::{test_aes_decrypt_output_buffer_too_small, test_aes_encrypt_bad_key_length,
    test_aes_encrypt_bad_iv_length, test_aes_decrypt_bad_key_length, test_aes_decrypt_bad_iv_length,
    test_aes_decrypt_tampered_auth_tag};
    prim/tests/test_hkdf.rs::{test_hkdf_bad_okm_length, test_hkdf_expand_bad_okm_length};
    prim/tests/test_kbkdf_ctr_hmac.rs::test_kbkdf_ctr_hmac_empty_okm.
    Gaps: no test passes a wrong-length buffer to DigestContext::finish
    (prim/tests/test_ecdsa.rs::test_digest_context_* always sizes by output_len()), and no test
    passes aes_decrypt a plain_text buffer LONGER than cipher_text.
  rationale: |
    This is the recommender's canonical capability target. One proof covers every MPL and
    ESDK caller of these wrappers. Expected finding (not a panic): aes_decrypt's own guard
    (lib.rs:236) rejects only |pt| < |ct|, but aws-lc-rs rejects any |pt| ≠ |ct|. So a
    longer buffer fails with a generic "gather" error, while the doc comment promises an
    error only for a shorter buffer. The safety comes from aws-lc-rs's check, not prim's. Both
    MPL callers size the buffer exactly (raw_aes_keyring.rs: `vec![0u8; encrypted_key.len()]`;
    branch_key_wrap unwrap). Tightening the guard or the docs is the owner's choice and is
    not changed here. The verus-zero-panic agent text ("prove the buffer relationship that
    makes open_separate_gather safe") should be read with this in mind: the provable
    relationship is equality. Trusted, not proven: Vec growth in extend_from_slice never
    hits capacity overflow or allocation failure (allocator is outside Verus's model).
  scoring:
    severity: 2          # panic → DoS
    coverage_gap: 0.7
    feasibility: 1.0     # must hold for all inputs of public functions
    blast_radius: 4      # every MPL keyring + the ESDK body/header/KDF/signature paths
    product: "2 × 0.7 × 1.0 × 4 = 5.60"
  quick_win: false       # score < 6.0
  dependencies: []
```

```yaml
recommendation:
  id: VR-2026-C04
  rank: 4
  priority_score: 5.60
  origin: capability-driven
  target:
    crate: aws-crypto-mpl
    file: >
      mpl/src/keyring/raw_aes_keyring.rs; mpl/src/aws_kms/hierarchical_keyring.rs;
      mpl/src/structures/encryption_materials.rs; mpl/src/structures/decryption_materials.rs
    function: >
      <RawAesKeyring as Keyring>::{on_encrypt, on_decrypt}; <HierarchicalKeyring as Keyring>::{on_encrypt, on_decrypt};
      HierarchicalKeyring::try_decrypt_edk (line 524); generate_random_data_key (raw_aes_keyring.rs:382, hierarchical_keyring.rs:607);
      EncryptionMaterials::new; DecryptionMaterials::new
  property: >
    Materials invariant pdk_ok(m): if m has a plaintext data key k, then
    |k| == m.algorithm_suite().encryption_key_length() (16, 24 or 32).
    Obligations: (i) both generate_random_data_key copies return exactly that length.
    (ii) every keyring output satisfies pdk_ok. (iii) the two material constructors
    either establish pdk_ok or are documented as not doing so.
    EXPECTED OUTCOME: the proof FAILS on two paths, which is the point of scoping it.
    (F1) HierarchicalKeyring::on_decrypt (line 415) wraps whatever try_decrypt_edk returns.
    That is unwrap's output of |ciphertext| − 60 bytes, with no length check against the
    suite. RawAesKeyring::on_decrypt does check (raw_aes_keyring.rs:326).
    (F2) EncryptionMaterials::new and DecryptionMaterials::new never check PDK length. Both
    keyrings' on_encrypt reuse an incoming PDK unchanged (`Some(pdk) => pdk.clone()`), so a
    wrong-length PDK supplied by a caller-built CMM or a chained keyring is wrapped and
    returned.
    With `requires pdk_ok(input)` both on_encrypt paths verify, and RawAesKeyring::on_decrypt
    verifies unconditionally.
  formal_spec: |
    spec fn pdk_ok_e(m: EncryptionMaterials) -> bool
      { m.plaintext_data_key matches Some(k) ==> k@.len() == m.algorithm_suite_id.specification().encryption_key_length() }
    spec fn pdk_ok_d(m: DecryptionMaterials) -> bool { /* same */ }
    fn generate_random_data_key(s: AlgorithmSuite) -> (r) ensures r matches Ok(k) ==> k@.len() == s.encryption_key_length()
    fn <RawAesKeyring>::on_decrypt(&self, m, edks) -> (r) ensures r matches Ok(m2) ==> pdk_ok_d(m2)            // expected: VERIFIES
    fn <RawAesKeyring>::on_encrypt(&self, m) -> (r) requires pdk_ok_e(m) ensures r matches Ok(m2) ==> pdk_ok_e(m2)  // verifies only with requires
    fn <HierarchicalKeyring>::on_encrypt(&self, m) -> (r) requires pdk_ok_e(m) ensures r matches Ok(m2) ==> pdk_ok_e(m2)
    fn <HierarchicalKeyring>::on_decrypt(&self, m, edks) -> (r) ensures r matches Ok(m2) ==> pdk_ok_d(m2)       // expected: FAILS (F1)
    fn EncryptionMaterials::new(.., pdk, ..) -> (r) ensures r matches Ok(m) ==> pdk_ok_e(m)                    // expected: FAILS (F2)
    // pure fragments extracted from the async fns for the proof (behavior-preserving, proof stage only)
  tool: Verus
  agent: verus-header-parsing-proofs
  estimated_effort: 1 week
  threat_references: []
  capability_reference:
    category: 1          # Functional correctness — 1a struct invariant / pre-postcondition adherence
    invariant: >
      Every plaintext data key that an in-repo keyring or materials constructor emits has
      exactly the algorithm suite's encryption-key length.
  trace_to_spec: >
    spec/framework/keyring-interface.md#generate-data-key ("length of the output plaintext data key MUST be equal
    to the KDF input length of the algorithm suite"); spec/framework/structures.md#plaintext-data-key
    and #plaintext-data-key-1 ("MUST fit the specification for the key derivation / encryption algorithm");
    spec/framework/algorithm-suites.md#encryption-key-length
  coverage_gap: 1.0
  coverage_evidence: >
    No test exercises a wrong-length PDK at any producer. mpl/tests/test_raw_aes_keyring.rs has
    no test reaching the "decrypted data key is N bytes, expected M" branch (a grep for that
    message in mpl/tests finds nothing). mpl/tests/test_aws_kms_hierarchical_keyring.rs has no
    decrypted-length test. mpl/tests/test_encryption_materials.rs and test_decryption_materials.rs
    test signing/verification-key and RECK invariants only (test_required_ec_keys_must_be_subset,
    test_edks_must_be_empty_without_pdk, test_verification_key_length_must_match_algorithm_suite).
    mpl/tests/test_default_cmm.rs mock keyrings always size PDKs with suite.encryption_key_length().
  rationale: |
    The capability sweep found this by asking "which constructor invariants does
    structures.md require, and which does the code establish?" Downstream impact is
    bounded. The ESDK re-checks PDK length before key derivation
    (esdk/src/key_derivation.rs:87 and :190, read in this step), so for the ESDK a
    violation fails closed later and does not weaken a key. That is why severity is 2.
    Other MPL consumers were not inspected. Adding a length check to
    HierarchicalKeyring::on_decrypt or to the material constructors rejects inputs that are
    accepted today, which is a behavior change. It is recorded for the owner and not
    changed here.
  scoring:
    severity: 2          # spec-MUST violation at the MPL boundary; ESDK rejects later (fail-closed)
    coverage_gap: 1.0
    feasibility: 0.7     # reachable via caller-supplied PDK / authorized encryptor's wrapped length
    blast_radius: 4      # both in-repo keyrings, every MPL consumer
    product: "2 × 1.0 × 0.7 × 4 = 5.60"
  quick_win: false       # score < 6.0
  dependencies: []
```

```yaml
recommendation:
  id: VR-2026-C05
  rank: 5
  priority_score: 2.40
  origin: capability-driven
  target:
    crate: aws-crypto-mpl (+ aws-mpl-primitives constants)
    file: mpl/src/structures/algorithm_suite.rs; prim/src/lib.rs; prim/src/ecdsa.rs
    function: >
      AlgorithmSuiteId::{specification, id_bytes, has_asymmetric_signing, has_symmetric_signing};
      AlgorithmSuite::verification_key_length; prim::AesGcm::key_len; prim::field_size; prim::signature_len
  property: >
    For all 11 AlgorithmSuiteId variants, specification() equals the row of the
    algorithm-suites.md table: id, key length, IV 12, tag 16, encryption KDF, commit KDF,
    signature algorithm, message format version, suite-data length.
    Structural consequences proven as lemmas:
    - id_bytes is injective and never [0x00, 0x00].
    - encryption_key_length ∈ {16, 24, 32} and equals AesGcm::key_len() of the matching AES variant.
    - commit_kdf.is_some() ⟺ message_format_version == 0x02 ⟺ algorithm_suite_data_length == 32.
    - encryption_kdf == IdentityKdf ⟺ id[0] == 0x00.
    - asymmetric EcdsaP256 ⟹ KDF HkdfSha256; EcdsaP384 ⟹ KDF ∈ {HkdfSha384, HkdfSha512}.
    - verification_key_length == Some(prim::field_size(curve)) (33 / 49).
    - has_symmetric_signing() is false for every variant.
  formal_spec: |
    spec fn row(id: AlgorithmSuiteId) -> AlgorithmSuite   // transcribed from algorithm-suites.md#supported-algorithm-suites-enum
    fn specification(self) -> (s: AlgorithmSuite) ensures s == row(self)
    proof fn ids_injective(a, b) requires a.id_bytes() == b.id_bytes() ensures a == b
    proof fn no_reserved_id(a) ensures a.id_bytes() != [0u8, 0u8]
    proof fn key_len_is_aes(a) ensures exists|g: AesGcm| g.key_len() as usize == a.specification().encryption_key_length()
    proof fn commit_shape(a) ensures (a.specification().commit_kdf.is_some() <==> a.specification().message_format_version == 2)
                                  && (a.specification().commit_kdf.is_some() <==> a.specification().algorithm_suite_data_length == 32)
    proof fn vk_len_matches_prim(a) ensures a.specification().verification_key_length() ==
        a.specification().asymmetric_signature_algorithm.map(|c| prim_field_size(curve_map(c)))
  tool: Verus
  agent: verus-header-parsing-proofs
  estimated_effort: 1 day
  threat_references: []
  capability_reference:
    category: 1          # Functional correctness — 1a exact table refinement
    invariant: >
      The algorithm-suite table is exactly the spec table. Its ids are a unique,
      non-reserved encoding, and its key/IV/tag/verification-key lengths agree with the
      constants prim enforces.
  trace_to_spec: >
    spec/framework/algorithm-suites.md#supported-algorithm-suites-enum, #encryption-key-length,
    #algorithm-suites-encryption-key-derivation-settings, #algorithm-suites-commit-key-derivation-settings,
    #algorithm-suites-signature-settings, #algorithm-suite-id
  coverage_gap: 0.5
  coverage_evidence: >
    mpl/tests/test_algorithm_suite_id.rs enumerates the finite domain (20 tests), including
    test_hex_ids_match_spec_table, test_hex_ids_are_unique_across_all_suites,
    test_reserved_id_00_00_is_not_used, test_encryption_key_length_matches_spec_table,
    test_encryption_kdf_matches_spec_table, test_commit_kdf_present_only_for_commit_key_suites,
    test_message_format_version_branches_v1_and_v2, test_verification_key_length_matches_spec_table,
    test_symmetric_signature_algorithm_is_none_for_every_esdk_suite. No test checks the
    cross-crate agreement with prim::AesGcm::key_len or prim::field_size.
  rationale: |
    Cheap and regression-proofing. The value beyond the near-exhaustive tests is the
    cross-crate agreement lemmas, which nothing tests. Those are what let C03/C04 and T07
    assume "suite key length is a valid AES key length". T09 already owns
    key_commitment() and the commitment-policy tables (see §4). The rest of the table is
    new here.
  scoring:
    severity: 3          # a wrong row = wrong key length / KDF / signature for every message of that suite
    coverage_gap: 0.5
    feasibility: 0.4     # constant data; defect only via a regression edit
    blast_radius: 4
    product: "3 × 0.5 × 0.4 × 4 = 2.40"
  quick_win: false
  dependencies: []
```

```yaml
recommendation:
  id: VR-2026-C06
  rank: 6
  priority_score: 1.96
  origin: capability-driven
  target:
    crate: aws-crypto-mpl
    file: mpl/src/aws_kms/hierarchical_keyring.rs
    function: HierarchicalKeyring::new — storm-tracking grace-period bound (lines 178–190)
  property: >
    The check `grace_in_seconds >= ttl_seconds` uses grace_in_seconds = grace_period in
    Seconds mode and grace_period / 1000 in Milliseconds mode. It rejects exactly the
    configurations whose real grace period is ≥ the TTL: in Milliseconds mode, the
    keyring is accepted ⟺ grace_period < 1000 · ttl_seconds over mathematical integers,
    which follows from floor(g / 1000) < t ⟺ g < 1000·t. The divisor is the non-zero
    constant 1000, and the check never multiplies, so it cannot overflow even for
    ttl_seconds = u64::MAX. TimeUnits defaults to Seconds when unset, consistent with
    ValidatedConfig::from_raw.
  formal_spec: |
    spec fn grace_ms(p: StormTrackingCache) -> int
      { match p.time_units.unwrap_or_default() { Seconds => p.grace_period as int * 1000, Milliseconds => p.grace_period as int } }
    fn new(.., ttl_seconds: u64, .., cache_type: Option<CacheType>, ..) -> (r: Result<Self, MaterialsError>)
      ensures cache_type matches Some(CacheType::StormTracking(p)) && ttl_seconds > 0 && grace_ms(p) >= 1000 * ttl_seconds as int
                ==> r.is_Err()
      ensures r.is_Ok() && cache_type matches Some(CacheType::StormTracking(p)) ==> grace_ms(p) < 1000 * ttl_seconds as int
    proof fn floor_div_lemma(g: u64, t: u64) ensures (g / 1000 < t) <==> (g as int) < 1000 * (t as int)
  tool: Verus
  agent: verus-zero-panic
  estimated_effort: 1 day
  threat_references: []
  capability_reference:
    category: 2          # Zero-panic — 2c non-zero divisor, 2b no overflow; plus 1a exactness of the comparison
    invariant: >
      The cross-object bound "storm-tracking grace period < cache-limit TTL" is decided
      exactly for both time units, with no overflow and no division by zero.
  trace_to_spec: >
    spec/framework/aws-kms/aws-kms-hierarchical-keyring.md#cache-limit-ttl;
    spec/framework/storm-tracking-cryptographic-materials-cache.md#grace-period
  coverage_gap: 0.7
  coverage_evidence: >
    mpl/tests/test_aws_kms_hierarchical_keyring.rs: new_with_storm_tracking_grace_period_equal_to_ttl_fails,
    new_with_storm_tracking_grace_period_greater_than_ttl_fails (both Seconds),
    new_with_storm_tracking_milliseconds_grace_period_under_ttl_succeeds (5_000 ms vs 60 s).
    No Milliseconds boundary test (59_999 ms vs 60_000 ms against ttl 60).
  rationale: |
    Small and exact. It is the one place in the cache-configuration code that converts
    units with integer division, where truncation bugs usually hide. Expected outcome:
    verifies, because floor division is exact for a strict `<` against an integer. The
    overflow-prone alternative (`ttl_seconds * 1000`) is absent, and the proof records
    why that matters.
  scoring:
    severity: 2          # misconfiguration accepted → grace window ≥ TTL (availability)
    coverage_gap: 0.7
    feasibility: 0.7     # caller-chosen configuration
    blast_radius: 2      # opt-in storm-tracking cache on a hierarchical keyring
    product: "2 × 0.7 × 0.7 × 2 = 1.96"
  quick_win: false
  dependencies: []
```

## 4. Overlaps with Step 1

The Stage 2' sweep produced each candidate below, but a Step 1 target already scopes it. It is **not** re-issued or re-scored here, to avoid duplication. The last column says what the capability view adds that Step 3 consolidation should merge into the Step 1 target.

| Capability candidate (category) | Step 1 target | Overlap | What the capability view adds |
|---|---|---|---|
| `PlaintextDataKey::zeroize` in-bounds `write_volatile` writes and all-zero post-state (cat 3a, + 2a for `ptr.add(i)`) | **VR-2026-T08** | Full. Same function, same property, same agent (`verus-unsafe-ffi-safety`). | (1) The capability rationale holds independently of TM-MPL-015 and of the fact that `zeroize` has zero call sites in `mpl/src`. Soundness of the repo's only `unsafe` block is baseline assurance on its own. (2) Viewed as a latent defect, an out-of-bounds raw write is memory corruption (capability severity 4), which is stronger than T08's info-disclosure framing (severity 3). Step 3 may raise T08's priority, but must not count it twice. (3) Add `ensures self.0@.len() == old(self).0@.len()` *and* no reallocation / unchanged `as_ptr()` across the loop, so the post-state talks about the same buffer. Closest analogue: VeriSMo / Nitro secret-scrubbing proofs. |
| `structures::EncryptionContext::{serialize, deserialize}` round trip and canonical layout (cat 1c) | **VR-2026-T15** (round trip, injectivity, expected unsorted-accept counterexample); **VR-2026-T16** (deserialize panic-freedom, offset arithmetic) | Full. | Only the framing: the Vest non-malleability shape ("accepted bytes ⇒ canonical bytes") is exactly T15's expected counterexample. No new obligation. |
| `keystore/record.rs` `to_attribute_map` / `encryption_context_from_item` inverse pair (cat 1c) | **VR-2026-T01** part (c) (EC→record→EC) | Partial. | The reverse direction (record→EC→record, identity iff no `tablename`/`enc` attribute) and the builder→reconstruction composition are new and live in **VR-2026-C01**. |
| `record::branch_key_materials_from_authenticated_encryption_context` exact Ok/Err (cat 1a) | **VR-2026-T02** | Full for the decoder alone. | C01 reuses T02's spec as a lemma (`dependencies: [VR-2026-T02]`) and does not restate it. |
| Cache TTL arithmetic overflow in `mpl/src/cmc/` (cat 2b): `now + self.inflight_ttl` (`storm_tracking.rs:446`), `inflight + grace_interval` (`storm_tracking.rs:536`); and the keyring sites `now + Duration::from_secs(ttl)` (`hierarchical_keyring.rs:342, 585`) | **VR-2026-T06** (expected to FAIL as written) | Full for the add sites. | The sweep confirms these are the **only** arithmetic panic sites in `cmc/`. All subtraction is total: `within_grace_period` uses `checked_sub` with `is_none_or`, every `duration_since` is mapped through `unwrap_or(Duration::ZERO)` / `map_or(true, ..)`, `Duration::from_secs/from_millis(u64)` cannot panic, and `prune_tail` uses `min(tail, len)`. So once T06's bounds exist, `cmc/` is arithmetic-panic-free. There is **no counter arithmetic at all** (see §5, R1). |
| `ValidatedConfig::from_raw` bounds; `within_grace_period` / `within_grace_interval` vs. spec formulas (cat 1a / 2b) | **VR-2026-T21** | Full. | — |
| `LocalCmc` `len ≤ entry_capacity`; `prune_tail` no underflow (cat 2b) | **VR-2026-T23** | Full. | `LruCache` length bookkeeping is inside the `lru` crate (TCB external spec), not MPL arithmetic. |
| Storm-tracking single-inflight / `|inflight| ≤ fan_out` under concurrency (cat 4a/4b) | **VR-2026-T21** (sequential slice + flagged concurrency specialist) | Full. | Category 4 obligations to hand the specialist: a `tracked` ghost permission over the `StormTrackingState` map tied to the mutex invariant, plus the two-mutex ordering (`LocalCmc` put completes before the in-flight mark is cleared, `storm_tracking.rs:541–553`). Category 3c (interior mutability) does not apply, because the repo has no `UnsafeCell`/`Cell`/atomics. |
| `cache_entry_within_limits` TTL gate (cat 1a) | **VR-2026-T14** part (b) | Full. | Precision note: `elapsed.as_secs() <= ttl_seconds` truncates, so an entry is accepted for elapsed < ttl + 1 s. With the in-repo `LocalCmc`/`StormTrackingCmc` this slack is unobservable, because entries are stored with `expiry_time = now + ttl` and evicted at `expiry_time <= now`. It is observable only with a caller-supplied `CacheType::Shared` cache that ignores expiry. T14's `elapsed_secs_sat` spec should state the truncation explicitly. |
| KBKDF fixed-info layout (cat 1d, listed in `verus-capabilities.md`) | **VR-2026-T05** | Full. | — |
| `prim::aes_encrypt` / `aes_decrypt` safe-wrapper length preconditions (cat 3b) | **VR-2026-T07** (caller-side preconditions ⇒ Ok, `verus-unsafe-ffi-safety`) | Partial. | **VR-2026-C03** covers only the unconditional half: no panic with no `requires`, and the `aes_decrypt` Ok ⇒ `|pt| == |ct|` contract (an equality that prim's own `<` guard does not express). T07 keeps "preconditions hold at the raw-AES call sites ⇒ the only Err is an auth failure". |
| `AlgorithmSuite::key_commitment` and commitment-policy allow-tables (cat 1a) | **VR-2026-T09** | Partial. | **VR-2026-C05** covers the rest of the suite table (lengths, KDFs, signature algorithms, format version, id injectivity, cross-crate constants). T09's `committing(id)` predicate is reused, not restated. |
| MPL-side `copy_from_slice` / `try_into` / slice / index / `.expect` sites (`branch_key_wrap::unwrap`, `try_decrypt_edk`, `RawAesKeyring::{on_decrypt, decryptable_edk_iv}`, `aws_kms_mrk_match_for_decrypt` `pa[5]`, `build_cache_identifier`, `DefaultCmm` `.expect`s, `kms_config::parse_arn` `segments[5]`) (cat 2a/2d) | **VR-2026-T16** (and T17 for `parse_arn`) | Full. | The `prim` side of the same sweep is new (**C02**, **C03**). `record.rs`'s `<[u8; 32]>::try_from` is total by construction (`map_err`) and is discharged inside T02. |
| `ecdsa_generate_keypair(..).expect` at `default_cmm.rs:115` (cat 2d) | **VR-2026-T16** (expected-unprovable obligation) | Full. | C02 deliberately excludes `prim::ecdsa_generate_keypair`. It already returns `Err` on every failure, so the abort is purely MPL-side. |

## 5. Considered and rejected

| # | Candidate | Reason rejected |
|---|---|---|
| R1 | Cache **usage-counter** overflow/underflow (`cmc/entry.rs` `MessageUsage(u64)`, `BytesUsage(u64)`, `UsageMetadata`) — the example lemma in `verus-zero-panic.md` | **No such arithmetic exists.** A grep finds no producer or mutator of `messages_used`/`bytes_used` in `mpl/src`. The only construction is `UsageMetadata::default()` in `hierarchical_keyring.rs`, and there is no caching CMM (Step 1 correction C4). There is no byte total or entry counter in MPL code either, because `lru::LruCache` tracks its own length. Nothing to prove until a caching CMM lands. |
| R2 | `constant_time_equal` is constant-time | Verus does not model timing. The functional result is a one-line call into aws-lc-rs. |
| R3 | `generate_random_bytes` output quality; partition-id / IV / salt uniqueness | Probabilistic secrecy (decision aid: "No — probabilistic"). |
| R4 | `sign_fixed_len` exhaustion probability ≤ 2^-128 | Probabilistic. Only the deterministic termination bound is scoped (C02). |
| R5 | Security of AES-GCM, ECDSA, HMAC, HKDF, KBKDF, SHA-384 | Cryptographic hardness, out of scope. |
| R6 | Termination of `error_chain::find_in_error_chain` / `aws_service_error_code` (`while let Some(current) = link { .. link = current.source() }`) | Termination depends on third-party `dyn Error::source()` implementations being acyclic. Proving it needs an unjustified axiom over external trait objects, so it is not a sound target. |
| R7 | Raw C-FFI buffer soundness (cat 3b proper) | No raw FFI in this repo. The `unsafe` inside aws-lc-rs (e.g. `open_separate_gather_impl`) is third-party and is trusted (TCB) by C03/T07. |
| R8 | Interior-mutability / custom-layout proofs (cat 3c); custom lock protocols (cat 4a) | None exist: no `UnsafeCell`/`Cell`/`RefCell`/atomics/`RwLock`, only `std::sync::Mutex`. The one protocol built on it (storm tracking) is T21. |
| R9 | `DigestContext::new` / `new_from_ecdsa` always `Ok`; `Format::{long_name, short_name}` | Trivial `match`/constant code with no proof content beyond what C05 already states. |
| R10 | `Duration::from_secs` / `from_millis` in `ValidatedConfig::from_raw` | Total in std for every `u64`. Nothing to prove. |
| R11 | Drop-driven zeroization of `BranchKeyMaterials`, `SigningKey`, `SymmetricSigningKey`, `RawAesKeyring.wrapping_key` | No code exists (Step 1 correction C6). Verus would only confirm the absence, and the fix is a design change. |
| R12 | Panic of `wait_for_leader` (`tokio::time::sleep`) under a non-Tokio executor | Runtime environment requirement, not a code property (as in T21's exclusions). |
| R13 | Allocation failure / `Vec` capacity overflow in `prim::aes_encrypt` `extend_from_slice` | Allocator behavior is outside Verus's model. Listed as a TCB assumption in C03 instead. |

## 6. Findings recorded, not changed

Each item is a behavior or product decision for the owner. No source file was modified in this step.

- **C04-F1:** `HierarchicalKeyring::on_decrypt` accepts an unwrapped PDK of any length (no check against `encryption_key_length`). `RawAesKeyring::on_decrypt` does check. The ESDK re-checks later (`esdk/src/key_derivation.rs:87, 190`).
- **C04-F2:** `EncryptionMaterials::new` / `DecryptionMaterials::new` do not enforce the `structures.md` PDK-length MUST. Both keyrings' `on_encrypt` pass an incoming PDK through unchecked.
- **C03:** `prim::aes_decrypt` documents an error only for a *shorter* `plain_text`, but any length mismatch errors inside aws-lc-rs. prim's guard (`lib.rs:236`) is partial and safety comes from the callee. Docs or guard could be tightened.
- **C01(c):** the custom-EC collision `Err` branch in `keystore/encryption_context.rs::build_base` is unreachable (dead code). It is harmless.
- **§4 / T14:** `cache_entry_within_limits` admits up to `ttl + 1 s` of elapsed time because of `as_secs()` truncation. It is only observable with a `Shared` cache that ignores `expiry_time`.

## 7. Accounting

- **6 capability-driven targets** (VR-2026-C01..C06), all `origin: capability-driven`, each with `capability_reference`. Category split: cat 1 ×3 (C01, C04, C05), cat 2 ×3 (C02, C03, C06). Cat 3 and cat 4 candidates were fully covered by Step 1 (T08, T21) and are recorded as overlaps.
- **Routing:** `verus-header-parsing-proofs` ×3 (C01, C04, C05), `verus-zero-panic` ×3 (C02, C03, C06). No new `verus-unsafe-ffi-safety` target, because its two surfaces are T08 (zeroize) and T07 (safe-wrapper preconditions).
- **14 overlap rows with Step 1:** T01, T02, T05, T06, T07, T08, T09, T14, T15, T16, T17, T21, T23.
- **13 candidates rejected** with reasons (R1–R13).
- Required considerations, and where each landed: prim `hmac` / `digest` / `aes_decrypt` / `DigestContext::finish` → C03. `ecdsa_sign` + `sign_fixed_len` termination → C02. `PlaintextDataKey::zeroize` → overlap T08. `record.rs` / `keystore/encryption_context.rs` codec round trips → C01 (+ overlaps T01, T02, T15). `cmc/` counter/TTL arithmetic → overlap T06/T21/T23 + R1 (no counters exist). Suite table → C05 (+ overlap T09).
