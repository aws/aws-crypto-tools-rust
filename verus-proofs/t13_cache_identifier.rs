// =============================================================================
// VR-2026-T13 (TM-MPL-009, TM-MPL-010; BUG-06): cache-identifier preimage of
//   cache_entry_identifier::build_cache_identifier
//
// Run:  ~/verus/verus verus-proofs/t13_cache_identifier.rs
// This file is NOT part of any cargo build (it lives outside mpl/, prim/, esdk/).
//
// -----------------------------------------------------------------------------
// THIS IS A MODEL-LEVEL PROOF, NOT A PROOF OF THE SHIPPED CODE.
// It proves facts about a hand-written, re-typed model of the preimage layout.
// The shipped function is native Rust, is not inside `verus!`, and is not compiled
// by Verus. Nothing here detects a later edit to mpl/. The link between model and
// code is the correspondence table below, reviewed by a human.
//
// STATUS: PARTLY PROVED. Everything verifies except ONE obligation that Verus
// REJECTS ON PURPOSE (expected-FAIL):
//     `lemma_bug06_injectivity_without_nul_precondition_EXPECTED_FAIL`  (section 8)
// It states the property the spec promises ("keyrings with different configuration
// CANNOT share cache entries": different field tuples give different identifiers)
// for ALL inputs, with no NUL precondition. The shipped layout does not satisfy it
// (BUG-06, High, open). The lemma is left failing, not weakened, not assumed, and not
// commented out. Section 8 also proves, as ordinary lemmas, the concrete collisions
// that make the claim false (and not merely unproved).
//
// -----------------------------------------------------------------------------
// WHAT IS MODELED (repo esdk-native-mpl, branch MPL-Verus, HEAD 4964d66)
//
//   mpl/src/aws_kms/cache_entry_identifier.rs
//     :18      RESOURCE_ID_HIERARCHICAL_KEYRING = 0x02
//     :20      NULL_BYTE = 0x00
//     :35-66   build_cache_identifier; preimage built at :42-60; SHA-384 at :62-64
//   mpl/src/aws_kms/hierarchical_keyring.rs
//     :596     partition id = caller string `.into_bytes()`
//     :626-640 generate_partition_id (16 bytes of a random v4 UUID; may contain 0x00)
//     :600-605 logical key store name = get_key_store_info().logical_key_store_name,
//              used as returned
//     :831-855 resolve_branch_key_id (configured id, or supplier output; not checked)
//     :644     uuid_16_bytes_to_str: version = hyphenated UUID text
//     :665-671 OnEncrypt call: SCOPE_ID_ENCRYPT, version None
//     :908-914 OnDecrypt call: SCOPE_ID_DECRYPT, version Some
//     :821, :825  SCOPE_ID_ENCRYPT = 0x01, SCOPE_ID_DECRYPT = 0x02
//
// CORRESPONDENCE TABLE (model item  <->  shipped code)
//
//   model                       code
//   --------------------------  ---------------------------------------------------
//   Bytes = Seq<u8>             &[u8], and &str via as_bytes() (UTF-8 bytes)
//   z()                         [NULL_BYTE]                      (:20, :44, :46, :50, :53, :58)
//   head(scope)                 [RESOURCE_ID.., NULL, scope, NULL]   (:42-47)
//   Fields.partition            partition_id: &[u8]
//   Fields.name                 logical_key_store_name.as_bytes()
//   Fields.branch_key_id        branch_key_id.as_bytes()
//   Fields.version              branch_key_version: Option<&str>, as_bytes()
//   opt_tail(Some(v))           push(NULL_BYTE); extend(v)       (:57-60)
//   preimage(t)                 the Vec<u8> `buf` after :60
//   identifier(h, t)            digest(Sha384, &buf, ..), with h standing for SHA-384
//   well_formed(t)              the two call shapes (:665, :908), see H_SCOPE_PAIRING
//
// -----------------------------------------------------------------------------
// HYPOTHESES AND EVIDENCE LEVELS
//
//   Evidence levels used in this file:
//     PROVED        machine-checked by Verus in this file, relative to the model and
//                   to the hypotheses below
//     ASSUMED       taken as a premise; not proved here (A_*)
//     CODE READING  a claim about the shipped code that Verus does not see (H_*);
//                   checked by a human reading the code at the lines named
//
//   H_MODEL_MATCH (CODE READING). `preimage` is the byte string the shipped code
//     passes to the digest: four fixed bytes, then the fields separated by single 0x00
//     bytes, with the version appended after one more 0x00 only when it is present.
//     Checked against :42-60 line by line. Not machine-checked.
//   H_BYTES (CODE READING). Fields are modeled as arbitrary byte sequences. A Rust
//     `&str` field is its UTF-8 bytes. UTF-8 validity is not modeled. UTF-8 encodes
//     U+0000 as the single byte 0x00 and never uses 0x00 for another character, so for a
//     `&str` "contains a 0x00 byte" and "contains U+0000" are the same. Consequence for
//     the only-if direction (section 5): the colliding partner it builds is a tuple of
//     byte fields. When the NUL is in the partition id (raw bytes), the partner's logical
//     name receives the tail after the NUL, and that tail must be valid UTF-8 for the
//     partner to exist in the shipped types. The concrete BUG-06 examples are ASCII, so
//     they exist. The proof does not decide whether every NUL-bearing configuration has a
//     realizable partner (for example a random 16-byte partition id whose tail is not
//     valid UTF-8).
//   H_SCOPE_PAIRING (CODE READING). The encrypt scope (0x01) is always called with
//     version None (:665-671) and the decrypt scope (0x02) always with Some(version)
//     (:908-914). `well_formed` encodes this. The if-direction against an arbitrary
//     partner (`lemma_if_direction_wf`) needs it: without it a NUL-free decrypt tuple
//     (id, Some(v)) has the same preimage as an encrypt tuple with id' = id 0x00 v
//     and version None, if both used the same scope byte. The scope byte is in the
//     preimage, so the pairing is what separates them. The both-NUL-free injectivity
//     (`lemma_nul_free_injective`) does not need the pairing.
//   H_VERSION_NO_NUL (CODE READING). The decrypt version string is
//     `Uuid::hyphenated().to_string()` of the 16 ciphertext bytes (:644, :886): 36
//     characters of lowercase hex digits and '-'. It cannot contain 0x00. Used only in
//     the "realistic" form of the theorem (`theorem_t13_iff_realistic`), where the
//     version field is excluded from the NUL-free requirement. The general theorem
//     (`theorem_t13_iff`) does not use it and treats the version like the other fields.
//   H_NO_DIGEST_ERROR (CODE READING). The `.expect` at :64 cannot fail because the
//     output buffer is exactly 48 bytes. Panic-freedom is not proved here (see T16).
//   A_DIGEST_CR (ASSUMED). SHA-384 is modeled as an arbitrary function `h` from byte
//     sequences to byte sequences, and `cr(h)` says `h` is injective. Real SHA-384 is
//     not injective (it maps unbounded inputs to 48 bytes); the assumption stands for
//     "no one can find two different preimages with the same digest" (computational
//     collision resistance), idealized. Every lemma that needs it takes `cr(h)` as an
//     explicit `requires`. The collision direction (equal preimages give equal
//     identifiers) holds for EVERY `h` and needs no assumption.
//   H_LEN_FITS (ASSUMED, fix only). For the length-prefixed encoding of section 9, every
//     field is shorter than 2^32 bytes. A real fix must check this (for example
//     `u32::try_from(len)`) and fail otherwise.
//
//   No `assume`, `admit`, `external_body`, `assume_specification` or uninterpreted
//   spec function is used. The trusted base is Verus, Z3 and the vstd Seq axioms, plus
//   the A_* and H_* items above.
//
// -----------------------------------------------------------------------------
// RESULTS (what the proofs establish; PROVED relative to the model and hypotheses)
//
//   R1  lemma_nul_free_injective   both tuples NUL-free  =>  equal preimages imply equal tuples.
//   R2  lemma_if_direction_wf      a NUL-free, b ANY well-formed tuple (NUL or not):
//                                  equal preimages imply a == b.
//   R3  lemma_partner_*            a has a 0x00 in some field  =>  there is a different
//                                  tuple with the same scope and shape and the SAME preimage.
//   R4  theorem_t13_iff            for a well-formed tuple a: "no other well-formed tuple
//                                  has a's preimage" <==> "every field of a is NUL-free".
//       theorem_t13_iff_identifier same, for identifiers, under A_DIGEST_CR (the only-if
//                                  half needs no assumption).
//       theorem_t13_iff_realistic  same with the version excluded (H_VERSION_NO_NUL): the
//                                  condition is that partition id, logical key store name
//                                  and branch key id are NUL-free.
//   R5  lemma_bug06_*              the BUG-06 collisions (encrypt and decrypt scope) as
//                                  proved facts, and the expected-FAIL obligation.
//   R6  lemma_nul_free_precondition_gives_identifier_injectivity
//                                  the NUL-free precondition (fix option 1) gives
//                                  injective identifiers under A_DIGEST_CR.
//   R7  lemma_lp_*, theorem_lp_*   a length-prefixed encoding (fix option 2) is injective
//                                  for ALL inputs, with no NUL precondition, under
//                                  A_DIGEST_CR and H_LEN_FITS; the BUG-06 pairs separate.
//   R8  lemma_scope_separation     encrypt and decrypt identifiers never coincide.
//       lemma_pairing_is_needed    H_SCOPE_PAIRING is load-bearing: with one scope byte, a
//                                  NUL-free decrypt-shaped tuple collides with an
//                                  encrypt-shaped tuple (id 0x00 v, no version).
//
// NOT COVERED
//   * Any other function. Cache hit/miss logic, TTL, storm tracking, and
//     `HierarchicalKeyringBuilder::build` are not modeled.
//   * That the colliding keyrings can be configured in a deployment (BUG-06 states the
//     preconditions: a Shared cache and attacker-influenced NUL-bearing configuration).
//   * Spec text. The layout is modeled as shipped; it equals the layout the spec mandates
//     (aws-kms-hierarchical-keyring.md, Appendix A), so the defect is in the spec too.
// =============================================================================

use vstd::prelude::*;

verus! {

// ============================================================
// SECTION 1: Model of build_cache_identifier
// ============================================================

pub type Bytes = Seq<u8>;

/// [NULL_BYTE], the single separator (cache_entry_identifier.rs :20).
pub open spec fn z() -> Bytes { seq![0u8] }

/// The call-site scope bytes (hierarchical_keyring.rs :821, :825).
pub open spec fn scope_encrypt() -> u8 { 0x01u8 }
pub open spec fn scope_decrypt() -> u8 { 0x02u8 }

/// The inputs of build_cache_identifier. `version: None` is the encrypt shape.
pub struct Fields {
    pub scope: u8,
    pub partition: Bytes,
    pub name: Bytes,
    pub branch_key_id: Bytes,
    pub version: Option<Bytes>,
}

/// vec![RESOURCE_ID_HIERARCHICAL_KEYRING, NULL_BYTE, scope_id, NULL_BYTE]  (:42-47).
/// RESOURCE_ID_HIERARCHICAL_KEYRING = 0x02 (:18).
pub open spec fn head(scope: u8) -> Bytes { seq![0x02u8, 0x00u8, scope, 0x00u8] }

/// `if let Some(version) = branch_key_version { push(NULL_BYTE); extend(version) }`  (:57-60).
pub open spec fn opt_tail(v: Option<Bytes>) -> Bytes {
    match v {
        Some(x) => z() + x,
        None => Seq::empty(),
    }
}

/// The preimage, in the order the code appends to `buf` (:42-60).
pub open spec fn preimage(t: Fields) -> Bytes {
    head(t.scope) + t.partition + z() + t.name + z() + t.branch_key_id + opt_tail(t.version)
}

/// Everything after the four head bytes, right-nested (concatenation is associative; this
/// form is easier for the proofs). `lemma_preimage_is_head_body` ties it to `preimage`.
pub open spec fn body(t: Fields) -> Bytes {
    t.partition + (z() + (t.name + (z() + (t.branch_key_id + opt_tail(t.version)))))
}

/// SHA-384 idealized as a function h (A_DIGEST_CR); the identifier is h(preimage).
pub open spec fn identifier(h: spec_fn(Bytes) -> Bytes, t: Fields) -> Bytes {
    h(preimage(t))
}

/// A_DIGEST_CR: h is injective (idealized collision resistance).
pub open spec fn cr(h: spec_fn(Bytes) -> Bytes) -> bool {
    forall|x: Bytes, y: Bytes| #![trigger h(x), h(y)] h(x) == h(y) ==> x == y
}

/// H_SCOPE_PAIRING: encrypt scope with no version, decrypt scope with a version.
pub open spec fn well_formed(t: Fields) -> bool {
    (t.scope == scope_encrypt() && t.version is None)
    || (t.scope == scope_decrypt() && t.version is Some)
}

/// No 0x00 byte in s.
pub open spec fn nul_free(s: Bytes) -> bool {
    forall|i: int| 0 <= i < s.len() ==> #[trigger] s[i] != 0u8
}

/// The three fields the keyring feeds in: partition id, logical key store name, branch key id.
pub open spec fn nul_free_core(t: Fields) -> bool {
    nul_free(t.partition) && nul_free(t.name) && nul_free(t.branch_key_id)
}

pub open spec fn version_nul_free(t: Fields) -> bool {
    match t.version {
        Some(v) => nul_free(v),
        None => true,
    }
}

/// "The input fields are NUL-free" (the T13 precondition): all four fields.
pub open spec fn fields_nul_free(t: Fields) -> bool {
    nul_free_core(t) && version_nul_free(t)
}

/// Number of 0x00 bytes in s.
pub open spec fn nz(s: Bytes) -> nat
    decreases s.len(),
{
    if s.len() == 0 {
        0
    } else {
        nz(s.drop_last()) + (if s.last() == 0u8 { 1nat } else { 0nat })
    }
}

pub open spec fn nz_opt(v: Option<Bytes>) -> nat {
    match v {
        Some(x) => 1 + nz(x),
        None => 0,
    }
}

// ============================================================
// SECTION 2: Helper lemmas (concatenation, zero counting, splitting)
// ============================================================

proof fn lemma_preimage_is_head_body(t: Fields)
    ensures
        preimage(t) =~= head(t.scope) + body(t),
{
}

/// Equal head+X and head+Y (heads built from scopes s1, s2) give equal scopes and equal tails.
proof fn lemma_strip_head(s1: u8, x: Bytes, s2: u8, y: Bytes)
    requires
        head(s1) + x == head(s2) + y,
    ensures
        s1 == s2,
        x == y,
{
    let l = head(s1) + x;
    let r = head(s2) + y;
    assert(l.len() == 4 + x.len());
    assert(r.len() == 4 + y.len());
    assert(l[2] == s1);
    assert(r[2] == s2);
    assert forall|i: int| 0 <= i < x.len() implies x[i] == y[i] by {
        assert(l[4 + i] == x[i]);
        assert(r[4 + i] == y[i]);
    }
    assert(x.len() == y.len());
    assert(x =~= y);
}

proof fn lemma_nz_add(a: Bytes, b: Bytes)
    ensures
        nz(a + b) == nz(a) + nz(b),
    decreases b.len(),
{
    if b.len() == 0 {
        assert(a + b =~= a);
    } else {
        let c = b.drop_last();
        assert((a + b).drop_last() =~= a + c);
        assert((a + b).last() == b.last());
        lemma_nz_add(a, c);
    }
}

proof fn lemma_nz_z()
    ensures
        nz(z()) == 1,
{
    assert(z().len() == 1);
    assert(z().last() == 0u8);
    assert(z().drop_last() =~= Seq::<u8>::empty());
    assert(nz(Seq::<u8>::empty()) == 0);
}

/// nz(s) == 0 exactly when s is NUL-free.
proof fn lemma_nz_zero_iff(s: Bytes)
    ensures
        nz(s) == 0 <==> nul_free(s),
    decreases s.len(),
{
    if s.len() > 0 {
        let c = s.drop_last();
        lemma_nz_zero_iff(c);
        if nz(s) == 0 {
            assert(nz(c) == 0);
            assert(s.last() != 0u8);
            assert forall|i: int| 0 <= i < s.len() implies #[trigger] s[i] != 0u8 by {
                if i < c.len() {
                    assert(c[i] == s[i]);
                }
            }
        }
        if nul_free(s) {
            assert(s[s.len() - 1] != 0u8);
            assert forall|i: int| 0 <= i < c.len() implies #[trigger] c[i] != 0u8 by {
                assert(c[i] == s[i]);
            }
            assert(nz(c) == 0);
        }
    }
}

/// A NUL-bearing sequence has a NUL at some index.
proof fn lemma_nul_index(s: Bytes) -> (i: int)
    requires
        !nul_free(s),
    ensures
        0 <= i < s.len(),
        s[i] == 0u8,
{
    choose|i: int| 0 <= i < s.len() && s[i] == 0u8
}

/// A sequence with a NUL at index i is p1 + [0] + p2 with p1 = prefix, p2 = suffix.
proof fn lemma_split_at_nul(s: Bytes, i: int)
    requires
        0 <= i < s.len(),
        s[i] == 0u8,
    ensures
        s =~= s.take(i) + z() + s.skip(i + 1),
{
}

/// A single 0x00 separates two fields uniquely when the first field is NUL-free in
/// both decompositions.
proof fn lemma_split_unique(x: Bytes, y: Bytes, x2: Bytes, y2: Bytes)
    requires
        nul_free(x),
        nul_free(x2),
        x + z() + y == x2 + z() + y2,
    ensures
        x == x2,
        y == y2,
{
    let s = x + z() + y;
    let s2 = x2 + z() + y2;
    assert(s.len() == x.len() + 1 + y.len());
    assert(s2.len() == x2.len() + 1 + y2.len());
    assert(s[x.len() as int] == 0u8);
    assert(s2[x2.len() as int] == 0u8);
    if x.len() < x2.len() {
        assert(s2[x.len() as int] == x2[x.len() as int]);
        assert(x2[x.len() as int] != 0u8);
    }
    if x2.len() < x.len() {
        assert(s[x2.len() as int] == x[x2.len() as int]);
        assert(x[x2.len() as int] != 0u8);
    }
    assert(x.len() == x2.len());
    assert forall|i: int| 0 <= i < x.len() implies x[i] == x2[i] by {
        assert(s[i] == x[i]);
        assert(s2[i] == x2[i]);
    }
    assert(x =~= x2);
    assert(y.len() == y2.len());
    assert forall|j: int| 0 <= j < y.len() implies y[j] == y2[j] by {
        assert(s[x.len() + 1 + j] == y[j]);
        assert(s2[x2.len() + 1 + j] == y2[j]);
    }
    assert(y =~= y2);
}

/// Zero count of the body: the fields' zeros plus the separators (2, or 3 with a version).
proof fn lemma_nz_body(t: Fields)
    ensures
        nz(body(t)) == nz(t.partition) + nz(t.name) + nz(t.branch_key_id) + nz_opt(t.version) + 2,
{
    lemma_nz_z();
    let tail = t.branch_key_id + opt_tail(t.version);
    lemma_nz_add(t.branch_key_id, opt_tail(t.version));
    match t.version {
        Some(v) => {
            lemma_nz_add(z(), v);
        },
        None => {
            assert(opt_tail(t.version) =~= Seq::<u8>::empty());
        },
    }
    lemma_nz_add(z(), tail);
    lemma_nz_add(t.name, z() + tail);
    lemma_nz_add(z(), t.name + (z() + tail));
    lemma_nz_add(t.partition, z() + (t.name + (z() + tail)));
    assert(nz(Seq::<u8>::empty()) == 0);
}

// ============================================================
// SECTION 3: Decoding the NUL-separated body (both sides NUL-free)
// ============================================================

/// If the preimages are equal, the scopes are equal and the bodies are equal.
proof fn lemma_equal_preimage_body(a: Fields, b: Fields)
    requires
        preimage(a) == preimage(b),
    ensures
        a.scope == b.scope,
        body(a) == body(b),
{
    lemma_preimage_is_head_body(a);
    lemma_preimage_is_head_body(b);
    lemma_strip_head(a.scope, body(a), b.scope, body(b));
}

/// Core decoding step: same shape, both NUL-free, equal bodies  =>  equal tuples.
proof fn lemma_decode_same_shape(a: Fields, b: Fields)
    requires
        fields_nul_free(a),
        fields_nul_free(b),
        a.version is Some == b.version is Some,
        body(a) == body(b),
        a.scope == b.scope,
    ensures
        a == b,
{
    // body = partition + z + (name + z + (id + opt))
    let ra = a.name + (z() + (a.branch_key_id + opt_tail(a.version)));
    let rb = b.name + (z() + (b.branch_key_id + opt_tail(b.version)));
    assert(a.partition + z() + ra =~= body(a));
    assert(b.partition + z() + rb =~= body(b));
    lemma_split_unique(a.partition, ra, b.partition, rb);
    let sa = a.branch_key_id + opt_tail(a.version);
    let sb = b.branch_key_id + opt_tail(b.version);
    assert(a.name + z() + sa =~= ra);
    assert(b.name + z() + sb =~= rb);
    lemma_split_unique(a.name, sa, b.name, sb);
    match (a.version, b.version) {
        (Some(va), Some(vb)) => {
            assert(a.branch_key_id + z() + va =~= sa);
            assert(b.branch_key_id + z() + vb =~= sb);
            lemma_split_unique(a.branch_key_id, va, b.branch_key_id, vb);
        },
        (None, None) => {
            assert(sa =~= a.branch_key_id);
            assert(sb =~= b.branch_key_id);
        },
        _ => {},
    }
}

// ============================================================
// SECTION 4: If-direction. NUL-free fields give injectivity.
// ============================================================

/// R1. Two NUL-free tuples with equal preimages are equal. No pairing hypothesis: the
/// zero count (2 or 3) fixes whether a version is present.
proof fn lemma_nul_free_injective(a: Fields, b: Fields)
    requires
        fields_nul_free(a),
        fields_nul_free(b),
        preimage(a) == preimage(b),
    ensures
        a == b,
{
    lemma_equal_preimage_body(a, a);
    lemma_equal_preimage_body(a, b);
    lemma_nz_body(a);
    lemma_nz_body(b);
    lemma_nz_zero_iff(a.partition);
    lemma_nz_zero_iff(a.name);
    lemma_nz_zero_iff(a.branch_key_id);
    lemma_nz_zero_iff(b.partition);
    lemma_nz_zero_iff(b.name);
    lemma_nz_zero_iff(b.branch_key_id);
    if let Some(v) = a.version {
        lemma_nz_zero_iff(v);
    }
    if let Some(v) = b.version {
        lemma_nz_zero_iff(v);
    }
    lemma_decode_same_shape(a, b);
}

/// R2. A NUL-free well-formed tuple a has the same preimage as NO other well-formed tuple,
/// including tuples whose fields contain 0x00. Equal preimages give equal zero counts; a has
/// none in its fields, so b has none either, and R1-style decoding applies.
proof fn lemma_if_direction_wf(a: Fields, b: Fields)
    requires
        well_formed(a),
        well_formed(b),
        fields_nul_free(a),
        preimage(a) == preimage(b),
    ensures
        a == b,
{
    lemma_equal_preimage_body(a, b);
    lemma_nz_body(a);
    lemma_nz_body(b);
    lemma_nz_zero_iff(a.partition);
    lemma_nz_zero_iff(a.name);
    lemma_nz_zero_iff(a.branch_key_id);
    if let Some(v) = a.version {
        lemma_nz_zero_iff(v);
    }
    // same scope, so same shape under H_SCOPE_PAIRING; the zero counts then force b NUL-free
    assert(a.version is Some == b.version is Some);
    match b.version {
        Some(v) => {
            lemma_nz_zero_iff(v);
        },
        None => {},
    }
    lemma_nz_zero_iff(b.partition);
    lemma_nz_zero_iff(b.name);
    lemma_nz_zero_iff(b.branch_key_id);
    lemma_decode_same_shape(a, b);
}

// ============================================================
// SECTION 5: Only-if direction. A 0x00 in any field gives a collision.
// ============================================================

/// 0x00 inside the partition id: move the tail after the NUL into the front of the logical name.
///   (p1 0 p2, n, id)  and  (p1, p2 0 n, id)  have the same preimage.
proof fn lemma_partner_partition(a: Fields) -> (b: Fields)
    requires
        !nul_free(a.partition),
    ensures
        b != a,
        preimage(b) == preimage(a),
        b.scope == a.scope,
        b.version == a.version,
{
    let i = lemma_nul_index(a.partition);
    lemma_split_at_nul(a.partition, i);
    let p1 = a.partition.take(i);
    let p2 = a.partition.skip(i + 1);
    let b = Fields {
        scope: a.scope,
        partition: p1,
        name: p2 + z() + a.name,
        branch_key_id: a.branch_key_id,
        version: a.version,
    };
    assert(b.partition.len() < a.partition.len());
    assert(b != a);
    let q = z() + (a.name + (z() + (a.branch_key_id + opt_tail(a.version))));
    // body(a) = (p1 0 p2) + (0 n 0 rest)  and  body(b) = p1 + (0 + ((p2 0 n) + (0 rest)))
    assert(a.partition + q =~= p1 + (z() + (p2 + q))) by {
        assert(a.partition =~= p1 + z() + p2);
    }
    assert(body(a) == a.partition + q);
    assert((p2 + z() + a.name) + (z() + (a.branch_key_id + opt_tail(a.version))) =~= p2 + q);
    assert(body(b) =~= p1 + (z() + (p2 + q)));
    lemma_preimage_is_head_body(a);
    lemma_preimage_is_head_body(b);
    b
}

/// 0x00 inside the logical name: move the front of the name into the partition id.
///   (p, n1 0 n2, id)  and  (p 0 n1, n2, id).
proof fn lemma_partner_name(a: Fields) -> (b: Fields)
    requires
        !nul_free(a.name),
    ensures
        b != a,
        preimage(b) == preimage(a),
        b.scope == a.scope,
        b.version == a.version,
{
    let i = lemma_nul_index(a.name);
    lemma_split_at_nul(a.name, i);
    let n1 = a.name.take(i);
    let n2 = a.name.skip(i + 1);
    let b = Fields {
        scope: a.scope,
        partition: a.partition + z() + n1,
        name: n2,
        branch_key_id: a.branch_key_id,
        version: a.version,
    };
    assert(b.partition.len() > a.partition.len());
    assert(b != a);
    assert(body(b) =~= body(a));
    lemma_preimage_is_head_body(a);
    lemma_preimage_is_head_body(b);
    b
}

/// 0x00 inside the branch key id: move the front of the id into the logical name.
///   (p, n, i1 0 i2, v)  and  (p, n 0 i1, i2, v). The version is unchanged.
proof fn lemma_partner_id(a: Fields) -> (b: Fields)
    requires
        !nul_free(a.branch_key_id),
    ensures
        b != a,
        preimage(b) == preimage(a),
        b.scope == a.scope,
        b.version == a.version,
{
    let i = lemma_nul_index(a.branch_key_id);
    lemma_split_at_nul(a.branch_key_id, i);
    let i1 = a.branch_key_id.take(i);
    let i2 = a.branch_key_id.skip(i + 1);
    let b = Fields {
        scope: a.scope,
        partition: a.partition,
        name: a.name + z() + i1,
        branch_key_id: i2,
        version: a.version,
    };
    assert(b.name.len() > a.name.len());
    assert(b != a);
    assert(body(b) =~= body(a));
    lemma_preimage_is_head_body(a);
    lemma_preimage_is_head_body(b);
    b
}

/// 0x00 inside the version: move the front of the version into the branch key id.
///   (p, n, id, Some(v1 0 v2))  and  (p, n, id 0 v1, Some(v2)).
proof fn lemma_partner_version(a: Fields) -> (b: Fields)
    requires
        !version_nul_free(a),
    ensures
        b != a,
        preimage(b) == preimage(a),
        b.scope == a.scope,
        b.version is Some,
{
    let v = a.version->Some_0;
    let i = lemma_nul_index(v);
    lemma_split_at_nul(v, i);
    let v1 = v.take(i);
    let v2 = v.skip(i + 1);
    let b = Fields {
        scope: a.scope,
        partition: a.partition,
        name: a.name,
        branch_key_id: a.branch_key_id + z() + v1,
        version: Some(v2),
    };
    assert(b.branch_key_id.len() > a.branch_key_id.len());
    assert(b != a);
    assert(body(b) =~= body(a));
    lemma_preimage_is_head_body(a);
    lemma_preimage_is_head_body(b);
    b
}

/// R3. If a field of a contains 0x00, a different tuple of the same scope and shape has the
/// same preimage.
proof fn lemma_partner_any(a: Fields) -> (b: Fields)
    requires
        !fields_nul_free(a),
    ensures
        b != a,
        preimage(b) == preimage(a),
        b.scope == a.scope,
        b.version is Some == a.version is Some,
{
    if !nul_free(a.partition) {
        lemma_partner_partition(a)
    } else if !nul_free(a.name) {
        lemma_partner_name(a)
    } else if !nul_free(a.branch_key_id) {
        lemma_partner_id(a)
    } else {
        lemma_partner_version(a)
    }
}

/// R3 for the three keyring-fed fields: the partner keeps the version, so it stays realistic.
proof fn lemma_partner_core(a: Fields) -> (b: Fields)
    requires
        !nul_free_core(a),
    ensures
        b != a,
        preimage(b) == preimage(a),
        b.scope == a.scope,
        b.version == a.version,
{
    if !nul_free(a.partition) {
        lemma_partner_partition(a)
    } else if !nul_free(a.name) {
        lemma_partner_name(a)
    } else {
        lemma_partner_id(a)
    }
}

// ============================================================
// SECTION 6: The iff theorem
// ============================================================

/// No other well-formed tuple has the same preimage.
pub open spec fn unambiguous(a: Fields) -> bool {
    forall|b: Fields| #![trigger preimage(b)]
        well_formed(b) && preimage(b) == preimage(a) ==> b == a
}

/// Realistic tuples: well-formed and a NUL-free version (H_SCOPE_PAIRING, H_VERSION_NO_NUL).
pub open spec fn realistic(t: Fields) -> bool {
    well_formed(t) && version_nul_free(t)
}

pub open spec fn unambiguous_realistic(a: Fields) -> bool {
    forall|b: Fields| #![trigger preimage(b)]
        realistic(b) && preimage(b) == preimage(a) ==> b == a
}

/// R4 (preimage level). For a well-formed tuple a:
///   no other well-formed tuple has a's preimage   <==>   every field of a is NUL-free.
proof fn theorem_t13_iff(a: Fields)
    requires
        well_formed(a),
    ensures
        unambiguous(a) <==> fields_nul_free(a),
{
    if fields_nul_free(a) {
        assert forall|b: Fields| well_formed(b) && preimage(b) == preimage(a) implies b == a by {
            lemma_if_direction_wf(a, b);
        }
    } else {
        let b = lemma_partner_any(a);
        assert(well_formed(b));
        assert(preimage(b) == preimage(a));
        assert(b != a);
        assert(!unambiguous(a));
    }
}

/// R4 (realistic form, H_VERSION_NO_NUL). For a realistic tuple a:
///   no other realistic tuple has a's preimage   <==>   partition id, logical key store
///   name and branch key id of a are NUL-free.
proof fn theorem_t13_iff_realistic(a: Fields)
    requires
        realistic(a),
    ensures
        unambiguous_realistic(a) <==> nul_free_core(a),
{
    if nul_free_core(a) {
        assert(fields_nul_free(a));
        assert forall|b: Fields| realistic(b) && preimage(b) == preimage(a) implies b == a by {
            lemma_if_direction_wf(a, b);
        }
    } else {
        let b = lemma_partner_core(a);
        assert(realistic(b));
        assert(preimage(b) == preimage(a));
        assert(b != a);
        assert(!unambiguous_realistic(a));
    }
}

/// H_SCOPE_PAIRING is load-bearing for R2. With the same scope byte, a decrypt-shaped tuple
/// (id, Some(v)) and the encrypt-shaped tuple (id 0x00 v, None) have the same preimage even
/// when every field of the first is NUL-free. The shipped call sites never build the pair
/// (decrypt always has a version, encrypt never has one), and the scope byte differs there.
proof fn lemma_pairing_is_needed(a: Fields)
    requires
        a.version is Some,
        fields_nul_free(a),
    ensures
        ({
            let v = a.version->Some_0;
            let b = Fields {
                scope: a.scope,
                partition: a.partition,
                name: a.name,
                branch_key_id: a.branch_key_id + z() + v,
                version: None,
            };
            &&& b != a
            &&& preimage(b) == preimage(a)
            &&& !well_formed(b) || !well_formed(a)
        }),
{
    let v = a.version->Some_0;
    let b = Fields {
        scope: a.scope,
        partition: a.partition,
        name: a.name,
        branch_key_id: a.branch_key_id + z() + v,
        version: None,
    };
    assert(b != a);
    assert(body(b) =~= body(a));
    lemma_preimage_is_head_body(a);
    lemma_preimage_is_head_body(b);
    // a.version is Some and b.version is None with one scope byte: at most one is well-formed
}

// ============================================================
// SECTION 7: Identifier level (SHA-384 idealized, A_DIGEST_CR)
// ============================================================

/// Equal preimages give equal identifiers for EVERY h. No assumption (the collision direction).
proof fn lemma_collision_passes_through_digest(h: spec_fn(Bytes) -> Bytes, a: Fields, b: Fields)
    requires
        preimage(a) == preimage(b),
    ensures
        identifier(h, a) == identifier(h, b),
{
}

/// With A_DIGEST_CR, equal identifiers give equal preimages.
proof fn lemma_identifier_equal_gives_preimage_equal(h: spec_fn(Bytes) -> Bytes, a: Fields, b: Fields)
    requires
        cr(h),
        identifier(h, a) == identifier(h, b),
    ensures
        preimage(a) == preimage(b),
{
}

/// No other well-formed tuple has the same identifier.
pub open spec fn unambiguous_id(h: spec_fn(Bytes) -> Bytes, a: Fields) -> bool {
    forall|b: Fields| #![trigger identifier(h, b)]
        well_formed(b) && identifier(h, b) == identifier(h, a) ==> b == a
}

/// R6 (d). The NUL-free precondition gives injective identifiers (fix option 1: reject
/// 0x00 in the partition id, logical key store name and branch key id; the version is
/// NUL-free by H_VERSION_NO_NUL). Under A_DIGEST_CR.
proof fn lemma_nul_free_precondition_gives_identifier_injectivity(
    h: spec_fn(Bytes) -> Bytes,
    a: Fields,
    b: Fields,
)
    requires
        cr(h),
        fields_nul_free(a),
        fields_nul_free(b),
        identifier(h, a) == identifier(h, b),
    ensures
        a == b,
{
    lemma_identifier_equal_gives_preimage_equal(h, a, b);
    lemma_nul_free_injective(a, b);
}

/// R4 (identifier level). The only-if half holds for every h; the if half uses A_DIGEST_CR.
proof fn theorem_t13_iff_identifier(h: spec_fn(Bytes) -> Bytes, a: Fields)
    requires
        cr(h),
        well_formed(a),
    ensures
        unambiguous_id(h, a) <==> fields_nul_free(a),
{
    if fields_nul_free(a) {
        assert forall|b: Fields| well_formed(b) && identifier(h, b) == identifier(h, a) implies b == a by {
            lemma_identifier_equal_gives_preimage_equal(h, b, a);
            lemma_if_direction_wf(a, b);
        }
    } else {
        let b = lemma_partner_any(a);
        lemma_collision_passes_through_digest(h, b, a);
        assert(well_formed(b));
        assert(b != a);
        assert(!unambiguous_id(h, a));
    }
}

// ============================================================
// SECTION 8: BUG-06 counterexample and the EXPECTED-FAIL obligation
// ============================================================

/// ASCII helpers for the witnesses: "tenant", "x", "L", "bk", "v" (byte values).
pub open spec fn s_tenant() -> Bytes { seq![116u8, 101u8, 110u8, 97u8, 110u8, 116u8] }
pub open spec fn s_x() -> Bytes { seq![120u8] }
pub open spec fn s_l() -> Bytes { seq![76u8] }
pub open spec fn s_bk() -> Bytes { seq![98u8, 107u8] }
pub open spec fn s_v() -> Bytes { seq![118u8] }

/// Encrypt scope, from the bug report: partition "tenant\0x", name "L", id "bk".
pub open spec fn bug06_enc_a() -> Fields {
    Fields {
        scope: 0x01u8,
        partition: s_tenant() + z() + s_x(),
        name: s_l(),
        branch_key_id: s_bk(),
        version: None,
    }
}

/// Encrypt scope: partition "tenant", name "x\0L", id "bk".
pub open spec fn bug06_enc_b() -> Fields {
    Fields {
        scope: 0x01u8,
        partition: s_tenant(),
        name: s_x() + z() + s_l(),
        branch_key_id: s_bk(),
        version: None,
    }
}

/// Decrypt scope: partition "tenant", name "L", id "bk\0x", version "v".
pub open spec fn bug06_dec_a() -> Fields {
    Fields {
        scope: 0x02u8,
        partition: s_tenant(),
        name: s_l(),
        branch_key_id: s_bk() + z() + s_x(),
        version: Some(s_v()),
    }
}

/// Decrypt scope: partition "tenant", name "L\0bk", id "x", version "v".
pub open spec fn bug06_dec_b() -> Fields {
    Fields {
        scope: 0x02u8,
        partition: s_tenant(),
        name: s_l() + z() + s_bk(),
        branch_key_id: s_x(),
        version: Some(s_v()),
    }
}

/// The BUG-06 witnesses are valid call shapes, differ as tuples, and have the SAME preimage
/// (hence the same identifier for every digest function h).
proof fn lemma_bug06_witness_collides()
    ensures
        well_formed(bug06_enc_a()),
        well_formed(bug06_enc_b()),
        bug06_enc_a() != bug06_enc_b(),
        preimage(bug06_enc_a()) == preimage(bug06_enc_b()),
        well_formed(bug06_dec_a()),
        well_formed(bug06_dec_b()),
        bug06_dec_a() != bug06_dec_b(),
        preimage(bug06_dec_a()) == preimage(bug06_dec_b()),
        forall|h: spec_fn(Bytes) -> Bytes|
            identifier(h, bug06_enc_a()) == identifier(h, bug06_enc_b())
            && identifier(h, bug06_dec_a()) == identifier(h, bug06_dec_b()),
{
    assert(bug06_enc_a().partition.len() == 8);
    assert(bug06_enc_b().partition.len() == 6);
    assert(preimage(bug06_enc_a()) =~= preimage(bug06_enc_b()));
    assert(bug06_dec_a().name.len() == 1);
    assert(bug06_dec_b().name.len() == 4);
    assert(preimage(bug06_dec_a()) =~= preimage(bug06_dec_b()));
}

/// The witnesses are tuples with a NUL: consistent with the iff theorem.
proof fn lemma_bug06_witnesses_are_not_nul_free()
    ensures
        !fields_nul_free(bug06_enc_a()),
        !fields_nul_free(bug06_enc_b()),
        !fields_nul_free(bug06_dec_a()),
        !fields_nul_free(bug06_dec_b()),
{
    assert(bug06_enc_a().partition[6] == 0u8);
    assert(bug06_enc_b().name[1] == 0u8);
    assert(bug06_dec_a().branch_key_id[2] == 0u8);
    assert(bug06_dec_b().name[1] == 0u8);
}

/// The identity function is a collision-resistant h in the model's sense (A_DIGEST_CR is
/// satisfiable), so the requires of the expected-FAIL lemma below are not vacuous.
proof fn lemma_cr_is_satisfiable()
    ensures
        cr(|x: Bytes| x),
{
}

/// EXPECTED-FAIL OBLIGATION (BUG-06): the spec-faithful property.
///
/// spec/framework/aws-kms/aws-kms-hierarchical-keyring.md, "Partition ID" and "Shared Cache
/// Considerations": keyrings that differ in partition id, logical key store name or branch
/// key id CANNOT share a cache entry. As a property of the identifier this is: two valid call
/// shapes with the same identifier are the same tuple. This is stated for ALL inputs, with no
/// NUL precondition.
///
/// EXPECTED TO FAIL. Verus reports "postcondition not satisfied". The shipped preimage is not
/// injective when a field contains 0x00; `lemma_bug06_witness_collides` proves the concrete
/// pairs, and `lemma_bug06_failing_claim_is_false` shows this statement is false (not just
/// unproved) for the digest h = identity. The obligation is deliberately NOT weakened, NOT
/// assumed, and NOT commented out. It is the FINDING BUG-06. It becomes provable only with a
/// NUL-free precondition (`lemma_nul_free_precondition_gives_identifier_injectivity`) or a
/// different encoding (`lemma_lp_identifier_injective`).
proof fn lemma_bug06_injectivity_without_nul_precondition_EXPECTED_FAIL(
    h: spec_fn(Bytes) -> Bytes,
    a: Fields,
    b: Fields,
)
    requires
        cr(h),
        well_formed(a),
        well_formed(b),
        identifier(h, a) == identifier(h, b),
    ensures
        a == b,
{
}

/// The claim above is false: for h = identity (which satisfies cr), the encrypt-scope pair
/// meets every `requires` and violates the `ensures`.
proof fn lemma_bug06_failing_claim_is_false()
    ensures
        ({
            let h = |x: Bytes| x;
            &&& cr(h)
            &&& well_formed(bug06_enc_a())
            &&& well_formed(bug06_enc_b())
            &&& identifier(h, bug06_enc_a()) == identifier(h, bug06_enc_b())
            &&& bug06_enc_a() != bug06_enc_b()
        }),
{
    lemma_cr_is_satisfiable();
    lemma_bug06_witness_collides();
}

// ============================================================
// SECTION 9: Proposed fix, length-prefixed encoding (BUG-06 fix option 2)
// ============================================================

/// Four-byte big-endian length (the prefix of the proposed encoding).
pub open spec fn be4(n: nat) -> Bytes {
    seq![
        ((n / 16777216nat) % 256nat) as u8,
        ((n / 65536nat) % 256nat) as u8,
        ((n / 256nat) % 256nat) as u8,
        (n % 256nat) as u8,
    ]
}

/// H_LEN_FITS bound.
pub open spec fn fits(s: Bytes) -> bool { s.len() < 4294967296nat }

/// be4 is injective on lengths below 2^32.
proof fn lemma_be4_injective(n: nat, m: nat)
    requires
        n < 4294967296nat,
        m < 4294967296nat,
        be4(n) == be4(m),
    ensures
        n == m,
{
    assert(be4(n)[0] == be4(m)[0]);
    assert(be4(n)[1] == be4(m)[1]);
    assert(be4(n)[2] == be4(m)[2]);
    assert(be4(n)[3] == be4(m)[3]);
    assert(n == (n / 16777216nat) * 16777216nat + (n / 65536nat) % 256nat * 65536nat
        + (n / 256nat) % 256nat * 256nat + n % 256nat) by (nonlinear_arith)
        requires n < 4294967296nat;
    assert(m == (m / 16777216nat) * 16777216nat + (m / 65536nat) % 256nat * 65536nat
        + (m / 256nat) % 256nat * 256nat + m % 256nat) by (nonlinear_arith)
        requires m < 4294967296nat;
    assert(n / 16777216nat < 256nat) by (nonlinear_arith)
        requires n < 4294967296nat;
    assert(m / 16777216nat < 256nat) by (nonlinear_arith)
        requires m < 4294967296nat;
}

/// A length-prefixed field: be4(len) ++ bytes.
pub open spec fn lpf(x: Bytes) -> Bytes { be4(x.len()) + x }

/// Proposed layout: the same four head bytes, then each variable field length-prefixed.
/// The version, when present, is length-prefixed too. No 0x00 separators are used.
pub open spec fn preimage_lp(t: Fields) -> Bytes {
    head(t.scope) + lpf(t.partition) + lpf(t.name) + lpf(t.branch_key_id)
        + (match t.version {
            Some(v) => lpf(v),
            None => Seq::empty(),
        })
}

pub open spec fn identifier_lp(h: spec_fn(Bytes) -> Bytes, t: Fields) -> Bytes {
    h(preimage_lp(t))
}

pub open spec fn fields_fit(t: Fields) -> bool {
    fits(t.partition) && fits(t.name) && fits(t.branch_key_id)
        && (match t.version {
            Some(v) => fits(v),
            None => true,
        })
}

/// A length-prefixed field splits uniquely, whatever its bytes are (NUL included).
proof fn lemma_lpf_split(x: Bytes, r: Bytes, y: Bytes, s: Bytes)
    requires
        fits(x),
        fits(y),
        lpf(x) + r == lpf(y) + s,
    ensures
        x == y,
        r == s,
{
    let l = lpf(x) + r;
    let m = lpf(y) + s;
    assert forall|k: int| 0 <= k < 4 implies be4(x.len())[k] == be4(y.len())[k] by {
        assert(l[k] == be4(x.len())[k]);
        assert(m[k] == be4(y.len())[k]);
    }
    assert(be4(x.len()) =~= be4(y.len()));
    lemma_be4_injective(x.len(), y.len());
    assert forall|i: int| 0 <= i < x.len() implies x[i] == y[i] by {
        assert(l[4 + i] == x[i]);
        assert(m[4 + i] == y[i]);
    }
    assert(x =~= y);
    assert(be4(x.len()).len() == 4);
    assert(l.len() == 4 + x.len() + r.len());
    assert(m.len() == 4 + y.len() + s.len());
    assert(r.len() == s.len());
    assert forall|j: int| 0 <= j < r.len() implies r[j] == s[j] by {
        assert(l[4 + x.len() + j] == r[j]);
        assert(m[4 + y.len() + j] == s[j]);
    }
    assert(r =~= s);
}

/// R7. The length-prefixed preimage is injective on ALL tuples that fit, with no NUL
/// precondition and no scope pairing.
proof fn lemma_lp_injective(a: Fields, b: Fields)
    requires
        fields_fit(a),
        fields_fit(b),
        preimage_lp(a) == preimage_lp(b),
    ensures
        a == b,
{
    let ta = lpf(a.partition) + (lpf(a.name) + (lpf(a.branch_key_id) + (match a.version {
        Some(v) => lpf(v),
        None => Seq::empty(),
    })));
    let tb = lpf(b.partition) + (lpf(b.name) + (lpf(b.branch_key_id) + (match b.version {
        Some(v) => lpf(v),
        None => Seq::empty(),
    })));
    assert(preimage_lp(a) =~= head(a.scope) + ta);
    assert(preimage_lp(b) =~= head(b.scope) + tb);
    lemma_strip_head(a.scope, ta, b.scope, tb);
    let ra = lpf(a.name) + (lpf(a.branch_key_id) + (match a.version {
        Some(v) => lpf(v),
        None => Seq::empty(),
    }));
    let rb = lpf(b.name) + (lpf(b.branch_key_id) + (match b.version {
        Some(v) => lpf(v),
        None => Seq::empty(),
    }));
    lemma_lpf_split(a.partition, ra, b.partition, rb);
    let sa = lpf(a.branch_key_id) + (match a.version {
        Some(v) => lpf(v),
        None => Seq::empty(),
    });
    let sb = lpf(b.branch_key_id) + (match b.version {
        Some(v) => lpf(v),
        None => Seq::empty(),
    });
    lemma_lpf_split(a.name, sa, b.name, sb);
    let oa = match a.version {
        Some(v) => lpf(v),
        None => Seq::empty(),
    };
    let ob = match b.version {
        Some(v) => lpf(v),
        None => Seq::empty(),
    };
    lemma_lpf_split(a.branch_key_id, oa, b.branch_key_id, ob);
    match (a.version, b.version) {
        (Some(va), Some(vb)) => {
            assert(lpf(va) + Seq::<u8>::empty() =~= oa);
            assert(lpf(vb) + Seq::<u8>::empty() =~= ob);
            lemma_lpf_split(va, Seq::empty(), vb, Seq::empty());
        },
        (Some(va), None) => {
            // oa has at least 4 bytes, ob is empty
            assert(oa.len() >= 4);
            assert(ob.len() == 0);
            assert(false);
        },
        (None, Some(vb)) => {
            assert(ob.len() >= 4);
            assert(oa.len() == 0);
            assert(false);
        },
        (None, None) => {},
    }
}

/// R7 (identifier level, the proposed fix). Under A_DIGEST_CR and H_LEN_FITS, the identifier
/// of the length-prefixed layout is injective for ALL inputs. This is the statement that the
/// expected-FAIL obligation in section 8 cannot prove for the shipped layout.
proof fn lemma_lp_identifier_injective(h: spec_fn(Bytes) -> Bytes, a: Fields, b: Fields)
    requires
        cr(h),
        fields_fit(a),
        fields_fit(b),
        identifier_lp(h, a) == identifier_lp(h, b),
    ensures
        a == b,
{
    lemma_lp_injective(a, b);
}

/// The proposed encoding separates the BUG-06 pairs (all four witnesses fit trivially).
proof fn theorem_lp_separates_bug06_witnesses(h: spec_fn(Bytes) -> Bytes)
    requires
        cr(h),
    ensures
        identifier_lp(h, bug06_enc_a()) != identifier_lp(h, bug06_enc_b()),
        identifier_lp(h, bug06_dec_a()) != identifier_lp(h, bug06_dec_b()),
{
    lemma_bug06_witness_collides();
    assert(fields_fit(bug06_enc_a()));
    assert(fields_fit(bug06_enc_b()));
    assert(fields_fit(bug06_dec_a()));
    assert(fields_fit(bug06_dec_b()));
    if identifier_lp(h, bug06_enc_a()) == identifier_lp(h, bug06_enc_b()) {
        lemma_lp_identifier_injective(h, bug06_enc_a(), bug06_enc_b());
    }
    if identifier_lp(h, bug06_dec_a()) == identifier_lp(h, bug06_dec_b()) {
        lemma_lp_identifier_injective(h, bug06_dec_a(), bug06_dec_b());
    }
}

// ============================================================
// SECTION 10: Scope separation and exact length (shipped layout)
// ============================================================

/// R8. Encrypt and decrypt identifiers never coincide, for any fields (NUL or not):
/// the scope byte sits at the fixed index 2 of the preimage.
proof fn lemma_scope_separation(h: spec_fn(Bytes) -> Bytes, a: Fields, b: Fields)
    requires
        cr(h),
        a.scope != b.scope,
    ensures
        identifier(h, a) != identifier(h, b),
{
    if identifier(h, a) == identifier(h, b) {
        lemma_preimage_is_head_body(a);
        lemma_preimage_is_head_body(b);
        assert(preimage(a)[2] == a.scope);
        assert(preimage(b)[2] == b.scope);
    }
}

/// Exact length of the shipped preimage: 4 + |p| + 1 + |n| + 1 + |id| (+ 1 + |v|).
proof fn lemma_preimage_len(t: Fields)
    ensures
        preimage(t).len() == 4 + t.partition.len() + 1 + t.name.len() + 1 + t.branch_key_id.len()
            + (match t.version {
                Some(v) => 1 + v.len(),
                None => 0,
            }),
{
}

} // verus!

fn main() {}
