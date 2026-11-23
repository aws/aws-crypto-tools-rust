// =============================================================================
// VR-2026-T20 (rank 22 of the threat-driven table, TM-MPL-023, TM-MPL-011, TM-MPL-001): the raw AES
//   keyring key-provider-information codec, `RawAesKeyring::serialize_provider_info` and
//   `RawAesKeyring::decryptable_edk_iv` (mpl/src/keyring/raw_aes_keyring.rs :129-142 and :191-219).
//
// Run:  ~/verus/verus verus-proofs/t20_raw_aes_provider_info.rs
// This file is NOT part of any cargo build (it lives outside mpl/, prim/, esdk/).
//
// =============================================================================
// 0. WHAT THIS FILE IS (read this first)
// =============================================================================
// THIS IS A MODEL-LEVEL PROOF, NOT A PROOF OF THE SHIPPED CODE.
// It proves facts about a hand-written, re-typed model of two small functions. The shipped functions
// are native Rust over `String`, `Vec<u8>` and `&[u8]`, outside `verus!`, and are not compiled by
// Verus. Nothing here detects a later edit to raw_aes_keyring.rs. The link between the model and the
// code is the correspondence table in section 2, reviewed by a human. The behavior of `std` calls
// (`split_at`, `try_into`, `to_be_bytes`, `from_be_bytes`, slice `!=`) is read from std (A_STD), not
// proved.
//
// STATUS: PROVED relative to the model and to the hypotheses in section 4:
//     `verification results:: 45 verified, 0 errors`
// Nothing is left failing on purpose. The code and the spec text agree on everything modeled, so no
// EXPECTED_FAIL obligation was written and none was invented (section 5, F0).
//
// HOW MUCH THIS PROOF IS WORTH (stated plainly).
//   * Part of the result is a consistency check against the spec text. `spec_accepts` restates
//     raw-aes-keyring.md :99-107 (the table) and :207-216 (the attempt conditions) without the
//     sequence of checks, and `theorem_decode_iff` shows the code-shaped `decode` equals it. The
//     layout lemma `lemma_layout` restates the table (order and widths of the fields). Neither would
//     catch a spec that is itself wrong.
//   * The parts with more weight: (a) the executable model `decryptable_edk_iv_exec` takes ANY
//     provider id and ANY provider info and Verus checks, for that model, that every slice range is in
//     bounds, every `+` cannot overflow, and the `try_into` inside the `?` cannot fail. So the model
//     does not panic and does not read out of bounds on any byte string. That is what "total" means
//     here. (b) The encoding is injective for 12-byte IVs (`theorem_encode_injective`), so a keyring
//     never accepts an EDK that another keyring (other name, other namespace, other name length)
//     produced (`theorem_cross_keyring_rejected`). (c) What happens to every kind of malformed input
//     is stated per reason (in-file SECTION 6), including a length field that claims more bytes than the
//     buffer has: the decoder never uses a length field to size a read, it compares the field with 12.
//     (d) The IV that comes out of `decode` is the IV that went into `encode`
//     (`theorem_roundtrip`, `roundtrip_exec`), and it is always 12 bytes (`theorem_accepted_shape`).
//   None of this shows that the shipped code, or the system around it, is safe.
//
// =============================================================================
// WHAT THE CODE DOES (code reading, mpl/src/keyring/raw_aes_keyring.rs)
// =============================================================================
// Constants the codec uses (:23-43): AUTH_TAG_LEN_LEN = 4, IV_LEN_LEN = 4, IV_LENGTH = 12, IV_LENGTH_FIELD = 12u32,
//   TAG_LENGTH_BITS = 128u32. The three wrapping algorithms all use a 12-byte IV and a 16-byte tag
//   (aes_wrapping_alg.rs :6, and the doc comments at :28-39), so one set of constants serves all.
// ENCODE `serialize_provider_info(&self, iv: &[u8]) -> Vec<u8>` (:129-142):
//   :130-134  debug_assert!(iv.len() == IV_LENGTH)       (compiled out in release builds)
//   :135      name = self.inner.key_name.as_bytes()
//   :136      Vec::with_capacity(name.len() + 4 + 4 + iv.len())
//   :137-140  info = name || be32(128) || be32(12) || iv       (extend_from_slice, in this order)
//   The constant 12 is written to the IV-length field whatever iv.len() is.
//   Only caller: wrap_data_key (:181), with `iv` = a fresh `vec![0u8; IV_LENGTH]` filled by the RNG
//   (:151-158), the same `iv` that goes to aes_encrypt (:165). The EDK's key provider id is the
//   namespace (:180).
// DECODE `decryptable_edk_iv(&self, edk) -> Option<&[u8]>` (:191-219). It is not a general parser. It
//   takes the keyring's own key name and checks the info against it:
//   :192-194  edk.key_provider_id() != self.inner.key_namespace         -> None
//   :196-200  info.len() != name.len() + 4 + 4 + 12                      -> None
//   :201-204  (info_name, rest) = info.split_at(name.len()); info_name != name   -> None
//   :206-210  (tag_bits, rest) = rest.split_at(4); tag_bits.try_into().ok()?; be32 != 128   -> None
//   :212-216  (iv_len, iv) = rest.split_at(4); iv_len.try_into().ok()?; be32 != 12          -> None
//   :218      Some(iv)                        iv is the last 12 bytes of the info, borrowed from the EDK
//   Every offset comes from name.len() and constants. No length field of the info is used to size or
//   position a read. Only caller: on_decrypt (:449). None is recorded as a NoMatchingDataKey error and
//   the loop goes on (:450-456). Some(iv) is passed as the IV of aes_decrypt (:477).
// There is no `unsafe` and no `unwrap` or `expect` in either function. The `split_at` calls would
//   panic if the length were smaller than the split point; the check at :198 is what prevents that.
//   The two `try_into().ok()?` calls are on 4-byte slices and cannot fail.
//
// =============================================================================
// WHAT IS PROVED (relative to the model and to section 4). Evidence level: PROVED (model).
// =============================================================================
//   P1  lemma_layout                   serialized info = name || 00 00 00 80 || 00 00 00 0c || iv, at
//                                      offsets n, n+4, n+8, total n + 8 + |iv|. (Consistency check
//                                      against the spec table.)
//   P2  theorem_decode_iff             decode(..) == Some(iv) exactly when pid == ns, |iv| == 12 and
//                                      info == name || be32(128) || be32(12) || iv. This is the YAML
//                                      `formal_spec` of T20. (Consistency check against the spec text.)
//       theorem_reject_reasons         decode is None exactly when: pid != ns, or |info| != n + 20, or
//                                      the first n bytes are not the name, or the tag field is not
//                                      be32(128), or the IV-length field is not be32(12).
//       theorem_accepted_shape         Some(iv) implies pid == ns, |iv| == 12, |info| == n + 20 and iv
//                                      is the last 12 bytes of the info.
//   P3  theorem_roundtrip              iv of 12 bytes: decode(ns, name, ns, encode(name, iv)) == Some(iv).
//       roundtrip_exec (exec)          the same for the executable models: serialize then decode, with
//                                      the same slice for the id, returns the same IV.
//   P4  theorem_encode_injective       for 12-byte IVs, equal info implies equal name and equal IV.
//       theorem_cross_keyring_rejected keyring B accepts keyring A's EDK exactly when the namespaces
//                                      and the key names are equal. Names of different lengths and
//                                      names that are prefixes of each other are covered.
//   P5  in-file SECTION 6              each kind of malformed input: wrong provider id
//                                      (lemma_reject_provider_id), wrong total length, including empty,
//                                      truncated, extended and off by one (lemma_reject_wrong_length),
//                                      wrong key name (lemma_reject_wrong_name), wrong tag-length field
//                                      (lemma_reject_tag_field), wrong IV-length field including a
//                                      value larger than the buffer (lemma_reject_iv_len_field), and
//                                      the same by value for every u32 other than 128 and 12
//                                      (theorem_field_values_rejected). All give None, never a panic.
//   P6  lemma_non_12_iv_never_accepted an IV of any length other than 12, serialized the way the code
//                                      does it (no check in release builds), is never accepted by any
//                                      keyring. See O2.
//   P7  decryptable_edk_iv_exec        the executable model, with no `requires` on the provider id or the
//       (exec)                         info, never panics, never indexes out of bounds and never
//                                      overflows (checked by Verus for the model), returns Some(iv) with
//                                      |iv| == 12 exactly when `decode` does, and None otherwise.
//       serialize_provider_info_exec   returns exactly `info_of(name, iv)`, for any IV length.
//   P8  witness_accepted, witness_rejected_iv_len_16, witness_empty_name, witness_two_names_differ
//                                      the hypotheses are satisfiable and the theorems are not vacuous:
//                                      one concrete accepted case, one concrete rejected case, the
//                                      empty key name, and two names of equal length that give
//                                      different info.
//
// =============================================================================
// WHAT IS NOT PROVED / WHAT THIS DOES NOT SHOW
// =============================================================================
//   * That the shipped code has any of these properties (model level only).
//   * That TM-MPL-023, TM-MPL-011 or TM-MPL-001 is mitigated. TM-MPL-023 (malformed provider info is
//     rejected, not a panic): the MODEL has no panic path; the shipped functions are not checked. The
//     rest of on_decrypt (ciphertext split at :467-469, AES-GCM, the plaintext key length) is not
//     modeled. TM-MPL-011 (the decryptor uses exactly the encryptor's IV): P3 shows the codec returns
//     the IV it was given. That the IV given to aes_encrypt is the one serialized, and that the IV
//     returned is the one given to aes_decrypt, is code reading (H_IV_FLOW). Nothing here says the IV is
//     random, fresh or unique; that is T07 and the 96-bit birthday bound, not modeled. TM-MPL-001
//     (provider-id filter): decode accepts only when pid == ns (P2). The namespace check in `build`
//     is T24, and downstream components that compare ids case-insensitively are out of scope.
//   * The ciphertext half of the spec sentence "the ciphertext and key provider information MUST be
//     successfully deserialized" (raw-aes-keyring.md :212). The ciphertext length check at :460 and the
//     split at :467-469 are not modeled.
//   * The error text, the error kind and the loop in on_decrypt (:448-457). The model returns None.
//   * AES-GCM, the wrapping key, the random IV generation, zeroization, `Debug`, the builder checks.
//   * That `Vec`, slices, `String::as_bytes`, `u32::to_be_bytes`, `u32::from_be_bytes`, `split_at` and
//     `try_into` behave as modeled (A_STD, A_BYTES). The two byte-order models are proved equal to the
//     arithmetic definitions; the std functions themselves are not.
//   * UTF-8. The key name is a `String` in the code and so valid UTF-8. The model takes any bytes
//     (A_BYTES) and does not use UTF-8 validity.
//   * Cross-component limits. The ESDK header writes the provider info with a 2-byte length
//     (esdk/src/message/encrypted_data_keys.rs :88-92), so a key name longer than 65515 bytes would
//     make that write fail. That is another function, not modeled, and not a claim about this codec.
//   * Timing. Provider info is not secret; byte comparison time is not considered.
//
// =============================================================================
// 1. SOURCE MODELED  (repo esdk-native-mpl, branch MPL-Verus, HEAD 0756760; mpl/, prim/, esdk/ unchanged by this work)
// =============================================================================
//   mpl/src/keyring/raw_aes_keyring.rs (md5 d9e81c5a71c0f18daf1decd085736018)
//     :21-43    the five constants the codec uses (a sixth, `TAG_LENGTH` :39, is used only by the
//               ciphertext split, which is not modeled) and their doc comments
//     :127-142  serialize_provider_info (:129)
//     :146-184  wrap_data_key: iv at :151-158, aes_encrypt at :163-170, EDK built at :179-183
//     :186-219  decryptable_edk_iv (:191)
//     :422-    on_decrypt: the call at :449, aes_decrypt at :472-480 with `iv` at :477
//   mpl/src/structures/encrypted_data_key.rs (md5 21a058b35efe29bf23839ee4401fb608)
//     :38 key_provider_id() -> &str, :44 key_provider_info() -> &[u8]
//   mpl/src/structures/aes_wrapping_alg.rs :6-35   three variants, all "12-byte IV and 16-byte tag"
//   prim/src/lib.rs :188, :224   `Nonce::try_assume_unique_for_key(iv)` (a wrong-length IV is an Err
//     from aes_encrypt / aes_decrypt, not a panic; read from the call, not proved)
//   spec/framework/raw-aes-keyring.md :90-123 "Key Provider Information" (table :99-107, "Authentication
//     Tag Length" :113-117, "IV Length" :119-123), :207-216 (OnDecrypt: deserialize, then attempt iff)
//   Tests (not proofs): mpl/tests/test_raw_aes_keyring.rs :406 (wire format), :465 (round trip for every
//     algorithm), :201 (key name mismatch), :586 (wrong provider id), :619 (wrong tag length),
//     :658 (wrong IV length), :548 (tampered IV), :696 (ciphertext shorter than the tag).
//     No test truncates or extends the provider info by one byte; R2 covers that case in the model.
//
// =============================================================================
// 2. CORRESPONDENCE TABLE (model item  <->  shipped code)
// =============================================================================
//   model                   shipped
//   ----------------------  ------------------------------------------------------------------------
//   Bytes = Seq<u8>         `String` (as_bytes), `&[u8]`, `Vec<u8>`. Byte sequences as Seq<u8> follow
//                           t02 and c01 (A_BYTES). Not imported: each proof file is its own crate root.
//   be32(x)                 `u32::to_be_bytes` (:138, :139). COPIED from t04_branch_key_wrap.rs :353
//                           (also t05 :282), unchanged. Checked against shifts in u32_to_be_bytes.
//   be32_val(s)             `u32::from_be_bytes` (:208, :214). New here; checked against shifts in
//                           u32_from_be_bytes, and against be32 in lemma_be32_value.
//   u32_to_be_bytes         COPIED from t04 :622 (body unchanged).
//   info_of(name, iv)       `serialize_provider_info` :137-140: name, then be32(128), then be32(12),
//                           then iv, for any iv length (the debug_assert! at :130-134 is not modeled).
//   info_len(name)          the length test at :198: name.len() + 4 + 4 + 12
//   decode(ns,name,pid,info)  `decryptable_edk_iv` :191-219, same checks in the same order. `None` is
//                           each `return None` and each `?` on a failed try_into. `info.subrange(a, b)`
//                           is the slice produced by `split_at` (:201, :206, :212).
//   pid, ns                 `edk.key_provider_id()` and `self.inner.key_namespace` (:192)
//   name                    `self.inner.key_name.as_bytes()` (:197)
//   info                    `edk.key_provider_info()` (:196)
//   spec_accepts            raw-aes-keyring.md :99-107 and :207-216 (and the T20 `formal_spec`)
//   serialize_provider_info_exec   :129-142 minus the debug_assert!; vstd `Vec::with_capacity`
//                           and `extend_from_slice`
//   decryptable_edk_iv_exec :191-219; `split_at(k)` is two index ranges [0..k] and [k..len]; the two
//                           `try_into().ok()?` are `array4_from_slice`, whose `requires` is the case
//                           where `try_into` is Ok; slice `!=` is `bytes_eq`
//   roundtrip_exec          wrap_data_key's EDK (:179-181) read back by decryptable_edk_iv (:449)
//
// =============================================================================
// 3. WHAT IS SPEC-DERIVED AND WHAT IS CODE-DERIVED
// =============================================================================
// Spec-derived (spec/framework/raw-aes-keyring.md):
//   :99-107   field order (key name, tag length, IV length, IV), widths 4 and 4, big-endian UInt32
//             -> P1, P2.
//   :113-117  the tag length is in bits and MUST match the wrapping algorithm (128) -> the constant
//             128 and the check in decode.
//   :119-123  the IV length is in bytes and MUST match the wrapping algorithm (12) -> the constant 12.
//   :207-216  the attempt conditions: deserialize, name equals, provider id equals, IV length equals,
//             tag length equals -> P2, P5.
// Code-derived, with no spec sentence: that the total length must be exactly name + 20 (the spec says
// the IV occupies the IV-length field's number of bytes and says nothing about trailing bytes); that
// the key name is taken from the keyring and not parsed from the info (the spec table has no length
// field for the key name, so a parser must be given it); that every mismatch is silently None; the
// order of the checks.
// So P1 and P2 are, in part, consistency checks of the model against the spec text. That the model is
// a correct transcription of :191-219 and :129-142 is not machine-checked (H_MODEL_MATCH).
//
// =============================================================================
// 4. HYPOTHESES AND EVIDENCE LEVELS
// =============================================================================
//  Evidence levels used in this file:
//    PROVED        machine-checked by Verus in this file, relative to the model and to the hypotheses
//    ASSUMED       taken as a premise or a definition; not proved here (A_*)
//    CODE READING  a claim about shipped code or std that Verus does not see (H_*); checked by a human
//                  reading the source at the lines named
//  No `assume`, `admit`, `external_body`, `external`, `assume_specification` or `#[verifier..]` attribute
//  is written in this file, and there is no uninterpreted spec function. The trusted base is Verus, Z3,
//  the vstd axioms for Seq and the vstd specs of `Vec::with_capacity`, `Vec::extend_from_slice`,
//  `Vec::as_slice` and slice indexing by range.
//
//  A_BYTES (ASSUMED, inherited from T24, C01, T02). Key names, provider ids and provider info are
//    arbitrary `Seq<u8>`. A Rust `String` is such a sequence (its UTF-8 bytes), so a theorem over all
//    byte sequences covers all strings and some non-strings. `edk.key_provider_id() != key_namespace`
//    (`&str` against `String`) is byte equality. Not machine-checked.
//  A_STD (ASSUMED). `u32::to_be_bytes` and `u32::from_be_bytes` are the big-endian encoding and its
//    inverse (the models are proved equal to the arithmetic definitions, std is not). `split_at(k)`
//    panics exactly when k > len and otherwise returns the sub-slices [..k] and [k..]. `<&[u8; 4]>::try_from`
//    on a 4-byte slice is Ok. Slice `==` and `!=` are element-wise and false for different lengths.
//    Read from std documentation, not proved.
//  A_NONCE (ASSUMED, read from prim/src/lib.rs :188 and :224, not proved). `aes_decrypt` returns an
//    Err, not a panic, for an IV that is not a valid nonce. Used only to say what a wrong-length IV would
//    do (O2). No theorem depends on it.
//  H_MODEL_MATCH (CODE READING). `info_of`, `decode` and the two exec functions perform, in the same
//    order, the operations of :129-142 and :191-219. Checked by reading.
//  H_NO_OVERFLOW (CODE READING + Rust). The `requires` of the exec functions (`name.len() + 20` and
//    `name.len() + iv.len() + 8` do not exceed usize::MAX) hold at the real call sites: a `String` is at
//    most isize::MAX bytes, the IV at :181 has 12 bytes, and `with_capacity` is only a capacity hint.
//    The model has no panic for an input of any other size. It is a precondition of the model, not a
//    proof about the allocator.
//  H_CALLER_IV (CODE READING). The only caller of `serialize_provider_info` is `wrap_data_key` (:181),
//    with `iv` = `vec![0u8; IV_LENGTH]` (:151). So the IV is always 12 bytes. The debug_assert! is not
//    what guarantees it. Checked by grep: no other call site in mpl/src, esdk/src or prim/src.
//  H_ONLY_CALLER_DECODE (CODE READING). The only caller of `decryptable_edk_iv` is on_decrypt (:449).
//    A None is recorded and the loop continues (:450-456); a Some(iv) is passed to aes_decrypt (:477).
//  H_IV_FLOW (CODE READING). In wrap_data_key the same `iv` Vec is passed to aes_encrypt (:165) and to
//    serialize_provider_info (:181). In on_decrypt the `iv` returned by decryptable_edk_iv is passed to
//    aes_decrypt (:477). Nothing between them changes it. The model does not see these two call sites.
//  H_ALG_CONSTANTS (CODE READING). All three AesWrappingAlg variants have a 12-byte IV and a 16-byte
//    tag (aes_wrapping_alg.rs :6, raw_aes_keyring.rs :28-39), so the constants at :31-43 are the
//    configured algorithm's values. The enum is `#[non_exhaustive]`: a later variant with other
//    lengths would need a code change here, and this proof would not notice.
//  H_NO_OTHER_READER (CODE READING). No other function in mpl/src, esdk/src or prim/src reads the
//    raw AES provider info layout (grep for the five constant names finds only this file).
// =============================================================================
// 5. FINDINGS AND OBSERVATIONS
// =============================================================================
//  F0 (no gap). The model satisfies the spec sentences it was checked against. No EXPECTED_FAIL
//    obligation exists. None was invented.
//  O1 (observation, not a gap). The spec table has no length field for the key name, so the provider
//    info cannot be parsed without knowing the name. The code takes the name from the keyring and
//    requires the total length to be exactly name + 20. With 12-byte IVs this makes the encoding
//    injective (theorem_encode_injective) and the filter exact (theorem_cross_keyring_rejected). The
//    exact total length is stricter than the spec text, which is silent about trailing bytes.
//  O2 (observation, not a gap). The IV length is checked in `serialize_provider_info` only by a
//    debug_assert! (:130-134). In a release build an IV of another length would be serialized with the
//    constant 12 in its length field, and no keyring would ever accept it (lemma_non_12_iv_never_accepted).
//    The only caller passes 12 bytes (H_CALLER_IV), so this does not occur. It would matter only if a
//    second caller were added.
//  O3 (observation). `build` requires only that `key_name` is set. The empty key name works in the
//    codec (witness_empty_name).
//  O4 (observation, diagnostics only). When the provider id matches but the provider info is malformed,
//    decryptable_edk_iv returns None and on_decrypt records "did not match the keyring, expected key
//    provider id {namespace}" (:451-454). The message names the provider id, which did match. The kind
//    is NoMatchingDataKey and the EDK is skipped. No safety effect; the model does not see the text.
//  O5 (scope). T20 covers the codec only. The ciphertext split (:460-469), the AES-GCM call and the
//    plaintext key length check are not modeled. IV freshness is T07.
// =============================================================================
// 6. OVERLAP
// =============================================================================
//  Mahnush_Verus (.agents/tasks/mpl-batch3-proofs/t20-duplicate-check.md, tip 8d6381e): no overlap. The
//    ref has no `verus!` in mpl/, and raw_aes_keyring.rs is identical to this branch and plain Rust there.
//    Its in-crate proofs (VR-006, VR-008, VR-009, VR-013, VR-014) are in prim/ and esdk/ and do not touch
//    the raw AES provider info.
//  This repository: T24 (t24_raw_aes_namespace.rs) models the namespace check in `build` and the
//    provider-id filter at :192 (its R5). T20 uses the same filter as one conjunct of `decode`, does not
//    use T24's model and does not repeat its theorems. `be32` and `u32_to_be_bytes` are copied from T04
//    (section 2). T04 and T05 model other codecs (branch-key wrap and KDF fixed info). C07 and C04 do
//    not model this codec. T20 duplicates none of them.
// =============================================================================
use vstd::prelude::*;
verus! {
// ============================================================
// SECTION 1: Types and constants (raw_aes_keyring.rs :21-43)
// ============================================================
/// A byte string. Key names, provider ids and provider info are all modeled as byte sequences (A_BYTES).
pub type Bytes = Seq<u8>;
/// :23 `AUTH_TAG_LEN_LEN` and :26 `IV_LEN_LEN`: the width of each length field, in bytes.
pub const AUTH_TAG_LEN_LEN: usize = 4;
pub const IV_LEN_LEN: usize = 4;
/// :31 `IV_LENGTH`, the IV length in bytes.
pub const IV_LENGTH: usize = 12;
/// :35 `IV_LENGTH_FIELD`, the value written into and read from the IV-length field.
pub const IV_LENGTH_FIELD: u32 = 12;
/// :43 `TAG_LENGTH_BITS`, the authentication tag length in bits, as serialized.
pub const TAG_LENGTH_BITS: u32 = 128;
// ============================================================
// SECTION 2: Specification functions
// ============================================================
/// 4-byte big-endian encoding of x, stated arithmetically (most significant byte first).
/// COPIED from t04_branch_key_wrap.rs :353 (the same item is in t05 :282). Models `u32::to_be_bytes`.
pub open spec fn be32(x: u32) -> Bytes {
    seq![
        ((x / 0x1000000u32) % 256u32) as u8,
        ((x / 0x10000u32) % 256u32) as u8,
        ((x / 0x100u32) % 256u32) as u8,
        (x % 256u32) as u8,
    ]
}
/// The value of four bytes read as a big-endian unsigned integer. Models `u32::from_be_bytes`.
/// Defined for every sequence; the result is only meaningful when `s.len() == 4`.
pub open spec fn be32_val(s: Bytes) -> int
    recommends
        s.len() == 4,
{
    (s[0] as int) * 16777216 + (s[1] as int) * 65536 + (s[2] as int) * 256 + (s[3] as int)
}
/// The key provider information written by `serialize_provider_info` (:129-142), for ANY iv length:
/// `key_name || be32(128) || be32(12) || iv`. The code writes the constant 12 into the IV-length field
/// whatever `iv.len()` is (the only length check is a `debug_assert!`, :130-134).
pub open spec fn info_of(name: Bytes, iv: Bytes) -> Bytes {
    name + be32(TAG_LENGTH_BITS) + be32(IV_LENGTH_FIELD) + iv
}
/// The length that `decryptable_edk_iv` requires of the info (:198): name + 4 + 4 + 12.
pub open spec fn info_len(name: Bytes) -> int {
    name.len() + (AUTH_TAG_LEN_LEN as int) + (IV_LEN_LEN as int) + (IV_LENGTH as int)
}
/// `decryptable_edk_iv` (:191-219) as one function of the keyring (namespace, key name) and the EDK
/// (provider id, provider info). Same checks in the same order as the code; `None` is `return None`.
///   :192  provider id == namespace
///   :198  info.len() == name.len() + 4 + 4 + 12
///   :201-202  info[..n] == name           (split_at(name.len()))
///   :206-208  be32_val(info[n..n+4]) == 128    (split_at(4), try_into, from_be_bytes)
///   :212-214  be32_val(info[n+4..n+8]) == 12
///   :218  Some(info[n+8..])
pub open spec fn decode(ns: Bytes, name: Bytes, pid: Bytes, info: Bytes) -> Option<Bytes> {
    if pid != ns {
        None
    } else if info.len() != info_len(name) {
        None
    } else {
        let n = name.len() as int;
        if info.subrange(0, n) != name {
            None
        } else if be32_val(info.subrange(n, n + 4)) != TAG_LENGTH_BITS as int {
            None
        } else if be32_val(info.subrange(n + 4, n + 8)) != IV_LENGTH_FIELD as int {
            None
        } else {
            Some(info.subrange(n + 8, info.len() as int))
        }
    }
}
/// The spec sentences, stated without the sequence of checks (raw-aes-keyring.md :99-107, :207-216 and
/// the YAML `formal_spec` of T20): the EDK is attempted exactly when the provider id equals the
/// namespace and the info is the table layout (key name, tag length 128 bits, IV length 12, an IV of
/// exactly that length) for this keyring's key name.
pub open spec fn spec_accepts(ns: Bytes, name: Bytes, pid: Bytes, info: Bytes, iv: Bytes) -> bool {
    &&& pid == ns
    &&& iv.len() == IV_LENGTH
    &&& info == info_of(name, iv)
}
// ============================================================
// SECTION 3: Lemmas about be32
// ============================================================
/// be32 is a big-endian encoding: the four bytes read back to x. COPIED from t04 :425 (proof body
/// unchanged), restated with `be32_val`.
pub proof fn lemma_be32_value(x: u32)
    ensures
        be32_val(be32(x)) == x as int,
{
    let a = x / 0x1000000u32;
    let b = (x / 0x10000u32) % 256u32;
    let c = (x / 0x100u32) % 256u32;
    let d = x % 256u32;
    assert(a < 256) by (nonlinear_arith)
        requires
            a == x / 0x1000000u32,
    ;
    assert(((x / 0x1000000u32) % 256u32) == a) by (nonlinear_arith)
        requires
            a == x / 0x1000000u32,
            a < 256,
    ;
    assert((a as int) * 16777216 + (b as int) * 65536 + (c as int) * 256 + (d as int) == x as int)
        by (bit_vector)
        requires
            a == x / 0x1000000u32,
            b == (x / 0x10000u32) % 256u32,
            c == (x / 0x100u32) % 256u32,
            d == x % 256u32,
    ;
}
/// Four bytes with the same big-endian value are the same four bytes (each byte is below 256).
pub proof fn lemma_val_injective(s: Bytes, t: Bytes)
    requires
        s.len() == 4,
        t.len() == 4,
        be32_val(s) == be32_val(t),
    ensures
        s == t,
{
    assert(s[0] == t[0] && s[1] == t[1] && s[2] == t[2] && s[3] == t[3]) by (nonlinear_arith)
        requires
            s.len() == 4,
            t.len() == 4,
            0 <= s[0] <= 255 && 0 <= s[1] <= 255 && 0 <= s[2] <= 255 && 0 <= s[3] <= 255,
            0 <= t[0] <= 255 && 0 <= t[1] <= 255 && 0 <= t[2] <= 255 && 0 <= t[3] <= 255,
            be32_val(s) == be32_val(t),
    ;
    assert(s =~= t);
}
/// Reading four bytes as a big-endian integer gives x exactly when the bytes are `be32(x)`.
pub proof fn lemma_val_eq_iff(s: Bytes, x: u32)
    requires
        s.len() == 4,
    ensures
        (be32_val(s) == x as int) <==> (s == be32(x)),
{
    lemma_be32_value(x);
    if be32_val(s) == x as int {
        assert(be32(x).len() == 4);
        lemma_val_injective(s, be32(x));
    }
}
/// `be32` of a u32 is injective in the value: different field values are different bytes.
pub proof fn lemma_be32_injective(x: u32, y: u32)
    ensures
        (be32(x) == be32(y)) <==> (x == y),
{
    lemma_be32_value(x);
    lemma_be32_value(y);
}
// ============================================================
// SECTION 4: Layout and the decode characterization
// ============================================================
/// L1 (consistency check against the spec table, raw-aes-keyring.md :99-107). The serialized info has
/// the fields in the order key name, tag length (4 bytes), IV length (4 bytes), IV, at these offsets,
/// and the total length is name + 8 + iv.
pub proof fn lemma_layout(name: Bytes, iv: Bytes)
    ensures
        info_of(name, iv).len() == name.len() + 4 + 4 + iv.len(),
        info_of(name, iv).subrange(0, name.len() as int) == name,
        info_of(name, iv).subrange(name.len() as int, name.len() as int + 4) == be32(TAG_LENGTH_BITS),
        info_of(name, iv).subrange(name.len() as int + 4, name.len() as int + 8) == be32(IV_LENGTH_FIELD),
        info_of(name, iv).subrange(name.len() as int + 8, info_of(name, iv).len() as int) == iv,
        be32(TAG_LENGTH_BITS) == seq![0u8, 0u8, 0u8, 128u8],
        be32(IV_LENGTH_FIELD) == seq![0u8, 0u8, 0u8, 12u8],
{
    let i = info_of(name, iv);
    let n = name.len() as int;
    assert(be32(TAG_LENGTH_BITS) =~= seq![0u8, 0u8, 0u8, 128u8]);
    assert(be32(IV_LENGTH_FIELD) =~= seq![0u8, 0u8, 0u8, 12u8]);
    assert(i.len() == n + 8 + iv.len());
    assert(i.subrange(0, n) =~= name);
    assert(i.subrange(n, n + 4) =~= be32(TAG_LENGTH_BITS));
    assert(i.subrange(n + 4, n + 8) =~= be32(IV_LENGTH_FIELD));
    assert(i.subrange(n + 8, i.len() as int) =~= iv);
}
/// L2 (YAML `formal_spec` of T20). `decode` returns `Some(iv)` exactly when the provider id equals the
/// namespace, `iv` has 12 bytes and the info is `key_name || be32(128) || be32(12) || iv`.
/// PART OF THIS IS A CONSISTENCY CHECK: the right side restates raw-aes-keyring.md :99-107 and
/// :207-216 without the sequence of checks, and the proof shows the code-shaped `decode` equals it.
pub proof fn theorem_decode_iff(ns: Bytes, name: Bytes, pid: Bytes, info: Bytes, iv: Bytes)
    ensures
        (decode(ns, name, pid, info) == Some(iv)) <==> spec_accepts(ns, name, pid, info, iv),
{
    let n = name.len() as int;
    if decode(ns, name, pid, info) == Some(iv) {
        // every check passed
        assert(pid == ns);
        assert(info.len() == info_len(name));
        assert(info.subrange(0, n) == name);
        assert(be32_val(info.subrange(n, n + 4)) == TAG_LENGTH_BITS as int);
        assert(be32_val(info.subrange(n + 4, n + 8)) == IV_LENGTH_FIELD as int);
        assert(iv == info.subrange(n + 8, info.len() as int));
        assert(info.subrange(n, n + 4).len() == 4);
        assert(info.subrange(n + 4, n + 8).len() == 4);
        lemma_val_eq_iff(info.subrange(n, n + 4), TAG_LENGTH_BITS);
        lemma_val_eq_iff(info.subrange(n + 4, n + 8), IV_LENGTH_FIELD);
        assert(iv.len() == IV_LENGTH);
        assert(info =~= info_of(name, iv));
    }
    if spec_accepts(ns, name, pid, info, iv) {
        lemma_layout(name, iv);
        lemma_be32_value(TAG_LENGTH_BITS);
        lemma_be32_value(IV_LENGTH_FIELD);
        assert(info.len() == info_len(name));
        assert(info.subrange(0, n) == name);
        assert(info.subrange(n, n + 4) == be32(TAG_LENGTH_BITS));
        assert(info.subrange(n + 4, n + 8) == be32(IV_LENGTH_FIELD));
        assert(info.subrange(n + 8, info.len() as int) == iv);
    }
}
/// L3. What `decode` rejects, as a list of reasons. `decode` is None exactly when: the provider id is
/// not the namespace, or the info length is not name + 20, or (with the right length) the first n bytes
/// are not the key name, or the tag-length field is not be32(128), or the IV-length field is not be32(12).
pub proof fn theorem_reject_reasons(ns: Bytes, name: Bytes, pid: Bytes, info: Bytes)
    ensures
        (decode(ns, name, pid, info) is None) <==> ({
        ||| pid != ns
        ||| info.len() != info_len(name)
        ||| info.subrange(0, name.len() as int) != name
        ||| info.subrange(name.len() as int, name.len() as int + 4) != be32(TAG_LENGTH_BITS)
        ||| info.subrange(name.len() as int + 4, name.len() as int + 8) != be32(IV_LENGTH_FIELD)
    }),
{
    let n = name.len() as int;
    if pid == ns && info.len() == info_len(name) {
        assert(info.subrange(n, n + 4).len() == 4);
        assert(info.subrange(n + 4, n + 8).len() == 4);
        lemma_val_eq_iff(info.subrange(n, n + 4), TAG_LENGTH_BITS);
        lemma_val_eq_iff(info.subrange(n + 4, n + 8), IV_LENGTH_FIELD);
    }
}
/// L4. The result of `decode` is either None or a 12-byte IV (the length `aes_decrypt` is given at
/// :477), and then the info is exactly name + 20 bytes long and the IV is its last 12 bytes.
pub proof fn theorem_accepted_shape(ns: Bytes, name: Bytes, pid: Bytes, info: Bytes)
    ensures
        match decode(ns, name, pid, info) {
            Some(iv) => {
                &&& pid == ns
                &&& iv.len() == IV_LENGTH
                &&& info.len() == name.len() + 20
                &&& iv == info.subrange(info.len() - 12, info.len() as int)
            },
            None => true,
        },
{
    if let Some(iv) = decode(ns, name, pid, info) {
        theorem_decode_iff(ns, name, pid, info, iv);
        lemma_layout(name, iv);
        assert(iv == info.subrange(info.len() - 12, info.len() as int));
    }
}
// ============================================================
// SECTION 5: Round trip, injectivity and cross-keyring rejection
// ============================================================
/// L5 (round trip, TM-MPL-011). For a 12-byte IV, `decode(encode(iv))` is `Some(iv)` when the provider
/// id is the namespace (the id `wrap_data_key` sets, :180). The IV that comes out is the IV that went in.
pub proof fn theorem_roundtrip(ns: Bytes, name: Bytes, iv: Bytes)
    requires
        iv.len() == IV_LENGTH,
    ensures
        decode(ns, name, ns, info_of(name, iv)) == Some(iv),
{
    theorem_decode_iff(ns, name, ns, info_of(name, iv), iv);
}
/// L6. With the key name fixed, the encoding is injective in the IV, for equal-length IVs.
/// For two 12-byte IVs and two key names, equal info means equal names and equal IVs.
pub proof fn theorem_encode_injective(n1: Bytes, iv1: Bytes, n2: Bytes, iv2: Bytes)
    requires
        iv1.len() == IV_LENGTH,
        iv2.len() == IV_LENGTH,
        info_of(n1, iv1) == info_of(n2, iv2),
    ensures
        n1 == n2,
        iv1 == iv2,
{
    lemma_layout(n1, iv1);
    lemma_layout(n2, iv2);
    // equal length, 12-byte IVs: the key names have equal length
    assert(n1.len() == n2.len());
    let i = info_of(n1, iv1);
    assert(n1 =~= i.subrange(0, n1.len() as int));
    assert(n2 =~= i.subrange(0, n2.len() as int));
    assert(iv1 =~= i.subrange(n1.len() as int + 8, i.len() as int));
    assert(iv2 =~= i.subrange(n2.len() as int + 8, i.len() as int));
}
/// L7 (TM-MPL-001 neighborhood, TM-MPL-011). A keyring (ns2, name2) never accepts an EDK that
/// keyring (ns1, name1) produced with a 12-byte IV, unless the two keyrings have the same namespace and
/// the same key name. Different key names (also names of different lengths) and different namespaces
/// are rejected. This is a property of the codec filter, not of the keyring as a whole.
pub proof fn theorem_cross_keyring_rejected(
    ns1: Bytes,
    name1: Bytes,
    ns2: Bytes,
    name2: Bytes,
    iv: Bytes,
)
    requires
        iv.len() == IV_LENGTH,
    ensures
        (decode(ns2, name2, ns1, info_of(name1, iv)) is Some) <==> (ns1 == ns2 && name1 == name2),
{
    if decode(ns2, name2, ns1, info_of(name1, iv)) is Some {
        let iv2 = decode(ns2, name2, ns1, info_of(name1, iv)).unwrap();
        theorem_decode_iff(ns2, name2, ns1, info_of(name1, iv), iv2);
        theorem_encode_injective(name1, iv, name2, iv2);
    }
    if ns1 == ns2 && name1 == name2 {
        theorem_roundtrip(ns2, name2, iv);
    }
}
/// L8 (observation O2). `serialize_provider_info` checks the IV length only with `debug_assert!`
/// (:130-134). If an IV of any length other than 12 were passed, the code would still write the
/// constant 12 in the IV-length field, and no keyring would ever accept the result (the length check
/// at :198 fails). The only caller passes a 12-byte IV (:151, :181). Not a gap; see O2.
pub proof fn lemma_non_12_iv_never_accepted(ns: Bytes, name: Bytes, iv: Bytes)
    requires
        iv.len() != IV_LENGTH,
    ensures
        decode(ns, name, ns, info_of(name, iv)) is None,
{
    lemma_layout(name, iv);
}
// ============================================================
// SECTION 6: Malformed input (named rejections)
// ============================================================
/// R1 wrong provider id: rejected, whatever the info is.
pub proof fn lemma_reject_provider_id(ns: Bytes, name: Bytes, pid: Bytes, info: Bytes)
    requires
        pid != ns,
    ensures
        decode(ns, name, pid, info) is None,
{
}
/// R2 wrong total length: every info whose length is not name + 20 is rejected, with no read of the
/// info. This covers an empty info, a truncated info, an info with trailing bytes, and an off-by-one
/// in either direction (name + 19, name + 21).
pub proof fn lemma_reject_wrong_length(ns: Bytes, name: Bytes, info: Bytes)
    requires
        info.len() != name.len() + 20,
    ensures
        decode(ns, name, ns, info) is None,
{
}
/// R3 right length, wrong key name.
pub proof fn lemma_reject_wrong_name(ns: Bytes, name: Bytes, info: Bytes)
    requires
        info.len() == name.len() + 20,
        info.subrange(0, name.len() as int) != name,
    ensures
        decode(ns, name, ns, info) is None,
{
}
/// R4 right length and name, tag-length field is not be32(128). Instances: 0, 127, 129, 256, 0xFFFFFFFF,
/// and the little-endian bytes 80 00 00 00 (the value 0x80000000).
pub proof fn lemma_reject_tag_field(ns: Bytes, name: Bytes, info: Bytes)
    requires
        info.len() == name.len() + 20,
        info.subrange(0, name.len() as int) == name,
        info.subrange(name.len() as int, name.len() as int + 4) != be32(TAG_LENGTH_BITS),
    ensures
        decode(ns, name, ns, info) is None,
{
    theorem_reject_reasons(ns, name, ns, info);
}
/// R5 right length, name and tag field, IV-length field is not be32(12). This includes a field that
/// claims more bytes than the buffer holds (for example be32(0xFFFFFFFF)): `decode` never uses the
/// field to size or position a read. It compares it with 12 and rejects.
pub proof fn lemma_reject_iv_len_field(ns: Bytes, name: Bytes, info: Bytes)
    requires
        info.len() == name.len() + 20,
        info.subrange(0, name.len() as int) == name,
        info.subrange(name.len() as int, name.len() as int + 4) == be32(TAG_LENGTH_BITS),
        info.subrange(name.len() as int + 4, name.len() as int + 8) != be32(IV_LENGTH_FIELD),
    ensures
        decode(ns, name, ns, info) is None,
{
    theorem_reject_reasons(ns, name, ns, info);
}
/// R6 Field values, by value: a tag-length field read as any u32 other than 128, or an IV-length field
/// read as any u32 other than 12, gives None, for all of the 2^32 - 1 other values, including values
/// larger than the buffer (the field is a value to compare, never a length to read).
pub proof fn theorem_field_values_rejected(ns: Bytes, name: Bytes, iv: Bytes, tag: u32, ivl: u32)
    requires
        iv.len() == IV_LENGTH,
        tag != TAG_LENGTH_BITS || ivl != IV_LENGTH_FIELD,
    ensures
        decode(ns, name, ns, name + be32(tag) + be32(ivl) + iv) is None,
{
    let info = name + be32(tag) + be32(ivl) + iv;
    let n = name.len() as int;
    assert(info.len() == n + 20);
    assert(info.subrange(0, n) =~= name);
    assert(info.subrange(n, n + 4) =~= be32(tag));
    assert(info.subrange(n + 4, n + 8) =~= be32(ivl));
    lemma_be32_injective(tag, TAG_LENGTH_BITS);
    lemma_be32_injective(ivl, IV_LENGTH_FIELD);
    theorem_reject_reasons(ns, name, ns, info);
}
// ============================================================
// SECTION 7: Witnesses (the hypotheses are satisfiable, the theorems are not vacuous)
// ============================================================
/// One concrete accepted case: namespace `n`, key name `k` (6b), 12-byte IV of 0x07.
pub proof fn witness_accepted()
    ensures
        ({
            let ns = seq![0x6eu8];
            let name = seq![0x6bu8];
            let iv = Seq::new(12, |i: int| 7u8);
            let info = seq![0x6bu8, 0, 0, 0, 128, 0, 0, 0, 12, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7];
            &&& info == info_of(name, iv)
            &&& decode(ns, name, ns, info) == Some(iv)
        }),
{
    let ns = seq![0x6eu8];
    let name = seq![0x6bu8];
    let iv = Seq::new(12, |i: int| 7u8);
    let info = seq![0x6bu8, 0, 0, 0, 128, 0, 0, 0, 12, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7];
    assert(be32(TAG_LENGTH_BITS) =~= seq![0u8, 0u8, 0u8, 128u8]);
    assert(be32(IV_LENGTH_FIELD) =~= seq![0u8, 0u8, 0u8, 12u8]);
    assert(info =~= info_of(name, iv));
    theorem_roundtrip(ns, name, iv);
}
/// One concrete rejected case: the same bytes with the IV-length field changed from 12 to 16.
pub proof fn witness_rejected_iv_len_16()
    ensures
        ({
            let ns = seq![0x6eu8];
            let name = seq![0x6bu8];
            let info = seq![0x6bu8, 0, 0, 0, 128, 0, 0, 0, 16, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7];
            decode(ns, name, ns, info) is None
        }),
{
    let ns = seq![0x6eu8];
    let name = seq![0x6bu8];
    let info = seq![0x6bu8, 0, 0, 0, 128, 0, 0, 0, 16, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7];
    assert(info.len() == 21);
    assert(info.subrange(0, 1) =~= name);
    assert(info.subrange(1, 5) =~= be32(TAG_LENGTH_BITS));
    assert(info.subrange(5, 9) =~= seq![0u8, 0u8, 0u8, 16u8]);
    assert(be32(IV_LENGTH_FIELD) =~= seq![0u8, 0u8, 0u8, 12u8]);
    assert(be32(TAG_LENGTH_BITS) =~= seq![0u8, 0u8, 0u8, 128u8]);
    assert(info.subrange(5, 9) != be32(IV_LENGTH_FIELD));
    lemma_reject_iv_len_field(ns, name, info);
}
/// The empty key name is a valid input to the codec (the builder only requires the field to be set,
/// :352-353): the info is exactly the 20 bytes of the two fields and the IV.
pub proof fn witness_empty_name(ns: Bytes, iv: Bytes)
    requires
        iv.len() == IV_LENGTH,
    ensures
        info_of(Seq::<u8>::empty(), iv).len() == 20,
        decode(ns, Seq::<u8>::empty(), ns, info_of(Seq::<u8>::empty(), iv)) == Some(iv),
{
    theorem_roundtrip(ns, Seq::<u8>::empty(), iv);
    lemma_layout(Seq::<u8>::empty(), iv);
}
/// Different key names of equal length give different info (the name is not just a label).
pub proof fn witness_two_names_differ()
    ensures
        ({
            let iv = Seq::new(12, |i: int| 7u8);
            info_of(seq![0x61u8], iv) != info_of(seq![0x62u8], iv)
        }),
{
    let iv = Seq::new(12, |i: int| 7u8);
    assert(info_of(seq![0x61u8], iv)[0] == 0x61u8);
    assert(info_of(seq![0x62u8], iv)[0] == 0x62u8);
}
// ============================================================
// SECTION 8: Executable models (R-EXEC)
// ============================================================
/// Model of `u32::to_be_bytes` (A_STD), written with shifts and masks and PROVED equal to the
/// arithmetic `be32`. COPIED from t04_branch_key_wrap.rs :622 (body unchanged). Used at :138-139.
pub fn u32_to_be_bytes(x: u32) -> (r: [u8; 4])
    ensures
        r@ == be32(x),
{
    proof {
        assert((x >> 24u32) == x / 0x1000000u32) by (bit_vector);
        assert(((x >> 16u32) & 0xffu32) == (x / 0x10000u32) % 256u32) by (bit_vector);
        assert(((x >> 8u32) & 0xffu32) == (x / 0x100u32) % 256u32) by (bit_vector);
        assert((x & 0xffu32) == x % 256u32) by (bit_vector);
    }
    let r = [
        (x >> 24) as u8,
        ((x >> 16) & 0xff) as u8,
        ((x >> 8) & 0xff) as u8,
        (x & 0xff) as u8,
    ];
    assert(r@ =~= be32(x));
    r
}
/// Model of `u32::from_be_bytes` (A_STD), with shifts. The result equals the arithmetic `be32_val`.
/// Used at :208 and :214.
pub fn u32_from_be_bytes(a: [u8; 4]) -> (r: u32)
    ensures
        r as int == be32_val(a@),
{
    let b0 = a[0] as u32;
    let b1 = a[1] as u32;
    let b2 = a[2] as u32;
    let b3 = a[3] as u32;
    proof {
        assert(b0 <= 255 && b1 <= 255 && b2 <= 255 && b3 <= 255);
    }
    let r: u32 = (b0 << 24) | (b1 << 16) | (b2 << 8) | b3;
    proof {
        assert(((b0 << 24) | (b1 << 16) | (b2 << 8) | b3) == b0 * 0x1000000u32 + b1 * 0x10000u32
            + b2 * 0x100u32 + b3) by (bit_vector)
            requires
                b0 <= 255 && b1 <= 255 && b2 <= 255 && b3 <= 255,
        ;
        assert(a@[0] as int == b0 as int);
        assert(a@[1] as int == b1 as int);
        assert(a@[2] as int == b2 as int);
        assert(a@[3] as int == b3 as int);
        assert(r as int == (b0 as int) * 16777216 + (b1 as int) * 65536 + (b2 as int) * 256 + (b3
            as int)) by (nonlinear_arith)
            requires
                r == b0 * 0x1000000u32 + b1 * 0x10000u32 + b2 * 0x100u32 + b3,
                b0 <= 255 && b1 <= 255 && b2 <= 255 && b3 <= 255,
        ;
    }
    r
}
/// Model of "copy a 4-byte slice into a [u8;4]" = `slice.try_into().ok()?` at :207 and :213. The
/// `requires` is the condition under which the real `try_into` is `Ok` (A_STD), so the call sites
/// prove that the `None` path of the `?` cannot be taken there.
pub fn array4_from_slice(s: &[u8]) -> (r: [u8; 4])
    requires
        s@.len() == 4,
    ensures
        r@ == s@,
{
    let r = [s[0], s[1], s[2], s[3]];
    assert(r@ =~= s@);
    r
}
/// Model of `<[u8] as PartialEq>::eq` (`!=` at :192 on the id bytes and :202 on the name), A_STD.
pub fn bytes_eq(a: &[u8], b: &[u8]) -> (r: bool)
    ensures
        r == (a@ == b@),
{
    if a.len() != b.len() {
        return false;
    }
    let mut i: usize = 0;
    while i < a.len()
        invariant
            a@.len() == b@.len(),
            i <= a@.len(),
            forall|j: int| 0 <= j < i ==> a@[j] == b@[j],
        decreases a@.len() - i,
    {
        if a[i] != b[i] {
            assert(a@ != b@);
            return false;
        }
        i += 1;
    }
    assert(a@ =~= b@);
    true
}
/// `serialize_provider_info` (:129-142), for any IV length (the `debug_assert!` at :130-134 is not
/// modeled: it is compiled out in release builds, so the model has no precondition on `iv`).
/// `requires` is H_NO_OVERFLOW. Every call is a vstd-specified `Vec` operation.
pub fn serialize_provider_info_exec(name: &[u8], iv: &[u8]) -> (r: Vec<u8>)
    requires
        name@.len() + iv@.len() + 8 <= usize::MAX,
    ensures
        r@ == info_of(name@, iv@),
{
    // :136
    let mut info: Vec<u8> = Vec::with_capacity(name.len() + AUTH_TAG_LEN_LEN + IV_LEN_LEN + iv.len());
    // :137
    info.extend_from_slice(name);
    // :138
    let t = u32_to_be_bytes(TAG_LENGTH_BITS);
    info.extend_from_slice(&t);
    // :139
    let l = u32_to_be_bytes(IV_LENGTH_FIELD);
    info.extend_from_slice(&l);
    // :140
    info.extend_from_slice(iv);
    proof {
        assert(info@ =~= info_of(name@, iv@));
    }
    info
}
/// `decryptable_edk_iv` (:191-219). `ns` is `self.inner.key_namespace`, `name` is
/// `self.inner.key_name.as_bytes()`, `pid` is `edk.key_provider_id()` and `info` is
/// `edk.key_provider_info()`. No precondition on `pid` or `info`: any byte string. The `requires` is
/// H_NO_OVERFLOW on the key name only (the sum at :198).
/// `split_at(k)` is modeled by two index ranges `[0..k]`, `[k..len]` whose bounds Verus checks, which is
/// the condition under which `split_at` does not panic (A_STD). The returned slice is a sub-slice of `info`.
pub fn decryptable_edk_iv_exec<'e>(ns: &[u8], name: &[u8], pid: &[u8], info: &'e [u8]) -> (r: Option<
    &'e [u8],
>)
    requires
        name@.len() + 20 <= usize::MAX,
    ensures
        match r {
            Some(iv) => decode(ns@, name@, pid@, info@) == Some(iv@) && iv@.len() == IV_LENGTH,
            None => decode(ns@, name@, pid@, info@) is None,
        },
{
    // :192-194
    if !bytes_eq(pid, ns) {
        return None;
    }
    // :196-197
    // :198-200
    let n = name.len();
    if info.len() != n + AUTH_TAG_LEN_LEN + IV_LEN_LEN + IV_LENGTH {
        return None;
    }
    // :201 let (info_name, rest) = info.split_at(name.len());
    let info_name = &info[0..n];
    let rest = &info[n..info.len()];
    // :202-204
    if !bytes_eq(info_name, name) {
        return None;
    }
    // :206 let (tag_bits, rest) = rest.split_at(AUTH_TAG_LEN_LEN);
    let tag_bits_s = &rest[0..AUTH_TAG_LEN_LEN];
    let rest2 = &rest[AUTH_TAG_LEN_LEN..rest.len()];
    // :207 try_into().ok()?  (cannot be None: tag_bits_s has 4 bytes)
    let tag_bits = array4_from_slice(tag_bits_s);
    // :208-210
    if u32_from_be_bytes(tag_bits) != TAG_LENGTH_BITS {
        return None;
    }
    // :212 let (iv_len, iv) = rest.split_at(IV_LEN_LEN);
    let iv_len_s = &rest2[0..IV_LEN_LEN];
    let iv = &rest2[IV_LEN_LEN..rest2.len()];
    // :213 try_into().ok()?
    let iv_len = array4_from_slice(iv_len_s);
    // :214-216
    if u32_from_be_bytes(iv_len) != IV_LENGTH_FIELD {
        return None;
    }
    // :218
    proof {
        let ni = n as int;
        assert(info_name@ =~= info@.subrange(0, ni));
        assert(tag_bits_s@ =~= info@.subrange(ni, ni + 4));
        assert(iv_len_s@ =~= info@.subrange(ni + 4, ni + 8));
        assert(iv@ =~= info@.subrange(ni + 8, info@.len() as int));
    }
    Some(iv)
}
/// The exec round trip (TM-MPL-011): what `wrap_data_key` writes (:179-181, provider id = namespace,
/// info from `serialize_provider_info`) is accepted by `decryptable_edk_iv` of the same keyring, and the
/// IV that comes back equals the IV that went in. Needs a 12-byte IV (H_CALLER_IV).
pub fn roundtrip_exec(ns: &[u8], name: &[u8], iv: &[u8]) -> (r: bool)
    requires
        iv@.len() == IV_LENGTH,
        name@.len() + 20 <= usize::MAX,
    ensures
        r,
{
    let info = serialize_provider_info_exec(name, iv);
    let got = decryptable_edk_iv_exec(ns, name, ns, info.as_slice());
    proof {
        theorem_roundtrip(ns@, name@, iv@);
    }
    match got {
        Some(x) => bytes_eq(x, iv),
        None => false,
    }
}
} // verus!
fn main() {}
