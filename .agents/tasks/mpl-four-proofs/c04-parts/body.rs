
/// AlgorithmSuite::encryption_key_length, algorithm_suite.rs :378-380: the table field.
pub open spec fn encryption_key_length(s: Suite) -> usize {
    code_row(s).key_len
}

// ============================================================
// SECTION 2: Two columns of the spec table (A_SPEC_COLS_COPY)
// ============================================================

/// A_SPEC_COLS_COPY: spec "Encryption Key Length (bits)", algorithm-suites.md :239-262, per ESDK suite.
pub open spec fn spec_key_bits(s: Suite) -> int {
    match s {
        Suite::AlgAes128GcmIv12Tag16NoKdf => 128,
        Suite::AlgAes192GcmIv12Tag16NoKdf => 192,
        Suite::AlgAes256GcmIv12Tag16NoKdf => 256,
        Suite::AlgAes128GcmIv12Tag16HkdfSha256 => 128,
        Suite::AlgAes192GcmIv12Tag16HkdfSha256 => 192,
        Suite::AlgAes256GcmIv12Tag16HkdfSha256 => 256,
        Suite::AlgAes128GcmIv12Tag16HkdfSha256EcdsaP256 => 128,
        Suite::AlgAes192GcmIv12Tag16HkdfSha384EcdsaP384 => 192,
        Suite::AlgAes256GcmIv12Tag16HkdfSha384EcdsaP384 => 256,
        Suite::AlgAes256GcmHkdfSha512CommitKey => 256,
        Suite::AlgAes256GcmHkdfSha512CommitKeyEcdsaP384 => 256,
    }
}

/// A_SPEC_COLS_COPY: spec "Key Derivation Input Length (bits)", algorithm-suites.md :214-237, per ESDK suite.
pub open spec fn spec_kdf_in_bits(s: Suite) -> int {
    match s {
        Suite::AlgAes128GcmIv12Tag16NoKdf => 128,
        Suite::AlgAes192GcmIv12Tag16NoKdf => 192,
        Suite::AlgAes256GcmIv12Tag16NoKdf => 256,
        Suite::AlgAes128GcmIv12Tag16HkdfSha256 => 128,
        Suite::AlgAes192GcmIv12Tag16HkdfSha256 => 192,
        Suite::AlgAes256GcmIv12Tag16HkdfSha256 => 256,
        Suite::AlgAes128GcmIv12Tag16HkdfSha256EcdsaP256 => 128,
        Suite::AlgAes192GcmIv12Tag16HkdfSha384EcdsaP384 => 192,
        Suite::AlgAes256GcmIv12Tag16HkdfSha384EcdsaP384 => 256,
        Suite::AlgAes256GcmHkdfSha512CommitKey => 256,
        Suite::AlgAes256GcmHkdfSha512CommitKeyEcdsaP384 => 256,
    }
}

/// The key length of every suite is 16, 24 or 32 bytes, and equals both spec columns divided by 8
/// (the C05 key-length fact, restated for the one column C04 uses).
proof fn lemma_key_len_table(s: Suite)
    ensures
        encryption_key_length(s) == 16 || encryption_key_length(s) == 24 || encryption_key_length(s) == 32,
        encryption_key_length(s) as int * 8 == spec_key_bits(s),
        encryption_key_length(s) as int * 8 == spec_kdf_in_bits(s),
{
    match s {
        Suite::AlgAes128GcmIv12Tag16NoKdf => {},
        Suite::AlgAes192GcmIv12Tag16NoKdf => {},
        Suite::AlgAes256GcmIv12Tag16NoKdf => {},
        Suite::AlgAes128GcmIv12Tag16HkdfSha256 => {},
        Suite::AlgAes192GcmIv12Tag16HkdfSha256 => {},
        Suite::AlgAes256GcmIv12Tag16HkdfSha256 => {},
        Suite::AlgAes128GcmIv12Tag16HkdfSha256EcdsaP256 => {},
        Suite::AlgAes192GcmIv12Tag16HkdfSha384EcdsaP384 => {},
        Suite::AlgAes256GcmIv12Tag16HkdfSha384EcdsaP384 => {},
        Suite::AlgAes256GcmHkdfSha512CommitKey => {},
        Suite::AlgAes256GcmHkdfSha512CommitKeyEcdsaP384 => {},
    }
}

// ============================================================
// SECTION 3: The model of materials, the check, and every path (section 3 of the header)
// ============================================================

/// PlaintextDataKey(Vec<u8>), modeled by its length (algorithm_suite.rs :506, `len` :529).
pub struct Pdk {
    pub len: usize,
}

/// EncryptionMaterials / DecryptionMaterials, the two fields that matter (H_ENC_DEC_SAME).
pub struct Mat {
    pub suite: Suite,
    pub pdk: Option<Pdk>,
}

/// EncryptionMaterialsBuilder / DecryptionMaterialsBuilder state. Any value is a legal builder
/// state: the setters store without a check (A5).
pub struct Bld {
    pub suite: Option<Suite>,
    pub pdk: Option<Pdk>,
}

/// Error kinds, abstract (A_ERR).
pub enum MErr {
    InvalidMaterials,
    Validation,
    Cryptographic,
    NoMatchingDataKey,
    Other,
}

/// The C04 invariant: a present PDK has the encryption key length of the suite of the same
/// materials. An absent PDK satisfies it.
pub open spec fn pdk_ok(m: Mat) -> bool {
    match m.pdk {
        Some(k) => k.len == encryption_key_length(m.suite),
        None => true,
    }
}

/// check_data_key_length, algorithm_suite.rs :547-562.
pub open spec fn check_data_key_length(s: Suite, k: Pdk) -> Result<(), MErr> {
    if k.len != encryption_key_length(s) {
        Err(MErr::InvalidMaterials)
    } else {
        Ok(())
    }
}

/// EncryptionMaterials::add_data_key, encryption_materials.rs :48-64.
pub open spec fn enc_add_data_key(m: Mat, k: Pdk) -> Result<Mat, MErr> {
    if m.pdk is Some {
        Err(MErr::InvalidMaterials)
    } else {
        match check_data_key_length(m.suite, k) {
            Err(e) => Err(e),
            Ok(_) => Ok(Mat { suite: m.suite, pdk: Some(k) }),
        }
    }
}

/// DecryptionMaterials::add_data_key, decryption_materials.rs :45-59.
pub open spec fn dec_add_data_key(m: Mat, k: Pdk) -> Result<Mat, MErr> {
    if m.pdk is Some {
        Err(MErr::InvalidMaterials)
    } else {
        match check_data_key_length(m.suite, k) {
            Err(e) => Err(e),
            Ok(_) => Ok(Mat { suite: m.suite, pdk: Some(k) }),
        }
    }
}

/// EncryptionMaterials::add_encrypted_data_key, encryption_materials.rs :71-83. The list of
/// encrypted data keys is not modeled. The suite and the PDK are unchanged.
pub open spec fn enc_add_edk(m: Mat) -> Result<Mat, MErr> {
    if m.pdk is None {
        Err(MErr::InvalidMaterials)
    } else {
        Ok(m)
    }
}

/// EncryptionMaterialsBuilder::build, encryption_materials.rs :358-436. `other_ok` is every other
/// check of `build` (A_OTHER_OK, H_BUILD_OTHER). The checked suite is the stored suite (H_BUILD_SAME_SUITE).
pub open spec fn enc_build(b: Bld, other_ok: bool) -> Result<Mat, MErr> {
    match b.suite {
        None => Err(MErr::Validation),
        Some(sid) => {
            let pdk_check: Result<(), MErr> = match b.pdk {
                Some(k) => check_data_key_length(sid, k),
                None => Ok(()),
            };
            match pdk_check {
                Err(e) => Err(e),
                Ok(_) => {
                    if other_ok {
                        Ok(Mat { suite: sid, pdk: b.pdk })
                    } else {
                        Err(MErr::Other)
                    }
                },
            }
        },
    }
}

/// DecryptionMaterialsBuilder::build, decryption_materials.rs :295-357.
pub open spec fn dec_build(b: Bld, other_ok: bool) -> Result<Mat, MErr> {
    match b.suite {
        None => Err(MErr::Validation),
        Some(sid) => {
            let pdk_check: Result<(), MErr> = match b.pdk {
                Some(k) => check_data_key_length(sid, k),
                None => Ok(()),
            };
            match pdk_check {
                Err(e) => Err(e),
                Ok(_) => {
                    if other_ok {
                        Ok(Mat { suite: sid, pdk: b.pdk })
                    } else {
                        Err(MErr::Other)
                    }
                },
            }
        },
    }
}

/// The PDK a keyring generates for `s`: `vec![0u8; suite.encryption_key_length()]`, then a fill
/// that cannot change the length (H_VEC_LEN, H_FILL_SLICE). Both keyrings (B1, B2).
pub open spec fn gen_pdk(s: Suite) -> Pdk {
    Pdk { len: encryption_key_length(s) }
}

/// raw_aes_keyring on_encrypt, :399-420.
pub open spec fn raw_enc(m: Mat) -> Result<Mat, MErr> {
    match m.pdk {
        Some(_) => enc_add_edk(m),
        None => enc_add_data_key(m, gen_pdk(m.suite)),
    }
}

/// hierarchical_keyring on_encrypt, :654-732: `pdk.clone()` when present, else a generated key;
/// `add_data_key` only for a generated key.
pub open spec fn hier_enc(m: Mat) -> Result<Mat, MErr> {
    let kg: (Pdk, bool) = match m.pdk {
        Some(p) => (p, false),
        None => (gen_pdk(m.suite), true),
    };
    if kg.1 {
        enc_add_data_key(m, kg.0)
    } else {
        enc_add_edk(m)
    }
}

/// raw_aes_keyring on_decrypt, :422-530. `ns[i]` is the plaintext length of the i-th EDK that
/// reached the length test at :489 (H_RAW_DEC_LOOP). The length is arbitrary.
pub open spec fn raw_dec(m: Mat, ns: Seq<usize>) -> Result<Mat, MErr>
    decreases ns.len(),
{
    if m.pdk is Some {
        Err(MErr::InvalidMaterials)
    } else if ns.len() == 0 {
        Err(MErr::Cryptographic)
    } else if ns[0] != encryption_key_length(m.suite) {
        raw_dec(m, ns.drop_first())
    } else {
        dec_add_data_key(m, Pdk { len: ns[0] })
    }
}

/// hierarchical_keyring on_decrypt, :734-802. `rs[i]` is `Some(n)` when `try_decrypt_edk` of the
/// i-th EDK returned n bytes, `None` when the EDK was filtered out or failed (H_HIER_DEC_LOOP).
/// There is no length test before `add_data_key`.
pub open spec fn hier_dec(m: Mat, rs: Seq<Option<usize>>) -> Result<Mat, MErr>
    decreases rs.len(),
{
    if m.pdk is Some {
        Err(MErr::InvalidMaterials)
    } else if rs.len() == 0 {
        Err(MErr::NoMatchingDataKey)
    } else {
        match rs[0] {
            Some(n) => dec_add_data_key(m, Pdk { len: n }),
            None => hier_dec(m, rs.drop_first()),
        }
    }
}

/// One operation on a materials value. Every operation that can write the PDK field or create PDK
/// bytes (section 3 of the header). `EncAdd`, `DecAdd`, `EncAddEdk` take any caller input.
pub enum Step {
    EncAdd(Pdk),
    EncAddEdk,
    DecAdd(Pdk),
    CloneMat,
    RawEnc,
    HierEnc,
    RawDec(Seq<usize>),
    HierDec(Seq<Option<usize>>),
}

pub open spec fn step(m: Mat, s: Step) -> Result<Mat, MErr> {
    match s {
        Step::EncAdd(k) => enc_add_data_key(m, k),
        Step::EncAddEdk => enc_add_edk(m),
        Step::DecAdd(k) => dec_add_data_key(m, k),
        Step::CloneMat => Ok(m),
        Step::RawEnc => raw_enc(m),
        Step::HierEnc => hier_enc(m),
        Step::RawDec(ns) => raw_dec(m, ns),
        Step::HierDec(rs) => hier_dec(m, rs),
    }
}

/// Apply the steps in order; stop at the first Err.
pub open spec fn run(m: Mat, steps: Seq<Step>) -> Result<Mat, MErr>
    decreases steps.len(),
{
    if steps.len() == 0 {
        Ok(m)
    } else {
        match step(m, steps[0]) {
            Err(e) => Err(e),
            Ok(m2) => run(m2, steps.drop_first()),
        }
    }
}

// ============================================================
// SECTION 4: Local lemmas for every path, then the closure
// ============================================================

/// P1: the check is Ok exactly when the length is the suite's.
proof fn theorem_check_exact(s: Suite, k: Pdk)
    ensures
        check_data_key_length(s, k) is Ok <==> k.len == encryption_key_length(s),
        check_data_key_length(s, k) is Err <==> k.len != encryption_key_length(s),
{
}

/// P2, add_data_key paths: Ok exactly when no PDK is present and the length is right; then the
/// stored PDK is the one passed and the suite is unchanged.
proof fn theorem_add_data_key_exact(m: Mat, k: Pdk)
    ensures
        (enc_add_data_key(m, k) is Ok) <==> (m.pdk is None && k.len == encryption_key_length(m.suite)),
        (dec_add_data_key(m, k) is Ok) <==> (m.pdk is None && k.len == encryption_key_length(m.suite)),
        enc_add_data_key(m, k) matches Ok(r) ==> r == (Mat { suite: m.suite, pdk: Some(k) }),
        dec_add_data_key(m, k) matches Ok(r) ==> r == (Mat { suite: m.suite, pdk: Some(k) }),
{
}

/// P2, build paths: Ok exactly when a suite is set, `other_ok` holds and the PDK, if any, has the
/// suite's length; then the materials carry exactly the builder's suite and PDK.
proof fn theorem_build_exact(b: Bld, other_ok: bool)
    ensures
        (enc_build(b, other_ok) is Ok) <==> (b.suite is Some && other_ok && (b.pdk matches Some(k) ==> k.len
            == encryption_key_length(b.suite->Some_0))),
        (dec_build(b, other_ok) is Ok) <==> (b.suite is Some && other_ok && (b.pdk matches Some(k) ==> k.len
            == encryption_key_length(b.suite->Some_0))),
        enc_build(b, other_ok) matches Ok(r) ==> r == (Mat { suite: b.suite->Some_0, pdk: b.pdk }),
        dec_build(b, other_ok) matches Ok(r) ==> r == (Mat { suite: b.suite->Some_0, pdk: b.pdk }),
        enc_build(b, other_ok) matches Ok(r) ==> pdk_ok(r),
        dec_build(b, other_ok) matches Ok(r) ==> pdk_ok(r),
{
}

/// P3, generators: the generated PDK passes the check and has the suite length. The spec requires
/// the length of a generated key to equal the KDF input length (keyring-interface.md :147).
proof fn lemma_gen_pdk(s: Suite)
    ensures
        gen_pdk(s).len == encryption_key_length(s),
        check_data_key_length(s, gen_pdk(s)) is Ok,
        gen_pdk(s).len as int * 8 == spec_kdf_in_bits(s),
{
    lemma_key_len_table(s);
}

/// P3, raw-AES decrypt: for any list of lengths, Ok only with a PDK of the suite length, and the
/// suite is unchanged. The result is Err when materials already hold a PDK.
proof fn lemma_raw_dec(m: Mat, ns: Seq<usize>)
    requires
        pdk_ok(m),
    ensures
        raw_dec(m, ns) matches Ok(r) ==> pdk_ok(r) && r.suite == m.suite && r.pdk is Some,
        m.pdk is Some ==> raw_dec(m, ns) is Err,
    decreases ns.len(),
{
    if m.pdk is None && ns.len() > 0 && ns[0] != encryption_key_length(m.suite) {
        lemma_raw_dec(m, ns.drop_first());
    }
}

/// P3, hierarchical decrypt: for any list of results, Ok only with a PDK of the suite length, and
/// the suite is unchanged. There is no length test before `add_data_key`; the check inside it is
/// the only gate.
proof fn lemma_hier_dec(m: Mat, rs: Seq<Option<usize>>)
    requires
        pdk_ok(m),
    ensures
        hier_dec(m, rs) matches Ok(r) ==> pdk_ok(r) && r.suite == m.suite && r.pdk is Some,
        m.pdk is Some ==> hier_dec(m, rs) is Err,
    decreases rs.len(),
{
    if m.pdk is None && rs.len() > 0 && rs[0] is None {
        lemma_hier_dec(m, rs.drop_first());
    }
}

/// Liveness witness for the decrypt paths: if no PDK is present and some EDK yields the right
/// length, `raw_dec` is Ok. Without it the safety lemma would hold for a function that always fails.
proof fn lemma_decrypt_succeeds_on_right_length(m: Mat, ns: Seq<usize>, i: int)
    requires
        m.pdk is None,
        0 <= i < ns.len(),
        ns[i] == encryption_key_length(m.suite),
    ensures
        raw_dec(m, ns) is Ok,
    decreases ns.len(),
{
    if ns[0] != encryption_key_length(m.suite) {
        assert(i >= 1);
        assert(ns.drop_first()[i - 1] == ns[i]);
        lemma_decrypt_succeeds_on_right_length(m, ns.drop_first(), i - 1);
    }
}

/// The inductive step: one path from a materials value with `pdk_ok` gives `pdk_ok` and the same
/// suite. P3 for the encrypt paths and the four accept paths.
proof fn lemma_step_preserves(m: Mat, s: Step)
    requires
        pdk_ok(m),
    ensures
        step(m, s) matches Ok(r) ==> pdk_ok(r) && r.suite == m.suite,
{
    match s {
        Step::EncAdd(_) => {},
        Step::EncAddEdk => {},
        Step::DecAdd(_) => {},
        Step::CloneMat => {},
        Step::RawEnc => {},
        Step::HierEnc => {},
        Step::RawDec(ns) => { lemma_raw_dec(m, ns); },
        Step::HierDec(rs) => { lemma_hier_dec(m, rs); },
    }
}

/// Transcription check: `step` dispatches each `Step` to the path function of the same name. This
/// is true by the definition of `step`. It is here so that an edit of `step` that drops or swaps a
/// path (and so removes it from the closure) is rejected.
proof fn lemma_step_dispatch(m: Mat)
    ensures
        forall|k: Pdk| #[trigger] step(m, Step::EncAdd(k)) == enc_add_data_key(m, k),
        forall|k: Pdk| #[trigger] step(m, Step::DecAdd(k)) == dec_add_data_key(m, k),
        step(m, Step::EncAddEdk) == enc_add_edk(m),
        step(m, Step::CloneMat) == Ok::<Mat, MErr>(m),
        step(m, Step::RawEnc) == raw_enc(m),
        step(m, Step::HierEnc) == hier_enc(m),
        forall|ns: Seq<usize>| #[trigger] step(m, Step::RawDec(ns)) == raw_dec(m, ns),
        forall|rs: Seq<Option<usize>>| #[trigger] step(m, Step::HierDec(rs)) == hier_dec(m, rs),
{
}

/// Induction over any sequence of paths.
proof fn lemma_run_preserves(m: Mat, steps: Seq<Step>)
    requires
        pdk_ok(m),
    ensures
        run(m, steps) matches Ok(r) ==> pdk_ok(r) && r.suite == m.suite,
    decreases steps.len(),
{
    if steps.len() > 0 {
        lemma_step_preserves(m, steps[0]);
        match step(m, steps[0]) {
            Ok(m2) => { lemma_run_preserves(m2, steps.drop_first()); },
            Err(_) => {},
        }
    }
}

/// P3 summary: the producer and encrypt paths, stated for every suite and materials value.
proof fn theorem_producers_exact(m: Mat)
    requires
        pdk_ok(m),
    ensures
        raw_enc(m) matches Ok(r) ==> pdk_ok(r) && r.pdk is Some,
        hier_enc(m) matches Ok(r) ==> pdk_ok(r) && r.pdk is Some,
        m.pdk is None ==> raw_enc(m) is Ok,
        m.pdk is None ==> hier_enc(m) is Ok,
        forall|ns: Seq<usize>| #[trigger] raw_dec(m, ns) matches Ok(r) ==> pdk_ok(r) && r.pdk is Some,
        forall|rs: Seq<Option<usize>>| #[trigger] hier_dec(m, rs) matches Ok(r) ==> pdk_ok(r) && r.pdk is Some,
{
    assert forall|ns: Seq<usize>| #[trigger] raw_dec(m, ns) matches Ok(r) ==> pdk_ok(r) && r.pdk is Some by {
        lemma_raw_dec(m, ns);
    }
    assert forall|rs: Seq<Option<usize>>| #[trigger] hier_dec(m, rs) matches Ok(r) ==> pdk_ok(r) && r.pdk is Some by {
        lemma_hier_dec(m, rs);
    }
    lemma_gen_pdk(m.suite);
}

/// P4: the closure. From any builder state (any suite, any PDK of any length, any `other_ok`),
/// build, then apply any finite sequence of the modeled paths. Every Ok value has `pdk_ok` and
/// the suite chosen at build. The only inputs the proof does not constrain are the lengths.
proof fn theorem_c04_closure(b: Bld, other_ok: bool, steps: Seq<Step>)
    ensures
        enc_build(b, other_ok) matches Ok(m) ==> (run(m, steps) matches Ok(r) ==> pdk_ok(r) && r.suite == m.suite
            && m.suite == b.suite->Some_0),
        dec_build(b, other_ok) matches Ok(m) ==> (run(m, steps) matches Ok(r) ==> pdk_ok(r) && r.suite == m.suite
            && m.suite == b.suite->Some_0),
{
    theorem_build_exact(b, other_ok);
    match enc_build(b, other_ok) {
        Ok(m) => { lemma_run_preserves(m, steps); },
        Err(_) => {},
    }
    match dec_build(b, other_ok) {
        Ok(m) => { lemma_run_preserves(m, steps); },
        Err(_) => {},
    }
}

/// P5: a present PDK of a materials value that satisfies the invariant has the length the spec
/// asks for, in bits, in both spec columns, and the length is 16, 24 or 32 bytes (A_FIT).
proof fn theorem_pdk_matches_spec_bits(m: Mat)
    requires
        pdk_ok(m),
    ensures
        m.pdk matches Some(k) ==> k.len as int * 8 == spec_key_bits(m.suite),
        m.pdk matches Some(k) ==> k.len as int * 8 == spec_kdf_in_bits(m.suite),
        m.pdk matches Some(k) ==> (k.len == 16 || k.len == 24 || k.len == 32),
{
    lemma_key_len_table(m.suite);
}

// ============================================================
// SECTION 5: Exec forms of the three small functions
// ============================================================

/// `encryption_key_length()`, executable form of the table lookup.
fn encryption_key_length_exec(s: Suite) -> (r: usize)
    ensures
        r == encryption_key_length(s),
{
    match s {
        Suite::AlgAes128GcmIv12Tag16NoKdf => 16,
        Suite::AlgAes192GcmIv12Tag16NoKdf => 24,
        Suite::AlgAes256GcmIv12Tag16NoKdf => 32,
        Suite::AlgAes128GcmIv12Tag16HkdfSha256 => 16,
        Suite::AlgAes192GcmIv12Tag16HkdfSha256 => 24,
        Suite::AlgAes256GcmIv12Tag16HkdfSha256 => 32,
        Suite::AlgAes128GcmIv12Tag16HkdfSha256EcdsaP256 => 16,
        Suite::AlgAes192GcmIv12Tag16HkdfSha384EcdsaP384 => 24,
        Suite::AlgAes256GcmIv12Tag16HkdfSha384EcdsaP384 => 32,
        Suite::AlgAes256GcmHkdfSha512CommitKey => 32,
        Suite::AlgAes256GcmHkdfSha512CommitKeyEcdsaP384 => 32,
    }
}

/// `check_data_key_length`, algorithm_suite.rs :547-562: `expected_len = suite.encryption_key_length();
/// if key.len() != expected_len { return Err(..) } Ok(())`.
fn check_data_key_length_exec(s: Suite, key_len: usize) -> (r: Result<(), MErr>)
    ensures
        r == check_data_key_length(s, Pdk { len: key_len }),
{
    let expected_len = encryption_key_length_exec(s);
    if key_len != expected_len {
        Err(MErr::InvalidMaterials)
    } else {
        Ok(())
    }
}

/// `generate_random_data_key`, raw_aes_keyring.rs :535-545 and hierarchical_keyring.rs :975-985,
/// success case: allocate `vec![0u8; suite.encryption_key_length()]`, fill it (not modeled; the
/// fill takes `&mut [u8]` and cannot change the length, H_FILL_SLICE), wrap it.
fn generate_exec(s: Suite) -> (r: Pdk)
    ensures
        r == gen_pdk(s),
{
    let bytes: Vec<u8> = vec![0u8; encryption_key_length_exec(s)];
    Pdk { len: bytes.len() }
}

/// P1, exec side: the exec check agrees with the spec check for every input.
proof fn theorem_check_exact_exec_agrees(s: Suite, key_len: usize)
    ensures
        check_data_key_length(s, Pdk { len: key_len }) is Ok <==> key_len == encryption_key_length(s),
{
}

// ============================================================
// SECTION 6: Non-vacuity witnesses
// ============================================================

/// For every suite: the right length is accepted by the check and by both builders, one byte
/// shorter, one byte longer and empty are rejected, and the type alone allows a wrong-length PDK
/// (it is `pdk_ok` that excludes it). So the invariant is not trivially true.
proof fn lemma_witnesses(s: Suite)
    ensures
        check_data_key_length(s, Pdk { len: encryption_key_length(s) }) is Ok,
        check_data_key_length(s, Pdk { len: (encryption_key_length(s) + 1) as usize }) is Err,
        check_data_key_length(s, Pdk { len: (encryption_key_length(s) - 1) as usize }) is Err,
        check_data_key_length(s, Pdk { len: 0 }) is Err,
        enc_build(Bld { suite: Some(s), pdk: Some(Pdk { len: encryption_key_length(s) }) }, true) is Ok,
        dec_build(Bld { suite: Some(s), pdk: Some(Pdk { len: encryption_key_length(s) }) }, true) is Ok,
        enc_build(Bld { suite: Some(s), pdk: Some(Pdk { len: (encryption_key_length(s) + 1) as usize }) }, true) is Err,
        dec_build(Bld { suite: Some(s), pdk: Some(Pdk { len: (encryption_key_length(s) - 1) as usize }) }, true) is Err,
        enc_add_data_key(Mat { suite: s, pdk: None }, Pdk { len: encryption_key_length(s) }) is Ok,
        dec_add_data_key(Mat { suite: s, pdk: None }, Pdk { len: (encryption_key_length(s) + 1) as usize }) is Err,
        !pdk_ok(Mat { suite: s, pdk: Some(Pdk { len: (encryption_key_length(s) + 1) as usize }) }),
{
    lemma_key_len_table(s);
}

/// A materials value with a PDK is reachable: build with no PDK, then a generating keyring, then
/// a second `add_data_key` is rejected. Shows `pdk_ok` is checked on a non-empty set.
proof fn lemma_run_witness(s: Suite)
    ensures
        enc_build(Bld { suite: Some(s), pdk: None }, true) is Ok,
        run(Mat { suite: s, pdk: None }, seq![Step::RawEnc]) is Ok,
        run(Mat { suite: s, pdk: None }, seq![Step::RawEnc]) matches Ok(r) ==> (r.pdk is Some && pdk_ok(r)),
        run(Mat { suite: s, pdk: None }, seq![Step::RawEnc, Step::EncAdd(Pdk { len: encryption_key_length(s) })])
            is Err,
{
    let m0 = Mat { suite: s, pdk: None };
    let k = Pdk { len: encryption_key_length(s) };
    let m1 = Mat { suite: s, pdk: Some(k) };
    let one = seq![Step::RawEnc];
    let two = seq![Step::RawEnc, Step::EncAdd(k)];
    reveal_with_fuel(run, 3);
    assert(one[0] == Step::RawEnc);
    assert(two[0] == Step::RawEnc);
    assert(step(m0, Step::RawEnc) == Ok::<Mat, MErr>(m1));
    assert(one.drop_first() =~= Seq::<Step>::empty());
    assert(two.drop_first() =~= seq![Step::EncAdd(k)]);
    assert(seq![Step::EncAdd(k)].drop_first() =~= Seq::<Step>::empty());
    assert(raw_enc(m0) == Ok::<Mat, MErr>(m1));
    assert(run(m0, one) == Ok::<Mat, MErr>(m1));
    assert(seq![Step::EncAdd(k)][0] == Step::EncAdd(k));
    assert(run(m1, seq![Step::EncAdd(k)]) is Err);
    assert(run(m0, two) is Err);
}

// ============================================================
// SECTION 7: Summary theorem
// ============================================================

/// P7: for arbitrary inputs, the model of every accept and producer path keeps `pdk_ok`.
proof fn theorem_c04_summary(s: Suite, b: Bld, other_ok: bool, steps: Seq<Step>, k: Pdk)
    ensures
        check_data_key_length(s, k) is Ok <==> k.len == encryption_key_length(s),
        enc_add_data_key(Mat { suite: s, pdk: None }, k) matches Ok(r) ==> pdk_ok(r),
        dec_add_data_key(Mat { suite: s, pdk: None }, k) matches Ok(r) ==> pdk_ok(r),
        enc_build(b, other_ok) matches Ok(r) ==> pdk_ok(r),
        dec_build(b, other_ok) matches Ok(r) ==> pdk_ok(r),
        check_data_key_length(s, gen_pdk(s)) is Ok,
        enc_build(b, other_ok) matches Ok(m) ==> (run(m, steps) matches Ok(r) ==> pdk_ok(r)),
        dec_build(b, other_ok) matches Ok(m) ==> (run(m, steps) matches Ok(r) ==> pdk_ok(r)),
{
    theorem_build_exact(b, other_ok);
    lemma_gen_pdk(s);
    theorem_c04_closure(b, other_ok, steps);
}

} // verus!
fn main() {}
