/// EsdkAlgorithmSuiteId, :69-92. Same variant names as the code.
pub enum Suite {
    AlgAes128GcmIv12Tag16NoKdf,
    AlgAes192GcmIv12Tag16NoKdf,
    AlgAes256GcmIv12Tag16NoKdf,
    AlgAes128GcmIv12Tag16HkdfSha256,
    AlgAes192GcmIv12Tag16HkdfSha256,
    AlgAes256GcmIv12Tag16HkdfSha256,
    AlgAes128GcmIv12Tag16HkdfSha256EcdsaP256,
    AlgAes192GcmIv12Tag16HkdfSha384EcdsaP384,
    AlgAes256GcmIv12Tag16HkdfSha384EcdsaP384,
    AlgAes256GcmHkdfSha512CommitKey,
    AlgAes256GcmHkdfSha512CommitKeyEcdsaP384,
}

pub enum CEnc { Aes }
pub enum CMode { Gcm }
/// KeyDerivationAlgorithm, algorithm_suite.rs.
pub enum CKdf { IdentityKdf, HkdfSha256, HkdfSha384, HkdfSha512 }
/// AsymmetricSignatureAlgorithm.
pub enum CAsym { EcdsaP256, EcdsaP384 }
/// SymmetricSignatureAlgorithm.
pub enum CSym { HmacSha384 }

/// AlgorithmSuite, :344-357 (the fields C05 is about).
pub struct CRow {
    pub id0: u8,
    pub id1: u8,
    pub enc: CEnc,
    pub mode: CMode,
    pub key_len: usize,
    pub iv_len: usize,
    pub tag_len: usize,
    pub enc_kdf: CKdf,
    pub commit_kdf: Option<CKdf>,
    pub asym: Option<CAsym>,
    pub sym: Option<CSym>,
    pub fmt: u8,
    pub data_len: usize,
}

/// A_CODE_COPY: EsdkAlgorithmSuiteId::specification, :144-305, one arm per variant.
pub open spec fn code_row(s: Suite) -> CRow {
    match s {
        Suite::AlgAes128GcmIv12Tag16NoKdf => CRow {
            id0: 0x00, id1: 0x14, enc: CEnc::Aes, mode: CMode::Gcm,
            key_len: 16, iv_len: 12, tag_len: 16,
            enc_kdf: CKdf::IdentityKdf, commit_kdf: None,
            asym: None, sym: None, fmt: 0x01, data_len: 0,
        },
        Suite::AlgAes192GcmIv12Tag16NoKdf => CRow {
            id0: 0x00, id1: 0x46, enc: CEnc::Aes, mode: CMode::Gcm,
            key_len: 24, iv_len: 12, tag_len: 16,
            enc_kdf: CKdf::IdentityKdf, commit_kdf: None,
            asym: None, sym: None, fmt: 0x01, data_len: 0,
        },
        Suite::AlgAes256GcmIv12Tag16NoKdf => CRow {
            id0: 0x00, id1: 0x78, enc: CEnc::Aes, mode: CMode::Gcm,
            key_len: 32, iv_len: 12, tag_len: 16,
            enc_kdf: CKdf::IdentityKdf, commit_kdf: None,
            asym: None, sym: None, fmt: 0x01, data_len: 0,
        },
        Suite::AlgAes128GcmIv12Tag16HkdfSha256 => CRow {
            id0: 0x01, id1: 0x14, enc: CEnc::Aes, mode: CMode::Gcm,
            key_len: 16, iv_len: 12, tag_len: 16,
            enc_kdf: CKdf::HkdfSha256, commit_kdf: None,
            asym: None, sym: None, fmt: 0x01, data_len: 0,
        },
        Suite::AlgAes192GcmIv12Tag16HkdfSha256 => CRow {
            id0: 0x01, id1: 0x46, enc: CEnc::Aes, mode: CMode::Gcm,
            key_len: 24, iv_len: 12, tag_len: 16,
            enc_kdf: CKdf::HkdfSha256, commit_kdf: None,
            asym: None, sym: None, fmt: 0x01, data_len: 0,
        },
        Suite::AlgAes256GcmIv12Tag16HkdfSha256 => CRow {
            id0: 0x01, id1: 0x78, enc: CEnc::Aes, mode: CMode::Gcm,
            key_len: 32, iv_len: 12, tag_len: 16,
            enc_kdf: CKdf::HkdfSha256, commit_kdf: None,
            asym: None, sym: None, fmt: 0x01, data_len: 0,
        },
        Suite::AlgAes128GcmIv12Tag16HkdfSha256EcdsaP256 => CRow {
            id0: 0x02, id1: 0x14, enc: CEnc::Aes, mode: CMode::Gcm,
            key_len: 16, iv_len: 12, tag_len: 16,
            enc_kdf: CKdf::HkdfSha256, commit_kdf: None,
            asym: Some(CAsym::EcdsaP256), sym: None, fmt: 0x01, data_len: 0,
        },
        Suite::AlgAes192GcmIv12Tag16HkdfSha384EcdsaP384 => CRow {
            id0: 0x03, id1: 0x46, enc: CEnc::Aes, mode: CMode::Gcm,
            key_len: 24, iv_len: 12, tag_len: 16,
            enc_kdf: CKdf::HkdfSha384, commit_kdf: None,
            asym: Some(CAsym::EcdsaP384), sym: None, fmt: 0x01, data_len: 0,
        },
        Suite::AlgAes256GcmIv12Tag16HkdfSha384EcdsaP384 => CRow {
            id0: 0x03, id1: 0x78, enc: CEnc::Aes, mode: CMode::Gcm,
            key_len: 32, iv_len: 12, tag_len: 16,
            enc_kdf: CKdf::HkdfSha384, commit_kdf: None,
            asym: Some(CAsym::EcdsaP384), sym: None, fmt: 0x01, data_len: 0,
        },
        Suite::AlgAes256GcmHkdfSha512CommitKey => CRow {
            id0: 0x04, id1: 0x78, enc: CEnc::Aes, mode: CMode::Gcm,
            key_len: 32, iv_len: 12, tag_len: 16,
            enc_kdf: CKdf::HkdfSha512, commit_kdf: Some(CKdf::HkdfSha512),
            asym: None, sym: None, fmt: 0x02, data_len: 32,
        },
        Suite::AlgAes256GcmHkdfSha512CommitKeyEcdsaP384 => CRow {
            id0: 0x05, id1: 0x78, enc: CEnc::Aes, mode: CMode::Gcm,
            key_len: 32, iv_len: 12, tag_len: 16,
            enc_kdf: CKdf::HkdfSha512, commit_kdf: Some(CKdf::HkdfSha512),
            asym: Some(CAsym::EcdsaP384), sym: None, fmt: 0x02, data_len: 32,
        },
    }
}
