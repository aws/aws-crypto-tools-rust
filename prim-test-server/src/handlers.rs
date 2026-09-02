//! Operation handlers — stateless dispatch to `aws-mpl-primitives`.

use crate::error::ServerError;
use crate::model::*;
use aws_mpl_primitives::{self as prim, AesGcm, DigestAlg, EcdsaSignatureAlgorithm};

// ─── Mapping helpers ────────────────────────────────────────────────────────

fn map_aes_alg(alg: AesAlgorithm) -> AesGcm {
    match alg {
        AesAlgorithm::Aes128Gcm => AesGcm::Aes128Gcm,
        AesAlgorithm::Aes192Gcm => AesGcm::Aes192Gcm,
        AesAlgorithm::Aes256Gcm => AesGcm::Aes256Gcm,
    }
}

fn map_digest_alg(alg: DigestAlgorithm) -> DigestAlg {
    match alg {
        DigestAlgorithm::Sha256 => DigestAlg::Sha256,
        DigestAlgorithm::Sha384 => DigestAlg::Sha384,
        DigestAlgorithm::Sha512 => DigestAlg::Sha512,
    }
}

fn map_ecdsa_alg(alg: EcdsaAlgorithm) -> EcdsaSignatureAlgorithm {
    match alg {
        EcdsaAlgorithm::EcdsaP256 => EcdsaSignatureAlgorithm::EcdsaP256,
        EcdsaAlgorithm::EcdsaP384 => EcdsaSignatureAlgorithm::EcdsaP384,
    }
}

fn prim_err(e: prim::Error) -> ServerError {
    ServerError::primitives(e.message)
}

// ─── AES ────────────────────────────────────────────────────────────────────

const AES_GCM_TAG_LEN: usize = 16;

pub fn aes_encrypt(req: AesEncryptRequest) -> Result<AesEncryptResponse, ServerError> {
    let alg = map_aes_alg(req.algorithm);
    let mut cipher_text = Vec::new();
    prim::aes_encrypt(
        alg,
        &req.iv,
        &req.key,
        &req.message,
        &req.aad,
        &mut cipher_text,
    )
    .map_err(prim_err)?;

    // aes_encrypt appends ciphertext + tag; split the tag off
    let tag_start = cipher_text.len().saturating_sub(AES_GCM_TAG_LEN);
    let auth_tag = cipher_text.split_off(tag_start);

    Ok(AesEncryptResponse {
        ciphertext: cipher_text,
        auth_tag,
    })
}

pub fn aes_decrypt(req: AesDecryptRequest) -> Result<AesDecryptResponse, ServerError> {
    let alg = map_aes_alg(req.algorithm);
    let mut plaintext = vec![0u8; req.ciphertext.len()];
    prim::aes_decrypt(
        alg,
        &req.key,
        &req.ciphertext,
        &req.auth_tag,
        &req.iv,
        &req.aad,
        &mut plaintext,
    )
    .map_err(prim_err)?;
    Ok(AesDecryptResponse { plaintext })
}

// ─── Random ─────────────────────────────────────────────────────────────────

pub fn generate_random_bytes(
    req: GenerateRandomBytesRequest,
) -> Result<GenerateRandomBytesResponse, ServerError> {
    let mut data = vec![0u8; req.length as usize];
    prim::generate_random_bytes(&mut data).map_err(prim_err)?;
    Ok(GenerateRandomBytesResponse { data })
}

// ─── Digest ─────────────────────────────────────────────────────────────────

pub fn digest(req: DigestRequest) -> Result<DigestResponse, ServerError> {
    let alg = map_digest_alg(req.algorithm);
    let mut digest = vec![0u8; alg.output_len()];
    prim::digest(alg, &req.data, &mut digest).map_err(prim_err)?;
    Ok(DigestResponse { digest })
}

// ─── HMAC ───────────────────────────────────────────────────────────────────

pub fn hmac(req: HmacRequest) -> Result<HmacResponse, ServerError> {
    let alg = map_digest_alg(req.algorithm);
    let mut digest = vec![0u8; alg.output_len()];
    prim::hmac(alg, &req.key, &req.message, &mut digest).map_err(prim_err)?;
    Ok(HmacResponse { digest })
}

// ─── HKDF ───────────────────────────────────────────────────────────────────

pub fn hkdf(req: HkdfRequest) -> Result<HkdfResponse, ServerError> {
    let alg = map_digest_alg(req.algorithm);
    let mut okm = vec![0u8; req.expected_length as usize];
    prim::hkdf(alg, &req.salt, &req.ikm, &[&req.info], &mut okm).map_err(prim_err)?;
    Ok(HkdfResponse { okm })
}

// ─── KBKDF-CTR-HMAC ────────────────────────────────────────────────────────

pub fn kbkdf_ctr_hmac(req: KbkdfCtrHmacRequest) -> Result<KbkdfCtrHmacResponse, ServerError> {
    let alg = map_digest_alg(req.algorithm);
    let mut okm = vec![0u8; req.expected_length as usize];
    prim::kbkdf_ctr_hmac(alg, &req.ikm, &req.info, &mut okm).map_err(prim_err)?;
    Ok(KbkdfCtrHmacResponse { okm })
}

// ─── ECDSA ──────────────────────────────────────────────────────────────────

pub fn ecdsa_generate_key_pair(
    req: EcdsaGenerateKeyPairRequest,
) -> Result<EcdsaGenerateKeyPairResponse, ServerError> {
    let alg = map_ecdsa_alg(req.algorithm);
    let key_pair = prim::ecdsa_generate_keypair(alg).map_err(prim_err)?;
    Ok(EcdsaGenerateKeyPairResponse {
        verification_key: key_pair.verification_key,
        signing_key: key_pair.signing_key,
    })
}

pub fn ecdsa_sign(req: EcdsaSignRequest) -> Result<EcdsaSignResponse, ServerError> {
    let alg = map_ecdsa_alg(req.algorithm);
    let mut signature = vec![0u8; prim::signature_len(alg)];
    prim::ecdsa_sign(alg, &req.signing_key, &req.message, &mut signature).map_err(prim_err)?;
    Ok(EcdsaSignResponse { signature })
}

pub fn ecdsa_verify(req: EcdsaVerifyRequest) -> Result<EcdsaVerifyResponse, ServerError> {
    let alg = map_ecdsa_alg(req.algorithm);
    let valid = prim::ecdsa_verify(alg, &req.verification_key, &req.message, &req.signature)
        .map_err(prim_err)?;
    Ok(EcdsaVerifyResponse { valid })
}
