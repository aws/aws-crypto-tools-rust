// Compile-time parity between the facade's re-declared enums and the generated
// cxx bridge enums. detail::to_ffi() converts one to the other with a plain
// static_cast, so their underlying values must match exactly; any drift here is
// a build error rather than a silent miscast at runtime.
#include <cstdint>

#include <aws/esdk/EncryptionSDK.h>

namespace {

template <typename A, typename B>
constexpr bool eq(A a, B b) {
    return static_cast<std::uint64_t>(a) == static_cast<std::uint64_t>(b);
}

static_assert(eq(Aws::Esdk::AlgorithmSuiteId::AesGcm128, ::EsdkAlgorithmSuiteId::AlgAes128GcmIv12Tag16NoKdf), "AesGcm128");
static_assert(eq(Aws::Esdk::AlgorithmSuiteId::AesGcm192, ::EsdkAlgorithmSuiteId::AlgAes192GcmIv12Tag16NoKdf), "AesGcm192");
static_assert(eq(Aws::Esdk::AlgorithmSuiteId::AesGcm256, ::EsdkAlgorithmSuiteId::AlgAes256GcmIv12Tag16NoKdf), "AesGcm256");
static_assert(eq(Aws::Esdk::AlgorithmSuiteId::AesGcm128Hkdf256, ::EsdkAlgorithmSuiteId::AlgAes128GcmIv12Tag16HkdfSha256), "AesGcm128Hkdf256");
static_assert(eq(Aws::Esdk::AlgorithmSuiteId::AesGcm192Hkdf256, ::EsdkAlgorithmSuiteId::AlgAes192GcmIv12Tag16HkdfSha256), "AesGcm192Hkdf256");
static_assert(eq(Aws::Esdk::AlgorithmSuiteId::AesGcm256Hkdf256, ::EsdkAlgorithmSuiteId::AlgAes256GcmIv12Tag16HkdfSha256), "AesGcm256Hkdf256");
static_assert(eq(Aws::Esdk::AlgorithmSuiteId::AesGcm128Hkdf256Ecdsa256, ::EsdkAlgorithmSuiteId::AlgAes128GcmIv12Tag16HkdfSha256EcdsaP256), "AesGcm128Hkdf256Ecdsa256");
static_assert(eq(Aws::Esdk::AlgorithmSuiteId::AesGcm192Hkdf384Ecdsa384, ::EsdkAlgorithmSuiteId::AlgAes192GcmIv12Tag16HkdfSha384EcdsaP384), "AesGcm192Hkdf384Ecdsa384");
static_assert(eq(Aws::Esdk::AlgorithmSuiteId::AesGcm256Hkdf384Ecdsa384, ::EsdkAlgorithmSuiteId::AlgAes256GcmIv12Tag16HkdfSha384EcdsaP384), "AesGcm256Hkdf384Ecdsa384");
static_assert(eq(Aws::Esdk::AlgorithmSuiteId::AesGcm256Hkdf512Commit, ::EsdkAlgorithmSuiteId::AlgAes256GcmHkdfSha512CommitKey), "AesGcm256Hkdf512Commit");
static_assert(eq(Aws::Esdk::AlgorithmSuiteId::AesGcm256Hkdf512CommitEcdsa384, ::EsdkAlgorithmSuiteId::AlgAes256GcmHkdfSha512CommitKeyEcdsaP384), "AesGcm256Hkdf512CommitEcdsa384");

static_assert(eq(Aws::Esdk::CommitmentPolicy::ForbidEncryptAllowDecrypt, ::EsdkCommitmentPolicy::ForbidEncryptAllowDecrypt), "ForbidEncryptAllowDecrypt");
static_assert(eq(Aws::Esdk::CommitmentPolicy::RequireEncryptAllowDecrypt, ::EsdkCommitmentPolicy::RequireEncryptAllowDecrypt), "RequireEncryptAllowDecrypt");
static_assert(eq(Aws::Esdk::CommitmentPolicy::RequireEncryptRequireDecrypt, ::EsdkCommitmentPolicy::RequireEncryptRequireDecrypt), "RequireEncryptRequireDecrypt");

static_assert(eq(Aws::Esdk::CacheKind::None, ::CacheType::NoCache), "CacheKind::None");
static_assert(eq(Aws::Esdk::CacheKind::MultiThreaded, ::CacheType::MultiThreadedCache), "CacheKind::MultiThreaded");

}  // namespace
