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

static_assert(eq(Aws::Esdk::AlgorithmSuiteId::AlgAes128GcmIv12Tag16NoKdf, ::EsdkAlgorithmSuiteId::AlgAes128GcmIv12Tag16NoKdf), "AlgAes128GcmIv12Tag16NoKdf");
static_assert(eq(Aws::Esdk::AlgorithmSuiteId::AlgAes192GcmIv12Tag16NoKdf, ::EsdkAlgorithmSuiteId::AlgAes192GcmIv12Tag16NoKdf), "AlgAes192GcmIv12Tag16NoKdf");
static_assert(eq(Aws::Esdk::AlgorithmSuiteId::AlgAes256GcmIv12Tag16NoKdf, ::EsdkAlgorithmSuiteId::AlgAes256GcmIv12Tag16NoKdf), "AlgAes256GcmIv12Tag16NoKdf");
static_assert(eq(Aws::Esdk::AlgorithmSuiteId::AlgAes128GcmIv12Tag16HkdfSha256, ::EsdkAlgorithmSuiteId::AlgAes128GcmIv12Tag16HkdfSha256), "AlgAes128GcmIv12Tag16HkdfSha256");
static_assert(eq(Aws::Esdk::AlgorithmSuiteId::AlgAes192GcmIv12Tag16HkdfSha256, ::EsdkAlgorithmSuiteId::AlgAes192GcmIv12Tag16HkdfSha256), "AlgAes192GcmIv12Tag16HkdfSha256");
static_assert(eq(Aws::Esdk::AlgorithmSuiteId::AlgAes256GcmIv12Tag16HkdfSha256, ::EsdkAlgorithmSuiteId::AlgAes256GcmIv12Tag16HkdfSha256), "AlgAes256GcmIv12Tag16HkdfSha256");
static_assert(eq(Aws::Esdk::AlgorithmSuiteId::AlgAes128GcmIv12Tag16HkdfSha256EcdsaP256, ::EsdkAlgorithmSuiteId::AlgAes128GcmIv12Tag16HkdfSha256EcdsaP256), "AlgAes128GcmIv12Tag16HkdfSha256EcdsaP256");
static_assert(eq(Aws::Esdk::AlgorithmSuiteId::AlgAes192GcmIv12Tag16HkdfSha384EcdsaP384, ::EsdkAlgorithmSuiteId::AlgAes192GcmIv12Tag16HkdfSha384EcdsaP384), "AlgAes192GcmIv12Tag16HkdfSha384EcdsaP384");
static_assert(eq(Aws::Esdk::AlgorithmSuiteId::AlgAes256GcmIv12Tag16HkdfSha384EcdsaP384, ::EsdkAlgorithmSuiteId::AlgAes256GcmIv12Tag16HkdfSha384EcdsaP384), "AlgAes256GcmIv12Tag16HkdfSha384EcdsaP384");
static_assert(eq(Aws::Esdk::AlgorithmSuiteId::AlgAes256GcmHkdfSha512CommitKey, ::EsdkAlgorithmSuiteId::AlgAes256GcmHkdfSha512CommitKey), "AlgAes256GcmHkdfSha512CommitKey");
static_assert(eq(Aws::Esdk::AlgorithmSuiteId::AlgAes256GcmHkdfSha512CommitKeyEcdsaP384, ::EsdkAlgorithmSuiteId::AlgAes256GcmHkdfSha512CommitKeyEcdsaP384), "AlgAes256GcmHkdfSha512CommitKeyEcdsaP384");

static_assert(eq(Aws::Esdk::CommitmentPolicy::ForbidEncryptAllowDecrypt, ::EsdkCommitmentPolicy::ForbidEncryptAllowDecrypt), "ForbidEncryptAllowDecrypt");
static_assert(eq(Aws::Esdk::CommitmentPolicy::RequireEncryptAllowDecrypt, ::EsdkCommitmentPolicy::RequireEncryptAllowDecrypt), "RequireEncryptAllowDecrypt");
static_assert(eq(Aws::Esdk::CommitmentPolicy::RequireEncryptRequireDecrypt, ::EsdkCommitmentPolicy::RequireEncryptRequireDecrypt), "RequireEncryptRequireDecrypt");

static_assert(eq(Aws::Esdk::CacheKind::None, ::CacheType::NoCache), "CacheKind::None");
static_assert(eq(Aws::Esdk::CacheKind::MultiThreaded, ::CacheType::MultiThreadedCache), "CacheKind::MultiThreaded");

}  // namespace
