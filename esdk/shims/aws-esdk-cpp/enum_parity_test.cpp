// detail::to_ffi() converts the facade enums to the bridge enums with a plain
// static_cast, so their values must match; drift fails this compile.
//
// This is an internal white-box check, so it deliberately includes the
// cxx-generated bridge header (which the public header no longer exposes).
#include <cstdint>

#include <aws/esdk/EncryptionSDK.h>
#include "aws-esdk-cpp/src/lib.rs.h"

namespace {

template <typename A, typename B>
constexpr bool eq(A a, B b) {
    return static_cast<std::uint64_t>(a) == static_cast<std::uint64_t>(b);
}

static_assert(eq(Aws::Esdk::AlgorithmSuiteId::AlgAes128GcmIv12Tag16NoKdf, ::aws_esdk_ffi::EsdkAlgorithmSuiteId::AlgAes128GcmIv12Tag16NoKdf), "AlgAes128GcmIv12Tag16NoKdf");
static_assert(eq(Aws::Esdk::AlgorithmSuiteId::AlgAes192GcmIv12Tag16NoKdf, ::aws_esdk_ffi::EsdkAlgorithmSuiteId::AlgAes192GcmIv12Tag16NoKdf), "AlgAes192GcmIv12Tag16NoKdf");
static_assert(eq(Aws::Esdk::AlgorithmSuiteId::AlgAes256GcmIv12Tag16NoKdf, ::aws_esdk_ffi::EsdkAlgorithmSuiteId::AlgAes256GcmIv12Tag16NoKdf), "AlgAes256GcmIv12Tag16NoKdf");
static_assert(eq(Aws::Esdk::AlgorithmSuiteId::AlgAes128GcmIv12Tag16HkdfSha256, ::aws_esdk_ffi::EsdkAlgorithmSuiteId::AlgAes128GcmIv12Tag16HkdfSha256), "AlgAes128GcmIv12Tag16HkdfSha256");
static_assert(eq(Aws::Esdk::AlgorithmSuiteId::AlgAes192GcmIv12Tag16HkdfSha256, ::aws_esdk_ffi::EsdkAlgorithmSuiteId::AlgAes192GcmIv12Tag16HkdfSha256), "AlgAes192GcmIv12Tag16HkdfSha256");
static_assert(eq(Aws::Esdk::AlgorithmSuiteId::AlgAes256GcmIv12Tag16HkdfSha256, ::aws_esdk_ffi::EsdkAlgorithmSuiteId::AlgAes256GcmIv12Tag16HkdfSha256), "AlgAes256GcmIv12Tag16HkdfSha256");
static_assert(eq(Aws::Esdk::AlgorithmSuiteId::AlgAes128GcmIv12Tag16HkdfSha256EcdsaP256, ::aws_esdk_ffi::EsdkAlgorithmSuiteId::AlgAes128GcmIv12Tag16HkdfSha256EcdsaP256), "AlgAes128GcmIv12Tag16HkdfSha256EcdsaP256");
static_assert(eq(Aws::Esdk::AlgorithmSuiteId::AlgAes192GcmIv12Tag16HkdfSha384EcdsaP384, ::aws_esdk_ffi::EsdkAlgorithmSuiteId::AlgAes192GcmIv12Tag16HkdfSha384EcdsaP384), "AlgAes192GcmIv12Tag16HkdfSha384EcdsaP384");
static_assert(eq(Aws::Esdk::AlgorithmSuiteId::AlgAes256GcmIv12Tag16HkdfSha384EcdsaP384, ::aws_esdk_ffi::EsdkAlgorithmSuiteId::AlgAes256GcmIv12Tag16HkdfSha384EcdsaP384), "AlgAes256GcmIv12Tag16HkdfSha384EcdsaP384");
static_assert(eq(Aws::Esdk::AlgorithmSuiteId::AlgAes256GcmHkdfSha512CommitKey, ::aws_esdk_ffi::EsdkAlgorithmSuiteId::AlgAes256GcmHkdfSha512CommitKey), "AlgAes256GcmHkdfSha512CommitKey");
static_assert(eq(Aws::Esdk::AlgorithmSuiteId::AlgAes256GcmHkdfSha512CommitKeyEcdsaP384, ::aws_esdk_ffi::EsdkAlgorithmSuiteId::AlgAes256GcmHkdfSha512CommitKeyEcdsaP384), "AlgAes256GcmHkdfSha512CommitKeyEcdsaP384");

// A value-initialized bridge enum is Unset: unset is the zero value, never a
// real selection.
static_assert(eq(::aws_esdk_ffi::EsdkAlgorithmSuiteId{}, ::aws_esdk_ffi::EsdkAlgorithmSuiteId::Unset), "zero-init AlgorithmSuiteId is Unset");
static_assert(eq(::aws_esdk_ffi::EsdkCommitmentPolicy{}, ::aws_esdk_ffi::EsdkCommitmentPolicy::Unset), "zero-init CommitmentPolicy is Unset");
static_assert(eq(::aws_esdk_ffi::KmsConfigurationType{}, ::aws_esdk_ffi::KmsConfigurationType::Unset), "zero-init KmsConfigurationType is Unset");
static_assert(eq(::aws_esdk_ffi::AesWrappingAlg{}, ::aws_esdk_ffi::AesWrappingAlg::Unset), "zero-init AesWrappingAlg is Unset");

static_assert(eq(Aws::Esdk::CommitmentPolicy::ForbidEncryptAllowDecrypt, ::aws_esdk_ffi::EsdkCommitmentPolicy::ForbidEncryptAllowDecrypt), "ForbidEncryptAllowDecrypt");
static_assert(eq(Aws::Esdk::CommitmentPolicy::RequireEncryptAllowDecrypt, ::aws_esdk_ffi::EsdkCommitmentPolicy::RequireEncryptAllowDecrypt), "RequireEncryptAllowDecrypt");
static_assert(eq(Aws::Esdk::CommitmentPolicy::RequireEncryptRequireDecrypt, ::aws_esdk_ffi::EsdkCommitmentPolicy::RequireEncryptRequireDecrypt), "RequireEncryptRequireDecrypt");

static_assert(eq(Aws::Esdk::AesWrappingAlgorithm::AlgAes128GcmIv12Tag16, ::aws_esdk_ffi::AesWrappingAlg::AlgAes128GcmIv12Tag16), "AlgAes128GcmIv12Tag16");
static_assert(eq(Aws::Esdk::AesWrappingAlgorithm::AlgAes192GcmIv12Tag16, ::aws_esdk_ffi::AesWrappingAlg::AlgAes192GcmIv12Tag16), "AlgAes192GcmIv12Tag16");
static_assert(eq(Aws::Esdk::AesWrappingAlgorithm::AlgAes256GcmIv12Tag16, ::aws_esdk_ffi::AesWrappingAlg::AlgAes256GcmIv12Tag16), "AlgAes256GcmIv12Tag16");

}  // namespace
