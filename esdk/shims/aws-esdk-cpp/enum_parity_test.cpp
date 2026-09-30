// detail::to_ffi() converts the C++ enums to the Rust enums
// with a plain static_cast (i.e. the same enum byte value),
// so the enum byte values must match.
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

// A value-initialized bridge enum is never a real selection: required-field
// enums keep an Unset zero, optional-field enums leave 0 unassigned.
static_assert(eq(::aws_esdk_ffi::KmsConfigurationType{}, ::aws_esdk_ffi::KmsConfigurationType::Unset), "zero-init KmsConfigurationType is Unset");
static_assert(eq(::aws_esdk_ffi::AesWrappingAlg{}, ::aws_esdk_ffi::AesWrappingAlg::Unset), "zero-init AesWrappingAlg is Unset");
static_assert(!eq(::aws_esdk_ffi::EsdkCommitmentPolicy{}, ::aws_esdk_ffi::EsdkCommitmentPolicy::ForbidEncryptAllowDecrypt), "zero-init CommitmentPolicy is not a selection");
static_assert(!eq(::aws_esdk_ffi::EsdkAlgorithmSuiteId{}, ::aws_esdk_ffi::EsdkAlgorithmSuiteId::AlgAes128GcmIv12Tag16NoKdf), "zero-init AlgorithmSuiteId is not a selection");
// The facade's guard decodes these reprs from the error-message prefix; a
// renumbering here must fail this build, not misclassify errors at runtime.
static_assert(eq(Aws::Esdk::ErrorKind::Validation, ::aws_esdk_ffi::ShimErrorKind::Validation), "ErrorKind::Validation");
static_assert(eq(Aws::Esdk::ErrorKind::Serialization, ::aws_esdk_ffi::ShimErrorKind::Serialization), "ErrorKind::Serialization");
static_assert(eq(Aws::Esdk::ErrorKind::Cryptographic, ::aws_esdk_ffi::ShimErrorKind::Cryptographic), "ErrorKind::Cryptographic");
static_assert(eq(Aws::Esdk::ErrorKind::InvalidMaterials, ::aws_esdk_ffi::ShimErrorKind::InvalidMaterials), "ErrorKind::InvalidMaterials");
static_assert(eq(Aws::Esdk::ErrorKind::EncryptionContextMismatch, ::aws_esdk_ffi::ShimErrorKind::EncryptionContextMismatch), "ErrorKind::EncryptionContextMismatch");
static_assert(eq(Aws::Esdk::ErrorKind::NoMatchingDataKey, ::aws_esdk_ffi::ShimErrorKind::NoMatchingDataKey), "ErrorKind::NoMatchingDataKey");
static_assert(eq(Aws::Esdk::ErrorKind::RemoteAccessDenied, ::aws_esdk_ffi::ShimErrorKind::RemoteAccessDenied), "ErrorKind::RemoteAccessDenied");
static_assert(eq(Aws::Esdk::ErrorKind::RemoteResourceNotFound, ::aws_esdk_ffi::ShimErrorKind::RemoteResourceNotFound), "ErrorKind::RemoteResourceNotFound");
static_assert(eq(Aws::Esdk::ErrorKind::RemoteThrottled, ::aws_esdk_ffi::ShimErrorKind::RemoteThrottled), "ErrorKind::RemoteThrottled");
static_assert(eq(Aws::Esdk::ErrorKind::RemoteTransport, ::aws_esdk_ffi::ShimErrorKind::RemoteTransport), "ErrorKind::RemoteTransport");
static_assert(eq(Aws::Esdk::ErrorKind::Remote, ::aws_esdk_ffi::ShimErrorKind::Remote), "ErrorKind::Remote");
static_assert(eq(Aws::Esdk::ErrorKind::Internal, ::aws_esdk_ffi::ShimErrorKind::Internal), "ErrorKind::Internal");


static_assert(eq(Aws::Esdk::CommitmentPolicy::ForbidEncryptAllowDecrypt, ::aws_esdk_ffi::EsdkCommitmentPolicy::ForbidEncryptAllowDecrypt), "ForbidEncryptAllowDecrypt");
static_assert(eq(Aws::Esdk::CommitmentPolicy::RequireEncryptAllowDecrypt, ::aws_esdk_ffi::EsdkCommitmentPolicy::RequireEncryptAllowDecrypt), "RequireEncryptAllowDecrypt");
static_assert(eq(Aws::Esdk::CommitmentPolicy::RequireEncryptRequireDecrypt, ::aws_esdk_ffi::EsdkCommitmentPolicy::RequireEncryptRequireDecrypt), "RequireEncryptRequireDecrypt");

static_assert(eq(Aws::Esdk::AesWrappingAlgorithm::AlgAes128GcmIv12Tag16, ::aws_esdk_ffi::AesWrappingAlg::AlgAes128GcmIv12Tag16), "AlgAes128GcmIv12Tag16");
static_assert(eq(Aws::Esdk::AesWrappingAlgorithm::AlgAes192GcmIv12Tag16, ::aws_esdk_ffi::AesWrappingAlg::AlgAes192GcmIv12Tag16), "AlgAes192GcmIv12Tag16");
static_assert(eq(Aws::Esdk::AesWrappingAlgorithm::AlgAes256GcmIv12Tag16, ::aws_esdk_ffi::AesWrappingAlg::AlgAes256GcmIv12Tag16), "AlgAes256GcmIv12Tag16");

}  // namespace
