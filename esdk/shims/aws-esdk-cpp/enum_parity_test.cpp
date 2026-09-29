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
static_assert(!eq(::aws_esdk_ffi::CacheKind{}, ::aws_esdk_ffi::CacheKind::Default), "zero-init CacheKind is not a selection");
// The facade's guard decodes these reprs from the error-message prefix; a
// renumbering here must fail this build, not misclassify errors at runtime.
static_assert(eq(::aws_esdk_ffi::ShimErrorKind::Esdk, 0), "ShimErrorKind::Esdk");
static_assert(eq(::aws_esdk_ffi::ShimErrorKind::SerializationError, 1), "ShimErrorKind::SerializationError");
static_assert(eq(::aws_esdk_ffi::ShimErrorKind::CryptographicError, 2), "ShimErrorKind::CryptographicError");
static_assert(eq(::aws_esdk_ffi::ShimErrorKind::MplError, 3), "ShimErrorKind::MplError");
static_assert(eq(::aws_esdk_ffi::ShimErrorKind::ValidationError, 4), "ShimErrorKind::ValidationError");

static_assert(eq(Aws::Esdk::MplErrorKind::Validation, ::aws_esdk_ffi::MplErrorKind::Validation), "MplErrorKind::Validation");
static_assert(eq(Aws::Esdk::MplErrorKind::NoBehaviorAttempted, ::aws_esdk_ffi::MplErrorKind::NoBehaviorAttempted), "MplErrorKind::NoBehaviorAttempted");
static_assert(eq(Aws::Esdk::MplErrorKind::PlaintextDataKeyAlreadyPresent, ::aws_esdk_ffi::MplErrorKind::PlaintextDataKeyAlreadyPresent), "MplErrorKind::PlaintextDataKeyAlreadyPresent");
static_assert(eq(Aws::Esdk::MplErrorKind::NoMatchingDataKey, ::aws_esdk_ffi::MplErrorKind::NoMatchingDataKey), "MplErrorKind::NoMatchingDataKey");
static_assert(eq(Aws::Esdk::MplErrorKind::KeyringFailed, ::aws_esdk_ffi::MplErrorKind::KeyringFailed), "MplErrorKind::KeyringFailed");
static_assert(eq(Aws::Esdk::MplErrorKind::RequiredEncryptionContextKeyMissing, ::aws_esdk_ffi::MplErrorKind::RequiredEncryptionContextKeyMissing), "MplErrorKind::RequiredEncryptionContextKeyMissing");
static_assert(eq(Aws::Esdk::MplErrorKind::EncryptionContextValueMismatch, ::aws_esdk_ffi::MplErrorKind::EncryptionContextValueMismatch), "MplErrorKind::EncryptionContextValueMismatch");
static_assert(eq(Aws::Esdk::MplErrorKind::AwsCryptoPublicKeyMissing, ::aws_esdk_ffi::MplErrorKind::AwsCryptoPublicKeyMissing), "MplErrorKind::AwsCryptoPublicKeyMissing");
static_assert(eq(Aws::Esdk::MplErrorKind::AwsCryptoPublicKeyUnexpected, ::aws_esdk_ffi::MplErrorKind::AwsCryptoPublicKeyUnexpected), "MplErrorKind::AwsCryptoPublicKeyUnexpected");
static_assert(eq(Aws::Esdk::MplErrorKind::Configuration, ::aws_esdk_ffi::MplErrorKind::Configuration), "MplErrorKind::Configuration");
static_assert(eq(Aws::Esdk::MplErrorKind::Kms, ::aws_esdk_ffi::MplErrorKind::Kms), "MplErrorKind::Kms");
static_assert(eq(Aws::Esdk::MplErrorKind::Dynamodb, ::aws_esdk_ffi::MplErrorKind::Dynamodb), "MplErrorKind::Dynamodb");
static_assert(eq(Aws::Esdk::MplErrorKind::RecordNotFound, ::aws_esdk_ffi::MplErrorKind::RecordNotFound), "MplErrorKind::RecordNotFound");
static_assert(eq(Aws::Esdk::MplErrorKind::RecordMalformed, ::aws_esdk_ffi::MplErrorKind::RecordMalformed), "MplErrorKind::RecordMalformed");
static_assert(eq(Aws::Esdk::MplErrorKind::Authentication, ::aws_esdk_ffi::MplErrorKind::Authentication), "MplErrorKind::Authentication");
static_assert(eq(Aws::Esdk::MplErrorKind::VersionConflict, ::aws_esdk_ffi::MplErrorKind::VersionConflict), "MplErrorKind::VersionConflict");
static_assert(eq(Aws::Esdk::MplErrorKind::Internal, ::aws_esdk_ffi::MplErrorKind::Internal), "MplErrorKind::Internal");
static_assert(eq(Aws::Esdk::MplErrorKind::StorageFailed, ::aws_esdk_ffi::MplErrorKind::StorageFailed), "MplErrorKind::StorageFailed");
static_assert(eq(Aws::Esdk::MplErrorKind::InvalidEntry, ::aws_esdk_ffi::MplErrorKind::InvalidEntry), "MplErrorKind::InvalidEntry");


static_assert(eq(Aws::Esdk::CommitmentPolicy::ForbidEncryptAllowDecrypt, ::aws_esdk_ffi::EsdkCommitmentPolicy::ForbidEncryptAllowDecrypt), "ForbidEncryptAllowDecrypt");
static_assert(eq(Aws::Esdk::CommitmentPolicy::RequireEncryptAllowDecrypt, ::aws_esdk_ffi::EsdkCommitmentPolicy::RequireEncryptAllowDecrypt), "RequireEncryptAllowDecrypt");
static_assert(eq(Aws::Esdk::CommitmentPolicy::RequireEncryptRequireDecrypt, ::aws_esdk_ffi::EsdkCommitmentPolicy::RequireEncryptRequireDecrypt), "RequireEncryptRequireDecrypt");

static_assert(eq(Aws::Esdk::AesWrappingAlgorithm::AlgAes128GcmIv12Tag16, ::aws_esdk_ffi::AesWrappingAlg::AlgAes128GcmIv12Tag16), "AlgAes128GcmIv12Tag16");
static_assert(eq(Aws::Esdk::AesWrappingAlgorithm::AlgAes192GcmIv12Tag16, ::aws_esdk_ffi::AesWrappingAlg::AlgAes192GcmIv12Tag16), "AlgAes192GcmIv12Tag16");
static_assert(eq(Aws::Esdk::AesWrappingAlgorithm::AlgAes256GcmIv12Tag16, ::aws_esdk_ffi::AesWrappingAlg::AlgAes256GcmIv12Tag16), "AlgAes256GcmIv12Tag16");

}  // namespace
