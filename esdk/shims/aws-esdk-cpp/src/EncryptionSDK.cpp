// EncryptionSDK.cpp - translates public types in EncryptionSDK.h to private cxx-generated types

#include "aws/esdk/EncryptionSDK.h"

#include <utility>

#include "rust/cxx.h"                 // rust::Error, rust::Box, rust::Vec, rust::Slice
#include "aws-esdk-cpp/src/lib.rs.h"  // cxx-generated bindings (namespace aws_esdk_ffi)

namespace ffi = ::aws_esdk_ffi;

namespace Aws {
namespace Esdk {
namespace detail {

// Rethrow Rust ESDK exceptions as corresponding C++ exceptions.
// If a Rust exception isn't explicitly listed, default to throwing the C++ AwsEncryptionSdkException.
[[noreturn]] void throw_shim_exception(const std::string& what) {
    ::ffi::ShimErrorKind kind = ::ffi::ShimErrorKind::Esdk;
    std::string message = what;
    if (what.size() >= 2 && what[1] == '\x1f' && what[0] >= '0' && what[0] <= '9') {
        kind = static_cast<::ffi::ShimErrorKind>(what[0] - '0');
        message = what.substr(2);
    }
    switch (kind) {
        case ::ffi::ShimErrorKind::SerializationError: throw SerializationException(message);
        case ::ffi::ShimErrorKind::CryptographicError: throw CryptographicException(message);
        case ::ffi::ShimErrorKind::ValidationError: throw ValidationException(message);
        //= spec/shim/shim.md#error-classification
        //# - An error whose kind the shim does not expose MUST be reported as the shim's
        //# own base error type.
        default: throw AwsEncryptionSdkException(message);
    }
}

// Converts a rust::Error into the matching Aws::Esdk exception.
// Attached to every call into the bridge.
template <typename F>
auto guard(F&& f) -> decltype(f()) {
    try {
        return f();
    } catch (const ::rust::Error& e) {
        throw_shim_exception(e.what());
    }
}

// Conversions from public type to FFI type

::ffi::EsdkAlgorithmSuiteId to_ffi(AlgorithmSuiteId a) {
    return static_cast<::ffi::EsdkAlgorithmSuiteId>(static_cast<std::uint16_t>(a));
}
::ffi::EsdkCommitmentPolicy to_ffi(CommitmentPolicy p) {
    return static_cast<::ffi::EsdkCommitmentPolicy>(static_cast<std::uint8_t>(p));
}
::ffi::AesWrappingAlg to_ffi(AesWrappingAlgorithm a) {
    return static_cast<::ffi::AesWrappingAlg>(static_cast<std::uint8_t>(a));
}

// Presence-encoded optionals: set=false defers to the ESDK Rust's default.

::ffi::OptU32 to_opt(const std::optional<std::uint32_t>& o) {
    return o ? ::ffi::OptU32{true, *o} : ::ffi::OptU32{false, 0};
}
::ffi::OptAlgId to_opt(const std::optional<AlgorithmSuiteId>& o) {
    return o ? ::ffi::OptAlgId{true, to_ffi(*o)} : ::ffi::OptAlgId{false, {}};
}
::ffi::OptCommitmentPolicy to_opt(const std::optional<CommitmentPolicy>& o) {
    return o ? ::ffi::OptCommitmentPolicy{true, to_ffi(*o)} : ::ffi::OptCommitmentPolicy{false, {}};
}

::rust::Vec<::ffi::EncryptionContextItem> to_ec(const std::map<std::string, std::string>& ec) {
    ::rust::Vec<::ffi::EncryptionContextItem> out;
    for (const auto& kv : ec) {
        ::ffi::EncryptionContextItem item;
        item.key = ::rust::String(kv.first);
        item.value = ::rust::String(kv.second);
        out.push_back(std::move(item));
    }
    return out;
}

// Conversions from FFI type to public type

AlgorithmSuiteId alg_from_ffi(::ffi::EsdkAlgorithmSuiteId a) {
    return static_cast<AlgorithmSuiteId>(static_cast<std::uint16_t>(a));
}

std::map<std::string, std::string> from_ec(const ::rust::Vec<::ffi::EncryptionContextItem>& ec) {
    std::map<std::string, std::string> out;
    for (const auto& item : ec) {
        out.emplace(std::string(item.key), std::string(item.value));
    }
    return out;
}

// Aws::Esdk::Bytes

struct BytesFactory {
    // Zero-copy wrapper for Rust buffer in C++-accessible type
    static Bytes make(::rust::Vec<std::uint8_t> buf) {
        auto owner = std::make_shared<::rust::Vec<std::uint8_t>>(std::move(buf));
        const std::uint8_t* data = owner->data();
        const std::size_t size = owner->size();
        return Bytes(data, size, std::move(owner));
    }
};

Bytes make_bytes(::rust::Vec<std::uint8_t> buf) {
    return BytesFactory::make(std::move(buf));
}

// Resources

// Resources may depend on other resources.
// All dependent resources are stored in the resource's `retained` field.
// What a resource retains is fixed by its type; a raw AES keyring retains nothing.
using Retained = std::vector<std::shared_ptr<void>>;

struct KeyringImpl {
    // `retained` must be declared before the handle so its resources are destroyed last.
    // In C++, destructor behavior is declared first -> destroyed last.
    // Dependent resources must be destroyed after the handle that depends on them.
    Retained retained;
    ::rust::Box<::ffi::Keyring> handle;
    KeyringImpl(Retained deps, ::rust::Box<::ffi::Keyring> h)
        : retained(std::move(deps)), handle(std::move(h)) {}
};

}  // namespace detail

// Keyrings

RawAesKeyring::RawAesKeyring(const std::string& key_namespace,
                             const std::string& key_name,
                             const std::vector<std::uint8_t>& wrapping_key,
                             AesWrappingAlgorithm wrapping_alg)
    : Keyring(std::make_shared<detail::KeyringImpl>(
          detail::Retained{}, detail::guard([&] {
              ::ffi::RawAesKeyringInput in{};
              in.key_namespace = ::rust::String(key_namespace);
              in.key_name = ::rust::String(key_name);
              in.wrapping_key =
                  ::rust::Slice<const std::uint8_t>(wrapping_key.data(), wrapping_key.size());
              in.wrapping_alg = detail::to_ffi(wrapping_alg);
              return ::ffi::create_raw_aes_keyring(in);
          }))) {}

// ESDK Operations

EncryptResult EncryptionSDK::encrypt(const std::vector<std::uint8_t>& plaintext,
                                     const Keyring& keyring,
                                     const EncryptOptions& options) {
    return encrypt(plaintext.data(), plaintext.size(), keyring, options);
}

EncryptResult EncryptionSDK::encrypt(const std::uint8_t* plaintext,
                                     std::size_t plaintext_len,
                                     const Keyring& keyring,
                                     const EncryptOptions& options) {
    ::ffi::EncryptInput in{};
    in.keyring = &*keyring.impl_->handle;
    in.plaintext = ::rust::Slice<const std::uint8_t>(plaintext, plaintext_len);
    in.encryption_context = detail::to_ec(options.encryption_context_);
    in.algorithm_suite_id = detail::to_opt(options.algorithm_suite_);
    in.commitment_policy = detail::to_opt(options.commitment_policy_);
    in.frame_length = detail::to_opt(options.frame_length_);
    in.max_encrypted_data_keys = detail::to_opt(options.max_encrypted_data_keys_);
    ::ffi::EncryptOutput out = detail::guard([&] { return ::ffi::encrypt(in); });
    EncryptResult result;
    result.ciphertext = detail::make_bytes(std::move(out.ciphertext));
    result.encryption_context = detail::from_ec(out.encryption_context);
    result.algorithm_suite_id = detail::alg_from_ffi(out.algorithm_suite_id);
    return result;
}

DecryptResult EncryptionSDK::decrypt(const std::vector<std::uint8_t>& ciphertext,
                                     const Keyring& keyring,
                                     const DecryptOptions& options) {
    return decrypt(ciphertext.data(), ciphertext.size(), keyring, options);
}

DecryptResult EncryptionSDK::decrypt(const Bytes& ciphertext,
                                     const Keyring& keyring,
                                     const DecryptOptions& options) {
    return decrypt(ciphertext.data(), ciphertext.size(), keyring, options);
}

DecryptResult EncryptionSDK::decrypt(const std::uint8_t* ciphertext,
                                     std::size_t ciphertext_len,
                                     const Keyring& keyring,
                                     const DecryptOptions& options) {
    ::ffi::DecryptInput in{};
    in.keyring = &*keyring.impl_->handle;
    in.ciphertext = ::rust::Slice<const std::uint8_t>(ciphertext, ciphertext_len);
    in.encryption_context = detail::to_ec(options.encryption_context_);
    in.commitment_policy = detail::to_opt(options.commitment_policy_);
    in.max_encrypted_data_keys = detail::to_opt(options.max_encrypted_data_keys_);
    ::ffi::DecryptOutput out = detail::guard([&] { return ::ffi::decrypt(in); });
    DecryptResult result;
    result.plaintext = detail::make_bytes(std::move(out.plaintext));
    result.encryption_context = detail::from_ec(out.encryption_context);
    result.algorithm_suite_id = detail::alg_from_ffi(out.algorithm_suite_id);
    return result;
}

}  // namespace Esdk
}  // namespace Aws
