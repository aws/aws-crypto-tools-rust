// EncryptionSDK.h — public types for the C++ Shim for the AWS Encryption SDK for Rust

#pragma once

#include <algorithm>
#include <cstdint>
#include <map>
#include <memory>
#include <optional>
#include <stdexcept>
#include <string>
#include <string_view>
#include <vector>

#if defined(__has_include)
#if __has_include(<version>)
#include <version>
#endif
#endif
#if defined(__cpp_lib_span)
#include <span>
#endif

namespace Aws {
namespace Esdk {

// File-wide invariants.
// Each requirement below holds for every type and operation in this facade.
// These cannot be explicitly tested, but are recorded as implications.
// Any edits to this file must respect these requirements.
//
//= spec/shim/shim.md#owned-interface
//= type=implication
//= reason=The facade defines its own enums in Aws::Esdk:: namespace
//# - For each core-library enumeration it exposes, the shim MUST define its own
//# corresponding enumeration type.
//
//= spec/shim/shim.md#owned-interface
//= type=implication
//= reason=Every public function uses only Aws::Esdk:: types and C++ standard-library types
//# - Each public function the shim exposes MUST use only owned-interface types or
//# standard-library types in its signature.
//
//= spec/shim/shim.md#owned-interface
//= type=implication
//# - Each owned interface that represents a core-library resource MUST hold the
//# generated handle privately and MUST NOT expose it in its public API.
//
//= spec/shim/shim.md#handles-and-lifetimes
//= type=implication
//= reason=Resourcs hold dependent resources inside its own implementation
//# - An owned interface that depends on another resource MUST retain ownership of
//# that resource for its own lifetime, so that a handle passed across the boundary
//# cannot outlive the resource it refers to.
//
//= spec/shim/shim.md#operation-contracts
//= type=implication
//= reason=with_* setters
//# - The shim MUST expose each optional input of the operations and resource
//# creations it exposes.
//
//= spec/shim/shim.md#operation-contracts
//= type=implication
//= reason=with_* setters
//# - The shim MUST accept optional inputs through a mechanism idiomatic to the
//# target language (e.g.
//
//= spec/shim/shim.md#operation-contracts
//= type=implication
//= reason=with_* setters
//# - The shim MUST define its operation and resource-creation inputs such that
//# an optional input can be added without breaking existing target code.
//
//= spec/shim/shim.md#operation-contracts
//= type=implication
//= reason=Options fields are std::optional (or empty); operations start from a value-initialized (all-unset) input and assign a field only when the caller set it.
//# - When the target does not supply an optional input, the shim MUST defer to
//# the core library's default and MUST NOT substitute its own.

//= spec/shim/shim.md#owned-interface
//= type=implication
//# - The shim MUST define its own error type for its public surface.
//
/// Base exception for every failure this library reports.
/// Catching this type catches everything the shim can throw.
class AwsEncryptionSdkException : public std::runtime_error {
public:
    explicit AwsEncryptionSdkException(const std::string& msg) : std::runtime_error(msg) {}
};

//= spec/shim/shim.md#error-classification
//= type=implication
//= reason=Every specific exception derives from AwsEncryptionSdkException
//# - Every exposed error kind MUST also be identifiable as the shim's own base
//# error type, so a target that handles only the base type is unaffected when a
//# kind is added.
//
/// The message bytes are malformed and could not be read or written.
/// No cryptography was attempted.
class SerializationException : public AwsEncryptionSdkException {
public:
    explicit SerializationException(const std::string& msg) : AwsEncryptionSdkException(msg) {}
};

/// A cryptographic operation failed (ex. auth tag did not verify).
/// Retrying the same input cannot succeed.
class CryptographicException : public AwsEncryptionSdkException {
public:
    explicit CryptographicException(const std::string& msg) : AwsEncryptionSdkException(msg) {}
};

/// An input is invalid (malformed/unrecognized value, or a missing required input type.)
/// Fix the input; retrying the same input cannot succeed.
class ValidationException : public AwsEncryptionSdkException {
public:
    explicit ValidationException(const std::string& msg) : AwsEncryptionSdkException(msg) {}
};

/// Algorithm suite for encryption, identified by the two-byte ID from the ESDK message format. 
/// <https://docs.aws.amazon.com/encryption-sdk/latest/developer-guide/supported-algorithms.html>
enum class AlgorithmSuiteId : std::uint16_t {
    AlgAes128GcmIv12Tag16NoKdf               = 0x0014,
    AlgAes192GcmIv12Tag16NoKdf               = 0x0046,
    AlgAes256GcmIv12Tag16NoKdf               = 0x0078,
    AlgAes128GcmIv12Tag16HkdfSha256          = 0x0114,
    AlgAes192GcmIv12Tag16HkdfSha256          = 0x0146,
    AlgAes256GcmIv12Tag16HkdfSha256          = 0x0178,
    AlgAes128GcmIv12Tag16HkdfSha256EcdsaP256 = 0x0214,
    AlgAes192GcmIv12Tag16HkdfSha384EcdsaP384 = 0x0346,
    AlgAes256GcmIv12Tag16HkdfSha384EcdsaP384 = 0x0378,
    AlgAes256GcmHkdfSha512CommitKey          = 0x0478,
    AlgAes256GcmHkdfSha512CommitKeyEcdsaP384 = 0x0578,
};

/// Governs whether messages are encrypted with, and are required to carry, key commitment.
/// <https://docs.aws.amazon.com/encryption-sdk/latest/developer-guide/migrate-commitment-policy.html>
enum class CommitmentPolicy : std::uint8_t {
    ForbidEncryptAllowDecrypt  = 1,
    RequireEncryptAllowDecrypt = 2,
    RequireEncryptRequireDecrypt = 3,
};

/// The AES-GCM algorithm a raw AES keyring uses to wrap and unwrap data keys.
enum class AesWrappingAlgorithm : std::uint8_t {
    AlgAes128GcmIv12Tag16 = 1,
    AlgAes192GcmIv12Tag16 = 2,
    AlgAes256GcmIv12Tag16 = 3,
};

// Implementation types defined inside EncryptionSDK.cpp.
// Deliberately left incomplete here so no consumer can construct, copy, or inspect them.
namespace detail {
struct KeyringImpl;
struct BytesFactory;
}  // namespace detail

/// Base Keyring type.
/// Every concrete keyring must derive from this type.
/// All ESDK-supplied keyrings can be shared across threads.
class Keyring {
    std::shared_ptr<detail::KeyringImpl> impl_;
    friend class EncryptionSDK;

protected:
    explicit Keyring(std::shared_ptr<detail::KeyringImpl> impl) : impl_(std::move(impl)) {}

public:
    virtual ~Keyring() = default;
};

/// Keyring that wraps and unwraps data keys locally with AES-GCM.
class RawAesKeyring : public Keyring {
public:
    /// Creates a Raw AES Keyring, which wraps and unwraps data keys locally using
    /// AES-GCM. The wrapping key bytes are copied into the keyring.
    /// \param key_namespace A namespace associated with this wrapping key.
    /// \param key_name A name associated with this wrapping key.
    /// \param wrapping_key The AES key used with AES_GCM encryption and decryption.
    ///        Its length must match the wrapping algorithm (16, 24, or 32 bytes).
    /// \param wrapping_alg The AES-GCM algorithm used to wrap and unwrap data keys.
    RawAesKeyring(const std::string& key_namespace,
                  const std::string& key_name,
                  const std::vector<std::uint8_t>& wrapping_key,
                  AesWrappingAlgorithm wrapping_alg);
};

/// Optional encrypt parameters.
/// A field left unset keeps the ESDK Rust's default.
class EncryptOptions {
    std::optional<AlgorithmSuiteId> algorithm_suite_;
    std::optional<CommitmentPolicy> commitment_policy_;
    std::map<std::string, std::string> encryption_context_;
    std::optional<std::uint32_t> frame_length_;
    std::optional<std::uint32_t> max_encrypted_data_keys_;
    friend class EncryptionSDK;

public:
    /// Algorithm suite for encryption, identified by the two-byte ID from the ESDK message format. 
    /// <https://docs.aws.amazon.com/encryption-sdk/latest/developer-guide/supported-algorithms.html>
    EncryptOptions& with_algorithm_suite(AlgorithmSuiteId a) { algorithm_suite_ = a; return *this; }
    /// Governs whether messages are encrypted with, and are required to carry, key commitment.
    /// <https://docs.aws.amazon.com/encryption-sdk/latest/developer-guide/migrate-commitment-policy.html>
    /// Default is CommitmentPolicy::RequireEncryptRequireDecrypt.
    EncryptOptions& with_commitment_policy(CommitmentPolicy p) { commitment_policy_ = p; return *this; }
    /// Key-value pairs to associate with the encrypted data.
    /// <https://docs.aws.amazon.com/encryption-sdk/latest/developer-guide/concepts.html#encryption-context>
    EncryptOptions& with_encryption_context(const std::map<std::string, std::string>& ec) { encryption_context_ = ec; return *this; }
    /// Length of each frame of framed data in bytes. Default 4096.
    EncryptOptions& with_frame_length(std::uint32_t n) { frame_length_ = n; return *this; }
    /// Limit to number of encrypted data keys on a message.
    /// 0 means no limit.
    /// <https://docs.aws.amazon.com/encryption-sdk/latest/developer-guide/configure.html#config-limit-keys>
    EncryptOptions& with_max_encrypted_data_keys(std::uint32_t n) { max_encrypted_data_keys_ = n; return *this; }
};

/// Optional decrypt parameters.
/// A field left unset keeps the ESDK Rust's default.
class DecryptOptions {
    std::optional<CommitmentPolicy> commitment_policy_;
    std::map<std::string, std::string> encryption_context_;
    std::optional<std::uint32_t> max_encrypted_data_keys_;
    friend class EncryptionSDK;

public:
    /// Default is CommitmentPolicy::RequireEncryptRequireDecrypt.
    DecryptOptions& with_commitment_policy(CommitmentPolicy p) { commitment_policy_ = p; return *this; }
    /// Encryption context to verify against the encrypted message; every entry must be present in the message's context.
    DecryptOptions& with_encryption_context(const std::map<std::string, std::string>& ec) { encryption_context_ = ec; return *this; }
    /// 0 means no limit.
    DecryptOptions& with_max_encrypted_data_keys(std::uint32_t n) { max_encrypted_data_keys_ = n; return *this; }
};

/// Read-only byte buffer returned by encrypt and decrypt.
///
/// This points into the Rust library's output buffer.
/// This enables an output sink to read the Rust buffer directly
/// without needing a potentially-expensive copy to an std::vector.
/// If you need a std::vector, use `.to_vector()`.
//= spec/shim/shim.md#bulk-data
//= reason=data()/size() read the ESDK Rust's buffer where it was written; no copy is made to construct a Bytes.
//# - The shim SHOULD let the caller read a payload result in place, where the
//# core library wrote it, instead of copying it into a new container first.
//
//= spec/shim/shim.md#bulk-data
//= type=implication
//= reason=Every Bytes shares the underlying buffer. The buffer is freed only when the last Bytes referring to it is destroyed.
//# - A result exposed this way MUST remain valid until the caller releases it.
class Bytes {
    const std::uint8_t* data_ = nullptr;
    std::size_t size_ = 0;
    std::shared_ptr<void> owner_;  // keeps the ESDK Rust's buffer alive
    friend struct detail::BytesFactory;
    Bytes(const std::uint8_t* data, std::size_t size, std::shared_ptr<void> owner)
        : data_(data), size_(size), owner_(std::move(owner)) {}

public:
    /// An empty buffer.
    Bytes() = default;
    Bytes(Bytes&&) = default;
    Bytes& operator=(Bytes&&) = default;
    /// Copies share the underlying buffer.
    /// The buffer is reference-counted and freed when the last copy is destroyed.
    Bytes(const Bytes&) = default;
    Bytes& operator=(const Bytes&) = default;

    /// Pointer to the first byte.
    const std::uint8_t* data() const { return data_; }
    /// Number of bytes.
    std::size_t size() const { return size_; }
    /// True when size() == 0, false otherwise.
    bool empty() const { return size_ == 0; }

    /// Iterator to the first byte.
    const std::uint8_t* begin() const { return data_; }
    /// Iterator one past the last byte.
    const std::uint8_t* end() const { return data_ + size_; }
    /// The byte at `index`; no bounds check.
    std::uint8_t operator[](std::size_t index) const { return data_[index]; }

    /// Copies the bytes into an owning std::vector.
    //= spec/shim/shim.md#bulk-data
    //# - The shim MUST also let the caller copy a result into memory the caller owns.
    std::vector<std::uint8_t> to_vector() const {
        return std::vector<std::uint8_t>(begin(), end());
    }

    /// Views the bytes as characters.
    /// The view is only valid while any Bytes sharing the buffer lives. No copy is made.
    std::string_view as_string_view() const {
        return std::string_view(reinterpret_cast<const char*>(data_), size_);
    }

#if defined(__cpp_lib_span)
    /// Views the bytes as a std::span;
    /// Only valid while any Bytes sharing the buffer live.
    std::span<const std::uint8_t> as_span() const { return {data_, size_}; }
#endif
};

/// Equality check impls
inline bool operator==(const Bytes& lhs, const Bytes& rhs) {
    return lhs.size() == rhs.size() && std::equal(lhs.begin(), lhs.end(), rhs.begin());
}
inline bool operator!=(const Bytes& lhs, const Bytes& rhs) { return !(lhs == rhs); }

inline bool operator==(const Bytes& lhs, const std::vector<std::uint8_t>& rhs) {
    return lhs.size() == rhs.size() && std::equal(lhs.begin(), lhs.end(), rhs.begin());
}
inline bool operator==(const std::vector<std::uint8_t>& lhs, const Bytes& rhs) { return rhs == lhs; }
inline bool operator!=(const Bytes& lhs, const std::vector<std::uint8_t>& rhs) { return !(lhs == rhs); }
inline bool operator!=(const std::vector<std::uint8_t>& lhs, const Bytes& rhs) { return !(rhs == lhs); }

/// Result of encrypt.
struct EncryptResult {
    /// The encrypted message.
    Bytes ciphertext;
    /// Encryption context associated with the encrypted message.
    /// This can differ from the value provided to EncryptInput.
    std::map<std::string, std::string> encryption_context;
    /// Algorithm suite used for encryption.
    /// This can differ from the value provided to EncryptInput.
    AlgorithmSuiteId algorithm_suite_id;
};

/// Result of decrypt.
struct DecryptResult {
    /// Decrypted plaintext data.
    Bytes plaintext;
    /// Encryption context recovered from the encrypted message.
    std::map<std::string, std::string> encryption_context;
    /// Algorithm suite used for decryption.
    AlgorithmSuiteId algorithm_suite_id;
};

/// ESDK client interface.
class EncryptionSDK {
public:
    EncryptionSDK() = default;

    EncryptResult encrypt(
        const std::vector<std::uint8_t>& plaintext,
        const Keyring& keyring,
        const EncryptOptions& options = {});

    /// Encrypts a plaintext held in any contiguous buffer
    /// (e.g. an mmap'd file or another library's buffer)
    /// without copying it into an std::vector first.
    /// The buffer must stay valid for the duration of the call.
    /// The plaintext bytes are not retained afterwards.
    //
    //= spec/shim/shim.md#bulk-data
    //# - The shim SHOULD let the caller pass a payload without first copying it into
    //# a shim-defined container: the operation reads the caller's bytes in place,
    //# and the caller's bytes need to stay valid only for the duration of the call.
    EncryptResult encrypt(
        const std::uint8_t* plaintext,
        std::size_t plaintext_len,
        const Keyring& keyring,
        const EncryptOptions& options = {});

    DecryptResult decrypt(
        const std::vector<std::uint8_t>& ciphertext,
        const Keyring& keyring,
        const DecryptOptions& options = {});

    /// Decrypts a ciphertext held in a Aws::Esdk::Bytes without copying it.
    DecryptResult decrypt(
        const Bytes& ciphertext,
        const Keyring& keyring,
        const DecryptOptions& options = {});

    /// Decrypts a ciphertext held in any contiguous buffer without copying it into a std::vector first.
    /// The buffer must stay valid for the duration of the call.
    /// The ciphertext bytes are not retained afterwards.
    DecryptResult decrypt(
        const std::uint8_t* ciphertext,
        std::size_t ciphertext_len,
        const Keyring& keyring,
        const DecryptOptions& options = {});

    /// Encrypts a text payload viewed through a std::string_view without copying it.
    /// The view must stay valid for the duration of the call.
    EncryptResult encrypt(
        std::string_view plaintext,
        const Keyring& keyring,
        const EncryptOptions& options = {}) {
        return encrypt(reinterpret_cast<const std::uint8_t*>(plaintext.data()),
                       plaintext.size(), keyring, options);
    }

#if defined(__cpp_lib_span)
    /// Encrypts a plaintext viewed through a std::span without copying it.
    /// The span must stay valid for the duration of the call.
    EncryptResult encrypt(
        std::span<const std::uint8_t> plaintext,
        const Keyring& keyring,
        const EncryptOptions& options = {}) {
        return encrypt(plaintext.data(), plaintext.size(), keyring, options);
    }

    /// Decrypts a ciphertext viewed through a std::span without copying it.
    /// The span must stay valid for the duration of the call.
    DecryptResult decrypt(
        std::span<const std::uint8_t> ciphertext,
        const Keyring& keyring,
        const DecryptOptions& options = {}) {
        return decrypt(ciphertext.data(), ciphertext.size(), keyring, options);
    }
#endif
};

}  // namespace Esdk
}  // namespace Aws
