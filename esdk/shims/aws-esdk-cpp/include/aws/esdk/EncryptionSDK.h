// EncryptionSDK.h — public types to interact with the C++ Shim for the AWS Encryption SDK for Rust.
//
// This header exposes only owned-interface types (Aws::Esdk::) and C++
// standard-library types. The cxx-generated FFI layer is confined to the
// compiled EncryptionSDK.cpp translation unit: no cxx-generated type, function,
// or header is reachable through this header, so consumers cannot take a
// dependency on the FFI layer even accidentally.

#pragma once

#include <algorithm>
#include <cstdint>
#include <map>
#include <memory>
#include <optional>
#include <stdexcept>
#include <string>
#include <vector>

namespace Aws {
namespace Esdk {

// File-wide invariants.
// Each requirement below holds for every type and operation in this facade.
// These cannot be explicitly tested, but are recorded as implications.
// Any edits to this file must respect these requirements. Enforcement mechanism:
// this header includes no cxx-generated header, so an edit that names an FFI
// type here fails to compile.
//
//= spec/shim/shim.md#owned-interface
//= type=implication
//= reason=The facade defines its own enums (Aws::Esdk::); the ffi-generated enum types are not visible in this header.
//# - For each core-library enumeration it exposes, the shim MUST define its own
//# corresponding enumeration type.
//
//= spec/shim/shim.md#owned-interface
//= type=implication
//= reason=Every public function signature uses only Aws::Esdk:: types and C++ standard-library types; no ffi-generated type is even visible in this header.
//# - Each public function the shim exposes MUST use only owned-interface types or
//# standard-library types in its signature.
//
//= spec/shim/shim.md#owned-interface
//= type=implication
//= reason=Every C++ resource holds its handle behind a private pointer to an implementation type that is only defined inside the compiled shim, so users cannot access or name it.
//# - Each owned interface that represents a core-library resource MUST hold the
//# generated handle privately and MUST NOT expose it in its public API.
//
//= spec/shim/shim.md#handles-and-lifetimes
//= type=implication
//= reason=Every C++ resource that depends on another resource holds it (or a shared owner of it) inside its implementation for its own lifetime.
//# - An owned interface that depends on another resource MUST retain ownership of
//# that resource for its own lifetime, so that a handle passed across the boundary
//# cannot outlive the resource it refers to.
//
//= spec/shim/shim.md#operation-contracts
//= type=implication
//= reason=Every optional input has a with_* setter on every operation's or resource's options object.
//# - The shim MUST expose each optional input of the operations and resource
//# creations it exposes.
//
//= spec/shim/shim.md#operation-contracts
//= type=implication
//= reason=Options objects with with_* setters are the idiomatic C++ optional-input mechanism.
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
/// Base exception for every failure this library reports. Catching this type
/// catches everything the shim can throw.
class AwsEncryptionSdkException : public std::runtime_error {
public:
    explicit AwsEncryptionSdkException(const std::string& msg) : std::runtime_error(msg) {}
};

/// Cryptographic verification failed — for example the authentication tag of a
/// tampered or corrupted message did not verify. The message cannot be
/// trusted; retrying the same input cannot succeed.
class AuthenticationException : public AwsEncryptionSdkException {
public:
    explicit AuthenticationException(const std::string& msg) : AwsEncryptionSdkException(msg) {}
};

/// A dependency service call (for example AWS KMS) or transient
/// cache-contention failure. The operation may succeed if retried.
class ServiceException : public AwsEncryptionSdkException {
public:
    explicit ServiceException(const std::string& msg) : AwsEncryptionSdkException(msg) {}
};

/// The caller supplied invalid input — a malformed message, an unrecognized
/// enum value, or a missing required resource. Fix the input; retrying the
/// same input cannot succeed.
class InvalidInputException : public AwsEncryptionSdkException {
public:
    explicit InvalidInputException(const std::string& msg) : AwsEncryptionSdkException(msg) {}
};

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

// Implementation types. Defined only inside the compiled shim
// (EncryptionSDK.cpp); deliberately left incomplete here so no consumer can
// construct, copy, or inspect them.
namespace detail {
struct ClientConfigImpl;
struct KmsClientImpl;
struct DdbClientImpl;
struct KeyStoreImpl;
struct KeyringImpl;
struct CacheImpl;
struct BytesFactory;
}  // namespace detail

class ClientConfig {
    std::shared_ptr<detail::ClientConfigImpl> impl_;
    friend class KmsClient;
    friend class DdbClient;

public:
    ClientConfig();
    ClientConfig& with_max_retry_attempts(std::uint32_t n);
    ClientConfig& with_adaptive_retry(bool a);
    ClientConfig& with_region(const std::string& r);
};

/// The KMS client a Key Store uses to call AWS KMS.
class KmsClient {
    std::shared_ptr<detail::KmsClientImpl> impl_;
    friend class KeyStore;

public:
    explicit KmsClient(const ClientConfig& cfg = {});
};

/// The DynamoDB client a Key Store uses to call Amazon DynamoDB.
class DdbClient {
    std::shared_ptr<detail::DdbClientImpl> impl_;
    friend class KeyStore;

public:
    explicit DdbClient(const ClientConfig& cfg = {});
};

/// Optional key store parameters. A field left empty is omitted from the core
/// library's key store configuration.
class KeyStoreOptions {
    std::string key_store_id_;
    std::vector<std::string> grant_tokens_;
    friend class KeyStore;

public:
    /// An identifier for this Key Store.
    KeyStoreOptions& with_id(const std::string& id) { key_store_id_ = id; return *this; }
    /// The AWS KMS grant tokens that are used when this Key Store calls to AWS KMS.
    KeyStoreOptions& with_grant_tokens(const std::vector<std::string>& tokens) { grant_tokens_ = tokens; return *this; }
};

class KeyStore {
    std::shared_ptr<detail::KeyStoreImpl> impl_;
    friend class HierarchicalKeyring;

public:
    /// Creates a Key Store backed by a DynamoDB table and protected by AWS KMS.
    /// \param table_name The DynamoDB table name that backs this Key Store.
    /// \param logical_key_store_name The logical name for this Key Store, which is
    ///        cryptographically bound to the keys it holds. This appears in the
    ///        Encryption Context of KMS requests as `tablename`.
    /// \param kms_arn Key Store is restricted to only this KMS Key ARN. If a different
    ///        KMS Key ARN is encountered when creating, versioning, or getting a Branch
    ///        Key or Beacon Key, KMS is never called and an exception is thrown.
    /// \param kms The KMS client this Key Store uses to call AWS KMS.
    /// \param ddb The DynamoDB client this Key Store uses to call Amazon DynamoDB.
    /// \param options Optional Key Store parameters.
    KeyStore(const std::string& table_name,
             const std::string& logical_key_store_name,
             const std::string& kms_arn,
             KmsClient kms,
             DdbClient ddb,
             const KeyStoreOptions& options = {});
};

/// Base type for every keyring encrypt/decrypt can accept. A concrete keyring
/// derives from it, supplies the created handle, and keeps its own dependencies
/// alive for its lifetime.
class Keyring {
    std::shared_ptr<detail::KeyringImpl> impl_;
    friend class EncryptionSDK;

protected:
    explicit Keyring(std::shared_ptr<detail::KeyringImpl> impl) : impl_(std::move(impl)) {}

public:
    virtual ~Keyring() = default;
};

/// A cryptographic materials cache for a Hierarchical Keyring, created via the
/// static factories. A keyring created without a cache uses the core library's
/// default cache. One Cache may be passed to multiple keyrings.
class Cache {
    std::shared_ptr<detail::CacheImpl> impl_;
    friend class HierarchicalKeyringOptions;
    friend class HierarchicalKeyring;
    explicit Cache(std::shared_ptr<detail::CacheImpl> impl) : impl_(std::move(impl)) {}

public:
    /// No caching: branch key material is fetched on every use.
    static Cache NoCache();
    /// Cache safe for concurrent use from multiple threads. A parameter left 0
    /// keeps the core library's default for that parameter.
    static Cache MultiThreaded(std::uint32_t entry_capacity = 0,
                               std::uint32_t entry_pruning_tail_size = 0);
};

/// Optional hierarchical keyring parameters.
/// A field left unset keeps the core library's default.
class HierarchicalKeyringOptions {
    std::shared_ptr<detail::CacheImpl> cache_;
    std::string partition_id_;
    friend class HierarchicalKeyring;

public:
    /// Sets the cache for this Hierarchical Keyring.
    HierarchicalKeyringOptions& with_cache(const Cache& cache) { cache_ = cache.impl_; return *this; }
    /// Partition ID to distinguish Cryptographic Material Providers (i.e: Keyrings) writing
    /// to a cache. If the Partition ID is the same for two Hierarchical Keyrings (or another
    /// Material Provider), they can share the same cache entries in the cache.
    HierarchicalKeyringOptions& with_partition_id(const std::string& id) { partition_id_ = id; return *this; }
};

class HierarchicalKeyring : public Keyring {
public:
    /// Creates a Hierarchical Keyring, which supports wrapping and unwrapping data keys
    /// using Branch Keys persisted in DynamoDB and protected by a symmetric AWS KMS Key or
    /// AWS KMS Multi-Region Key.
    /// \param key_store The Key Store which contains the Branch Key(s) responsible for
    ///        wrapping and unwrapping data keys.
    /// \param branch_key_id The identifier for the single Branch Key responsible for
    ///        wrapping and unwrapping the data key.
    /// \param ttl_seconds How many seconds the Branch Key material is allowed to be reused
    ///        within the local cache before it is re-retrieved from Amazon DynamoDB and
    ///        re-authenticated with AWS KMS.
    /// \param options Optional Hierarchical Keyring parameters.
    HierarchicalKeyring(KeyStore key_store,
                        const std::string& branch_key_id,
                        std::uint32_t ttl_seconds,
                        const HierarchicalKeyringOptions& options = {});
};

class RawAesKeyring : public Keyring {
public:
    /// Creates a Raw AES Keyring, which wraps and unwraps data keys locally using
    /// AES-GCM. The wrapping key bytes are copied into the keyring.
    /// \param key_namespace A namespace associated with this wrapping key.
    /// \param key_name A name associated with this wrapping key.
    /// \param wrapping_key The AES key. Its length must match the wrapping
    ///        algorithm (16, 24, or 32 bytes).
    /// \param wrapping_alg The AES-GCM algorithm used to wrap and unwrap data keys.
    RawAesKeyring(const std::string& key_namespace,
                  const std::string& key_name,
                  const std::vector<std::uint8_t>& wrapping_key,
                  AesWrappingAlgorithm wrapping_alg);
};

/// Optional encrypt parameters.
/// A field left unset keeps the core library's default.
class EncryptOptions {
    std::optional<AlgorithmSuiteId> algorithm_suite_;
    std::optional<CommitmentPolicy> commitment_policy_;
    std::map<std::string, std::string> encryption_context_;
    std::optional<std::uint32_t> frame_length_;
    std::optional<std::uint32_t> max_encrypted_data_keys_;
    friend class EncryptionSDK;

public:
    /// Algorithm suite. See <https://docs.aws.amazon.com/encryption-sdk/latest/developer-guide/supported-algorithms.html>
    EncryptOptions& with_algorithm_suite(AlgorithmSuiteId a) { algorithm_suite_ = a; return *this; }
    /// Default is CommitmentPolicy::RequireEncryptRequireDecrypt.
    EncryptOptions& with_commitment_policy(CommitmentPolicy p) { commitment_policy_ = p; return *this; }
    /// Key-value pairs to associate with the encrypted data.
    EncryptOptions& with_encryption_context(const std::map<std::string, std::string>& ec) { encryption_context_ = ec; return *this; }
    /// Bytes of plaintext data per frame. Default 4096.
    EncryptOptions& with_frame_length(std::uint32_t n) { frame_length_ = n; return *this; }
    /// 0 means no limit.
    EncryptOptions& with_max_encrypted_data_keys(std::uint32_t n) { max_encrypted_data_keys_ = n; return *this; }
};

/// Optional decrypt parameters.
/// A field left unset keeps the core library's default.
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

/// Owned, read-only byte buffer returned by encrypt and decrypt.
///
/// This owns the core (Rust) library's output buffer without copying it: the
/// data/size pair points into the core library's buffer, and a type-erased
/// owner releases it when the last Bytes referring to it is destroyed.
/// If you need a std::vector, use `.to_vector()`.
class Bytes {
    const std::uint8_t* data_ = nullptr;
    std::size_t size_ = 0;
    std::shared_ptr<void> owner_;  // keeps the core library's buffer alive
    friend struct detail::BytesFactory;
    Bytes(const std::uint8_t* data, std::size_t size, std::shared_ptr<void> owner)
        : data_(data), size_(size), owner_(std::move(owner)) {}

public:
    Bytes() = default;
    Bytes(Bytes&&) = default;
    Bytes& operator=(Bytes&&) = default;
    Bytes(const Bytes&) = delete;
    Bytes& operator=(const Bytes&) = delete;

    const std::uint8_t* data() const { return data_; }
    std::size_t size() const { return size_; }
    bool empty() const { return size_ == 0; }

    const std::uint8_t* begin() const { return data_; }
    const std::uint8_t* end() const { return data_ + size_; }
    std::uint8_t operator[](std::size_t index) const { return data_[index]; }

    /// Copies the bytes into an owning std::vector.
    std::vector<std::uint8_t> to_vector() const {
        return std::vector<std::uint8_t>(begin(), end());
    }
};

inline bool operator==(const Bytes& lhs, const std::vector<std::uint8_t>& rhs) {
    return lhs.size() == rhs.size() && std::equal(lhs.begin(), lhs.end(), rhs.begin());
}
inline bool operator==(const std::vector<std::uint8_t>& lhs, const Bytes& rhs) { return rhs == lhs; }
inline bool operator!=(const Bytes& lhs, const std::vector<std::uint8_t>& rhs) { return !(lhs == rhs); }
inline bool operator!=(const std::vector<std::uint8_t>& lhs, const Bytes& rhs) { return !(rhs == lhs); }

/// Result of encrypt: the ciphertext plus the encryption context and algorithm
/// suite the core library actually used. A CMM may add context entries and the
/// suite may be defaulted, so both can differ from what was requested.
struct EncryptResult {
    /// The encrypted message.
    Bytes ciphertext;
    /// Encryption context associated with the encrypted message.
    std::map<std::string, std::string> encryption_context;
    /// Algorithm suite used for encryption.
    AlgorithmSuiteId algorithm_suite_id;
};

/// Result of decrypt: the plaintext plus the encryption context and algorithm
/// suite that were authenticated during decryption.
struct DecryptResult {
    /// Decrypted plaintext data.
    Bytes plaintext;
    /// Encryption context recovered from the encrypted message.
    std::map<std::string, std::string> encryption_context;
    /// Algorithm suite used for decryption.
    AlgorithmSuiteId algorithm_suite_id;
};

/// Client-level configuration for EncryptionSDK, mirroring the Rust core's
/// EsdkConfig (a commitment policy and an optional cap on encrypted data
/// keys). A field set on a per-call EncryptOptions/DecryptOptions overrides
/// the same field set here; a field unset in both defers to the core
/// library's default.
class SdkOptions {
    std::optional<CommitmentPolicy> commitment_policy_;
    std::optional<std::uint32_t> max_encrypted_data_keys_;
    friend class EncryptionSDK;

public:
    /// Commitment policy applied to every operation on this client.
    SdkOptions& with_commitment_policy(CommitmentPolicy p) { commitment_policy_ = p; return *this; }
    /// Cap on the number of encrypted data keys per message, applied to every
    /// operation on this client. 0 means no limit.
    SdkOptions& with_max_encrypted_data_keys(std::uint32_t n) { max_encrypted_data_keys_ = n; return *this; }
};

class EncryptionSDK {
    std::optional<CommitmentPolicy> commitment_policy_;
    std::optional<std::uint32_t> max_encrypted_data_keys_;

public:
    /// A client with no cross-call configuration: every unset input defers to
    /// the core library's default.
    EncryptionSDK() = default;
    /// A client whose configuration applies to every operation; a per-call
    /// options object overrides it field by field.
    explicit EncryptionSDK(const SdkOptions& options)
        : commitment_policy_(options.commitment_policy_),
          max_encrypted_data_keys_(options.max_encrypted_data_keys_) {}

    EncryptResult encrypt(
        const std::vector<std::uint8_t>& plaintext,
        const Keyring& keyring,
        const EncryptOptions& options = {});

    /// Encrypts a plaintext held in any contiguous buffer — e.g. an mmap'd
    /// file or another library's buffer — without copying it into a
    /// std::vector first. The buffer must stay valid for the duration of the
    /// call; the plaintext bytes are not retained afterwards.
    EncryptResult encrypt(
        const std::uint8_t* plaintext,
        std::size_t plaintext_len,
        const Keyring& keyring,
        const EncryptOptions& options = {});

    DecryptResult decrypt(
        const std::vector<std::uint8_t>& ciphertext,
        const Keyring& keyring,
        const DecryptOptions& options = {});

    /// Decrypts a ciphertext held in a Bytes — e.g. an EncryptResult's
    /// ciphertext fed straight back in — without copying it.
    DecryptResult decrypt(
        const Bytes& ciphertext,
        const Keyring& keyring,
        const DecryptOptions& options = {});

    /// Decrypts a ciphertext held in any contiguous buffer without copying it
    /// into a std::vector first. The buffer must stay valid for the duration
    /// of the call; the ciphertext bytes are not retained afterwards.
    DecryptResult decrypt(
        const std::uint8_t* ciphertext,
        std::size_t ciphertext_len,
        const Keyring& keyring,
        const DecryptOptions& options = {});
};

}  // namespace Esdk
}  // namespace Aws
