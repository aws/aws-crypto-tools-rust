// EncryptionSDK.h — public types to interact with the C++ Shim for the AWS Encryption SDK for Rust.

#pragma once

#include <algorithm>
#include <cstdint>
#include <map>
#include <memory>
#include <optional>
#include <stdexcept>
#include <string>
#include <vector>

#include "rust/cxx.h"                 // rust::Error, rust::Box, rust::Vec, rust::Slice
#include "aws-esdk-cpp/src/lib.rs.h"  // cxx-generated bindings (global namespace)

namespace Aws {
namespace Esdk {

// File-wide invariants.
// Each requirement below holds for every type and operation in this facade.
// These cannot be explicitly tested, but are recorded as implications.
// Any edits to this file must respect these requirements.
//
//= spec/shim/shim.md#owned-interface
//= type=implication
//= reason=The facade defines its own Aws::Esdk:: enums and does not expose any ffi-generated enum types.
//# - For each core-library enumeration it exposes, the shim MUST define its own
//# corresponding enumeration type.
//
//= spec/shim/shim.md#owned-interface
//= type=implication
//= reason=Every public method signature uses only Aws::Esdk:: types and standard-library types.
//# - Each public function the shim exposes MUST use only owned-interface types or
//# standard-library types in its signature.
//
//= spec/shim/shim.md#owned-interface
//= type=implication
//= reason=Every wrapper stores its generated handle in a private member and exposes it only through the internal ffi() accessor.
//# - Each owned interface that represents a core-library resource MUST hold the
//# generated handle privately and MUST NOT expose it in its public API.
//
//= spec/shim/shim.md#handles-and-lifetimes
//= type=implication
//= reason=Each wrapper that depends on another resource holds it as a member declared before its own handle to prevent this.
//# - An owned interface that depends on another resource MUST retain ownership of
//# that resource for its own lifetime, so that a handle passed across the boundary
//# cannot outlive the resource it refers to.
//
//= spec/shim/shim.md#operation-contracts
//= type=implication
//= reason=Every optional input has a with_* setter on the operation's or resource's options object.
//# - The shim MUST expose each optional input of the operations and resource
//# creations it exposes.
//
//= spec/shim/shim.md#operation-contracts
//= type=implication
//= reason=Options objects with chained with_* setters are the idiomatic C++ optional-input mechanism.
//# - The shim MUST accept optional inputs through a mechanism idiomatic to the
//# target language (e.g.
//
//= spec/shim/shim.md#operation-contracts
//= type=implication
//= reason=The with_* setters provide this
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
//= reason=AwsEncryptionSdkException is the shim's own error type; detail::guard translates every cxx rust::Error into it, so no cxx or core-library error type appears on the public surface.
//# - The shim MUST define its own error type for its public surface.
class AwsEncryptionSdkException : public std::runtime_error {
public:
    explicit AwsEncryptionSdkException(const std::string& msg) : std::runtime_error(msg) {}
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

namespace detail {

// Calls into Rust and catches any Rust error, re-throwing it as our
// own C++ exception type so callers only ever see AwsEncryptionSdkException.
template <typename F>
inline auto guard(F&& f) -> decltype(f()) {
    try {
        return f();
    } catch (const ::rust::Error& e) {
        throw AwsEncryptionSdkException(e.what());
    }
}

// Convert our enums to the generated FFI enums.
// Users must depend on these ESDK enums so changes to the FFI layer don't break them.
inline ::EsdkAlgorithmSuiteId to_ffi(AlgorithmSuiteId a) {
    return static_cast<::EsdkAlgorithmSuiteId>(static_cast<std::uint16_t>(a));
}
inline ::EsdkCommitmentPolicy to_ffi(CommitmentPolicy p) {
    return static_cast<::EsdkCommitmentPolicy>(static_cast<std::uint8_t>(p));
}

inline ::rust::Vec<::EncryptionContextItem> to_ec(
    const std::map<std::string, std::string>& ec) {
    ::rust::Vec<::EncryptionContextItem> out;
    for (const auto& kv : ec) {
        ::EncryptionContextItem item;
        item.key = ::rust::String(kv.first);
        item.value = ::rust::String(kv.second);
        out.push_back(std::move(item));
    }
    return out;
}

inline AlgorithmSuiteId alg_from_ffi(::EsdkAlgorithmSuiteId a) {
    return static_cast<AlgorithmSuiteId>(static_cast<std::uint16_t>(a));
}

inline std::map<std::string, std::string> from_ec(
    const ::rust::Vec<::EncryptionContextItem>& ec) {
    std::map<std::string, std::string> out;
    for (const auto& item : ec) {
        out.emplace(std::string(item.key), std::string(item.value));
    }
    return out;
}

}  // namespace detail

class ClientConfig {
    ::MplAwsClientConfig cfg_{};
    const ::MplAwsClientConfig& raw() const { return cfg_; }
    friend class KmsClient;
    friend class DdbClient;
public:
    ClientConfig& with_max_retry_attempts(std::uint32_t n) { cfg_.retry.max_attempts = n; return *this; }
    ClientConfig& with_adaptive_retry(bool a)              { cfg_.retry.mode_adaptive = a; return *this; }
    ClientConfig& with_region(const std::string& r)        { cfg_.region = ::rust::String(r); return *this; }
};

/// The KMS client this Key Store uses to call AWS KMS.
class KmsClient {
    std::shared_ptr<::rust::Box<::MplKmsClient>> inner_;
    const ::MplKmsClient* ffi() const { return &**inner_; }
    friend class KeyStore;
public:
    explicit KmsClient(const ClientConfig& cfg)
        : inner_(std::make_shared<::rust::Box<::MplKmsClient>>(
              detail::guard([&] { return ::create_kms_client(cfg.raw()); }))) {}
};

/// The DynamoDB client this Key Store uses to call Amazon DynamoDB.
class DdbClient {
    std::shared_ptr<::rust::Box<::MplDdbClient>> inner_;
    const ::MplDdbClient* ffi() const { return &**inner_; }
    friend class KeyStore;
public:
    explicit DdbClient(const ClientConfig& cfg)
        : inner_(std::make_shared<::rust::Box<::MplDdbClient>>(
              detail::guard([&] { return ::create_ddb_client(cfg.raw()); }))) {}
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
    // kms and ddb must be declared before inner_ (core, Rust) keystore
    // so they are destroyed after inner_ is
    KmsClient kms_;
    DdbClient ddb_;
    std::shared_ptr<::rust::Box<::KeyStore>> inner_;
    const ::KeyStore* ffi() const { return &**inner_; }
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
             const KeyStoreOptions& options = {})
        : kms_(std::move(kms)),
          ddb_(std::move(ddb)),
          inner_(std::make_shared<::rust::Box<::KeyStore>>(detail::guard([&] {
              ::KeyStoreConfig c{};
              c.ddb_table_name = ::rust::String(table_name);
              c.logical_key_store_name = ::rust::String(logical_key_store_name);
              c.kms_configuration_type = ::KmsConfigurationType::KmsKeyArn;
              c.kms_configuration_value = ::rust::String(kms_arn);
              c.id = ::rust::String(options.key_store_id_);
              for (const auto& token : options.grant_tokens_) {
                  c.grant_tokens.push_back(::rust::String(token));
              }
              c.kms_client = kms_.ffi();
              c.ddb_client = ddb_.ffi();
              return ::create_keystore(c);
          }))) {}
};

/// Base type for every keyring encrypt/decrypt can accept. A concrete keyring
/// derives from it, supplies the created handle, and keeps its own dependencies
/// alive for its lifetime.
class Keyring {
    std::shared_ptr<::rust::Box<::Keyring>> inner_;
    const ::Keyring* ffi() const { return &**inner_; }
    friend class EncryptionSDK;

protected:
    explicit Keyring(std::shared_ptr<::rust::Box<::Keyring>> inner)
        : inner_(std::move(inner)) {}

public:
    virtual ~Keyring() = default;
};

/// A cryptographic materials cache for a Hierarchical Keyring, created via the
/// static factories. A keyring created without a cache uses the core library's
/// default cache. One Cache may be passed to multiple keyrings.
class Cache {
    std::shared_ptr<::rust::Box<::Cache>> inner_;
    friend class HierarchicalKeyringOptions;
    friend class HierarchicalKeyring;
    explicit Cache(::rust::Box<::Cache> inner)
        : inner_(std::make_shared<::rust::Box<::Cache>>(std::move(inner))) {}

public:
    /// No caching: branch key material is fetched on every use.
    static Cache NoCache() {
        return Cache(detail::guard([] { return ::create_no_cache(); }));
    }
    /// Cache safe for concurrent use from multiple threads. A parameter left 0
    /// keeps the core library's default for that parameter.
    static Cache MultiThreaded(std::uint32_t entry_capacity = 0,
                               std::uint32_t entry_pruning_tail_size = 0) {
        return Cache(detail::guard([&] {
            return ::create_multi_threaded_cache(entry_capacity, entry_pruning_tail_size);
        }));
    }
};

/// Optional hierarchical keyring parameters.
/// A field left unset keeps the core library's default.
class HierarchicalKeyringOptions {
    std::shared_ptr<::rust::Box<::Cache>> cache_;
    std::string partition_id_;
    friend class HierarchicalKeyring;

public:
    /// Sets the cache for this Hierarchical Keyring.
    HierarchicalKeyringOptions& with_cache(const Cache& cache) { cache_ = cache.inner_; return *this; }
    /// Partition ID to distinguish Cryptographic Material Providers (i.e: Keyrings) writing
    /// to a cache. If the Partition ID is the same for two Hierarchical Keyrings (or another
    /// Material Provider), they can share the same cache entries in the cache.
    HierarchicalKeyringOptions& with_partition_id(const std::string& id) { partition_id_ = id; return *this; }
};

class HierarchicalKeyring : public Keyring {
    KeyStore key_store_;  // owns the keystore (and transitively its clients)
    std::shared_ptr<::rust::Box<::Cache>> cache_;  // retains the cache handle, if one was supplied
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
                        const HierarchicalKeyringOptions& options = {})
        : Keyring(create(key_store, branch_key_id, ttl_seconds, options)),
          key_store_(std::move(key_store)),
          cache_(options.cache_) {}

private:
    static std::shared_ptr<::rust::Box<::Keyring>> create(const KeyStore& key_store,
                                                          const std::string& branch_key_id,
                                                          std::uint32_t ttl_seconds,
                                                          const HierarchicalKeyringOptions& options) {
        return std::make_shared<::rust::Box<::Keyring>>(detail::guard([&] {
            ::HierarchicalKeyringInput in{};
            in.branch_key_id = ::rust::String(branch_key_id);
            in.key_store = key_store.ffi();
            in.ttl_seconds = ttl_seconds;
            in.partition_id = ::rust::String(options.partition_id_);
            if (options.cache_) in.cache = &**options.cache_;
            return ::create_hierarchical_keyring(in);
        }));
    }
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
/// This owns the core (Rust) library's output buffer; not a C++ type.
/// This setup allows readers to read outputs without a copy, improving performance.
/// If you need a std::vector, use `.to_vector()`.
class Bytes {
    ::rust::Vec<std::uint8_t> buf_;
    friend class EncryptionSDK;
    explicit Bytes(::rust::Vec<std::uint8_t> buf) : buf_(std::move(buf)) {}

public:
    Bytes() = default;
    Bytes(Bytes&&) = default;
    Bytes& operator=(Bytes&&) = default;
    Bytes(const Bytes&) = delete;
    Bytes& operator=(const Bytes&) = delete;

    const std::uint8_t* data() const { return buf_.data(); }
    std::size_t size() const { return buf_.size(); }
    bool empty() const { return buf_.empty(); }

    const std::uint8_t* begin() const { return buf_.data(); }
    const std::uint8_t* end() const { return buf_.data() + buf_.size(); }
    std::uint8_t operator[](std::size_t index) const { return buf_[index]; }

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

class EncryptionSDK {
public:
    EncryptResult encrypt(
        const std::vector<std::uint8_t>& plaintext,
        const Keyring& keyring,
        const EncryptOptions& options = {}) {
        // Overrides only the fields the caller set, so defaults are never
        // re-declared in C++ and cannot diverge from the Rust core.
        ::EncryptInput in{};
        in.keyring = keyring.ffi();
        in.plaintext = ::rust::Slice<const std::uint8_t>(plaintext.data(), plaintext.size());
        in.encryption_context = detail::to_ec(options.encryption_context_);
        if (options.algorithm_suite_) in.algorithm_suite_id = detail::to_ffi(*options.algorithm_suite_);
        if (options.commitment_policy_) in.commitment_policy = detail::to_ffi(*options.commitment_policy_);
        if (options.frame_length_) in.frame_length = *options.frame_length_;
        if (options.max_encrypted_data_keys_) in.max_encrypted_data_keys = *options.max_encrypted_data_keys_;
        ::EncryptOutput out = detail::guard([&] { return ::encrypt(in); });
        EncryptResult result;
        result.ciphertext = Bytes(std::move(out.ciphertext));
        result.encryption_context = detail::from_ec(out.encryption_context);
        result.algorithm_suite_id = detail::alg_from_ffi(out.algorithm_suite_id);
        return result;
    }

    DecryptResult decrypt(
        const std::vector<std::uint8_t>& ciphertext,
        const Keyring& keyring,
        const DecryptOptions& options = {}) {
        return decrypt_bytes(ciphertext.data(), ciphertext.size(), keyring, options);
    }

    /// Decrypts a ciphertext held in a Bytes — e.g. an EncryptResult's
    /// ciphertext fed straight back in — without copying it.
    DecryptResult decrypt(
        const Bytes& ciphertext,
        const Keyring& keyring,
        const DecryptOptions& options = {}) {
        return decrypt_bytes(ciphertext.data(), ciphertext.size(), keyring, options);
    }

private:
    DecryptResult decrypt_bytes(
        const std::uint8_t* ciphertext,
        std::size_t ciphertext_len,
        const Keyring& keyring,
        const DecryptOptions& options) {
        ::DecryptInput in{};
        in.keyring = keyring.ffi();
        in.ciphertext = ::rust::Slice<const std::uint8_t>(ciphertext, ciphertext_len);
        in.encryption_context = detail::to_ec(options.encryption_context_);
        if (options.commitment_policy_) in.commitment_policy = detail::to_ffi(*options.commitment_policy_);
        if (options.max_encrypted_data_keys_) in.max_encrypted_data_keys = *options.max_encrypted_data_keys_;
        ::DecryptOutput out = detail::guard([&] { return ::decrypt(in); });
        DecryptResult result;
        result.plaintext = Bytes(std::move(out.plaintext));
        result.encryption_context = detail::from_ec(out.encryption_context);
        result.algorithm_suite_id = detail::alg_from_ffi(out.algorithm_suite_id);
        return result;
    }
};

}  // namespace Esdk
}  // namespace Aws
