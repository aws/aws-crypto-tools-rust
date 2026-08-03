// EncryptionSDK.h — idiomatic C++ facade over the cxx-generated bindings.
//
// Design invariants:
//   * Stable, GENERATOR-AGNOSTIC public API: no cxx type (rust::*, the generated
//     enums/structs) appears in any public signature, so swapping the binding
//     backend touches only this file's internals, not consumer code.
//   * RAII + exceptions: cxx throws rust::Error on failure; we translate that
//     into Aws::Esdk::AwsEncryptionSdkException so callers never see a cxx type.
//   * Memory safety at the handle seam: the bridge passes handles as raw
//     `*const` pointers inside config structs, which can dangle if a C++ caller
//     drops a client before it is used. Each wrapper here OWNS its dependencies
//     via shared_ptr and declares them before the object that points at them,
//     so a dependency can never be destroyed while something references it.
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

// File-wide invariants (see spec/shim/shim.md): each requirement below holds
// for every wrapper, options type, and operation in this facade, so it is
// recorded once here. Optional inputs are options objects with chained with_*
// setters over std::optional fields; only fields the caller set override the
// bridge's default_*_input() values.
//= spec/shim/shim.md#owned-interface
//= type=implication
//= reason=The facade defines its own Aws::Esdk:: enum for every core-library enumeration it exposes (AlgorithmSuiteId, CommitmentPolicy, CacheKind).
//# - For each core-library enumeration it exposes, the shim MUST define its own
//# corresponding enumeration type.
//
//= spec/shim/shim.md#owned-interface
//= type=implication
//= reason=Every public method signature uses only Aws::Esdk:: types and standard-library types; no generated or core-library type appears.
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
//# - An owned interface that depends on another resource MUST retain ownership of
//# that resource for its own lifetime, so that a handle passed across the boundary
//# cannot outlive the resource it refers to.
//
//= spec/shim/shim.md#operation-contracts
//= type=implication
//= reason=Every optional input is a with_* setter on the operation's or resource's options object.
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
//= reason=A new optional input is a new with_* setter and defaulted field on an options object; existing call sites keep compiling.
//# - The shim MUST define its operation and resource-creation inputs such that
//# an optional input can be added without breaking existing target code.
//
//= spec/shim/shim.md#operation-contracts
//= reason=Options fields are std::optional (or empty); an operation overrides a default_*_input() value only when the caller set the field.
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
    ForbidEncryptAllowDecrypt  = 0,
    RequireEncryptAllowDecrypt = 1,
    RequireEncryptRequireDecrypt = 2,
};

enum class CacheKind : std::uint8_t {
    /// No caching: branch key material is fetched on every use.
    None = 0,
    /// Cache safe for concurrent use from multiple threads.
    MultiThreaded = 1,
};

namespace detail {

// Run a cxx call, translating rust::Error -> AwsEncryptionSdkException so no cxx
// exception type escapes this header.
template <typename F>
inline auto guard(F&& f) -> decltype(f()) {
    try {
        return f();
    } catch (const ::rust::Error& e) {
        throw AwsEncryptionSdkException(e.what());
    }
}

// Enum translation is the only code that knows the generated enum types exist.
// Values are kept identical to the generated enums, so casts are exact.
inline ::EsdkAlgorithmSuiteId to_ffi(AlgorithmSuiteId a) {
    return static_cast<::EsdkAlgorithmSuiteId>(static_cast<std::uint16_t>(a));
}
inline ::EsdkCommitmentPolicy to_ffi(CommitmentPolicy p) {
    return static_cast<::EsdkCommitmentPolicy>(static_cast<std::uint8_t>(p));
}
inline ::CacheType to_ffi(CacheKind c) {
    return static_cast<::CacheType>(static_cast<std::uint8_t>(c));
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
    ::MplAwsClientConfig cfg_ = ::default_client_config();
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
    // Declared before inner_ so they outlive it; shared_ptr keeps the Rust
    // clients alive for as long as this KeyStore exists -> the raw pointers the
    // bridge stores can never dangle.
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
              ::KeyStoreConfig c = ::default_keystore_config();
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

/// Optional hierarchical keyring parameters. A field left unset keeps the core
/// library's default; an empty partition id is omitted.
class HierarchicalKeyringOptions {
    std::optional<CacheKind> cache_;
    std::optional<std::uint32_t> cache_capacity_;
    std::string partition_id_;
    friend class HierarchicalKeyring;

public:
    /// Sets the type of cache for this Hierarchical Keyring.
    HierarchicalKeyringOptions& with_cache(CacheKind kind) { cache_ = kind; return *this; }
    /// Maximum number of entries cached.
    HierarchicalKeyringOptions& with_cache_capacity(std::uint32_t entries) { cache_capacity_ = entries; return *this; }
    /// Partition ID to distinguish Cryptographic Material Providers (i.e: Keyrings) writing
    /// to a cache. If the Partition ID is the same for two Hierarchical Keyrings (or another
    /// Material Provider), they can share the same cache entries in the cache.
    HierarchicalKeyringOptions& with_partition_id(const std::string& id) { partition_id_ = id; return *this; }
};

class HierarchicalKeyring : public Keyring {
    KeyStore key_store_;  // owns the keystore (and transitively its clients)
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
          key_store_(std::move(key_store)) {}

private:
    static std::shared_ptr<::rust::Box<::Keyring>> create(const KeyStore& key_store,
                                                          const std::string& branch_key_id,
                                                          std::uint32_t ttl_seconds,
                                                          const HierarchicalKeyringOptions& options) {
        return std::make_shared<::rust::Box<::Keyring>>(detail::guard([&] {
            ::HierarchicalKeyringInput in = ::default_hierarchical_keyring_input();
            in.branch_key_id = ::rust::String(branch_key_id);
            in.key_store = key_store.ffi();
            in.ttl_seconds = ttl_seconds;
            in.partition_id = ::rust::String(options.partition_id_);
            if (options.cache_) in.cache = detail::to_ffi(*options.cache_);
            if (options.cache_capacity_) in.multi_threaded_cache.entryCapacity = *options.cache_capacity_;
            return ::create_hierarchical_keyring(in);
        }));
    }
};

/// Optional encrypt parameters. A field left unset keeps the core library's
/// default.
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

/// Optional decrypt parameters. A field left unset keeps the core library's
/// default.
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
/// It owns the core library's output buffer, so obtaining it and reading it —
/// data()/size(), indexing, iteration, comparison — never copy. to_vector() is
/// the only accessor that copies. Move-only, so the buffer is never duplicated
/// implicitly; call to_vector() when an owning std::vector is required.
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
        ::EncryptInput in = ::default_encrypt_input();
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
        ::DecryptInput in = ::default_decrypt_input();
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
