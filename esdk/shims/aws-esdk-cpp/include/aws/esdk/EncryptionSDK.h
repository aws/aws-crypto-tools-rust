// EncryptionSDK.h — idiomatic C++ facade over the cxx-generated bindings.
//
// Design goals (learnings from the binding-strategy review):
//   * Stable, GENERATOR-AGNOSTIC public API: no cxx type (rust::*, the generated
//     enums/structs) appears in any public signature. Swapping the binding
//     backend later touches only this file's internals, not consumer code.
//   * RAII + exceptions: cxx throws rust::Error on failure; we translate that
//     into Aws::Esdk::EsdkException so callers never see a cxx type.
//   * Memory safety at the handle seam: the bridge passes handles as raw
//     `*const` pointers inside config structs, which can dangle if a C++ caller
//     drops a client before it is used. Each wrapper here OWNS its dependencies
//     via shared_ptr and declares them before the object that points at them,
//     so a dependency can never be destroyed while something references it.
#pragma once

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

// ---- File-wide owned-interface / lifetime invariants (see spec/shim/shim.md) -
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

// ---- Public exception: hides cxx's rust::Error ------------------------------
//= spec/shim/shim.md#owned-interface
//= type=implication
//= reason=EsdkException is the shim's own error type; detail::guard translates every cxx rust::Error into it, so no cxx or core-library error type appears on the public surface.
//# - The shim MUST define its own error type for its public surface.
class EsdkException : public std::runtime_error {
public:
    explicit EsdkException(const std::string& msg) : std::runtime_error(msg) {}
};

// ---- Public enums: our own, so the generated enums never leak ----------------
enum class AlgorithmSuiteId : std::uint16_t {
    AesGcm128                      = 0x0014,
    AesGcm192                      = 0x0046,
    AesGcm256                      = 0x0078,
    AesGcm128Hkdf256               = 0x0114,
    AesGcm192Hkdf256               = 0x0146,
    AesGcm256Hkdf256               = 0x0178,
    AesGcm128Hkdf256Ecdsa256       = 0x0214,
    AesGcm192Hkdf384Ecdsa384       = 0x0346,
    AesGcm256Hkdf384Ecdsa384       = 0x0378,
    AesGcm256Hkdf512Commit         = 0x0478,
    AesGcm256Hkdf512CommitEcdsa384 = 0x0578,
};

enum class CommitmentPolicy : std::uint8_t {
    ForbidEncryptAllowDecrypt  = 0,
    RequireEncryptAllowDecrypt = 1,
    RequireEncryptRequireDecrypt = 2,
};

enum class CacheKind : std::uint8_t { None = 0, MultiThreaded = 1 };

namespace detail {

// Run a cxx call, translating rust::Error -> EsdkException so no cxx exception
// type escapes this header.
template <typename F>
inline auto guard(F&& f) -> decltype(f()) {
    try {
        return f();
    } catch (const ::rust::Error& e) {
        throw EsdkException(e.what());
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

// Reverse translations, for values the core library returns to the target.
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

// ---- Fluent client config ----------------------------------------------------
class ClientConfig {
    ::MplAwsClientConfig cfg_ = ::default_client_config();
public:
    ClientConfig& with_max_retry_attempts(std::uint32_t n) { cfg_.retry.max_attempts = n; return *this; }
    ClientConfig& with_adaptive_retry(bool a)              { cfg_.retry.mode_adaptive = a; return *this; }
    ClientConfig& with_region(const std::string& r)        { cfg_.region = ::rust::String(r); return *this; }
    const ::MplAwsClientConfig& raw() const { return cfg_; }   // internal; POD-ish, low leak risk
};

// ---- Handle wrappers: copyable (shared_ptr), so they can be owned as deps -----
class KmsClient {
    std::shared_ptr<::rust::Box<::MplKmsClient>> inner_;
    const ::MplKmsClient* ffi() const { return &**inner_; }
    friend class KeyStore;
public:
    explicit KmsClient(const ClientConfig& cfg)
        : inner_(std::make_shared<::rust::Box<::MplKmsClient>>(
              detail::guard([&] { return ::create_kms_client(cfg.raw()); }))) {}
};

class DdbClient {
    std::shared_ptr<::rust::Box<::MplDdbClient>> inner_;
    const ::MplDdbClient* ffi() const { return &**inner_; }
    friend class KeyStore;
public:
    explicit DdbClient(const ClientConfig& cfg)
        : inner_(std::make_shared<::rust::Box<::MplDdbClient>>(
              detail::guard([&] { return ::create_ddb_client(cfg.raw()); }))) {}
};

// Optional key store parameters. A field left empty is omitted from the core
// library's key store configuration.
class KeyStoreOptions {
    std::string key_store_id_;
    std::vector<std::string> grant_tokens_;
    friend class KeyStore;

public:
    KeyStoreOptions& with_key_store_id(const std::string& id) { key_store_id_ = id; return *this; }
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

// Base type for every keyring encrypt/decrypt can accept. A concrete keyring
// (e.g. HierarchicalKeyring) derives from it, creates the generated handle, and
// keeps its own dependencies alive; the base owns the handle.
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

// Optional hierarchical keyring parameters. A field left unset keeps the
// Rust-defined default from default_hierarchical_keyring_input(); an empty
// partition id is omitted from the core library's input.
class HierarchicalKeyringOptions {
    std::optional<CacheKind> cache_;
    std::optional<std::uint32_t> cache_capacity_;
    std::string partition_id_;
    friend class HierarchicalKeyring;

public:
    HierarchicalKeyringOptions& with_cache(CacheKind kind) { cache_ = kind; return *this; }
    HierarchicalKeyringOptions& with_cache_capacity(std::uint32_t entries) { cache_capacity_ = entries; return *this; }
    HierarchicalKeyringOptions& with_partition_id(const std::string& id) { partition_id_ = id; return *this; }
};

class HierarchicalKeyring : public Keyring {
    KeyStore key_store_;  // owns the keystore (and transitively its clients)
public:
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
            in.ttl = ttl_seconds;
            in.partition_id = ::rust::String(options.partition_id_);
            if (options.cache_) in.cache = detail::to_ffi(*options.cache_);
            if (options.cache_capacity_) in.multi_threaded_cache.entryCapacity = *options.cache_capacity_;
            return ::create_hierarchical_keyring(in);
        }));
    }
};

// Optional encrypt parameters. A field left unset keeps the Rust-defined
// default from default_encrypt_input(), so defaults live only in the Rust core.
class EncryptOptions {
    std::optional<AlgorithmSuiteId> algorithm_suite_;
    std::optional<CommitmentPolicy> commitment_policy_;
    std::map<std::string, std::string> encryption_context_;
    std::optional<std::uint32_t> frame_length_;
    std::optional<std::uint32_t> max_encrypted_data_keys_;
    friend class EncryptionSDK;

public:
    EncryptOptions& with_algorithm_suite(AlgorithmSuiteId a) { algorithm_suite_ = a; return *this; }
    EncryptOptions& with_commitment_policy(CommitmentPolicy p) { commitment_policy_ = p; return *this; }
    EncryptOptions& with_encryption_context(const std::map<std::string, std::string>& ec) { encryption_context_ = ec; return *this; }
    EncryptOptions& with_frame_length(std::uint32_t n) { frame_length_ = n; return *this; }
    /// 0 means no limit.
    EncryptOptions& with_max_encrypted_data_keys(std::uint32_t n) { max_encrypted_data_keys_ = n; return *this; }
};

// Optional decrypt parameters. A field left unset keeps the Rust-defined
// default from default_decrypt_input().
class DecryptOptions {
    std::optional<CommitmentPolicy> commitment_policy_;
    std::map<std::string, std::string> encryption_context_;
    std::optional<std::uint32_t> max_encrypted_data_keys_;
    friend class EncryptionSDK;

public:
    DecryptOptions& with_commitment_policy(CommitmentPolicy p) { commitment_policy_ = p; return *this; }
    DecryptOptions& with_encryption_context(const std::map<std::string, std::string>& ec) { encryption_context_ = ec; return *this; }
    /// 0 means no limit.
    DecryptOptions& with_max_encrypted_data_keys(std::uint32_t n) { max_encrypted_data_keys_ = n; return *this; }
};

// encrypt returns the ciphertext plus the encryption context and algorithm suite
// the core library actually used; a CMM may add context entries and the suite may
// be defaulted, so both can differ from what the caller requested.
struct EncryptResult {
    std::vector<std::uint8_t> ciphertext;
    std::map<std::string, std::string> encryption_context;
    AlgorithmSuiteId algorithm_suite_id;
};

// ---- Decrypt result ----------------------------------------------------------
// decrypt returns not just the plaintext but the encryption context and algorithm
// suite the core library reported, so the caller can inspect what was actually
// used and authenticated (for example, to make access-control decisions).
struct DecryptResult {
    std::vector<std::uint8_t> plaintext;
    std::map<std::string, std::string> encryption_context;
    AlgorithmSuiteId algorithm_suite_id;
};

// ---- SDK facade --------------------------------------------------------------
class EncryptionSDK {
public:
    EncryptResult encrypt(
        const std::vector<std::uint8_t>& plaintext,
        const Keyring& keyring,
        const EncryptOptions& options = {}) {
        // Start from the Rust-defined defaults, then override only the fields
        // the caller set — so we never re-declare defaults in C++ and risk
        // diverging from the Rust core.
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
        result.ciphertext = std::vector<std::uint8_t>(out.ciphertext.begin(), out.ciphertext.end());
        result.encryption_context = detail::from_ec(out.encryption_context);
        result.algorithm_suite_id = detail::alg_from_ffi(out.algorithm_suite_id);
        return result;
    }

    DecryptResult decrypt(
        const std::vector<std::uint8_t>& ciphertext,
        const Keyring& keyring,
        const DecryptOptions& options = {}) {
        ::DecryptInput in = ::default_decrypt_input();
        in.keyring = keyring.ffi();
        in.ciphertext = ::rust::Slice<const std::uint8_t>(ciphertext.data(), ciphertext.size());
        in.encryption_context = detail::to_ec(options.encryption_context_);
        if (options.commitment_policy_) in.commitment_policy = detail::to_ffi(*options.commitment_policy_);
        if (options.max_encrypted_data_keys_) in.max_encrypted_data_keys = *options.max_encrypted_data_keys_;
        ::DecryptOutput out = detail::guard([&] { return ::decrypt(in); });
        DecryptResult result;
        result.plaintext = std::vector<std::uint8_t>(out.plaintext.begin(), out.plaintext.end());
        result.encryption_context = detail::from_ec(out.encryption_context);
        result.algorithm_suite_id = detail::alg_from_ffi(out.algorithm_suite_id);
        return result;
    }
};

}  // namespace Esdk
}  // namespace Aws
