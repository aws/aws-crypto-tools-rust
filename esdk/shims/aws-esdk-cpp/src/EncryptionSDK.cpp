// EncryptionSDK.cpp - translates public types in EncryptionSDK.h to private cxx-generated types

#include "aws/esdk/EncryptionSDK.h"

#include <algorithm>
#include <map>
#include <optional>
#include <string>
#include <string_view>
#include <utility>

#include "rust/cxx.h"                 // rust::Error, rust::Box, rust::Vec, rust::Slice
#include "aws-esdk-cpp/src/lib.rs.h"  // cxx-generated bindings (namespace aws_esdk_ffi)

namespace ffi = ::aws_esdk_ffi;

namespace Aws::Esdk {
inline namespace abi_v1 {
namespace detail {

// A Rust error, decoded from the string lib.rs's encode_err builds.
struct ShimError {
    ::ffi::ShimErrorKind kind;
    ErrorDetails details;
    std::string message;
};

// Parses a small non-negative decimal number; nullopt if `v` is not one.
std::optional<std::uint8_t> parse_repr(std::string_view v) {
    if (v.empty() || v.size() > 3) {
        return std::nullopt;
    }
    unsigned value = 0;
    for (const char c : v) {
        if (c < '0' || c > '9') {
            return std::nullopt;
        }
        value = value * 10 + static_cast<unsigned>(c - '0');
    }
    if (value > 255) {
        return std::nullopt;
    }
    return static_cast<std::uint8_t>(value);
}

// Parses a decimal byte length; nullopt if `v` is not one.
std::optional<std::size_t> parse_len(std::string_view v) {
    if (v.empty() || v.size() > 9) {
        return std::nullopt;
    }
    std::size_t value = 0;
    for (const char c : v) {
        if (c < '0' || c > '9') {
            return std::nullopt;
        }
        value = value * 10 + static_cast<std::size_t>(c - '0');
    }
    return value;
}

std::optional<std::string> non_empty(std::string_view v) {
    if (v.empty()) {
        return std::nullopt;
    }
    return std::string(v);
}

// The message part of `what`, without the header: what follows the header end, or all of `what`.
std::string message_part(std::string_view what) {
    const auto header_end = what.find('\x1e');
    return std::string(header_end == std::string_view::npos ? what : what.substr(header_end + 1));
}

// nullopt when `what` does not have the encode_err layout.
std::optional<ShimError> decode_shim_error(std::string_view what) {
    const auto header_end = what.find('\x1e');
    if (header_end == std::string_view::npos) {
        return std::nullopt;
    }
    std::map<std::string_view, std::string_view> fields;
    std::string_view header = what.substr(0, header_end);
    while (!header.empty()) {
        const auto sep = header.find('\x1f');
        const auto field = header.substr(0, sep);
        const auto eq = field.find('=');
        if (eq != std::string_view::npos) {
            fields[field.substr(0, eq)] = field.substr(eq + 1);
        }
        if (sep == std::string_view::npos) {
            break;
        }
        header.remove_prefix(sep + 1);
    }
    const auto kind = parse_repr(fields["kind"]);
    if (!kind) {
        return std::nullopt;
    }
    ErrorDetails details;
    details.retryable = fields["retryable"] == "1";
    const auto retry = fields["retry"];
    if (retry == "transient") {
        details.retry_kind = RetryKind::Transient;
    } else if (retry == "throttling") {
        details.retry_kind = RetryKind::Throttling;
    } else if (retry == "server") {
        details.retry_kind = RetryKind::Server;
    } else if (retry == "client") {
        details.retry_kind = RetryKind::Client;
    }
    const auto service = fields["service"];
    if (service == "kms") {
        details.service = Service::Kms;
    } else if (service == "dynamodb") {
        details.service = Service::DynamoDb;
    }
    const auto resource_type = fields["resource_type"];
    const std::string resource(fields["resource"]);
    if (resource_type == "kms_key") {
        details.resource = Resource{ResourceType::KmsKey, resource};
    } else if (resource_type == "dynamodb_table") {
        details.resource = Resource{ResourceType::DynamoDbTable, resource};
    } else if (resource_type == "branch_key") {
        details.resource = Resource{ResourceType::BranchKey, resource};
    } else if (resource_type == "cache") {
        details.resource = Resource{ResourceType::Cache, ""};
    } else if (resource_type == "keyring") {
        details.resource = Resource{ResourceType::Keyring, resource};
    } else if (resource_type == "cmm") {
        details.resource = Resource{ResourceType::Cmm, resource};
    } else if (!resource_type.empty()) {
        details.resource = Resource{ResourceType::Unknown, resource};
    }
    details.code = non_empty(fields["code"]);
    details.request_id = non_empty(fields["request_id"]);
    const auto reason = fields["conflict_reason"];
    if (reason == "already_exists") {
        details.conflict_reason = ConflictReason::AlreadyExists;
    } else if (reason == "concurrent_modification") {
        details.conflict_reason = ConflictReason::ConcurrentModification;
    }
    details.credentials = fields["credentials"] == "1";
    details.name = std::string(fields["name"]);
    // The message part is the Rust `{}` text, `display_len` bytes, then the `{:#}` text,
    // `full_len` bytes, then the Rust backtrace.
    const std::string_view body = what.substr(header_end + 1);
    const auto display_len = parse_len(fields["display_len"]);
    const auto full_len = parse_len(fields["full_len"]);
    if (!display_len || !full_len || *display_len > body.size() ||
        *full_len > body.size() - *display_len) {
        return std::nullopt;
    }
    details.full_message = std::string(body.substr(*display_len, *full_len));
    details.backtrace = std::string(body.substr(*display_len + *full_len));
    return ShimError{
        static_cast<::ffi::ShimErrorKind>(*kind),
        std::move(details),
        std::string(body.substr(0, *display_len)),
    };
}

// Rethrow a Rust error as the matching C++ exception.
[[noreturn]] void throw_shim_exception(const std::string& what) {
    auto error = decode_shim_error(what);
    if (!error) {
        throw AwsEncryptionSdkException(message_part(what));
    }
    auto& m = error->message;
    auto& d = error->details;
    switch (error->kind) {
        case ::ffi::ShimErrorKind::Validation: throw ValidationException(m, std::move(d));
        case ::ffi::ShimErrorKind::Serialization: throw SerializationException(m, std::move(d));
        case ::ffi::ShimErrorKind::Cryptographic: throw CryptographicException(m, std::move(d));
        case ::ffi::ShimErrorKind::InvalidMaterials: throw InvalidMaterialsException(m, std::move(d));
        case ::ffi::ShimErrorKind::EncryptionContextMismatch: throw EncryptionContextMismatchException(m, std::move(d));
        case ::ffi::ShimErrorKind::NoMatchingDataKey: throw NoMatchingDataKeyException(m, std::move(d));
        case ::ffi::ShimErrorKind::AccessDenied: throw AccessDeniedException(m, std::move(d));
        case ::ffi::ShimErrorKind::ResourceNotFound: throw ResourceNotFoundException(m, std::move(d));
        case ::ffi::ShimErrorKind::Service: throw ServiceException(m, std::move(d));
        case ::ffi::ShimErrorKind::Dispatch: throw DispatchException(m, std::move(d));
        case ::ffi::ShimErrorKind::Internal: throw InternalException(m, std::move(d));
        case ::ffi::ShimErrorKind::Io: throw IoException(m, std::move(d));
        case ::ffi::ShimErrorKind::Throttling: throw ThrottlingException(m, std::move(d));
        case ::ffi::ShimErrorKind::Conflict: throw ConflictException(m, std::move(d));
        //= spec/shim/shim.md#error-classification
        //# - An error whose kind the shim does not expose MUST be reported as the shim's
        //# own base error type.
        default: throw AwsEncryptionSdkException(std::nullopt, std::move(d), m);
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

::ffi::Duration to_ffi(std::chrono::nanoseconds d, const char* field) {
    if (d.count() < 0) {
        throw ValidationException(std::string(field) + " must not be negative");
    }
    const auto secs = std::chrono::duration_cast<std::chrono::seconds>(d);
    return ::ffi::Duration{static_cast<std::uint64_t>(secs.count()),
                           static_cast<std::uint32_t>((d - secs).count())};
}

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
::ffi::OptString to_opt(const std::optional<std::string>& o) {
    return o ? ::ffi::OptString{true, ::rust::String(*o)} : ::ffi::OptString{false, {}};
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

// MPL Client Config

struct ClientConfigImpl {
    ::ffi::MplAwsClientConfig cfg{};
};

// Resources

// Resources may depend on other resources.
// (ex. KeyStore depends on KMS and DDB clients.)
// All dependent resources are stored in the resource's `retained` field.
// What a resource retains is fixed by its type (ex. Keyring);
// an HKeyring may retain a Key Store and cache, while a raw AES keyring may retain nothing.
using Retained = std::vector<std::shared_ptr<void>>;

struct KmsClientImpl {
    // `retained` must be declared before the handle so its resources are destroyed last.
    // In C++, destructor behavior is declared first -> destroyed last.
    // Dependent resources must be destroyed after the handle that depends on them to avoid NPE in resource operation.
    Retained retained;
    ::rust::Box<::ffi::MplKmsClient> handle;
    KmsClientImpl(Retained deps, ::rust::Box<::ffi::MplKmsClient> h)
        : retained(std::move(deps)), handle(std::move(h)) {}
};

struct DdbClientImpl {
    Retained retained;
    ::rust::Box<::ffi::MplDdbClient> handle;
    DdbClientImpl(Retained deps, ::rust::Box<::ffi::MplDdbClient> h)
        : retained(std::move(deps)), handle(std::move(h)) {}
};

struct KeyStoreImpl {
    Retained retained;
    ::rust::Box<::ffi::KeyStore> handle;
    KeyStoreImpl(Retained deps, ::rust::Box<::ffi::KeyStore> h)
        : retained(std::move(deps)), handle(std::move(h)) {}
};

struct CryptographicMaterialsCacheImpl {
    Retained retained;
    ::rust::Box<::ffi::CryptographicMaterialsCache> handle;
    CryptographicMaterialsCacheImpl(Retained deps,
                                    ::rust::Box<::ffi::CryptographicMaterialsCache> h)
        : retained(std::move(deps)), handle(std::move(h)) {}
};

struct KeyringImpl {
    Retained retained;
    ::rust::Box<::ffi::Keyring> handle;
    KeyringImpl(Retained deps, ::rust::Box<::ffi::Keyring> h)
        : retained(std::move(deps)), handle(std::move(h)) {}
};

struct EncryptStreamImpl {
    Retained retained;
    ::rust::Box<::ffi::EncryptStream> handle;
    EncryptStreamImpl(Retained deps, ::rust::Box<::ffi::EncryptStream> h)
        : retained(std::move(deps)), handle(std::move(h)) {}
};

struct DecryptStreamImpl {
    Retained retained;
    ::rust::Box<::ffi::DecryptStream> handle;
    DecryptStreamImpl(Retained deps, ::rust::Box<::ffi::DecryptStream> h)
        : retained(std::move(deps)), handle(std::move(h)) {}
};

}  // namespace detail

// ClientConfig

ClientConfig::ClientConfig() : impl_(std::make_shared<detail::ClientConfigImpl>()) {}
ClientConfig& ClientConfig::with_max_retry_attempts(std::uint32_t n) {
    impl_->cfg.retry.max_attempts = ::ffi::OptU32{true, n};
    return *this;
}
ClientConfig& ClientConfig::with_adaptive_retry(bool a) {
    impl_->cfg.retry.mode_adaptive = a;
    return *this;
}
ClientConfig& ClientConfig::with_region(const std::string& r) {
    impl_->cfg.region = ::ffi::OptString{true, ::rust::String(r)};
    return *this;
}

// Service clients

KmsClient::KmsClient(const ClientConfig& cfg)
    : impl_(std::make_shared<detail::KmsClientImpl>(
          detail::Retained{},
          detail::guard([&] { return ::ffi::create_kms_client(cfg.impl_->cfg); }))) {}

DdbClient::DdbClient(const ClientConfig& cfg)
    : impl_(std::make_shared<detail::DdbClientImpl>(
          detail::Retained{},
          detail::guard([&] { return ::ffi::create_ddb_client(cfg.impl_->cfg); }))) {}

// KeyStore

KeyStore::KeyStore(const std::string& table_name,
                   const std::string& logical_key_store_name,
                   const std::string& kms_arn,
                   const KeyStoreOptions& options)
    : impl_(std::make_shared<detail::KeyStoreImpl>(
          // Retain only the clients the caller supplied; an unset client is
          // built by the ESDK Rust and owned by the key store itself.
          [&] {
              detail::Retained deps;
              if (options.kms_client_) deps.push_back(options.kms_client_->impl_);
              if (options.ddb_client_) deps.push_back(options.ddb_client_->impl_);
              return deps;
          }(),
          detail::guard([&] {
              ::ffi::KeyStoreConfig c{};
              c.ddb_table_name = ::rust::String(table_name);
              c.logical_key_store_name = ::rust::String(logical_key_store_name);
              c.kms_configuration_type = ::ffi::KmsConfigurationType::KmsKeyArn;
              c.kms_configuration_value = ::rust::String(kms_arn);
              c.id = detail::to_opt(options.key_store_id_);
              for (const auto& token : options.grant_tokens_) {
                  c.grant_tokens.push_back(::rust::String(token));
              }
              // A null handle tells the shim to defer to the core ESDK's default client.
              if (options.kms_client_) c.kms_client = &*options.kms_client_->impl_->handle;
              if (options.ddb_client_) c.ddb_client = &*options.ddb_client_->impl_->handle;
              return ::ffi::create_keystore(c);
          }))) {}

// Cryptographic materials caches

namespace detail {
::ffi::OptDuration to_opt(const std::optional<std::chrono::nanoseconds>& o, const char* field) {
    return o ? ::ffi::OptDuration{true, to_ffi(*o, field)} : ::ffi::OptDuration{false, {}};
}
}  // namespace detail

StormTrackingCmc::StormTrackingCmc(const StormTrackingCmcOptions& options)
    : CryptographicMaterialsCache(std::make_shared<detail::CryptographicMaterialsCacheImpl>(
          detail::Retained{}, detail::guard([&] {
              ::ffi::StormTrackingCmcOptions o{};
              o.entry_capacity = detail::to_opt(options.entry_capacity_);
              o.entry_pruning_tail_size = detail::to_opt(options.entry_pruning_tail_size_);
              o.grace_period = detail::to_opt(options.grace_period_, "grace_period");
              o.grace_interval = detail::to_opt(options.grace_interval_, "grace_interval");
              o.fan_out = detail::to_opt(options.fan_out_);
              o.inflight_ttl = detail::to_opt(options.inflight_ttl_, "inflight_ttl");
              o.sleep = detail::to_opt(options.sleep_, "sleep");
              return ::ffi::create_storm_tracking_cmc(o);
          }))) {}

DefaultCmc::DefaultCmc(std::uint32_t entry_capacity)
    : CryptographicMaterialsCache(std::make_shared<detail::CryptographicMaterialsCacheImpl>(
          detail::Retained{},
          detail::guard([&] { return ::ffi::create_default_cmc(entry_capacity); }))) {}

LocalCmc::LocalCmc(std::uint32_t entry_capacity)
    : CryptographicMaterialsCache(std::make_shared<detail::CryptographicMaterialsCacheImpl>(
          detail::Retained{},
          detail::guard([&] { return ::ffi::create_local_cmc(entry_capacity); }))) {}

// Keyrings

// Adopt a custom Rust keyring into the Aws::Esdk::Keyring type
Keyring Keyring::adopt(void* raw_handle) {
    return Keyring(std::make_shared<detail::KeyringImpl>(
        // Custom implementations of Keyrings currently can't retain C++ resources,
        // but support for this can be added in the future as a non-breaking change.
        detail::Retained{},
        ::rust::Box<::ffi::Keyring>::from_raw(static_cast<::ffi::Keyring*>(raw_handle))));
}

HierarchicalKeyring::HierarchicalKeyring(KeyStore key_store,
                                         const std::string& branch_key_id,
                                         std::chrono::nanoseconds ttl,
                                         const HierarchicalKeyringOptions& options,
                                         Tag)
    : Keyring(std::make_shared<detail::KeyringImpl>(
          options.cache_ ? detail::Retained{key_store.impl_, options.cache_->impl_}
                         : detail::Retained{key_store.impl_},
          detail::guard([&] {
              ::ffi::HierarchicalKeyringInput in{};
              in.branch_key_id = ::rust::String(branch_key_id);
              in.key_store = &*key_store.impl_->handle;
              in.ttl = detail::to_ffi(ttl, "ttl");
              in.partition_id = detail::to_opt(options.partition_id_);
              // A null handle tells the shim to defer to the core ESDK's default cache.
              if (options.cache_) in.cache = &*options.cache_->impl_->handle;
              return ::ffi::create_hierarchical_keyring(in);
          }))) {}

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
    //= spec/shim/esdk-shim.md#client-configuration
    //# - A configuration value the target supplies on both the client and a
    //# per-operation input MUST be rejected as invalid input.
    if (commitment_policy_ && options.commitment_policy_)
        throw ValidationException(
            "commitment_policy is provided by both the EncryptionSDK client and the "
            "per-call options. Set it in exactly one place.");
    //= spec/shim/esdk-shim.md#client-configuration
    //# - A configuration value the target supplies on neither the client nor the
    //# operation MUST defer to the core ESDK's default.
    in.commitment_policy = detail::to_opt(options.commitment_policy_ ? options.commitment_policy_
                                                                     : commitment_policy_);
    in.frame_length = detail::to_opt(options.frame_length_);
    if (max_encrypted_data_keys_ && options.max_encrypted_data_keys_)
        throw ValidationException(
            "max_encrypted_data_keys is provided by both the EncryptionSDK client and "
            "the per-call options. Set it in exactly one place.");
    in.max_encrypted_data_keys = detail::to_opt(
        options.max_encrypted_data_keys_ ? options.max_encrypted_data_keys_
                                         : max_encrypted_data_keys_);
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
    //= spec/shim/esdk-shim.md#client-configuration
    //# - A configuration value the target supplies on both the client and a
    //# per-operation input MUST be rejected as invalid input.
    if (commitment_policy_ && options.commitment_policy_)
        throw ValidationException(
            "commitment_policy is provided by both the EncryptionSDK client and the "
            "per-call options. Set it in exactly one place.");
    //= spec/shim/esdk-shim.md#client-configuration
    //# - A configuration value the target supplies on neither the client nor the
    //# operation MUST defer to the core ESDK's default.
    in.commitment_policy = detail::to_opt(options.commitment_policy_ ? options.commitment_policy_
                                                                     : commitment_policy_);
    if (max_encrypted_data_keys_ && options.max_encrypted_data_keys_)
        throw ValidationException(
            "max_encrypted_data_keys is provided by both the EncryptionSDK client and "
            "the per-call options. Set it in exactly one place.");
    in.max_encrypted_data_keys = detail::to_opt(
        options.max_encrypted_data_keys_ ? options.max_encrypted_data_keys_
                                         : max_encrypted_data_keys_);
    ::ffi::DecryptOutput out = detail::guard([&] { return ::ffi::decrypt(in); });
    DecryptResult result;
    result.plaintext = detail::make_bytes(std::move(out.plaintext));
    result.encryption_context = detail::from_ec(out.encryption_context);
    result.algorithm_suite_id = detail::alg_from_ffi(out.algorithm_suite_id);
    return result;
}

// Streaming

EncryptStream EncryptionSDK::create_encrypt_stream(const Keyring& keyring,
                                                   const EncryptOptions& options) {
    ::ffi::EncryptInput in{};
    in.keyring = &*keyring.impl_->handle;
    in.encryption_context = detail::to_ec(options.encryption_context_);
    in.algorithm_suite_id = detail::to_opt(options.algorithm_suite_);
    //= spec/shim/esdk-shim.md#client-configuration
    //# - A configuration value the target supplies on both the client and a
    //# per-operation input MUST be rejected as invalid input.
    if (commitment_policy_ && options.commitment_policy_)
        throw ValidationException(
            "commitment_policy is provided by both the EncryptionSDK client and the "
            "per-call options. Set it in exactly one place.");
    //= spec/shim/esdk-shim.md#client-configuration
    //# - A configuration value the target supplies on neither the client nor the
    //# operation MUST defer to the core ESDK's default.
    in.commitment_policy = detail::to_opt(options.commitment_policy_ ? options.commitment_policy_
                                                                     : commitment_policy_);
    in.frame_length = detail::to_opt(options.frame_length_);
    if (max_encrypted_data_keys_ && options.max_encrypted_data_keys_)
        throw ValidationException(
            "max_encrypted_data_keys is provided by both the EncryptionSDK client and "
            "the per-call options. Set it in exactly one place.");
    in.max_encrypted_data_keys = detail::to_opt(
        options.max_encrypted_data_keys_ ? options.max_encrypted_data_keys_
                                         : max_encrypted_data_keys_);
    // Keyring MUST be retained.
    // The stream outlives this call and must not outlive the keyring it was created from.
    return EncryptStream(std::make_shared<detail::EncryptStreamImpl>(
        detail::Retained{keyring.impl_},
        detail::guard([&] { return ::ffi::create_encrypt_stream(in); })));
}

DecryptStream EncryptionSDK::create_decrypt_stream(const Keyring& keyring,
                                                   const DecryptOptions& options) {
    ::ffi::DecryptInput in{};
    in.keyring = &*keyring.impl_->handle;
    in.encryption_context = detail::to_ec(options.encryption_context_);
    //= spec/shim/esdk-shim.md#client-configuration
    //# - A configuration value the target supplies on both the client and a
    //# per-operation input MUST be rejected as invalid input.
    if (commitment_policy_ && options.commitment_policy_)
        throw ValidationException(
            "commitment_policy is provided by both the EncryptionSDK client and the "
            "per-call options. Set it in exactly one place.");
    //= spec/shim/esdk-shim.md#client-configuration
    //# - A configuration value the target supplies on neither the client nor the
    //# operation MUST defer to the core ESDK's default.
    in.commitment_policy = detail::to_opt(options.commitment_policy_ ? options.commitment_policy_
                                                                     : commitment_policy_);
    if (max_encrypted_data_keys_ && options.max_encrypted_data_keys_)
        throw ValidationException(
            "max_encrypted_data_keys is provided by both the EncryptionSDK client and "
            "the per-call options. Set it in exactly one place.");
    in.max_encrypted_data_keys = detail::to_opt(
        options.max_encrypted_data_keys_ ? options.max_encrypted_data_keys_
                                         : max_encrypted_data_keys_);
    // Keyring MUST be retained.
    // The stream outlives this call and must not outlive the keyring it was created from.
    return DecryptStream(std::make_shared<detail::DecryptStreamImpl>(
        detail::Retained{keyring.impl_},
        detail::guard([&] { return ::ffi::create_decrypt_stream(in); })));
}

Bytes EncryptStream::write(const std::uint8_t* data, std::size_t size) {
    static const std::uint8_t empty = 0;
    // An empty write is a poll.
    // Keep the slice pointer valid even when the caller passes null with size 0.
    if (size == 0) data = &empty;
    return detail::make_bytes(detail::guard([&] {
        return ::ffi::encrypt_stream_write(*impl_->handle,
                                           ::rust::Slice<const std::uint8_t>(data, size));
    }));
}

StreamResult EncryptStream::finish() {
    ::ffi::StreamFinishOutput out =
        detail::guard([&] { return ::ffi::encrypt_stream_finish(*impl_->handle); });
    StreamResult result;
    result.trailing_output = detail::make_bytes(std::move(out.trailing_output));
    result.encryption_context = detail::from_ec(out.encryption_context);
    result.algorithm_suite_id = detail::alg_from_ffi(out.algorithm_suite_id);
    return result;
}

Bytes DecryptStream::write(const std::uint8_t* data, std::size_t size) {
    static const std::uint8_t empty = 0;
    // An empty write is a poll.
    // Keep the slice pointer valid even when the caller passes null with size 0.
    if (size == 0) data = &empty;
    return detail::make_bytes(detail::guard([&] {
        return ::ffi::decrypt_stream_write(*impl_->handle,
                                           ::rust::Slice<const std::uint8_t>(data, size));
    }));
}

StreamResult DecryptStream::finish() {
    ::ffi::StreamFinishOutput out =
        detail::guard([&] { return ::ffi::decrypt_stream_finish(*impl_->handle); });
    StreamResult result;
    result.trailing_output = detail::make_bytes(std::move(out.trailing_output));
    result.encryption_context = detail::from_ec(out.encryption_context);
    result.algorithm_suite_id = detail::alg_from_ffi(out.algorithm_suite_id);
    return result;
}

namespace detail {

// Reads `source` in chunks, feeds each to `stream.write`, and forwards the
// produced bytes to `sink`; then finalizes and appends the trailing output.
// Throws if `source` fails before end-of-stream or `sink` rejects a write.
template <typename Stream>
StreamResult pump_stream(Stream& stream, std::istream& source, std::ostream& sink) {
    char buf[4096];
    while (source.read(buf, sizeof(buf)) || source.gcount() > 0) {
        Bytes produced = stream.write(reinterpret_cast<const std::uint8_t*>(buf),
                                      static_cast<std::size_t>(source.gcount()));
        sink.write(reinterpret_cast<const char*>(produced.data()),
                   static_cast<std::streamsize>(produced.size()));
    }
    // If `source` failed to read, throw so an incomplete output is not surfaced
    if (source.bad() || !source.eof())
        throw AwsEncryptionSdkException("reading from the source stream failed before the end of input");
    StreamResult result = stream.finish();
    sink.write(reinterpret_cast<const char*>(result.trailing_output.data()),
               static_cast<std::streamsize>(result.trailing_output.size()));
    // If `sink` failed to write, throw so an incomplete output is not surfaced
    if (!sink)
        throw AwsEncryptionSdkException("writing to the sink stream failed; its output is incomplete");
    return result;
}

}  // namespace detail

StreamResult EncryptionSDK::encrypt_stream(std::istream& source, std::ostream& sink,
                                           const Keyring& keyring,
                                           const EncryptOptions& options) {
    EncryptStream stream = create_encrypt_stream(keyring, options);
    return detail::pump_stream(stream, source, sink);
}

StreamResult EncryptionSDK::decrypt_stream(std::istream& source, std::ostream& sink,
                                           const Keyring& keyring,
                                           const DecryptOptions& options) {
    DecryptStream stream = create_decrypt_stream(keyring, options);
    return detail::pump_stream(stream, source, sink);
}

}  // inline namespace abi_v1
}  // namespace Aws::Esdk
