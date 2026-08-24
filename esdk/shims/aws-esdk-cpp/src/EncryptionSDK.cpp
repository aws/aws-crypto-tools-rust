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

CacheType CacheType::Default(std::uint32_t entry_capacity) {
    CacheType c(Kind::Default);
    c.entry_capacity_ = entry_capacity;
    return c;
}

CacheType CacheType::No() { return CacheType(Kind::No); }

CacheType CacheType::StormTracking(
    std::uint32_t entry_capacity,
    std::uint32_t entry_pruning_tail_size,
    std::uint32_t grace_period,
    std::uint32_t grace_interval,
    std::uint32_t fan_out,
    std::uint32_t inflight_ttl,
    std::uint32_t sleep_milli,
    std::optional<TimeUnits> time_units) {
    CacheType c(Kind::StormTracking);
    c.entry_capacity_ = entry_capacity;
    c.entry_pruning_tail_size_ = entry_pruning_tail_size;
    c.grace_period_ = grace_period;
    c.grace_interval_ = grace_interval;
    c.fan_out_ = fan_out;
    c.inflight_ttl_ = inflight_ttl;
    c.sleep_milli_ = sleep_milli;
    c.time_units_ = time_units;
    return c;
}

CacheType CacheType::Shared(const CryptographicMaterialsCache& cache) {
    CacheType c(Kind::Shared);
    c.shared_ = cache.impl_;
    return c;
}

namespace detail {
// Lowers the public CacheType to the bridge struct. The result borrows a
// Shared descriptor's handle; the caller retains that cache's impl.
struct CacheTypeLowerer {
    static ::ffi::CacheType lower(const CacheType& c) {
        ::ffi::CacheType out{};
        switch (c.kind_) {
            case CacheType::Kind::Default:
                out.kind = ::ffi::CacheKind::Default;
                out.entry_capacity = c.entry_capacity_;
                break;
            case CacheType::Kind::No:
                out.kind = ::ffi::CacheKind::No;
                break;
            case CacheType::Kind::StormTracking:
                out.kind = ::ffi::CacheKind::StormTracking;
                out.entry_capacity = c.entry_capacity_;
                out.entry_pruning_tail_size = c.entry_pruning_tail_size_;
                out.grace_period = c.grace_period_;
                out.grace_interval = c.grace_interval_;
                out.fan_out = c.fan_out_;
                out.inflight_ttl = c.inflight_ttl_;
                out.sleep_milli = c.sleep_milli_;
                out.time_units = c.time_units_
                    ? (*c.time_units_ == TimeUnits::Milliseconds ? ::ffi::TimeUnits::Milliseconds
                                                                 : ::ffi::TimeUnits::Seconds)
                    : ::ffi::TimeUnits::Unset;
                break;
            case CacheType::Kind::Shared:
                out.kind = ::ffi::CacheKind::Shared;
                out.shared = c.shared_ ? &*c.shared_->handle : nullptr;
                break;
        }
        return out;
    }
};
}  // namespace detail

CryptographicMaterialsCache::CryptographicMaterialsCache(const CacheType& cache)
    : impl_(std::make_shared<detail::CryptographicMaterialsCacheImpl>(
          cache.shared_ ? detail::Retained{cache.shared_} : detail::Retained{},
          detail::guard([&] {
              ::ffi::CacheType ffi_cache = detail::CacheTypeLowerer::lower(cache);
              return ::ffi::create_cryptographic_materials_cache(ffi_cache);
          }))) {}

// Keyrings

HierarchicalKeyring::HierarchicalKeyring(KeyStore key_store,
                                         const std::string& branch_key_id,
                                         std::uint32_t ttl_seconds,
                                         const HierarchicalKeyringOptions& options)
    : Keyring(std::make_shared<detail::KeyringImpl>(
          (options.cache_ && options.cache_->shared_)
              ? detail::Retained{key_store.impl_, options.cache_->shared_}
              : detail::Retained{key_store.impl_},
          detail::guard([&] {
              ::ffi::HierarchicalKeyringInput in{};
              in.branch_key_id = ::rust::String(branch_key_id);
              in.key_store = &*key_store.impl_->handle;
              in.ttl_seconds = ttl_seconds;
              in.partition_id = detail::to_opt(options.partition_id_);
              in.cache = options.cache_
                             ? ::ffi::OptCacheType{true,
                                                   detail::CacheTypeLowerer::lower(*options.cache_)}
                             : ::ffi::OptCacheType{false, ::ffi::CacheType{}};
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
template <typename Stream>
StreamResult pump_stream(Stream& stream, std::istream& source, std::ostream& sink) {
    char buf[4096];
    while (source.read(buf, sizeof(buf)) || source.gcount() > 0) {
        Bytes produced = stream.write(reinterpret_cast<const std::uint8_t*>(buf),
                                      static_cast<std::size_t>(source.gcount()));
        sink.write(reinterpret_cast<const char*>(produced.data()),
                   static_cast<std::streamsize>(produced.size()));
    }
    StreamResult result = stream.finish();
    sink.write(reinterpret_cast<const char*>(result.trailing_output.data()),
               static_cast<std::streamsize>(result.trailing_output.size()));
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

}  // namespace Esdk
}  // namespace Aws
