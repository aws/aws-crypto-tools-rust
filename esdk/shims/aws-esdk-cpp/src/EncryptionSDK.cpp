// EncryptionSDK.cpp - translates public types in EncryptionSDK.h to private cxx-generated types

#include "aws/esdk/EncryptionSDK.h"

#include <utility>

#include "rust/cxx.h"                 // rust::Error, rust::Box, rust::Vec, rust::Slice
#include "aws-esdk-cpp/src/lib.rs.h"  // cxx-generated bindings (namespace aws_esdk_ffi)

namespace ffi = ::aws_esdk_ffi;

namespace Aws {
namespace Esdk {
namespace detail {

// Decodes the `{ShimErrorKind repr}{U+001F}` prefix `shim_err` (lib.rs) puts on
// every bridge error and throws the exception type named after the core's
// error kind. Kinds without a dedicated type (Esdk, MplError, LegacyError) and
// unprefixed messages throw the base type.
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
        default: throw AwsEncryptionSdkException(message);
    }
}

// Error-catching wrapper for a function call into the core Rust ESDK.
// If attached to a function call, catches any Rust error from that call
// and re-throws it as the matching Aws::Esdk exception type.
// This should be attached to every call to the Rust ESDK.
template <typename F>
auto guard(F&& f) -> decltype(f()) {
    try {
        return f();
    } catch (const ::rust::Error& e) {
        throw_shim_exception(e.what());
    }
}

// Conversions from the owned-interface types to the FFI types
::ffi::EsdkAlgorithmSuiteId to_ffi(AlgorithmSuiteId a) {
    return static_cast<::ffi::EsdkAlgorithmSuiteId>(static_cast<std::uint16_t>(a));
}
::ffi::EsdkCommitmentPolicy to_ffi(CommitmentPolicy p) {
    return static_cast<::ffi::EsdkCommitmentPolicy>(static_cast<std::uint8_t>(p));
}
::ffi::AesWrappingAlg to_ffi(AesWrappingAlgorithm a) {
    return static_cast<::ffi::AesWrappingAlg>(static_cast<std::uint8_t>(a));
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

// Conversions from the FFI types to the owned-interface types
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

// Wraps an ESDK Rust output buffer as a Bytes.
// Used to pass output to user without an expensive copy.
struct BytesFactory {
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

struct ClientConfigImpl {
    ::ffi::MplAwsClientConfig cfg{};
};

// Resources

struct KmsClientImpl {
    ::rust::Box<::ffi::MplKmsClient> handle;
    explicit KmsClientImpl(::rust::Box<::ffi::MplKmsClient> h) : handle(std::move(h)) {}
};

struct DdbClientImpl {
    ::rust::Box<::ffi::MplDdbClient> handle;
    explicit DdbClientImpl(::rust::Box<::ffi::MplDdbClient> h) : handle(std::move(h)) {}
};

struct KeyStoreImpl {
    // kms and ddb must outlive the key store handle, so they must be declared first.
    // (In C++, declared first -> destroyed last.)
    std::shared_ptr<KmsClientImpl> kms;
    std::shared_ptr<DdbClientImpl> ddb;
    ::rust::Box<::ffi::KeyStore> handle;
    KeyStoreImpl(std::shared_ptr<KmsClientImpl> kms_in,
                 std::shared_ptr<DdbClientImpl> ddb_in,
                 ::rust::Box<::ffi::KeyStore> h)
        : kms(std::move(kms_in)), ddb(std::move(ddb_in)), handle(std::move(h)) {}
};

struct CacheImpl {
    ::rust::Box<::ffi::Cache> handle;
    explicit CacheImpl(::rust::Box<::ffi::Cache> h) : handle(std::move(h)) {}
};

struct KeyringImpl {
    // key_store and cache must outlive the key store handle, so they must be declared first.
    std::shared_ptr<KeyStoreImpl> key_store;
    std::shared_ptr<CacheImpl> cache;
    ::rust::Box<::ffi::Keyring> handle;
    KeyringImpl(std::shared_ptr<KeyStoreImpl> ks,
                std::shared_ptr<CacheImpl> c,
                ::rust::Box<::ffi::Keyring> h)
        : key_store(std::move(ks)), cache(std::move(c)), handle(std::move(h)) {}
};

struct EncryptStreamImpl {
    ::rust::Box<::ffi::EncryptStream> handle;
    explicit EncryptStreamImpl(::rust::Box<::ffi::EncryptStream> h) : handle(std::move(h)) {}
};

struct DecryptStreamImpl {
    ::rust::Box<::ffi::DecryptStream> handle;
    explicit DecryptStreamImpl(::rust::Box<::ffi::DecryptStream> h) : handle(std::move(h)) {}
};

}  // namespace detail

// ClientConfig

ClientConfig::ClientConfig() : impl_(std::make_shared<detail::ClientConfigImpl>()) {}
ClientConfig& ClientConfig::with_max_retry_attempts(std::uint32_t n) {
    impl_->cfg.retry.max_attempts = n;
    return *this;
}
ClientConfig& ClientConfig::with_adaptive_retry(bool a) {
    impl_->cfg.retry.mode_adaptive = a;
    return *this;
}
ClientConfig& ClientConfig::with_region(const std::string& r) {
    impl_->cfg.region = ::rust::String(r);
    return *this;
}

// Service clients

KmsClient::KmsClient(const ClientConfig& cfg)
    : impl_(std::make_shared<detail::KmsClientImpl>(
          detail::guard([&] { return ::ffi::create_kms_client(cfg.impl_->cfg); }))) {}

DdbClient::DdbClient(const ClientConfig& cfg)
    : impl_(std::make_shared<detail::DdbClientImpl>(
          detail::guard([&] { return ::ffi::create_ddb_client(cfg.impl_->cfg); }))) {}

// KeyStore

KeyStore::KeyStore(const std::string& table_name,
                   const std::string& logical_key_store_name,
                   const std::string& kms_arn,
                   KmsClient kms,
                   DdbClient ddb,
                   const KeyStoreOptions& options)
    : impl_(std::make_shared<detail::KeyStoreImpl>(
          kms.impl_, ddb.impl_, detail::guard([&] {
              ::ffi::KeyStoreConfig c{};
              c.ddb_table_name = ::rust::String(table_name);
              c.logical_key_store_name = ::rust::String(logical_key_store_name);
              c.kms_configuration_type = ::ffi::KmsConfigurationType::KmsKeyArn;
              c.kms_configuration_value = ::rust::String(kms_arn);
              c.id = ::rust::String(options.key_store_id_);
              for (const auto& token : options.grant_tokens_) {
                  c.grant_tokens.push_back(::rust::String(token));
              }
              c.kms_client = &*kms.impl_->handle;
              c.ddb_client = &*ddb.impl_->handle;
              return ::ffi::create_keystore(c);
          }))) {}

// Caches

Cache Cache::NoCache() {
    return Cache(std::make_shared<detail::CacheImpl>(
        detail::guard([] { return ::ffi::create_no_cache(); })));
}

Cache Cache::MultiThreaded(std::uint32_t entry_capacity, std::uint32_t entry_pruning_tail_size) {
    return Cache(std::make_shared<detail::CacheImpl>(detail::guard([&] {
        return ::ffi::create_multi_threaded_cache(entry_capacity, entry_pruning_tail_size);
    })));
}

// Keyrings

Keyring Keyring::adopt(void* raw_handle) {
    return Keyring(std::make_shared<detail::KeyringImpl>(
        nullptr, nullptr,
        ::rust::Box<::ffi::Keyring>::from_raw(static_cast<::ffi::Keyring*>(raw_handle))));
}

HierarchicalKeyring::HierarchicalKeyring(KeyStore key_store,
                                         const std::string& branch_key_id,
                                         std::uint32_t ttl_seconds,
                                         const HierarchicalKeyringOptions& options)
    : Keyring(std::make_shared<detail::KeyringImpl>(
          key_store.impl_, options.cache_, detail::guard([&] {
              ::ffi::HierarchicalKeyringInput in{};
              in.branch_key_id = ::rust::String(branch_key_id);
              in.key_store = &*key_store.impl_->handle;
              in.ttl_seconds = ttl_seconds;
              in.partition_id = ::rust::String(options.partition_id_);
              if (options.cache_) in.cache = &*options.cache_->handle;
              return ::ffi::create_hierarchical_keyring(in);
          }))) {}

RawAesKeyring::RawAesKeyring(const std::string& key_namespace,
                             const std::string& key_name,
                             const std::vector<std::uint8_t>& wrapping_key,
                             AesWrappingAlgorithm wrapping_alg)
    : Keyring(std::make_shared<detail::KeyringImpl>(
          nullptr, nullptr, detail::guard([&] {
              ::ffi::RawAesKeyringInput in{};
              in.key_namespace = ::rust::String(key_namespace);
              in.key_name = ::rust::String(key_name);
              in.wrapping_key =
                  ::rust::Slice<const std::uint8_t>(wrapping_key.data(), wrapping_key.size());
              in.wrapping_alg = detail::to_ffi(wrapping_alg);
              return ::ffi::create_raw_aes_keyring(in);
          }))) {}

// Operations

// Encrypt with C++-idiomatic std::vector.
EncryptResult EncryptionSDK::encrypt(const std::vector<std::uint8_t>& plaintext,
                                     const Keyring& keyring,
                                     const EncryptOptions& options) {
    return encrypt(plaintext.data(), plaintext.size(), keyring, options);
}

// Encrypt from any contiguous caller-owned buffer, without copying it into a
// std::vector first. The slice borrows the buffer only for this call.
EncryptResult EncryptionSDK::encrypt(const std::uint8_t* plaintext,
                                     std::size_t plaintext_len,
                                     const Keyring& keyring,
                                     const EncryptOptions& options) {
    ::ffi::EncryptInput in{};
    in.keyring = &*keyring.impl_->handle;
    in.plaintext = ::rust::Slice<const std::uint8_t>(plaintext, plaintext_len);
    in.encryption_context = detail::to_ec(options.encryption_context_);
    if (options.algorithm_suite_) in.algorithm_suite_id = detail::to_ffi(*options.algorithm_suite_);
    // Matching the core's client: configuration provided in two places is
    // rejected; unset in both stays zero-initialized (the core's default).
    if (commitment_policy_ && options.commitment_policy_)
        throw ValidationException(
            "commitment_policy is provided by both the EncryptionSDK client and the "
            "per-call options. Set it in exactly one place.");
    if (const auto p = options.commitment_policy_ ? options.commitment_policy_ : commitment_policy_)
        in.commitment_policy = detail::to_ffi(*p);
    if (options.frame_length_) in.frame_length = *options.frame_length_;
    if (max_encrypted_data_keys_ && options.max_encrypted_data_keys_)
        throw ValidationException(
            "max_encrypted_data_keys is provided by both the EncryptionSDK client and "
            "the per-call options. Set it in exactly one place.");
    if (const auto m = options.max_encrypted_data_keys_ ? options.max_encrypted_data_keys_
                                                        : max_encrypted_data_keys_)
        in.max_encrypted_data_keys = *m;
    ::ffi::EncryptOutput out = detail::guard([&] { return ::ffi::encrypt(in); });
    EncryptResult result;
    result.ciphertext = detail::make_bytes(std::move(out.ciphertext));
    result.encryption_context = detail::from_ec(out.encryption_context);
    result.algorithm_suite_id = detail::alg_from_ffi(out.algorithm_suite_id);
    return result;
}

// Decrypt with C++-idiomatic std::vector.
DecryptResult EncryptionSDK::decrypt(const std::vector<std::uint8_t>& ciphertext,
                                     const Keyring& keyring,
                                     const DecryptOptions& options) {
    return decrypt(ciphertext.data(), ciphertext.size(), keyring, options);
}

// Decrypt with custom Aws::Esdk::Bytes type.
// Aws::Esdk::Bytes wraps a Rust type directly, avoiding a possibly expensive copy
// from a C++ std::vector to a Rust buffer.
DecryptResult EncryptionSDK::decrypt(const Bytes& ciphertext,
                                     const Keyring& keyring,
                                     const DecryptOptions& options) {
    return decrypt(ciphertext.data(), ciphertext.size(), keyring, options);
}

// Decrypt from any contiguous caller-owned buffer, without copying it into a
// std::vector first. The slice borrows the buffer only for this call.
DecryptResult EncryptionSDK::decrypt(const std::uint8_t* ciphertext,
                                     std::size_t ciphertext_len,
                                     const Keyring& keyring,
                                     const DecryptOptions& options) {
    ::ffi::DecryptInput in{};
    in.keyring = &*keyring.impl_->handle;
    in.ciphertext = ::rust::Slice<const std::uint8_t>(ciphertext, ciphertext_len);
    in.encryption_context = detail::to_ec(options.encryption_context_);
    // Matching the core's client: configuration provided in two places is
    // rejected; unset in both stays zero-initialized (the core's default).
    if (commitment_policy_ && options.commitment_policy_)
        throw ValidationException(
            "commitment_policy is provided by both the EncryptionSDK client and the "
            "per-call options. Set it in exactly one place.");
    if (const auto p = options.commitment_policy_ ? options.commitment_policy_ : commitment_policy_)
        in.commitment_policy = detail::to_ffi(*p);
    if (max_encrypted_data_keys_ && options.max_encrypted_data_keys_)
        throw ValidationException(
            "max_encrypted_data_keys is provided by both the EncryptionSDK client and "
            "the per-call options. Set it in exactly one place.");
    if (const auto m = options.max_encrypted_data_keys_ ? options.max_encrypted_data_keys_
                                                        : max_encrypted_data_keys_)
        in.max_encrypted_data_keys = *m;
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
    if (options.algorithm_suite_) in.algorithm_suite_id = detail::to_ffi(*options.algorithm_suite_);
    // Matching the core's client: configuration provided in two places is
    // rejected; unset in both stays zero-initialized (the core's default).
    if (commitment_policy_ && options.commitment_policy_)
        throw ValidationException(
            "commitment_policy is provided by both the EncryptionSDK client and the "
            "per-call options. Set it in exactly one place.");
    if (const auto p = options.commitment_policy_ ? options.commitment_policy_ : commitment_policy_)
        in.commitment_policy = detail::to_ffi(*p);
    if (options.frame_length_) in.frame_length = *options.frame_length_;
    if (max_encrypted_data_keys_ && options.max_encrypted_data_keys_)
        throw ValidationException(
            "max_encrypted_data_keys is provided by both the EncryptionSDK client and "
            "the per-call options. Set it in exactly one place.");
    if (const auto m = options.max_encrypted_data_keys_ ? options.max_encrypted_data_keys_
                                                        : max_encrypted_data_keys_)
        in.max_encrypted_data_keys = *m;
    return EncryptStream(std::make_shared<detail::EncryptStreamImpl>(
        detail::guard([&] { return ::ffi::create_encrypt_stream(in); })));
}

DecryptStream EncryptionSDK::create_decrypt_stream(const Keyring& keyring,
                                                   const DecryptOptions& options) {
    ::ffi::DecryptInput in{};
    in.keyring = &*keyring.impl_->handle;
    in.encryption_context = detail::to_ec(options.encryption_context_);
    // Matching the core's client: configuration provided in two places is
    // rejected; unset in both stays zero-initialized (the core's default).
    if (commitment_policy_ && options.commitment_policy_)
        throw ValidationException(
            "commitment_policy is provided by both the EncryptionSDK client and the "
            "per-call options. Set it in exactly one place.");
    if (const auto p = options.commitment_policy_ ? options.commitment_policy_ : commitment_policy_)
        in.commitment_policy = detail::to_ffi(*p);
    if (max_encrypted_data_keys_ && options.max_encrypted_data_keys_)
        throw ValidationException(
            "max_encrypted_data_keys is provided by both the EncryptionSDK client and "
            "the per-call options. Set it in exactly one place.");
    if (const auto m = options.max_encrypted_data_keys_ ? options.max_encrypted_data_keys_
                                                        : max_encrypted_data_keys_)
        in.max_encrypted_data_keys = *m;
    return DecryptStream(std::make_shared<detail::DecryptStreamImpl>(
        detail::guard([&] { return ::ffi::create_decrypt_stream(in); })));
}

Bytes EncryptStream::write(const std::uint8_t* data, std::size_t size) {
    // An empty write is a poll; keep the slice pointer valid even when the
    // caller passes null with size 0.
    static const std::uint8_t empty = 0;
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
    // An empty write is a poll; keep the slice pointer valid even when the
    // caller passes null with size 0.
    static const std::uint8_t empty = 0;
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

}  // namespace Esdk
}  // namespace Aws
