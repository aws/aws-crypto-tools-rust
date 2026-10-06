// EncryptionSDK.h — public types for the C++ Shim for the AWS Encryption SDK for Rust

#pragma once

#include <algorithm>
#include <chrono>
#include <cstdint>
#include <istream>
#include <map>
#include <memory>
#include <optional>
#include <ostream>
#include <stdexcept>
#include <string>
#include <utility>
#include <string_view>
#include <type_traits>
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
/// What went wrong, as a caller would act on it.
/// The same kinds, under the same names, as ESDK Rust's `Error` variants.
/// Each kind's exception class says when it occurs and what to do.
///
/// Check retryable() first:
/// a retryable error might succeed if the same call is made again later.
/// Then decide from the exception type.
/// what() is the Rust error's message and details; full_message() adds its causes, for logs.
///
/// Later releases can add kinds, so code that switches on the kind needs a default case.
///
/// Messages are for people, not code.
/// Their text can change in any release, including a minor or patch release.
/// Decide from the exception type and its fields, never from what().
///
/// What a minor or patch release can change:
/// - what(), full_message(), and every other message;
/// - an exception that is not an AwsEncryptionSdkException, or an InternalException,
///   which is a bug and can become a specific exception type;
/// - which exception type a collection of several failures becomes;
/// - new kinds and enum values, so every switch needs a default case.
enum class ErrorKind : std::uint8_t {
    Validation = 0,
    Serialization = 1,
    Cryptographic = 2,
    InvalidMaterials = 3,
    EncryptionContextMismatch = 4,
    NoMatchingDataKey = 5,
    AccessDenied = 6,
    ResourceNotFound = 7,
    Service = 8,
    Dispatch = 9,
    Internal = 10,
    Io = 11,
    Throttling = 12,
    Conflict = 13,
};

/// Why an error might succeed if the same call is made again later.
/// The same values as the AWS SDK's retry classification.
///
/// Later releases can add values, so code that switches on the value needs a default case.
enum class RetryKind : std::uint8_t {
    /// A connection-level failure, such as a timeout.
    Transient = 0,
    /// The service throttled the request.
    Throttling = 1,
    /// The service failed on its side.
    Server = 2,
    /// The request failed but a retry can succeed.
    Client = 3,
};

/// The AWS service an error is about.
///
/// Later releases can add values, so code that switches on the value needs a default case.
enum class Service : std::uint8_t {
    Kms = 0,
    DynamoDb = 1,
};

/// What kind of resource an error is about.
/// Not limited to AWS resources: a keyring, a CMM, or the materials cache can be one.
///
/// Later releases can add values, so code that switches on the value needs a default case.
enum class ResourceType : std::uint8_t {
    /// A KMS key; the name is its ARN.
    KmsKey = 0,
    /// A DynamoDB table; the name is the table name.
    DynamoDbTable = 1,
    /// A hierarchical keyring branch key; the name is its ID.
    BranchKey = 2,
    /// A cryptographic materials cache; the name is empty.
    Cache = 3,
    /// A keyring; the name is the keyring's name.
    Keyring = 4,
    /// A CMM; the name is the CMM's name.
    Cmm = 5,
    /// A resource this library does not know yet; the name describes it.
    Unknown = 255,
};

/// The resource you need to act on. Other resources involved are named in the message.
class Resource {
public:
    Resource(ResourceType type, std::string name) : type_(type), name_(std::move(name)) {}
    /// What kind of resource this is.
    ResourceType type() const noexcept { return type_; }
    /// The resource's name; what it holds depends on type().
    const std::string& name() const noexcept { return name_; }

private:
    ResourceType type_;
    std::string name_;
};

/// Why a request conflicts with the current state of a resource.
///
/// Later releases can add values, so code that switches on the value needs a default case.
enum class ConflictReason : std::uint8_t {
    /// The resource already exists, for example create_key with a branch key ID that is in use.
    AlreadyExists = 0,
    /// Another caller changed the resource between this call's read and its write,
    /// for example two version_key calls on the same branch key.
    ConcurrentModification = 1,
};

/// The details an exception carries beyond its kind and message.
/// For constructing exceptions in tests; read an exception's details through its accessors.
struct ErrorDetails {
    bool retryable = false;
    /// Empty when the error is not retryable, or its retry kind is one this library does not know yet.
    std::optional<RetryKind> retry_kind;
    std::optional<Service> service;
    std::optional<Resource> resource;
    std::optional<std::string> code;
    std::optional<std::string> request_id;
    std::optional<ConflictReason> conflict_reason;
    bool credentials = false;
    /// The Rust variant name, such as "Throttling".
    std::string name;
    /// The Rust error with its causes, as `{:#}` prints it.
    std::string full_message;
    /// Where the Rust error was created; empty unless backtrace capture is enabled.
    std::string backtrace;
};

namespace detail {
// Rethrows an encoded ESDK Rust error as the matching exception.
[[noreturn]] void throw_shim_exception(const std::string& what);
}  // namespace detail

/// Base exception for every failure this library reports.
/// Catching this type catches everything the shim can throw.
class AwsEncryptionSdkException : public std::runtime_error {
public:
    explicit AwsEncryptionSdkException(const std::string& msg) : std::runtime_error(msg), message_(msg) {}
    /// What went wrong.
    /// Empty when ESDK Rust reports a kind this library does not know yet.
    std::optional<ErrorKind> kind() const noexcept { return kind_; }
    /// Whether the same call might succeed if retried.
    bool retryable() const noexcept { return details_.retryable; }
    /// Why the same call might succeed if retried;
    /// empty if it cannot, or if the reason is one this library does not know yet.
    std::optional<RetryKind> retry_kind() const noexcept { return details_.retry_kind; }
    /// The AWS service the failed call went to; empty when no AWS service was involved.
    std::optional<Service> service() const noexcept { return details_.service; }
    /// The resource you need to act on; other resources involved are named in the message.
    std::optional<Resource> resource() const { return details_.resource; }
    /// The AWS service's error code, such as "AccessDeniedException"; empty unless a service answered.
    std::optional<std::string> code() const { return details_.code; }
    /// The AWS request ID, which AWS Support asks for; empty unless a service answered.
    std::optional<std::string> request_id() const { return details_.request_id; }
    /// The Rust variant name, such as "Throttling". Stable across releases, for metrics and logs.
    /// Empty for an exception this library raised without a Rust error.
    const std::string& name() const noexcept { return details_.name; }
    /// The message with every cause, for logs. Equal to what() when there is no cause.
    const std::string& full_message() const noexcept {
        return details_.full_message.empty() ? message_ : details_.full_message;
    }
    /// Where in ESDK Rust the error was created, for bug reports.
    /// Empty unless the process set `RUST_BACKTRACE=1` or `RUST_LIB_BACKTRACE=1`
    /// before the error occurred, and for an exception this library raised without a Rust error.
    const std::string& backtrace() const noexcept { return details_.backtrace; }

protected:
    /// An empty kind is an ESDK Rust error kind this library does not know yet.
    AwsEncryptionSdkException(std::optional<ErrorKind> kind, ErrorDetails details, const std::string& msg)
        : std::runtime_error(msg), kind_(kind), details_(std::move(details)), message_(msg) {}
    const ErrorDetails& details() const noexcept { return details_; }

private:
    friend void detail::throw_shim_exception(const std::string& what);

    std::optional<ErrorKind> kind_;
    ErrorDetails details_;
    std::string message_;
};

//= spec/shim/shim.md#error-classification
//= type=implication
//= reason=Every specific exception derives from AwsEncryptionSdkException
//# - Every exposed error kind MUST also be identifiable as the shim's own base
//# error type, so a target that handles only the base type is unaffected when a
//# kind is added.

/// An input or configuration value is invalid,
/// for example an input with no keyring or CMM, a zero TTL, or a wrapping key of the wrong length.
///
/// Fix the input; the same call cannot succeed.
class ValidationException : public AwsEncryptionSdkException {
public:
    explicit ValidationException(const std::string& msg, ErrorDetails details = {})
        : AwsEncryptionSdkException(ErrorKind::Validation, std::move(details), msg) {}
};

/// The bytes are not a well-formed encrypted message,
/// for example truncated input, an unsupported message version, or data after the footer.
///
/// Treat the message as corrupt; retrying cannot succeed.
class SerializationException : public AwsEncryptionSdkException {
public:
    explicit SerializationException(const std::string& msg, ErrorDetails details = {})
        : AwsEncryptionSdkException(ErrorKind::Serialization, std::move(details), msg) {}
};

/// A cryptographic check failed,
/// for example an AES-GCM authentication tag or a message signature did not verify.
///
/// The message is corrupt or modified, or is being decrypted with the wrong key;
/// retrying cannot succeed.
class CryptographicException : public AwsEncryptionSdkException {
public:
    explicit CryptographicException(const std::string& msg, ErrorDetails details = {})
        : AwsEncryptionSdkException(ErrorKind::Cryptographic, std::move(details), msg) {}
};

/// A keyring, CMM, or key store returned materials that are inconsistent or malformed,
/// for example no plaintext data key after encryption, a signing key for a suite that does not sign,
/// or a branch key record with a missing attribute or a key of the wrong length.
///
/// resource() names the branch key, keyring, or CMM.
/// Usually a bug in a custom keyring or CMM, or a corrupt key store record;
/// retrying cannot succeed.
class InvalidMaterialsException : public AwsEncryptionSdkException {
public:
    explicit InvalidMaterialsException(const std::string& msg, ErrorDetails details = {})
        : AwsEncryptionSdkException(ErrorKind::InvalidMaterials, std::move(details), msg) {}
};

/// An encryption context does not match,
/// for example a required key is missing, or a value passed to decrypt differs from the message's.
///
/// Check the encryption context passed to the call.
class EncryptionContextMismatchException : public AwsEncryptionSdkException {
public:
    explicit EncryptionContextMismatchException(const std::string& msg, ErrorDetails details = {})
        : AwsEncryptionSdkException(ErrorKind::EncryptionContextMismatch, std::move(details), msg) {}
};

/// None of the configured keys wrapped any of the message's encrypted data keys,
/// for example when decrypting with a keyring that did not encrypt the message.
///
/// resource() names the keyring or CMM that was used.
/// Decrypt with a keyring that has one of the message's keys.
class NoMatchingDataKeyException : public AwsEncryptionSdkException {
public:
    explicit NoMatchingDataKeyException(const std::string& msg, ErrorDetails details = {})
        : AwsEncryptionSdkException(ErrorKind::NoMatchingDataKey, std::move(details), msg) {}
};

/// AWS KMS or DynamoDB denied access.
///
/// is_credentials() says whether the credentials are expired or invalid;
/// otherwise fix the permissions for service() on resource().
class AccessDeniedException : public AwsEncryptionSdkException {
public:
    explicit AccessDeniedException(const std::string& msg, ErrorDetails details = {})
        : AwsEncryptionSdkException(ErrorKind::AccessDenied, std::move(details), msg) {}
    /// Whether the credentials are expired or invalid, rather than missing a permission.
    bool is_credentials() const noexcept { return details().credentials; }
};

/// A KMS key, DynamoDB table, or branch key does not exist.
///
/// Fix the configuration that names the resource().
class ResourceNotFoundException : public AwsEncryptionSdkException {
public:
    explicit ResourceNotFoundException(const std::string& msg, ErrorDetails details = {})
        : AwsEncryptionSdkException(ErrorKind::ResourceNotFound, std::move(details), msg) {}
};

/// A service or resource throttled the request.
///
/// service() and resource() say what was throttled:
/// AWS KMS, DynamoDB, or the materials cache (ResourceType::Cache, with no service()).
/// Always retryable, with RetryKind::Throttling.
class ThrottlingException : public AwsEncryptionSdkException {
public:
    explicit ThrottlingException(const std::string& msg, ErrorDetails details = {})
        : AwsEncryptionSdkException(ErrorKind::Throttling, std::move(details), msg) {}
};

/// The request conflicts with the current state of resource(),
/// for example creating a branch key whose ID already exists,
/// or rotating a branch key that another caller rotated at the same time.
///
/// reason() says which.
/// Re-read the resource before acting; retrying the same call unchanged is not safe.
/// Not retryable.
class ConflictException : public AwsEncryptionSdkException {
public:
    explicit ConflictException(const std::string& msg, ErrorDetails details = {})
        : AwsEncryptionSdkException(ErrorKind::Conflict, std::move(details), msg) {}
    /// Why the request conflicts, when known.
    std::optional<ConflictReason> reason() const noexcept { return details().conflict_reason; }
};

/// AWS KMS or DynamoDB rejected or failed the request for any other reason,
/// for example an internal service error or a KMS IncorrectKeyException.
///
/// code() is the service's error code.
/// A server-side failure is retryable.
class ServiceException : public AwsEncryptionSdkException {
public:
    explicit ServiceException(const std::string& msg, ErrorDetails details = {})
        : AwsEncryptionSdkException(ErrorKind::Service, std::move(details), msg) {}
};

/// A request to AWS KMS or DynamoDB was not sent, or its response did not arrive,
/// for example because of a network error, a timeout, or missing credentials or region.
///
/// Retryable for a network error or timeout.
class DispatchException : public AwsEncryptionSdkException {
public:
    explicit DispatchException(const std::string& msg, ErrorDetails details = {})
        : AwsEncryptionSdkException(ErrorKind::Dispatch, std::move(details), msg) {}
};

/// An internal invariant was violated, for example a poisoned lock.
///
/// A bug; report it. Never retryable.
class InternalException : public AwsEncryptionSdkException {
public:
    explicit InternalException(const std::string& msg, ErrorDetails details = {})
        : AwsEncryptionSdkException(ErrorKind::Internal, std::move(details), msg) {}
};

/// A caller-supplied stream failed while streaming,
/// for example a closed connection or a full disk.
class IoException : public AwsEncryptionSdkException {
public:
    explicit IoException(const std::string& msg, ErrorDetails details = {})
        : AwsEncryptionSdkException(ErrorKind::Io, std::move(details), msg) {}
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
struct ClientConfigImpl;
struct EncryptStreamImpl;
struct DecryptStreamImpl;
struct KmsClientImpl;
struct DdbClientImpl;
struct KeyStoreImpl;
struct KeyringImpl;
struct CryptographicMaterialsCacheImpl;
struct CacheTypeLowerer;
struct BytesFactory;

// Every duration parameter accepts any integer std::chrono::duration.
template <class Rep, class Period>
std::chrono::nanoseconds to_nanoseconds(std::chrono::duration<Rep, Period> d) {
    static_assert(
        std::is_convertible_v<std::chrono::duration<Rep, Period>, std::chrono::nanoseconds>,
        "durations must be an integer std::chrono::duration, such as std::chrono::seconds");
    return d;
}
}  // namespace detail

/// AWS service-client configuration for AWS SDK clients.
/// A field left unset defers to the ESDK Rust's default configuration resolution.
/// One ClientConfig may configure multiple clients.
class ClientConfig {
    std::shared_ptr<detail::ClientConfigImpl> impl_;
    friend class KmsClient;
    friend class DdbClient;

public:
    ClientConfig();
    /// Maximum request attempts (1 = no retries).
    ClientConfig& with_max_retry_attempts(std::uint32_t n);
    /// Selects adaptive retry mode instead of the standard one.
    ClientConfig& with_adaptive_retry(bool a);
    /// AWS region for the client (ex. "us-west-2").
    ClientConfig& with_region(const std::string& r);
};

/// KMS Client.
class KmsClient {
    std::shared_ptr<detail::KmsClientImpl> impl_;
    friend class KeyStore;

public:
    /// Creates a KMS client.
    explicit KmsClient(const ClientConfig& cfg = {});
};

/// DynamoDB client.
class DdbClient {
    std::shared_ptr<detail::DdbClientImpl> impl_;
    friend class KeyStore;

public:
    /// Creates a DynamoDB client.
    explicit DdbClient(const ClientConfig& cfg = {});
};

/// Optional Key Store parameters.
/// A field left unset is omitted from the ESDK Rust's Key Store configuration.
class KeyStoreOptions {
    std::optional<std::string> key_store_id_;
    std::vector<std::string> grant_tokens_;
    std::optional<KmsClient> kms_client_;
    std::optional<DdbClient> ddb_client_;
    friend class KeyStore;

public:
    /// An identifier for this Key Store.
    KeyStoreOptions& with_id(const std::string& id) { key_store_id_ = id; return *this; }
    /// The AWS KMS grant tokens that are used when this Key Store calls to AWS KMS.
    KeyStoreOptions& with_grant_tokens(const std::vector<std::string>& tokens) { grant_tokens_ = tokens; return *this; }
    /// The KMS client this Key Store uses. Unset lets the ESDK Rust build a default one.
    KeyStoreOptions& with_kms_client(KmsClient kms) { kms_client_ = std::move(kms); return *this; }
    /// The DynamoDB client this Key Store uses. Unset lets the ESDK Rust build a default one.
    KeyStoreOptions& with_ddb_client(DdbClient ddb) { ddb_client_ = std::move(ddb); return *this; }
};

/// A Branch Key Store backed by a DynamoDB table and protected by AWS KMS.
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
    /// \param options Optional Key Store parameters, including the KMS and DynamoDB
    ///        clients. A client left unset is built with defaults by the ESDK Rust.
    KeyStore(const std::string& table_name,
             const std::string& logical_key_store_name,
             const std::string& kms_arn,
             const KeyStoreOptions& options = {});
};

/// Base Keyring type.
/// Every concrete keyring must derive from this type.
/// All ESDK-supplied keyrings can be shared across threads.
///
/// If implementing a custom keyring, the implementation is responsible for:
///  - Deriving from this base type
///  - Keeping its own dependencies alive for its lifetime
///  - Handling its own thread safety
class Keyring {
    std::shared_ptr<detail::KeyringImpl> impl_;
    friend class EncryptionSDK;

protected:
    explicit Keyring(std::shared_ptr<detail::KeyringImpl> impl) : impl_(std::move(impl)) {}

public:
    virtual ~Keyring() = default;

    /// Adopts a custom keyring defined in Rust.
    /// See `custom-keyring` example for usage.
    ///
    /// `raw_handle` must be the return value of passing the custom Rust keyring into `aws_esdk_cpp::into_keyring_handle`.
    /// You may only pass each handle to exactly one adopt call's `raw_handle` arg.
    /// Ownership transfer's to that call's returned Keyring; any other pointer is undefined behavior.
    /// Everything the keyring depends on must be owned by the Rust keyring itself.
    /// Do not reference C++ objects from the Rust keyring through raw pointers.
    static Keyring adopt(void* raw_handle);
};

class CacheType;

/// A constructed cryptographic materials cache.
/// Copies share the underlying cache.
class CryptographicMaterialsCache {
    std::shared_ptr<detail::CryptographicMaterialsCacheImpl> impl_;
    friend class CacheType;
    friend class HierarchicalKeyring;
    explicit CryptographicMaterialsCache(
        std::shared_ptr<detail::CryptographicMaterialsCacheImpl> impl)
        : impl_(std::move(impl)) {}

public:
    /// Constructs the cache described by `cache`.
    /// \param cache Which type of local cache to use.
    explicit CryptographicMaterialsCache(const CacheType& cache);
};

// TODO: expose remaining MPL cache kinds (No, SingleThreaded, MultiThreaded)
/// Selects a kind of cryptographic materials cache, carrying that kind's own parameters.
class CacheType {
public:
    /// The best choice for most situations. Probably a StormTrackingCache.
    /// \param entry_capacity Maximum number of entries cached.
    static CacheType Default(std::uint32_t entry_capacity);
    /// A cache safe for multi-threaded use that also limits redundant and
    /// overly parallel backend calls.
    /// For a cache with sensible defaults, use Default instead.
    /// \param entry_capacity Maximum number of entries cached.
    /// \param entry_pruning_tail_size Number of entries to prune at a time.
    /// \param grace_period Time before expiration to begin refreshing.
    /// \param grace_interval Time between refresh attempts.
    /// \param fan_out Maximum number of simultaneous refresh attempts.
    /// \param inflight_ttl Time until a refresh attempt is forgotten.
    /// \param sleep Time a thread sleeps when fan_out is exceeded.
    template <class GraceRep, class GracePeriod, class IntervalRep, class IntervalPeriod,
              class InflightRep, class InflightPeriod, class SleepRep, class SleepPeriod>
    static CacheType StormTracking(
        std::uint32_t entry_capacity,
        std::uint32_t entry_pruning_tail_size,
        std::chrono::duration<GraceRep, GracePeriod> grace_period,
        std::chrono::duration<IntervalRep, IntervalPeriod> grace_interval,
        std::uint32_t fan_out,
        std::chrono::duration<InflightRep, InflightPeriod> inflight_ttl,
        std::chrono::duration<SleepRep, SleepPeriod> sleep) {
        return StormTracking(entry_capacity, entry_pruning_tail_size,
                             detail::to_nanoseconds(grace_period),
                             detail::to_nanoseconds(grace_interval), fan_out,
                             detail::to_nanoseconds(inflight_ttl), detail::to_nanoseconds(sleep),
                             Tag{});
    }
    /// Shared cache across multiple Hierarchical Keyrings. For this cache type,
    /// the user should provide an already constructed CryptographicMaterialsCache
    /// to the Hierarchical Keyring at initialization.
    static CacheType Shared(const CryptographicMaterialsCache& cache);

private:
    // Keeps the private overload out of overload resolution for callers,
    // so std::chrono::nanoseconds arguments still select the public template.
    struct Tag {};
    static CacheType StormTracking(std::uint32_t entry_capacity,
                                   std::uint32_t entry_pruning_tail_size,
                                   std::chrono::nanoseconds grace_period,
                                   std::chrono::nanoseconds grace_interval,
                                   std::uint32_t fan_out,
                                   std::chrono::nanoseconds inflight_ttl,
                                   std::chrono::nanoseconds sleep,
                                   Tag);

    enum class Kind { Default, StormTracking, Shared };
    explicit CacheType(Kind kind) : kind_(kind) {}
    Kind kind_;
    std::uint32_t entry_capacity_ = 0;
    std::uint32_t entry_pruning_tail_size_ = 0;
    std::chrono::nanoseconds grace_period_{};
    std::chrono::nanoseconds grace_interval_{};
    std::uint32_t fan_out_ = 0;
    std::chrono::nanoseconds inflight_ttl_{};
    std::chrono::nanoseconds sleep_{};
    std::shared_ptr<detail::CryptographicMaterialsCacheImpl> shared_;
    friend class CryptographicMaterialsCache;
    friend class HierarchicalKeyring;
    friend struct detail::CacheTypeLowerer;
};

/// Optional hierarchical keyring parameters.
/// A field left unset keeps the ESDK Rust's default.
class HierarchicalKeyringOptions {
    std::optional<CacheType> cache_;
    std::optional<std::string> partition_id_;
    friend class HierarchicalKeyring;

public:
    /// Sets the type of cache for this Hierarchical Keyring.
    /// By providing an already initialized 'Shared' cache, users can determine the scope of the cache.
    /// That is, if the cache is shared across other Cryptographic Material Providers,
    /// for instance other Hierarchical Keyrings or Caching Cryptographic Materials Managers (Caching CMMs).
    /// If any other type of cache in the CacheType union is provided,
    /// the Hierarchical Keyring will initialize a cache of that type,
    /// to be used with only this Hierarchical Keyring.
    /// If not set, a DefaultCache is initialized to be used with only this Hierarchical Keyring
    /// with entryCapacity = 1000.
    HierarchicalKeyringOptions& with_cache(const CacheType& cache) {
        cache_ = cache;
        return *this;
    }
    /// Partition ID to distinguish Cryptographic Material Providers (i.e: Keyrings) writing to a cache.
    /// If the Partition ID is the same for two Hierarchical Keyrings (or another Material Provider),
    /// they can share the same cache entries in the cache.
    HierarchicalKeyringOptions& with_partition_id(const std::string& id) { partition_id_ = id; return *this; }
};

/// Keyring backed by Branch Keys in a KeyStore.
class HierarchicalKeyring : public Keyring {
public:
    /// Creates a Hierarchical Keyring, which supports wrapping and unwrapping data keys
    /// using Branch Keys persisted in DynamoDB and protected by a symmetric AWS KMS Key or
    /// AWS KMS Multi-Region Key.
    /// \param key_store The Key Store which contains the Branch Key(s) responsible for
    ///        wrapping and unwrapping data keys.
    /// \param branch_key_id The identifier for the single Branch Key responsible for
    ///        wrapping and unwrapping the data key.
    /// \param ttl How long the Branch Key material is allowed to be reused within the
    ///        local cache before it is re-retrieved from Amazon DynamoDB and
    ///        re-authenticated with AWS KMS.
    /// \param options Optional Hierarchical Keyring parameters.
    template <class Rep, class Period>
    HierarchicalKeyring(KeyStore key_store,
                        const std::string& branch_key_id,
                        std::chrono::duration<Rep, Period> ttl,
                        const HierarchicalKeyringOptions& options = {})
        : HierarchicalKeyring(std::move(key_store), branch_key_id, detail::to_nanoseconds(ttl),
                              options, Tag{}) {}

private:
    // Keeps the private constructor out of overload resolution for callers,
    // so a std::chrono::nanoseconds argument still selects the public template.
    struct Tag {};

    HierarchicalKeyring(KeyStore key_store,
                        const std::string& branch_key_id,
                        std::chrono::nanoseconds ttl,
                        const HierarchicalKeyringOptions& options,
                        Tag);
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

/// Client-level configuration for EncryptionSDK.
///
/// A field set both here and on a per-call EncryptOptions/DecryptOptions is rejected with ValidationException.
/// Each field must be set in exactly one place.
/// A field unset in both defers to the core library's default.
//
//= spec/shim/esdk-shim.md#client-configuration
//# The ESDK shim MAY expose a client-level configuration mirroring the core
//# ESDK's client configuration, applied to every operation of that client.
class EncryptionSDKConfig {
    std::optional<CommitmentPolicy> commitment_policy_;
    std::optional<std::uint32_t> max_encrypted_data_keys_;
    friend class EncryptionSDK;

public:
    /// Commitment policy applied to every operation on this client.
    EncryptionSDKConfig& with_commitment_policy(CommitmentPolicy p) { commitment_policy_ = p; return *this; }
    /// Cap on the number of encrypted data keys per message, applied to every
    /// operation on this client. 0 means no limit.
    EncryptionSDKConfig& with_max_encrypted_data_keys(std::uint32_t n) { max_encrypted_data_keys_ = n; return *this; }
};

/// Result of finishing a stream
struct StreamResult {
    /// Output bytes produced by finishing a stream.
    // For encrypt: the final frame (and for signing suites, the signature footer).
    Bytes trailing_output;
    /// Encryption context associated with the message.
    std::map<std::string, std::string> encryption_context;
    /// Algorithm suite used.
    AlgorithmSuiteId algorithm_suite_id;
};

/// Streaming encrypt. Feed plaintext in chunks, receive ciphertext as it is produced.
/// `finish()` flushes the final frame (and signature footer, for signing suites).
/// Create via EncryptionSDK::create_encrypt_stream.
/// One stream is single-threaded; different streams may run on different threads.
class EncryptStream {
    std::shared_ptr<detail::EncryptStreamImpl> impl_;
    friend class EncryptionSDK;
    explicit EncryptStream(std::shared_ptr<detail::EncryptStreamImpl> impl) : impl_(std::move(impl)) {}

public:
    /// Feeds a plaintext chunk and returns whatever ciphertext the Rust ESDK has produced so far.
    /// The output ciphertext for a given write may be empty. Frames are emitted as they fill and the pump is asynchronous.
    /// An empty write adds no input and polls for produced output.
    Bytes write(const std::uint8_t* data, std::size_t size);
    /// \copydoc write(const std::uint8_t*, std::size_t)
    Bytes write(const std::vector<std::uint8_t>& chunk) { return write(chunk.data(), chunk.size()); }
    /// \copydoc write(const std::uint8_t*, std::size_t)
    Bytes write(std::string_view chunk) {
        return write(reinterpret_cast<const std::uint8_t*>(chunk.data()), chunk.size());
    }
    /// Ends the plaintext input, flushes the final frame (and the signature footer
    /// for signing suites), and returns it with the message metadata.
    /// The stream cannot be written after finish.
    StreamResult finish();
};

/// Streaming decrypt. Feed ciphertext in chunks, receive plaintext as it is produced.
/// Call finish() to complete verification.
///
/// SECURITY: the message is not fully verified until finish() returns successfully.
/// Do not act on released plaintext before finish() succeeds,
/// and discard everything released if finish() throws.
///
/// Streamed decrypt cannot be used to decrypt messages
/// that were encrypted with signing suites and have multiple frames.
/// Decrypt these messages with Aws::Esdk::decrypt instead.
class DecryptStream {
    std::shared_ptr<detail::DecryptStreamImpl> impl_;
    friend class EncryptionSDK;
    explicit DecryptStream(std::shared_ptr<detail::DecryptStreamImpl> impl) : impl_(std::move(impl)) {}

public:
    /// Feeds a ciphertext chunk and returns whatever plaintext the Rust ESDK has released so far.
    /// The output plaintext for a given write may be empty.
    /// An empty write adds no input and polls for produced output.
    /// Released plaintext is unverified until finish() succeeds; see the class documentation.
    //
    //= spec/shim/shim.md#streaming
    //= type=implication
    //# - The shim MUST document to users that output returned before the finish step
    //# succeeds is not yet complete or verified.
    Bytes write(const std::uint8_t* data, std::size_t size);
    /// \copydoc write(const std::uint8_t*, std::size_t)
    Bytes write(const std::vector<std::uint8_t>& chunk) { return write(chunk.data(), chunk.size()); }
    /// \copydoc write(const std::uint8_t*, std::size_t)
    Bytes write(const Bytes& chunk) { return write(chunk.data(), chunk.size()); }
    /// Ends the ciphertext input and completes decryption, including signature
    /// verification for signing suites.
    /// Success means every byte this stream released is authenticated and is safe to be acted upon.
    /// Failure means the user must discard all released plaintext.
    StreamResult finish();
};

/// ESDK client interface.
class EncryptionSDK {
    std::optional<CommitmentPolicy> commitment_policy_;
    std::optional<std::uint32_t> max_encrypted_data_keys_;

public:
    EncryptionSDK() = default;
    explicit EncryptionSDK(const EncryptionSDKConfig& options)
        : commitment_policy_(options.commitment_policy_),
          max_encrypted_data_keys_(options.max_encrypted_data_keys_) {}

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

    /// Creates a streaming encrypt operation.
    EncryptStream create_encrypt_stream(
        const Keyring& keyring,
        const EncryptOptions& options = {});

    /// Creates a streaming decrypt operation.
    /// See DecryptStream documentation for the verification semantics of streamed plaintext.
    DecryptStream create_decrypt_stream(
        const Keyring& keyring,
        const DecryptOptions& options = {});

    /// Encrypts a whole stream: reads plaintext from `source` in chunks, encrypts
    /// each, and writes the ciphertext to `sink` until `source` is exhausted,
    /// then flushes the final frame. Returns the message metadata. Neither the
    /// plaintext nor the ciphertext is ever fully held in memory, so this works
    /// on inputs too large to fit. For per-chunk control, use create_encrypt_stream.
    /// Throws if `source` fails before reaching end-of-stream or `sink` rejects a write.
    StreamResult encrypt_stream(
        std::istream& source,
        std::ostream& sink,
        const Keyring& keyring,
        const EncryptOptions& options = {});

    /// Decrypts a whole stream: reads ciphertext from `source`, writes plaintext
    /// to `sink`, and returns the message metadata.
    /// Throws if `source` fails before reaching end-of-stream or `sink` rejects a write.
    /// SECURITY: `sink` receives plaintext before verification completes. On a
    /// normal return every byte written to `sink` is authenticated; if this
    /// throws, discard everything written to `sink`. Streamed decrypt cannot
    /// decrypt a multi-frame message under a signing suite; use decrypt() for those.
    StreamResult decrypt_stream(
        std::istream& source,
        std::ostream& sink,
        const Keyring& keyring,
        const DecryptOptions& options = {});

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
