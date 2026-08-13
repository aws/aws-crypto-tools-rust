// Integration tests for the C++ facade (EncryptionSDK.h).

#include <iostream>
#include <map>
#include <string>
#include <typeinfo>
#include <vector>

#include "esdk_test_support.h"

// Passes only if `expr` throws exactly `ExType`. The handler catches the
// specific expected type, as a caller would; the typeid guard then rejects a
// subclass, so a base-type expectation is not satisfied by a derived throw.
#define CHECK_THROWS_TYPE(ExType, expr)                                        \
    do {                                                                       \
        ++::esdk_test::g_checks;                                               \
        try {                                                                  \
            expr;                                                              \
            ++::esdk_test::g_failures;                                         \
            std::cerr << "FAIL: " << #expr << " did not throw\n";              \
        } catch (const ExType& e) {                                            \
            if (typeid(e) != typeid(ExType)) {                                 \
                ++::esdk_test::g_failures;                                     \
                std::cerr << "FAIL: " << #expr << " threw " << typeid(e).name() \
                          << ", a subtype of " << #ExType << ": " << e.what() << "\n"; \
            }                                                                  \
        } catch (const std::exception& e) {                                    \
            ++::esdk_test::g_failures;                                         \
            std::cerr << "FAIL: " << #expr << " threw wrong type: " << e.what() << "\n"; \
        }                                                                      \
    } while (0)

#define CHECK_THROWS_ESDK(expr)                                                \
    do {                                                                       \
        ++::esdk_test::g_checks;                                               \
        bool threw = false;                                                    \
        try {                                                                  \
            expr;                                                              \
        } catch (const Aws::Esdk::AwsEncryptionSdkException&) {                             \
            threw = true;                                                      \
        } catch (...) {                                                        \
        }                                                                      \
        if (!threw) {                                                          \
            ++::esdk_test::g_failures;                                         \
            std::cerr << "FAIL: expected AwsEncryptionSdkException from " << #expr << "\n"; \
        }                                                                      \
    } while (0)

namespace {

using esdk_test::make_keyring;
using esdk_test::to_bytes;
using TestConfig = esdk_test::TestConfig;

void test_round_trip(const TestConfig& cfg) {
    auto keyring = make_keyring(cfg);
    Aws::Esdk::EncryptionSDK sdk;
    auto plaintext = to_bytes("Hello World");
    auto ciphertext = sdk.encrypt(plaintext, keyring).ciphertext;
    ESDK_CHECK(ciphertext != plaintext);

    //= spec/shim/esdk-shim.md#encrypt-inputs
    //= type=test
    //= reason=A plaintext modified before core encrypt would decrypt back to the modified bytes, failing the equality below.
    //# - MUST pass the target-supplied plaintext to the core ESDK unmodified.
    //
    //= spec/shim/esdk-shim.md#encrypt-outputs
    //= type=test
    //= reason=A ciphertext modified after core encrypt fails AEAD authentication on decrypt.
    //# - MUST return the core ESDK's ciphertext unmodified.
    //
    //= spec/shim/esdk-shim.md#decrypt-inputs
    //= type=test
    //= reason=A ciphertext modified before core decrypt fails AEAD authentication.
    //# - MUST pass the target-supplied ciphertext to the core ESDK unmodified.
    //
    //= spec/shim/esdk-shim.md#decrypt-outputs
    //= type=test
    //= reason=A plaintext modified after core decrypt fails the equality below.
    //# - MUST return the core ESDK's plaintext unmodified.
    auto decrypted = sdk.decrypt(ciphertext, keyring);
    ESDK_CHECK(decrypted.plaintext == plaintext);
}

void test_round_trip_with_encryption_context(const TestConfig& cfg) {
    auto keyring = make_keyring(cfg);
    Aws::Esdk::EncryptionSDK sdk;
    auto plaintext = to_bytes("context matters");
    std::map<std::string, std::string> ec = {{"purpose", "test"}, {"origin", "cxx"}};
    auto encrypted = sdk.encrypt(plaintext, keyring,
                                 Aws::Esdk::EncryptOptions()
                                     .with_algorithm_suite(Aws::Esdk::AlgorithmSuiteId::AlgAes256GcmHkdfSha512CommitKeyEcdsaP384)
                                     .with_commitment_policy(Aws::Esdk::CommitmentPolicy::RequireEncryptRequireDecrypt)
                                     .with_encryption_context(ec));
    ESDK_CHECK(encrypted.algorithm_suite_id ==
          Aws::Esdk::AlgorithmSuiteId::AlgAes256GcmHkdfSha512CommitKeyEcdsaP384);
    for (const auto& kv : ec) {
        ESDK_CHECK(encrypted.encryption_context.count(kv.first) == 1);
        ESDK_CHECK(encrypted.encryption_context[kv.first] == kv.second);
    }
    auto decrypted = sdk.decrypt(encrypted.ciphertext, keyring,
                                 Aws::Esdk::DecryptOptions().with_encryption_context(ec));
    ESDK_CHECK(decrypted.plaintext == plaintext);

    //= spec/shim/esdk-shim.md#decrypt-outputs
    //= type=test
    //= reason=The decrypt result exposes the encryption context the core library returned; it contains every pair supplied at encrypt time.
    //# - MUST return the result encryption context, converted as defined in
    //# [Encryption context](#encryption-context).
    for (const auto& kv : ec) {
        ESDK_CHECK(decrypted.encryption_context.count(kv.first) == 1);
        ESDK_CHECK(decrypted.encryption_context[kv.first] == kv.second);
    }

    //= spec/shim/esdk-shim.md#decrypt-outputs
    //= type=test
    //= reason=The decrypt result exposes the algorithm suite the core library used; it equals the suite selected at encrypt time.
    //# - MUST return the used algorithm suite, converted as defined in
    //# [Algorithm suite identifier](#algorithm-suite-identifier).
    ESDK_CHECK(decrypted.algorithm_suite_id ==
          Aws::Esdk::AlgorithmSuiteId::AlgAes256GcmHkdfSha512CommitKeyEcdsaP384);
}

void test_decrypt_garbage_throws(const TestConfig& cfg) {
    auto keyring = make_keyring(cfg);
    Aws::Esdk::EncryptionSDK sdk;
    auto garbage = to_bytes("this is not a valid ESDK message");
    // Header parsing fails before the keyring is consulted: SerializationError.
    CHECK_THROWS_TYPE(Aws::Esdk::SerializationException, sdk.decrypt(garbage, keyring));

    std::string msg;
    try {
        sdk.decrypt(garbage, keyring);
    } catch (const Aws::Esdk::AwsEncryptionSdkException& e) {
        msg = e.what();
    }
    ESDK_CHECK(msg.find("decrypt") != std::string::npos);
}

void test_tampered_ciphertext_throws(const TestConfig& cfg) {
    auto keyring = make_keyring(cfg);
    Aws::Esdk::EncryptionSDK sdk;
    auto ciphertext = sdk.encrypt(to_bytes("tamper me"), keyring).ciphertext.to_vector();
    ESDK_CHECK(!ciphertext.empty());
    ciphertext[ciphertext.size() / 2] ^= 0xFF;  // flip a byte mid-message
    // The kind depends on which region the flipped byte lands in;
    // test_error_kinds pins the per-region kinds with targeted tampering.
    CHECK_THROWS_ESDK(sdk.decrypt(ciphertext, keyring));
}

void test_lifetime_safety(const TestConfig& cfg) {
    Aws::Esdk::HierarchicalKeyring keyring = make_keyring(cfg);
    Aws::Esdk::EncryptionSDK sdk;
    auto plaintext = to_bytes("outlives its dependencies");
    auto ciphertext = sdk.encrypt(plaintext, keyring).ciphertext;
    auto decrypted = sdk.decrypt(ciphertext, keyring);
    ESDK_CHECK(decrypted.plaintext == plaintext);
}

void test_default_options_defer(const TestConfig& cfg) {
    auto keyring = make_keyring(cfg);
    Aws::Esdk::EncryptionSDK sdk;
    auto encrypted = sdk.encrypt(to_bytes("defer to defaults"), keyring);
    ESDK_CHECK(encrypted.algorithm_suite_id ==
          Aws::Esdk::AlgorithmSuiteId::AlgAes256GcmHkdfSha512CommitKeyEcdsaP384);
}

// Raw AES keyring tests are fully local and run unconditionally.
void test_raw_aes_round_trip() {
    std::vector<std::uint8_t> key(32, 0x2A);
    //= spec/shim/esdk-shim.md#create-raw-aes-keyring
    //= type=test
    //# - The shim MUST provide an operation that creates a raw AES keyring backed by
    //# the core ESDK.
    Aws::Esdk::RawAesKeyring keyring("test-ns", "test-key", key,
                                     Aws::Esdk::AesWrappingAlgorithm::AlgAes256GcmIv12Tag16);
    Aws::Esdk::EncryptionSDK sdk;
    auto plaintext = to_bytes("raw aes through the facade");
    auto ciphertext = sdk.encrypt(plaintext, keyring).ciphertext;
    ESDK_CHECK(ciphertext != plaintext);
    auto decrypted = sdk.decrypt(ciphertext, keyring);
    ESDK_CHECK(decrypted.plaintext == plaintext);
}

void test_raw_aes_wrong_keyring_fails() {
    std::vector<std::uint8_t> key_a(32, 0x01);
    std::vector<std::uint8_t> key_b(32, 0x02);
    Aws::Esdk::RawAesKeyring keyring_a("test-ns", "test-key", key_a,
                                       Aws::Esdk::AesWrappingAlgorithm::AlgAes256GcmIv12Tag16);
    Aws::Esdk::RawAesKeyring keyring_b("test-ns", "test-key", key_b,
                                       Aws::Esdk::AesWrappingAlgorithm::AlgAes256GcmIv12Tag16);
    Aws::Esdk::EncryptionSDK sdk;
    auto ciphertext = sdk.encrypt(to_bytes("keyed to A"), keyring_a).ciphertext;
    // The unwrap failure's kind is unpinned; any shim error passes.
    CHECK_THROWS_ESDK(sdk.decrypt(ciphertext, keyring_b));
}

void test_raw_aes_mismatched_key_length_throws() {
    std::vector<std::uint8_t> short_key(16, 0x01);
    //= spec/shim/esdk-shim.md#aes-wrapping-algorithm
    //= type=test
    //= reason=A 16-byte key is too short for AES 256 (needs 32)
    //# - The shim MUST translate the target AES wrapping algorithm to the core ESDK
    //# wrapping algorithm of the same meaning.
    //
    // LegacyError kind: exactly the base exception type.
    CHECK_THROWS_TYPE(Aws::Esdk::AwsEncryptionSdkException,
                      Aws::Esdk::RawAesKeyring(
                          "test-ns", "test-key", short_key,
                          Aws::Esdk::AesWrappingAlgorithm::AlgAes256GcmIv12Tag16));
}

// The created cache is opaque, so a construction that does not throw is the
// observable.
void test_cache_kinds() {
    //= spec/shim/esdk-shim.md#create-cryptographic-materials-cache
    //= type=test
    //= reason=NoCache() returns a usable cache, so the operation exists and is backed by the core.
    //# - The shim MUST provide an operation that creates a cryptographic materials
    //# cache of a target-selected kind, backed by the core ESDK.
    //
    //= spec/shim/esdk-shim.md#create-cryptographic-materials-cache
    //= type=test
    //# - The shim MUST support creating a cache that performs no caching.
    Aws::Esdk::CryptographicMaterialsCache::Create(Aws::Esdk::CacheType::No());

    //= spec/shim/esdk-shim.md#create-cryptographic-materials-cache
    //= type=test
    //# - The shim MUST support creating a multi-threaded cache.
    Aws::Esdk::CryptographicMaterialsCache::Create(Aws::Esdk::CacheType::MultiThreaded(100, 1));
    // Pruning tail left unset defers to the core.
    Aws::Esdk::CryptographicMaterialsCache::Create(Aws::Esdk::CacheType::MultiThreaded(100));

    Aws::Esdk::CryptographicMaterialsCache::Create(Aws::Esdk::CacheType::Default(100));
}

// Error kinds surface as typed exceptions; all offline via the raw AES keyring.
void test_error_kinds() {
    std::vector<std::uint8_t> key(32, 0x2A);
    Aws::Esdk::RawAesKeyring keyring("test-ns", "test-key", key,
                                     Aws::Esdk::AesWrappingAlgorithm::AlgAes256GcmIv12Tag16);
    Aws::Esdk::EncryptionSDK sdk;

    //= spec/shim/shim.md#error-classification
    //= type=test
    //= reason=The core's SerializationError and CryptographicError kinds arrive as the matching C++ exception subclasses; an unclassified kind arrives as the base type.
    //# - When the core library distinguishes kinds of errors, the shim SHOULD expose
    //# the same kinds under the core library's own names, expressed in the target
    //# language's error mechanism.
    // Malformed message: the core's SerializationError kind.
    CHECK_THROWS_TYPE(Aws::Esdk::SerializationException,
                      sdk.decrypt(to_bytes("this is not a valid ESDK message"), keyring));

    // Tampered message under a non-signing suite (authentication tag
    // flipped): the core's CryptographicError kind.
    auto tampered = sdk.encrypt(to_bytes("tamper me"), keyring,
                                Aws::Esdk::EncryptOptions().with_algorithm_suite(
                                    Aws::Esdk::AlgorithmSuiteId::AlgAes256GcmHkdfSha512CommitKey))
                        .ciphertext.to_vector();
    tampered.back() ^= 0xFF;
    CHECK_THROWS_TYPE(Aws::Esdk::CryptographicException, sdk.decrypt(tampered, keyring));

    // Tampered message under a signing suite (the default): the footer
    // signature failure carries the base Esdk kind.
    auto signed_tampered = sdk.encrypt(to_bytes("tamper me signed"), keyring)
                               .ciphertext.to_vector();
    signed_tampered.back() ^= 0xFF;
    CHECK_THROWS_TYPE(Aws::Esdk::AwsEncryptionSdkException,
                      sdk.decrypt(signed_tampered, keyring));

    // Mismatched wrapping-key length is unclassified: exactly the base
    // exception type, not a subclass.
    //= spec/shim/shim.md#error-classification
    //= type=test
    //= reason=A LegacyError-kind failure must have the base exception as its exact dynamic type; a subclass fails the typeid equality in CHECK_THROWS_TYPE.
    //# - An error whose kind the shim does not expose MUST be reported as the shim's
    //# own base error type.
    std::vector<std::uint8_t> short_key(16, 0x01);
    CHECK_THROWS_TYPE(Aws::Esdk::AwsEncryptionSdkException,
                      Aws::Esdk::RawAesKeyring(
                          "ns", "n", short_key,
                          Aws::Esdk::AesWrappingAlgorithm::AlgAes256GcmIv12Tag16));
}

// Client-level configuration applies to every operation and is overridden
// field-by-field by per-call options; all offline via the raw AES keyring.
void test_client_configuration() {
    std::vector<std::uint8_t> key(32, 0x2A);
    Aws::Esdk::RawAesKeyring keyring("test-ns", "test-key", key,
                                     Aws::Esdk::AesWrappingAlgorithm::AlgAes256GcmIv12Tag16);

    // The client's ForbidEncryptAllowDecrypt policy rejects a committing suite.
    // The rejection's kind is unpinned; any shim error passes.
    Aws::Esdk::EncryptionSDK forbid_sdk(Aws::Esdk::SdkOptions().with_commitment_policy(
        Aws::Esdk::CommitmentPolicy::ForbidEncryptAllowDecrypt));
    CHECK_THROWS_ESDK(forbid_sdk.encrypt(
        to_bytes("client policy applies"), keyring,
        Aws::Esdk::EncryptOptions().with_algorithm_suite(
            Aws::Esdk::AlgorithmSuiteId::AlgAes256GcmHkdfSha512CommitKey)));

    // Matching the core's client: the same field set on both the client and
    // the per-call options is rejected.
    //= spec/shim/esdk-shim.md#client-configuration
    //= type=test
    //# - A configuration value the target supplies on both the client and a
    //# per-operation input MUST be rejected as invalid input.
    CHECK_THROWS_TYPE(
        Aws::Esdk::ValidationException,
        forbid_sdk.encrypt(to_bytes("set in two places"), keyring,
                           Aws::Esdk::EncryptOptions().with_commitment_policy(
                               Aws::Esdk::CommitmentPolicy::RequireEncryptRequireDecrypt)));

    // Unset everywhere defers to the core default (committing suite allowed).
    //= spec/shim/esdk-shim.md#client-configuration
    //= type=test
    //= reason=With no client or per-call policy, encrypt succeeds under the core's default policy.
    //# - A configuration value the target supplies on neither the client nor the
    //# operation MUST defer to the core ESDK's default.
    Aws::Esdk::EncryptionSDK default_sdk;
    auto rt = default_sdk.encrypt(to_bytes("defaults"), keyring);
    auto pt = default_sdk.decrypt(rt.ciphertext, keyring);
    ESDK_CHECK(pt.plaintext == to_bytes("defaults"));
}

// String-view and Bytes ergonomics; offline via the raw AES keyring.
void test_bytes_and_string_ergonomics() {
    std::vector<std::uint8_t> key(32, 0x2A);
    Aws::Esdk::RawAesKeyring keyring("test-ns", "test-key", key,
                                     Aws::Esdk::AesWrappingAlgorithm::AlgAes256GcmIv12Tag16);
    Aws::Esdk::EncryptionSDK sdk;

    // Text payload in, text payload out.
    //= spec/shim/shim.md#bulk-data
    //= type=test
    //= reason=The string_view borrows the caller's characters; no shim container is constructed for the input.
    //# - The shim SHOULD let the caller pass a payload without first copying it into
    //# a shim-defined container: the operation reads the caller's bytes in place,
    //# and the caller's bytes need to stay valid only for the duration of the call.
    auto encrypted = sdk.encrypt(std::string_view("text payload"), keyring);
    //= spec/shim/shim.md#bulk-data
    //= type=test
    //= reason=as_string_view reads the plaintext where the core wrote it; no copy is made.
    //# - The shim SHOULD let the caller read a payload result in place, where the
    //# core library wrote it, instead of copying it into a new container first.
    auto decrypted = sdk.decrypt(encrypted.ciphertext, keyring);
    ESDK_CHECK(decrypted.plaintext.as_string_view() == "text payload");

    //= spec/shim/shim.md#bulk-data
    //= type=test
    //= reason=to_vector yields caller-owned bytes equal to the in-place view.
    //# - The shim MUST also let the caller copy a result into memory the caller
    //# owns.
    ESDK_CHECK(encrypted.ciphertext.to_vector() == encrypted.ciphertext);

    // Copies share the buffer and compare equal; different content does not.
    Aws::Esdk::Bytes copy = encrypted.ciphertext;
    ESDK_CHECK(copy == encrypted.ciphertext);
    ESDK_CHECK(copy.data() == encrypted.ciphertext.data());
    auto other = sdk.encrypt(std::string_view("different payload"), keyring);
    ESDK_CHECK(copy != other.ciphertext);

    // A copy keeps the buffer alive after the original is destroyed.
    //= spec/shim/shim.md#bulk-data
    //= type=test
    //= reason=The surviving copy decrypts after the original result left scope, so the buffer outlived its first owner.
    //# - A result exposed this way MUST remain valid until the caller releases it.
    Aws::Esdk::Bytes survivor;
    {
        auto scoped = sdk.encrypt(std::string_view("outlives original"), keyring);
        survivor = scoped.ciphertext;
    }
    auto plain = sdk.decrypt(survivor, keyring);
    ESDK_CHECK(plain.plaintext.as_string_view() == "outlives original");
}

// Streaming through the facade; offline via the raw AES keyring.
void test_streaming() {
    std::vector<std::uint8_t> key(32, 0x2A);
    Aws::Esdk::RawAesKeyring keyring("test-ns", "test-key", key,
                                     Aws::Esdk::AesWrappingAlgorithm::AlgAes256GcmIv12Tag16);
    Aws::Esdk::EncryptionSDK sdk;
    // Non-signing suite: streamed decrypt of multi-frame signed messages is
    // refused by the core (pinned below).
    auto opts = Aws::Esdk::EncryptOptions()
                    .with_algorithm_suite(Aws::Esdk::AlgorithmSuiteId::AlgAes256GcmHkdfSha512CommitKey)
                    .with_frame_length(4096);

    std::vector<std::uint8_t> plaintext(20000);
    for (std::size_t i = 0; i < plaintext.size(); ++i) plaintext[i] = static_cast<std::uint8_t>(i % 251);

    //= spec/shim/shim.md#streaming
    //= type=test
    //= reason=Plaintext fed in non-frame-aligned chunks streams to ciphertext that one-shot decrypt accepts, and streamed decrypt recovers it below.
    //# If a core library resource or operation supports [streamed](../client-apis/streaming.md) inputs/outputs,
    //# the shim library SHOULD support it as well.
    //
    //= spec/shim/esdk-shim.md#encrypt-stream-and-decrypt-stream
    //= type=test
    //= reason=Both streaming operations exist and accept the same non-payload inputs; the payload is supplied in chunks.
    //# - The ESDK shim SHOULD provide streaming encrypt and decrypt operations,
    //# accepting the same inputs as [encrypt](#encrypt-inputs) and
    //# [decrypt](#decrypt-inputs) except the plaintext or ciphertext, which the
    //# target supplies incrementally.
    auto enc = sdk.create_encrypt_stream(keyring, opts);
    std::vector<std::uint8_t> ciphertext;
    //= spec/shim/shim.md#streaming
    //= type=test
    //= reason=write is called repeatedly with successive chunks, and its returned output is collected into the ciphertext that later decrypts.
    //# - The shim MUST provide a write step that the target calls repeatedly, each
    //# call supplying the next chunk of input and returning whatever output the
    //# operation has produced so far (possibly none).
    for (std::size_t off = 0; off < plaintext.size(); off += 3001) {
        auto n = std::min<std::size_t>(3001, plaintext.size() - off);
        auto out = enc.write(plaintext.data() + off, n);
        ciphertext.insert(ciphertext.end(), out.begin(), out.end());
    }
    // Streaming means streaming: with all plaintext written and the stream
    // still open, at least one frame of ciphertext must already be released.
    //= spec/shim/shim.md#streaming
    //= type=test
    //= reason=With every plaintext chunk written but the input still open (finish not called), at least one full frame is already released.
    //# - The shim SHOULD return output from write steps as the core library produces
    //# it, rather than holding all output until the finish step.
    for (int i = 0; i < 2000 && ciphertext.size() < 4096; ++i) {
        auto out = enc.write(nullptr, 0);
        ciphertext.insert(ciphertext.end(), out.begin(), out.end());
    }
    ESDK_CHECK(ciphertext.size() >= 4096);
    //= spec/shim/shim.md#streaming
    //= type=test
    //= reason=finish ends the input and returns trailing output; the assembled ciphertext decrypts, so the operation completed.
    //# - The shim MUST provide a finish step that ends the input, completes the
    //# operation, and returns the operation's result together with any output not
    //# yet returned by a write step.
    auto enc_fin = enc.finish();
    //= spec/shim/esdk-shim.md#encrypt-stream-and-decrypt-stream
    //= type=test
    //= reason=finish's result carries the used suite, matching encrypt outputs.
    //# - A successful finish step MUST return the same non-payload outputs as
    //# [encrypt outputs](#encrypt-outputs) or [decrypt outputs](#decrypt-outputs).
    ESDK_CHECK(enc_fin.algorithm_suite_id ==
               Aws::Esdk::AlgorithmSuiteId::AlgAes256GcmHkdfSha512CommitKey);
    ciphertext.insert(ciphertext.end(), enc_fin.trailing_output.begin(), enc_fin.trailing_output.end());

    // Streamed ciphertext one-shot decrypts.
    ESDK_CHECK(sdk.decrypt(ciphertext, keyring).plaintext == plaintext);

    // Streamed decrypt recovers the plaintext.
    auto dec = sdk.create_decrypt_stream(keyring);
    std::vector<std::uint8_t> recovered;
    for (std::size_t off = 0; off < ciphertext.size(); off += 1517) {
        auto n = std::min<std::size_t>(1517, ciphertext.size() - off);
        auto out = dec.write(ciphertext.data() + off, n);
        recovered.insert(recovered.end(), out.begin(), out.end());
    }
    auto dec_fin = dec.finish();
    recovered.insert(recovered.end(), dec_fin.trailing_output.begin(), dec_fin.trailing_output.end());
    ESDK_CHECK(recovered == plaintext);

    // The only path exercising the bridge's ValidationError decode;
    // test_client_configuration's ValidationException is facade-thrown.
    {
        auto done = sdk.create_encrypt_stream(keyring);
        done.finish();
        CHECK_THROWS_TYPE(Aws::Esdk::ValidationException, done.write(std::string_view("late")));
    }

    // Tampered stream: released plaintext must be discarded; the failure
    // surfaces as CryptographicException by finish() at the latest.
    //= spec/shim/shim.md#streaming
    //= type=test
    //= reason=The tampered stream's failure is thrown by a write or by finish, whichever the target reaches first.
    //# - When the operation has failed, the shim MUST return an error from the next
    //# write or finish step.
    auto tampered = ciphertext;
    tampered.back() ^= 0xFF;
    ++::esdk_test::g_checks;
    try {
        auto bad = sdk.create_decrypt_stream(keyring);
        for (std::size_t off = 0; off < tampered.size(); off += 4096) {
            auto n = std::min<std::size_t>(4096, tampered.size() - off);
            bad.write(tampered.data() + off, n);
        }
        bad.finish();
        ++::esdk_test::g_failures;
        std::cerr << "FAIL: tampered stream did not throw\n";
    } catch (const Aws::Esdk::CryptographicException&) {
        // expected
    }
}

// Builds every resource explicitly instead of using make_keyring, so each
// creation requirement is exercised through the facade.
void test_full_resource_chain(const TestConfig& cfg) {
    auto client_config = Aws::Esdk::ClientConfig().with_max_retry_attempts(3);
    if (!cfg.region.empty()) {
        client_config.with_region(cfg.region);
    }

    //= spec/shim/esdk-shim.md#create-kms-client
    //= type=test
    //# - The shim MUST provide an operation that creates a KMS service client backed by
    //# the core ESDK.
    //
    //= spec/shim/esdk-shim.md#create-kms-client
    //= type=test
    //# - Creating a KMS client MUST apply the target-supplied client configuration, as
    //# defined in [Service client configuration](#service-client-configuration).
    Aws::Esdk::KmsClient kms(client_config);

    //= spec/shim/esdk-shim.md#create-dynamodb-client
    //= type=test
    //# - The shim MUST provide an operation that creates a DynamoDB service client
    //# backed by the core ESDK.
    //
    //= spec/shim/esdk-shim.md#create-dynamodb-client
    //= type=test
    //# - Creating a DynamoDB client MUST apply the target-supplied client configuration,
    //# as defined in [Service client configuration](#service-client-configuration).
    Aws::Esdk::DdbClient ddb(client_config);

    //= spec/shim/esdk-shim.md#create-key-store
    //= type=test
    //# - The shim MUST provide an operation that creates a key store backed by the core
    //# ESDK.
    //
    //= spec/shim/esdk-shim.md#create-key-store
    //= type=test
    //# - Creating a key store MUST provide the target-supplied table name and logical key
    //# store name to the core ESDK.
    //
    //= spec/shim/esdk-shim.md#create-key-store
    //= type=test
    //# - Creating a key store MUST provide the target-supplied KMS configuration to the
    //# core ESDK, converted as defined in [KMS configuration](#kms-configuration).
    //
    //= spec/shim/esdk-shim.md#create-key-store
    //= type=test
    //# - Creating a key store MUST provide the target-supplied key store id and grant
    //# tokens to the core ESDK when present; an unset value is omitted.
    auto keystore = Aws::Esdk::KeyStore(
        cfg.ddb_table, cfg.logical_keystore, cfg.kms_key_arn, kms, ddb,
        Aws::Esdk::KeyStoreOptions()
            .with_id("shim-integration-test")
            .with_grant_tokens({"grant-token-example"}));

    //= spec/shim/esdk-shim.md#create-hierarchical-keyring
    //= type=test
    //= reason=A created cache is supplied via CacheType::Shared and the keyring creation succeeds and round-trips.
    //# - Creating a hierarchical keyring MAY be supplied with a
    //# [cryptographic materials cache](#create-cryptographic-materials-cache),
    //# checked as defined in
    //# [Shim Specification: Handles and lifetimes](./shim.md#handles-and-lifetimes).
    auto cache = Aws::Esdk::CryptographicMaterialsCache::Create(
        Aws::Esdk::CacheType::MultiThreaded(100, 1));

    //= spec/shim/esdk-shim.md#create-hierarchical-keyring
    //= type=test
    //# - The shim MUST provide an operation that creates a hierarchical keyring backed
    //# by the core ESDK.
    //
    //= spec/shim/esdk-shim.md#create-hierarchical-keyring
    //= type=test
    //# - Creating a hierarchical keyring MUST provide the target-supplied branch key id
    //# and time-to-live to the core ESDK.
    //
    //= spec/shim/esdk-shim.md#create-hierarchical-keyring
    //= type=test
    //# - Creating a hierarchical keyring MUST provide the target-supplied partition id to
    //# the core ESDK when present; an unset value is omitted.
    auto keyring = Aws::Esdk::HierarchicalKeyring(
        keystore, cfg.branch_key_id, /*ttl_seconds=*/600,
        Aws::Esdk::HierarchicalKeyringOptions()
            .with_cache(Aws::Esdk::CacheType::Shared(cache))
            .with_partition_id("shim-partition"));

    Aws::Esdk::EncryptionSDK sdk;
    auto plaintext = to_bytes("Hello from the C++ integration test");
    std::map<std::string, std::string> ec = {{"purpose", "integration-test"}};

    // frame length and max-EDKs are forwarded plumbing whose values here equal
    // the ESDK defaults; their forwarding is pinned by the Rust apply_* tests.
    auto enc = sdk.encrypt(
        plaintext, keyring,
        Aws::Esdk::EncryptOptions()
            .with_algorithm_suite(Aws::Esdk::AlgorithmSuiteId::AlgAes256GcmHkdfSha512CommitKey)
            .with_encryption_context(ec)
            .with_frame_length(4096)
            .with_max_encrypted_data_keys(3));
    ESDK_CHECK(enc.ciphertext != plaintext);

    //= spec/shim/esdk-shim.md#encrypt-inputs
    //= type=test
    //= reason=0x0478 differs from the core default 0x0578; a dropped input suite would echo the default here.
    //# - MUST provide the target-supplied algorithm suite to the core ESDK,
    //# converted as defined in [Algorithm suite identifier](#algorithm-suite-identifier).
    //
    //= spec/shim/esdk-shim.md#encrypt-outputs
    //= type=test
    //# - MUST return the used algorithm suite, converted as defined in
    //# [Algorithm suite identifier](#algorithm-suite-identifier).
    ESDK_CHECK(enc.algorithm_suite_id ==
               Aws::Esdk::AlgorithmSuiteId::AlgAes256GcmHkdfSha512CommitKey);

    //= spec/shim/esdk-shim.md#encrypt-inputs
    //= type=test
    //= reason=Core's result encryption context carries the pairs it received; a dropped input pair would be absent here.
    //# - MUST provide the target-supplied encryption context to the core ESDK,
    //# converted as defined in [Encryption context](#encryption-context).
    //
    //= spec/shim/esdk-shim.md#encrypt-outputs
    //= type=test
    //# - MUST return the result encryption context, converted as defined in
    //# [Encryption context](#encryption-context).
    ESDK_CHECK(enc.encryption_context.count("purpose") == 1);
    ESDK_CHECK(enc.encryption_context["purpose"] == "integration-test");

    //= spec/shim/esdk-shim.md#decrypt-inputs
    //= type=test
    //= reason=Core rejects a reproduced encryption context that mismatches the message; decrypt succeeding requires these pairs to have reached it.
    //# - MUST provide the target-supplied encryption context to the core ESDK,
    //# converted as defined in [Encryption context](#encryption-context).
    auto dec = sdk.decrypt(enc.ciphertext, keyring,
                           Aws::Esdk::DecryptOptions()
                               .with_encryption_context(ec)
                               .with_max_encrypted_data_keys(3));
    ESDK_CHECK(dec.plaintext == plaintext);
    ESDK_CHECK(dec.algorithm_suite_id ==
               Aws::Esdk::AlgorithmSuiteId::AlgAes256GcmHkdfSha512CommitKey);
    ESDK_CHECK(dec.encryption_context.count("purpose") == 1);
    ESDK_CHECK(dec.encryption_context["purpose"] == "integration-test");
}

// Streamed decrypt cannot verify a multi-frame signed message until the end, so
// the core refuses it; offline via the raw AES keyring.
void test_streaming_signed_message_refused() {
    std::vector<std::uint8_t> key(32, 0x2A);
    Aws::Esdk::RawAesKeyring keyring("test-ns", "test-key", key,
                                     Aws::Esdk::AesWrappingAlgorithm::AlgAes256GcmIv12Tag16);
    Aws::Esdk::EncryptionSDK sdk;

    // Multi-frame message under the default (signing) suite.
    std::vector<std::uint8_t> plaintext(10000, 0x5A);
    auto ciphertext = sdk.encrypt(plaintext, keyring,
                                  Aws::Esdk::EncryptOptions().with_frame_length(4096))
                          .ciphertext;

    // One-shot decrypt handles it.
    ESDK_CHECK(sdk.decrypt(ciphertext, keyring).plaintext == plaintext);

    // Streamed decrypt refuses: it never releases plaintext it cannot yet verify.
    //= spec/shim/esdk-shim.md#encrypt-stream-and-decrypt-stream
    //= type=test
    //= reason=The core's refusal to stream the multi-frame signed message surfaces as a thrown exception instead of released plaintext.
    //# - Streamed decrypt MUST NOT release plaintext the core ESDK would not release,
    //# and the shim MUST surface the core ESDK's refusal to stream a message whose
    //# verification cannot complete until the end of the message.
    ++::esdk_test::g_checks;
    try {
        auto dec = sdk.create_decrypt_stream(keyring);
        for (std::size_t off = 0; off < ciphertext.size(); off += 4096) {
            auto n = std::min<std::size_t>(4096, ciphertext.size() - off);
            dec.write(ciphertext.data() + off, n);
        }
        dec.finish();
        ++::esdk_test::g_failures;
        std::cerr << "FAIL: streamed decrypt of multi-frame signed message did not throw\n";
    } catch (const Aws::Esdk::AwsEncryptionSdkException&) {
        // expected
    }
}

}  // namespace

int main(int argc, char** argv) {
    try {
        test_raw_aes_round_trip();
        test_raw_aes_wrong_keyring_fails();
        test_raw_aes_mismatched_key_length_throws();
        test_cache_kinds();
        test_error_kinds();
        test_client_configuration();
        test_bytes_and_string_ergonomics();
        test_streaming();
        test_streaming_signed_message_refused();
    } catch (const std::exception& e) {
        std::cerr << "FATAL: unexpected exception aborted the suite: " << e.what() << "\n";
        return 2;
    }

    auto cfg = esdk_test::integration_config_or_gate(argc, argv, "test_esdk");
    if (!cfg) {
        return esdk_test::report("test_esdk");
    }

    try {
        test_round_trip(*cfg);
        test_round_trip_with_encryption_context(*cfg);
        test_decrypt_garbage_throws(*cfg);
        test_tampered_ciphertext_throws(*cfg);
        test_lifetime_safety(*cfg);
        test_default_options_defer(*cfg);
        test_full_resource_chain(*cfg);
    } catch (const std::exception& e) {
        std::cerr << "FATAL: unexpected exception aborted the suite: " << e.what() << "\n";
        return 2;
    }

    return esdk_test::report("test_esdk");
}
