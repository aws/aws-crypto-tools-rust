// Integration tests exercising the C++ interfaces (EncryptionSDK.h).

#include <chrono>
#include <iostream>
#include <map>
#include <sstream>
#include <stdexcept>
#include <streambuf>
#include <string>
#include <thread>
#include <typeinfo>
#include <vector>

#include "esdk_test_support.h"

// Test utility -- OK iff `expr` throws `ExType`
#define CHECK_THROWS_TYPE(ExType, expr)                                                  \
    do {                                                                                 \
        ++::esdk_test::g_checks;                                                         \
        try {                                                                            \
            expr;                                                                        \
            ++::esdk_test::g_failures;                                                   \
            std::cerr << "FAIL: " << #expr << " did not throw\n";                        \
        } catch (const ExType& e) {                                                      \
            if (typeid(e) != typeid(ExType)) {                                           \
                ++::esdk_test::g_failures;                                               \
                std::cerr << "FAIL: " << #expr << " threw " << typeid(e).name()          \
                          << ", a subtype of " << #ExType << ": " << e.what() << "\n";   \
            }                                                                            \
        } catch (const std::exception& e) {                                              \
            ++::esdk_test::g_failures;                                                   \
            std::cerr << "FAIL: " << #expr << " threw wrong type: " << e.what() << "\n"; \
        }                                                                                \
    } while (0)

// Test utility -- OK iff `expr` throws `AwsEncryptionSdkException`
#define CHECK_THROWS_ESDK(expr)                                                             \
    do {                                                                                    \
        ++::esdk_test::g_checks;                                                            \
        bool threw = false;                                                                 \
        try {                                                                               \
            expr;                                                                           \
        } catch (const Aws::Esdk::AwsEncryptionSdkException&) {                             \
            threw = true;                                                                   \
        } catch (...) {                                                                     \
        }                                                                                   \
        if (!threw) {                                                                       \
            ++::esdk_test::g_failures;                                                      \
            std::cerr << "FAIL: expected AwsEncryptionSdkException from " << #expr << "\n"; \
        }                                                                                   \
    } while (0)

namespace {

using esdk_test::make_hierarchical_keyring;
using esdk_test::to_bytes;
using TestConfig = esdk_test::TestConfig;

void test_round_trip(const TestConfig& cfg) {
    auto keyring = make_hierarchical_keyring(cfg);
    Aws::Esdk::EncryptionSDK esdk;
    auto plaintext = to_bytes("Hello World");
    auto ciphertext = esdk.encrypt(plaintext, keyring).ciphertext;
    ESDK_CHECK(ciphertext != plaintext);

    auto decrypted = esdk.decrypt(ciphertext, keyring);
    //= spec/shim/esdk-shim.md#encrypt-inputs
    //= type=test
    //= reason=Round trip would only pass consistently if plaintext was provided unmodified.
    //# - MUST pass the target-supplied plaintext to the core ESDK unmodified.
    //
    //= spec/shim/esdk-shim.md#encrypt-outputs
    //= type=test
    //= reason=Round trip would only pass consistently if ciphertext was returned unmodified.
    //# - MUST return the core ESDK's ciphertext unmodified.
    //
    //= spec/shim/esdk-shim.md#decrypt-inputs
    //= type=test
    //= reason=Round trip would only pass consistently if ciphertext was provided unmodified.
    //# - MUST pass the target-supplied ciphertext to the core ESDK unmodified.
    //
    //= spec/shim/esdk-shim.md#decrypt-outputs
    //= type=test
    //= reason=Round trip would only pass consistently if plaintext was returned unmodified.
    //# - MUST return the core ESDK's plaintext unmodified.
    ESDK_CHECK(decrypted.plaintext == plaintext);
}

void test_round_trip_with_encryption_context(const TestConfig& cfg) {
    auto keyring = make_hierarchical_keyring(cfg);
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
    //# - MUST return the result encryption context, converted as defined in
    //# [Encryption context](#encryption-context).
    for (const auto& kv : ec) {
        ESDK_CHECK(decrypted.encryption_context.count(kv.first) == 1);
        ESDK_CHECK(decrypted.encryption_context[kv.first] == kv.second);
    }

    //= spec/shim/esdk-shim.md#decrypt-outputs
    //= type=test
    //# - MUST return the used algorithm suite, converted as defined in
    //# [Algorithm suite identifier](#algorithm-suite-identifier).
    ESDK_CHECK(decrypted.algorithm_suite_id ==
          Aws::Esdk::AlgorithmSuiteId::AlgAes256GcmHkdfSha512CommitKeyEcdsaP384);
}

void test_decrypt_garbage_throws(const TestConfig& cfg) {
    auto keyring = make_hierarchical_keyring(cfg);
    Aws::Esdk::EncryptionSDK sdk;
    auto garbage = to_bytes("this is not a valid ESDK ciphertext");
    // Assert decrypting garbage raises SerializationException
    CHECK_THROWS_TYPE(Aws::Esdk::SerializationException, sdk.decrypt(garbage, keyring));
}

void test_tampered_ciphertext_throws(const TestConfig& cfg) {
    auto keyring = make_hierarchical_keyring(cfg);
    Aws::Esdk::EncryptionSDK sdk;
    auto ciphertext = sdk.encrypt(to_bytes("tamper me"), keyring).ciphertext.to_vector();
    ESDK_CHECK(!ciphertext.empty());
    ciphertext[ciphertext.size() / 2] ^= 0xFF;  // flip a byte mid-message
    CHECK_THROWS_ESDK(sdk.decrypt(ciphertext, keyring));
}

void test_raw_aes_round_trip() {
    struct Case {
        Aws::Esdk::AesWrappingAlgorithm alg;
        std::size_t key_len;
    };
    const Case cases[] = {
        {Aws::Esdk::AesWrappingAlgorithm::AlgAes128GcmIv12Tag16, 16},
        {Aws::Esdk::AesWrappingAlgorithm::AlgAes192GcmIv12Tag16, 24},
        {Aws::Esdk::AesWrappingAlgorithm::AlgAes256GcmIv12Tag16, 32},
    };
    for (const auto& c : cases) {
        std::vector<std::uint8_t> key(c.key_len, 0x2A);
        //= spec/shim/esdk-shim.md#create-raw-aes-keyring
        //= type=test
        //# - The shim MUST provide an operation that creates a raw AES keyring backed by
        //# the core ESDK.
        Aws::Esdk::RawAesKeyring keyring("test-ns", "test-key", key, c.alg);
        Aws::Esdk::EncryptionSDK sdk;
        auto plaintext = to_bytes("raw aes through the facade");
        auto ciphertext = sdk.encrypt(plaintext, keyring).ciphertext;
        ESDK_CHECK(ciphertext != plaintext);
        auto decrypted = sdk.decrypt(ciphertext, keyring);
        ESDK_CHECK(decrypted.plaintext == plaintext);
    }
}

void test_raw_aes_mismatched_key_length_throws() {
    std::vector<std::uint8_t> short_key(16, 0x01);
    //= spec/shim/esdk-shim.md#aes-wrapping-algorithm
    //= type=test
    //= reason=A 16-byte key is too short for AES 256 (needs 32)
    //# - The shim MUST translate the target AES wrapping algorithm to the core ESDK
    //# wrapping algorithm of the same meaning.
    CHECK_THROWS_TYPE(Aws::Esdk::AwsEncryptionSdkException,
                      Aws::Esdk::RawAesKeyring(
                          "test-ns", "test-key", short_key,
                          Aws::Esdk::AesWrappingAlgorithm::AlgAes256GcmIv12Tag16));
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
    CHECK_THROWS_ESDK(sdk.decrypt(ciphertext, keyring_b));
}

void test_cache_kinds() {
    //= spec/shim/esdk-shim.md#create-cryptographic-materials-cache
    //= type=test
    //# - The shim MUST provide an operation that creates a cryptographic materials
    //# cache of a target-selected kind, backed by the core ESDK.
    //
    //= spec/shim/esdk-shim.md#create-cryptographic-materials-cache
    //= type=test
    //# - The shim MUST support creating a storm tracking cache.
    auto storm_cache = Aws::Esdk::CryptographicMaterialsCache(Aws::Esdk::CacheType::StormTracking(
        /*entry_capacity=*/100, /*entry_pruning_tail_size=*/1, /*grace_period=*/10,
        /*grace_interval=*/1, /*fan_out=*/20, /*inflight_ttl=*/10, /*sleep_milli=*/20));

    //= spec/shim/esdk-shim.md#create-cryptographic-materials-cache
    //= type=test
    //# - The shim MUST support creating a default cache.
    auto default_cache =
        Aws::Esdk::CryptographicMaterialsCache(Aws::Esdk::CacheType::Default(100));
    // entry_capacity above ESDK Rust's i32 limit is rejected.
    CHECK_THROWS_TYPE(Aws::Esdk::ValidationException,
                      Aws::Esdk::CryptographicMaterialsCache(
                          Aws::Esdk::CacheType::Default(0x80000000u)));
}

// This test is offline -- short table name rejection happens before any network calls
void test_keystore_rejects_short_table_name() {
    Aws::Esdk::KmsClient kms;
    Aws::Esdk::DdbClient ddb;
    // KeystoreError kind: no C++ class of its own, so exactly the base exception type.
    CHECK_THROWS_TYPE(Aws::Esdk::AwsEncryptionSdkException,
                      Aws::Esdk::KeyStore("ab", "ab",
                                          "arn:aws:kms:us-west-2:000000000000:key/test",
                                          Aws::Esdk::KeyStoreOptions()
                                              .with_kms_client(kms)
                                              .with_ddb_client(ddb)));
}

// Offline: building a hierarchical keyring does not contact the key store.
void test_hierarchical_keyring_ttl() {
    using namespace std::chrono_literals;
    Aws::Esdk::KmsClient kms;
    Aws::Esdk::DdbClient ddb;
    auto keystore = Aws::Esdk::KeyStore(
        "test-table", "test-logical",
        "arn:aws:kms:us-west-2:111122223333:key/1234abcd-12ab-34cd-56ef-1234567890ab",
        Aws::Esdk::KeyStoreOptions().with_kms_client(kms).with_ddb_client(ddb));

    Aws::Esdk::HierarchicalKeyring(keystore, "branch-key-id", 10min);
    Aws::Esdk::HierarchicalKeyring(keystore, "branch-key-id", 2000ms);
    Aws::Esdk::HierarchicalKeyring(keystore, "branch-key-id", 500ms);
    CHECK_THROWS_TYPE(Aws::Esdk::AwsEncryptionSdkException,
                      Aws::Esdk::HierarchicalKeyring(keystore, "branch-key-id", 0s));
    CHECK_THROWS_TYPE(Aws::Esdk::ValidationException,
                      Aws::Esdk::HierarchicalKeyring(keystore, "branch-key-id", -1s));
}

// Assert a particular error scenario forwards the error raised by ESDK Rust
void test_error_kinds() {
    std::vector<std::uint8_t> key(32, 0x2A);
    Aws::Esdk::RawAesKeyring keyring("test-ns", "test-key", key,
                                     Aws::Esdk::AesWrappingAlgorithm::AlgAes256GcmIv12Tag16);
    Aws::Esdk::EncryptionSDK sdk;

    //= spec/shim/shim.md#error-classification
    //= type=test
    //# - When the core library distinguishes kinds of errors, the shim SHOULD expose
    //# the same kinds under the core library's own names, expressed in the target
    //# language's error mechanism.
    // Malformed message -> ESDK Rust's SerializationError
    CHECK_THROWS_TYPE(Aws::Esdk::SerializationException,
                      sdk.decrypt(to_bytes("this is not a valid ESDK message"), keyring));

    // Tampered message under a non-signing suite -> ESDK Rust's CryptographicError
    auto tampered = sdk.encrypt(to_bytes("tamper me"), keyring,
                                Aws::Esdk::EncryptOptions().with_algorithm_suite(
                                    Aws::Esdk::AlgorithmSuiteId::AlgAes256GcmHkdfSha512CommitKey))
                        .ciphertext.to_vector();
    tampered.back() ^= 0xFF;
    CHECK_THROWS_TYPE(Aws::Esdk::CryptographicException, sdk.decrypt(tampered, keyring));
}

void test_client_configuration() {
    std::vector<std::uint8_t> key(32, 0x2A);
    Aws::Esdk::RawAesKeyring keyring("test-ns", "test-key", key,
                                     Aws::Esdk::AesWrappingAlgorithm::AlgAes256GcmIv12Tag16);

    // ForbidEncryptAllowDecrypt must forward ESDK Rust's behavior of rejecting committing policy in config
    Aws::Esdk::EncryptionSDK forbid_sdk(Aws::Esdk::EncryptionSDKConfig().with_commitment_policy(
        Aws::Esdk::CommitmentPolicy::ForbidEncryptAllowDecrypt));
    CHECK_THROWS_ESDK(forbid_sdk.encrypt(
        to_bytes("client policy applies"), keyring,
        Aws::Esdk::EncryptOptions().with_algorithm_suite(
            Aws::Esdk::AlgorithmSuiteId::AlgAes256GcmHkdfSha512CommitKey)));

    //= spec/shim/esdk-shim.md#client-configuration
    //= type=test
    //# - A configuration value the target supplies on both the client and a
    //# per-operation input MUST be rejected as invalid input.
    CHECK_THROWS_TYPE(
        Aws::Esdk::ValidationException,
        forbid_sdk.encrypt(to_bytes("set in two places"), keyring,
                           Aws::Esdk::EncryptOptions().with_commitment_policy(
                               Aws::Esdk::CommitmentPolicy::RequireEncryptRequireDecrypt)));

    //= spec/shim/esdk-shim.md#client-configuration
    //= type=test
    //# - A configuration value the target supplies on neither the client nor the
    //# operation MUST defer to the core ESDK's default.
    Aws::Esdk::EncryptionSDK default_sdk;
    auto rt = default_sdk.encrypt(to_bytes("defaults"), keyring);
    auto pt = default_sdk.decrypt(rt.ciphertext, keyring);
    ESDK_CHECK(pt.plaintext == to_bytes("defaults"));
}

// String-view and Bytes ergonomics for non-std::vector input/output types
void test_bytes_and_string_ergonomics() {
    std::vector<std::uint8_t> key(32, 0x2A);
    Aws::Esdk::RawAesKeyring keyring("test-ns", "test-key", key,
                                     Aws::Esdk::AesWrappingAlgorithm::AlgAes256GcmIv12Tag16);
    Aws::Esdk::EncryptionSDK sdk;

    // Text payload in, text payload out.
    //= spec/shim/shim.md#bulk-data
    //= type=test
    //# - The shim SHOULD let the caller pass a payload without first copying it into
    //# a shim-defined container: the operation reads the caller's bytes in place,
    //# and the caller's bytes need to stay valid only for the duration of the call.
    auto encrypted = sdk.encrypt(std::string_view("text payload"), keyring);
    //= spec/shim/shim.md#bulk-data
    //= type=test
    //# - The shim SHOULD let the caller read a payload result in place, where the
    //# core library wrote it, instead of copying it into a new container first.
    auto decrypted = sdk.decrypt(encrypted.ciphertext, keyring);
    ESDK_CHECK(decrypted.plaintext.as_string_view() == "text payload");

    //= spec/shim/shim.md#bulk-data
    //= type=test
    //= reason=Bytes-provided to_vector copies the data
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
    //# - A result exposed this way MUST remain valid until the caller releases it.
    Aws::Esdk::Bytes survivor;
    {
        auto scoped = sdk.encrypt(std::string_view("outlives original"), keyring);
        survivor = scoped.ciphertext;
    }
    auto plain = sdk.decrypt(survivor, keyring);
    ESDK_CHECK(plain.plaintext.as_string_view() == "outlives original");
}

// Streaming RTT
void test_streaming() {
    std::vector<std::uint8_t> key(32, 0x2A);
    Aws::Esdk::RawAesKeyring keyring("test-ns", "test-key", key,
                                     Aws::Esdk::AesWrappingAlgorithm::AlgAes256GcmIv12Tag16);
    Aws::Esdk::EncryptionSDK sdk;
    // MUST be a non-signing suite to test round-trip here.
    // Streamed decrypt of multi-frame signed messages is refused by any ESDK.
    //
    //= spec/shim/esdk-shim.md#encrypt-stream-and-decrypt-stream
    //= type=test
    //# - The ESDK shim SHOULD provide streaming encrypt and decrypt operations,
    //# accepting the same inputs as [encrypt](#encrypt-inputs) and
    //# [decrypt](#decrypt-inputs) except the plaintext or ciphertext, which the
    //# target supplies incrementally.
    auto opts = Aws::Esdk::EncryptOptions()
                    .with_algorithm_suite(Aws::Esdk::AlgorithmSuiteId::AlgAes256GcmHkdfSha512CommitKey)
                    .with_frame_length(4096)
                    .with_max_encrypted_data_keys(3)
                    .with_commitment_policy(Aws::Esdk::CommitmentPolicy::RequireEncryptRequireDecrypt);

    std::vector<std::uint8_t> plaintext(20000);
    for (std::size_t i = 0; i < plaintext.size(); ++i) plaintext[i] = static_cast<std::uint8_t>(i % 251);

    //= spec/shim/shim.md#streaming
    //= type=test
    //# If a core library resource or operation supports [streamed](../client-apis/streaming.md) inputs/outputs,
    //# the shim library SHOULD support it as well.
    auto enc = sdk.create_encrypt_stream(keyring, opts);
    std::vector<std::uint8_t> ciphertext;
    for (std::size_t off = 0; off < plaintext.size(); off += 3001) {
        auto n = std::min<std::size_t>(3001, plaintext.size() - off);
        //= spec/shim/shim.md#streaming
        //= type=test
        //# - The shim MUST provide a write step that the target calls repeatedly, each
        //# call supplying the next chunk of input and returning whatever output the
        //# operation has produced so far (possibly none).
        auto out = enc.write(plaintext.data() + off, n);
        ciphertext.insert(ciphertext.end(), out.begin(), out.end());
    }
    for (int i = 0; i < 2000 && ciphertext.size() < 4096; ++i) {
        //= spec/shim/shim.md#streaming
        //= type=test
        //= reason=With every plaintext chunk written but the input still open (finish not called), at least one full frame is already released.
        //# - The shim SHOULD return output from write steps as the core library produces
        //# it, rather than holding all output until the finish step.
        auto out = enc.write(nullptr, 0);
        ciphertext.insert(ciphertext.end(), out.begin(), out.end());
        // Sleep briefly to ensure the background worker thread consuming these writes can be scheduled
        std::this_thread::sleep_for(std::chrono::milliseconds(1));
    }
    ESDK_CHECK(ciphertext.size() >= 4096);
    //= spec/shim/shim.md#streaming
    //= type=test
    //# - The shim MUST provide a finish step that ends the input, completes the
    //# operation, and returns the operation's result together with any output not
    //# yet returned by a write step.
    auto enc_fin = enc.finish();
    //= spec/shim/esdk-shim.md#encrypt-stream-and-decrypt-stream
    //= type=test
    //# - A successful finish step MUST return the same non-payload outputs as
    //# [encrypt outputs](#encrypt-outputs) or [decrypt outputs](#decrypt-outputs).
    ESDK_CHECK(enc_fin.algorithm_suite_id ==
               Aws::Esdk::AlgorithmSuiteId::AlgAes256GcmHkdfSha512CommitKey);
    ciphertext.insert(ciphertext.end(), enc_fin.trailing_output.begin(), enc_fin.trailing_output.end());

    // Assert the ciphertext one-shot decrypts.
    ESDK_CHECK(sdk.decrypt(ciphertext, keyring).plaintext == plaintext);

    // Streamed decrypt recovers the plaintext.
    auto dec = sdk.create_decrypt_stream(
        keyring, Aws::Esdk::DecryptOptions()
                     .with_max_encrypted_data_keys(3)
                     .with_commitment_policy(Aws::Esdk::CommitmentPolicy::RequireEncryptRequireDecrypt));
    std::vector<std::uint8_t> recovered;
    for (std::size_t off = 0; off < ciphertext.size(); off += 1517) {
        auto n = std::min<std::size_t>(1517, ciphertext.size() - off);
        auto out = dec.write(ciphertext.data() + off, n);
        recovered.insert(recovered.end(), out.begin(), out.end());
    }
    auto dec_fin = dec.finish();
    recovered.insert(recovered.end(), dec_fin.trailing_output.begin(), dec_fin.trailing_output.end());
    ESDK_CHECK(recovered == plaintext);

    // Assert the stream can't be operated on after it's finished
    {
        auto done = sdk.create_encrypt_stream(keyring);
        done.finish();
        CHECK_THROWS_TYPE(Aws::Esdk::ValidationException, done.write(std::string_view("late")));
        CHECK_THROWS_TYPE(Aws::Esdk::ValidationException, done.finish());
    }

    // Tampered stream: released plaintext must be discarded.
    // The failure surfaces as CryptographicException by finish() (at the latest).
    //= spec/shim/shim.md#streaming
    //= type=test
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

void test_full_resource_chain(const TestConfig& cfg) {
    auto client_config = Aws::Esdk::ClientConfig().with_max_retry_attempts(3);
    if (!cfg.region.empty()) {
        client_config.with_region(cfg.region);
    }

    //= spec/shim/esdk-shim.md#create-kms-client
    //= type=test
    //# - The shim MUST provide an operation that creates a KMS service client backed by
    //# the core ESDK.
    Aws::Esdk::KmsClient kms(
        //= spec/shim/esdk-shim.md#create-kms-client
        //= type=test
        //# - Creating a KMS client MUST apply the target-supplied client configuration, as
        //# defined in [Service client configuration](#service-client-configuration).
        client_config
    );

    //= spec/shim/esdk-shim.md#create-dynamodb-client
    //= type=test
    //# - The shim MUST provide an operation that creates a DynamoDB service client
    //# backed by the core ESDK.
    Aws::Esdk::DdbClient ddb(
        //= spec/shim/esdk-shim.md#create-dynamodb-client
        //= type=test
        //# - Creating a DynamoDB client MUST apply the target-supplied client configuration,
        //# as defined in [Service client configuration](#service-client-configuration).
        client_config
    );

    //= spec/shim/esdk-shim.md#create-key-store
    //= type=test
    //# - The shim MUST provide an operation that creates a key store backed by the core
    //# ESDK.
    auto keystore = Aws::Esdk::KeyStore(
        //= spec/shim/esdk-shim.md#create-key-store
        //= type=test
        //# - Creating a key store MUST provide the target-supplied table name and logical key
        //# store name to the core ESDK.
        cfg.ddb_table,
        cfg.logical_keystore,
        //= spec/shim/esdk-shim.md#create-key-store
        //= type=test
        //# - Creating a key store MUST provide the target-supplied KMS configuration to the
        //# core ESDK, converted as defined in [KMS configuration](#kms-configuration).
        cfg.kms_key_arn,
        //= spec/shim/esdk-shim.md#create-key-store
        //= type=test
        //# - Creating a key store MAY be supplied with a KMS client and a DynamoDB client,
        //# each checked as defined in
        //# [Shim Specification: Handles and lifetimes](./shim.md#handles-and-lifetimes); a
        //# supplied client MUST be provided to the core ESDK, and an absent one MUST be
        //# left for the core ESDK to default.
        Aws::Esdk::KeyStoreOptions()
            .with_kms_client(kms)
            .with_ddb_client(ddb)
            //= spec/shim/esdk-shim.md#create-key-store
            //= type=test
            //# - Creating a key store MUST provide the target-supplied key store id and grant
            //# tokens to the core ESDK when present; an unset value is omitted.
            .with_id("shim-integration-test")
            .with_grant_tokens({"grant-token-example"}));

    Aws::Esdk::CryptographicMaterialsCache cache(Aws::Esdk::CacheType::StormTracking(
        /*entry_capacity=*/100, /*entry_pruning_tail_size=*/1, /*grace_period=*/10,
        /*grace_interval=*/1, /*fan_out=*/20, /*inflight_ttl=*/10, /*sleep_milli=*/20));

    //= spec/shim/esdk-shim.md#create-hierarchical-keyring
    //= type=test
    //# - The shim MUST provide an operation that creates a hierarchical keyring backed
    //# by the core ESDK.
    auto keyring = Aws::Esdk::HierarchicalKeyring(
        keystore,
        //= spec/shim/esdk-shim.md#create-hierarchical-keyring
        //= type=test
        //# - Creating a hierarchical keyring MUST provide the target-supplied branch key id
        //# and time-to-live to the core ESDK.
        cfg.branch_key_id,
        std::chrono::seconds{600},
        Aws::Esdk::HierarchicalKeyringOptions()
            //= spec/shim/esdk-shim.md#create-hierarchical-keyring
            //= type=test
            //# - Creating a hierarchical keyring MAY be supplied with a
            //# [cryptographic materials cache](#create-cryptographic-materials-cache),
            //# checked as defined in
            //# [Shim Specification: Handles and lifetimes](./shim.md#handles-and-lifetimes).
            .with_cache(Aws::Esdk::CacheType::Shared(cache))
            //= spec/shim/esdk-shim.md#create-hierarchical-keyring
            //= type=test
            //# - Creating a hierarchical keyring MUST provide the target-supplied partition id to
            //# the core ESDK when present; an unset value is omitted.
            .with_partition_id("shim-partition"));

    Aws::Esdk::EncryptionSDK sdk;
    auto plaintext = to_bytes("Hello from the C++ integration test");
    std::map<std::string, std::string> ec = {{"purpose", "integration-test"}};

    auto enc = sdk.encrypt(
        plaintext, keyring,
        Aws::Esdk::EncryptOptions()
            //= spec/shim/esdk-shim.md#encrypt-inputs
            //= type=test
            //# - MUST provide the target-supplied algorithm suite to the core ESDK,
            //# converted as defined in [Algorithm suite identifier](#algorithm-suite-identifier).
            .with_algorithm_suite(Aws::Esdk::AlgorithmSuiteId::AlgAes256GcmHkdfSha512CommitKey)
            //= spec/shim/esdk-shim.md#encrypt-inputs
            //= type=test
            //# - MUST provide the target-supplied encryption context to the core ESDK,
            //# converted as defined in [Encryption context](#encryption-context).
            .with_encryption_context(ec));
    ESDK_CHECK(enc.ciphertext != plaintext);

    //= spec/shim/esdk-shim.md#encrypt-outputs
    //= type=test
    //# - MUST return the used algorithm suite, converted as defined in
    //# [Algorithm suite identifier](#algorithm-suite-identifier).
    ESDK_CHECK(enc.algorithm_suite_id ==
               Aws::Esdk::AlgorithmSuiteId::AlgAes256GcmHkdfSha512CommitKey);

    //= spec/shim/esdk-shim.md#encrypt-outputs
    //= type=test
    //# - MUST return the result encryption context, converted as defined in
    //# [Encryption context](#encryption-context).
    ESDK_CHECK(enc.encryption_context.count("purpose") == 1);
    ESDK_CHECK(enc.encryption_context["purpose"] == "integration-test");

    auto dec = sdk.decrypt(enc.ciphertext, keyring,
                           Aws::Esdk::DecryptOptions()
                               //= spec/shim/esdk-shim.md#decrypt-inputs
                               //= type=test
                               //# - MUST provide the target-supplied encryption context to the core ESDK,
                               //# converted as defined in [Encryption context](#encryption-context).
                               .with_encryption_context(ec));
    ESDK_CHECK(dec.plaintext == plaintext);
    ESDK_CHECK(dec.algorithm_suite_id ==
               Aws::Esdk::AlgorithmSuiteId::AlgAes256GcmHkdfSha512CommitKey);
    ESDK_CHECK(dec.encryption_context.count("purpose") == 1);
    ESDK_CHECK(dec.encryption_context["purpose"] == "integration-test");
}

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

// Round trip through the whole-stream pump (encrypt_stream/decrypt_stream).
void test_streaming_pump() {
    std::vector<std::uint8_t> key(32, 0x2A);
    Aws::Esdk::RawAesKeyring keyring("test-ns", "test-key", key,
                                     Aws::Esdk::AesWrappingAlgorithm::AlgAes256GcmIv12Tag16);
    Aws::Esdk::EncryptionSDK sdk;
    const std::string message = "stream pump round trip";

    // Encrypt: stream the plaintext source into the ciphertext sink.
    std::istringstream plaintext_in(message);
    std::ostringstream ciphertext_out;
    sdk.encrypt_stream(plaintext_in, ciphertext_out, keyring,
                       Aws::Esdk::EncryptOptions().with_algorithm_suite(
                           Aws::Esdk::AlgorithmSuiteId::AlgAes256GcmHkdfSha512CommitKey));
    const std::string ciphertext = ciphertext_out.str();
    ESDK_CHECK(ciphertext != message);

    // Decrypt: stream the ciphertext back into a plaintext sink.
    std::istringstream ciphertext_in(ciphertext);
    std::ostringstream plaintext_out;
    sdk.decrypt_stream(ciphertext_in, plaintext_out, keyring);
    ESDK_CHECK(plaintext_out.str() == message);
}

// A stream that fails mid-pump must surface as an error
void test_streaming_pump_io_failure() {

    // Mock a failing stream:

    class FailingReadBuf : public std::streambuf {
        std::string data_;

    public:
        // Seed the get area with valid data to serve the initial read(s)...
        explicit FailingReadBuf(std::string data) : data_(std::move(data)) {
            setg(data_.data(), data_.data(), data_.data() + data_.size());
        }
        // ... then fail once that data is drained and more input is requested
        int_type underflow() override { throw std::runtime_error("simulated read failure"); }
    };

    std::vector<std::uint8_t> key(32, 0x2A);
    Aws::Esdk::RawAesKeyring keyring("test-ns", "test-key", key,
                                     Aws::Esdk::AesWrappingAlgorithm::AlgAes256GcmIv12Tag16);
    Aws::Esdk::EncryptionSDK sdk;

    // Assert source fails to read
    FailingReadBuf buf("partial plaintext");
    std::istream failing_source(&buf);
    std::ostringstream sink;
    CHECK_THROWS_TYPE(Aws::Esdk::AwsEncryptionSdkException,
                      sdk.encrypt_stream(failing_source, sink, keyring));

    // Assert sink fails to write
    // (Note this doesn't use the FailingReadBuf defined above and uses a different failure mode)
    std::istringstream source("plaintext");
    std::ostringstream failed_sink;
    failed_sink.setstate(std::ios::badbit);
    CHECK_THROWS_TYPE(Aws::Esdk::AwsEncryptionSdkException,
                      sdk.encrypt_stream(source, failed_sink, keyring));
}

}  // namespace

int main(int argc, char** argv) {
    // Always run offline tests
    try {
        test_raw_aes_round_trip();
        test_raw_aes_wrong_keyring_fails();
        test_raw_aes_mismatched_key_length_throws();
        test_cache_kinds();
        test_keystore_rejects_short_table_name();
        test_hierarchical_keyring_ttl();
        test_error_kinds();
        test_client_configuration();
        test_bytes_and_string_ergonomics();
        test_streaming();
        test_streaming_signed_message_refused();
        test_streaming_pump();
        test_streaming_pump_io_failure();
    } catch (const std::exception& e) {
        std::cerr << "FATAL: unexpected exception aborted the suite: " << e.what() << "\n";
        return 2;
    }

    // If enabled, also run tests that require creds
    auto cfg = esdk_test::integration_config_or_gate(argc, argv, "test_esdk");
    if (!cfg) {
        return esdk_test::report("test_esdk");
    }

    try {
        test_round_trip(*cfg);
        test_round_trip_with_encryption_context(*cfg);
        test_decrypt_garbage_throws(*cfg);
        test_tampered_ciphertext_throws(*cfg);
        test_full_resource_chain(*cfg);
    } catch (const std::exception& e) {
        std::cerr << "FATAL: unexpected exception aborted the suite: " << e.what() << "\n";
        return 2;
    }

    return esdk_test::report("test_esdk");
}
