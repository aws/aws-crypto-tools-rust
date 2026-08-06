// Integration tests for the C++ facade (EncryptionSDK.h).

#include <iostream>
#include <map>
#include <string>
#include <vector>

#include "esdk_test_support.h"

// Passes only if `expr` throws exactly the exception type `ExType` (allowing
// derived-to-base only when ExType is that exact class in the hierarchy check
// below via catch ordering).
#define CHECK_THROWS_TYPE(ExType, expr)                                        \
    do {                                                                       \
        ++::esdk_test::g_checks;                                               \
        bool caught_expected = false;                                          \
        try {                                                                  \
            expr;                                                              \
        } catch (const ExType&) {                                              \
            caught_expected = true;                                            \
        } catch (const std::exception& e) {                                    \
            std::cerr << "FAIL: " << #expr << " threw wrong type: " << e.what() << "\n"; \
        }                                                                      \
        if (caught_expected) {                                                 \
        } else {                                                               \
            ++::esdk_test::g_failures;                                         \
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
    CHECK_THROWS_ESDK(sdk.decrypt(garbage, keyring));

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
    ciphertext[ciphertext.size() / 2] ^= 0xFF;  // flip a byte in the body
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
    CHECK_THROWS_ESDK(sdk.decrypt(ciphertext, keyring_b));
}

void test_raw_aes_mismatched_key_length_throws() {
    std::vector<std::uint8_t> short_key(16, 0x01);
    CHECK_THROWS_ESDK(Aws::Esdk::RawAesKeyring(
        "test-ns", "test-key", short_key,
        Aws::Esdk::AesWrappingAlgorithm::AlgAes256GcmIv12Tag16));
}

// Error kinds surface as typed exceptions; all offline via the raw AES keyring.
void test_error_kinds() {
    std::vector<std::uint8_t> key(32, 0x2A);
    Aws::Esdk::RawAesKeyring keyring("test-ns", "test-key", key,
                                     Aws::Esdk::AesWrappingAlgorithm::AlgAes256GcmIv12Tag16);
    Aws::Esdk::EncryptionSDK sdk;

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

    // Mismatched wrapping-key length is unclassified: the base exception type,
    // not one of the subclasses.
    std::vector<std::uint8_t> short_key(16, 0x01);
    ++::esdk_test::g_checks;
    try {
        Aws::Esdk::RawAesKeyring bad("ns", "n", short_key,
                                     Aws::Esdk::AesWrappingAlgorithm::AlgAes256GcmIv12Tag16);
        ++::esdk_test::g_failures;
        std::cerr << "FAIL: short wrapping key did not throw\n";
    } catch (const Aws::Esdk::SerializationException&) {
        ++::esdk_test::g_failures;
        std::cerr << "FAIL: short wrapping key threw SerializationException\n";
    } catch (const Aws::Esdk::CryptographicException&) {
        ++::esdk_test::g_failures;
        std::cerr << "FAIL: short wrapping key threw CryptographicException\n";
    } catch (const Aws::Esdk::ValidationException&) {
        ++::esdk_test::g_failures;
        std::cerr << "FAIL: short wrapping key threw ValidationException\n";
    } catch (const Aws::Esdk::AwsEncryptionSdkException&) {
        // expected: the core's LegacyError kind has no dedicated type
    }
}

// Client-level configuration applies to every operation and is overridden
// field-by-field by per-call options; all offline via the raw AES keyring.
void test_client_configuration() {
    std::vector<std::uint8_t> key(32, 0x2A);
    Aws::Esdk::RawAesKeyring keyring("test-ns", "test-key", key,
                                     Aws::Esdk::AesWrappingAlgorithm::AlgAes256GcmIv12Tag16);

    // The client's ForbidEncryptAllowDecrypt policy rejects a committing suite.
    Aws::Esdk::EncryptionSDK forbid_sdk(Aws::Esdk::SdkOptions().with_commitment_policy(
        Aws::Esdk::CommitmentPolicy::ForbidEncryptAllowDecrypt));
    CHECK_THROWS_ESDK(forbid_sdk.encrypt(
        to_bytes("client policy applies"), keyring,
        Aws::Esdk::EncryptOptions().with_algorithm_suite(
            Aws::Esdk::AlgorithmSuiteId::AlgAes256GcmHkdfSha512CommitKey)));

    // Matching the core's client: the same field set on both the client and
    // the per-call options is rejected.
    CHECK_THROWS_TYPE(
        Aws::Esdk::ValidationException,
        forbid_sdk.encrypt(to_bytes("set in two places"), keyring,
                           Aws::Esdk::EncryptOptions().with_commitment_policy(
                               Aws::Esdk::CommitmentPolicy::RequireEncryptRequireDecrypt)));

    // Unset everywhere defers to the core default (committing suite allowed).
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
    auto encrypted = sdk.encrypt(std::string_view("text payload"), keyring);
    auto decrypted = sdk.decrypt(encrypted.ciphertext, keyring);
    ESDK_CHECK(decrypted.plaintext.as_string_view() == "text payload");

    // Copies share the buffer and compare equal; different content does not.
    Aws::Esdk::Bytes copy = encrypted.ciphertext;
    ESDK_CHECK(copy == encrypted.ciphertext);
    ESDK_CHECK(copy.data() == encrypted.ciphertext.data());
    auto other = sdk.encrypt(std::string_view("different payload"), keyring);
    ESDK_CHECK(copy != other.ciphertext);

    // A copy keeps the buffer alive after the original is destroyed.
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

    auto enc = sdk.create_encrypt_stream(keyring, opts);
    std::vector<std::uint8_t> ciphertext;
    for (std::size_t off = 0; off < plaintext.size(); off += 3001) {
        auto n = std::min<std::size_t>(3001, plaintext.size() - off);
        auto out = enc.write(plaintext.data() + off, n);
        ciphertext.insert(ciphertext.end(), out.begin(), out.end());
    }
    // Streaming means streaming: with all plaintext written and the stream
    // still open, at least one frame of ciphertext must already be released.
    for (int i = 0; i < 2000 && ciphertext.size() < 4096; ++i) {
        auto out = enc.write(nullptr, 0);
        ciphertext.insert(ciphertext.end(), out.begin(), out.end());
    }
    ESDK_CHECK(ciphertext.size() >= 4096);
    auto enc_fin = enc.finish();
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

    // Tampered stream: released plaintext must be discarded; the failure
    // surfaces as AuthenticationException by finish() at the latest.
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

}  // namespace

int main() {
    try {
        test_raw_aes_round_trip();
        test_raw_aes_wrong_keyring_fails();
        test_raw_aes_mismatched_key_length_throws();
        test_error_kinds();
        test_client_configuration();
        test_bytes_and_string_ergonomics();
        test_streaming();
    } catch (const std::exception& e) {
        std::cerr << "FATAL: unexpected exception aborted the suite: " << e.what() << "\n";
        return 2;
    }

    auto cfg = esdk_test::load_test_config();
    if (!cfg) {
        std::cout << "SKIP: set ESDK_TEST_KMS_KEY_ARN, ESDK_TEST_DDB_TABLE, "
                     "ESDK_TEST_LOGICAL_KEYSTORE, and ESDK_TEST_BRANCH_KEY_ID to "
                     "run the C++ integration tests.\n";
        return esdk_test::report("test_esdk");
    }

    try {
        test_round_trip(*cfg);
        test_round_trip_with_encryption_context(*cfg);
        test_decrypt_garbage_throws(*cfg);
        test_tampered_ciphertext_throws(*cfg);
        test_lifetime_safety(*cfg);
        test_default_options_defer(*cfg);
    } catch (const std::exception& e) {
        std::cerr << "FATAL: unexpected exception aborted the suite: " << e.what() << "\n";
        return 2;
    }

    return esdk_test::report("test_esdk");
}
