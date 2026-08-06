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

    // Malformed message: InvalidInputException.
    CHECK_THROWS_TYPE(Aws::Esdk::InvalidInputException,
                      sdk.decrypt(to_bytes("this is not a valid ESDK message"), keyring));

    // Tampered message (authentication tag flipped): AuthenticationException.
    auto tampered = sdk.encrypt(to_bytes("tamper me"), keyring).ciphertext.to_vector();
    tampered.back() ^= 0xFF;
    CHECK_THROWS_TYPE(Aws::Esdk::AuthenticationException, sdk.decrypt(tampered, keyring));

    // Mismatched wrapping-key length is unclassified: the base exception type,
    // not one of the subclasses.
    std::vector<std::uint8_t> short_key(16, 0x01);
    ++::esdk_test::g_checks;
    try {
        Aws::Esdk::RawAesKeyring bad("ns", "n", short_key,
                                     Aws::Esdk::AesWrappingAlgorithm::AlgAes256GcmIv12Tag16);
        ++::esdk_test::g_failures;
        std::cerr << "FAIL: short wrapping key did not throw\n";
    } catch (const Aws::Esdk::AuthenticationException&) {
        ++::esdk_test::g_failures;
        std::cerr << "FAIL: short wrapping key threw AuthenticationException\n";
    } catch (const Aws::Esdk::ServiceException&) {
        ++::esdk_test::g_failures;
        std::cerr << "FAIL: short wrapping key threw ServiceException\n";
    } catch (const Aws::Esdk::InvalidInputException&) {
        ++::esdk_test::g_failures;
        std::cerr << "FAIL: short wrapping key threw InvalidInputException\n";
    } catch (const Aws::Esdk::AwsEncryptionSdkException&) {
        // expected: base type only
    }
}

}  // namespace

int main() {
    try {
        test_raw_aes_round_trip();
        test_raw_aes_wrong_keyring_fails();
        test_raw_aes_mismatched_key_length_throws();
        test_error_kinds();
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
