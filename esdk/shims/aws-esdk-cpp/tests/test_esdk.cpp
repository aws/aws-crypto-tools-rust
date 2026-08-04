// Integration tests for the C++ facade (EncryptionSDK.h).

#include <iostream>
#include <map>
#include <string>
#include <vector>

#include "esdk_test_support.h"

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

    //= spec/shim/shim.md#delegation
    //= type=implication
    //= reason=Each shim operation is a thin wrapper over the corresponding core call.
    //# - Each operation the shim exposes MUST produce its result by invoking the
    //# corresponding core-library operation.
    //
    //= spec/shim/esdk-shim.md#encrypt-inputs
    //= type=test
    //= reason=Round-tripping back to the original plaintext proves encrypt passed the target plaintext to the core library unmodified.
    //# - MUST pass the target-supplied plaintext to the core ESDK unmodified.
    //
    //= spec/shim/esdk-shim.md#encrypt-outputs
    //= type=test
    //= reason=Decrypting the returned ciphertext back to the original plaintext proves encrypt returned the core library's ciphertext unmodified.
    //# - MUST return the core ESDK's ciphertext unmodified.
    //
    //= spec/shim/esdk-shim.md#decrypt-inputs
    //= type=test
    //= reason=Decrypting this exact ciphertext back to the original plaintext proves it reached the core library unmodified; any modification would fail authentication.
    //# - MUST pass the target-supplied ciphertext to the core ESDK unmodified.
    //
    //= spec/shim/esdk-shim.md#decrypt-outputs
    //= type=test
    //= reason=The recovered plaintext equals the original, proving decrypt returned the core library's plaintext unmodified.
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
    //= spec/shim/shim.md#delegation
    //= type=test
    //# - When a core-library operation returns an error, the shim MUST return an error to
    //# the target and MUST NOT report the operation as successful.
    CHECK_THROWS_ESDK(sdk.decrypt(garbage, keyring));

    std::string msg;
    try {
        sdk.decrypt(garbage, keyring);
    } catch (const Aws::Esdk::AwsEncryptionSdkException& e) {
        msg = e.what();
    }
    //= spec/shim/shim.md#delegation
    //= type=test
    //# - An error the shim returns for a failed core-library operation SHOULD include
    //# context identifying which operation failed.
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
    //= spec/shim/shim.md#handles-and-lifetimes
    //= type=test
    //= reason=make_keyring builds the KmsClient/DdbClient/KeyStore as locals and returns only the keyring; a successful encrypt+decrypt after those locals are destroyed proves the keyring retained ownership of its dependencies, so a handle could not outlive the resource it refers to.
    //# - An owned interface that depends on another resource MUST retain ownership of
    //# that resource for its own lifetime, so that a handle passed across the boundary
    //# cannot outlive the resource it refers to.
    auto ciphertext = sdk.encrypt(plaintext, keyring).ciphertext;
    auto decrypted = sdk.decrypt(ciphertext, keyring);
    ESDK_CHECK(decrypted.plaintext == plaintext);
}

void test_default_options_defer(const TestConfig& cfg) {
    auto keyring = make_keyring(cfg);
    Aws::Esdk::EncryptionSDK sdk;
    auto encrypted = sdk.encrypt(to_bytes("defer to defaults"), keyring);
    //= spec/shim/shim.md#operation-contracts
    //= type=implication
    //= reason=apply_*_options sets a core field only when the target supplied it; unset inputs keep the core default.
    //# - When the target does not supply an optional input, the shim MUST defer to
    //# the core library's default and MUST NOT substitute its own.
    ESDK_CHECK(encrypted.algorithm_suite_id ==
          Aws::Esdk::AlgorithmSuiteId::AlgAes256GcmHkdfSha512CommitKeyEcdsaP384);
}

}  // namespace

int main() {
    auto cfg = esdk_test::load_test_config();
    if (!cfg) {
        std::cout << "SKIP: set ESDK_TEST_KMS_KEY_ARN, ESDK_TEST_DDB_TABLE, "
                     "ESDK_TEST_LOGICAL_KEYSTORE, and ESDK_TEST_BRANCH_KEY_ID "
                     "to run the C++ integration tests.\n";
        return 0;
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
