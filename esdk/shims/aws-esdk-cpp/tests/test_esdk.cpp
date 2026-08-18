// Offline tests exercising the C++ interfaces (EncryptionSDK.h).
// Every test here uses only the raw AES keyring and one-shot encrypt/decrypt,
// so the suite runs fully offline with no credentials and no flags.

#include <iostream>
#include <string>
#include <typeinfo>
#include <vector>

#include "esdk_test_support.h"

// Test utility -- OK iff `expr` throws `ExType`
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

// Test utility -- OK iff `expr` throws `AwsEncryptionSdkException`
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

using esdk_test::to_bytes;

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
    // The unwrap failure's kind is unpinned; any shim error passes.
    CHECK_THROWS_ESDK(sdk.decrypt(ciphertext, keyring_b));
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

}  // namespace

int main() {
    // Every test is offline.
    try {
        test_raw_aes_round_trip();
        test_raw_aes_wrong_keyring_fails();
        test_raw_aes_mismatched_key_length_throws();
        test_error_kinds();
        test_bytes_and_string_ergonomics();
    } catch (const std::exception& e) {
        std::cerr << "FATAL: unexpected exception aborted the suite: " << e.what() << "\n";
        return 2;
    }

    return esdk_test::report("test_esdk");
}
