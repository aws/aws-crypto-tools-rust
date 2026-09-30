// Handles the exceptions encrypt and decrypt throw.
//
// Each failure below is triggered on purpose, then handled by `handle`,
// which decides what to do from the exception's kind alone.

#include <iostream>
#include <string>
#include <vector>
#include <aws/esdk/EncryptionSDK.h>

namespace {

// What an application does about a failed call.
enum class Action { Retry, RejectInput, FixConfiguration, RejectMessage, Fail };

// Decide what to do about `e` from its kind and retryability.
Action handle(const Aws::Esdk::AwsEncryptionSdkException& e) {
    // A retryable error, such as a throttled KMS or DynamoDB request, might
    // succeed if the same call is made again later.
    if (e.retryable()) {
        return Action::Retry;
    }
    // kind() is empty for a kind this library does not know yet,
    // and new kinds can appear in later releases, so always keep a default.
    if (!e.kind()) {
        return Action::Fail;
    }
    switch (*e.kind()) {
        case Aws::Esdk::ErrorKind::Validation:
            return Action::RejectInput;
        case Aws::Esdk::ErrorKind::RemoteAccessDenied:
        case Aws::Esdk::ErrorKind::RemoteResourceNotFound:
            return Action::FixConfiguration;
        case Aws::Esdk::ErrorKind::NoMatchingDataKey:
        case Aws::Esdk::ErrorKind::Cryptographic:
        case Aws::Esdk::ErrorKind::Serialization:
        case Aws::Esdk::ErrorKind::EncryptionContextMismatch:
            return Action::RejectMessage;
        default:
            return Action::Fail;
    }
}

Aws::Esdk::RawAesKeyring raw_aes_keyring(std::uint8_t key_byte) {
    // For demonstration only: a real application must source its wrapping
    // key from a secure store and never hardcode it.
    return Aws::Esdk::RawAesKeyring("my-key-namespace", "my-key-name",
                                    std::vector<std::uint8_t>(32, key_byte),
                                    Aws::Esdk::AesWrappingAlgorithm::AlgAes256GcmIv12Tag16);
}

// Run `call`, which must throw, and return what `handle` decides.
template <typename F>
Action expect_failure(const char* what, F&& call) {
    try {
        call();
    } catch (const Aws::Esdk::AwsEncryptionSdkException& e) {
        std::cout << what << ": " << e.what() << "\n";
        return handle(e);
    }
    std::cerr << what << ": did not fail\n";
    std::exit(1);
}

}  // namespace

int main() {
    try {
        Aws::Esdk::EncryptionSDK sdk;
        auto keyring = raw_aes_keyring(0x01);
        std::vector<std::uint8_t> plaintext = {'H', 'e', 'l', 'l', 'o', ' ', 'W', 'o', 'r', 'l', 'd'};
        auto encrypted = sdk.encrypt(plaintext, keyring);
        std::vector<std::uint8_t> ciphertext(encrypted.ciphertext.begin(), encrypted.ciphertext.end());

        // A specific kind can also be caught by its own exception type.
        try {
            sdk.decrypt(ciphertext, raw_aes_keyring(0x02));
        } catch (const Aws::Esdk::CryptographicException& e) {
            std::cout << "caught CryptographicException: " << e.what() << "\n";
        }

        // A keyring whose key did not encrypt the message cannot decrypt it.
        bool ok = expect_failure("wrong key", [&] { sdk.decrypt(ciphertext, raw_aes_keyring(0x02)); })
                  == Action::RejectMessage;

        // A modified message fails authentication.
        auto tampered = ciphertext;
        tampered.back() ^= 0x01;
        ok &= expect_failure("modified message", [&] { sdk.decrypt(tampered, keyring); })
              == Action::RejectMessage;

        // Bytes that are not an encrypted message cannot be read at all.
        std::vector<std::uint8_t> garbage = {'n', 'o', 't', ' ', 'a', ' ', 'm', 'e', 's', 's', 'a', 'g', 'e'};
        ok &= expect_failure("not a message", [&] { sdk.decrypt(garbage, keyring); })
              == Action::RejectMessage;

        if (!ok) {
            std::cerr << "An error was not handled as expected\n";
            return 1;
        }
        std::cout << "Success! Every error was handled by its kind.\n";
    } catch (const std::exception& e) {
        std::cerr << "Error: " << e.what() << "\n";
        return 1;
    }
    return 0;
}
