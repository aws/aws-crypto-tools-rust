// Handles the exceptions encrypt and decrypt throw.

#include <iostream>
#include <vector>
#include <aws/esdk/EncryptionSDK.h>

namespace {

Aws::Esdk::RawAesKeyring raw_aes_keyring(std::uint8_t key_byte) {
    // For demonstration only: a real application must source its wrapping
    // key from a secure store and never hardcode it.
    return Aws::Esdk::RawAesKeyring("my-key-namespace", "my-key-name",
                                    std::vector<std::uint8_t>(32, key_byte),
                                    Aws::Esdk::AesWrappingAlgorithm::AlgAes256GcmIv12Tag16);
}

}  // namespace

int main() {
    Aws::Esdk::EncryptionSDK sdk;
    std::vector<std::uint8_t> plaintext = {'H', 'e', 'l', 'l', 'o', ' ', 'W', 'o', 'r', 'l', 'd'};
    auto encrypted = sdk.encrypt(plaintext, raw_aes_keyring(0x01));

    // Decrypt with a keyring whose key did not encrypt the message.
    try {
        sdk.decrypt(encrypted.ciphertext, raw_aes_keyring(0x02));
        std::cerr << "decrypt with the wrong key unexpectedly succeeded\n";
        return 1;
    } catch (const Aws::Esdk::RemoteThrottledException& e) {
        // A specific kind can be caught by its own exception type.
        std::cout << "retry later: " << e.what() << "\n";
    } catch (const Aws::Esdk::AwsEncryptionSdkException& e) {
        // Or catch the base type and decide from kind() and retryable().
        // kind() is empty for a kind this library does not know yet.
        if (e.retryable()) {
            std::cout << "retry later: " << e.what() << "\n";
        } else if (e.kind() == Aws::Esdk::ErrorKind::Validation) {
            std::cout << "fix the input: " << e.what() << "\n";
        } else if (e.kind() == Aws::Esdk::ErrorKind::Cryptographic ||
                   e.kind() == Aws::Esdk::ErrorKind::NoMatchingDataKey ||
                   e.kind() == Aws::Esdk::ErrorKind::Serialization) {
            std::cout << "reject the message: " << e.what() << "\n";
        } else {
            std::cout << "failed: " << e.what() << "\n";
        }
        if (e.kind() != Aws::Esdk::ErrorKind::Cryptographic) {
            std::cerr << "expected a Cryptographic error\n";
            return 1;
        }
    }
    return 0;
}
