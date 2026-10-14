// Encrypts and decrypts a message with a raw AES keyring.

#include <iostream>
#include <vector>
#include <aws/esdk/EncryptionSDK.h>

int main() {
    try {
        // For demonstration only: a real application must source its wrapping
        // key from a secure store and never hardcode it.
        std::vector<std::uint8_t> wrapping_key(32, 0x01);

        // The namespace and name identify this wrapping key.
        // Decrypt must use a keyring with the same namespace, name, key, and algorithm.
        auto keyring = Aws::Esdk::RawAesKeyring(
            "my-key-namespace",
            "my-key-name",
            wrapping_key,
            Aws::Esdk::AesWrappingAlgorithm::AlgAes256GcmIv12Tag16
        );

        Aws::Esdk::Client sdk;

        std::vector<uint8_t> plaintext = {'H', 'e', 'l', 'l', 'o', ' ', 'W', 'o', 'r', 'l', 'd'};
        auto encrypted = sdk.encrypt(plaintext, keyring);

        auto decrypted = sdk.decrypt(encrypted.ciphertext, keyring);

        if (plaintext != decrypted.plaintext) {
            std::cerr << "Decryption failed: plaintext mismatch\n";
            return 1;
        }

        std::cout << "Success! Encryption and decryption completed successfully.\n";

    } catch (const std::exception &e) {
        std::cerr << "Error: " << e.what() << "\n";
        return 1;
    }

    return 0;
}
