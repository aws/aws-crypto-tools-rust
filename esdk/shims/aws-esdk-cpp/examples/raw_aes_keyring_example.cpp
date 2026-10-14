// Encrypts and decrypts a message with a raw AES keyring.

#include <iostream>
#include <string>
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

        const std::string plaintext = "Hello World";
        // This uses the string API; the bytes APIs take a std::vector, a pointer and length, or a std::span (C++20).
        auto encrypted = sdk.encrypt(plaintext, keyring);

        try {
            auto decrypted = sdk.decrypt(encrypted.ciphertext, keyring);
            if (decrypted.plaintext.as_string_view() != plaintext) {
                std::cerr << "Decryption failed: plaintext mismatch\n";
                return 1;
            }
        } catch (const Aws::Esdk::NoMatchingDataKeyException&) {
            std::cerr << "the message was encrypted under a different keyring\n";
            return 1;
        } catch (const Aws::Esdk::CryptographicException&) {
            std::cerr << "the message is corrupt or was tampered with\n";
            return 1;
        } catch (const Aws::Esdk::SerializationException&) {
            std::cerr << "the message is corrupt or was tampered with\n";
            return 1;
        }

        std::cout << "Success! Encryption and decryption completed successfully.\n";

    } catch (const std::exception &e) {
        std::cerr << "Error: " << e.what() << "\n";
        return 1;
    }

    return 0;
}
