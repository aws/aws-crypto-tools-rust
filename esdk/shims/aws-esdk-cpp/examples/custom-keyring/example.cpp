// Encrypts and decrypts a message with a keyring defined in Rust (see
// src/lib.rs in this directory). The Rust side hands over an opaque handle;
// Keyring::adopt turns it into a keyring usable anywhere one is accepted.

#include <iostream>
#include <vector>
#include <aws/esdk/EncryptionSDK.h>

// Implemented by this example's Rust crate. Returns a handle for
// Aws::Esdk::Keyring::adopt, or null on failure; each non-null handle must be
// adopted exactly once.
extern "C" void* custom_keyring_create();

int main() {
    try {
        void* handle = custom_keyring_create();
        if (handle == nullptr) {
            std::cerr << "Rust keyring construction failed\n";
            return 1;
        }
        auto keyring = Aws::Esdk::Keyring::adopt(handle);

        Aws::Esdk::EncryptionSDK sdk;

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
