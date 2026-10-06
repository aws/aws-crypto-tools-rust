// Your C++ code using the custom keyring.

#include <iostream>
#include <string>
#include <aws/esdk/EncryptionSDK.h>

// Declare the extern "C" constructor your Rust crate exports.
extern "C" void* custom_keyring_create();

int main() {
    try {
        // Step 4: adopt the handle
        void* handle = custom_keyring_create();
        if (handle == nullptr) {
            std::cerr << "Rust keyring construction failed\n";
            return 1;
        }
        auto keyring = Aws::Esdk::Keyring::adopt(handle);

        // From here on, nothing is special about your keyring.
        // Use it like any other keyring.
        Aws::Esdk::EncryptionSDK sdk;

        const std::string plaintext = "Hello World";
        // This uses the string API; the bytes APIs take a std::vector, a pointer and length, or a std::span (C++20).
        auto encrypted = sdk.encrypt(plaintext, keyring);

        auto decrypted = sdk.decrypt(encrypted.ciphertext, keyring);

        if (decrypted.plaintext.as_string_view() != plaintext) {
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
