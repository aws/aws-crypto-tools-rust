// Encrypts with a chosen algorithm suite instead of the default.
//
// The default suite, AlgAes256GcmHkdfSha512CommitKeyEcdsaP384, commits to the data key and signs the message.
// Signing lets a decryptor verify that the message came from someone allowed to encrypt,
// not just someone allowed to decrypt.
// When encryptors and decryptors are equally trusted, a suite without signing is faster.
// This example uses AlgAes256GcmHkdfSha512CommitKey, which commits but does not sign.

#include <iostream>
#include <string>
#include <vector>
#include <aws/esdk/EncryptionSDK.h>

int main() {
    try {
        // For demonstration only: a real application must source its wrapping
        // key from a secure store and never hardcode it.
        auto keyring = Aws::Esdk::RawAesKeyring(
            "my-key-namespace",
            "my-key-name",
            std::vector<std::uint8_t>(32, 0x01),
            Aws::Esdk::AesWrappingAlgorithm::AlgAes256GcmIv12Tag16
        );

        Aws::Esdk::EncryptionSDK sdk;
        const std::string plaintext = "Hello World";

        auto encrypted = sdk.encrypt(
            plaintext, keyring,
            Aws::Esdk::EncryptOptions().with_algorithm_suite(
                Aws::Esdk::AlgorithmSuiteId::AlgAes256GcmHkdfSha512CommitKey));
        if (encrypted.algorithm_suite_id != Aws::Esdk::AlgorithmSuiteId::AlgAes256GcmHkdfSha512CommitKey) {
            std::cerr << "unexpected algorithm suite\n";
            return 1;
        }

        // Decrypt reads the algorithm suite from the message, so it is not set here.
        auto decrypted = sdk.decrypt(encrypted.ciphertext, keyring);
        if (decrypted.plaintext.as_string_view() != plaintext) {
            std::cerr << "Decryption failed: plaintext mismatch\n";
            return 1;
        }

        std::cout << "Success! Encrypted and decrypted with a non-signing algorithm suite.\n";

    } catch (const std::exception& e) {
        std::cerr << "Error: " << e.what() << "\n";
        return 1;
    }

    return 0;
}
