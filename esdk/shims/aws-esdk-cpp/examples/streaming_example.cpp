// Example demonstrating use of streaming APIs.
//
// Streamed encrypt/decrypt is for data too large to hold in memory at once.
// encrypt_stream and decrypt_stream read from a std::istream source and write to a std::ostream sink,
// so you can stream a whole file (or socket) straight through.
// 
// This example encrypts a plaintext file to a ciphertext file, then decrypts that back to a third file.
//
// A non-signing suite is used so streamed decrypt works regardless of message size;
// the ESDK refuses streamed decrypt of a multi-frame signed message.

#include <cstdio>
#include <cstdint>
#include <fstream>
#include <iostream>
#include <map>
#include <string>
#include <vector>
#include <aws/esdk/EncryptionSDK.h>

namespace {

const char* PLAINTEXT_FILE = "streaming_example_plaintext.txt";
const char* CIPHERTEXT_FILE = "streaming_example_ciphertext.bin";
const char* DECRYPTED_FILE = "streaming_example_decrypted.txt";

bool files_equal(const char* a, const char* b) {
    std::ifstream fa(a, std::ios::binary), fb(b, std::ios::binary);
    return std::string(std::istreambuf_iterator<char>(fa), {}) ==
           std::string(std::istreambuf_iterator<char>(fb), {});
}

}  // namespace

int main() {
    try {
        // Seed a plaintext file to encrypt. In practice this file already exists.
        {
            std::ofstream seed(PLAINTEXT_FILE, std::ios::binary);
            seed << "the quick brown fox jumps over the lazy dog";
        }

        // For demonstration only: a real application must source its wrapping
        // key from a secure store and never hardcode it.
        std::vector<std::uint8_t> wrapping_key(32, 0x01);
        auto keyring = Aws::Esdk::RawAesKeyring(
            "my-key-namespace", "my-key-name", wrapping_key,
            Aws::Esdk::AesWrappingAlgorithm::AlgAes256GcmIv12Tag16);

        // The encryption context is authenticated, not encrypted. It is bound to
        // the message and must be reproducible on decrypt.
        std::map<std::string, std::string> encryption_context = {
            {"purpose", "streaming-example"},
            {"is not", "secret"},
        };

        Aws::Esdk::Client esdk;

        // Encrypt the plaintext file straight into the ciphertext file.
        {
            std::ifstream in(PLAINTEXT_FILE, std::ios::binary);
            std::ofstream out(CIPHERTEXT_FILE, std::ios::binary);
            esdk.encrypt_stream(in, out, keyring,
                                Aws::Esdk::EncryptOptions()
                                    .with_algorithm_suite(
                                        Aws::Esdk::AlgorithmSuiteId::AlgAes256GcmHkdfSha512CommitKey)
                                    .with_encryption_context(encryption_context));
        }

        // Decrypt the ciphertext file back into the decrypted file.
        // Note: decrypt_stream writes plaintext to the sink before verification completes.
        // The function returns normally only if the whole message authenticates.
        // If the function throws, you MUST discard the decrypted file/output.
        {
            std::ifstream in(CIPHERTEXT_FILE, std::ios::binary);
            std::ofstream out(DECRYPTED_FILE, std::ios::binary);
            esdk.decrypt_stream(
                in, out, keyring,
                Aws::Esdk::DecryptOptions().with_encryption_context(encryption_context));
        }

        // The decrypted file matches the original plaintext (demo check only).
        if (!files_equal(PLAINTEXT_FILE, DECRYPTED_FILE)) {
            std::cerr << "Decryption failed: decrypted file differs from plaintext\n";
            return 1;
        }

        std::remove(PLAINTEXT_FILE);
        std::remove(CIPHERTEXT_FILE);
        std::remove(DECRYPTED_FILE);

        std::cout << "Success! Streaming encryption and decryption completed successfully.\n";

    } catch (const std::exception& e) {
        std::cerr << "Error: " << e.what() << "\n";
        return 1;
    }

    return 0;
}
