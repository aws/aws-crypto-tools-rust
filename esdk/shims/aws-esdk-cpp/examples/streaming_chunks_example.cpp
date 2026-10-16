// Example demonstrating use of lower-level streaming APIs.
//
// The higher-level APIs in streaming_example.cpp are the right tool for most cases.
// However, you should use the lower-level APIs if:
//  - your data is not an iostream
//  - your data arrives in chunks you poll for
//  - you want to control how chunks are handled (backpressure, early cancel)
//  - you want to buffer unverified plaintext 
//
// This example encrypts a plaintext file that it reads in chunks,
// then decrypts it back while withholding the plaintext until it is authenticated.
//
// A non-signing suite is used so streamed decrypt works regardless of message size;
// the ESDK refuses streamed decrypt of a multi-frame signed message.

#include <cstdint>
#include <cstdio>
#include <fstream>
#include <iostream>
#include <map>
#include <stdexcept>
#include <string>
#include <string_view>
#include <vector>
#include <aws/esdk/EncryptionSDK.h>

namespace {

const char* PLAINTEXT_FILE = "streaming_chunks_example_plaintext.txt";
const char* CIPHERTEXT_FILE = "streaming_chunks_example_ciphertext.bin";
const char* DECRYPTED_FILE = "streaming_chunks_example_decrypted.txt";

void append(std::vector<std::uint8_t>& dst, const Aws::Esdk::Plaintext& src) {
    dst.insert(dst.end(), src.begin(), src.end());
}

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
            std::string message = "the quick brown fox jumps over the lazy dog, ";
            for (int i = 0; i < 6; ++i) message += message;  // lengthen message to span multiple frames
            std::ofstream seed(PLAINTEXT_FILE, std::ios::binary);
            seed << message;
        }

        // For demonstration only: a real application must source its wrapping
        // key from a secure store and never hardcode it.
        std::vector<std::uint8_t> wrapping_key(32, 0x01);
        auto keyring = Aws::Esdk::RawAesKeyring(
            "my-key-namespace", "my-key-name", wrapping_key,
            Aws::Esdk::AesWrappingAlgorithm::AlgAes256GcmIv12Tag16);

        std::map<std::string, std::string> encryption_context = {
            {"purpose", "streaming-chunks-example"},
            {"is not", "secret"},
        };

        Aws::Esdk::Client esdk;

        // Encrypt
        {
            auto enc = esdk.create_encrypt_stream(
                keyring, Aws::Esdk::EncryptOptions()
                             .with_algorithm_suite(
                                 Aws::Esdk::AlgorithmSuiteId::AlgAes256GcmHkdfSha512CommitKey)
                             .with_encryption_context(encryption_context));

            std::ifstream in(PLAINTEXT_FILE, std::ios::binary);
            std::ofstream out(CIPHERTEXT_FILE, std::ios::binary);

            // Read the plaintext file one chunk at a time.
            char chunk[512];
            while (in.read(chunk, sizeof chunk), in.gcount() > 0) {
                // Feed each chunk.
                Aws::Esdk::Ciphertext produced =
                    // write() returns the ciphertext produced so far, possibly empty until a frame fills.
                    enc.write(std::string_view(chunk, static_cast<std::size_t>(in.gcount())));
                // You can forward the ciphertext produced so far to an output stream
                // (in contrast to plaintext, which you MUST buffer; see below).
                out.write(reinterpret_cast<const char*>(produced.data()), produced.size());
            }
            // finish() flushes the last frame (and signature footer, for signing suites).
            // The loop above exits on read errors too, not just EOF.
            // Check for EOF first so a truncated read never becomes a valid message.
            if (!in.eof() || in.bad())
                throw std::runtime_error("failed reading plaintext file");
            Aws::Esdk::Ciphertext trailing = enc.finish().trailing_output;
            out.write(reinterpret_cast<const char*>(trailing.data()), trailing.size());
            if (!out) throw std::runtime_error("failed writing ciphertext file");
        }

        // Decrypt
        {
            auto dec = esdk.create_decrypt_stream(
                keyring,
                Aws::Esdk::DecryptOptions().with_encryption_context(encryption_context));

            std::ifstream in(CIPHERTEXT_FILE, std::ios::binary);

            // write() releases plaintext as frames verify,
            // but the plaintext is not authenticated until finish() returns.
            // Buffer here and do not act on, persist, or forward these bytes yet.
            // If finish() throws, drop them.
            std::vector<std::uint8_t> unverified;
            char chunk[1024];
            while (in.read(chunk, sizeof chunk), in.gcount() > 0) {
                append(unverified,
                       dec.write(std::string_view(chunk, static_cast<std::size_t>(in.gcount()))));
            }
            if (!in.eof() || in.bad())
                throw std::runtime_error("failed reading ciphertext file");
            append(unverified, dec.finish().trailing_output);

            // finish() returned. Every byte is now authenticated and safe to use.
            std::ofstream out(DECRYPTED_FILE, std::ios::binary);
            out.write(reinterpret_cast<const char*>(unverified.data()), unverified.size());
            if (!out) throw std::runtime_error("failed writing decrypted file");
        }

        if (!files_equal(PLAINTEXT_FILE, DECRYPTED_FILE)) {
            std::cerr << "Decryption failed: decrypted file differs from plaintext\n";
            return 1;
        }

        std::remove(PLAINTEXT_FILE);
        std::remove(CIPHERTEXT_FILE);
        std::remove(DECRYPTED_FILE);

        std::cout << "Success! Chunked encryption and decryption completed successfully.\n";

    } catch (const std::exception& e) {
        std::cerr << "Error: " << e.what() << "\n";
        return 1;
    }

    return 0;
}
