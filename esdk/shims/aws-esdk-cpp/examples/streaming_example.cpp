// Encrypts and decrypts in chunks, with bounded working memory.
//
// The one-shot encrypt/decrypt APIs need the whole payload in one buffer.
// That doesn't work for data that never fits in memory at once, like a large file or a socket.
// The streaming APIs accept the payload chunk by chunk and hand output back as it is produced:
// ciphertext frames as they fill, plaintext frames as they verify.
//
// The ESDK rejects streamed decrypt of a multi-frame message under a signing suite.
// If you need this, decrypt those with the one-shot API instead.

#include <cstdint>
#include <iostream>
#include <vector>
#include <aws/esdk/EncryptionSDK.h>

int main() {
    try {
        // For demonstration only: a real application must source its wrapping
        // key from a secure store and never hardcode it.
        std::vector<std::uint8_t> wrapping_key(32, 0x01);
        auto keyring = Aws::Esdk::RawAesKeyring(
            "my-key-namespace", "my-key-name", wrapping_key,
            Aws::Esdk::AesWrappingAlgorithm::AlgAes256GcmIv12Tag16);

        Aws::Esdk::EncryptionSDK sdk;

        // Stand-in for a large source: 1 MiB produced in 64 KiB chunks. Only
        // one chunk is ever materialized here; the full payload never is.
        constexpr std::size_t kChunk = 64 * 1024;
        constexpr std::size_t kChunks = 16;

        // Encrypt: write each chunk as it "arrives"; ship returned ciphertext
        // immediately (here it is collected so the example can decrypt it).
        auto encryptor = sdk.create_encrypt_stream(
            keyring,
            Aws::Esdk::EncryptOptions()
                .with_algorithm_suite(Aws::Esdk::AlgorithmSuiteId::AlgAes256GcmHkdfSha512CommitKey)
                .with_frame_length(4096));
        std::vector<std::uint8_t> ciphertext;
        for (std::size_t i = 0; i < kChunks; ++i) {
            std::vector<std::uint8_t> chunk(kChunk, static_cast<std::uint8_t>(i));
            auto produced = encryptor.write(chunk);
            ciphertext.insert(ciphertext.end(), produced.begin(), produced.end());
        }
        // finish() flushes the final frame; nothing more may be written.
        auto enc_done = encryptor.finish();
        ciphertext.insert(ciphertext.end(), enc_done.trailing_output.begin(),
                          enc_done.trailing_output.end());
        std::cout << "streamed " << kChunks * kChunk << " plaintext bytes into "
                  << ciphertext.size() << " ciphertext bytes\n";

        // Decrypt: same shape in reverse. Plaintext released before finish()
        // is not yet verified data — buffer it or make its consumption
        // revocable, and only commit once finish() succeeds. If finish()
        // throws, discard everything this stream released.
        auto decryptor = sdk.create_decrypt_stream(keyring);
        std::vector<std::uint8_t> recovered;
        for (std::size_t off = 0; off < ciphertext.size(); off += kChunk) {
            auto n = std::min(kChunk, ciphertext.size() - off);
            auto released = decryptor.write(ciphertext.data() + off, n);
            recovered.insert(recovered.end(), released.begin(), released.end());
        }
        auto dec_done = decryptor.finish();
        recovered.insert(recovered.end(), dec_done.trailing_output.begin(),
                         dec_done.trailing_output.end());

        for (std::size_t i = 0; i < kChunks; ++i) {
            for (std::size_t j = 0; j < kChunk; ++j) {
                if (recovered[i * kChunk + j] != static_cast<std::uint8_t>(i)) {
                    std::cerr << "Decryption failed: plaintext mismatch\n";
                    return 1;
                }
            }
        }
        std::cout << "Success! Streaming encryption and decryption completed successfully.\n";

    } catch (const std::exception& e) {
        std::cerr << "Error: " << e.what() << "\n";
        return 1;
    }

    return 0;
}
