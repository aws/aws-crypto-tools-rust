// Incremental streaming: feed chunks as they arrive, drive the operation yourself.
//
// The whole-stream encrypt_stream/decrypt_stream (see streaming_example.cpp) is
// the right tool when your data is behind a std::istream/std::ostream and you
// can let the SDK own the copy loop. Reach for the lower-level
// create_encrypt_stream/create_decrypt_stream instead when:
//   - your data is not an iostream (a socket, a pipe, an async reactor callback)
//     and arrives in chunks you poll for,
//   - you want per-chunk control (backpressure, early cancel), or
//   - on decrypt, you must not let unverified plaintext escape (see below).
//
// This example encrypts a message that arrives in chunks from a stand-in byte
// source, then decrypts it back while withholding the plaintext until it is
// authenticated.
//
// A non-signing suite is used so streamed decrypt works regardless of message
// size; the ESDK refuses streamed decrypt of a multi-frame signed message.

#include <algorithm>
#include <cstdint>
#include <iostream>
#include <map>
#include <string>
#include <utility>
#include <vector>
#include <aws/esdk/EncryptionSDK.h>

namespace {

// Stands in for a byte source you poll as data shows up: a socket read, a pipe,
// an async reactor. It is deliberately NOT a std::istream -- that is the whole
// reason this example drives the stream by hand instead of using encrypt_stream.
class ChunkSource {
public:
    ChunkSource(std::vector<std::uint8_t> data, std::size_t chunk_size)
        : data_(std::move(data)), chunk_size_(chunk_size) {}

    // The next chunk, or empty once drained. A real source would block until
    // more bytes arrive; here we just walk a buffer.
    std::vector<std::uint8_t> next() {
        const std::size_t n = std::min(chunk_size_, data_.size() - pos_);
        std::vector<std::uint8_t> chunk(data_.begin() + pos_, data_.begin() + pos_ + n);
        pos_ += n;
        return chunk;
    }
    bool drained() const { return pos_ >= data_.size(); }

private:
    std::vector<std::uint8_t> data_;
    std::size_t chunk_size_;
    std::size_t pos_ = 0;
};

void append(std::vector<std::uint8_t>& dst, const Aws::Esdk::Bytes& src) {
    dst.insert(dst.end(), src.begin(), src.end());
}

}  // namespace

int main() {
    try {
        // For demonstration only: a real application must source its wrapping
        // key from a secure store and never hardcode it.
        std::vector<std::uint8_t> wrapping_key(32, 0x01);
        auto keyring = Aws::Esdk::RawAesKeyring(
            "my-key-namespace", "my-key-name", wrapping_key,
            Aws::Esdk::AesWrappingAlgorithm::AlgAes256GcmIv12Tag16);

        // Authenticated, not encrypted; bound to the message, reproduced on decrypt.
        std::map<std::string, std::string> encryption_context = {
            {"purpose", "streaming-chunks-example"},
            {"is not", "secret"},
        };

        Aws::Esdk::EncryptionSDK esdk;

        std::string message = "the quick brown fox jumps over the lazy dog, ";
        for (int i = 0; i < 6; ++i) message += message;  // ~2.8 KiB, spans frames
        const std::vector<std::uint8_t> plaintext(message.begin(), message.end());

        // --- Encrypt: poll the source, feed each chunk, ship ciphertext onward.
        std::vector<std::uint8_t> ciphertext;  // stands in for the downstream sink
        {
            auto enc = esdk.create_encrypt_stream(
                keyring, Aws::Esdk::EncryptOptions()
                             .with_algorithm_suite(
                                 Aws::Esdk::AlgorithmSuiteId::AlgAes256GcmHkdfSha512CommitKey)
                             .with_encryption_context(encryption_context));

            ChunkSource source(plaintext, 512);
            while (!source.drained()) {
                // write() returns the ciphertext produced so far, possibly empty
                // until a frame fills. In a real app you would ship it here.
                append(ciphertext, enc.write(source.next()));
            }
            // finish() flushes the last frame (and signature footer, for signing suites).
            append(ciphertext, enc.finish().trailing_output);
        }

        // --- Decrypt: hold released plaintext until finish() authenticates it.
        std::vector<std::uint8_t> plaintext_out;
        {
            auto dec = esdk.create_decrypt_stream(
                keyring,
                Aws::Esdk::DecryptOptions().with_encryption_context(encryption_context));

            // write() releases plaintext as frames verify, but the MESSAGE is not
            // authenticated until finish() returns. Buffer here and do not act on,
            // persist, or forward these bytes yet -- if finish() throws, drop them.
            std::vector<std::uint8_t> unverified;
            ChunkSource source(ciphertext, 1024);
            while (!source.drained()) {
                append(unverified, dec.write(source.next()));
            }
            append(unverified, dec.finish().trailing_output);

            // finish() returned: every byte is now authenticated and safe to use.
            plaintext_out = std::move(unverified);
        }

        if (plaintext_out != plaintext) {
            std::cerr << "Decryption failed: recovered bytes differ from plaintext\n";
            return 1;
        }

        std::cout << "Success! Chunked encryption and decryption completed successfully.\n";

    } catch (const std::exception& e) {
        std::cerr << "Error: " << e.what() << "\n";
        return 1;
    }

    return 0;
}
