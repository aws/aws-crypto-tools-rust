// Encrypt a buffer to a file (and decrypt it back) without copying.
//
// The ESDK's encrypt/decrypt methods accept their input payloads (plaintext/ciphertext, respectively)
//  as either an std::vector or a pointer.
// They return their output payloads as Aws::Esdk::Bytes.
//
// Why not std::vector everywhere, like a normal C++ API?
// Because this is a shim for the underlying Rust library.
// The alternative types provide options for improved performance.
// Every conversion to or from std::vector is a full copy of your
// payload, and these alternative types can skip those copies entirely.
//
// On input: your data usually isn't in a vector. 
// It's in a file, or you're reading it from a socket.
// A vector-only API would force you to copy it into a vector first.
// The pointer overload borrows your buffer where it is instead, saving you copy cost.
//
// On output: the ESDK produces ciphertext in a buffer owned by its Rust core.
// That buffer cannot become a std::vector without copying every byte.
// Usually, it doesn't need to. 
// Output sinks (fwrite, sockets, etc.) can read from Aws::Esdk::Bytes directly
// without needing to pay for a copy to std::vector.
// You only need to copy the output to an to std::vector
// if you must modify the bytes or feed an API that insists on owning a vector.
//
// This example demonstrates running the same job (encrypt 32 MiB, write it to a file, read it back, decrypt)
// first using std::vectors and then using the alternative types.
//
// Run: `make zero_copy_example && ./zero_copy_comparison`.

#include <aws/esdk/EncryptionSDK.h>

#include <sys/mman.h>

#include <algorithm>
#include <chrono>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <iostream>
#include <memory>
#include <vector>

using namespace Aws::Esdk;
using Clock = std::chrono::steady_clock;

namespace {

constexpr std::size_t PAYLOAD_BYTES = 32u * 1024 * 1024;  // 32 MiB
constexpr int ITERATIONS = 5;  // averaged, interleaved: file I/O timing is noisy
const char* CIPHERTEXT_FILE = "zero_copy_example_ciphertext.bin";

double ms_since(Clock::time_point start) {
    return std::chrono::duration<double, std::milli>(Clock::now() - start).count();
}

// Your application's data, in its own buffer — NOT a std::vector. Stands in
// for an arena allocation, an mmap'd input, or another library's buffer.
std::unique_ptr<std::uint8_t[]> make_payload() {
    auto buf = std::make_unique<std::uint8_t[]>(PAYLOAD_BYTES);
    for (std::size_t i = 0; i < PAYLOAD_BYTES; ++i) {
        buf[i] = static_cast<std::uint8_t>(i * 31 + 7);
    }
    return buf;
}

void write_file(const char* path, const std::uint8_t* data, std::size_t size) {
    std::FILE* f = std::fopen(path, "wb");
    if (!f || std::fwrite(data, 1, size, f) != size) {
        std::perror("write failed");
        std::exit(1);
    }
    std::fclose(f);
}

}  // namespace

int main() {
    RawAesKeyring keyring("example-ns", "example-key",
                          std::vector<std::uint8_t>(32, 0x42),
                          AesWrappingAlgorithm::AlgAes256GcmIv12Tag16);
    EncryptionSDK sdk;

    auto payload = make_payload();
    const std::uint8_t* data = payload.get();

    // Warm up one-time initialization (runtime, keyring) outside the timings.
    (void)sdk.encrypt(data, 16, keyring);

    // Best-of-N timing: disk-write noise can exceed the copy savings, so the
    // reliable claim is the copies themselves, not the milliseconds.
    double slow_ms = 1e300;
    double fast_ms = 1e300;
    for (int i = 0; i < ITERATIONS; ++i) {
        // ---- SLOW: encrypt your buffer to a file, copying at each hand-off --
        auto slow_start = Clock::now();
        {
            // Copy #1: your data into the container you assume the API wants.
            std::vector<std::uint8_t> plaintext_copy(data, data + PAYLOAD_BYTES);
            auto encrypted = sdk.encrypt(plaintext_copy, keyring);

            // Copy #2: the ciphertext out of the result, just to write it.
            std::vector<std::uint8_t> ciphertext_copy = encrypted.ciphertext.to_vector();
            write_file(CIPHERTEXT_FILE, ciphertext_copy.data(), ciphertext_copy.size());
        }
        slow_ms = std::min(slow_ms, ms_since(slow_start));

        // ---- FAST: same task, zero copies ----------------------------------
        auto fast_start = Clock::now();
        {
            // encrypt borrows your buffer; fwrite reads the result in place.
            // Any (pointer, length) sink works the same way: POSIX write,
            // sockets, AWS SDK request bodies.
            auto encrypted = sdk.encrypt(data, PAYLOAD_BYTES, keyring);
            write_file(CIPHERTEXT_FILE, encrypted.ciphertext.data(),
                       encrypted.ciphertext.size());
        }
        fast_ms = std::min(fast_ms, ms_since(fast_start));
    }

    // ---- Read it back: mmap the file, decrypt it in place -----------------
    std::FILE* f = std::fopen(CIPHERTEXT_FILE, "rb");
    std::fseek(f, 0, SEEK_END);
    const std::size_t file_size = static_cast<std::size_t>(std::ftell(f));
    void* mapped = mmap(nullptr, file_size, PROT_READ, MAP_PRIVATE, fileno(f), 0);
    std::fclose(f);
    if (mapped == MAP_FAILED) {
        std::perror("mmap failed");
        return 1;
    }

    auto decrypted =
        sdk.decrypt(static_cast<const std::uint8_t*>(mapped), file_size, keyring);
    munmap(mapped, file_size);

    // Consume the plaintext through Bytes directly; no to_vector() needed.
    if (decrypted.plaintext.size() != PAYLOAD_BYTES ||
        std::memcmp(decrypted.plaintext.data(), data, PAYLOAD_BYTES) != 0) {
        std::cerr << "round trip failed!\n";
        return 1;
    }

    std::remove(CIPHERTEXT_FILE);

    std::cout << "encrypt " << (PAYLOAD_BYTES >> 20)
              << " MiB and write it to a file (best of " << ITERATIONS << " runs):\n"
              << "  slow: " << slow_ms << " ms — copies 2 x "
              << (PAYLOAD_BYTES >> 20) << " MiB per call\n"
              << "  fast: " << fast_ms << " ms — copies nothing\n"
              << "Round trip verified: file decrypted in place via mmap.\n";
    return 0;
}
