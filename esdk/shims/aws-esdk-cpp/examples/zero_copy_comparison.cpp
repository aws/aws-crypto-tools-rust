// zero_copy_comparison.cpp — why the pointer+length overloads and the Bytes
// output type exist.
//
// Scenario: your plaintext does not live in a std::vector. In real programs it
// rarely does — it's an mmap'd file, a protobuf arena, a network buffer, a
// std::string. And after encrypting, you usually just write the ciphertext
// somewhere (socket, file, S3 SDK call) and never need to own it in a vector.
//
// SLOW path (what the API used to force):
//   1. Copy your buffer into a std::vector      <- copy #1, doubles peak memory
//   2. encrypt(vector)
//   3. result.ciphertext.to_vector()            <- copy #2, doubles it again
//
// FAST path (what the overloads enable):
//   1. encrypt(ptr, len)                        <- borrows your buffer in place
//   2. read result.ciphertext.data()/size()     <- reads Rust's buffer in place
//
// The crypto work is identical; the difference is pure memcpy + allocator
// traffic. Run it and compare:
//
//   c++ -std=c++17 -O2 -Iinclude examples/zero_copy_comparison.cpp \
//       target/release/libaws_esdk_cpp.a \
//       target/release/build/cxx-*/out/libcxxbridge1.a \
//       -framework Security -framework CoreFoundation \
//       -framework SystemConfiguration -o zero_copy_comparison   # macOS
//   ./zero_copy_comparison
//
// Uses a Raw AES keyring, so it runs offline with no AWS account.

#include <aws/esdk/EncryptionSDK.h>

#include <chrono>
#include <cstdint>
#include <cstring>
#include <iostream>
#include <memory>
#include <vector>

using namespace Aws::Esdk;
using Clock = std::chrono::steady_clock;

namespace {

constexpr std::size_t PAYLOAD_BYTES = 64u * 1024 * 1024;  // 64 MiB
constexpr int ITERATIONS = 5;

double ms_since(Clock::time_point start) {
    return std::chrono::duration<double, std::milli>(Clock::now() - start).count();
}

// A caller-owned buffer that is NOT a std::vector — stands in for an mmap'd
// file, an arena allocation, or a buffer handed to you by another library.
std::unique_ptr<std::uint8_t[]> make_payload() {
    auto buf = std::make_unique<std::uint8_t[]>(PAYLOAD_BYTES);
    for (std::size_t i = 0; i < PAYLOAD_BYTES; ++i) {
        buf[i] = static_cast<std::uint8_t>(i * 31 + 7);
    }
    return buf;
}

// Stand-in for "send the ciphertext somewhere": a sink that only needs to
// *read* the bytes (a socket write, fwrite, or an S3 PutObject body).
std::uint64_t sink(const std::uint8_t* data, std::size_t size) {
    std::uint64_t checksum = 0;
    for (std::size_t i = 0; i < size; i += 4096) {  // touch each page
        checksum += data[i];
    }
    return checksum;
}

}  // namespace

int main() {
    RawAesKeyring keyring("example-ns", "example-key",
                          std::vector<std::uint8_t>(32, 0x42),
                          AesWrappingAlgorithm::AlgAes256GcmIv12Tag16);
    EncryptionSDK sdk;

    auto payload = make_payload();
    const std::uint8_t* data = payload.get();

    std::cout << "payload: " << (PAYLOAD_BYTES >> 20) << " MiB, "
              << ITERATIONS << " iterations each\n\n";

    // Warm up (first call pays one-time init: tokio runtime, keyring setup).
    (void)sdk.encrypt(data, 16, keyring);

    // Correctness check (outside the timed loops): both input paths round-trip
    // back to the original payload. Note the two ciphertexts themselves always
    // differ — the ESDK generates a fresh data key and IV per message.
    {
        auto via_ptr = sdk.encrypt(data, PAYLOAD_BYTES, keyring);
        auto recovered = sdk.decrypt(via_ptr.ciphertext, keyring);
        if (recovered.plaintext.size() != PAYLOAD_BYTES ||
            std::memcmp(recovered.plaintext.data(), data, PAYLOAD_BYTES) != 0) {
            std::cerr << "round trip failed!\n";
            return 1;
        }
    }

    // Keeps the sink reads observable so the compiler cannot drop them.
    std::uint64_t observed = 0;

    // ------------------------- SLOW: copy at every boundary ----------------
    double slow_total = 0;
    for (int i = 0; i < ITERATIONS; ++i) {
        auto start = Clock::now();

        // Copy #1: the old vector-only API forced your buffer into a vector.
        std::vector<std::uint8_t> plaintext_copy(data, data + PAYLOAD_BYTES);
        auto encrypted = sdk.encrypt(plaintext_copy, keyring);

        // Copy #2: pulling the output into a vector instead of reading Bytes.
        std::vector<std::uint8_t> ciphertext_copy = encrypted.ciphertext.to_vector();
        observed += sink(ciphertext_copy.data(), ciphertext_copy.size());

        slow_total += ms_since(start);
    }

    // ------------------------- FAST: zero-copy at both boundaries ----------
    double fast_total = 0;
    for (int i = 0; i < ITERATIONS; ++i) {
        auto start = Clock::now();

        // No input copy: encrypt borrows the caller's buffer in place.
        auto encrypted = sdk.encrypt(data, PAYLOAD_BYTES, keyring);

        // No output copy: Bytes reads the core library's buffer in place.
        observed += sink(encrypted.ciphertext.data(), encrypted.ciphertext.size());

        fast_total += ms_since(start);
    }

    if (observed == 0) {
        std::cerr << "sink observed no data\n";
        return 1;
    }

    const double slow_avg = slow_total / ITERATIONS;
    const double fast_avg = fast_total / ITERATIONS;
    std::cout << "slow (copy in + copy out): " << slow_avg << " ms/iter\n"
              << "fast (zero-copy in/out):   " << fast_avg << " ms/iter\n"
              << "saved: " << (slow_avg - fast_avg) << " ms/iter ("
              << (100.0 * (slow_avg - fast_avg) / slow_avg) << "%)\n\n"
              << "The fast path also avoids two " << (PAYLOAD_BYTES >> 20)
              << " MiB allocations per call, halving peak memory per boundary.\n";
    return 0;
}
