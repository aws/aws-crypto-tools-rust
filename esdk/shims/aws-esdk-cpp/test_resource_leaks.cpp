// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

// Repeated encrypt/decrypt round trips must not grow the process's resident
// memory, measured through /proc/self/statm (Linux only).
//
// Local because live-memory growth is in-process and never appears on the wire.

#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <optional>
#include <vector>

#include <unistd.h>

#include "esdk_test_support.h"

namespace {

constexpr int WARMUP_ITERS = 50;
constexpr int MEASURED_ITERS = 500;
constexpr std::size_t PAYLOAD_BYTES = 64 * 1024;
// A per-iteration leak of the plaintext buffer would add MEASURED_ITERS * 64 KiB
// (~31 MiB), several times this bound; benign allocator drift after warmup stays
// well under it.
constexpr long MAX_GROWTH_BYTES = 12L * 1024 * 1024;

// Resident set size in bytes from /proc/self/statm, or 0 when it cannot be read
// (non-Linux, or /proc not mounted) so the caller can skip.
long read_rss_bytes() {
    std::FILE* statm = std::fopen("/proc/self/statm", "r");
    if (!statm) {
        return 0;
    }
    long resident_pages = 0;
    int fields = std::fscanf(statm, "%*d %ld", &resident_pages);
    std::fclose(statm);
    if (fields != 1) {
        return 0;
    }
    return resident_pages * sysconf(_SC_PAGESIZE);
}

// One encrypt/decrypt round trip; returns whether the plaintext survived.
bool round_trip(Aws::Esdk::EncryptionSDK& sdk,
                const Aws::Esdk::HierarchicalKeyring& keyring,
                const std::vector<std::uint8_t>& plaintext) {
    auto encrypted = sdk.encrypt(plaintext, keyring);
    auto decrypted = sdk.decrypt(encrypted.ciphertext, keyring);
    return decrypted.plaintext == plaintext;
}

}  // namespace

int main() {
    auto cfg = esdk_test::load_test_config();
    if (!cfg) {
        std::cout << "SKIP: set ESDK_TEST_KMS_KEY_ARN, ESDK_TEST_DDB_TABLE, "
                     "ESDK_TEST_LOGICAL_KEYSTORE, and ESDK_TEST_BRANCH_KEY_ID to "
                     "run the C++ resource-leak test.\n";
        return 0;
    }
    if (read_rss_bytes() == 0) {
        std::cout << "SKIP: /proc/self/statm is unavailable; the resource-leak "
                     "test needs it to measure resident memory.\n";
        return 0;
    }

    Aws::Esdk::EncryptionSDK sdk;
    try {
        auto keyring = esdk_test::make_keyring(*cfg);
        std::vector<std::uint8_t> plaintext(PAYLOAD_BYTES, 0xA5);

        bool all_round_trips_ok = true;
        // Warm up so one-time allocations (keyring cache, connection pools) are
        // counted before the baseline.
        for (int i = 0; i < WARMUP_ITERS; ++i) {
            all_round_trips_ok &= round_trip(sdk, keyring, plaintext);
        }
        long baseline = read_rss_bytes();
        if (baseline == 0) {
            std::cout << "SKIP: /proc/self/statm became unavailable during the resource-leak test.\n";
            return 0;
        }

        for (int i = 0; i < MEASURED_ITERS; ++i) {
            all_round_trips_ok &= round_trip(sdk, keyring, plaintext);
        }
        long after = read_rss_bytes();
        if (after == 0) {
            std::cout << "SKIP: /proc/self/statm became unavailable during the resource-leak test.\n";
            return 0;
        }
        ESDK_CHECK(all_round_trips_ok);

        long growth = after - baseline;
        if (growth >= MAX_GROWTH_BYTES) {
            std::cerr << "resident memory grew by " << growth << " bytes over "
                      << MEASURED_ITERS << " round trips (limit " << MAX_GROWTH_BYTES
                      << ")\n";
        }
        ESDK_CHECK(growth < MAX_GROWTH_BYTES);
    } catch (const std::exception& e) {
        std::cerr << "FATAL: unexpected exception aborted the suite: " << e.what() << "\n";
        return 2;
    }

    return esdk_test::report("test_resource_leaks");
}
