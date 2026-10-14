// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

// Repeated round trips must not grow resident memory proportionally to the number of round trips.
// If it does, this indicates a memory leak.
// Only runs on Linux due to checking /proc/self/statm for memory stats

#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <optional>
#include <vector>

#include <unistd.h>

#include "esdk_test_support.h"

namespace {

constexpr int WARMUP_ITERS = 5;
constexpr int MEASURED_ITERS = 500;
constexpr std::size_t PAYLOAD_BYTES = 64 * 1024;  // 64 kB
// Fail if memory grows by more than a constant multiple of the payload bytes
// If memory use scales with number of iterations, this indicates a resource leak
constexpr long MAX_GROWTH_BYTES = PAYLOAD_BYTES * 10;

long read_rss_bytes() {
    // This read is only valid on Linux, so this test can only run on Linux right now
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

bool round_trip(Aws::Esdk::Client& sdk,
                const Aws::Esdk::HierarchicalKeyring& keyring,
                const std::vector<std::uint8_t>& plaintext) {
    auto encrypted = sdk.encrypt(plaintext, keyring);
    auto decrypted = sdk.decrypt(encrypted.ciphertext, keyring);
    return decrypted.plaintext == plaintext;
}

}  // namespace

int main(int argc, char** argv) {
    auto cfg = esdk_test::integration_config_or_gate(argc, argv, "test_resource_leaks");
    if (!cfg) {
        // --local-only: this suite has no offline cases, so there is nothing to run.
        return 0;
    }
    if (read_rss_bytes() == 0) {
        // /proc/self/statm is only valid on Linux, so this test can only run on Linux right now
        if (esdk_test::has_flag(argc, argv, "--non-linux")) {
            std::cout << "test_resource_leaks: --non-linux, skipping the "
                         "resident-memory leak check (needs /proc/self/statm)\n";
            return 0;
        }
        std::cerr << "FATAL: /proc/self/statm is unavailable, so resident memory "
                     "cannot be measured (this suite runs on Linux only). Pass "
                     "--non-linux to skip the leak check on this platform.\n";
        return 2;
    }

    Aws::Esdk::Client sdk;
    try {
        auto keyring = esdk_test::make_hierarchical_keyring(*cfg);
        std::vector<std::uint8_t> plaintext(PAYLOAD_BYTES, 0xA5);

        bool all_round_trips_ok = true;
        // One-time allocations (keyring cache, connection pools) land before the baseline.
        for (int i = 0; i < WARMUP_ITERS; ++i) {
            all_round_trips_ok &= round_trip(sdk, keyring, plaintext);
        }
        long baseline = read_rss_bytes();
        if (baseline == 0) {
            std::cerr << "FATAL: /proc/self/statm became unavailable mid-test; "
                         "resident memory can no longer be measured.\n";
            return 2;
        }

        for (int i = 0; i < MEASURED_ITERS; ++i) {
            all_round_trips_ok &= round_trip(sdk, keyring, plaintext);
        }
        long after = read_rss_bytes();
        if (after == 0) {
            std::cerr << "FATAL: /proc/self/statm became unavailable mid-test; "
                         "resident memory can no longer be measured.\n";
            return 2;
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
