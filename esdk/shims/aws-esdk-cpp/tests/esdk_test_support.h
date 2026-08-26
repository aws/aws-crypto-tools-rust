// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

// Shared setup for the offline tests.
//
// Every test in this suite runs fully offline: it uses only the raw AES keyring
// and the one-shot encrypt/decrypt operations, so it needs no AWS credentials,
// no environment variables, and no flags.
#pragma once

#include <cstdint>
#include <iostream>
#include <string>
#include <vector>

#include <aws/esdk/EncryptionSDK.h>

namespace esdk_test {

// Assertion harness; call only from the main thread.
inline int g_checks = 0;
inline int g_failures = 0;

// Assert helper -- return 0 iff `cond` is true, else error
#define ESDK_CHECK(cond)                                                       \
    do {                                                                       \
        ++::esdk_test::g_checks;                                               \
        if (!(cond)) {                                                         \
            ++::esdk_test::g_failures;                                         \
            std::cerr << "FAIL: " << #cond << " (" << __FILE__ << ":"          \
                      << __LINE__ << ")\n";                                    \
        }                                                                      \
    } while (0)

// Print the tally and return a process exit code.
// 0 --> all checks passed; 1 --> tests failed.
inline int report(const char* suite) {
    std::cout << suite << ": " << (g_checks - g_failures) << "/" << g_checks
              << " checks passed\n";
    if (g_failures > 0) {
        std::cerr << g_failures << " check(s) FAILED\n";
        return 1;
    }
    return 0;
}

inline std::vector<std::uint8_t> to_bytes(const std::string& s) {
    return std::vector<std::uint8_t>(s.begin(), s.end());
}

}  // namespace esdk_test
