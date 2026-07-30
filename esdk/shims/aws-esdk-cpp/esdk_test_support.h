// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

// Shared setup for the local-correctness tests (test_concurrency.cpp and
// test_resource_leaks.cpp).
//
// The hierarchical keyring is the only materials source the shim exposes, so
// these tests drive the real crypto path and need live AWS resources. Provide
// them through the same environment variables test_esdk.cpp uses; when any
// required var is unset, load_test_config() returns std::nullopt so the caller
// can print SKIP and exit 0 (it never fails credential-less CI):
//
//   ESDK_TEST_KMS_KEY_ARN       KMS key ARN backing the key store
//   ESDK_TEST_DDB_TABLE         DynamoDB table name of the key store
//   ESDK_TEST_LOGICAL_KEYSTORE  logical key store name
//   ESDK_TEST_BRANCH_KEY_ID     branch key id provisioned in the key store
//   ESDK_TEST_REGION            (optional) AWS region, e.g. us-west-2
#pragma once

#include <cstdint>
#include <cstdlib>
#include <iostream>
#include <optional>
#include <string>
#include <vector>

#include <aws/esdk/EncryptionSDK.h>

namespace esdk_test {

// Assertion harness. Call only from the main thread; worker threads report
// results back through their own synchronized state, not these counters.
inline int g_checks = 0;
inline int g_failures = 0;

#define ESDK_CHECK(cond)                                                       \
    do {                                                                       \
        ++::esdk_test::g_checks;                                               \
        if (!(cond)) {                                                         \
            ++::esdk_test::g_failures;                                         \
            std::cerr << "FAIL: " << #cond << " (" << __FILE__ << ":"          \
                      << __LINE__ << ")\n";                                    \
        }                                                                      \
    } while (0)

// Print the tally and return a process exit code (0 = all checks passed).
inline int report(const char* suite) {
    std::cout << suite << ": " << (g_checks - g_failures) << "/" << g_checks
              << " checks passed\n";
    if (g_failures > 0) {
        std::cerr << g_failures << " check(s) FAILED\n";
        return 1;
    }
    return 0;
}

struct TestConfig {
    std::string kms_key_arn;
    std::string ddb_table;
    std::string logical_keystore;
    std::string branch_key_id;
    std::string region;
};

inline const char* env_or_null(const char* name) {
    const char* value = std::getenv(name);
    return (value && *value) ? value : nullptr;
}

// std::nullopt when a required variable is unset, so the caller can SKIP.
inline std::optional<TestConfig> load_test_config() {
    const char* kms = env_or_null("ESDK_TEST_KMS_KEY_ARN");
    const char* ddb = env_or_null("ESDK_TEST_DDB_TABLE");
    const char* logical = env_or_null("ESDK_TEST_LOGICAL_KEYSTORE");
    const char* branch = env_or_null("ESDK_TEST_BRANCH_KEY_ID");
    const char* region = env_or_null("ESDK_TEST_REGION");
    if (!kms || !ddb || !logical || !branch) {
        return std::nullopt;
    }
    return TestConfig{kms, ddb, logical, branch, region ? region : ""};
}

// A hierarchical keyring built from the test config. The keyring's cache
// defaults to the multi-threaded cache, so one instance is shared across
// threads by the concurrency test.
inline Aws::Esdk::HierarchicalKeyring make_keyring(const TestConfig& cfg) {
    auto client_config = Aws::Esdk::ClientConfig().with_max_retry_attempts(3);
    if (!cfg.region.empty()) {
        client_config.with_region(cfg.region);
    }
    Aws::Esdk::KmsClient kms(client_config);
    Aws::Esdk::DdbClient ddb(client_config);
    Aws::Esdk::KeyStore keystore(cfg.ddb_table, cfg.logical_keystore,
                                 cfg.kms_key_arn, kms, ddb);
    return Aws::Esdk::HierarchicalKeyring(
        std::move(keystore), cfg.branch_key_id, /*ttl_seconds=*/600,
        Aws::Esdk::HierarchicalKeyringOptions().with_cache_capacity(100));
}

inline std::vector<std::uint8_t> to_bytes(const std::string& s) {
    return std::vector<std::uint8_t>(s.begin(), s.end());
}

}  // namespace esdk_test
