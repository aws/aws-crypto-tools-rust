// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

// Shared setup for test_concurrency.cpp and test_resource_leaks.cpp.
//
// These tests use the hierarchical keyring, so they need live AWS resources.
// Provide them through the same environment variables test_esdk.cpp uses.
// When any required var is unset, the test is skipped so as to not fail a cred-less CI.
// The CI test targets (make test-ci-*) refuse to run when the variables are unset.
//
//   ESDK_TEST_KMS_KEY_ARN       KMS key ARN backing the key store
//   ESDK_TEST_DDB_TABLE         DynamoDB table name of the key store
//   ESDK_TEST_LOGICAL_KEYSTORE  logical key store name
//   ESDK_TEST_BRANCH_KEY_ID     branch key id provisioned in the key store
//   ESDK_TEST_REGION            (optional) AWS region
#pragma once

#include <cstdint>
#include <cstdlib>
#include <iostream>
#include <optional>
#include <string>
#include <vector>

#include <aws/esdk/EncryptionSDK.h>

namespace esdk_test {

// Assertion harness; call only from the main thread.
inline int g_checks = 0;
inline int g_failures = 0;

// Assert helper -- pass iff cond is true
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

// Return std::nullopt if a required variable is unset so the caller can skip
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

inline bool has_local_only_flag(int argc, char** argv) {
    for (int i = 1; i < argc; ++i) {
        if (std::string(argv[i]) == "--local-only") {
            return true;
        }
    }
    return false;
}

// Gate for the credentialed integration tests. Skipping requires the explicit
// --local-only flag; a missing ESDK_TEST_* variable is a hard failure, never a
// silent skip, so a dropped CI credential cannot turn into a green build.
inline std::optional<TestConfig> integration_config_or_gate(int argc, char** argv,
                                                            const char* suite) {
    if (has_local_only_flag(argc, argv)) {
        std::cout << suite << ": --local-only, skipping integration tests\n";
        return std::nullopt;
    }
    auto cfg = load_test_config();
    if (!cfg) {
        std::cerr << "FATAL: " << suite
                  << " integration tests require ESDK_TEST_KMS_KEY_ARN, "
                     "ESDK_TEST_DDB_TABLE, ESDK_TEST_LOGICAL_KEYSTORE, and "
                     "ESDK_TEST_BRANCH_KEY_ID. Pass --local-only to run only the "
                     "offline tests.\n";
        std::exit(2);
    }
    return cfg;
}

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
        Aws::Esdk::HierarchicalKeyringOptions().with_cache(
            Aws::Esdk::CacheType::MultiThreaded(100)));
}

inline std::vector<std::uint8_t> to_bytes(const std::string& s) {
    return std::vector<std::uint8_t>(s.begin(), s.end());
}

}  // namespace esdk_test
