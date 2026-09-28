// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

// Shared setup for tests.
//
// These tests use the HKeyring, so they need live AWS resources.
// A missing variable is a hard failure (see integration_config_or_gate).
// To skip credentialed tests, supply the --local-only flag.
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

// Return std::nullopt when a required variable is unset
// If callers receive std::nullopt, they should fail
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

// Check invocation args for presence of `flag`
inline bool has_flag(int argc, char** argv, const char* flag) {
    for (int i = 1; i < argc; ++i) {
        if (std::string(argv[i]) == flag) {
            return true;
        }
    }
    return false;
}

inline bool has_local_only_flag(int argc, char** argv) {
    return has_flag(argc, argv, "--local-only");
}

// Gate for the credentialed integration tests.
// Skip these tests by passing --local-only flag.
// If an ESDK_TEST_* variable is missing, fail.
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

inline Aws::Esdk::HierarchicalKeyring make_hierarchical_keyring(const TestConfig& cfg) {
    auto client_config = Aws::Esdk::ClientConfig().with_max_retry_attempts(3);
    if (!cfg.region.empty()) {
        client_config.with_region(cfg.region);
    }
    Aws::Esdk::KmsClient kms(client_config);
    Aws::Esdk::DdbClient ddb(client_config);
    Aws::Esdk::KeyStore keystore(cfg.ddb_table, cfg.logical_keystore, cfg.kms_key_arn,
                                 Aws::Esdk::KeyStoreOptions()
                                     .with_kms_client(kms)
                                     .with_ddb_client(ddb));
    return Aws::Esdk::HierarchicalKeyring(
        std::move(keystore), cfg.branch_key_id, /*ttl_seconds=*/600,
        Aws::Esdk::HierarchicalKeyringOptions().with_cache(
            Aws::Esdk::CacheType::StormTracking(
                /*entry_capacity=*/ 100,
                /*entry_pruning_tail_size=*/ 1,
                /*grace_period=*/ 10,
                /*grace_interval=*/ 1,
                /*fan_out=*/ 20,
                /*inflight_ttl=*/ 10,
                /*sleep_milli=*/ 20)));
}

inline std::vector<std::uint8_t> to_bytes(const std::string& s) {
    return std::vector<std::uint8_t>(s.begin(), s.end());
}

}  // namespace esdk_test
