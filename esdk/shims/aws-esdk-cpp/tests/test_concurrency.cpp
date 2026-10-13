// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

// Test that message IDs stay unique under concurrent encrypts.
// Message ID assertions are important because a repeat would reuse the derived data key and frame IVs, breaking AES-GCM.
// This also tests using ESDK resources (keyrings, etc.) under concurrent load.

#include <cstddef>
#include <cstdint>
#include <mutex>
#include <optional>
#include <set>
#include <string>
#include <thread>
#include <vector>

#include "esdk_test_support.h"

namespace {

constexpr std::size_t THREADS = 8;
constexpr std::size_t ITERS_PER_THREAD = 24;

// V2 header: version (1) + algorithm suite id (2) + message id (32).
std::vector<std::uint8_t> v2_message_id(const Aws::Esdk::Bytes& ct) {
    if (ct.size() < 35 || ct[0] != 0x02) {
        return {};
    }
    return std::vector<std::uint8_t>(ct.begin() + 3, ct.begin() + 35);
}

// V1 header: version (1) + type (1) + algorithm suite id (2) + message id (16).
std::vector<std::uint8_t> v1_message_id(const Aws::Esdk::Bytes& ct) {
    if (ct.size() < 20 || ct[0] != 0x01) {
        return {};
    }
    return std::vector<std::uint8_t>(ct.begin() + 4, ct.begin() + 20);
}

using ExtractId = std::vector<std::uint8_t> (*)(const Aws::Esdk::Bytes&);

struct Collected {
    std::vector<std::vector<std::uint8_t>> message_ids;
    std::vector<std::string> errors;
};

Collected concurrent_round_trips(const Aws::Esdk::Keyring& keyring,
                                 std::optional<Aws::Esdk::AlgorithmSuiteId> suite,
                                 Aws::Esdk::CommitmentPolicy policy,
                                 ExtractId extract_id) {
    // One client shared by every thread.
    Aws::Esdk::EncryptionSDK sdk(Aws::Esdk::EncryptionSDKConfig().with_commitment_policy(policy));
    Collected collected;
    std::mutex mu;
    std::vector<std::thread> threads;
    threads.reserve(THREADS);

    for (std::size_t t = 0; t < THREADS; ++t) {
        threads.emplace_back([&, t] {
            try {
                for (std::size_t i = 0; i < ITERS_PER_THREAD; ++i) {
                    auto plaintext = esdk_test::to_bytes(
                        "thread " + std::to_string(t) + " message " + std::to_string(i));

                    Aws::Esdk::EncryptOptions enc_options;
                    if (suite) {
                        enc_options.with_algorithm_suite(*suite);
                    }
                    auto encrypted = sdk.encrypt(plaintext, keyring, enc_options);

                    auto decrypted = sdk.decrypt(encrypted.ciphertext, keyring);

                    std::lock_guard<std::mutex> lock(mu);
                    collected.message_ids.push_back(extract_id(encrypted.ciphertext));
                    if (decrypted.plaintext != plaintext) {
                        collected.errors.push_back("round trip did not return the plaintext");
                    }
                }
            } catch (const std::exception& e) {
                std::lock_guard<std::mutex> lock(mu);
                collected.errors.push_back(std::string("worker threw: ") + e.what());
            }
        });
    }
    for (auto& thread : threads) {
        thread.join();
    }
    return collected;
}

void run_case(const char* label,
              const Aws::Esdk::Keyring& keyring,
              std::optional<Aws::Esdk::AlgorithmSuiteId> suite,
              Aws::Esdk::CommitmentPolicy policy, ExtractId extract_id,
              std::size_t id_len) {
    auto collected = concurrent_round_trips(keyring, suite, policy, extract_id);

    for (const auto& error : collected.errors) {
        std::cerr << label << ": " << error << "\n";
    }
    ESDK_CHECK(collected.errors.empty());
    ESDK_CHECK(collected.message_ids.size() == THREADS * ITERS_PER_THREAD);

    bool all_expected_length = true;
    for (const auto& id : collected.message_ids) {
        if (id.size() != id_len) {
            all_expected_length = false;
        }
    }
    ESDK_CHECK(all_expected_length);

    std::set<std::vector<std::uint8_t>> unique(collected.message_ids.begin(),
                                               collected.message_ids.end());
    ESDK_CHECK(unique.size() == collected.message_ids.size());
}

}  // namespace

int main(int argc, char** argv) {
    // Always run offline tests
    {
        std::vector<std::uint8_t> key(32, 0x2A);
        Aws::Esdk::RawAesKeyring keyring("test-ns", "test-key", key,
                                         Aws::Esdk::AesWrappingAlgorithm::AlgAes256GcmIv12Tag16);
        try {
            //= spec/shim/shim.md#concurrency
            //= type=test
            //# If a core library resource or operation supports concurrent use from multiple threads,
            //# the shim library SHOULD support it as well.
            run_case("raw-aes v2", keyring, std::nullopt,
                     Aws::Esdk::CommitmentPolicy::RequireEncryptRequireDecrypt,
                     v2_message_id, 32);
            run_case("raw-aes v1", keyring,
                     Aws::Esdk::AlgorithmSuiteId::AlgAes256GcmIv12Tag16HkdfSha256,
                     Aws::Esdk::CommitmentPolicy::ForbidEncryptAllowDecrypt,
                     v1_message_id, 16);
        } catch (const std::exception& e) {
            std::cerr << "FATAL: unexpected exception aborted the suite: " << e.what() << "\n";
            return 2;
        }
    }

    // If configured to do integ tests, also test HKeyring
    auto cfg = esdk_test::integration_config_or_gate(argc, argv, "test_concurrency");
    if (!cfg) {
        return esdk_test::report("test_concurrency");
    }

    try {
        auto keyring = esdk_test::make_hierarchical_keyring(*cfg);

        run_case("v2", keyring, std::nullopt,
                 Aws::Esdk::CommitmentPolicy::RequireEncryptRequireDecrypt,
                 v2_message_id, 32);

        run_case("v1", keyring,
                 Aws::Esdk::AlgorithmSuiteId::AlgAes256GcmIv12Tag16HkdfSha256,
                 Aws::Esdk::CommitmentPolicy::ForbidEncryptAllowDecrypt,
                 v1_message_id, 16);
    } catch (const std::exception& e) {
        std::cerr << "FATAL: unexpected exception aborted the suite: " << e.what() << "\n";
        return 2;
    }

    return esdk_test::report("test_concurrency");
}
