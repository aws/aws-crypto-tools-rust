// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

// Test that message IDs stay unique under concurrent encrypts.
// This is important because a repeat would reuse the derived data key and frame IVs, breaking AES-GCM.

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

Collected concurrent_round_trips(Aws::Esdk::EncryptionSDK& sdk,
                                 const Aws::Esdk::HierarchicalKeyring& keyring,
                                 std::optional<Aws::Esdk::AlgorithmSuiteId> suite,
                                 Aws::Esdk::CommitmentPolicy policy,
                                 ExtractId extract_id) {
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
                    enc_options.with_commitment_policy(policy);
                    if (suite) {
                        enc_options.with_algorithm_suite(*suite);
                    }
                    auto encrypted = sdk.encrypt(plaintext, keyring, enc_options);

                    Aws::Esdk::DecryptOptions dec_options;
                    dec_options.with_commitment_policy(policy);
                    auto decrypted = sdk.decrypt(encrypted.ciphertext, keyring, dec_options);

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

void run_case(const char* label, Aws::Esdk::EncryptionSDK& sdk,
              const Aws::Esdk::HierarchicalKeyring& keyring,
              std::optional<Aws::Esdk::AlgorithmSuiteId> suite,
              Aws::Esdk::CommitmentPolicy policy, ExtractId extract_id,
              std::size_t id_len) {
    auto collected = concurrent_round_trips(sdk, keyring, suite, policy, extract_id);

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

int main() {
    auto cfg = esdk_test::load_test_config();
    if (!cfg) {
        return esdk_test::skip_or_fail_without_creds("the C++ concurrency test");
    }

    Aws::Esdk::EncryptionSDK sdk;
    try {
        auto keyring = esdk_test::make_keyring(*cfg);

        run_case("v2", sdk, keyring, std::nullopt,
                 Aws::Esdk::CommitmentPolicy::RequireEncryptRequireDecrypt,
                 v2_message_id, 32);

        run_case("v1", sdk, keyring,
                 Aws::Esdk::AlgorithmSuiteId::AlgAes256GcmIv12Tag16HkdfSha256,
                 Aws::Esdk::CommitmentPolicy::ForbidEncryptAllowDecrypt,
                 v1_message_id, 16);
    } catch (const std::exception& e) {
        std::cerr << "FATAL: unexpected exception aborted the suite: " << e.what() << "\n";
        return 2;
    }

    return esdk_test::report("test_concurrency");
}
