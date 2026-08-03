// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

// Encrypt/decrypt round trips run concurrently across threads, sharing one
// keyring and one SDK facade.
//
// Why assert message ID uniqueness? Two messages with the same message ID get
// the same data key and the same frame IVs. Repeating an AES-GCM key+IV pair
// breaks the cipher: plaintext can be recovered and messages forged. So the
// test asserts message IDs stay unique even when many threads encrypt at once.
//
// Local because it drives the shim from real OS threads through the shared Tokio
// runtime inside the bindings.

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

// Everything the worker threads produce.
struct Collected {
    std::vector<std::vector<std::uint8_t>> message_ids;
    std::vector<std::string> errors;
};

// Run THREADS threads, each doing ITERS_PER_THREAD encrypt + decrypt round trips
// through the shared sdk and keyring. Returns every message ID produced.
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

// One case: run the concurrent round trips, then check that they all succeeded
// and that every message ID is present, the expected length, and unique.
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
        std::cout << "SKIP: set ESDK_TEST_KMS_KEY_ARN, ESDK_TEST_DDB_TABLE, "
                     "ESDK_TEST_LOGICAL_KEYSTORE, and ESDK_TEST_BRANCH_KEY_ID to "
                     "run the C++ concurrency test.\n";
        return 0;
    }

    Aws::Esdk::EncryptionSDK sdk;
    try {
        auto keyring = esdk_test::make_keyring(*cfg);

        // The default committing suite produces V2 messages (32-byte message id).
        run_case("v2", sdk, keyring, std::nullopt,
                 Aws::Esdk::CommitmentPolicy::RequireEncryptRequireDecrypt,
                 v2_message_id, 32);

        // A non-committing suite produces V1 messages (16-byte message id).
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
