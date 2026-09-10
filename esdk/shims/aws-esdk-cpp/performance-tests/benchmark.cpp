// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

// Performance benchmark for the C++ shim. Exercises encrypt/decrypt through
// Aws::Esdk::EncryptionSDK with a selectable keyring (--keyring hierarchical
// or raw-aes) and measures throughput, resident memory, and concurrent round
// trips. Results are written as JSON and, in CI, published to CloudWatch Logs
// under language "rust-cpp".

#include <algorithm>
#include <atomic>
#include <chrono>
#include <cstdint>
#include <cstring>
#include <exception>
#include <stdexcept>
#include <iostream>
#include <map>
#include <mutex>
#include <optional>
#include <random>
#include <string>
#include <thread>
#include <utility>
#include <vector>

#include "benchmark_support.h"

namespace {

using clock_type = std::chrono::steady_clock;
using esdk_bench::BenchmarkConfig;
using esdk_bench::BenchmarkResult;

double ms_since(clock_type::time_point start) {
    auto elapsed = clock_type::now() - start;
    return std::chrono::duration<double, std::milli>(elapsed).count();
}

std::vector<std::uint8_t> random_bytes(std::size_t n) {
    std::vector<std::uint8_t> data(n);
    std::mt19937_64 rng{std::random_device{}()};
    std::size_t i = 0;
    for (; i + sizeof(std::uint64_t) <= n; i += sizeof(std::uint64_t)) {
        std::uint64_t word = rng();
        std::memcpy(data.data() + i, &word, sizeof(word));
    }
    for (; i < n; ++i) {
        data[i] = static_cast<std::uint8_t>(rng());
    }
    return data;
}

// One encrypt+decrypt round trip; returns {encrypt_ms, decrypt_ms}. Throws on
// failure or a plaintext mismatch.
std::pair<double, double> encrypt_decrypt(
    Aws::Esdk::EncryptionSDK& sdk,
    const Aws::Esdk::Keyring& keyring,
    const std::vector<std::uint8_t>& data) {
    Aws::Esdk::EncryptOptions encrypt_options;
    encrypt_options.with_encryption_context(
        {{"purpose", "performance-test"}, {"size", std::to_string(data.size())}});

    auto encrypt_start = clock_type::now();
    auto encrypted = sdk.encrypt(data, keyring, encrypt_options);
    double encrypt_ms = ms_since(encrypt_start);

    auto decrypt_start = clock_type::now();
    auto decrypted = sdk.decrypt(encrypted.ciphertext, keyring);
    double decrypt_ms = ms_since(decrypt_start);

    if (decrypted.plaintext != data) {
        throw std::runtime_error("data integrity check failed");
    }
    return {encrypt_ms, decrypt_ms};
}

// Operations per second and latency percentiles over serial round trips.
BenchmarkResult run_throughput(Aws::Esdk::EncryptionSDK& sdk,
                               const Aws::Esdk::Keyring& keyring,
                               std::size_t data_size, int warmup,
                               int measurement) {
    auto data = random_bytes(data_size);

    // Warmup; for the hierarchical keyring this also primes the branch-key cache.
    for (int i = 0; i < warmup; ++i) {
        encrypt_decrypt(sdk, keyring, data);
    }

    std::vector<double> encrypt_latencies;
    std::vector<double> decrypt_latencies;
    std::vector<double> end_to_end_latencies;
    std::uint64_t total_bytes = 0;

    auto start = clock_type::now();
    for (int i = 0; i < measurement; ++i) {
        auto iteration_start = clock_type::now();
        auto latencies = encrypt_decrypt(sdk, keyring, data);
        double iteration_ms = ms_since(iteration_start);
        encrypt_latencies.push_back(latencies.first);
        decrypt_latencies.push_back(latencies.second);
        end_to_end_latencies.push_back(iteration_ms);
        total_bytes += data_size;
    }
    double total_seconds =
        std::chrono::duration<double>(clock_type::now() - start).count();

    std::sort(end_to_end_latencies.begin(), end_to_end_latencies.end());

    BenchmarkResult result;
    result.test_name = "throughput";
    result.data_size = data_size;
    result.concurrency = 1;
    result.encrypt_latency_ms = esdk_bench::average(encrypt_latencies);
    result.decrypt_latency_ms = esdk_bench::average(decrypt_latencies);
    result.end_to_end_latency_ms = esdk_bench::average(end_to_end_latencies);
    result.ops_per_second =
        total_seconds > 0.0 ? measurement / total_seconds : 0.0;
    result.bytes_per_second =
        total_seconds > 0.0 ? static_cast<double>(total_bytes) / total_seconds : 0.0;
    result.p50_latency = esdk_bench::percentile(end_to_end_latencies, 50.0);
    result.p95_latency = esdk_bench::percentile(end_to_end_latencies, 95.0);
    result.p99_latency = esdk_bench::percentile(end_to_end_latencies, 99.0);
    return result;
}

// Peak resident-memory delta and payload-bytes-per-byte efficiency during one
// operation, sampled from a background thread.
BenchmarkResult run_memory(Aws::Esdk::EncryptionSDK& sdk,
                           const Aws::Esdk::Keyring& keyring,
                           std::size_t data_size) {
    auto data = random_bytes(data_size);
    double peak_delta_mb = 0.0;

    for (int i = 0; i < esdk_bench::MEMORY_TEST_ITERATIONS; ++i) {
        double baseline_mb = esdk_bench::read_rss_bytes() / (1024.0 * 1024.0);
        double iteration_peak_mb = baseline_mb;

        std::atomic<bool> done{false};
        std::exception_ptr error;
        std::thread operation([&] {
            try {
                encrypt_decrypt(sdk, keyring, data);
            } catch (...) {
                error = std::current_exception();
            }
            done.store(true);
        });

        while (!done.load()) {
            double current_mb = esdk_bench::read_rss_bytes() / (1024.0 * 1024.0);
            if (current_mb > iteration_peak_mb) {
                iteration_peak_mb = current_mb;
            }
            std::this_thread::sleep_for(std::chrono::milliseconds(1));
        }
        operation.join();
        if (error) {
            std::rethrow_exception(error);
        }

        double after_mb = esdk_bench::read_rss_bytes() / (1024.0 * 1024.0);
        if (after_mb > iteration_peak_mb) {
            iteration_peak_mb = after_mb;
        }
        double delta_mb = iteration_peak_mb - baseline_mb;
        if (delta_mb > peak_delta_mb) {
            peak_delta_mb = delta_mb;
        }
    }

    BenchmarkResult result;
    result.test_name = "memory";
    result.data_size = data_size;
    result.concurrency = 1;
    result.peak_memory_mb = peak_delta_mb;
    result.memory_efficiency_ratio =
        peak_delta_mb > 0.0
            ? static_cast<double>(data_size) / (peak_delta_mb * 1024.0 * 1024.0)
            : 0.0;
    return result;
}

// Parallel throughput across workers sharing one keyring and SDK facade.
BenchmarkResult run_concurrent(Aws::Esdk::EncryptionSDK& sdk,
                               const Aws::Esdk::Keyring& keyring,
                               std::size_t data_size, int concurrency) {
    std::mutex mutex;
    std::vector<double> all_times;
    std::exception_ptr error;

    auto start = clock_type::now();
    std::vector<std::thread> workers;
    workers.reserve(concurrency);
    for (int w = 0; w < concurrency; ++w) {
        workers.emplace_back([&] {
            try {
                auto data = random_bytes(data_size);
                std::vector<double> times;
                for (int j = 0; j < esdk_bench::CONCURRENT_ITERS_PER_WORKER; ++j) {
                    auto iteration_start = clock_type::now();
                    encrypt_decrypt(sdk, keyring, data);
                    times.push_back(ms_since(iteration_start));
                }
                std::lock_guard<std::mutex> lock(mutex);
                all_times.insert(all_times.end(), times.begin(), times.end());
            } catch (...) {
                std::lock_guard<std::mutex> lock(mutex);
                if (!error) {
                    error = std::current_exception();
                }
            }
        });
    }
    for (auto& worker : workers) {
        worker.join();
    }
    double total_seconds =
        std::chrono::duration<double>(clock_type::now() - start).count();
    if (error) {
        std::rethrow_exception(error);
    }

    int total_ops = concurrency * esdk_bench::CONCURRENT_ITERS_PER_WORKER;
    std::uint64_t total_bytes =
        static_cast<std::uint64_t>(total_ops) * data_size;

    std::sort(all_times.begin(), all_times.end());

    BenchmarkResult result;
    result.test_name = "concurrent";
    result.data_size = data_size;
    result.concurrency = concurrency;
    result.end_to_end_latency_ms = esdk_bench::average(all_times);
    result.ops_per_second =
        total_seconds > 0.0 ? total_ops / total_seconds : 0.0;
    result.bytes_per_second =
        total_seconds > 0.0 ? static_cast<double>(total_bytes) / total_seconds : 0.0;
    result.p50_latency = esdk_bench::percentile(all_times, 50.0);
    result.p95_latency = esdk_bench::percentile(all_times, 95.0);
    result.p99_latency = esdk_bench::percentile(all_times, 99.0);
    return result;
}

// Constructs the keyring selected on the command line. The raw AES keyring
// wraps locally; the hierarchical keyring reads the key store described by env.
Aws::Esdk::Keyring make_benchmark_keyring(
    const std::string& keyring_name,
    const std::optional<esdk_bench::KeyStoreEnv>& env) {
    if (keyring_name == "raw-aes") {
        return esdk_bench::make_raw_aes_keyring();
    }
    return esdk_bench::make_hierarchical_keyring(*env);
}

}  // namespace

int main(int argc, char** argv) {
    std::string output = "results/raw-data/cpp_results.json";
    std::string keyring_name = "hierarchical";
    BenchmarkConfig config;
    bool quick = false;

    for (int i = 1; i < argc; ++i) {
        std::string arg = argv[i];
        if (arg == "--quick") {
            quick = true;
        } else if (arg == "--output" && i + 1 < argc) {
            output = argv[++i];
        } else if (arg == "--keyring" && i + 1 < argc) {
            keyring_name = argv[++i];
            if (keyring_name != "hierarchical" && keyring_name != "raw-aes") {
                std::cerr << "unknown keyring: " << keyring_name
                          << " (expected hierarchical or raw-aes)\n";
                return 2;
            }
        } else {
            std::cerr << "usage: " << argv[0]
                      << " [--quick] [--keyring hierarchical|raw-aes] [--output FILE]\n";
            return 2;
        }
    }
    if (quick) {
        config = esdk_bench::quick_config();
    }

    // Only the hierarchical keyring needs key store coordinates; the raw AES
    // keyring wraps data keys locally.
    std::optional<esdk_bench::KeyStoreEnv> env;
    if (keyring_name == "hierarchical") {
        env = esdk_bench::load_env();
        if (!env) {
            std::cout << "SKIP: set ESDK_TEST_KMS_KEY_ARN, ESDK_TEST_DDB_TABLE, "
                         "ESDK_TEST_LOGICAL_KEYSTORE, and ESDK_TEST_BRANCH_KEY_ID to "
                         "run the C++ hierarchical keyring benchmark.\n";
            return 0;
        }
    }

    Aws::Esdk::EncryptionSDK sdk;
    std::vector<BenchmarkResult> results;
    try {
        auto keyring = make_benchmark_keyring(keyring_name, env);

        for (std::size_t data_size : config.data_sizes) {
            results.push_back(
                run_throughput(sdk, keyring, data_size, config.warmup, config.measurement));
            results.push_back(run_memory(sdk, keyring, data_size));
            for (int concurrency : config.concurrency_levels) {
                if (concurrency > 1) {
                    results.push_back(
                        run_concurrent(sdk, keyring, data_size, concurrency));
                }
            }
        }
    } catch (const std::exception& e) {
        std::cerr << "FATAL: benchmark aborted: " << e.what() << "\n";
        return 1;
    }

    if (results.empty()) {
        std::cerr << "benchmark produced no results\n";
        return 1;
    }

    esdk_bench::write_results_json(output, results, esdk_bench::collect_run_info(),
                                   keyring_name);
    std::cout << "wrote " << results.size() << " results to " << output << "\n";
    return 0;
}
