// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

// Support for the C++ hierarchical-keyring performance benchmark
// (benchmark.cpp): scenario configuration, keyring setup from the environment,
// resident-memory sampling, latency statistics, the result record, and JSON
// output. The JSON schema matches the Rust benchmark so both feed the same
// CloudWatch pipeline; results carry language "rust-cpp".
#pragma once

#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cmath>
#include <ctime>
#include <fstream>
#include <iomanip>
#include <optional>
#include <sstream>
#include <string>
#include <thread>
#include <vector>

#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#include <aws/esdk/EncryptionSDK.h>

namespace esdk_bench {

// Encrypt/decrypt round trips sampled by the memory test.
constexpr int MEMORY_TEST_ITERATIONS = 5;

// Round trips each worker performs in the concurrent test.
constexpr int CONCURRENT_ITERS_PER_WORKER = 5;

struct BenchmarkConfig {
    // Sizes match the Rust benchmark scenarios so both plot on the same
    // CloudWatch series; 1 KiB and 1 MiB alongside 50 MiB separate fixed
    // per-call cost from per-byte cost.
    std::vector<std::size_t> data_sizes = {1024, 1048576, 52428800};
    int warmup = 5;
    int measurement = 10;
    std::vector<int> concurrency_levels = {1, 2};
};

// Reduced iterations; what CI runs.
inline BenchmarkConfig quick_config() {
    BenchmarkConfig config;
    config.warmup = 3;
    config.measurement = 3;
    return config;
}

// Key store coordinates for the hierarchical keyring, read from the
// environment (the same variables the C++ shim tests use).
struct KeyStoreEnv {
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

// std::nullopt when a required variable is unset, so the caller can skip.
inline std::optional<KeyStoreEnv> load_env() {
    const char* kms = env_or_null("ESDK_TEST_KMS_KEY_ARN");
    const char* ddb = env_or_null("ESDK_TEST_DDB_TABLE");
    const char* logical = env_or_null("ESDK_TEST_LOGICAL_KEYSTORE");
    const char* branch = env_or_null("ESDK_TEST_BRANCH_KEY_ID");
    const char* region = env_or_null("ESDK_TEST_REGION");
    if (!kms || !ddb || !logical || !branch) {
        return std::nullopt;
    }
    return KeyStoreEnv{kms, ddb, logical, branch, region ? region : ""};
}

// Hierarchical keyring backed by the key store named in the environment. The
// long TTL keeps the branch key cached for the whole run, so measured latency
// reflects the SDK crypto path rather than a KMS round trip.
inline Aws::Esdk::HierarchicalKeyring make_keyring(const KeyStoreEnv& env) {
    auto client_config = Aws::Esdk::ClientConfig().with_max_retry_attempts(5);
    if (!env.region.empty()) {
        client_config.with_region(env.region);
    }
    Aws::Esdk::KmsClient kms(client_config);
    Aws::Esdk::DdbClient ddb(client_config);
    Aws::Esdk::KeyStore keystore(env.ddb_table, env.logical_keystore,
                                 env.kms_key_arn, kms, ddb);
    return Aws::Esdk::HierarchicalKeyring(
        std::move(keystore), env.branch_key_id, /*ttl_seconds=*/600000,
        Aws::Esdk::HierarchicalKeyringOptions().with_cache_capacity(100));
}

// Resident set size in bytes from /proc/self/statm, or 0 when it cannot be read
// (non-Linux, or /proc not mounted).
inline long read_rss_bytes() {
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

inline double average(const std::vector<double>& values) {
    if (values.empty()) {
        return 0.0;
    }
    double sum = 0.0;
    for (double v : values) {
        sum += v;
    }
    return sum / static_cast<double>(values.size());
}

// Linear-interpolated percentile of an already-sorted sample.
inline double percentile(const std::vector<double>& sorted_values, double p) {
    if (sorted_values.empty()) {
        return 0.0;
    }
    if (p <= 0.0) {
        return sorted_values.front();
    }
    if (p >= 100.0) {
        return sorted_values.back();
    }

    double index = (p / 100.0) * static_cast<double>(sorted_values.size() - 1);
    double lower = std::floor(index);
    double upper = std::ceil(index);
    auto lower_index = static_cast<std::size_t>(lower);
    auto upper_index = static_cast<std::size_t>(upper);

    if (lower_index == upper_index) {
        return sorted_values[lower_index];
    }

    double weight = index - lower;
    return sorted_values[lower_index] * (1.0 - weight) +
           sorted_values[upper_index] * weight;
}

struct BenchmarkResult {
    std::string test_name;
    std::size_t data_size = 0;
    int concurrency = 1;
    double encrypt_latency_ms = 0.0;
    double decrypt_latency_ms = 0.0;
    double end_to_end_latency_ms = 0.0;
    double ops_per_second = 0.0;
    double bytes_per_second = 0.0;
    double peak_memory_mb = 0.0;
    double memory_efficiency_ratio = 0.0;
    double p50_latency = 0.0;
    double p95_latency = 0.0;
    double p99_latency = 0.0;
};

// Host and toolchain facts recorded once per run.
struct RunInfo {
    std::string timestamp;
    std::string compiler;
    int cpu_count = 0;
    double total_memory_gb = 0.0;
};

inline std::string utc_timestamp() {
    std::time_t now = std::time(nullptr);
    std::tm tm{};
    gmtime_r(&now, &tm);
    char buffer[32];
    std::strftime(buffer, sizeof(buffer), "%Y-%m-%d %H:%M:%S", &tm);
    return std::string(buffer);
}

inline RunInfo collect_run_info() {
    RunInfo info;
    info.timestamp = utc_timestamp();
    info.compiler = __VERSION__;
    unsigned int cores = std::thread::hardware_concurrency();
    info.cpu_count = cores == 0 ? 1 : static_cast<int>(cores);
    long pages = sysconf(_SC_PHYS_PAGES);
    long page_size = sysconf(_SC_PAGESIZE);
    if (pages > 0 && page_size > 0) {
        info.total_memory_gb = static_cast<double>(pages) *
                               static_cast<double>(page_size) /
                               (1024.0 * 1024.0 * 1024.0);
    }
    return info;
}

inline std::string json_escape(const std::string& s) {
    std::string out;
    out.reserve(s.size());
    for (char c : s) {
        if (c == '"' || c == '\\') {
            out.push_back('\\');
        }
        out.push_back(c);
    }
    return out;
}

inline std::string json_number(double value) {
    if (!std::isfinite(value)) {
        value = 0.0;
    }
    std::ostringstream os;
    os << std::setprecision(10) << value;
    return os.str();
}

// Create each parent directory of path (like `mkdir -p` on the dirname).
inline void ensure_parent_dir(const std::string& path) {
    std::size_t last_slash = path.find_last_of('/');
    if (last_slash == std::string::npos) {
        return;
    }
    std::string dir = path.substr(0, last_slash);
    std::string accumulated;
    std::size_t start = 0;
    if (!dir.empty() && dir[0] == '/') {
        accumulated = "/";
        start = 1;
    }
    while (start <= dir.size()) {
        std::size_t next = dir.find('/', start);
        std::size_t len =
            (next == std::string::npos) ? std::string::npos : next - start;
        std::string component = dir.substr(start, len);
        if (!component.empty()) {
            if (!accumulated.empty() && accumulated.back() != '/') {
                accumulated.push_back('/');
            }
            accumulated += component;
            ::mkdir(accumulated.c_str(), 0755);
        }
        if (next == std::string::npos) {
            break;
        }
        start = next + 1;
    }
}

inline void append_result_json(std::ostringstream& os, const BenchmarkResult& r,
                               const RunInfo& info) {
    os << "    {\n";
    os << "      \"test_name\": \"" << json_escape(r.test_name) << "\",\n";
    os << "      \"language\": \"rust-cpp\",\n";
    os << "      \"data_size\": " << r.data_size << ",\n";
    os << "      \"concurrency\": " << r.concurrency << ",\n";
    os << "      \"encrypt_latency_ms\": " << json_number(r.encrypt_latency_ms) << ",\n";
    os << "      \"decrypt_latency_ms\": " << json_number(r.decrypt_latency_ms) << ",\n";
    os << "      \"end_to_end_latency_ms\": " << json_number(r.end_to_end_latency_ms) << ",\n";
    os << "      \"ops_per_second\": " << json_number(r.ops_per_second) << ",\n";
    os << "      \"bytes_per_second\": " << json_number(r.bytes_per_second) << ",\n";
    os << "      \"peak_memory_mb\": " << json_number(r.peak_memory_mb) << ",\n";
    os << "      \"memory_efficiency_ratio\": " << json_number(r.memory_efficiency_ratio) << ",\n";
    os << "      \"p50_latency\": " << json_number(r.p50_latency) << ",\n";
    os << "      \"p95_latency\": " << json_number(r.p95_latency) << ",\n";
    os << "      \"p99_latency\": " << json_number(r.p99_latency) << ",\n";
    os << "      \"timestamp\": \"" << json_escape(info.timestamp) << "\",\n";
    os << "      \"compiler\": \"" << json_escape(info.compiler) << "\",\n";
    os << "      \"cpu_count\": " << info.cpu_count << ",\n";
    os << "      \"total_memory_gb\": " << json_number(info.total_memory_gb) << "\n";
    os << "    }";
}

inline void write_results_json(const std::string& path,
                               const std::vector<BenchmarkResult>& results,
                               const RunInfo& info) {
    std::ostringstream os;
    os << "{\n";
    os << "  \"metadata\": {\n";
    os << "    \"language\": \"rust-cpp\",\n";
    os << "    \"keyring\": \"hierarchical\",\n";
    os << "    \"timestamp\": \"" << json_escape(info.timestamp) << "\",\n";
    os << "    \"compiler\": \"" << json_escape(info.compiler) << "\",\n";
    os << "    \"cpu_count\": " << info.cpu_count << ",\n";
    os << "    \"total_memory_gb\": " << json_number(info.total_memory_gb) << ",\n";
    os << "    \"total_tests\": " << results.size() << "\n";
    os << "  },\n";
    os << "  \"results\": [\n";
    for (std::size_t i = 0; i < results.size(); ++i) {
        append_result_json(os, results[i], info);
        os << (i + 1 < results.size() ? ",\n" : "\n");
    }
    os << "  ]\n";
    os << "}\n";

    ensure_parent_dir(path);
    std::ofstream file(path);
    if (!file.is_open()) {
        throw std::ios_base::failure("failed to open results output file: " + path);
    }
    file << os.str();
    if (!file) {
        throw std::ios_base::failure("failed to write results to: " + path);
    }
}

}  // namespace esdk_bench
