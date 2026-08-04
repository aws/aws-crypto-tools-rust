// C ABI over the idiomatic C++ facade (aws/esdk/EncryptionSDK.h). The Rust
// server calls these functions; each one runs entirely through Aws::Esdk:: so
// the C++ shim surface is what gets exercised end to end.

#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <exception>
#include <map>
#include <string>
#include <vector>

#include <aws/esdk/EncryptionSDK.h>

using Aws::Esdk::AlgorithmSuiteId;
using Aws::Esdk::CommitmentPolicy;
using Aws::Esdk::DdbClient;
using Aws::Esdk::DecryptOptions;
using Aws::Esdk::DecryptResult;
using Aws::Esdk::EncryptionSDK;
using Aws::Esdk::EncryptOptions;
using Aws::Esdk::EncryptResult;
using Aws::Esdk::AesWrappingAlgorithm;
using Aws::Esdk::HierarchicalKeyring;
using Aws::Esdk::KmsClient;
using Aws::Esdk::RawAesKeyring;
// Aws::Esdk::KeyStore and Aws::Esdk::Keyring are referenced fully qualified: the
// generated cxx header declares global ::KeyStore and ::Keyring, so importing the
// facade's into this scope clashes.

namespace {

char* dup_message(const std::string& msg) {
    char* out = static_cast<char*>(std::malloc(msg.size() + 1));
    if (out) {
        std::memcpy(out, msg.c_str(), msg.size() + 1);
    }
    return out;
}

uint8_t* dup_bytes(const Aws::Esdk::Bytes& bytes) {
    uint8_t* out = static_cast<uint8_t*>(std::malloc(bytes.empty() ? 1 : bytes.size()));
    if (out && !bytes.empty()) {
        std::memcpy(out, bytes.data(), bytes.size());
    }
    return out;
}

std::map<std::string, std::string> to_map(const char* const* keys,
                                          const char* const* vals,
                                          size_t len) {
    std::map<std::string, std::string> out;
    for (size_t i = 0; i < len; ++i) {
        out.emplace(keys[i], vals[i]);
    }
    return out;
}

}  // namespace

extern "C" {

// On success returns 0 and sets *out_client; on failure returns 1 and sets
// *out_err to a malloc'd message the caller frees with esdk_cpp_free_err.
int esdk_cpp_create_hierarchical_client(const char* region,
                                        const char* table_name,
                                        const char* logical_key_store_name,
                                        const char* kms_key_arn,
                                        const char* branch_key_id,
                                        uint32_t ttl_seconds,
                                        void** out_client,
                                        char** out_err) {
    try {
        Aws::Esdk::ClientConfig config;
        if (region && region[0] != '\0') {
            config.with_region(region);
        }
        KmsClient kms(config);
        DdbClient ddb(config);
        Aws::Esdk::KeyStore key_store(table_name, logical_key_store_name, kms_key_arn, kms, ddb);
        Aws::Esdk::Keyring* keyring = new HierarchicalKeyring(std::move(key_store), branch_key_id, ttl_seconds);
        *out_client = keyring;
        return 0;
    } catch (const std::exception& e) {
        *out_err = dup_message(e.what());
        return 1;
    } catch (...) {
        *out_err = dup_message("unknown C++ exception creating hierarchical client");
        return 1;
    }
}

// On success returns 0 and sets *out_client; on failure returns 1 and sets
// *out_err. wrapping_alg is 1/2/3 for AES-128/192/256-GCM.
int esdk_cpp_create_raw_aes_client(const char* key_namespace,
                                   const char* key_name,
                                   const uint8_t* wrapping_key,
                                   size_t wrapping_key_len,
                                   uint8_t wrapping_alg,
                                   void** out_client,
                                   char** out_err) {
    try {
        std::vector<uint8_t> key(wrapping_key, wrapping_key + wrapping_key_len);
        Aws::Esdk::Keyring* keyring = new RawAesKeyring(key_namespace, key_name, key,
                                             static_cast<AesWrappingAlgorithm>(wrapping_alg));
        *out_client = keyring;
        return 0;
    } catch (const std::exception& e) {
        *out_err = dup_message(e.what());
        return 1;
    } catch (...) {
        *out_err = dup_message("unknown C++ exception creating raw AES client");
        return 1;
    }
}

// commitment_policy is the CommitmentPolicy enum value. algorithm_suite_id, frame_length, and
// max_encrypted_data_keys use 0 to mean "unset — defer to the core default".
int esdk_cpp_encrypt(void* client,
                     const uint8_t* plaintext,
                     size_t plaintext_len,
                     uint8_t commitment_policy,
                     uint16_t algorithm_suite_id,
                     uint32_t frame_length,
                     uint32_t max_encrypted_data_keys,
                     const char* const* ec_keys,
                     const char* const* ec_vals,
                     size_t ec_len,
                     uint8_t** out_buf,
                     size_t* out_len,
                     char** out_err) {
    try {
        auto* keyring = reinterpret_cast<Aws::Esdk::Keyring*>(client);
        EncryptOptions options;
        options.with_commitment_policy(static_cast<CommitmentPolicy>(commitment_policy));
        if (algorithm_suite_id != 0) {
            options.with_algorithm_suite(static_cast<AlgorithmSuiteId>(algorithm_suite_id));
        }
        if (frame_length != 0) {
            options.with_frame_length(frame_length);
        }
        if (max_encrypted_data_keys != 0) {
            options.with_max_encrypted_data_keys(max_encrypted_data_keys);
        }
        options.with_encryption_context(to_map(ec_keys, ec_vals, ec_len));

        std::vector<uint8_t> input(plaintext, plaintext + plaintext_len);
        EncryptionSDK sdk;
        EncryptResult result = sdk.encrypt(input, *keyring, options);
        *out_buf = dup_bytes(result.ciphertext);
        *out_len = result.ciphertext.size();
        return 0;
    } catch (const std::exception& e) {
        *out_err = dup_message(e.what());
        return 1;
    } catch (...) {
        *out_err = dup_message("unknown C++ exception during encrypt");
        return 1;
    }
}

int esdk_cpp_decrypt(void* client,
                     const uint8_t* ciphertext,
                     size_t ciphertext_len,
                     uint8_t commitment_policy,
                     uint32_t max_encrypted_data_keys,
                     const char* const* ec_keys,
                     const char* const* ec_vals,
                     size_t ec_len,
                     uint8_t** out_buf,
                     size_t* out_len,
                     char** out_err) {
    try {
        auto* keyring = reinterpret_cast<Aws::Esdk::Keyring*>(client);
        DecryptOptions options;
        options.with_commitment_policy(static_cast<CommitmentPolicy>(commitment_policy));
        if (max_encrypted_data_keys != 0) {
            options.with_max_encrypted_data_keys(max_encrypted_data_keys);
        }
        options.with_encryption_context(to_map(ec_keys, ec_vals, ec_len));

        std::vector<uint8_t> input(ciphertext, ciphertext + ciphertext_len);
        EncryptionSDK sdk;
        DecryptResult result = sdk.decrypt(input, *keyring, options);
        *out_buf = dup_bytes(result.plaintext);
        *out_len = result.plaintext.size();
        return 0;
    } catch (const std::exception& e) {
        *out_err = dup_message(e.what());
        return 1;
    } catch (...) {
        *out_err = dup_message("unknown C++ exception during decrypt");
        return 1;
    }
}

void esdk_cpp_free_client(void* client) {
    delete reinterpret_cast<Aws::Esdk::Keyring*>(client);
}

void esdk_cpp_free_buf(uint8_t* buf) { std::free(buf); }

void esdk_cpp_free_err(char* err) { std::free(err); }

}  // extern "C"
