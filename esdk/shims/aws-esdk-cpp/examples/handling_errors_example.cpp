// Handles the exceptions a hierarchical keyring throws: retries a decrypt that can succeed later,
// and reports a branch key or key store table that does not exist.
//
// Requires AWS credentials and the key store in basic_hierarchical_keyring_example.cpp.

#include <chrono>
#include <iostream>
#include <string>
#include <thread>
#include <vector>
#include <aws/esdk/EncryptionSDK.h>

using namespace std::chrono_literals;

namespace {

// The AWS Crypto Tools CI test key store.
// Replace these with your own key store's table, name, KMS key ARN, and branch key ID.
const char* const kTableName = "KeyStoreDdbTable";
const char* const kLogicalKeyStoreName = "KeyStoreDdbTable";
const char* const kKmsKeyArn =
    "arn:aws:kms:us-west-2:370957321024:key/9d989aa2-2f9c-438c-a745-cc57d3ad0126";
const char* const kBranchKeyId = "3ce7656b-e166-40f3-8c9b-a920ce6596cd";

// Building the key store and keyring does no IO,
// so a missing table or branch key shows up on the first encrypt or decrypt.
Aws::Esdk::HierarchicalKeyring hierarchical_keyring(const std::string& table_name,
                                                    const std::string& branch_key_id) {
    auto keystore = Aws::Esdk::KeyStore(table_name, kLogicalKeyStoreName, kKmsKeyArn);
    return Aws::Esdk::HierarchicalKeyring(keystore, branch_key_id, 600s);
}

// Decrypt, retrying a retryable failure with exponential backoff.
//
// The KMS and DynamoDB clients already retry each call a few times.
// This loop retries the whole decrypt once those retries are used up,
// for example during a sustained throttle or a network outage.
Aws::Esdk::DecryptResult decrypt_with_retry(Aws::Esdk::EncryptionSDK& esdk,
                                            const Aws::Esdk::Bytes& ciphertext,
                                            const Aws::Esdk::HierarchicalKeyring& keyring) {
    constexpr int kMaxAttempts = 4;
    auto delay = 200ms;
    for (int attempt = 1;; ++attempt) {
        try {
            return esdk.decrypt(ciphertext, keyring);
        } catch (const Aws::Esdk::AwsEncryptionSdkException& e) {
            // A retryable error might succeed if the same call is made again later.
            // Any other error fails the same way every time, so rethrow it at once.
            if (!e.retryable() || attempt == kMaxAttempts) {
                throw;
            }
            std::cerr << "decrypt attempt " << attempt << " failed, retrying in "
                      << delay.count() << "ms: " << e.what() << "\n";
            std::this_thread::sleep_for(delay);
            delay *= 2;
        }
    }
}

// Say what to do about an exception that retrying cannot fix.
void report(const Aws::Esdk::AwsEncryptionSdkException& e) {
    // kind() is empty for a kind this library does not know yet.
    const auto kind = e.kind();
    if (kind == Aws::Esdk::ErrorKind::RemoteResourceNotFound) {
        // A missing branch key or a missing table; what() names the call that failed.
        std::cout << "a branch key or the key store table does not exist; check the configuration\n";
    } else if (kind == Aws::Esdk::ErrorKind::RemoteAccessDenied) {
        // IAM usually allows only the key store's own table,
        // so a request for a table that does not exist is often denied before DynamoDB looks for it.
        std::cout << "access denied; check the IAM policy for the key store table and KMS key\n";
    } else if (kind == Aws::Esdk::ErrorKind::RemoteTransport) {
        // Still failing after the retries, or not retryable at all, such as missing credentials.
        std::cout << "could not reach AWS; check the credentials, region, and network\n";
    } else if (kind == Aws::Esdk::ErrorKind::Validation) {
        std::cout << "invalid input or configuration; fix it and try again\n";
    } else if (kind == Aws::Esdk::ErrorKind::Cryptographic ||
               kind == Aws::Esdk::ErrorKind::NoMatchingDataKey ||
               kind == Aws::Esdk::ErrorKind::Serialization ||
               kind == Aws::Esdk::ErrorKind::EncryptionContextMismatch) {
        std::cout << "reject the message\n";
    } else {
        std::cout << "failed\n";
    }
    // For logs. Decide from the exception type and kind(), never from this text.
    std::cout << "  " << e.what() << "\n";
}

// Encrypt with `keyring`, expecting it to fail, and report the failure.
bool expect_encrypt_failure(Aws::Esdk::EncryptionSDK& esdk,
                            const Aws::Esdk::HierarchicalKeyring& keyring) {
    const std::vector<std::uint8_t> plaintext = {'H', 'e', 'l', 'l', 'o'};
    try {
        esdk.encrypt(plaintext, keyring);
    } catch (const Aws::Esdk::AwsEncryptionSdkException& e) {
        report(e);
        return true;
    }
    std::cerr << "encrypt unexpectedly succeeded\n";
    return false;
}

}  // namespace

int main() {
    Aws::Esdk::EncryptionSDK esdk;
    try {
        auto keyring = hierarchical_keyring(kTableName, kBranchKeyId);
        const std::vector<std::uint8_t> plaintext = {'H', 'e', 'l', 'l', 'o', ' ',
                                                     'W', 'o', 'r', 'l', 'd'};
        auto encrypted = esdk.encrypt(plaintext, keyring);
        auto decrypted = decrypt_with_retry(esdk, encrypted.ciphertext, keyring);
        if (decrypted.plaintext != plaintext) {
            std::cerr << "decryption failed: plaintext mismatch\n";
            return 1;
        }
        std::cout << "decrypted the message\n";
    } catch (const Aws::Esdk::AwsEncryptionSdkException& e) {
        report(e);
        return 1;
    }

    // A branch key ID with no record in the key store.
    if (!expect_encrypt_failure(esdk,
                                hierarchical_keyring(kTableName, "branch-key-that-does-not-exist"))) {
        return 1;
    }
    // A key store table that does not exist.
    if (!expect_encrypt_failure(esdk,
                                hierarchical_keyring("table-that-does-not-exist", kBranchKeyId))) {
        return 1;
    }
    return 0;
}
