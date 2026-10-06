// Handles the exceptions that the hierarchical keyring throws.
//
// Each kind of failure is its own exception type; catch the ones you act on by type,
// then decide from service() and resource(), never from what().
//
// Requires AWS credentials and the key store in basic_hierarchical_keyring_example.cpp.

#include <chrono>
#include <iostream>
#include <optional>
#include <string>
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

}  // namespace

int main() {
    try {
        auto keystore = Aws::Esdk::KeyStore(kTableName, kLogicalKeyStoreName, kKmsKeyArn);
        auto keyring = Aws::Esdk::HierarchicalKeyring(keystore, kBranchKeyId, 600s);
        Aws::Esdk::EncryptionSDK esdk;

        const std::string plaintext = "Hello World";
        std::optional<Aws::Esdk::EncryptResult> encrypted;
        try {
            // This uses the string API; the bytes APIs take a std::vector, a pointer and length, or a std::span (C++20).
            encrypted = esdk.encrypt(plaintext, keyring);
        } catch (const Aws::Esdk::AccessDeniedException& e) {
            const auto resource = e.resource();
            if (e.is_credentials()) {
                std::cerr << "the AWS credentials are expired or invalid\n";
            } else if (e.service() == Aws::Esdk::Service::Kms && resource &&
                       resource->type() == Aws::Esdk::ResourceType::KmsKey) {
                std::cerr << "AWS KMS denied access to the KMS key " << resource->name() << "\n";
            } else if (e.service() == Aws::Esdk::Service::DynamoDb && resource &&
                       resource->type() == Aws::Esdk::ResourceType::DynamoDbTable) {
                std::cerr << "DynamoDB denied access to the table " << resource->name() << "\n";
            } else {
                std::cerr << "access denied: " << e.what() << "\n";
            }
            return 1;
        } catch (const Aws::Esdk::ResourceNotFoundException& e) {
            const auto resource = e.resource();
            switch (resource ? resource->type() : Aws::Esdk::ResourceType::Unknown) {
            case Aws::Esdk::ResourceType::BranchKey:
                std::cerr << "branch key " << resource->name() << " is not in the key store\n";
                break;
            case Aws::Esdk::ResourceType::DynamoDbTable:
                std::cerr << "the key store table " << resource->name() << " does not exist\n";
                break;
            case Aws::Esdk::ResourceType::KmsKey:
                std::cerr << "the KMS key " << resource->name() << " does not exist\n";
                break;
            default:
                std::cerr << "an AWS resource does not exist: " << e.what() << "\n";
            }
            return 1;
        } catch (const Aws::Esdk::AwsEncryptionSdkException& e) {
            // The AWS SDK clients already retried; retry_kind() says how to back off.
            if (e.retryable()) {
                std::cerr << "retry later: " << e.what() << "\n";
            } else {
                std::cerr << "encrypt failed: " << e.what() << "\n";
            }
            return 1;
        }

        try {
            auto decrypted = esdk.decrypt(encrypted->ciphertext, keyring);
            if (decrypted.plaintext.as_string_view() != plaintext) {
                std::cerr << "decryption failed: plaintext mismatch\n";
                return 1;
            }
        } catch (const Aws::Esdk::InvalidMaterialsException& e) {
            const auto resource = e.resource();
            if (resource && resource->type() == Aws::Esdk::ResourceType::BranchKey) {
                std::cerr << "the record for branch key " << resource->name() << " is malformed\n";
            } else {
                std::cerr << "invalid materials: " << e.what() << "\n";
            }
            return 1;
        } catch (const Aws::Esdk::NoMatchingDataKeyException&) {
            std::cerr << "the message was encrypted under a different keyring\n";
            return 1;
        } catch (const Aws::Esdk::CryptographicException&) {
            std::cerr << "the message is corrupt or was tampered with\n";
            return 1;
        } catch (const Aws::Esdk::SerializationException&) {
            std::cerr << "the message is corrupt or was tampered with\n";
            return 1;
        } catch (const Aws::Esdk::AwsEncryptionSdkException& e) {
            if (e.retryable()) {
                std::cerr << "retry later: " << e.what() << "\n";
            } else {
                std::cerr << "decrypt failed: " << e.full_message() << "\n";
            }
            return 1;
        }
        std::cout << "decrypted the message\n";
    } catch (const Aws::Esdk::AwsEncryptionSdkException& e) {
        std::cerr << "failed: " << e.full_message() << "\n";
        return 1;
    }
    return 0;
}
