// Handles the exceptions that the hierarchical keyring throws.
//
// Every failure is an AwsEncryptionSdkException, or a subclass for its kind.
// You handle it by asking up to four questions, in order,
// and you stop at whichever level of detail your application needs:
//
// 1. Can a retry help? retryable() answers this for every exception.
// 2. What kind of failure is it? The exception type: AccessDeniedException, ResourceNotFoundException, ...
// 3. Which service failed? service(): AWS KMS, DynamoDB, or empty for a local failure.
// 4. Which resource do you need to act on? resource(): a KMS key, a table, a branch key.
//
// Each answer is a field on the exception, so you never parse what().
// Messages are for people and logs, and their text can change in any release.
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

        // ---- Encrypt: the four questions, from coarse to fine ----
        //
        // The hierarchical keyring reads the branch key from DynamoDB and decrypts it with AWS KMS,
        // so encrypt can fail in either service.
        const std::string plaintext = "Hello World";
        std::optional<Aws::Esdk::EncryptResult> encrypted;
        try {
            // This uses the string API; the bytes APIs take a std::vector, a pointer and length, or a std::span (C++20).
            encrypted = esdk.encrypt(plaintext, keyring);
        } catch (const Aws::Esdk::AwsEncryptionSdkException& e) {
            // Question 1: can a retry help?
            // Checking retryable() before the type catches throttling, timeouts, connection failures
            // and AWS server errors in one place, whatever their type.
            // The AWS SDK clients already retried these, so retry at a higher level;
            // retry_kind() says how to back off.
            if (e.retryable()) {
                std::cerr << "retry later: " << e.what() << "\n";
                return 1;
            }

            // Question 2: what kind of failure is it?
            // Many applications stop here and handle each exception type the same way.
            // Rethrowing lets the typed catch clauses below pick the type.
            try {
                throw;
            } catch (const Aws::Esdk::AccessDeniedException& denied) {
                // is_credentials() refines one type further:
                // AWS rejected the credentials themselves, not a permission on a resource.
                if (denied.is_credentials()) {
                    std::cerr << "the AWS credentials are expired or invalid\n";
                    return 1;
                }
                // Question 3: which service denied access?
                // The fix differs per service: a KMS key policy or grant, or an IAM policy on the table.
                // service() is empty for a failure with no AWS service, so check it first.
                const auto service = denied.service();
                const auto resource = denied.resource();
                const auto resource_type = resource ? resource->type() : Aws::Esdk::ResourceType::Unknown;
                if (!service) {
                    std::cerr << "access denied: " << denied.what() << "\n";
                    return 1;
                }
                switch (*service) {
                case Aws::Esdk::Service::Kms:
                    // Question 4: which resource do you need to act on?
                    // resource() is a copy of the resource this exception carries.
                    switch (resource_type) {
                    case Aws::Esdk::ResourceType::KmsKey:
                        std::cerr << "grant access to the KMS key " << resource->name() << "\n";
                        break;
                    default:
                        // Later releases add resource types,
                        // so every switch on the resource ends in a default case.
                        std::cerr << "AWS KMS denied access: " << denied.what() << "\n";
                    }
                    break;
                case Aws::Esdk::Service::DynamoDb:
                    switch (resource_type) {
                    case Aws::Esdk::ResourceType::DynamoDbTable:
                        std::cerr << "grant access to the key store table " << resource->name() << "\n";
                        break;
                    default:
                        std::cerr << "DynamoDB denied access: " << denied.what() << "\n";
                    }
                    break;
                default:
                    // Later releases add services, so the service switch needs a default case too.
                    std::cerr << "access denied: " << denied.what() << "\n";
                }
            } catch (const Aws::Esdk::ResourceNotFoundException& not_found) {
                // A missing resource carries the resource to create or fix.
                // Branch on the service, then on the resource within it, the same way.
                const auto service = not_found.service();
                const auto resource = not_found.resource();
                const auto resource_type = resource ? resource->type() : Aws::Esdk::ResourceType::Unknown;
                if (!service) {
                    std::cerr << "a resource does not exist: " << not_found.what() << "\n";
                    return 1;
                }
                switch (*service) {
                case Aws::Esdk::Service::Kms:
                    switch (resource_type) {
                    case Aws::Esdk::ResourceType::KmsKey:
                        std::cerr << "the KMS key " << resource->name() << " does not exist\n";
                        break;
                    default:
                        std::cerr << "an AWS KMS resource does not exist: " << not_found.what() << "\n";
                    }
                    break;
                case Aws::Esdk::Service::DynamoDb:
                    // The key store keeps branch keys in DynamoDB,
                    // so both a missing branch key and a missing table are DynamoDB resources.
                    switch (resource_type) {
                    case Aws::Esdk::ResourceType::BranchKey:
                        std::cerr << "create the branch key " << resource->name() << " in the key store\n";
                        break;
                    case Aws::Esdk::ResourceType::DynamoDbTable:
                        std::cerr << "the key store table " << resource->name() << " does not exist\n";
                        break;
                    default:
                        std::cerr << "a DynamoDB resource does not exist: " << not_found.what() << "\n";
                    }
                    break;
                default:
                    std::cerr << "a resource does not exist: " << not_found.what() << "\n";
                }
            } catch (const Aws::Esdk::AwsEncryptionSdkException& other) {
                // Later releases add exception types,
                // so the base class catches every other failure, today's and future ones.
                // full_message() adds every cause below the error, for the log.
                std::cerr << "encrypt failed: " << other.full_message() << "\n";
            }
            return 1;
        }

        // ---- Decrypt: failures only decrypt has ----
        try {
            auto decrypted = esdk.decrypt(encrypted->ciphertext, keyring);
            if (decrypted.plaintext.as_string_view() != plaintext) {
                std::cerr << "decryption failed: plaintext mismatch\n";
                return 1;
            }
        } catch (const Aws::Esdk::InvalidMaterialsException& e) {
            // The branch key record in DynamoDB is malformed, for example a key of the wrong length.
            // resource() names the branch key to repair.
            const auto resource = e.resource();
            if (resource && resource->type() == Aws::Esdk::ResourceType::BranchKey) {
                std::cerr << "the record for branch key " << resource->name() << " is malformed\n";
            } else {
                std::cerr << "invalid materials: " << e.what() << "\n";
            }
            return 1;
        } catch (const Aws::Esdk::NoMatchingDataKeyException& e) {
            // None of the message's encrypted data keys belongs to this keyring.
            // what() lists the key provider IDs the message was encrypted for.
            std::cerr << "the message was encrypted under a different keyring: " << e.what() << "\n";
            return 1;
        } catch (const Aws::Esdk::CryptographicException&) {
            // The message is corrupt or was modified. Retrying cannot help.
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
        // Setting up the key store or keyring failed.
        std::cerr << "failed: " << e.full_message() << "\n";
        return 1;
    }
    return 0;
}
