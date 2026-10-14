// Encrypts and decrypts a message with a hierarchical keyring that calls AWS KMS with credentials issued for one request.
//
// Requires an existing key store with a provisioned branch key.
// The request credentials are read from AWS_ACCESS_KEY_ID, AWS_SECRET_ACCESS_KEY, and AWS_SESSION_TOKEN.

#include <chrono>
#include <cstdlib>
#include <iostream>
#include <stdexcept>
#include <string>
#include <aws/esdk/EncryptionSDK.h>

using namespace std::chrono_literals;

// Stands in for the credentials a service receives with each request.
Aws::Esdk::Credentials credentials_for_request() {
    const char* access_key_id = std::getenv("AWS_ACCESS_KEY_ID");
    const char* secret_access_key = std::getenv("AWS_SECRET_ACCESS_KEY");
    const char* session_token = std::getenv("AWS_SESSION_TOKEN");
    if (access_key_id == nullptr || secret_access_key == nullptr) {
        throw std::runtime_error("set AWS_ACCESS_KEY_ID and AWS_SECRET_ACCESS_KEY");
    }
    auto credentials = Aws::Esdk::Credentials(access_key_id, secret_access_key)
                           .with_expiration(std::chrono::system_clock::now() + 15min);
    if (session_token != nullptr) {
        credentials.with_session_token(session_token);
    }
    return credentials;
}

// Handles one request: every KMS call it makes uses that request's credentials.
void handle_request(const Aws::Esdk::KmsClient& kms,
                    const Aws::Esdk::DdbClient& ddb,
                    Aws::Esdk::Client& esdk,
                    const Aws::Esdk::Credentials& credentials) {
    // The AWS Crypto Tools CI test key store.
    // Replace these with your own key store's table, name, and KMS key ARN.
    auto keystore = Aws::Esdk::KeyStore(
        "KeyStoreDdbTable",  // table_name
        "KeyStoreDdbTable",  // logical_key_store_name
        "arn:aws:kms:us-west-2:370957321024:key/9d989aa2-2f9c-438c-a745-cc57d3ad0126",  // kms_arn
        Aws::Esdk::KeyStoreOptions()
            .with_kms_client(kms.with_credentials(credentials))
            .with_ddb_client(ddb));

    // A keyring with its own cache, so branch key material fetched with one request's
    // credentials is never served to another request.
    auto keyring = Aws::Esdk::HierarchicalKeyring(
        keystore,
        "3ce7656b-e166-40f3-8c9b-a920ce6596cd",  // branch_key_id
        300s);                                   // ttl

    const std::string plaintext = "Hello World";
    auto encrypted = esdk.encrypt(plaintext, keyring);
    auto decrypted = esdk.decrypt(encrypted.ciphertext, keyring);
    if (decrypted.plaintext.as_string_view() != plaintext) {
        throw std::runtime_error("plaintext mismatch");
    }
}

int main() {
    try {
        // Created once and shared by every request.
        // One HttpClient gives the KMS and DynamoDB clients, and every per-request copy of them,
        // a single connection pool.
        // DynamoDB calls use the default credential chain; KMS calls use each request's credentials.
        const Aws::Esdk::HttpClient http;
        const auto config = Aws::Esdk::AwsSdkClientConfig().with_region("us-west-2").with_http_client(http);
        const Aws::Esdk::KmsClient kms(config);
        const Aws::Esdk::DdbClient ddb(config);
        Aws::Esdk::Client esdk;

        handle_request(kms, ddb, esdk, credentials_for_request());

        std::cout << "Success! Encryption and decryption completed successfully.\n";
    } catch (const std::exception& e) {
        std::cerr << "Error: " << e.what() << "\n";
        return 1;
    }
    return 0;
}
