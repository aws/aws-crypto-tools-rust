// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

// A child process created by fork() can use the shim with objects it creates itself,
// even after the parent has used the shim.
// The parent uses the shim before and after the child runs, so neither process breaks the other.

#include <chrono>
#include <csignal>
#include <cstdint>
#include <cstdio>
#include <sstream>
#include <string>
#include <vector>

#include <sys/wait.h>
#include <unistd.h>

#include <aws/esdk/EncryptionSDK.h>

namespace {

constexpr unsigned CHILD_TIMEOUT_SECONDS = 30;

// Encrypts and decrypts with a new keyring, once in one call and once as a stream.
bool round_trip() {
    const std::vector<std::uint8_t> wrapping_key(32, 0x01);
    const Aws::Esdk::RawAesKeyring keyring("fork-test", "fork-test", wrapping_key,
                                           Aws::Esdk::AesWrappingAlgorithm::AlgAes256GcmIv12Tag16);
    const Aws::Esdk::Client esdk;
    const std::string plaintext = "fork test";

    const auto encrypted = esdk.encrypt(plaintext, keyring);
    if (esdk.decrypt(encrypted.ciphertext, keyring).plaintext.as_string_view() != plaintext) {
        return false;
    }

    // Streams run on the shim's runtime threads, which fork() does not copy.
    std::istringstream plain_in(plaintext);
    std::stringstream cipher;
    esdk.encrypt_stream(plain_in, cipher, keyring);
    std::ostringstream plain_out;
    esdk.decrypt_stream(cipher, plain_out, keyring);
    return plain_out.str() == plaintext;
}

// Makes a real DynamoDB call, which waits on the runtime's network I/O.
// The made-up credentials make the call fail, so it needs network access but no AWS account.
bool network_call_returns() {
    const auto config = Aws::Esdk::AwsSdkClientConfig().with_region("us-west-2").with_credentials(
        Aws::Esdk::Credentials("AKIDFORKTEST", "fork-test-secret"));
    const Aws::Esdk::KeyStore key_store(
        "fork-test-table", "fork-test-table",
        "arn:aws:kms:us-west-2:111122223333:key/00000000-0000-0000-0000-000000000000",
        Aws::Esdk::KeyStoreOptions()
            .with_kms_client(Aws::Esdk::KmsClient(config))
            .with_ddb_client(Aws::Esdk::DdbClient(config)));
    const Aws::Esdk::HierarchicalKeyring keyring(key_store, "fork-test-branch-key", std::chrono::seconds(60));
    try {
        Aws::Esdk::Client().encrypt(std::string("fork test"), keyring);
    } catch (const Aws::Esdk::AwsEncryptionSdkException&) {
        return true;
    }
    return false;
}

}  // namespace

int main() {
    if (!round_trip()) {
        std::fprintf(stderr, "FAIL: parent round trip before fork\n");
        return 1;
    }

    const pid_t pid = fork();
    if (pid < 0) {
        std::perror("fork");
        return 1;
    }
    if (pid == 0) {
        // A hang in the child kills it, so the parent sees a failure instead of waiting forever.
        alarm(CHILD_TIMEOUT_SECONDS);
        try {
            if (!round_trip()) _exit(2);
            _exit(network_call_returns() ? 0 : 4);
        } catch (const std::exception& e) {
            std::fprintf(stderr, "child: %s\n", e.what());
            _exit(3);
        }
    }

    int status = 0;
    waitpid(pid, &status, 0);
    if (WIFSIGNALED(status)) {
        std::fprintf(stderr, "FAIL: child killed by signal %d (SIGALRM means it hung)\n",
                     WTERMSIG(status));
        return 1;
    }
    if (WEXITSTATUS(status) != 0) {
        std::fprintf(stderr, "FAIL: child exited with %d\n", WEXITSTATUS(status));
        return 1;
    }

    if (!round_trip()) {
        std::fprintf(stderr, "FAIL: parent round trip after fork\n");
        return 1;
    }
    std::printf("PASS: fork\n");
    return 0;
}
