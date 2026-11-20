// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

// A process forked before the shim is used can use the shim.
// A process forked after the shim is used gets a ValidationException instead of hanging.

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

Aws::Esdk::RawAesKeyring make_keyring() {
    const std::vector<std::uint8_t> wrapping_key(32, 0x01);
    return Aws::Esdk::RawAesKeyring("fork-test", "fork-test", wrapping_key,
                                    Aws::Esdk::AesWrappingAlgorithm::AlgAes256GcmIv12Tag16);
}

// Encrypts and decrypts, once in one call and once as a stream.
bool round_trip() {
    const auto keyring = make_keyring();
    const Aws::Esdk::Client esdk;
    const std::string plaintext = "fork test";

    const auto encrypted = esdk.encrypt(plaintext, keyring);
    if (esdk.decrypt(encrypted.ciphertext, keyring).plaintext.as_string_view() != plaintext) {
        return false;
    }

    std::istringstream plain_in(plaintext);
    std::stringstream cipher;
    esdk.encrypt_stream(plain_in, cipher, keyring);
    std::ostringstream plain_out;
    esdk.decrypt_stream(cipher, plain_out, keyring);
    return plain_out.str() == plaintext;
}

// True if encrypt, encrypt_stream and creating a KMS client all throw the fork error.
bool rejected_after_fork() {
    const auto keyring = make_keyring();
    const Aws::Esdk::Client esdk;
    const std::string plaintext = "fork test";
    int rejected = 0;
    try {
        esdk.encrypt(plaintext, keyring);
    } catch (const Aws::Esdk::ValidationException& e) {
        if (std::string(e.what()).find("before this process was forked") != std::string::npos) {
            ++rejected;
        }
    }
    try {
        std::istringstream plain_in(plaintext);
        std::stringstream cipher;
        esdk.encrypt_stream(plain_in, cipher, keyring);
    } catch (const Aws::Esdk::ValidationException& e) {
        if (std::string(e.what()).find("before this process was forked") != std::string::npos) {
            ++rejected;
        }
    }
    try {
        Aws::Esdk::KmsClient(Aws::Esdk::AwsSdkClientConfig().with_region("us-west-2"));
    } catch (const Aws::Esdk::ValidationException& e) {
        if (std::string(e.what()).find("before this process was forked") != std::string::npos) {
            ++rejected;
        }
    }
    return rejected == 3;
}

// Runs `check` in a child process. Returns false if it fails, throws or hangs.
bool in_child(bool (*check)(), const char* name) {
    const pid_t pid = fork();
    if (pid < 0) {
        std::perror("fork");
        return false;
    }
    if (pid == 0) {
        // Kill the child if it hangs, so the test fails instead of waiting forever.
        alarm(CHILD_TIMEOUT_SECONDS);
        try {
            _exit(check() ? 0 : 1);
        } catch (const std::exception& e) {
            std::fprintf(stderr, "%s: %s\n", name, e.what());
            _exit(2);
        }
    }
    int status = 0;
    waitpid(pid, &status, 0);
    if (WIFSIGNALED(status)) {
        std::fprintf(stderr, "FAIL: %s: child killed by signal %d\n", name, WTERMSIG(status));
        return false;
    }
    if (WEXITSTATUS(status) != 0) {
        std::fprintf(stderr, "FAIL: %s: child exited with %d\n", name, WEXITSTATUS(status));
        return false;
    }
    return true;
}

}  // namespace

int main() {
    // Accepts a child forked before the main process uses the shim
    if (!in_child(round_trip, "forked before use")) return 1;

    if (!round_trip()) {
        std::fprintf(stderr, "FAIL: main process round trip\n");
        return 1;
    }

    // Rejects a child forked after the main process uses the shim
    if (!in_child(rejected_after_fork, "forked after use")) return 1;

    // The rejected child did not break the main process
    if (!round_trip()) {
        std::fprintf(stderr, "FAIL: main process round trip after fork\n");
        return 1;
    }
    std::printf("PASS: fork\n");
    return 0;
}
