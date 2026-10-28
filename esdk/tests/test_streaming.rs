// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

#[allow(clippy::duplicate_mod)]
mod fixtures;
mod test_helpers;

use aws_esdk::Client;
use aws_esdk::keyring::RawAesKeyring;
use aws_esdk::types::{EncryptionContext, SignedStreaming};
use test_helpers::{
    aes_keyring, encrypt_with_signing_suite, multi_frame_signed_for_stream,
    multi_frame_unsigned_for_stream, test_keyring,
};

/// Stream-decrypt `ct` with `setting`, returning the result and the bytes written, even on failure.
async fn decrypt_stream_with(
    keyring: RawAesKeyring,
    ct: &[u8],
    setting: SignedStreaming,
) -> (Result<(), aws_esdk::Error>, Vec<u8>) {
    let mut ct_cursor = std::io::Cursor::new(ct);
    let mut output: Vec<u8> = Vec::new();
    let result = Client::default()
        .decrypt_stream()
        .keyring(keyring)
        .signed_streaming(setting)
        .ciphertext(&mut ct_cursor)
        .plaintext(&mut output)
        .send()
        .await
        .map(|_| ());
    (result, output)
}

#[tokio::test(flavor = "multi_thread")]
async fn test_streaming_encrypt_decrypt_round_trip() {
    let keyring = test_keyring().await;
    let esdk = Client::default();
    let plaintext = b"hello streaming world";

    let ec = EncryptionContext::new();
    let mut pt_cursor = std::io::Cursor::new(&plaintext[..]);
    let mut ciphertext: Vec<u8> = Vec::new();

    //= spec/client-apis/streaming.md#inputs
    //= type=test
    //= reason=encrypt_stream reads from the Cursor incrementally, making bytes consumable; the round-trip succeeds
    //# - There MUST be a mechanism for input bytes to become consumable.
    //
    //= spec/client-apis/streaming.md#inputs
    //= type=test
    //= reason=the Cursor returns Ok(0) at EOF; encrypt_stream completes successfully, proving the EOF mechanism works
    //# - There MUST be a mechanism to indicate that there are no more input bytes.
    //
    //= spec/client-apis/streaming.md#inputs
    //= type=test
    //= reason=encrypt_stream accepts an AsyncRead (Cursor) as input; the round-trip succeeds, proving the streaming-input mechanism works
    //# In order to support streaming, the operation MUST accept some input within a streaming framework.
    //
    //= spec/client-apis/encrypt.md#plaintext
    //= type=test
    //= reason=the round-trip with a Cursor input source succeeds, proving plaintext can be streamed to encrypt
    //# This input MAY be [streamed](streaming.md) to this operation.
    esdk.encrypt_stream()
        .set_encryption_context(Some(ec.clone()))
        .keyring(keyring.clone())
        .plaintext(&mut pt_cursor)
        .ciphertext(&mut ciphertext)
        .send()
        .await
        .unwrap();

    //= spec/client-apis/encrypt.md#encrypted-message
    //= type=test
    //= reason=the round-trip with a Vec<u8> ciphertext sink succeeds, proving the encrypted message can be streamed
    //# This operation MAY [stream](streaming.md) the encrypted message.
    assert!(!ciphertext.is_empty(), "ciphertext must not be empty");

    let mut ct_cursor = std::io::Cursor::new(&ciphertext[..]);
    let mut decrypted: Vec<u8> = Vec::new();

    //= spec/client-apis/streaming.md#outputs
    //= type=test
    //= reason=the Vec<u8> receives bytes via AsyncWrite::poll_write(), which is the mechanism for releasing output bytes
    //# - There MUST be a mechanism for output bytes to be released.
    //
    //= spec/client-apis/streaming.md#outputs
    //= type=test
    //= reason=decrypt_stream writes output to a Vec<u8> via AsyncWrite; the non-empty result proves streaming output
    //# In order to support streaming, the operation MUST produce some output within a streaming framework.
    esdk.decrypt_stream()
        .set_encryption_context(Some(ec))
        .keyring(keyring)
        .ciphertext(&mut ct_cursor)
        .plaintext(&mut decrypted)
        .send()
        .await
        .unwrap();

    //= spec/client-apis/streaming.md#overview
    //= type=test
    //= reason=encrypt_stream and decrypt_stream are the streaming APIs; the round-trip proves both work
    //# The AWS Encryption SDK MAY provide APIs that enable streamed [encryption](encrypt.md)
    //# and [decryption](decrypt.md).
    //
    //= spec/client-apis/streaming.md#outputs
    //= type=test
    //= reason=decrypt_stream returns Ok only after all plaintext is written; the round-trip assertion confirms this
    //# Operations MUST NOT indicate completion or success until an end to the output has been indicated.
    //
    //= spec/client-apis/streaming.md#outputs
    //= type=test
    //= reason=decrypt_stream's Ok return means all plaintext is in the output, proving end-of-output signaling
    //# - There MUST be a mechanism to indicate that the entire output has been released.
    assert_eq!(decrypted, plaintext, "round-trip plaintext must match");
}

#[tokio::test(flavor = "multi_thread")]
async fn test_decrypt_stream_multi_frame_signed_rejected() {
    // multi_frame_signed_for_stream produces a 30-byte / frame_length=10 ECDSA-P384
    // payload (3 frames: 2 regular + final). decrypt_stream rejects it without
    // releasing any plaintext.
    let (_plaintext, keyring, ct) = multi_frame_signed_for_stream().await;

    let mut ct_cursor = std::io::Cursor::new(&ct[..]);
    let mut output: Vec<u8> = Vec::new();
    let err = Client::default()
        .decrypt_stream()
        .keyring(keyring)
        .ciphertext(&mut ct_cursor)
        .plaintext(&mut output)
        .send()
        .await
        .expect_err("multi-frame signed message must fail in streaming mode");
    assert!(err.is_validation(), "expected Validation, got {:?}", err);

    assert!(
        output.is_empty(),
        "no plaintext must be released before signature verification"
    );
}

// Multi-frame unsigned payloads round-trip in streaming mode because each frame
// is individually authenticated via AES-GCM (no trailing signature).
#[tokio::test(flavor = "multi_thread")]
async fn test_decrypt_stream_multi_frame_unsigned_accepted() {
    let (plaintext, keyring, ct) = multi_frame_unsigned_for_stream().await;

    let mut ct_cursor = std::io::Cursor::new(&ct[..]);
    let mut output: Vec<u8> = Vec::new();
    Client::default()
        .decrypt_stream()
        .keyring(keyring)
        .ciphertext(&mut ct_cursor)
        .plaintext(&mut output)
        .send()
        .await
        .unwrap();
    assert_eq!(
        output, plaintext,
        "multi-frame unsigned round-trip mismatch"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn test_decrypt_stream_release_regular_frames_round_trips() {
    let (plaintext, keyring, ct) = multi_frame_signed_for_stream().await;
    //= spec/client-apis/decrypt.md#decrypt-the-message-body
    //= type=test
    //# - If the streamed Decrypt operation is using an algorithm suite with a signature algorithm,
    //# all plaintext decrypted from regular frames SHOULD be released as soon as the above calculation,
    //# including tag verification, succeeds.
    let (result, output) =
        decrypt_stream_with(keyring, &ct, SignedStreaming::ReleaseRegularFrames).await;
    result.unwrap();
    assert_eq!(output, plaintext);
}

#[tokio::test(flavor = "multi_thread")]
async fn test_decrypt_stream_release_regular_frames_holds_final_frame() {
    // Corrupt the signature.
    // Of the three 10-byte frames, only the two regular frames reach the output.
    let (plaintext, keyring, mut ct) = multi_frame_signed_for_stream().await;
    let last = ct.len() - 1;
    ct[last] ^= 0x01;
    //= spec/client-apis/decrypt.md#decrypt-the-message-body
    //= type=test
    //# Any plaintext decrypted from [nonframed data](../data-format/message-body.md#nonframed-data) or
    //# a final frame in a streamed Decrypt operation MUST NOT be released until [signature verification](#verify-the-signature)
    //# successfully completes.
    let (result, output) =
        decrypt_stream_with(keyring, &ct, SignedStreaming::ReleaseRegularFrames).await;
    assert!(result.unwrap_err().is_cryptographic());
    assert_eq!(output, plaintext[..20]);
}

#[tokio::test(flavor = "multi_thread")]
async fn test_decrypt_stream_reject_signed_fails_after_header() {
    // This keyring cannot decrypt the message.
    // A Validation error, not NoMatchingDataKey, shows decrypt fails before fetching materials.
    let ct = encrypt_with_signing_suite(b"single frame").await;
    //= spec/client-apis/decrypt.md#behavior
    //= type=test
    //# - The ESDK MUST provide a configuration option that causes the decryption operation
    //# to fail immediately after parsing the header if a signed algorithm suite is used.
    let (result, output) =
        decrypt_stream_with(aes_keyring(9).await, &ct, SignedStreaming::RejectSigned).await;
    assert!(result.unwrap_err().is_validation());
    assert!(output.is_empty());

    let (plaintext, keyring, ct) = multi_frame_unsigned_for_stream().await;
    let (result, output) = decrypt_stream_with(keyring, &ct, SignedStreaming::RejectSigned).await;
    result.unwrap();
    assert_eq!(output, plaintext);
}

#[tokio::test(flavor = "multi_thread")]
async fn test_streaming_rejects_neither_and_both_sources() {
    let keyring = test_keyring().await;
    let cmm = aws_crypto_mpl::cmm::DefaultCmm::new(keyring.clone());

    //= spec/client-apis/encrypt.md#input
    //= type=test
    //# The Encrypt operation MUST validate that exactly one keyring or CMM was provided by the caller.
    //
    //= spec/client-apis/encrypt.md#input
    //= type=test
    //# If the caller does not provide exactly one of a keyring or CMM, the Encrypt operation MUST fail.
    let esdk = Client::default();
    let neither = esdk
        .encrypt_stream()
        .plaintext(&b"pt"[..])
        .ciphertext(Vec::new())
        .send()
        .await;
    let both = esdk
        .encrypt_stream()
        .keyring(keyring.clone())
        .cmm(cmm.clone())
        .plaintext(&b"pt"[..])
        .ciphertext(Vec::new())
        .send()
        .await;
    for (case, result) in [("neither", neither), ("both", both)] {
        let err = result.expect_err("encrypt_stream must fail");
        assert!(
            err.is_validation(),
            "expected Validation error for {case}, got {:?}",
            err
        );
    }

    //= spec/client-apis/decrypt.md#input
    //= type=test
    //# The Decrypt operation MUST validate that exactly one of a keyring or CMM was provided by the caller.
    //
    //= spec/client-apis/decrypt.md#input
    //= type=test
    //# If the caller does not provide exactly one of a keyring or CMM, the Decrypt operation MUST fail.
    let neither = esdk
        .decrypt_stream()
        .ciphertext(&b""[..])
        .plaintext(Vec::new())
        .send()
        .await;
    let both = esdk
        .decrypt_stream()
        .keyring(keyring)
        .cmm(cmm)
        .ciphertext(&b""[..])
        .plaintext(Vec::new())
        .send()
        .await;
    for (case, result) in [("neither", neither), ("both", both)] {
        let err = result.expect_err("decrypt_stream must fail");
        assert!(
            err.is_validation(),
            "expected Validation error for {case}, got {:?}",
            err
        );
    }
}

// Reads one byte at a time with a pending poll between reads; writes at most three bytes at a time.
// Exercises resuming after every partial and pending read and write.
struct Trickle<T> {
    inner: T,
    ready: bool,
}

impl<T> Trickle<T> {
    fn new(inner: T) -> Self {
        Self {
            inner,
            ready: false,
        }
    }
}

impl<T: tokio::io::AsyncRead + Unpin> tokio::io::AsyncRead for Trickle<T> {
    fn poll_read(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &mut tokio::io::ReadBuf<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        if !std::mem::replace(&mut self.ready, true) {
            cx.waker().wake_by_ref();
            return std::task::Poll::Pending;
        }
        self.ready = false;
        let mut one = [0u8; 1];
        let mut one_buf = tokio::io::ReadBuf::new(&mut one);
        let poll = std::pin::Pin::new(&mut self.inner).poll_read(cx, &mut one_buf);
        if let std::task::Poll::Ready(Ok(())) = poll {
            buf.put_slice(one_buf.filled());
        }
        poll
    }
}

impl<T: tokio::io::AsyncWrite + Unpin> tokio::io::AsyncWrite for Trickle<T> {
    fn poll_write(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &[u8],
    ) -> std::task::Poll<std::io::Result<usize>> {
        if !std::mem::replace(&mut self.ready, true) {
            cx.waker().wake_by_ref();
            return std::task::Poll::Pending;
        }
        self.ready = false;
        let n = buf.len().min(3);
        std::pin::Pin::new(&mut self.inner).poll_write(cx, &buf[..n])
    }

    fn poll_flush(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        std::pin::Pin::new(&mut self.inner).poll_flush(cx)
    }

    fn poll_shutdown(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        std::pin::Pin::new(&mut self.inner).poll_shutdown(cx)
    }
}

#[tokio::test]
async fn test_streaming_round_trip_through_pending_partial_io() {
    let keyring = test_keyring().await;
    // Three frames, the last one partial.
    let plaintext: Vec<u8> = (0..=255u8).cycle().take(2 * 4096 + 100).collect();

    let esdk = Client::default();
    let mut ciphertext = Vec::new();
    esdk.encrypt_stream()
        .keyring(keyring.clone())
        .algorithm_suite_id(aws_esdk::types::AlgorithmSuiteId::AlgAes256GcmHkdfSha512CommitKey)
        .plaintext(Trickle::new(plaintext.as_slice()))
        .ciphertext(Trickle::new(&mut ciphertext))
        .send()
        .await
        .unwrap();

    let mut decrypted = Vec::new();
    esdk.decrypt_stream()
        .keyring(keyring)
        .ciphertext(Trickle::new(ciphertext.as_slice()))
        .plaintext(Trickle::new(&mut decrypted))
        .send()
        .await
        .unwrap();

    assert_eq!(decrypted, plaintext);
}

// On a single-threaded runtime, another task should run when the encrypt/decrypt task yields.
#[tokio::test(flavor = "current_thread")]
async fn test_large_message_yields_to_other_tasks() {
    use std::num::NonZeroU32;
    use std::sync::Arc;
    use std::sync::atomic::{AtomicU64, Ordering};

    let ticks = Arc::new(AtomicU64::new(0));
    let ticker = tokio::spawn({
        let ticks = ticks.clone();
        async move {
            loop {
                // The ticker should advance when encryption/decryption yields between frames.
                ticks.fetch_add(1, Ordering::Relaxed);
                tokio::task::yield_now().await;
            }
        }
    });

    let keyring = test_keyring().await;
    let plaintext = vec![0u8; 4 << 20];
    let esdk = aws_esdk::Client::default();
    for frame_length in [4096, 1 << 20] {
        let before_encrypt = ticks.load(Ordering::Relaxed);
        let ciphertext = esdk
            .encrypt()
            .plaintext(&plaintext)
            .keyring(keyring.clone())
            .algorithm_suite_id(aws_esdk::types::AlgorithmSuiteId::AlgAes256GcmHkdfSha512CommitKey)
            .frame_length(NonZeroU32::new(frame_length).unwrap())
            .send()
            .await
            .unwrap()
            .into_ciphertext()
            .into_inner();
        let after_encrypt = ticks.load(Ordering::Relaxed);
        assert!(
            after_encrypt > before_encrypt,
            "the ticker never ran during encrypt with {frame_length}-byte frames"
        );

        esdk.decrypt()
            .ciphertext(&ciphertext)
            .keyring(keyring.clone())
            .send()
            .await
            .unwrap();
        assert!(
            ticks.load(Ordering::Relaxed) > after_encrypt,
            "the ticker never ran during decrypt with {frame_length}-byte frames"
        );
    }
    ticker.abort();
}
