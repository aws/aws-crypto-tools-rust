// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

#[allow(clippy::duplicate_mod)]
mod fixtures;
mod test_helpers;

use aws_esdk::{DecryptStreamInput, EncryptStreamInput, EncryptionContext};
use test_helpers::{
    CallStyle, multi_frame_signed_for_stream, multi_frame_unsigned_for_stream, run_decrypt_stream,
    run_encrypt_stream, test_keyring,
};

// Round-trips plaintext via the streaming encrypt/decrypt path. Iterates over
// CallStyle so both the free `encrypt_stream`/`decrypt_stream` functions AND
// `Esdk::default().encrypt_stream`/`decrypt_stream` are exercised by this one
// test. A failure under either path will name the offending CallStyle.
#[tokio::test(flavor = "multi_thread")]
async fn test_streaming_encrypt_decrypt_round_trip() {
    for style in CallStyle::ALL {
        let keyring = test_keyring().await;
        let plaintext = b"hello streaming world";

        // Encrypt via streaming API
        let ec = EncryptionContext::new();
        let enc_input = EncryptStreamInput::builder()
            .encryption_context(ec.clone())
            .keyring(keyring.clone())
            .build()
            .unwrap();

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
        //= reason=encrypt_stream accepts a SafeRead (Cursor) as input; the round-trip succeeds, proving the streaming-input mechanism works
        //# In order to support streaming, the operation MUST accept some input within a streaming framework.
        //
        //= spec/client-apis/encrypt.md#plaintext
        //= type=test
        //= reason=the round-trip with a Cursor input source succeeds, proving plaintext can be streamed to encrypt
        //# This input MAY be [streamed](streaming.md) to this operation.
        run_encrypt_stream(style, &mut pt_cursor, &mut ciphertext, &enc_input)
            .await
            .unwrap_or_else(|e| panic!("encrypt_stream failed under {style:?}: {e:?}"));

        //= spec/client-apis/encrypt.md#encrypted-message
        //= type=test
        //= reason=the round-trip with a Vec<u8> ciphertext sink succeeds, proving the encrypted message can be streamed
        //# This operation MAY [stream](streaming.md) the encrypted message.
        assert!(
            !ciphertext.is_empty(),
            "ciphertext must not be empty (style: {style:?})"
        );

        // Decrypt via streaming API
        let dec_input = DecryptStreamInput::builder()
            .encryption_context(ec)
            .keyring(keyring)
            .build()
            .unwrap();
        let mut ct_cursor = std::io::Cursor::new(&ciphertext[..]);
        let mut decrypted: Vec<u8> = Vec::new();

        //= spec/client-apis/streaming.md#outputs
        //= type=test
        //= reason=the Vec<u8> receives bytes via SafeWrite::write(), which is the mechanism for releasing output bytes
        //# - There MUST be a mechanism for output bytes to be released.
        //
        //= spec/client-apis/streaming.md#outputs
        //= type=test
        //= reason=decrypt_stream writes output to a Vec<u8> via SafeWrite; the non-empty result proves streaming output
        //# In order to support streaming, the operation MUST produce some output within a streaming framework.
        run_decrypt_stream(style, &mut ct_cursor, &mut decrypted, &dec_input)
            .await
            .unwrap_or_else(|e| panic!("decrypt_stream failed under {style:?}: {e:?}"));

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
        assert_eq!(
            decrypted, plaintext,
            "round-trip plaintext must match (style: {style:?})"
        );
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn test_decrypt_stream_multi_frame_signed_rejected() {
    // multi_frame_signed_for_stream produces a 30-byte / frame_length=10 ECDSA-P384
    // payload (3 frames: 2 regular + final). decrypt_stream rejects it without
    // releasing any plaintext.
    for style in CallStyle::ALL {
        let (_plaintext, keyring, ct) = multi_frame_signed_for_stream().await;

        let dec_input = DecryptStreamInput::builder()
            .keyring(keyring)
            .build()
            .unwrap();

        let mut ct_cursor = std::io::Cursor::new(&ct[..]);
        let mut output: Vec<u8> = Vec::new();
        let err = run_decrypt_stream(style, &mut ct_cursor, &mut output, &dec_input)
            .await
            .expect_err("multi-frame signed message must fail in streaming mode");
        assert!(
            err.is_validation(),
            "expected Validation under {style:?}, got {:?}",
            err
        );

        assert!(
            output.is_empty(),
            "no plaintext must be released before signature verification (style: {style:?})"
        );
    }
}

// Multi-frame unsigned payloads round-trip in streaming mode because each frame
// is individually authenticated via AES-GCM (no trailing signature).
#[tokio::test(flavor = "multi_thread")]
async fn test_decrypt_stream_multi_frame_unsigned_accepted() {
    for style in CallStyle::ALL {
        let (plaintext, keyring, ct) = multi_frame_unsigned_for_stream().await;

        let dec_input = DecryptStreamInput::builder()
            .keyring(keyring)
            .build()
            .unwrap();

        let mut ct_cursor = std::io::Cursor::new(&ct[..]);
        let mut output: Vec<u8> = Vec::new();
        run_decrypt_stream(style, &mut ct_cursor, &mut output, &dec_input)
            .await
            .unwrap_or_else(|e| panic!("decrypt_stream failed under {style:?}: {e:?}"));
        assert_eq!(
            output, plaintext,
            "multi-frame unsigned round-trip mismatch under {style:?}"
        );
    }
}

// EncryptStreamInputBuilder::build() and DecryptStreamInputBuilder::build()
// reject an input that sets neither keyring nor cmm, and one that sets both.
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
    let neither = EncryptStreamInput::builder().build();
    let both = EncryptStreamInput::builder()
        .keyring(keyring.clone())
        .cmm(cmm.clone())
        .build();
    for (case, result) in [("neither", neither), ("both", both)] {
        let err = result.expect_err("EncryptStreamInput build must fail");
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
    let neither = DecryptStreamInput::builder().build();
    let both = DecryptStreamInput::builder()
        .keyring(keyring)
        .cmm(cmm)
        .build();
    for (case, result) in [("neither", neither), ("both", both)] {
        let err = result.expect_err("DecryptStreamInput build must fail");
        assert!(
            err.is_validation(),
            "expected Validation error for {case}, got {:?}",
            err
        );
    }
}

// An async source that hands out one byte per read and pends between reads,
// and a sink that accepts at most three bytes per write.
// The round trip through them checks that the streaming APIs resume
// correctly after every partial and pending read and write.
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

    let enc_input = EncryptStreamInput::builder()
        .keyring(keyring.clone())
        .algorithm_suite_id(aws_esdk::AlgorithmSuiteId::AlgAes256GcmHkdfSha512CommitKey)
        .build()
        .unwrap();
    let mut ciphertext = Vec::new();
    aws_esdk::encrypt_stream(
        Trickle::new(plaintext.as_slice()),
        Trickle::new(&mut ciphertext),
        &enc_input,
    )
    .await
    .unwrap();

    let dec_input = DecryptStreamInput::builder()
        .keyring(keyring)
        .build()
        .unwrap();
    let mut decrypted = Vec::new();
    aws_esdk::decrypt_stream(
        Trickle::new(ciphertext.as_slice()),
        Trickle::new(&mut decrypted),
        &dec_input,
    )
    .await
    .unwrap();

    assert_eq!(decrypted, plaintext);
}

// On a single-threaded runtime, another task runs only when this one yields.
// A large one-shot encrypt and decrypt must let it run.
#[tokio::test(flavor = "current_thread")]
async fn test_large_message_yields_to_other_tasks() {
    use std::sync::Arc;
    use std::sync::atomic::{AtomicU64, Ordering};

    let ticks = Arc::new(AtomicU64::new(0));
    let ticker = tokio::spawn({
        let ticks = ticks.clone();
        async move {
            loop {
                ticks.fetch_add(1, Ordering::Relaxed);
                tokio::task::yield_now().await;
            }
        }
    });

    let keyring = test_keyring().await;
    let plaintext = vec![0u8; 4 << 20];
    let ciphertext = aws_esdk::encrypt(
        &aws_esdk::EncryptInput::builder()
            .plaintext(&plaintext)
            .keyring(keyring.clone())
            .algorithm_suite_id(aws_esdk::AlgorithmSuiteId::AlgAes256GcmHkdfSha512CommitKey)
            .build()
            .unwrap(),
    )
    .await
    .unwrap()
    .ciphertext;
    let after_encrypt = ticks.load(Ordering::Relaxed);
    assert!(after_encrypt > 0, "the ticker never ran during encrypt");

    aws_esdk::decrypt(
        &aws_esdk::DecryptInput::builder()
            .ciphertext(&ciphertext)
            .keyring(keyring)
            .build()
            .unwrap(),
    )
    .await
    .unwrap();
    assert!(
        ticks.load(Ordering::Relaxed) > after_encrypt,
        "the ticker never ran during decrypt"
    );
    ticker.abort();
}

// A std::io reader and writer passed through SyncReader and SyncWriter round-trip.
#[tokio::test]
async fn test_streaming_round_trip_through_sync_adapters() {
    use aws_esdk::io::{SyncReader, SyncWriter};

    let keyring = test_keyring().await;
    let plaintext: Vec<u8> = (0..=255u8).cycle().take(4096 + 17).collect();

    let enc_input = EncryptStreamInput::builder()
        .keyring(keyring.clone())
        .algorithm_suite_id(aws_esdk::AlgorithmSuiteId::AlgAes256GcmHkdfSha512CommitKey)
        .build()
        .unwrap();
    let mut ciphertext = SyncWriter::new(Vec::new());
    aws_esdk::encrypt_stream(
        SyncReader::new(std::io::Cursor::new(&plaintext)),
        &mut ciphertext,
        &enc_input,
    )
    .await
    .unwrap();
    let ciphertext = ciphertext.into_inner();

    let dec_input = DecryptStreamInput::builder()
        .keyring(keyring)
        .build()
        .unwrap();
    let mut decrypted = SyncWriter::new(Vec::new());
    aws_esdk::decrypt_stream(
        SyncReader::new(ciphertext.as_slice()),
        &mut decrypted,
        &dec_input,
    )
    .await
    .unwrap();

    assert_eq!(decrypted.into_inner(), plaintext);
}
