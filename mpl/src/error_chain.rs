// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

//! Helpers for inspecting the `source()` chain of an MPL error.
//!
//! An error that wraps a lower-level failure keeps it as a cause, so an AWS
//! SDK error raised inside the keystore is still reachable from the
//! [`MaterialsError`](crate::structures::MaterialsError) a keyring hands
//! back.

use std::error::Error;

use aws_sdk_dynamodb::error::ProvideErrorMetadata;

/// Search `err` and its `source()` chain for an error of type `E`.
///
/// Use this to recover a concrete AWS SDK error from an MPL error:
///
/// ```no_run
/// use aws_crypto_mpl::error_chain::find_in_error_chain;
/// use aws_sdk_kms::error::SdkError;
/// use aws_sdk_kms::operation::decrypt::DecryptError;
/// # fn example(err: &aws_crypto_mpl::structures::MaterialsError) {
/// if let Some(sdk) = find_in_error_chain::<SdkError<DecryptError>>(err) {
///     if sdk.as_service_error().is_some_and(DecryptError::is_incorrect_key_exception) {
///         // the branch key's ciphertext was encrypted under a different KMS key
///     }
/// }
/// # }
/// ```
///
/// The type must be named exactly, including the `SdkError` response
/// parameter, which defaults to the SDK's `HttpResponse`. A downcast to a
/// type from a different version of the same SDK crate silently yields
/// `None`; [`aws_sdk_kms`](crate::aws_sdk_kms) and
/// [`aws_sdk_dynamodb`](crate::aws_sdk_dynamodb) are re-exported so the
/// version matches.
pub fn find_in_error_chain<'a, E>(err: &'a (dyn Error + 'static)) -> Option<&'a E>
where
    E: Error + 'static,
{
    let mut link: Option<&'a (dyn Error + 'static)> = Some(err);
    while let Some(current) = link {
        if let Some(found) = current.downcast_ref::<E>() {
            return Some(found);
        }
        link = current.source();
    }
    None
}

/// The AWS service error code (`"AccessDeniedException"`,
/// `"ThrottlingException"`, …) for the SDK failure underlying `err`, if any.
///
/// Walks the `source()` chain, so this works on any error this crate
/// returns — a `MaterialsError` from a keyring as well as a `KeystoreError`
/// — without the caller knowing which AWS operation was in flight.
///
/// Returns `None` when the chain holds no SDK error, and also when the SDK
/// error is not a *service* error: per
/// `aws_smithy_runtime_api::client::result`, construction, timeout,
/// dispatch, and response-parsing failures carry no service metadata, so a
/// missing-credentials or connection failure has no code. Match on
/// [`KeystoreError::kind`](crate::KeystoreError::kind) to separate those
/// from a rejection by the service.
pub fn aws_service_error_code<'a>(err: &'a (dyn Error + 'static)) -> Option<&'a str> {
    // A new arm is required for every AWS operation this crate invokes: the
    // lookup is a downcast, which matches one concrete type.
    macro_rules! code_if_matches {
        ($e:expr, $($ty:ty),+ $(,)?) => {{
            $(
                if let Some(sdk) = $e.downcast_ref::<$ty>() {
                    return ProvideErrorMetadata::code(sdk);
                }
            )+
        }};
    }

    let mut link: Option<&'a (dyn Error + 'static)> = Some(err);
    while let Some(current) = link {
        code_if_matches!(
            current,
            aws_sdk_kms::error::SdkError<aws_sdk_kms::operation::decrypt::DecryptError>,
            aws_sdk_kms::error::SdkError<
                aws_sdk_kms::operation::generate_data_key_without_plaintext::GenerateDataKeyWithoutPlaintextError,
            >,
            aws_sdk_kms::error::SdkError<aws_sdk_kms::operation::re_encrypt::ReEncryptError>,
            aws_sdk_dynamodb::error::SdkError<aws_sdk_dynamodb::operation::get_item::GetItemError>,
            aws_sdk_dynamodb::error::SdkError<
                aws_sdk_dynamodb::operation::describe_table::DescribeTableError,
            >,
            aws_sdk_dynamodb::error::SdkError<
                aws_sdk_dynamodb::operation::create_table::CreateTableError,
            >,
            aws_sdk_dynamodb::error::SdkError<
                aws_sdk_dynamodb::operation::transact_write_items::TransactWriteItemsError,
            >,
        );
        link = current.source();
    }
    None
}
