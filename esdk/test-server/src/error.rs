// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

//! The two modeled TestServer errors and their rpcv2Cbor wire form.

use aws_esdk::error::{ConflictReason, Resource};
use aws_esdk::Error;
use ciborium::value::Value;

/// A modeled TestServer error.
#[derive(Debug, Clone)]
pub enum ServerError {
    /// A failure outside an ESDK operation: a malformed request, an unknown clientId,
    /// a rejected CreateClient configuration, etc.
    Generic(String),
    /// A failure forwarded from the underlying ESDK, or an ESDK input this server rejects itself.
    Esdk(Box<Details>),
}

/// The members of `ESDKClientError`.
/// When `feature-config.json` turns the error checks on, the shared tests compare every member but `message`.
/// `ErrorFields` in commons' test-server-common/tests-support defines the formats.
#[derive(Debug, Clone, Default)]
pub struct Details {
    pub message: String,
    pub kind: Option<String>,
    pub service: Option<String>,
    pub resource: Option<String>,
    pub code: Option<String>,
    pub retryable: Option<bool>,
    pub retry_kind: Option<String>,
    pub conflict_reason: Option<String>,
}

const NS: &str = "aws.cryptography.esdk.testserver";

impl ServerError {
    pub fn generic(message: impl Into<String>) -> Self {
        Self::Generic(message.into())
    }

    /// An ESDK input this server rejects itself, before calling the ESDK.
    /// It has a message and nothing else.
    pub fn esdk(message: impl Into<String>) -> Self {
        Self::Esdk(Box::new(Details {
            message: message.into(),
            ..Details::default()
        }))
    }

    /// An error the ESDK returned, with every member the shared tests can check.
    pub fn from_esdk(e: Error) -> Self {
        Self::Esdk(Box::new(Details {
            message: e.to_string(),
            kind: Some(kind(&e).to_owned()),
            service: e.service().map(|s| s.as_str().to_owned()),
            resource: e.resource().map(resource),
            code: e.code().map(str::to_owned),
            retryable: Some(e.is_retryable()),
            retry_kind: e.retry_kind().map(|k| k.as_str().to_owned()),
            conflict_reason: match &e {
                Error::Conflict(c) => c.reason().map(|r| conflict_reason(r).to_owned()),
                _ => None,
            },
        }))
    }

    /// The `__type` shape id placed on the wire.
    pub fn type_id(&self) -> String {
        match self {
            Self::Generic(_) => format!("{NS}#GenericServerError"),
            Self::Esdk(_) => format!("{NS}#ESDKClientError"),
        }
    }

    pub fn message(&self) -> &str {
        match self {
            Self::Generic(m) => m,
            Self::Esdk(d) => &d.message,
        }
    }

    /// Serialize to the rpcv2Cbor error body: a CBOR map of `__type`, `message` and each member that has a value.
    pub fn to_cbor(&self) -> Vec<u8> {
        let text = |s: &str| Value::Text(s.to_owned());
        let mut map = vec![
            (text("__type"), text(&self.type_id())),
            (text("message"), text(self.message())),
        ];
        if let Self::Esdk(d) = self {
            let members = [
                ("kind", &d.kind),
                ("service", &d.service),
                ("resource", &d.resource),
                ("code", &d.code),
                ("retryKind", &d.retry_kind),
                ("conflictReason", &d.conflict_reason),
            ];
            for (name, value) in members {
                if let Some(value) = value {
                    map.push((text(name), text(value)));
                }
            }
            if let Some(retryable) = d.retryable {
                map.push((text("retryable"), Value::Bool(retryable)));
            }
        }
        let mut buf = Vec::new();
        // Serializing a hand-built Value to a Vec never fails.
        ciborium::into_writer(&Value::Map(map), &mut buf).expect("CBOR error encoding");
        buf
    }
}

/// The variant name, which the shared tests call the error's kind.
fn kind(e: &Error) -> &'static str {
    match e {
        Error::Validation(_) => "Validation",
        Error::InvalidMaterials(_) => "InvalidMaterials",
        Error::EncryptionContextMismatch(_) => "EncryptionContextMismatch",
        Error::NoMatchingDataKey(_) => "NoMatchingDataKey",
        Error::Cryptographic(_) => "Cryptographic",
        Error::AccessDenied(_) => "AccessDenied",
        Error::ResourceNotFound(_) => "ResourceNotFound",
        Error::Throttling(_) => "Throttling",
        Error::Conflict(_) => "Conflict",
        Error::Service(_) => "Service",
        Error::Dispatch(_) => "Dispatch",
        Error::Serialization(_) => "Serialization",
        Error::Io(_) => "Io",
        Error::Internal(_) => "Internal",
        // No test expects "Unknown", so a kind check on a new variant fails until it is listed here.
        _ => "Unknown",
    }
}

/// The resource as `Type:id`, for example `KmsKey:arn:aws:kms:...` or `Cache`.
fn resource(r: &Resource) -> String {
    match r {
        Resource::KmsKey(k) => format!("KmsKey:{}", k.arn()),
        Resource::DynamoDbTable(t) => format!("DynamoDbTable:{}", t.name()),
        Resource::BranchKey(b) => format!("BranchKey:{}", b.id()),
        Resource::Cache(_) => "Cache".to_owned(),
        Resource::Keyring(k) => format!("Keyring:{}", k.name()),
        Resource::Cmm(c) => format!("Cmm:{}", c.name()),
        _ => "Unknown".to_owned(),
    }
}

fn conflict_reason(r: &ConflictReason) -> &'static str {
    match r {
        ConflictReason::AlreadyExists => "AlreadyExists",
        ConflictReason::ConcurrentModification => "ConcurrentModification",
        _ => "Unknown",
    }
}
