// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

//! The two modeled TestServer errors and their rpcv2Cbor wire form.

use aws_crypto_mpl::Error;
use aws_crypto_mpl::error::{ConflictReason, Resource};
use ciborium::value::Value;

/// A modeled TestServer error.
#[derive(Debug, Clone)]
pub enum ServerError {
    /// Framework-side failure (bad request, unknown operation, unknown ID, etc.).
    Generic(String),
    /// A failure forwarded from the underlying MPL, or an MPL input this server rejects itself.
    Mpl(Box<Details>),
}

/// The members of `MPLClientError`.
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
    /// The messages of the failures the MPL collected, in order; empty when it collected none.
    pub collected_errors: Vec<String>,
}

const NS: &str = "aws.cryptography.mpl.testserver";

impl ServerError {
    pub fn generic(message: impl Into<String>) -> Self {
        Self::Generic(message.into())
    }

    /// An MPL input this server rejects itself, before calling the MPL.
    /// It has a message and nothing else.
    pub fn mpl(message: impl Into<String>) -> Self {
        Self::Mpl(Box::new(Details {
            message: message.into(),
            ..Details::default()
        }))
    }

    /// An error the MPL returned, with every member the shared tests can check.
    pub fn from_mpl(e: Error) -> Self {
        let message = e.to_string();
        let failures = e.failures();
        // failures() yields the error itself when it collected nothing.
        let collected_none = failures.len() == 1 && failures[0].to_string() == message;
        let collected_errors = if collected_none {
            Vec::new()
        } else {
            failures.iter().map(ToString::to_string).collect()
        };
        Self::Mpl(Box::new(Details {
            message,
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
            collected_errors,
        }))
    }

    /// The `__type` shape id placed on the wire.
    pub fn type_id(&self) -> String {
        match self {
            Self::Generic(_) => format!("{NS}#GenericServerError"),
            Self::Mpl(_) => format!("{NS}#MPLClientError"),
        }
    }

    pub fn message(&self) -> &str {
        match self {
            Self::Generic(m) => m,
            Self::Mpl(d) => &d.message,
        }
    }

    /// Serialize to the rpcv2Cbor error body: a CBOR map of `__type`, `message` and each member that has a value.
    pub fn to_cbor(&self) -> Vec<u8> {
        let text = |s: &str| Value::Text(s.to_owned());
        let mut map = vec![
            (text("__type"), text(&self.type_id())),
            (text("message"), text(self.message())),
        ];
        if let Self::Mpl(d) = self {
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
            if !d.collected_errors.is_empty() {
                map.push((
                    text("collectedErrors"),
                    Value::Array(
                        d.collected_errors
                            .iter()
                            .map(|m| Value::Text(m.clone()))
                            .collect(),
                    ),
                ));
            }
        }
        let mut buf = Vec::new();
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

#[cfg(test)]
mod tests {
    use super::*;

    fn decode(error: &ServerError) -> Vec<(String, Value)> {
        let Value::Map(entries) = ciborium::from_reader(&error.to_cbor()[..]).unwrap() else {
            panic!("error body is not a CBOR map");
        };
        entries
            .into_iter()
            .map(|(k, v)| (k.into_text().unwrap(), v))
            .collect()
    }

    #[test]
    fn collected_errors_go_on_the_wire_only_when_present() {
        let none = decode(&ServerError::mpl("failed"));
        assert!(none.iter().all(|(k, _)| k != "collectedErrors"));

        let error = ServerError::Mpl(Box::new(Details {
            message: "failed".to_owned(),
            collected_errors: vec!["first".to_owned(), "second".to_owned()],
            ..Details::default()
        }));
        let collected = decode(&error)
            .into_iter()
            .find(|(k, _)| k == "collectedErrors")
            .map(|(_, v)| v)
            .expect("collectedErrors");
        assert_eq!(
            collected,
            Value::Array(vec![
                Value::Text("first".to_owned()),
                Value::Text("second".to_owned())
            ])
        );
    }
}
