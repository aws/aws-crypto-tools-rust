// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

//! The two modeled TestServer errors and their rpcv2Cbor wire form.

use ciborium::value::Value;

/// A modeled TestServer error.
#[derive(Debug, Clone)]
pub enum ServerError {
    /// Framework-side failure (bad request, unknown operation, unknown ID, etc.).
    Generic(String),
    /// A failure forwarded from the underlying MPL.
    Mpl {
        message: String,
        /// The messages of the failures the MPL collected, in order; empty when it collected none.
        collected_errors: Vec<String>,
    },
}

const NS: &str = "aws.cryptography.mpl.testserver";

impl ServerError {
    pub fn generic(message: impl Into<String>) -> Self {
        Self::Generic(message.into())
    }

    /// An `MPLClientError` the server raises itself, with no collected errors.
    pub fn mpl(message: impl Into<String>) -> Self {
        Self::Mpl {
            message: message.into(),
            collected_errors: Vec::new(),
        }
    }

    /// An `MPLClientError` for an error the MPL returned, with the failures it collected.
    pub fn from_mpl(error: aws_crypto_mpl::Error) -> Self {
        let message = error.to_string();
        let failures = error.failures();
        // failures() yields the error itself when it collected nothing.
        let collected_none = failures.len() == 1 && failures[0].to_string() == message;
        let collected_errors = if collected_none {
            Vec::new()
        } else {
            failures.iter().map(ToString::to_string).collect()
        };
        Self::Mpl {
            message,
            collected_errors,
        }
    }

    /// The `__type` shape id placed on the wire.
    pub fn type_id(&self) -> String {
        match self {
            Self::Generic(_) => format!("{NS}#GenericServerError"),
            Self::Mpl { .. } => format!("{NS}#MPLClientError"),
        }
    }

    pub fn message(&self) -> &str {
        match self {
            Self::Generic(message) | Self::Mpl { message, .. } => message,
        }
    }

    /// Serialize to the rpcv2Cbor error body: a CBOR map `{__type, message}`,
    /// plus `collectedErrors` when the MPL collected any.
    pub fn to_cbor(&self) -> Vec<u8> {
        let mut entries = vec![
            (
                Value::Text("__type".to_owned()),
                Value::Text(self.type_id()),
            ),
            (
                Value::Text("message".to_owned()),
                Value::Text(self.message().to_owned()),
            ),
        ];
        if let Self::Mpl {
            collected_errors, ..
        } = self
            && !collected_errors.is_empty()
        {
            entries.push((
                Value::Text("collectedErrors".to_owned()),
                Value::Array(
                    collected_errors
                        .iter()
                        .map(|m| Value::Text(m.clone()))
                        .collect(),
                ),
            ));
        }
        let mut buf = Vec::new();
        ciborium::into_writer(&Value::Map(entries), &mut buf).expect("CBOR error encoding");
        buf
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

        let error = ServerError::Mpl {
            message: "failed".to_owned(),
            collected_errors: vec!["first".to_owned(), "second".to_owned()],
        };
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
