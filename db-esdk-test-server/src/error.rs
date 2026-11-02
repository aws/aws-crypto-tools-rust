// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

//! The two modeled TestServer errors and their rpcv2Cbor wire form.

/// A modeled TestServer error.
#[derive(Debug, Clone)]
pub enum ServerError {
    /// A failure in the test server itself: an unknown clientId, a malformed request, an unsupported operation, etc.
    Generic(String),
    /// A failure from the DB-ESDK library; the message is the library error's.
    Client(String),
}

const NS: &str = "aws.cryptography.dbesdk.testserver";

impl ServerError {
    pub fn generic(message: impl Into<String>) -> Self {
        Self::Generic(message.into())
    }

    pub fn client(message: impl Into<String>) -> Self {
        Self::Client(message.into())
    }

    /// The `__type` shape id placed on the wire.
    pub fn type_id(&self) -> String {
        match self {
            Self::Generic(_) => format!("{NS}#GenericServerError"),
            Self::Client(_) => format!("{NS}#DBESDKClientError"),
        }
    }

    pub fn message(&self) -> &str {
        match self {
            Self::Generic(m) | Self::Client(m) => m,
        }
    }

    /// Serialize to the rpcv2Cbor error body: a CBOR map `{__type, message}`.
    pub fn to_cbor(&self) -> Vec<u8> {
        let map = ciborium::value::Value::Map(vec![
            (
                ciborium::value::Value::Text("__type".to_owned()),
                ciborium::value::Value::Text(self.type_id()),
            ),
            (
                ciborium::value::Value::Text("message".to_owned()),
                ciborium::value::Value::Text(self.message().to_owned()),
            ),
        ]);
        let mut buf = Vec::new();
        // Serializing a hand-built Value to a Vec never fails.
        ciborium::into_writer(&map, &mut buf).expect("CBOR error encoding");
        buf
    }
}

impl From<aws_db_esdk::Error> for ServerError {
    fn from(e: aws_db_esdk::Error) -> Self {
        Self::client(e.to_string())
    }
}
