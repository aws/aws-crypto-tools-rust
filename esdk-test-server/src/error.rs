//! The two modeled TestServer errors and their rpcv2Cbor wire form.

/// A modeled TestServer error.
#[derive(Debug, Clone)]
pub enum ServerError {
    /// Framework-side failure (bad/unknown clientId, unset variant, streaming on
    /// a non-streaming server, any uncaught error).
    Generic(String),
    /// A failure forwarded from the underlying ESDK; the message is the ESDK
    /// error's message.
    Esdk(String),
}

const NS: &str = "aws.cryptography.esdk.testserver";

impl ServerError {
    pub fn generic(message: impl Into<String>) -> Self {
        Self::Generic(message.into())
    }

    pub fn esdk(message: impl Into<String>) -> Self {
        Self::Esdk(message.into())
    }

    /// Map a vendored-MPL error to the forwarded-ESDK error variant.
    pub fn from_mpl(e: aws_mpl_legacy::error::Error) -> Self {
        Self::Esdk(e.message)
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
            Self::Generic(m) | Self::Esdk(m) => m,
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
