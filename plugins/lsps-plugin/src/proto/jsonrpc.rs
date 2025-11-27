use serde::{de::DeserializeOwned, Deserialize, Serialize};
use serde_json::{self, Value};
use std::fmt;
use thiserror::Error;

// Constants for JSON-RPC error codes.
pub const PARSE_ERROR: i64 = -32700;
pub const INVALID_REQUEST: i64 = -32600;
pub const METHOD_NOT_FOUND: i64 = -32601;
pub const INVALID_PARAMS: i64 = -32602;
pub const INTERNAL_ERROR: i64 = -32603;

/// Error type for JSON-RPC related operations.
///
/// Encapsulates various error conditions that may occur during JSON-RPC
/// operations, including serialization errors, transport issues, and
/// protocol-specific errors.
#[derive(Debug, Error)]
pub enum Error {
    #[error("Failed to parse JSON-RPC response")]
    ParseResponse,
    #[error("Failed to parse JSON-RPC response")]
    ParseJsonResponse {
        #[source]
        source: serde_json::Error,
    },
    #[error("Got JSON-RPC error")]
    RpcError(#[from] RpcError),
    #[error("Internal error: {0}")]
    Other(String),
}

impl Error {
    pub fn other<T: core::fmt::Display>(v: T) -> Self {
        return Self::Other(v.to_string());
    }
}

impl From<serde_json::Error> for Error {
    fn from(value: serde_json::Error) -> Self {
        Self::ParseJsonResponse { source: value }
    }
}

/// Convenience type alias for Result with the JSON-RPC Error type.
pub type Result<T> = std::result::Result<T, Error>;

/// Trait for types that can be converted into JSON-RPC request objects.
///
/// Implementing this trait allows a struct to be used as a typed JSON-RPC
/// request, with an associated method name and automatic conversion to the
/// request format.
pub trait JsonRpcRequest: Serialize {
    const METHOD: &'static str;
    fn into_request(self, id: Option<String>) -> RequestObject<Self>
    where
        Self: Sized,
    {
        RequestObject {
            jsonrpc: "2.0".into(),
            method: Self::METHOD.into(),
            params: Some(self),
            id,
        }
    }
}

/// # RequestObject
///
/// Represents a JSON-RPC 2.0 Request object, as defined in section 4 of the
/// specification. This structure encapsulates all necessary information for
/// a remote procedure call.
///
/// # Type Parameters
///
/// * `T`: The type of the `params` field.  This *MUST* implement `Serialize`
///   to allow it to be encoded as JSON. Typically this will be a struct
///   implementing the `JsonRpcRequest` trait.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct RequestObject<T>
where
    T: Serialize,
{
    ///  **REQUIRED**.  MUST be `"2.0"`.
    pub jsonrpc: String,
    ///  **REQUIRED**.  The method to be invoked.
    pub method: String,
    /// A struct containing the method parameters.
    #[serde(skip_serializing_if = "is_none_or_null")]
    pub params: Option<T>,
    /// An identifier established by the Client that MUST contain a String.
    /// # Note: this is special to LSPS0, might change to match the more general
    /// JSON-RPC 2.0 sepec if needed.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub id: Option<String>,
}

impl<T> RequestObject<T>
where
    T: Serialize,
{
    /// Returns the inner data object contained by params for handling or future
    /// processing.
    pub fn into_inner(self) -> Option<T> {
        self.params
    }
}

/// Helper function to check if params is None or would serialize to null.
fn is_none_or_null<T: Serialize>(opt: &Option<T>) -> bool {
    match opt {
        None => true,
        Some(val) => match serde_json::to_value(&val) {
            Ok(Value::Null) => true,
            _ => false,
        },
    }
}

pub struct JsonRpcResponse<R = ()> {
    id: String,
    body: JsonRpcResponseBody<R>,
}

impl JsonRpcResponse<()> {
    pub fn error<T: Into<String>>(error: RpcError, id: T) -> Self {
        Self {
            id: id.into(),
            body: JsonRpcResponseBody::Error { error },
        }
    }
}

impl<R> JsonRpcResponse<R> {
    pub fn success<T: Into<String>>(result: R, id: T) -> Self {
        Self {
            id: id.into(),
            body: JsonRpcResponseBody::Success { result },
        }
    }

    pub fn into_result(self) -> std::result::Result<R, RpcError> {
        self.body.into_result()
    }

    pub fn as_result(&self) -> std::result::Result<&R, &RpcError> {
        self.body.as_result()
    }

    pub fn is_ok(&self) -> bool {
        self.body.is_ok()
    }

    pub fn is_err(&self) -> bool {
        self.body.is_err()
    }

    pub fn map<U, F>(self, f: F) -> JsonRpcResponse<U>
    where
        F: FnOnce(R) -> U,
    {
        JsonRpcResponse {
            id: self.id,
            body: self.body.map(f),
        }
    }

    /// Unwrap the result, panicking on RPC error
    pub fn unwrap(self) -> R {
        self.body.unwrap()
    }

    /// Expect success or panic with message
    pub fn expect(self, msg: &str) -> R {
        self.body.expect(msg)
    }
}

// Custom Serialize to match JSON-RPC 2.0 wire format
impl<R: Serialize> Serialize for JsonRpcResponse<R> {
    fn serialize<S>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        use serde::ser::SerializeStruct;

        let mut state = serializer.serialize_struct("JsonRpcResponse", 3)?;
        state.serialize_field("jsonrpc", "2.0")?;
        state.serialize_field("id", &self.id)?;

        match &self.body {
            JsonRpcResponseBody::Success { result } => {
                state.serialize_field("result", result)?;
            }
            JsonRpcResponseBody::Error { error } => {
                state.serialize_field("error", error)?;
            }
        }

        state.end()
    }
}

// Custom Deserialize from JSON-RPC 2.0 wire format
impl<'de, R: DeserializeOwned> Deserialize<'de> for JsonRpcResponse<R> {
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        #[derive(Deserialize)]
        struct RawResponse<R> {
            jsonrpc: String,
            result: Option<R>,
            error: Option<RpcError>,
            id: String,
        }

        let raw = RawResponse::deserialize(deserializer)?;

        if raw.jsonrpc != "2.0" {
            return Err(serde::de::Error::custom(format!(
                "Invalid JSON-RPC version: {}",
                raw.jsonrpc
            )));
        }

        let body = match (raw.result, raw.error) {
            (Some(result), None) => JsonRpcResponseBody::Success { result },
            (None, Some(error)) => JsonRpcResponseBody::Error { error },
            (Some(_), Some(_)) => {
                return Err(serde::de::Error::custom(
                    "Response cannot have both result and error",
                ))
            }
            (None, None) => {
                return Err(serde::de::Error::custom(
                    "Response must have either result or error",
                ))
            }
        };

        Ok(JsonRpcResponse { id: raw.id, body })
    }
}

pub enum JsonRpcResponseBody<R> {
    Success { result: R },
    Error { error: RpcError },
}

impl<R> JsonRpcResponseBody<R> {
    pub fn into_result(self) -> std::result::Result<R, RpcError> {
        match self {
            Self::Success { result } => Ok(result),
            Self::Error { error } => Err(error),
        }
    }

    pub fn as_result(&self) -> std::result::Result<&R, &RpcError> {
        match self {
            Self::Success { result } => Ok(result),
            Self::Error { error } => Err(error),
        }
    }

    pub fn is_ok(&self) -> bool {
        matches!(self, JsonRpcResponseBody::Success { .. })
    }

    pub fn is_err(&self) -> bool {
        matches!(self, JsonRpcResponseBody::Error { .. })
    }

    pub fn map<U, F>(self, f: F) -> JsonRpcResponseBody<U>
    where
        F: FnOnce(R) -> U,
    {
        match self {
            Self::Success { result } => JsonRpcResponseBody::Success { result: f(result) },
            Self::Error { error } => JsonRpcResponseBody::Error { error },
        }
    }

    pub fn unwrap(self) -> R {
        match self {
            Self::Success { result } => result,
            Self::Error { error } => panic!("Called unwrap on RPC Error: {}", error),
        }
    }

    pub fn expect(self, msg: &str) -> R {
        match self {
            Self::Success { result } => result,
            Self::Error { error } => panic!("{}: {}", msg, error),
        }
    }
}

/// Macro to generate RpcError helper methods for protocol-specific error codes
///
/// This generates two methods for each error code:
/// - `method_name(message)` - Creates error without data
/// - `method_name_with_data(message, data)` - Creates error with data
macro_rules! rpc_error_methods {
    ($($method:ident => $code:expr),* $(,)?) => {
        $(
            paste::paste! {
                fn $method<T: std::fmt::Display>(message: T) -> $crate::proto::jsonrpc::RpcError {
                    $crate::proto::jsonrpc::RpcError {
                        code: $code,
                        message: message.to_string(),
                        data: None,
                    }
                }

                fn [<$method _with_data>]<T: std::fmt::Display>(
                    message: T,
                    data: serde_json::Value,
                ) -> $crate::proto::jsonrpc::RpcError {
                    $crate::proto::jsonrpc::RpcError {
                        code: $code,
                        message: message.to_string(),
                        data: Some(data),
                    }
                }
            }
        )*
    };
}

/// # RpcError
///
/// Represents an error object in a JSON-RPC 2.0 Response object (section 5.1).
/// Provides structured information about an error that occurred during the
/// method invocation.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct RpcError {
    ///  **REQUIRED**. An integer indicating the type of error.
    pub code: i64,
    ///  **REQUIRED**. A string containing a short description of the error.
    pub message: String,
    /// A primitive that can be either Primitive or Structured type if there
    /// were.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub data: Option<Value>,
}

impl RpcError {
    /// Reserved for implementation-defined server-errors.
    pub fn custom_error<T: core::fmt::Display>(code: i64, message: T) -> Self {
        RpcError {
            code,
            message: message.to_string(),
            data: None,
        }
    }

    /// Reserved for implementation-defined server-errors.
    pub fn custom_error_with_data<T: core::fmt::Display>(
        code: i64,
        message: T,
        data: serde_json::Value,
    ) -> Self {
        RpcError {
            code,
            message: message.to_string(),
            data: Some(data),
        }
    }
}

pub trait RpcErrorExt {
    rpc_error_methods! {
    parse_error => PARSE_ERROR,
    internal_error => INTERNAL_ERROR,
    invalid_params => INVALID_PARAMS,
    method_not_found => METHOD_NOT_FOUND,
    invalid_request => INVALID_REQUEST,
    }
}

impl RpcErrorExt for RpcError {}

impl fmt::Display for RpcError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "JSON-RPC Error (code: {}, message: {}, data: {:?})",
            self.code, self.message, self.data
        )
    }
}

impl std::error::Error for RpcError {}

#[cfg(test)]
mod test_message_serialization {
    use super::*;
    use serde_json::json;

    #[test]
    fn test_empty_params_serialization() {
        // Empty params should serialize to `"params":{}` instead of
        // `"params":null`.
        #[derive(Debug, Serialize, Deserialize)]
        pub struct SayHelloRequest;
        impl JsonRpcRequest for SayHelloRequest {
            const METHOD: &'static str = "say_hello";
        }
        let rpc_request = SayHelloRequest.into_request(Some("unique-id-123".into()));
        assert!(!serde_json::to_string(&rpc_request)
            .expect("could not convert to json")
            .contains("\"params\""));
    }

    #[test]
    fn test_request_serialization_and_deserialization() {
        // Ensure that we correctly serialize to a valid JSON-RPC 2.0 request.
        #[derive(Default, Debug, Serialize, Deserialize)]
        pub struct SayNameRequest {
            name: String,
            age: i32,
        }
        impl JsonRpcRequest for SayNameRequest {
            const METHOD: &'static str = "say_name";
        }
        let rpc_request = SayNameRequest {
            name: "Satoshi".to_string(),
            age: 99,
        }
        .into_request(Some("unique-id-123".into()));

        let json_value: serde_json::Value = serde_json::to_value(&rpc_request).unwrap();
        let expected_value: serde_json::Value = serde_json::json!({
            "jsonrpc": "2.0",
            "method": "say_name",
            "params": {
                "name": "Satoshi",
                "age": 99
            },
            "id": "unique-id-123"
        });
        assert_eq!(json_value, expected_value);

        let request: RequestObject<serde_json::Value> = serde_json::from_value(json_value).unwrap();
        assert_eq!(request.method, "say_name");
        assert_eq!(request.jsonrpc, "2.0");

        let request: RequestObject<SayNameRequest> =
            serde_json::from_value(expected_value).unwrap();
        let inner = request.into_inner();
        assert_eq!(inner.unwrap().name, rpc_request.params.unwrap().name);
    }

    #[test]
    fn test_response_deserialization() {
        // Check that we can convert a JSON-RPC response into a typed result.
        #[derive(Debug, Serialize, Deserialize, PartialEq)]
        pub struct SayNameResponse {
            name: String,
            age: i32,
            message: String,
        }

        let json_response = r#"
            {
                "jsonrpc": "2.0",
                "result": {
                    "age": 99,
                    "message": "Hello Satoshi!",
                    "name": "Satoshi"
                },
                "id": "unique-id-123"
            }"#;

        let response: JsonRpcResponse<SayNameResponse> =
            serde_json::from_str(json_response).unwrap();

        let result = response.into_result().unwrap();
        assert_eq!(
            result,
            SayNameResponse {
                name: "Satoshi".into(),
                age: 99,
                message: "Hello Satoshi!".into(),
            }
        );
    }

    #[test]
    fn test_empty_result() {
        // Check that we correctly deserialize an empty result.
        #[derive(Debug, Serialize, Deserialize, PartialEq)]
        pub struct DummyResponse {}

        let json_response = r#"
            {
                "jsonrpc": "2.0",
                "result": {},
                "id": "unique-id-123"
            }"#;

        let response: JsonRpcResponse<DummyResponse> = serde_json::from_str(json_response).unwrap();
        let result = response.into_result().unwrap();
        assert_eq!(result, DummyResponse {});
    }
    #[test]
    fn test_error_deserialization() {
        // Check that we deserialize an error if we got one.
        #[derive(Debug, Serialize, Deserialize, PartialEq)]
        pub struct DummyResponse {}

        let json_response = r#"
            {
                "jsonrpc": "2.0",
                "id": "unique-id-123",
                "error": {
                    "code": -32099,
                    "message": "something bad happened",
                    "data": {
                        "f1": "v1",
                        "f2": 2
                    }
                }
            }"#;

        let response: JsonRpcResponse<DummyResponse> = serde_json::from_str(json_response).unwrap();
        assert!(response.is_err());

        let err = response.into_result().unwrap_err();
        assert!(matches!(err, RpcError { .. }));
        assert_eq!(err.message, "something bad happened");
        assert_eq!(err.data, Some(serde_json::json!({"f1":"v1","f2":2})));
    }

    #[test]
    fn test_error_serialization() {
        let error = RpcError::invalid_request("Invalid request");
        let serialized = serde_json::to_string(&error).unwrap();
        assert_eq!(serialized, r#"{"code":-32600,"message":"Invalid request"}"#);

        let error_with_data = RpcError::internal_error_with_data(
            "Internal server error",
            json!({"details": "Something went wrong"}),
        );
        let serialized_with_data = serde_json::to_string(&error_with_data).unwrap();
        assert_eq!(
            serialized_with_data,
            r#"{"code":-32603,"message":"Internal server error","data":{"details":"Something went wrong"}}"#
        );
    }
}
