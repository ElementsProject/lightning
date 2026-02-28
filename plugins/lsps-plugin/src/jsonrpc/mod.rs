pub mod client;
use log::debug;
use serde::{de::DeserializeOwned, Deserialize, Serialize};
use serde_json::{self, Value};
pub mod server;
use std::fmt;
use thiserror::Error;

// Constants for JSON-RPC error codes
const PARSE_ERROR: i64 = -32700;
const INVALID_REQUEST: i64 = -32600;
const METHOD_NOT_FOUND: i64 = -32601;
const INVALID_PARAMS: i64 = -32602;
const INTERNAL_ERROR: i64 = -32603;

/// Error type for JSON-RPC related operations.
///
/// Encapsulates various error conditions that may occur during JSON-RPC
/// operations, including serialization errors, transport issues, and
/// protocol-specific errors.
#[derive(Error, Debug)]
pub enum Error {
    #[error("JSON error: {0}")]
    Json(#[from] serde_json::Error),
    #[error("RPC error: {0}")]
    Rpc(#[from] RpcError),
    #[error("Transport error: {0}")]
    Transport(#[from] TransportError),
    #[error("Other error: {0}")]
    Other(String),
}

impl Error {
    pub fn other<T: core::fmt::Display>(v: T) -> Self {
        return Self::Other(v.to_string());
    }
}

/// Transport-specific errors that may occur when sending or receiving JSON-RPC
/// messages.
#[derive(Error, Debug)]
pub enum TransportError {
    #[error("Timeout")]
    Timeout,
    #[error("Other error: {0}")]
    Other(String),
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

/// Trait for types that can be converted from JSON-RPC response objects.
///
/// This trait provides methods for converting between typed response objects
/// and JSON-RPC protocol response envelopes.
pub trait JsonRpcResponse<T>
where
    T: DeserializeOwned,
{
    fn into_response(self, id: String) -> ResponseObject<Self>
    where
        Self: Sized + DeserializeOwned,
    {
        ResponseObject {
            jsonrpc: "2.0".into(),
            id: id.into(),
            result: Some(self),
            error: None,
        }
    }

    fn from_response(resp: ResponseObject<T>) -> Result<T>
    where
        T: core::fmt::Debug,
    {
        match (resp.result, resp.error) {
            (Some(result), None) => Ok(result),
            (None, Some(error)) => Err(Error::Rpc(error)),
            _ => {
                debug!(
                    "Invalid JSON-RPC response - missing both result and error fields, or both set: id={}",
                    resp.id
                );
                Err(Error::Rpc(RpcError::internal_error(
                    "not a valid json respone",
                )))
            }
        }
    }
}

/// Automatically implements the `JsonRpcResponse` trait for all types that
/// implement `DeserializeOwned`. This simplifies creating JSON-RPC services,
/// as you only need to define data structures that can be deserialized.
impl<T> JsonRpcResponse<T> for T where T: DeserializeOwned {}

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

/// # ResponseObject
///
/// Represents a JSON-RPC 2.0 Response object, as defined in section 5.0 of the
/// specification. This structure encapsulates either a successful result or
/// an error.
///
/// # Type Parameters
///
/// * `T`: The type of the `result` field, which will be returned upon a
///   succesful execution of the procedure. *MUST* implement both `Serialize`
///   (to allow construction of responses) and `DeserializeOwned` (to allow
///   receipt and parsing of responses).
#[derive(Debug, Serialize, Deserialize)]
#[serde(bound = "T: Serialize + DeserializeOwned")]
pub struct ResponseObject<T>
where
    T: DeserializeOwned,
{
    ///  **REQUIRED**.  MUST be `"2.0"`.
    jsonrpc: String,
    /// **REQUIRED**. The identifier of the original request this is a response.
    id: String,
    /// **REQUIRED on success**. The data if there is a request and non-errored.
    /// MUST NOT exist if there was an error triggered during invocation.
    #[serde(skip_serializing_if = "Option::is_none")]
    result: Option<T>,
    /// **REQUIRED on error** An error type if there was a failure.
    error: Option<RpcError>,
}

impl<T> ResponseObject<T>
where
    T: DeserializeOwned + Serialize + core::fmt::Debug,
{
    /// Returns a potential data (result) if the code execution passed else it
    /// returns with RPC error, data (error details) if there was
    pub fn into_inner(self) -> Result<T> {
        T::from_response(self)
    }
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
    pub fn into_response(self, id: String) -> ResponseObject<serde_json::Value> {
        ResponseObject {
            jsonrpc: "2.0".into(),
            id: id.into(),
            result: None,
            error: Some(self),
        }
    }
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

    /// Invalid JSON was received by the server.
    /// An error occurred on the server while parsing the JSON text.
    pub fn parse_error<T: core::fmt::Display>(message: T) -> Self {
        Self::custom_error(PARSE_ERROR, message)
    }

    /// Invalid JSON was received by the server.
    /// An error occurred on the server while parsing the JSON text.
    pub fn parse_error_with_data<T: core::fmt::Display>(
        message: T,
        data: serde_json::Value,
    ) -> Self {
        Self::custom_error_with_data(PARSE_ERROR, message, data)
    }

    /// The JSON sent is not a valid Request object.
    pub fn invalid_request<T: core::fmt::Display>(message: T) -> Self {
        Self::custom_error(INVALID_REQUEST, message)
    }

    /// The JSON sent is not a valid Request object.
    pub fn invalid_request_with_data<T: core::fmt::Display>(
        message: T,
        data: serde_json::Value,
    ) -> Self {
        Self::custom_error_with_data(INVALID_REQUEST, message, data)
    }

    /// The method does not exist / is not available.
    pub fn method_not_found<T: core::fmt::Display>(message: T) -> Self {
        Self::custom_error(METHOD_NOT_FOUND, message)
    }

    /// The method does not exist / is not available.
    pub fn method_not_found_with_data<T: core::fmt::Display>(
        message: T,
        data: serde_json::Value,
    ) -> Self {
        Self::custom_error_with_data(METHOD_NOT_FOUND, message, data)
    }

    /// Invalid method parameter(s).
    pub fn invalid_params<T: core::fmt::Display>(message: T) -> Self {
        Self::custom_error(INVALID_PARAMS, message)
    }

    /// Invalid method parameter(s).
    pub fn invalid_params_with_data<T: core::fmt::Display>(
        message: T,
        data: serde_json::Value,
    ) -> Self {
        Self::custom_error_with_data(INVALID_PARAMS, message, data)
    }

    /// Internal JSON-RPC error.
    pub fn internal_error<T: core::fmt::Display>(message: T) -> Self {
        Self::custom_error(INTERNAL_ERROR, message)
    }

    /// Internal JSON-RPC error.
    pub fn internal_error_with_data<T: core::fmt::Display>(
        message: T,
        data: serde_json::Value,
    ) -> Self {
        Self::custom_error_with_data(INTERNAL_ERROR, message, data)
    }
}

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

        let response_object: ResponseObject<SayNameResponse> =
            serde_json::from_str(json_response).unwrap();

        let response: SayNameResponse = response_object.into_inner().unwrap();
        let expected_response = SayNameResponse {
            name: "Satoshi".into(),
            age: 99,
            message: "Hello Satoshi!".into(),
        };

        assert_eq!(response, expected_response);
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

        let response_object: ResponseObject<DummyResponse> =
            serde_json::from_str(json_response).unwrap();

        let response: DummyResponse = response_object.into_inner().unwrap();
        let expected_response = DummyResponse {};

        assert_eq!(response, expected_response);
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

        let response_object: ResponseObject<DummyResponse> =
            serde_json::from_str(json_response).unwrap();

        let response = response_object.into_inner();
        let err = response.unwrap_err();
        match err {
            Error::Rpc(err) => {
                assert_eq!(err.code, -32099);
                assert_eq!(err.message, "something bad happened");
                assert_eq!(
                    err.data,
                    serde_json::from_str("{\"f1\":\"v1\",\"f2\":2}").unwrap()
                );
            }
            _ => assert!(false),
        }
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
