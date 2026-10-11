use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum PromiseError {
    TooLong { length: usize, max: usize },
}

impl core::fmt::Display for PromiseError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            PromiseError::TooLong { length, max } => {
                write!(
                    f,
                    "promise string is too long: {} bytes (max allowed {})",
                    length, max
                )
            }
        }
    }
}

impl core::error::Error for PromiseError {}

/// The `promise` of an `opening_fee_params` object.
///
/// The promise is opaque: it is created by the LSP, and clients "MUST NOT
/// parse or interpret this string, and only provide it verbatim later"
/// (bLIP-52). This type only checks the limits the spec puts on the string
/// and gives access to it as `&str`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(try_from = "String", into = "String")]
pub struct Promise(String);

impl Promise {
    pub const MAX_BYTES: usize = 512;

    /// Returns the promise string.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl TryFrom<String> for Promise {
    type Error = PromiseError;

    fn try_from(s: String) -> Result<Self, Self::Error> {
        let len = s.len();
        if len <= Promise::MAX_BYTES {
            Ok(Promise(s))
        } else {
            Err(PromiseError::TooLong {
                length: len,
                max: Promise::MAX_BYTES,
            })
        }
    }
}

impl TryFrom<&str> for Promise {
    type Error = PromiseError;

    fn try_from(s: &str) -> Result<Self, Self::Error> {
        Promise::try_from(s.to_owned())
    }
}

impl From<Promise> for String {
    fn from(promise: Promise) -> Self {
        promise.0
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // Helper struct for testing Serde
    #[derive(Serialize, Deserialize, Debug, PartialEq)]
    struct TestData {
        label: String,
        value: Promise,
    }

    #[test]
    fn test_serde_promise_ok() {
        let json = r#"{"label": "short", "value": "This is valid"}"#;
        let result = serde_json::from_str::<TestData>(json);
        assert!(result.is_ok());
        let data = result.unwrap();
        assert_eq!(data.value.as_str(), "This is valid");
        assert_eq!(
            serde_json::to_string(&data.value).unwrap(),
            r#""This is valid""#
        );
    }

    #[test]
    fn test_promise_max_length() {
        assert!(Promise::try_from("a".repeat(512)).is_ok());
        assert_eq!(
            Promise::try_from("a".repeat(513)),
            Err(PromiseError::TooLong {
                length: 513,
                max: 512
            })
        );
    }

    #[test]
    fn test_serde_promise_too_long() {
        let long_value = "a".repeat(513); // Exceeds 512 bytes
        let json = format!(r#"{{"label": "long", "value": "{}"}}"#, long_value);
        let result = serde_json::from_str::<TestData>(&json);
        assert!(result.is_err());
        // Check the error message relates to our PromiseError
        assert!(
            result
                .unwrap_err()
                .to_string()
                .contains("promise string is too long")
        );
    }

    #[test]
    fn test_serde_promise_wrong_type() {
        // Input JSON has a number where a string is expected for 'value'
        let json = r#"{"label": "wrong_type", "value": 123}"#;
        let result = serde_json::from_str::<TestData>(json);
        assert!(result.is_err());
        // This error occurs when Serde tries to deserialize 123 as the String
        // required by `try_from = "String"`.
        assert!(
            result
                .unwrap_err()
                .to_string()
                .contains("invalid type: integer")
        );
    }
}
