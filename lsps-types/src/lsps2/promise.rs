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

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(try_from = "String")]
pub struct Promise(pub String);

impl Promise {
    pub const MAX_BYTES: usize = 512;
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
        let len = s.len();
        if len <= Promise::MAX_BYTES {
            Ok(Promise(s.to_owned()))
        } else {
            Err(PromiseError::TooLong {
                length: len,
                max: Promise::MAX_BYTES,
            })
        }
    }
}

impl core::fmt::Display for Promise {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
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
        assert_eq!(data.value.0, "This is valid");
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
