use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum PromiseError {
    TooLong { length: usize, max: usize },
    InvalidChar { position: usize, ch: char },
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
            PromiseError::InvalidChar { position, ch } => {
                write!(
                    f,
                    "promise string contains {:?} at byte {}: only printable ASCII \
                     without '\"' and '\\' is allowed",
                    ch, position
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
///
/// bLIP-52 requires of the LSP, when generating the `promise`:
///
/// > * MUST ensure the promise is no longer than 512 bytes (not including
/// >   the `"` delimiters) when encoded as a UTF8-encoded JSON string.
/// > * MUST avoid characters outside of the printable ASCII range.
/// > * MUST avoid characters that would require escapes in JSON format.
///
/// and of the client, when reading it:
///
/// > * MUST abort this flow if `promise` exceeds 512 bytes (not including
/// >   the `"` delimiters) when encoded as a UTF8-encoded JSON string.
///
/// Both sides enforce both rules here: a promise is at most 512 bytes of
/// printable ASCII (0x20 to 0x7E) other than `"` and `\`. With that
/// character set the JSON encoding has no escapes, so the decoded length
/// is the encoded length.
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
        if len > Promise::MAX_BYTES {
            return Err(PromiseError::TooLong {
                length: len,
                max: Promise::MAX_BYTES,
            });
        }
        if let Some((position, ch)) = s.char_indices().find(|&(_, c)| !is_allowed_char(c)) {
            return Err(PromiseError::InvalidChar { position, ch });
        }
        Ok(Promise(s))
    }
}

impl TryFrom<&str> for Promise {
    type Error = PromiseError;

    fn try_from(s: &str) -> Result<Self, Self::Error> {
        Promise::try_from(s.to_owned())
    }
}

/// Printable ASCII that needs no escape in a JSON string.
fn is_allowed_char(c: char) -> bool {
    matches!(c, ' '..='~') && c != '"' && c != '\\'
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
    fn test_promise_charset() {
        // Every printable ASCII character except '"' and '\\' is allowed.
        let allowed: String = (0x20u8..=0x7e)
            .map(char::from)
            .filter(|&c| c != '"' && c != '\\')
            .collect();
        assert_eq!(allowed.len(), 93);
        assert_eq!(
            Promise::try_from(allowed.as_str()).unwrap().as_str(),
            allowed
        );

        for (s, position, ch) in [
            ("ab\"c", 2, '"'),
            ("ab\\c", 2, '\\'),
            ("ab\nc", 2, '\n'),
            ("\u{7f}", 0, '\u{7f}'),
            ("\u{1f}", 0, '\u{1f}'),
            ("abc\u{e9}", 3, '\u{e9}'),
        ] {
            assert_eq!(
                Promise::try_from(s),
                Err(PromiseError::InvalidChar { position, ch }),
                "{s:?}"
            );
        }
    }

    #[test]
    fn test_serde_promise_rejects_escaped_chars() {
        // Valid JSON strings that decode to forbidden characters.
        for json in [
            r#""a\"b""#,
            r#""a\\b""#,
            r#""a\u0041\u0000""#,
            r#""\u00e9""#,
        ] {
            assert!(serde_json::from_str::<Promise>(json).is_err(), "{json}");
        }
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
