/// The codec is used to encode and decode messages received from and
/// sent to the main daemon. The protocol uses `stdout` and `stdin` to
/// exchange JSON formatted messages. Each message is separated by an
/// empty line and we're guaranteed that no other empty line is
/// present in the messages.
use crate::{Error, RpcError};
use bytes::{BufMut, BytesMut};
use serde_json::value::Value;
use std::str::FromStr;
use std::{io, str};
use tokio_util::codec::{Decoder, Encoder};

use crate::messages::JsonRpc;
use crate::messages::{Notification, Request};

/// A simple codec that parses messages separated by two successive
/// `\n` newlines.
#[derive(Default)]
pub struct MultiLineCodec {
    search_pos: usize,
}

fn utf8(buf: &[u8]) -> Result<&str, io::Error> {
    str::from_utf8(buf)
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "Unable to decode input as UTF8"))
}

impl Decoder for MultiLineCodec {
    type Item = String;
    type Error = Error;
    fn decode(&mut self, buf: &mut BytesMut) -> Result<Option<Self::Item>, Error> {
        let bytes = &buf[..];
        let mut i = self.search_pos;

        while i + 1 < bytes.len() {
            if bytes[i] == b'\n' && bytes[i + 1] == b'\n' {
                let line = buf.split_to(i + 2);
                let line = &line[..line.len() - 2];

                self.search_pos = 0;

                return Ok(Some(utf8(line)?.to_owned()));
            }
            i += 1;
        }

        self.search_pos = bytes.len().saturating_sub(1);

        Ok(None)
    }
}

impl<T> Encoder<T> for MultiLineCodec
where
    T: AsRef<str>,
{
    type Error = Error;
    fn encode(&mut self, line: T, buf: &mut BytesMut) -> Result<(), Self::Error> {
        let line = line.as_ref();
        buf.reserve(line.len() + 2);
        buf.put(line.as_bytes());
        buf.put_u8(b'\n');
        buf.put_u8(b'\n');
        Ok(())
    }
}

#[derive(Default)]
pub struct JsonCodec {
    /// Sub-codec used to split the input into chunks that can then be
    /// parsed by the JSON parser.
    inner: MultiLineCodec,
}

impl<T> Encoder<T> for JsonCodec
where
    T: Into<Value>,
{
    type Error = Error;
    fn encode(&mut self, msg: T, buf: &mut BytesMut) -> Result<(), Self::Error> {
        let s = msg.into().to_string();
        self.inner.encode(s, buf)
    }
}

impl Decoder for JsonCodec {
    type Item = Result<Value, Value>;
    type Error = Error;

    fn decode(&mut self, buf: &mut BytesMut) -> Result<Option<Self::Item>, Error> {
        match self.inner.decode(buf) {
            Ok(None) => Ok(None),
            Err(e) => Err(e),
            Ok(Some(s)) => {
                if let Ok(v) = Value::from_str(&s) {
                    Ok(Some(Ok(v)))
                } else {
                    let id = recover_id(&s).unwrap();

                    Ok(Some(Err(json!({
                        "jsonrpc": "2.0",
                        "id": id,
                        "error": RpcError {
                            code: Some(-32700),
                            message: format!("failed to parse as JSON: `{s}`"),
                            data: None,
                    }
                    }))))
                }
            }
        }
    }
}

/// A codec that reads fully formed [crate::messages::JsonRpc]
/// messages. Internally it uses the [JsonCodec] which itself is built
/// on the [MultiLineCodec].
#[derive(Default)]
pub(crate) struct JsonRpcCodec {
    inner: JsonCodec,
}

impl Decoder for JsonRpcCodec {
    type Item = JsonRpc<Notification, Request>;
    type Error = Error;

    fn decode(&mut self, buf: &mut BytesMut) -> Result<Option<Self::Item>, Error> {
        match self.inner.decode(buf) {
            Ok(None) => Ok(None),
            Err(e) => Err(e),
            Ok(Some(Err(rpc_err))) => Ok(Some(JsonRpc::Error(rpc_err))),
            Ok(Some(Ok(v))) => {
                let req: Self::Item = serde_json::from_value(v)?;
                Ok(Some(req))
            }
        }
    }
}

fn recover_id(input: &str) -> Option<serde_json::Value> {
    let bytes = input.as_bytes();
    let len = bytes.len();
    let mut i = 0;
    let mut depth: i32 = 0;

    while i < len {
        let c = bytes[i] as char;

        match c {
            '"' => {
                let content_start = i + 1;
                let mut j = content_start;
                let mut escaped = false;
                let end = loop {
                    if j >= len {
                        return None;
                    }
                    let cj = bytes[j] as char;
                    if escaped {
                        escaped = false;
                    } else if cj == '\\' {
                        escaped = true;
                    } else if cj == '"' {
                        break j;
                    }
                    j += 1;
                };

                let key = &input[content_start..end];
                if depth == 1 && key == "id" {
                    let mut k = end + 1;
                    k += skip_ws(&bytes[k..]);
                    if k < len && bytes[k] as char == ':' {
                        k += 1;
                        k += skip_ws(&bytes[k..]);
                        if let Some((value, consumed)) = parse_value_prefix(&input[k..]) {
                            let after = k + consumed;
                            let ws = skip_ws(&bytes[after..]);
                            let next = bytes.get(after + ws).map(|b| *b as char);
                            // A well-formed object only ever has ',' or
                            // '}' right after a field's value. Anything
                            // else means we accidentally consumed part
                            // of the next key/token, and the value we
                            // extracted can't be trusted.
                            if matches!(next, None | Some(',' | '}')) {
                                return Some(value);
                            }
                        }
                        return None;
                    }
                }
                i = end + 1;
            }
            '{' | '[' => {
                depth += 1;
                i += 1;
            }
            '}' | ']' => {
                depth -= 1;
                i += 1;
            }
            _ => {
                i += 1;
            }
        }
    }
    None
}

fn skip_ws(bytes: &[u8]) -> usize {
    bytes
        .iter()
        .take_while(|b| (**b as char).is_ascii_whitespace())
        .count()
}

/// Parse a single JSON value from the start of `input`. Returns the value
/// plus the number of bytes consumed, so the caller can validate what
/// immediately follows it.
fn parse_value_prefix(input: &str) -> Option<(serde_json::Value, usize)> {
    let bytes = input.as_bytes();

    for (lit, val) in [
        ("null", serde_json::Value::Null),
        ("true", serde_json::Value::Bool(true)),
        ("false", serde_json::Value::Bool(false)),
    ] {
        if input.starts_with(lit) {
            // Guard against "nullish" / "trueish" / "falseX" being
            // mistaken for the real keyword.
            let boundary_ok = match bytes.get(lit.len()) {
                None => true,
                Some(b) => {
                    let c = *b as char;
                    !(c.is_ascii_alphanumeric() || c == '_')
                }
            };
            return boundary_ok.then_some((val, lit.len()));
        }
    }

    if let Some(rest) = input.strip_prefix('"') {
        let rbytes = rest.as_bytes();
        let mut escaped = false;
        for (idx, b) in rbytes.iter().enumerate() {
            let c = *b as char;
            if escaped {
                escaped = false;
                continue;
            }
            if c == '\\' {
                escaped = true;
                continue;
            }
            if c == '"' {
                let literal = format!("\"{}\"", &rest[..idx]);
                return serde_json::from_str::<serde_json::Value>(&literal)
                    .ok()
                    .map(|v| (v, idx + 2)); // opening quote + content + closing quote
            }
        }
        return None; // unterminated
    }

    let end = input
        .char_indices()
        .take_while(|(_, c)| c.is_ascii_digit() || matches!(c, '-' | '+' | '.' | 'e' | 'E'))
        .map(|(idx, c)| idx + c.len_utf8())
        .last()
        .unwrap_or(0);

    if end == 0 {
        return None;
    }
    serde_json::from_str::<serde_json::Value>(&input[..end])
        .ok()
        .map(|v| (v, end))
}

#[cfg(test)]
mod test {
    use crate::codec::recover_id;

    use super::{JsonCodec, MultiLineCodec};
    use bytes::{BufMut, BytesMut};
    use serde_json::json;
    use tokio_util::codec::{Decoder, Encoder};

    #[test]
    fn test_ml_decoder() {
        struct Test(String, Option<String>, String);
        let tests = vec![
            Test("".to_string(), None, "".to_string()),
            Test(
                "{\"hello\":\"world\"}\n\nremainder".to_string(),
                Some("{\"hello\":\"world\"}".to_string()),
                "remainder".to_string(),
            ),
            Test(
                "{\"hello\":\"world\"}\n\n{}\n\nremainder".to_string(),
                Some("{\"hello\":\"world\"}".to_string()),
                "{}\n\nremainder".to_string(),
            ),
        ];

        for t in tests.iter() {
            let mut buf = BytesMut::new();
            buf.put_slice(t.0.as_bytes());

            let mut codec = MultiLineCodec::default();
            let mut remainder = BytesMut::new();
            remainder.put_slice(t.2.as_bytes());

            assert_eq!(codec.decode(&mut buf).unwrap(), t.1);
            assert_eq!(buf, remainder);
        }
    }

    #[test]
    fn test_ml_encoder() {
        let tests = vec!["test"];

        for t in tests.iter() {
            let mut buf = BytesMut::new();
            let mut codec = MultiLineCodec::default();
            let mut expected = BytesMut::new();
            expected.put_slice(t.as_bytes());
            expected.put_u8(b'\n');
            expected.put_u8(b'\n');
            codec.encode(t, &mut buf).unwrap();
            assert_eq!(buf, expected);
        }
    }

    #[test]
    fn test_json_codec() {
        let tests = vec![json!({"hello": "world"})];

        for t in tests.iter() {
            let mut codec = JsonCodec::default();
            let mut buf = BytesMut::new();
            codec.encode(t.clone(), &mut buf).unwrap();
            let decoded = codec.decode(&mut buf).unwrap().unwrap().unwrap();
            assert_eq!(&decoded, t);
        }
    }

    #[test]
    fn string_id_basic() {
        let msg = r#"{"id":"abc123","method":"foo"}"#;
        assert_eq!(recover_id(msg), Some(json!("abc123")));
    }

    #[test]
    fn string_id_with_colon_and_hash() {
        let msg = r#"{"id":"cli:testmethod#2078394/cln:testmethod#65","method":"foo"}"#;
        assert_eq!(
            recover_id(msg),
            Some(json!("cli:testmethod#2078394/cln:testmethod#65"))
        );
    }

    #[test]
    fn string_id_empty() {
        let msg = r#"{"id":"","method":"foo"}"#;
        assert_eq!(recover_id(msg), Some(json!("")));
    }

    #[test]
    fn string_id_with_escaped_quote() {
        let msg = r#"{"id":"say \"hi\"","method":"foo"}"#;
        assert_eq!(recover_id(msg), Some(json!("say \"hi\"")));
    }

    #[test]
    fn string_id_with_escaped_backslash() {
        let msg = r#"{"id":"back\\slash","method":"foo"}"#;
        assert_eq!(recover_id(msg), Some(json!("back\\slash")));
    }

    #[test]
    fn string_id_with_newline_escape() {
        let msg = r#"{"id":"line1\nline2","method":"foo"}"#;
        assert_eq!(recover_id(msg), Some(json!("line1\nline2")));
    }

    #[test]
    fn string_id_with_unicode_escape() {
        let msg = r#"{"id":"caf\u00e9","method":"foo"}"#;
        assert_eq!(recover_id(msg), Some(json!("café")));
    }

    #[test]
    fn string_id_with_literal_unicode() {
        let msg = r#"{"id":"héllo-世界","method":"foo"}"#;
        assert_eq!(recover_id(msg), Some(json!("héllo-世界")));
    }

    #[test]
    fn string_id_with_embedded_braces_and_brackets() {
        let msg = r#"{"id":"{not real} [json] here","method":"foo"}"#;
        assert_eq!(recover_id(msg), Some(json!("{not real} [json] here")));
    }

    #[test]
    fn string_id_with_embedded_comma_and_colon() {
        let msg = r#"{"id":"a, b: c","method":"foo"}"#;
        assert_eq!(recover_id(msg), Some(json!("a, b: c")));
    }

    #[test]
    fn string_id_whitespace_before_colon() {
        let msg = r#"{"id"   :   "abc","method":"foo"}"#;
        assert_eq!(recover_id(msg), Some(json!("abc")));
    }

    #[test]
    fn string_id_no_whitespace() {
        let msg = r#"{"id":"abc","method":"foo"}"#;
        assert_eq!(recover_id(msg), Some(json!("abc")));
    }

    #[test]
    fn string_id_tabs_and_newlines_around_colon() {
        let msg = "{\"id\"\t:\n\"abc\",\"method\":\"foo\"}";
        assert_eq!(recover_id(msg), Some(json!("abc")));
    }

    #[test]
    fn string_id_unterminated_is_unrecoverable() {
        let msg = r#"{"id":"abc,"method":"foo"}"#;
        let result = recover_id(msg);
        assert!(result.is_none());
    }

    #[test]
    fn string_id_containing_the_word_id() {
        // "id" appearing inside a string ID value itself.
        let msg = r#"{"id":"this-is-my-id-value","method":"foo"}"#;
        assert_eq!(recover_id(msg), Some(json!("this-is-my-id-value")));
    }

    #[test]
    fn string_id_after_malformed_params() {
        let msg = r#"{"jsonrpc":"2.0","method":"testmethod","params":{"channels":[123x22x12]},"id":"cli:testmethod#99"}"#;
        assert_eq!(recover_id(msg), Some(json!("cli:testmethod#99")));
    }

    #[test]
    fn string_id_before_malformed_params() {
        let msg = r#"{"jsonrpc":"2.0","id":"cli:testmethod#99","method":"testmethod","params":{"channels":[123x22x12]}}"#;
        assert_eq!(recover_id(msg), Some(json!("cli:testmethod#99")));
    }

    #[test]
    fn number_id_positive_int() {
        let msg = r#"{"id":42,"method":"foo"}"#;
        assert_eq!(recover_id(msg), Some(json!(42)));
    }

    #[test]
    fn number_id_zero() {
        let msg = r#"{"id":0,"method":"foo"}"#;
        assert_eq!(recover_id(msg), Some(json!(0)));
    }

    #[test]
    fn number_id_negative_int() {
        let msg = r#"{"id":-17,"method":"foo"}"#;
        assert_eq!(recover_id(msg), Some(json!(-17)));
    }

    #[test]
    fn number_id_float() {
        let msg = r#"{"id":3.15,"method":"foo"}"#;
        assert_eq!(recover_id(msg), Some(json!(3.15)));
    }

    #[test]
    fn number_id_negative_float() {
        let msg = r#"{"id":-0.5,"method":"foo"}"#;
        assert_eq!(recover_id(msg), Some(json!(-0.5)));
    }

    #[test]
    fn number_id_with_exponent() {
        let msg = r#"{"id":1e10,"method":"foo"}"#;
        assert_eq!(recover_id(msg), Some(json!(1e10)));
    }

    #[test]
    fn number_id_with_signed_exponent() {
        let msg = r#"{"id":2.5e-3,"method":"foo"}"#;
        assert_eq!(recover_id(msg), Some(json!(2.5e-3)));
    }

    #[test]
    fn number_id_large_integer() {
        let msg = r#"{"id":9007199254740993,"method":"foo"}"#;
        assert_eq!(recover_id(msg), Some(json!(9_007_199_254_740_993_i64)));
    }

    #[test]
    fn number_id_whitespace_before_colon() {
        let msg = r#"{"id"  :  42,"method":"foo"}"#;
        assert_eq!(recover_id(msg), Some(json!(42)));
    }

    #[test]
    fn number_id_followed_directly_by_brace() {
        let msg = r#"{"id":7}"#;
        assert_eq!(recover_id(msg), Some(json!(7)));
    }

    #[test]
    fn number_id_followed_directly_by_bracket_in_params() {
        let msg = r#"{"method":"foo","id":7,"params":[bad,tokens,here]}"#;
        assert_eq!(recover_id(msg), Some(json!(7)));
    }

    #[test]
    fn number_id_invalid_leading_plus_is_unrecoverable() {
        let msg = r#"{"id":+42,"method":"foo"}"#;
        assert_eq!(recover_id(msg), None);
    }

    #[test]
    fn number_id_bare_minus_is_unrecoverable() {
        let msg = r#"{"id":-,"method":"foo"}"#;
        assert_eq!(recover_id(msg), None);
    }

    #[test]
    fn number_id_trailing_dot_no_digits_is_unrecoverable() {
        let msg = r#"{"id":1.,"method":"foo"}"#;
        assert_eq!(recover_id(msg), None);
    }

    #[test]
    fn number_id_double_leading_zero_still_parses_prefix() {
        let msg = r#"{"id":007,"method":"foo"}"#;
        assert_eq!(recover_id(msg), None);
    }

    #[test]
    fn number_id_mixed_with_bad_downstream_object() {
        let msg =
            r#"{"jsonrpc":"2.0","id":123,"method":"testmethod","params":{"channels":[123x22x12]}}"#;
        assert_eq!(recover_id(msg), Some(json!(123)));
    }

    #[test]
    fn number_id_adjacent_to_nested_id_key_ignored() {
        let msg = r#"{"method":"foo","params":{"id":"decoy"},"id":555}"#;
        assert_eq!(recover_id(msg), Some(json!(555)));
    }
}
