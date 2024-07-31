//! The codec is used to encode and decode messages received from and
//! sent to the main daemon. The protocol uses `stdout` and `stdin` to
//! exchange JSON formatted messages. Each message is separated by an
//! empty line and we're guaranteed that no other empty line is
//! present in the messages.
use crate::Error;
use anyhow::anyhow;
use bytes::{BufMut, BytesMut};
use serde_json::value::Value;
use std::str::FromStr;
use std::{io, str};
use tokio_util::codec::{Decoder, Encoder};

pub use crate::jsonrpc::JsonRpc;
use crate::{
    model::{Request},
    notifications::Notification,
};

/// A simple codec that parses messages separated by two successive
/// `\n` newlines.
#[derive(Default)]
pub struct MultiLineCodec {}

/// Find two consecutive newlines, i.e., an empty line, signalling the
/// end of one message and the start of the next message.
fn find_separator(buf: &mut BytesMut) -> Option<usize> {
    buf.iter()
        .zip(buf.iter().skip(1))
        .position(|b| *b.0 == b'\n' && *b.1 == b'\n')
}

fn utf8(buf: &[u8]) -> Result<&str, io::Error> {
    str::from_utf8(buf)
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "Unable to decode input as UTF8"))
}

impl Decoder for MultiLineCodec {
    type Item = String;
    type Error = Error;
    fn decode(&mut self, buf: &mut BytesMut) -> Result<Option<Self::Item>, Error> {
        if let Some(newline_offset) = find_separator(buf) {
            let line = buf.split_to(newline_offset + 2);
            let line = &line[..line.len() - 2];
            let line = utf8(line)?;
            Ok(Some(line.to_string()))
        } else {
            Ok(None)
        }
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
    type Item = Value;
    type Error = Error;

    fn decode(&mut self, buf: &mut BytesMut) -> Result<Option<Self::Item>, Error> {
        match self.inner.decode(buf) {
            Ok(None) => Ok(None),
            Err(e) => Err(e),
            Ok(Some(s)) => {
                if let Ok(v) = Value::from_str(&s) {
                    Ok(Some(v))
                } else {
                    Err(anyhow!("failed to parse JSON"))
                }
            }
        }
    }
}

/// A codec that reads fully formed [crate::messages::JsonRpc]
/// messages. Internally it uses the [JsonCodec] which itself is built
/// on the [MultiLineCodec].
#[allow(dead_code)]
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
            Ok(Some(s)) => {
                let req: Self::Item = serde_json::from_value(s)?;
                Ok(Some(req))
            }
        }
    }
}

#[cfg(test)]
mod test {
    use super::{find_separator, JsonCodec, MultiLineCodec};
    use bytes::{BufMut, BytesMut};
    use serde_json::json;
    use tokio_util::codec::{Decoder, Encoder};

    #[test]
    fn test_separator() {
        struct Test(String, Option<usize>);
        let tests = vec![
            Test("".to_string(), None),
            Test("}\n\n".to_string(), Some(1)),
            Test("\"hello\"},\n\"world\"}\n\n".to_string(), Some(18)),
        ];

        for t in tests.iter() {
            let mut buf = BytesMut::new();
            buf.put_slice(t.0.as_bytes());
            assert_eq!(find_separator(&mut buf), t.1);
        }
    }

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
            let decoded = codec.decode(&mut buf).unwrap().unwrap();
            assert_eq!(&decoded, t);
        }
    }
}
