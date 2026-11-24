use crate::codec::JsonCodec;
use anyhow::Context;
use futures::SinkExt;
use serde::Serialize;
use std::sync::Arc;
use tokio::io::AsyncWrite;
use tokio::sync::Mutex;
use tokio::sync::mpsc;
use tokio_util::codec::FramedWrite;

#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "lowercase")]
struct LogEntry {
    level: LogLevel,
    message: String,
}

#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "lowercase")]
enum LogLevel {
    Debug,
    Info,
    Warn,
    Error,
    Trace,
}

impl From<log::Level> for LogLevel {
    fn from(lvl: log::Level) -> Self {
        match lvl {
            log::Level::Error => LogLevel::Error,
            log::Level::Warn => LogLevel::Warn,
            log::Level::Info => LogLevel::Info,
            log::Level::Debug => LogLevel::Debug,
            log::Level::Trace => LogLevel::Trace,
        }
    }
}

/// Start a listener that receives incoming log events, and then
/// writes them out to `stdout`, after wrapping them in a valid
/// JSON-RPC notification object.
fn spawn_writer<O>(
    out: Arc<Mutex<FramedWrite<O, JsonCodec>>>,
    mut receiver: mpsc::UnboundedReceiver<LogEntry>,
) where
    O: AsyncWrite + Send + Unpin + 'static,
{
    tokio::spawn(async move {
        while let Some(i) = receiver.recv().await {
            // We continue draining the queue, even if we get some
            // errors when forwarding. Forwarding could break due to
            // an interrupted connection or stdout being closed, but
            // keeping the messages in the queue is a memory leak.
            let payload = json!({
                "jsonrpc": "2.0",
                "method": "log",
                "params": i
            });

            let _ = out.lock().await.send(payload).await;
        }
    });
}

/// Initialize the logger starting a flusher to the passed in sink.
pub async fn init<O>(out: Arc<Mutex<FramedWrite<O, JsonCodec>>>) -> Result<(), anyhow::Error>
where
    O: AsyncWrite + Send + Unpin + 'static,
{
    return trace::init(out).context("initializing tracing logger");
}

mod trace {
    use super::*;
    use tracing::Level;
    use tracing_subscriber::Layer;
    use tracing_subscriber::prelude::*;

    /// Initialize the logger starting a flusher to the passed in sink.
    pub fn init<O>(
        out: Arc<Mutex<FramedWrite<O, JsonCodec>>>,
    ) -> Result<(), tracing_subscriber::util::TryInitError>
    where
        O: AsyncWrite + Send + Unpin + 'static,
    {
        let filter = tracing_subscriber::filter::EnvFilter::builder()
            .with_default_directive(tracing_subscriber::filter::LevelFilter::INFO.into())
            .with_env_var("CLN_PLUGIN_LOG")
            .from_env_lossy();
        let (sender, receiver) = mpsc::unbounded_channel::<LogEntry>();

        tracing_subscriber::registry()
            .with(filter)
            .with(LoggingLayer::new(sender))
            .try_init()?;

        spawn_writer(out, receiver);
        Ok(())
    }

    struct LoggingLayer {
        sender: mpsc::UnboundedSender<LogEntry>,
    }
    impl LoggingLayer {
        fn new(sender: mpsc::UnboundedSender<LogEntry>) -> Self {
            LoggingLayer { sender }
        }
    }

    impl<S> Layer<S> for LoggingLayer
    where
        S: tracing::Subscriber,
    {
        fn on_event(
            &self,
            event: &tracing::Event<'_>,
            _ctx: tracing_subscriber::layer::Context<'_, S>,
        ) {
            let mut extractor = LogExtract::default();
            event.record(&mut extractor);

            let message = match (extractor.msg, extractor.fields.is_empty()) {
                (Some(msg), false) => format!("{msg} [{}]", extractor.fields.join(", ")),
                (Some(msg), true) => msg,
                (None, false) => format!("[{}]", extractor.fields.join(", ")),
                (None, true) => return,
            };

            let level = event.metadata().level().into();
            if let Err(err) = self.sender.send(LogEntry { level, message }) {
                // The writer task is gone, most likely because the
                // runtime is shutting down. We must not panic, and we
                // must not silently drop the message, so write it to
                // stderr: stdout is the JSON-RPC channel to
                // lightningd.
                let entry = err.0;
                eprintln!("{:?}: {}", entry.level, entry.message);
            }
        }
    }

    impl From<&Level> for LogLevel {
        fn from(l: &Level) -> LogLevel {
            match l {
                &Level::DEBUG => LogLevel::Debug,
                &Level::ERROR => LogLevel::Error,
                &Level::INFO => LogLevel::Info,
                &Level::WARN => LogLevel::Warn,
                &Level::TRACE => LogLevel::Trace,
            }
        }
    }

    /// Extracts the message from the visitor
    #[derive(Default)]
    struct LogExtract {
        msg: Option<String>,
        fields: Vec<String>,
    }

    impl LogExtract {
        fn record_quoted(&mut self, field_name: &str, value: String) {
            if field_name == "message" {
                self.msg = Some(value);
            } else if !is_log_metadata_field(field_name) {
                self.fields.push(format!("{field_name}=\"{value}\""));
            }
        }

        fn record_unquoted(&mut self, field_name: &str, value: impl std::fmt::Display) {
            if field_name == "message" {
                self.msg = Some(value.to_string());
            } else if !is_log_metadata_field(field_name) {
                self.fields.push(format!("{field_name}={value}"));
            }
        }
    }

    impl tracing::field::Visit for LogExtract {
        fn record_f64(&mut self, field: &tracing::field::Field, value: f64) {
            self.record_unquoted(field.name(), value);
        }

        fn record_i64(&mut self, field: &tracing::field::Field, value: i64) {
            self.record_unquoted(field.name(), value);
        }

        fn record_u64(&mut self, field: &tracing::field::Field, value: u64) {
            self.record_unquoted(field.name(), value);
        }

        fn record_i128(&mut self, field: &tracing::field::Field, value: i128) {
            self.record_unquoted(field.name(), value);
        }

        fn record_u128(&mut self, field: &tracing::field::Field, value: u128) {
            self.record_unquoted(field.name(), value);
        }

        fn record_bool(&mut self, field: &tracing::field::Field, value: bool) {
            self.record_unquoted(field.name(), value);
        }

        fn record_str(&mut self, field: &tracing::field::Field, value: &str) {
            self.record_quoted(field.name(), value.to_owned());
        }

        fn record_debug(&mut self, field: &tracing::field::Field, value: &dyn std::fmt::Debug) {
            self.record_quoted(field.name(), format!("{value:?}"));
        }
    }

    fn is_log_metadata_field(name: &str) -> bool {
        matches!(
            name,
            "log.target" | "log.module_path" | "log.file" | "log.line"
        )
    }

    #[cfg(test)]
    mod tests {
        use super::*;

        /// The writer task may be gone by the time an event is
        /// emitted, e.g., during shutdown. The `send` then fails with
        /// a `SendError`, but logging must never panic: the entry
        /// must be written to stderr instead.
        #[test]
        fn test_logging_layer_with_dropped_writer() {
            let (sender, receiver) = mpsc::unbounded_channel::<LogEntry>();
            drop(receiver); // Simulate the writer task having exited.

            let subscriber = tracing_subscriber::registry().with(LoggingLayer::new(sender));
            tracing::subscriber::with_default(subscriber, || {
                tracing::info!("this must not panic");
            });
        }

        #[test]
        fn test_logging_layer_structured_event_without_message() {
            let (sender, mut receiver) = mpsc::unbounded_channel::<LogEntry>();
            let subscriber = tracing_subscriber::registry().with(LoggingLayer::new(sender));

            tracing::subscriber::with_default(subscriber, || {
                tracing::info!(peer_id = "alice", amount = 1000);
            });

            let entry = receiver
                .try_recv()
                .expect("structured tracing event without message field was dropped");
            assert_eq!(entry.message, r#"[peer_id="alice", amount=1000]"#);
        }

        #[test]
        fn test_logging_layer_field_quoting() {
            let (sender, mut receiver) = mpsc::unbounded_channel::<LogEntry>();
            let subscriber = tracing_subscriber::registry().with(LoggingLayer::new(sender));

            let url = "ws://127.0.0.1:37473";
            tracing::subscriber::with_default(subscriber, || {
                tracing::info!(
                    peer = "alice",
                    url = %url,
                    count = 3,
                    ratio = 1.5,
                    ok = true,
                    "hello"
                );
            });

            let entry = receiver.try_recv().unwrap();
            assert_eq!(
                entry.message,
                r#"hello [peer="alice", url="ws://127.0.0.1:37473", count=3, ratio=1.5, ok=true]"#
            );
        }

        #[tokio::test]
        async fn test_logging_init_twice_returns_err_instead_of_panicking() {
            let out1 = Arc::new(Mutex::new(FramedWrite::new(
                tokio::io::sink(),
                JsonCodec::default(),
            )));
            let out2 = Arc::new(Mutex::new(FramedWrite::new(
                tokio::io::sink(),
                JsonCodec::default(),
            )));

            crate::logging::init(out1).await.unwrap();
            assert!(crate::logging::init(out2).await.is_err());
        }
    }
}
