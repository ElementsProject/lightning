use anyhow::Context;
use serde::Serialize;
use tokio::sync::mpsc;

#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "lowercase")]
pub(crate) struct LogEntry {
    level: LogLevel,
    message: String,
}

#[derive(Serialize)]
pub(crate) struct LogNotification<'a> {
    jsonrpc: &'static str,
    method: &'static str,
    params: &'a LogEntry,
}

impl<'a> LogNotification<'a> {
    pub(crate) fn new(params: &'a LogEntry) -> Self {
        Self {
            jsonrpc: "2.0",
            method: "log",
            params,
        }
    }
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

/// Initialize the logger forwarding log events to the plugin's writer task.
pub async fn init(sender: mpsc::UnboundedSender<LogEntry>) -> Result<(), anyhow::Error> {
    trace::init(sender).context("initializing tracing logger")
}

mod trace {
    use super::*;
    use tracing::Level;
    use tracing_subscriber::Layer;
    use tracing_subscriber::prelude::*;

    /// Initialize the logger forwarding log events to the passed-in channel.
    pub fn init(sender: mpsc::UnboundedSender<LogEntry>) -> Result<(), log::SetLoggerError> {
        let filter = tracing_subscriber::filter::EnvFilter::builder()
            .with_default_directive(tracing_subscriber::filter::LevelFilter::INFO.into())
            .with_env_var("CLN_PLUGIN_LOG")
            .from_env_lossy();

        tracing_subscriber::registry()
            .with(filter)
            .with(LoggingLayer::new(sender))
            .init();

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
            let mut message = match extractor.msg {
                Some(m) => m,
                None => return,
            };

            // Append any additional fields to the message
            if !extractor.fields.is_empty() {
                let fields_str: Vec<String> = extractor
                    .fields
                    .iter()
                    .map(|(k, v)| format!("{}=\"{}\"", k, v))
                    .collect();
                message = format!("{} [{}]", message, fields_str.join(", "));
            }

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
        fields: Vec<(String, String)>,
    }

    impl tracing::field::Visit for LogExtract {
        fn record_debug(&mut self, field: &tracing::field::Field, value: &dyn std::fmt::Debug) {
            let field_name = field.name();
            let field_value = format!("{value:?}");

            if field_name == "message" {
                self.msg = Some(field_value);
            } else if !is_log_metadata_field(field_name) {
                self.fields.push((field_name.to_owned(), field_value));
            }
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
    }
}
