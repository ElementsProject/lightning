use crate::codec::JsonCodec;
use anyhow::Context;
use futures::SinkExt;
use serde::Serialize;
use std::sync::Arc;
use tokio::io::AsyncWrite;
use tokio::sync::mpsc;
use tokio::sync::Mutex;
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
}

impl From<log::Level> for LogLevel {
    fn from(lvl: log::Level) -> Self {
        match lvl {
            log::Level::Error => LogLevel::Error,
            log::Level::Warn => LogLevel::Warn,
            log::Level::Info => LogLevel::Info,
            log::Level::Debug | log::Level::Trace => LogLevel::Debug,
        }
    }
}

/// Start a listener that receives incoming log events, and then
/// writes them out to `stdout`, after wrapping them in a valid
/// JSON-RPC notification object.
fn start_writer<O>(out: Arc<Mutex<FramedWrite<O, JsonCodec>>>) -> mpsc::UnboundedSender<LogEntry>
where
    O: AsyncWrite + Send + Unpin + 'static,
{
    let (sender, mut receiver) = mpsc::unbounded_channel::<LogEntry>();
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
    sender
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
    use tracing_subscriber::prelude::*;
    use tracing_subscriber::Layer;

    /// Initialize the logger starting a flusher to the passed in sink.
    pub fn init<O>(out: Arc<Mutex<FramedWrite<O, JsonCodec>>>) -> Result<(), log::SetLoggerError>
    where
        O: AsyncWrite + Send + Unpin + 'static,
    {
        let filter = tracing_subscriber::filter::EnvFilter::builder()
            .with_default_directive(tracing_subscriber::filter::LevelFilter::INFO.into())
            .with_env_var("CLN_PLUGIN_LOG")
            .from_env_lossy();
        let sender = start_writer(out);

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
            let message = match extractor.msg {
                Some(m) => m,
                None => return,
            };
            let level = event.metadata().level().into();
            self.sender.send(LogEntry { level, message }).unwrap();
        }
    }

    impl From<&Level> for LogLevel {
        fn from(l: &Level) -> LogLevel {
            match l {
                &Level::DEBUG => LogLevel::Debug,
                &Level::ERROR => LogLevel::Error,
                &Level::INFO => LogLevel::Info,
                &Level::WARN => LogLevel::Warn,
                &Level::TRACE => LogLevel::Debug,
            }
        }
    }

    /// Extracts the message from the visitor
    #[derive(Default)]
    struct LogExtract {
        msg: Option<String>,
    }

    impl tracing::field::Visit for LogExtract {
        fn record_debug(&mut self, field: &tracing::field::Field, value: &dyn std::fmt::Debug) {
            if field.name() != "message" {
                return;
            }
            self.msg = Some(format!("{:?}", value));
        }
    }
}
