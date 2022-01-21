use crate::codec::JsonCodec;
use futures::SinkExt;
use log::{Level, Metadata, Record};
use serde::Serialize;
use std::sync::Arc;
use tokio::io::AsyncWrite;
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

/// A simple logger that just wraps log entries in a JSON-RPC
/// notification and delivers it to `lightningd`.
struct PluginLogger {
    // An unbounded mpsc channel we can use to talk to the
    // flusher. This avoids having circular locking dependencies if we
    // happen to emit a log record while holding the lock on the
    // plugin connection.
    sender: tokio::sync::mpsc::UnboundedSender<LogEntry>,
}

/// Initialize the logger starting a flusher to the passed in sink.
pub async fn init<O>(out: Arc<Mutex<FramedWrite<O, JsonCodec>>>) -> Result<(), log::SetLoggerError>
where
    O: AsyncWrite + Send + Unpin + 'static,
{
    let out = out.clone();
    let (sender, mut receiver) = tokio::sync::mpsc::unbounded_channel::<LogEntry>();
    tokio::spawn(async move {
        while let Some(i) = receiver.recv().await {
            // We continue draining the queue, even if we get some
            // errors when forwarding. Forwarding could break due to
            // an interrupted connection or stdout being closed, but
            // keeping the messages in the queue is a memory leak.
            let _ = out
                .lock()
                .await
                .send(json!({
                    "jsonrpc": "2.0",
                    "method": "log",
                    "params": i
                }))
                .await;
        }
    });
    log::set_boxed_logger(Box::new(PluginLogger { sender }))
        .map(|()| log::set_max_level(log::LevelFilter::Debug))
}

impl log::Log for PluginLogger {
    fn enabled(&self, metadata: &Metadata) -> bool {
        metadata.level() <= Level::Debug
    }

    fn log(&self, record: &Record) {
        if self.enabled(record.metadata()) {
            self.sender
                .send(LogEntry {
                    level: record.level().into(),
                    message: record.args().to_string(),
                })
                .unwrap();
        }
    }

    fn flush(&self) {}
}
