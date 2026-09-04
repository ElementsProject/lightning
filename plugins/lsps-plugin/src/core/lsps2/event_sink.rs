use crate::core::lsps2::session::SessionEvent;
use crate::proto::lsps0::ShortChannelId;
use bitcoin::hashes::sha256::Hash as PaymentHash;
use std::sync::Arc;
use tokio::sync::mpsc;

#[derive(Debug, Clone)]
pub struct SessionEventEnvelope {
    pub scid: ShortChannelId,
    pub payment_hash: PaymentHash,
    pub event: SessionEvent,
}

pub trait EventSink: Send + Sync {
    fn send(&self, envelope: &SessionEventEnvelope);
}

pub struct NoopEventSink;
impl EventSink for NoopEventSink {
    fn send(&self, _: &SessionEventEnvelope) {}
}

pub struct CompositeEventSink {
    sinks: Vec<Arc<dyn EventSink>>,
}

impl CompositeEventSink {
    pub fn new(sinks: Vec<Arc<dyn EventSink>>) -> Self {
        Self { sinks }
    }
}

impl EventSink for CompositeEventSink {
    fn send(&self, envelope: &SessionEventEnvelope) {
        for sink in &self.sinks {
            sink.send(envelope);
        }
    }
}

pub struct ChannelEventSink {
    tx: mpsc::UnboundedSender<SessionEventEnvelope>,
}

impl ChannelEventSink {
    pub fn new() -> (Self, mpsc::UnboundedReceiver<SessionEventEnvelope>) {
        let (tx, rx) = mpsc::unbounded_channel();
        (Self { tx }, rx)
    }
}

impl EventSink for ChannelEventSink {
    fn send(&self, envelope: &SessionEventEnvelope) {
        let _ = self.tx.send(envelope.clone());
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::lsps2::session::SessionEvent;
    use crate::proto::lsps0::ShortChannelId;
    use bitcoin::hashes::sha256::Hash as PaymentHash;
    use bitcoin::hashes::Hash;
    use std::sync::atomic::{AtomicUsize, Ordering};

    fn test_envelope() -> SessionEventEnvelope {
        SessionEventEnvelope {
            scid: ShortChannelId::from(100u64 << 40 | 1u64 << 16),
            payment_hash: PaymentHash::from_byte_array([1; 32]),
            event: SessionEvent::FundingChannel,
        }
    }

    struct CountingSink(AtomicUsize);
    impl CountingSink {
        fn new() -> Self { Self(AtomicUsize::new(0)) }
        fn count(&self) -> usize { self.0.load(Ordering::SeqCst) }
    }
    impl EventSink for CountingSink {
        fn send(&self, _: &SessionEventEnvelope) {
            self.0.fetch_add(1, Ordering::SeqCst);
        }
    }

    #[test]
    fn noop_sink_does_not_panic() {
        let sink = NoopEventSink;
        sink.send(&test_envelope());
    }

    #[test]
    fn composite_fans_out_to_all_sinks() {
        let s1 = Arc::new(CountingSink::new());
        let s2 = Arc::new(CountingSink::new());
        let composite = CompositeEventSink::new(vec![
            s1.clone() as Arc<dyn EventSink>,
            s2.clone(),
        ]);
        composite.send(&test_envelope());
        composite.send(&test_envelope());
        assert_eq!(s1.count(), 2);
        assert_eq!(s2.count(), 2);
    }

    #[test]
    fn composite_with_no_sinks_does_not_panic() {
        let composite = CompositeEventSink::new(vec![]);
        composite.send(&test_envelope());
    }

    #[tokio::test]
    async fn channel_sink_delivers_to_receiver() {
        let (sink, mut rx) = ChannelEventSink::new();
        let envelope = test_envelope();
        sink.send(&envelope);
        sink.send(&envelope);
        let received = rx.recv().await.unwrap();
        assert_eq!(received.scid, envelope.scid);
        let received2 = rx.recv().await.unwrap();
        assert_eq!(received2.scid, envelope.scid);
    }

    #[test]
    fn channel_sink_silently_drops_when_receiver_gone() {
        let (sink, rx) = ChannelEventSink::new();
        drop(rx);
        sink.send(&test_envelope()); // must not panic
    }
}
