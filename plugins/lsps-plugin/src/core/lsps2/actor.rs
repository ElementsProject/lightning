use crate::{
    core::lsps2::{
        event_sink::{EventSink, SessionEventEnvelope},
        provider::DatastoreProvider,
        session::{PaymentPart, Session, SessionAction, SessionEvent, SessionInput},
    },
    proto::{
        lsps0::{Msat, ShortChannelId},
        lsps2::{DatastoreEntry, OpeningFeeParams},
    },
};
use anyhow::Result;
use async_trait::async_trait;
use bitcoin::hashes::sha256::Hash as PaymentHash;
use bitcoin::hashes::Hash;
use log::{debug, warn};
use std::{collections::HashMap, sync::Arc, time::Duration};
use tokio::sync::{mpsc, oneshot};

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HtlcResponse {
    Forward {
        channel_id: String,
        fee_msat: u64,
        forward_msat: u64,
    },
    Fail {
        failure_code: &'static str,
    },
    Continue,
}

enum ActorInput {
    AddPart {
        part: PaymentPart,
        reply_tx: oneshot::Sender<HtlcResponse>,
    },
    ChannelReady {
        channel_id: String,
        funding_psbt: String,
    },
    FundingFailed,
    PaymentSettled {
        preimage: Option<String>,
        updated_index: Option<u64>,
    },
    PaymentFailed {
        updated_index: Option<u64>,
    },
    FundingBroadcasted { txid: String },
    NewBlock {
        height: u32,
    },
    ChannelClosed {
        channel_id: String,
    },
}

/// Adapter for FSM side-effect actions.
#[async_trait]
pub trait ActionExecutor {
    async fn fund_channel(
        &self,
        peer_id: String,
        channel_capacity_msat: Msat,
        opening_fee_params: OpeningFeeParams,
        scid: ShortChannelId,
    ) -> Result<(String, String)>;

    async fn abandon_session(&self, channel_id: String, funding_psbt: String) -> Result<()>;

    async fn broadcast_tx(&self, channel_id: String, funding_psbt: String) -> Result<String>;

    async fn disconnect(&self, peer_id: String) -> Result<()>;

    async fn is_channel_alive(&self, channel_id: &str) -> Result<bool>;
}

#[derive(Debug, Clone)]
pub struct ActorInboxHandle {
    tx: mpsc::Sender<ActorInput>,
}

impl ActorInboxHandle {
    pub async fn add_part(&self, part: PaymentPart) -> Result<HtlcResponse> {
        let (reply_tx, rx) = oneshot::channel();
        self.tx.send(ActorInput::AddPart { part, reply_tx }).await?;
        Ok(rx.await?)
    }

    pub async fn payment_settled(
        &self,
        preimage: Option<String>,
        updated_index: Option<u64>,
    ) -> Result<()> {
        Ok(self
            .tx
            .send(ActorInput::PaymentSettled {
                preimage,
                updated_index,
            })
            .await?)
    }

    pub async fn payment_failed(&self, updated_index: Option<u64>) -> Result<()> {
        Ok(self
            .tx
            .send(ActorInput::PaymentFailed { updated_index })
            .await?)
    }

    pub async fn new_block(&self, height: u32) -> Result<()> {
        Ok(self.tx.send(ActorInput::NewBlock { height }).await?)
    }
}

/// Per-session actor that drives the LSPS2 syncronous session FSM and bridges
/// it to async side effects.
///
/// It's the runtime boundary around a single `Session`. It owns input ordering,
/// pending HTLC replies, timeout handling, and execution of FMS-emitted side
/// effects and actions.
pub struct SessionActor<A, D> {
    session: Session,
    entry: DatastoreEntry,
    inbox: mpsc::Receiver<ActorInput>,
    pending_htlcs: HashMap<u64, oneshot::Sender<HtlcResponse>>,
    collect_fired: bool,
    channel_poll_handle: Option<tokio::task::JoinHandle<()>>,
    self_send: mpsc::Sender<ActorInput>,
    executor: A,
    peer_id: String,
    collect_timeout_secs: u64,
    scid: ShortChannelId,
    datastore: D,
    event_sink: Arc<dyn EventSink>,
}

impl<A: ActionExecutor + Clone + Send + 'static, D: DatastoreProvider + Clone + Send + 'static>
    SessionActor<A, D>
{
    pub fn spawn_session_actor(
        session: Session,
        entry: DatastoreEntry,
        executor: A,
        peer_id: String,
        collect_timeout_secs: u64,
        scid: ShortChannelId,
        datastore: D,
        event_sink: Arc<dyn EventSink>,
    ) -> ActorInboxHandle {
        let (tx, inbox) = mpsc::channel(128); // Should we use max_htlcs?
        let actor = SessionActor {
            session,
            entry,
            inbox,
            pending_htlcs: HashMap::new(),
            collect_fired: false,
            channel_poll_handle: None,
            self_send: tx.clone(),
            executor,
            peer_id,
            collect_timeout_secs,
            scid,
            datastore,
            event_sink,
        };
        tokio::spawn(actor.run());
        ActorInboxHandle { tx }
    }

    pub fn spawn_recovered_session_actor(
        session: Session,
        entry: DatastoreEntry,
        initial_actions: Vec<SessionAction>,
        executor: A,
        scid: ShortChannelId,
        datastore: D,
        event_sink: Arc<dyn EventSink>,
    ) -> ActorInboxHandle {
        let (tx, inbox) = mpsc::channel(128);
        let handle = ActorInboxHandle { tx: tx.clone() };

        let actor = SessionActor {
            session,
            entry,
            inbox,
            pending_htlcs: HashMap::new(),
            collect_fired: true,
            channel_poll_handle: None,
            self_send: tx,
            executor,
            peer_id: String::new(),
            collect_timeout_secs: 0,
            scid,
            datastore,
            event_sink,
        };

        tokio::spawn(actor.run_recovered(initial_actions));
        handle
    }

    fn dispatch_events(&self, events: Vec<SessionEvent>) {
        let payment_hash = match self.entry.payment_hash.as_deref() {
            Some(s) => match s.parse::<PaymentHash>() {
                Ok(h) => h,
                Err(e) => {
                    warn!("malformed payment_hash in datastore for scid={}: {e}", self.scid);
                    PaymentHash::all_zeros()
                }
            },
            None => PaymentHash::all_zeros(),
        };
        for event in events {
            debug!("session event: {:?}", event);
            self.event_sink.send(&SessionEventEnvelope {
                scid: self.scid,
                payment_hash,
                event,
            });
        }
    }

    async fn convert_input(&mut self, input: ActorInput) -> Option<SessionInput> {
        match input {
            ActorInput::AddPart { part, reply_tx } => {
                let htlc_id = part.htlc_id;
                self.pending_htlcs.insert(htlc_id, reply_tx);
                Some(SessionInput::AddPart { part })
            }
            ActorInput::ChannelReady {
                channel_id,
                funding_psbt,
            } => {
                self.entry.channel_id = Some(channel_id.clone());
                self.entry.funding_psbt = Some(funding_psbt.clone());
                if let Err(e) = self.datastore.save_session(&self.scid, &self.entry).await {
                    warn!("save_session failed on ChannelReady: {e}");
                }
                Some(SessionInput::ChannelReady {
                    channel_id,
                    funding_psbt,
                })
            }
            ActorInput::FundingFailed => Some(SessionInput::FundingFailed),
            ActorInput::PaymentSettled {
                preimage,
                updated_index,
            } => {
                if let Some(index) = updated_index {
                    self.entry.forwards_updated_index = Some(index);
                }
                if let Some(ref pre) = preimage {
                    self.entry.preimage = Some(pre.clone());
                }
                if updated_index.is_some() || preimage.is_some() {
                    if let Err(e) = self.datastore.save_session(&self.scid, &self.entry).await {
                        warn!("save_session failed on PaymentSettled: {e}");
                    }
                }
                Some(SessionInput::PaymentSettled)
            }
            ActorInput::PaymentFailed { updated_index } => {
                if let Some(index) = updated_index {
                    self.entry.forwards_updated_index = Some(index);
                    if let Err(e) = self.datastore.save_session(&self.scid, &self.entry).await {
                        warn!("save_session failed on PaymentFailed: {e}");
                    }
                }
                Some(SessionInput::PaymentFailed)
            }
            ActorInput::FundingBroadcasted { txid } => {
                self.entry.funding_txid = Some(txid);
                if let Err(e) = self.datastore.save_session(&self.scid, &self.entry).await {
                    warn!("save_session failed on FundingBroadcasted: {e}");
                }
                Some(SessionInput::FundingBroadcasted)
            }
            ActorInput::NewBlock { height } => Some(SessionInput::NewBlock { height }),
            ActorInput::ChannelClosed { channel_id } => {
                Some(SessionInput::ChannelClosed { channel_id })
            }
        }
    }

    /// Apply a session input to the FSM and execute resulting actions.
    /// Returns `true` if the session reached a terminal state.
    fn apply_and_execute(&mut self, input: SessionInput) -> bool {
        match self.session.apply(input) {
            Ok(result) => {
                self.dispatch_events(result.events);
                for action in result.actions {
                    self.execute_action(action);
                }
                self.session.is_terminal()
            }
            Err(e) => {
                warn!("session FSM error: {e}");
                if self.session.is_terminal() {
                    self.release_pending_htlcs();
                    true
                } else {
                    false
                }
            }
        }
    }

    fn start_channel_poll(&mut self, channel_id: String) {
        let tx = self.self_send.clone();
        let executor = self.executor.clone();
        self.channel_poll_handle = Some(tokio::spawn(async move {
            let interval = Duration::from_secs(5);
            loop {
                tokio::time::sleep(interval).await;
                match executor.is_channel_alive(&channel_id).await {
                    Ok(true) => continue,
                    Ok(false) | Err(_) => {
                        let _ = tx
                            .send(ActorInput::ChannelClosed {
                                channel_id: channel_id.clone(),
                            })
                            .await;
                        break;
                    }
                }
            }
        }));
    }

    fn cancel_channel_poll(&mut self) {
        if let Some(handle) = self.channel_poll_handle.take() {
            handle.abort();
        }
    }

    async fn run(mut self) {
        let collect_deadline = tokio::time::sleep(
            Duration::from_secs(self.collect_timeout_secs),
        );
        tokio::pin!(collect_deadline);

        loop {
            tokio::select! {
                input = self.inbox.recv() => {
                    let Some(input) = input else { break };
                    let Some(session_input) = self.convert_input(input).await else {
                        continue;
                    };
                    if self.apply_and_execute(session_input) {
                        break;
                    }
                }
                _ = &mut collect_deadline, if !self.collect_fired => {
                    self.collect_fired = true;
                    if self.apply_and_execute(SessionInput::CollectTimeout) {
                        break;
                    }
                }
            }
        }

        self.release_pending_htlcs();
        Self::finalize(&self.session, &self.datastore, self.scid).await;
    }

    async fn run_recovered(
        mut self,
        initial_actions: Vec<SessionAction>,
    ) {
        // Execute initial actions (e.g., BroadcastFundingTx for Broadcasting state)
        for action in initial_actions {
            self.execute_action(action);
        }

        if self.session.is_terminal() {
            Self::finalize(&self.session, &self.datastore, self.scid).await;
            return;
        }

        // Main loop: process inbox events from forward_event notifications
        loop {
            match self.inbox.recv().await {
                Some(actor_input) => {
                    // Only process settlement/failure/broadcast events
                    let session_input = match &actor_input {
                        ActorInput::PaymentSettled { .. }
                        | ActorInput::PaymentFailed { .. }
                        | ActorInput::FundingBroadcasted { .. } => {
                            self.convert_input(actor_input).await
                        }
                        _ => continue,
                    };

                    if let Some(input) = session_input {
                        if self.apply_and_execute(input) {
                            break;
                        }
                    }
                }
                None => break,
            }
        }

        Self::finalize(&self.session, &self.datastore, self.scid).await;
    }

    async fn finalize(session: &Session, datastore: &D, scid: ShortChannelId) {
        if let Some(outcome) = session.outcome() {
            if let Err(e) = datastore.finalize_session(&scid, outcome).await {
                warn!("finalize_session failed for scid={scid}: {e}");
            }
        }
    }

    fn execute_action(&mut self, action: SessionAction) {
        match action {
            SessionAction::FailHtlcs { failure_code } => {
                for (_, reply_tx) in self.pending_htlcs.drain() {
                    let _ = reply_tx.send(HtlcResponse::Fail { failure_code });
                }
            }
            SessionAction::ForwardHtlcs { parts, channel_id } => {
                // First time forwarding HTLCs, we mark the collect timeout as
                // fired and start polling the channel for closure:
                self.collect_fired = true;
                self.start_channel_poll(channel_id.clone());
                for part in &parts {
                    if let Some(reply_tx) = self.pending_htlcs.remove(&part.htlc_id) {
                        let _ = reply_tx.send(HtlcResponse::Forward {
                            channel_id: channel_id.clone(),
                            fee_msat: part.fee_msat,
                            forward_msat: part.forward_msat,
                        });
                    }
                }
            }
            SessionAction::FundChannel {
                peer_id,
                channel_capacity_msat,
                opening_fee_params,
            } => {
                let executor = self.executor.clone();
                let self_tx = self.self_send.clone();
                let scid = self.scid;
                tokio::spawn(async move {
                    match executor
                        .fund_channel(peer_id, channel_capacity_msat, opening_fee_params, scid)
                        .await
                    {
                        Ok((channel_id, funding_psbt)) => {
                            let _ = self_tx
                                .send(ActorInput::ChannelReady {
                                    channel_id,
                                    funding_psbt,
                                })
                                .await;
                        }
                        Err(e) => {
                            warn!("fund_channel failed: {e}");
                            let _ = self_tx.send(ActorInput::FundingFailed).await;
                        }
                    }
                });
            }
            SessionAction::FailSession => {
                // Is basically a no-op as it is always accompanied with FailHtlcs.
                let n = self.release_pending_htlcs();
                debug_assert_eq!(n, 0);
            }
            SessionAction::AbandonSession {
                channel_id,
                funding_psbt,
            } => {
                // Is also basically a no-op as all htlcs should have been
                // already forwarded.
                let n = self.release_pending_htlcs();
                debug_assert_eq!(n, 0);

                let executor = self.executor.clone();
                tokio::spawn(async move {
                    if let Err(e) = executor
                        .abandon_session(channel_id.clone(), funding_psbt.clone())
                        .await
                    {
                        warn!(
                            "abandon_session failed (channel_id={}, funding_psbt={}): {}",
                            channel_id, funding_psbt, e
                        );
                    }
                });
            }
            SessionAction::BroadcastFundingTx {
                channel_id,
                funding_psbt,
            } => {
                self.cancel_channel_poll();
                let executor = self.executor.clone();
                let self_tx = self.self_send.clone();
                tokio::spawn(async move {
                    match executor
                        .broadcast_tx(channel_id.clone(), funding_psbt.clone())
                        .await
                    {
                        Ok(txid) => {
                            let _ = self_tx.send(ActorInput::FundingBroadcasted { txid }).await;
                        }
                        Err(e) => {
                            warn!(
                                "broadcast_tx failed (channel_id={}, funding_psbt={}): {}",
                                channel_id, funding_psbt, e
                            );
                        }
                    }
                });
            }
            SessionAction::Disconnect => {
                let executor = self.executor.clone();
                let peer_id = self.peer_id.clone();
                tokio::spawn(async move {
                    if let Err(e) = executor.disconnect(peer_id.clone()).await {
                        warn!("disconnect failed (peer_id={}): {}", peer_id, e);
                    }
                });
            }
        }
    }

    fn release_pending_htlcs(&mut self) -> usize {
        let n = self.pending_htlcs.iter().len();
        for (_, reply_tx) in self.pending_htlcs.drain() {
            let _ = reply_tx.send(HtlcResponse::Continue);
        }
        n
    }
}

#[async_trait]
impl<T: ActionExecutor + Send + Sync> ActionExecutor for Arc<T> {
    async fn fund_channel(
        &self,
        peer_id: String,
        channel_capacity_msat: Msat,
        opening_fee_params: OpeningFeeParams,
        scid: ShortChannelId,
    ) -> Result<(String, String)> {
        (**self)
            .fund_channel(peer_id, channel_capacity_msat, opening_fee_params, scid)
            .await
    }

    async fn abandon_session(&self, channel_id: String, funding_psbt: String) -> Result<()> {
        (**self).abandon_session(channel_id, funding_psbt).await
    }

    async fn broadcast_tx(&self, channel_id: String, funding_psbt: String) -> Result<String> {
        (**self).broadcast_tx(channel_id, funding_psbt).await
    }

    async fn disconnect(&self, peer_id: String) -> Result<()> {
        (**self).disconnect(peer_id).await
    }

    async fn is_channel_alive(&self, channel_id: &str) -> Result<bool> {
        (**self).is_channel_alive(channel_id).await
    }
}

#[async_trait]
impl<T: DatastoreProvider + Send + Sync> DatastoreProvider for Arc<T> {
    async fn store_buy_request(
        &self,
        scid: &ShortChannelId,
        peer_id: &bitcoin::secp256k1::PublicKey,
        offer: &OpeningFeeParams,
        expected_payment_size: &Option<Msat>,
        channel_capacity_msat: &Msat,
    ) -> Result<DatastoreEntry> {
        (**self)
            .store_buy_request(scid, peer_id, offer, expected_payment_size, channel_capacity_msat)
            .await
    }

    async fn get_buy_request(
        &self,
        scid: &ShortChannelId,
    ) -> Result<DatastoreEntry> {
        (**self).get_buy_request(scid).await
    }

    async fn save_session(
        &self,
        scid: &ShortChannelId,
        entry: &DatastoreEntry,
    ) -> Result<()> {
        (**self).save_session(scid, entry).await
    }

    async fn finalize_session(
        &self,
        scid: &ShortChannelId,
        outcome: crate::proto::lsps2::SessionOutcome,
    ) -> Result<()> {
        (**self).finalize_session(scid, outcome).await
    }

    async fn list_active_sessions(&self) -> Result<Vec<(ShortChannelId, DatastoreEntry)>> {
        (**self).list_active_sessions().await
    }
}
