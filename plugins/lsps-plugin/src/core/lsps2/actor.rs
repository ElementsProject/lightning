use crate::{
    core::lsps2::{
        event_sink::{EventSink, SessionEventEnvelope},
        provider::{DatastoreProvider, ForwardActivity, RecoveryProvider},
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
use tokio::{
    sync::{mpsc, oneshot},
    task::JoinHandle,
};

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
    CollectTimeout,
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
    collect_timeout_handle: Option<JoinHandle<()>>,
    channel_poll_handle: Option<JoinHandle<()>>,
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
            collect_timeout_handle: None,
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
        channel_id: String,
        executor: A,
        scid: ShortChannelId,
        datastore: D,
        recovery: Arc<dyn RecoveryProvider>,
        forwards_updated_index: Option<u64>,
        event_sink: Arc<dyn EventSink>,
    ) -> ActorInboxHandle {
        let (tx, inbox) = mpsc::channel(128);
        let handle = ActorInboxHandle { tx: tx.clone() };

        let actor = SessionActor {
            session,
            entry,
            inbox,
            pending_htlcs: HashMap::new(),
            collect_timeout_handle: None,
            channel_poll_handle: None,
            self_send: tx,
            executor,
            peer_id: String::new(),
            collect_timeout_secs: 0,
            scid,
            datastore,
            event_sink,
        };

        tokio::spawn(actor.run_recovered(
            initial_actions,
            channel_id,
            recovery,
            forwards_updated_index,
        ));
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

    fn start_collect_timeout(&mut self) {
        let tx = self.self_send.clone();
        let timeout = Duration::from_secs(self.collect_timeout_secs);
        self.collect_timeout_handle = Some(tokio::spawn(async move {
            tokio::time::sleep(timeout).await;
            let _ = tx.send(ActorInput::CollectTimeout).await;
        }));
    }

    fn cancel_collect_timeout(&mut self) {
        if let Some(handle) = self.collect_timeout_handle.take() {
            handle.abort();
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
        self.start_collect_timeout();
        while let Some(input) = self.inbox.recv().await {
            let input = match input {
                ActorInput::AddPart { part, reply_tx } => {
                    let htlc_id = part.htlc_id;
                    self.pending_htlcs.insert(htlc_id, reply_tx);
                    SessionInput::AddPart { part }
                }
                ActorInput::CollectTimeout => SessionInput::CollectTimeout,
                ActorInput::ChannelReady {
                    channel_id,
                    funding_psbt,
                } => {
                    self.entry.channel_id = Some(channel_id.clone());
                    self.entry.funding_psbt = Some(funding_psbt.clone());
                    if let Err(e) = self.datastore.save_session(&self.scid, &self.entry).await {
                        warn!("save_session failed on ChannelReady: {e}");
                    }
                    SessionInput::ChannelReady {
                        channel_id,
                        funding_psbt,
                    }
                }
                ActorInput::FundingFailed => SessionInput::FundingFailed,
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
                    SessionInput::PaymentSettled
                }
                ActorInput::PaymentFailed { updated_index } => {
                    if let Some(index) = updated_index {
                        self.entry.forwards_updated_index = Some(index);
                        if let Err(e) = self.datastore.save_session(&self.scid, &self.entry).await {
                            warn!("save_session failed on PaymentFailed: {e}");
                        }
                    }
                    SessionInput::PaymentFailed
                }
                ActorInput::FundingBroadcasted { txid } => {
                    self.entry.funding_txid = Some(txid);
                    if let Err(e) = self.datastore.save_session(&self.scid, &self.entry).await {
                        warn!("save_session failed on FundingBroadcasted: {e}");
                    }
                    SessionInput::FundingBroadcasted
                }
                ActorInput::NewBlock { height } => SessionInput::NewBlock { height },
                ActorInput::ChannelClosed { channel_id } => {
                    SessionInput::ChannelClosed { channel_id }
                }
            };

            match self.session.apply(input) {
                Ok(result) => {
                    self.dispatch_events(result.events);

                    for action in result.actions {
                        self.execute_action(action);
                    }

                    if self.session.is_terminal() {
                        break;
                    }
                }
                Err(e) => {
                    warn!("session FSM error: {e}");
                    if self.session.is_terminal() {
                        self.release_pending_htlcs();
                        break;
                    }
                }
            }
        }

        // We exited the loop, just continue all held HTLCs and let the handler
        // decide.
        self.release_pending_htlcs();
        Self::finalize(&self.session, &self.datastore, self.scid).await;
    }

    async fn run_recovered(
        mut self,
        initial_actions: Vec<SessionAction>,
        channel_id: String,
        recovery: Arc<dyn RecoveryProvider>,
        forwards_updated_index: Option<u64>,
    ) {
        // Execute initial actions (e.g., BroadcastFundingTx for Broadcasting state)
        for action in initial_actions {
            self.execute_action(action);
        }

        if self.session.is_terminal() {
            Self::finalize(&self.session, &self.datastore, self.scid).await;
            return;
        }

        // Start forward monitoring
        let from_index = forwards_updated_index.unwrap_or(0);
        let self_tx = self.self_send.clone();
        let monitor_handle = {
            let recovery = recovery.clone();
            let channel_id = channel_id.clone();
            let scid = self.scid;

            tokio::spawn(async move {
                // First: check listforwards for already-settled forwards
                match recovery.get_forward_activity(&channel_id).await {
                    Ok(ForwardActivity::Settled) => {
                        let _ = self_tx
                            .send(ActorInput::PaymentSettled {
                                preimage: None,
                                updated_index: None,
                            })
                            .await;
                        return;
                    }
                    Ok(ForwardActivity::AllFailed) => {
                        let _ = self_tx
                            .send(ActorInput::PaymentFailed { updated_index: None })
                            .await;
                        return;
                    }
                    Ok(ForwardActivity::Offered)
                    | Ok(ForwardActivity::NoForwards)
                    | Err(_) => {
                        // Fall through to wait loop
                    }
                }

                // Poll using wait subsystem
                let mut current_index = from_index;
                loop {
                    match recovery
                        .wait_for_forward_resolution(&channel_id, current_index)
                        .await
                    {
                        Ok((ForwardActivity::Settled, new_index)) => {
                            let _ = self_tx
                                .send(ActorInput::PaymentSettled {
                                    preimage: None,
                                    updated_index: Some(new_index),
                                })
                                .await;
                            return;
                        }
                        Ok((ForwardActivity::AllFailed, new_index)) => {
                            let _ = self_tx
                                .send(ActorInput::PaymentFailed {
                                    updated_index: Some(new_index),
                                })
                                .await;
                            return;
                        }
                        Ok((ForwardActivity::Offered, new_index))
                        | Ok((ForwardActivity::NoForwards, new_index)) => {
                            current_index = new_index;
                            continue;
                        }
                        Err(e) => {
                            warn!("forward monitoring error for scid={scid}: {e}");
                            tokio::time::sleep(Duration::from_secs(5)).await;
                            continue;
                        }
                    }
                }
            })
        };

        // Main loop: process inbox events
        loop {
            match self.inbox.recv().await {
                Some(actor_input) => {
                    let session_input = match actor_input {
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
                            SessionInput::PaymentSettled
                        }
                        ActorInput::PaymentFailed { updated_index } => {
                            if let Some(index) = updated_index {
                                self.entry.forwards_updated_index = Some(index);
                                if let Err(e) = self.datastore.save_session(&self.scid, &self.entry).await {
                                    warn!("save_session failed on PaymentFailed: {e}");
                                }
                            }
                            SessionInput::PaymentFailed
                        }
                        ActorInput::FundingBroadcasted { txid } => {
                            self.entry.funding_txid = Some(txid);
                            if let Err(e) = self.datastore.save_session(&self.scid, &self.entry).await {
                                warn!("save_session failed on FundingBroadcasted: {e}");
                            }
                            SessionInput::FundingBroadcasted
                        }
                        _ => continue,
                    };

                    match self.session.apply(session_input) {
                        Ok(result) => {
                            self.dispatch_events(result.events);
                            for action in result.actions {
                                self.execute_action(action);
                            }
                        }
                        Err(e) => {
                            warn!("FSM error in recovered session: {e}");
                            break;
                        }
                    }

                    if self.session.is_terminal() {
                        break;
                    }
                }
                None => break,
            }
        }

        monitor_handle.abort();
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
                // First time forwarding HTLCs, we cancel the collect timeout
                // and start polling the channel for closure:
                self.cancel_collect_timeout();
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
