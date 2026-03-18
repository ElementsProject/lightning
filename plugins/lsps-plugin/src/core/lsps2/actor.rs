use crate::{
    core::lsps2::{
        provider::DatastoreProvider,
        session::{PaymentPart, Session, SessionAction, SessionInput},
    },
    proto::{
        lsps0::{Msat, ShortChannelId},
        lsps2::OpeningFeeParams,
    },
};
use anyhow::Result;
use async_trait::async_trait;
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
    PaymentSettled { preimage: Option<String> },
    PaymentFailed,
    FundingBroadcasted,
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

    pub async fn payment_settled(&self, preimage: Option<String>) -> Result<()> {
        Ok(self.tx.send(ActorInput::PaymentSettled { preimage }).await?)
    }

    pub async fn payment_failed(&self) -> Result<()> {
        Ok(self.tx.send(ActorInput::PaymentFailed).await?)
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
}

impl<A: ActionExecutor + Clone + Send + 'static, D: DatastoreProvider + Clone + Send + 'static>
    SessionActor<A, D>
{
    pub fn spawn_session_actor(
        session: Session,
        executor: A,
        peer_id: String,
        collect_timeout_secs: u64,
        scid: ShortChannelId,
        datastore: D,
    ) -> ActorInboxHandle {
        let (tx, inbox) = mpsc::channel(128); // Should we use max_htlcs?
        let actor = SessionActor {
            session,
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
        };
        tokio::spawn(actor.run());
        ActorInboxHandle { tx }
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
                } => SessionInput::ChannelReady {
                    channel_id,
                    funding_psbt,
                },
                ActorInput::FundingFailed => SessionInput::FundingFailed,
                ActorInput::PaymentSettled { preimage } => {
                    if let Some(ref pre) = preimage {
                        let datastore = self.datastore.clone();
                        let scid = self.scid;
                        let pre = pre.clone();
                        tokio::spawn(async move {
                            if let Err(e) = datastore.update_session_preimage(&scid, &pre).await {
                                warn!("update_session_preimage failed for scid={scid}: {e}");
                            }
                        });
                    }
                    SessionInput::PaymentSettled
                }
                ActorInput::PaymentFailed => SessionInput::PaymentFailed,
                ActorInput::FundingBroadcasted => SessionInput::FundingBroadcasted,
                ActorInput::NewBlock { height } => SessionInput::NewBlock { height },
                ActorInput::ChannelClosed { channel_id } => {
                    SessionInput::ChannelClosed { channel_id }
                }
            };

            match self.session.apply(input) {
                Ok(result) => {
                    for event in &result.events {
                        // Note: Add event handler later on.
                        debug!("session event: {:?}", event);
                    }

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

        if let Some(outcome) = self.session.outcome() {
            if let Err(e) = self.datastore.finalize_session(&self.scid, outcome).await {
                warn!("finalize_session failed for scid={}: {e}", self.scid);
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
                let datastore = self.datastore.clone();
                let scid = self.scid;
                tokio::spawn(async move {
                    match executor
                        .fund_channel(peer_id, channel_capacity_msat, opening_fee_params)
                        .await
                    {
                        Ok((channel_id, funding_psbt)) => {
                            if let Err(e) = datastore
                                .update_session_funding(&scid, &channel_id, &funding_psbt)
                                .await
                            {
                                warn!("update_session_funding failed for scid={scid}: {e}");
                            }
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
                let datastore = self.datastore.clone();
                let scid = self.scid;
                tokio::spawn(async move {
                    match executor
                        .broadcast_tx(channel_id.clone(), funding_psbt.clone())
                        .await
                    {
                        Ok(txid) => {
                            if let Err(e) = datastore
                                .update_session_funding_txid(&scid, &txid)
                                .await
                            {
                                warn!("update_session_funding_txid failed for scid={scid}: {e}");
                            }
                            let _ = self_tx.send(ActorInput::FundingBroadcasted).await;
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
    ) -> Result<(String, String)> {
        (**self)
            .fund_channel(peer_id, channel_capacity_msat, opening_fee_params)
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
    ) -> Result<bool> {
        (**self)
            .store_buy_request(scid, peer_id, offer, expected_payment_size, channel_capacity_msat)
            .await
    }

    async fn get_buy_request(
        &self,
        scid: &ShortChannelId,
    ) -> Result<crate::proto::lsps2::DatastoreEntry> {
        (**self).get_buy_request(scid).await
    }

    async fn del_buy_request(&self, scid: &ShortChannelId) -> Result<()> {
        (**self).del_buy_request(scid).await
    }

    async fn finalize_session(
        &self,
        scid: &ShortChannelId,
        outcome: crate::proto::lsps2::SessionOutcome,
    ) -> Result<()> {
        (**self).finalize_session(scid, outcome).await
    }

    async fn update_session_funding(
        &self,
        scid: &ShortChannelId,
        channel_id: &str,
        funding_psbt: &str,
    ) -> Result<()> {
        (**self)
            .update_session_funding(scid, channel_id, funding_psbt)
            .await
    }

    async fn update_session_funding_txid(
        &self,
        scid: &ShortChannelId,
        funding_txid: &str,
    ) -> Result<()> {
        (**self)
            .update_session_funding_txid(scid, funding_txid)
            .await
    }

    async fn update_session_preimage(
        &self,
        scid: &ShortChannelId,
        preimage: &str,
    ) -> Result<()> {
        (**self).update_session_preimage(scid, preimage).await
    }
}
