use crate::{
    core::lsps2::{
        actor::ActionExecutor,
        provider::{
            Blockheight, BlockheightProvider, DatastoreProvider, Lsps2PolicyProvider,
        },
    },
    proto::{
        lsps0::Msat,
        lsps2::{
            DatastoreEntry, FinalizedDatastoreEntry, Lsps2PolicyBuyRequest, Lsps2PolicyBuyResponse,
            Lsps2PolicyGetInfoRequest, Lsps2PolicyGetInfoResponse, OpeningFeeParams,
            SessionOutcome,
        },
    },
};
use anyhow::{Context, Result};
use async_trait::async_trait;
use bitcoin::secp256k1::PublicKey;
use cln_rpc::{
    model::{
        requests::{
            AddpsbtoutputRequest, CloseRequest, ConnectRequest, DatastoreMode, DatastoreRequest,
            DeldatastoreRequest, DisconnectRequest, FundchannelCancelRequest,
            FundchannelCompleteRequest, FundchannelStartRequest,
            FundpsbtRequest, GetinfoRequest, ListdatastoreRequest, ListpeerchannelsRequest,
            SendpsbtRequest, SignpsbtRequest, UnreserveinputsRequest,
        },
        responses::ListdatastoreResponse,
    },
    primitives::{Amount, AmountOrAll, ChannelState, Feerate, Sha256, ShortChannelId},
    ClnRpc,
};
use core::fmt;
use log::warn;
use serde::Serialize;
use std::path::PathBuf;
use std::str::FromStr;
use std::time::Duration;

pub const DS_MAIN_KEY: &'static str = "lsps";
pub const DS_SUB_KEY: &'static str = "lsps2";
pub const DS_SESSIONS_KEY: &str = "sessions";
pub const DS_ACTIVE_KEY: &str = "active";
pub const DS_FINALIZED_KEY: &str = "finalized";

#[derive(Clone)]
pub struct ClnApiRpc {
    rpc_path: PathBuf,
}

impl ClnApiRpc {
    pub fn new(rpc_path: PathBuf) -> Self {
        Self { rpc_path }
    }

    async fn create_rpc(&self) -> Result<ClnRpc> {
        // Note: Add retry and backoff, be nicer than just failing.
        ClnRpc::new(&self.rpc_path).await
    }

    async fn poll_channel_ready(
        &self,
        channel_id: &Sha256,
        timeout: Duration,
        interval: Duration,
    ) -> Result<()> {
        let deadline = tokio::time::Instant::now() + timeout;
        loop {
            if self.check_channel_normal(channel_id).await? {
                return Ok(());
            }
            if tokio::time::Instant::now() + interval > deadline {
                anyhow::bail!(
                    "timed out waiting for channel {} to reach CHANNELD_NORMAL",
                    channel_id
                );
            }
            tokio::time::sleep(interval).await;
        }
    }

    async fn check_channel_normal(&self, channel_id: &Sha256) -> Result<bool> {
        let mut rpc = self.create_rpc().await?;
        let r = rpc
            .call_typed(&ListpeerchannelsRequest {
                channel_id: Some(*channel_id),
                id: None,
                short_channel_id: None,
            })
            .await
            .with_context(|| "calling listpeerchannels")?;

        Ok(r.channels
            .first()
            .is_some_and(|ch| ch.state == ChannelState::CHANNELD_NORMAL))
    }

    async fn cleanup_failed_funding(&self, peer_id: &PublicKey, psbt: &str) {
        if let Err(e) = self.unreserve_inputs(psbt).await {
            warn!("cleanup: unreserveinputs for psbt={psbt} failed: {e}");
        }
        if let Err(e) = self.cancel_fundchannel(peer_id).await {
            warn!("cleanup: fundchannel_cancel failed: {e}");
        }
    }

    async fn unreserve_inputs(&self, psbt: &str) -> Result<()> {
        let mut rpc = self.create_rpc().await?;
        rpc.call_typed(&UnreserveinputsRequest {
            reserve: None,
            psbt: psbt.to_string(),
        })
        .await
        .with_context(|| "calling unreserveinputs")?;
        Ok(())
    }

    async fn cancel_fundchannel(&self, peer_id: &PublicKey) -> Result<()> {
        let mut rpc = self.create_rpc().await?;
        rpc.call_typed(&FundchannelCancelRequest {
            id: peer_id.to_owned(),
        })
        .await
        .with_context(|| "calling fundchannel_cancel")?;
        Ok(())
    }

    async fn connect(&self, peer_id: String) -> Result<()> {
        // Note: We could add a retry here.
        let mut rpc = self.create_rpc().await?;
        let _ = rpc
            .call_typed(&ConnectRequest {
                host: None,
                port: None,
                id: peer_id,
            })
            .await
            .with_context(|| "calling connect")?;
        Ok(())
    }
}

/// Converts msat to sat, rounding up to avoid underfunding.
fn msat_to_sat_ceil(msat: u64) -> u64 {
    msat.div_ceil(1000)
}

#[async_trait]
impl ActionExecutor for ClnApiRpc {
    async fn fund_channel(
        &self,
        peer_id: String,
        channel_size: Msat,
        _opening_fee_params: OpeningFeeParams,
    ) -> anyhow::Result<(String, String)> {
        let pk = PublicKey::from_str(&peer_id)
            .with_context(|| format!("parsing peer_id '{peer_id}'"))?;
        let channel_sat = msat_to_sat_ceil(channel_size.msat());

        self.connect(peer_id).await?;

        let mut rpc = self.create_rpc().await?;
        let start_res = rpc
            .call_typed(&FundchannelStartRequest {
                id: pk,
                amount: Amount::from_sat(channel_sat),
                mindepth: Some(0),
                channel_type: Some(vec![12, 46, 50]), // zero_conf channel
                announce: Some(false),
                close_to: None,
                feerate: None,
                push_msat: None,
                reserve: Some(Amount::from_sat(0)),
            })
            .await
            .with_context(|| "calling fundchannel_start")?;
        let funding_address = start_res.funding_address;

        // Reserve input and add to tx
        let mut rpc = self.create_rpc().await?;
        let fundpsbt_res = match rpc
            .call_typed(&FundpsbtRequest {
                satoshi: AmountOrAll::Amount(Amount::from_sat(channel_sat)),
                feerate: Feerate::Normal,
                startweight: 1000,
                excess_as_change: Some(true),
                locktime: None,
                min_witness_weight: None,
                minconf: None,
                nonwrapped: None,
                opening_anchor_channel: None,
                reserve: None,
            })
            .await
        {
            Ok(r) => r,
            Err(e) => {
                self.cancel_fundchannel(&pk).await.ok();
                return Err(anyhow::Error::new(e).context("calling fundpsbt"));
            }
        };

        let addout_res = match rpc
            .call_typed(&AddpsbtoutputRequest {
                satoshi: Amount::from_sat(channel_sat),
                initialpsbt: Some(fundpsbt_res.psbt.clone()),
                destination: Some(funding_address),
                locktime: None,
            })
            .await
        {
            Ok(r) => r,
            Err(e) => {
                self.cleanup_failed_funding(&pk, &fundpsbt_res.psbt).await;
                return Err(anyhow::Error::new(e).context("calling addpsbtoutput"));
            }
        };
        let psbt = addout_res.psbt;

        let complete_res = match rpc
            .call_typed(&FundchannelCompleteRequest {
                id: pk,
                psbt: psbt.clone(),
                withhold: Some(true),
            })
            .await
        {
            Ok(r) => r,
            Err(e) => {
                self.cleanup_failed_funding(&pk, &psbt).await;
                return Err(anyhow::Error::new(e).context("calling fundchannel_complete"));
            }
        };
        let channel_id = complete_res.channel_id;

        if let Err(e) = self
            .poll_channel_ready(
                &channel_id,
                Duration::from_secs(120),
                Duration::from_secs(1),
            )
            .await
        {
            self.cleanup_failed_funding(&pk, &psbt).await;
            return Err(e);
        }

        Ok((channel_id.to_string(), psbt))
    }

    async fn broadcast_tx(
        &self,
        _channel_id: String,
        funding_psbt: String,
    ) -> anyhow::Result<String> {
        let mut rpc = self.create_rpc().await?;
        let sign_res = rpc
            .call_typed(&SignpsbtRequest {
                psbt: funding_psbt,
                signonly: None,
            })
            .await
            .with_context(|| "calling signpsbt")?;
        let send_res = rpc
            .call_typed(&SendpsbtRequest {
                psbt: sign_res.signed_psbt,
                reserve: None,
            })
            .await
            .with_context(|| "calling sendpsbt")?;
        Ok(send_res.txid)
    }

    async fn abandon_session(
        &self,
        channel_id: String,
        funding_psbt: String,
    ) -> anyhow::Result<()> {
        let close_res = {
            let mut rpc = self.create_rpc().await?;
            rpc.call_typed(&CloseRequest {
                destination: None,
                fee_negotiation_step: None,
                force_lease_closed: None,
                unilateraltimeout: Some(1), // We didn't even broadcast the channel yet.
                wrong_funding: None,
                feerange: None,
                id: channel_id.clone(),
            })
            .await
            .with_context(|| format!("calling close for channel_id={channel_id}"))
        };

        if let Err(e) = &close_res {
            warn!("abandon_session: close failed for channel_id={channel_id}: {e}");
        }

        let unreserve_res = self.unreserve_inputs(&funding_psbt).await;
        if let Err(e) = &unreserve_res {
            warn!("abandon_session: unreserveinputs failed for funding_psbt={funding_psbt}: {e}");
        }

        match (close_res, unreserve_res) {
            (Ok(_), Ok(())) => Ok(()),
            (Err(close_err), Ok(())) => Err(close_err),
            (Ok(_), Err(unreserve_err)) => Err(unreserve_err),
            (Err(close_err), Err(unreserve_err)) => Err(anyhow::anyhow!(
                "abandon_session failed for channel_id={channel_id}: close failed: {close_err}; unreserveinputs failed for funding_psbt={funding_psbt}: {unreserve_err}"
            )),
        }
    }

    async fn disconnect(&self, peer_id: String) -> anyhow::Result<()> {
        let pk = PublicKey::from_str(&peer_id)
            .with_context(|| format!("parsing peer_id '{peer_id}'"))?;
        let mut rpc = self.create_rpc().await?;
        let _ = rpc
            .call_typed(&DisconnectRequest {
                id: pk,
                force: None,
            })
            .await
            .with_context(|| "calling disconnect")?;
        Ok(())
    }

    async fn is_channel_alive(&self, channel_id: &str) -> anyhow::Result<bool> {
        let sha = channel_id
            .parse::<Sha256>()
            .with_context(|| format!("parsing channel_id '{channel_id}'"))?;
        self.check_channel_normal(&sha).await
    }
}

#[async_trait]
impl DatastoreProvider for ClnApiRpc {
    async fn store_buy_request(
        &self,
        scid: &ShortChannelId,
        peer_id: &PublicKey,
        opening_fee_params: &OpeningFeeParams,
        expected_payment_size: &Option<Msat>,
        channel_capacity_msat: &Msat,
    ) -> Result<bool> {
        let mut rpc = self.create_rpc().await?;
        #[derive(Serialize)]
        struct BorrowedDatastoreEntry<'a> {
            peer_id: &'a PublicKey,
            opening_fee_params: &'a OpeningFeeParams,
            #[serde(borrow)]
            expected_payment_size: &'a Option<Msat>,
            channel_capacity_msat: &'a Msat,
            created_at: chrono::DateTime<chrono::Utc>,
            #[serde(skip_serializing_if = "Option::is_none")]
            channel_id: Option<String>,
            #[serde(skip_serializing_if = "Option::is_none")]
            funding_psbt: Option<String>,
            #[serde(skip_serializing_if = "Option::is_none")]
            funding_txid: Option<String>,
            #[serde(skip_serializing_if = "Option::is_none")]
            preimage: Option<String>,
        }

        let ds = BorrowedDatastoreEntry {
            peer_id,
            opening_fee_params,
            expected_payment_size,
            channel_capacity_msat,
            created_at: chrono::Utc::now(),
            channel_id: None,
            funding_psbt: None,
            funding_txid: None,
            preimage: None,
        };
        let json_str = serde_json::to_string(&ds)?;

        let ds = DatastoreRequest {
            generation: None,
            hex: None,
            mode: Some(DatastoreMode::MUST_CREATE),
            string: Some(json_str),
            key: vec![
                DS_MAIN_KEY.to_string(),
                DS_SUB_KEY.to_string(),
                DS_SESSIONS_KEY.to_string(),
                DS_ACTIVE_KEY.to_string(),
                scid.to_string(),
            ],
        };

        let _ = rpc
            .call_typed(&ds)
            .await
            .map_err(anyhow::Error::new)
            .with_context(|| "calling datastore")?;

        Ok(true)
    }

    async fn get_buy_request(&self, scid: &ShortChannelId) -> Result<DatastoreEntry> {
        let mut rpc = self.create_rpc().await?;
        let key = vec![
            DS_MAIN_KEY.to_string(),
            DS_SUB_KEY.to_string(),
            DS_SESSIONS_KEY.to_string(),
            DS_ACTIVE_KEY.to_string(),
            scid.to_string(),
        ];
        let res = rpc
            .call_typed(&ListdatastoreRequest {
                key: Some(key.clone()),
            })
            .await
            .with_context(|| "calling listdatastore")?;

        let (rec, _) = deserialize_by_key(&res, key)?;
        Ok(rec)
    }

    async fn del_buy_request(&self, scid: &ShortChannelId) -> Result<()> {
        let mut rpc = self.create_rpc().await?;
        let key = vec![
            DS_MAIN_KEY.to_string(),
            DS_SUB_KEY.to_string(),
            DS_SESSIONS_KEY.to_string(),
            DS_ACTIVE_KEY.to_string(),
            scid.to_string(),
        ];

        let _ = rpc
            .call_typed(&DeldatastoreRequest {
                generation: None,
                key,
            })
            .await;

        Ok(())
    }

    async fn finalize_session(&self, scid: &ShortChannelId, outcome: SessionOutcome) -> Result<()> {
        let entry = match self.get_buy_request(scid).await {
            Ok(e) => e,
            Err(e) => {
                warn!("finalize_session: active entry for scid={scid} already gone: {e}");
                return Ok(());
            }
        };

        let finalized = FinalizedDatastoreEntry {
            entry,
            outcome,
            finalized_at: chrono::Utc::now(),
        };
        let json_str = serde_json::to_string(&finalized)?;

        let mut rpc = self.create_rpc().await?;
        let key = vec![
            DS_MAIN_KEY.to_string(),
            DS_SUB_KEY.to_string(),
            DS_SESSIONS_KEY.to_string(),
            DS_FINALIZED_KEY.to_string(),
            scid.to_string(),
        ];
        rpc.call_typed(&DatastoreRequest {
            generation: None,
            hex: None,
            mode: Some(DatastoreMode::MUST_CREATE),
            string: Some(json_str),
            key,
        })
        .await
        .with_context(|| "calling datastore for finalize_session")?;

        self.del_buy_request(scid).await?;
        Ok(())
    }

    async fn update_session_funding(
        &self,
        scid: &ShortChannelId,
        channel_id: &str,
        funding_psbt: &str,
    ) -> Result<()> {
        let mut entry = self.get_buy_request(scid).await?;
        entry.channel_id = Some(channel_id.to_string());
        entry.funding_psbt = Some(funding_psbt.to_string());
        let json_str = serde_json::to_string(&entry)?;

        let mut rpc = self.create_rpc().await?;
        rpc.call_typed(&DatastoreRequest {
            generation: None,
            hex: None,
            mode: Some(DatastoreMode::CREATE_OR_REPLACE),
            string: Some(json_str),
            key: vec![
                DS_MAIN_KEY.to_string(),
                DS_SUB_KEY.to_string(),
                DS_SESSIONS_KEY.to_string(),
                DS_ACTIVE_KEY.to_string(),
                scid.to_string(),
            ],
        })
        .await
        .with_context(|| "calling datastore for update_session_funding")?;
        Ok(())
    }

    async fn update_session_funding_txid(
        &self,
        scid: &ShortChannelId,
        funding_txid: &str,
    ) -> Result<()> {
        let mut entry = self.get_buy_request(scid).await?;
        entry.funding_txid = Some(funding_txid.to_string());
        let json_str = serde_json::to_string(&entry)?;

        let mut rpc = self.create_rpc().await?;
        rpc.call_typed(&DatastoreRequest {
            generation: None,
            hex: None,
            mode: Some(DatastoreMode::CREATE_OR_REPLACE),
            string: Some(json_str),
            key: vec![
                DS_MAIN_KEY.to_string(),
                DS_SUB_KEY.to_string(),
                DS_SESSIONS_KEY.to_string(),
                DS_ACTIVE_KEY.to_string(),
                scid.to_string(),
            ],
        })
        .await
        .with_context(|| "calling datastore for update_session_funding_txid")?;
        Ok(())
    }

    async fn update_session_preimage(&self, scid: &ShortChannelId, preimage: &str) -> Result<()> {
        let mut entry = self.get_buy_request(scid).await?;
        entry.preimage = Some(preimage.to_string());
        let json_str = serde_json::to_string(&entry)?;

        let mut rpc = self.create_rpc().await?;
        rpc.call_typed(&DatastoreRequest {
            generation: None,
            hex: None,
            mode: Some(DatastoreMode::CREATE_OR_REPLACE),
            string: Some(json_str),
            key: vec![
                DS_MAIN_KEY.to_string(),
                DS_SUB_KEY.to_string(),
                DS_SESSIONS_KEY.to_string(),
                DS_ACTIVE_KEY.to_string(),
                scid.to_string(),
            ],
        })
        .await
        .with_context(|| "calling datastore for update_session_preimage")?;
        Ok(())
    }
}

#[async_trait]
impl Lsps2PolicyProvider for ClnApiRpc {
    async fn get_info(
        &self,
        request: &Lsps2PolicyGetInfoRequest,
    ) -> Result<Lsps2PolicyGetInfoResponse> {
        let mut rpc = self.create_rpc().await?;
        rpc.call_raw("lsps2-policy-getpolicy", request)
            .await
            .context("failed to call lsps2-policy-getpolicy")
    }

    async fn buy(&self, request: &Lsps2PolicyBuyRequest) -> Result<Lsps2PolicyBuyResponse> {
        let mut rpc = self.create_rpc().await?;
        rpc.call_raw("lsps2-policy-buy", request)
            .await
            .map_err(anyhow::Error::new)
            .with_context(|| "calling lsps2-policy-buy")
    }
}

#[async_trait]
impl BlockheightProvider for ClnApiRpc {
    async fn get_blockheight(&self) -> Result<Blockheight> {
        let mut rpc = self.create_rpc().await?;
        let info = rpc
            .call_typed(&GetinfoRequest {})
            .await
            .map_err(anyhow::Error::new)
            .with_context(|| "calling getinfo")?;
        Ok(info.blockheight)
    }
}

#[derive(Debug)]
pub enum DsError {
    /// No datastore entry with this exact key.
    NotFound { key: Vec<String> },
    /// Entry existed but had neither `string` nor `hex`.
    MissingValue { key: Vec<String> },
    /// JSON parse failed (from `string` or decoded `hex`).
    JsonParse {
        key: Vec<String>,
        source: serde_json::Error,
    },
    /// Hex decode failed.
    HexDecode {
        key: Vec<String>,
        source: hex::FromHexError,
    },
}

impl fmt::Display for DsError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            DsError::NotFound { key } => write!(f, "no datastore entry for key {:?}", key),
            DsError::MissingValue { key } => write!(
                f,
                "datastore entry had neither `string` nor `hex` for key {:?}",
                key
            ),
            DsError::JsonParse { key, source } => {
                write!(f, "failed to parse JSON at key {:?}: {}", key, source)
            }
            DsError::HexDecode { key, source } => {
                write!(f, "failed to decode hex at key {:?}: {}", key, source)
            }
        }
    }
}

impl std::error::Error for DsError {}

pub fn deserialize_by_key<K>(
    resp: &ListdatastoreResponse,
    key: K,
) -> std::result::Result<(DatastoreEntry, Option<u64>), DsError>
where
    K: AsRef<[String]>,
{
    let wanted: &[String] = key.as_ref();

    let ds = resp
        .datastore
        .iter()
        .find(|d| d.key.as_slice() == wanted)
        .ok_or_else(|| DsError::NotFound {
            key: wanted.to_vec(),
        })?;

    // Prefer `string`, fall back to `hex`
    if let Some(s) = &ds.string {
        let value = serde_json::from_str::<DatastoreEntry>(s).map_err(|e| DsError::JsonParse {
            key: ds.key.clone(),
            source: e,
        })?;
        return Ok((value, ds.generation));
    }

    if let Some(hx) = &ds.hex {
        let bytes = hex::decode(hx).map_err(|e| DsError::HexDecode {
            key: ds.key.clone(),
            source: e,
        })?;
        let value =
            serde_json::from_slice::<DatastoreEntry>(&bytes).map_err(|e| DsError::JsonParse {
                key: ds.key.clone(),
                source: e,
            })?;
        return Ok((value, ds.generation));
    }

    Err(DsError::MissingValue {
        key: ds.key.clone(),
    })
}
