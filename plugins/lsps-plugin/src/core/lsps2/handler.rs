use crate::{
    core::lsps2::service::Lsps2Handler,
    lsps2::{
        cln::{HtlcAcceptedRequest, HtlcAcceptedResponse, TLV_FORWARD_AMT},
        DS_MAIN_KEY, DS_SUB_KEY,
    },
    proto::{
        jsonrpc::{RpcError, RpcErrorExt as _},
        lsps0::{LSPS0RpcErrorExt, Msat, ShortChannelId},
        lsps2::{
            compute_opening_fee,
            failure_codes::{TEMPORARY_CHANNEL_FAILURE, UNKNOWN_NEXT_PEER},
            DatastoreEntry, Lsps2BuyRequest, Lsps2BuyResponse, Lsps2GetInfoRequest,
            Lsps2GetInfoResponse, Lsps2PolicyGetChannelCapacityRequest,
            Lsps2PolicyGetChannelCapacityResponse, Lsps2PolicyGetInfoRequest,
            Lsps2PolicyGetInfoResponse, OpeningFeeParams, PolicyOpeningFeeParams, Promise,
        },
    },
};
use anyhow::{Context, Result as AnyResult};
use async_trait::async_trait;
use bitcoin::{
    hashes::{sha256::Hash as Sha256, Hash as _},
    secp256k1::PublicKey,
};
use chrono::Utc;
use cln_rpc::{
    model::{
        requests::{
            DatastoreMode, DatastoreRequest, DeldatastoreRequest, FundchannelRequest,
            GetinfoRequest, ListdatastoreRequest, ListpeerchannelsRequest,
        },
        responses::ListdatastoreResponse,
    },
    primitives::{Amount, AmountOrAll, ChannelState},
    ClnRpc,
};
use log::{debug, warn};
use rand::{rng, Rng as _};
use serde::Serialize;
use std::{fmt, path::PathBuf, sync::Arc, time::Duration};

const DEFAULT_CLTV_EXPIRY_DELTA: u32 = 144;

#[derive(Clone)]
pub struct ClnApiRpc {
    rpc_path: PathBuf,
}

impl ClnApiRpc {
    pub fn new(rpc_path: PathBuf) -> Self {
        Self { rpc_path }
    }

    async fn create_rpc(&self) -> AnyResult<ClnRpc> {
        ClnRpc::new(&self.rpc_path).await
    }
}

#[async_trait]
impl LightningProvider for ClnApiRpc {
    async fn fund_jit_channel(
        &self,
        peer_id: &PublicKey,
        amount: &Msat,
    ) -> AnyResult<(Sha256, String)> {
        let mut rpc = self.create_rpc().await?;
        let res = rpc
            .call_typed(&FundchannelRequest {
                announce: Some(false),
                close_to: None,
                compact_lease: None,
                feerate: None,
                minconf: None,
                mindepth: Some(0),
                push_msat: None,
                request_amt: None,
                reserve: None,
                channel_type: Some(vec![12, 46, 50]),
                utxos: None,
                amount: AmountOrAll::Amount(Amount::from_msat(amount.msat())),
                id: peer_id.to_owned(),
            })
            .await
            .with_context(|| "calling fundchannel")?;
        Ok((res.channel_id, res.txid))
    }

    async fn is_channel_ready(&self, peer_id: &PublicKey, channel_id: &Sha256) -> AnyResult<bool> {
        let mut rpc = self.create_rpc().await?;
        let r = rpc
            .call_typed(&ListpeerchannelsRequest {
                id: Some(peer_id.to_owned()),
                short_channel_id: None,
            })
            .await
            .with_context(|| "calling listpeerchannels")?;

        let chs = r
            .channels
            .iter()
            .find(|&ch| ch.channel_id.is_some_and(|id| id == *channel_id));
        if let Some(ch) = chs {
            if ch.state == ChannelState::CHANNELD_NORMAL {
                return Ok(true);
            }
        }

        return Ok(false);
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
    ) -> AnyResult<bool> {
        let mut rpc = self.create_rpc().await?;
        #[derive(Serialize)]
        struct BorrowedDatastoreEntry<'a> {
            peer_id: &'a PublicKey,
            opening_fee_params: &'a OpeningFeeParams,
            #[serde(borrow)]
            expected_payment_size: &'a Option<Msat>,
        }

        let ds = BorrowedDatastoreEntry {
            peer_id,
            opening_fee_params,
            expected_payment_size,
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

    async fn get_buy_request(&self, scid: &ShortChannelId) -> AnyResult<DatastoreEntry> {
        let mut rpc = self.create_rpc().await?;
        let key = vec![
            DS_MAIN_KEY.to_string(),
            DS_SUB_KEY.to_string(),
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

    async fn del_buy_request(&self, scid: &ShortChannelId) -> AnyResult<()> {
        let mut rpc = self.create_rpc().await?;
        let key = vec![
            DS_MAIN_KEY.to_string(),
            DS_SUB_KEY.to_string(),
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
}

#[async_trait]
impl Lsps2OfferProvider for ClnApiRpc {
    async fn get_offer(
        &self,
        request: &Lsps2PolicyGetInfoRequest,
    ) -> AnyResult<Lsps2PolicyGetInfoResponse> {
        let mut rpc = self.create_rpc().await?;
        rpc.call_raw("lsps2-policy-getpolicy", request)
            .await
            .context("failed to call lsps2-policy-getpolicy")
    }

    async fn get_channel_capacity(
        &self,
        params: &Lsps2PolicyGetChannelCapacityRequest,
    ) -> AnyResult<Lsps2PolicyGetChannelCapacityResponse> {
        let mut rpc = self.create_rpc().await?;
        rpc.call_raw("lsps2-policy-getchannelcapacity", params)
            .await
            .map_err(anyhow::Error::new)
            .with_context(|| "calling lsps2-policy-getchannelcapacity")
    }
}

#[async_trait]
impl BlockheightProvider for ClnApiRpc {
    async fn get_blockheight(&self) -> AnyResult<Blockheight> {
        let mut rpc = self.create_rpc().await?;
        let info = rpc
            .call_typed(&GetinfoRequest {})
            .await
            .map_err(anyhow::Error::new)
            .with_context(|| "calling getinfo")?;
        Ok(info.blockheight)
    }
}

#[async_trait]
pub trait Lsps2OfferProvider: Send + Sync {
    async fn get_offer(
        &self,
        request: &Lsps2PolicyGetInfoRequest,
    ) -> AnyResult<Lsps2PolicyGetInfoResponse>;

    async fn get_channel_capacity(
        &self,
        params: &Lsps2PolicyGetChannelCapacityRequest,
    ) -> AnyResult<Lsps2PolicyGetChannelCapacityResponse>;
}

type Blockheight = u32;

#[async_trait]
pub trait BlockheightProvider: Send + Sync {
    async fn get_blockheight(&self) -> AnyResult<Blockheight>;
}

#[async_trait]
pub trait DatastoreProvider: Send + Sync {
    async fn store_buy_request(
        &self,
        scid: &ShortChannelId,
        peer_id: &PublicKey,
        offer: &OpeningFeeParams,
        expected_payment_size: &Option<Msat>,
    ) -> AnyResult<bool>;

    async fn get_buy_request(&self, scid: &ShortChannelId) -> AnyResult<DatastoreEntry>;
    async fn del_buy_request(&self, scid: &ShortChannelId) -> AnyResult<()>;
}

#[async_trait]
pub trait LightningProvider: Send + Sync {
    async fn fund_jit_channel(
        &self,
        peer_id: &PublicKey,
        amount: &Msat,
    ) -> AnyResult<(Sha256, String)>;

    async fn is_channel_ready(&self, peer_id: &PublicKey, channel_id: &Sha256) -> AnyResult<bool>;
}

pub struct Lsps2ServiceHandler<A> {
    pub api: Arc<A>,
    pub promise_secret: [u8; 32],
}

impl<A> Lsps2ServiceHandler<A> {
    pub fn new(api: Arc<A>, promise_seret: &[u8; 32]) -> Self {
        Lsps2ServiceHandler {
            api,
            promise_secret: promise_seret.to_owned(),
        }
    }
}

async fn get_info_handler<A: Lsps2OfferProvider + 'static>(
    api: Arc<A>,
    secret: &[u8; 32],
    request: &Lsps2GetInfoRequest,
) -> std::result::Result<Lsps2GetInfoResponse, RpcError> {
    let res_data = api
        .get_offer(&Lsps2PolicyGetInfoRequest {
            token: request.token.clone(),
        })
        .await
        .map_err(|_| RpcError::internal_error("internal error"))?;

    if res_data.client_rejected {
        return Err(RpcError::client_rejected("client was rejected"));
    };

    let opening_fee_params_menu = res_data
        .policy_opening_fee_params_menu
        .iter()
        .map(|v| make_opening_fee_params(v, secret))
        .collect::<Result<Vec<_>, _>>()?;

    Ok(Lsps2GetInfoResponse {
        opening_fee_params_menu,
    })
}

fn make_opening_fee_params(
    v: &PolicyOpeningFeeParams,
    secret: &[u8; 32],
) -> Result<OpeningFeeParams, RpcError> {
    let promise: Promise = v
        .get_hmac_hex(secret)
        .try_into()
        .map_err(|_| RpcError::internal_error("internal error"))?;
    Ok(OpeningFeeParams {
        min_fee_msat: v.min_fee_msat,
        proportional: v.proportional,
        valid_until: v.valid_until,
        min_lifetime: v.min_lifetime,
        max_client_to_self_delay: v.max_client_to_self_delay,
        min_payment_size_msat: v.min_payment_size_msat,
        max_payment_size_msat: v.max_payment_size_msat,
        promise,
    })
}

#[async_trait]
impl<A: DatastoreProvider + BlockheightProvider + Lsps2OfferProvider + 'static> Lsps2Handler
    for Lsps2ServiceHandler<A>
{
    async fn handle_get_info(
        &self,
        request: Lsps2GetInfoRequest,
    ) -> std::result::Result<Lsps2GetInfoResponse, RpcError> {
        get_info_handler(self.api.clone(), &self.promise_secret, &request).await
    }

    async fn handle_buy(
        &self,
        peer_id: PublicKey,
        request: Lsps2BuyRequest,
    ) -> core::result::Result<Lsps2BuyResponse, RpcError> {
        let fee_params = request.opening_fee_params;

        // FIXME: In the future we should replace the \`None\` with a meaningful
        // value that reflects the inbound capacity for this node from the
        // public network for a better pre-condition check on the payment_size.
        fee_params.validate(&self.promise_secret, request.payment_size_msat, None)?;

        // Generate a tmp scid to identify jit channel request in htlc.
        let blockheight = self
            .api
            .get_blockheight()
            .await
            .map_err(|_| RpcError::internal_error("internal error"))?;

        // FIXME: Future task: Check that we don't conflict with any jit scid we
        // already handed out -> Check datastore entries.
        let jit_scid = ShortChannelId::from(generate_jit_scid(blockheight));

        let ok = self
            .api
            .store_buy_request(&jit_scid, &peer_id, &fee_params, &request.payment_size_msat)
            .await
            .map_err(|_| RpcError::internal_error("internal error"))?;

        if !ok {
            return Err(RpcError::internal_error("internal error"))?;
        }

        Ok(Lsps2BuyResponse {
            jit_channel_scid: jit_scid,
            // We can make this configurable if necessary.
            lsp_cltv_expiry_delta: DEFAULT_CLTV_EXPIRY_DELTA,
            // We can implement the other mode later on as we might have to do
            // some additional work on core-lightning to enable this.
            client_trusts_lsp: false,
        })
    }
}

fn generate_jit_scid(best_blockheigt: u32) -> u64 {
    let mut rng = rng();
    let block = best_blockheigt + 6; // Approx 1 hour in the future and should avoid collision with confirmed channels
    let tx_idx: u32 = rng.random_range(0..5000);
    let output_idx: u16 = rng.random_range(0..10);

    ((block as u64) << 40) | ((tx_idx as u64) << 16) | (output_idx as u64)
}

pub struct HtlcAcceptedHookHandler<A> {
    api: A,
    htlc_minimum_msat: u64,
    backoff_listpeerchannels: Duration,
}

impl<A> HtlcAcceptedHookHandler<A> {
    pub fn new(api: A, htlc_minimum_msat: u64) -> Self {
        Self {
            api,
            htlc_minimum_msat,
            backoff_listpeerchannels: Duration::from_secs(10),
        }
    }
}

impl<A: DatastoreProvider + Lsps2OfferProvider + LightningProvider> HtlcAcceptedHookHandler<A> {
    pub async fn handle(&self, req: HtlcAcceptedRequest) -> AnyResult<HtlcAcceptedResponse> {
        let scid = match req.onion.short_channel_id {
            Some(scid) => scid,
            None => {
                // We are the final destination of this htlc.
                return Ok(HtlcAcceptedResponse::continue_(None, None, None));
            }
        };

        // A) Is this SCID one that we care about?
        let ds_rec = match self.api.get_buy_request(&scid).await {
            Ok(rec) => rec,
            Err(_) => {
                return Ok(HtlcAcceptedResponse::continue_(None, None, None));
            }
        };

        // Fixme: Check that we don't have a channel yet with the peer that we await to
        // become READY to use.
        // ---

        // Fixme: We only accept no-mpp for now, mpp and other flows will be added later on
        // Fixme: We continue mpp for now to let the test mock handle the htlc, as we need
        // to test the client implementation for mpp payments.
        if ds_rec.expected_payment_size.is_some() {
            warn!("mpp payments are not implemented yet");
            return Ok(HtlcAcceptedResponse::continue_(None, None, None));
            // return Ok(HtlcAcceptedResponse::fail(
            //     Some(UNKNOWN_NEXT_PEER.to_string()),
            //     None,
            // ));
        }

        // B) Is the fee option menu still valid?
        let now = Utc::now();
        if now >= ds_rec.opening_fee_params.valid_until {
            // Not valid anymore, remove from DS and fail HTLC.
            let _ = self.api.del_buy_request(&scid).await;
            return Ok(HtlcAcceptedResponse::fail(
                Some(TEMPORARY_CHANNEL_FAILURE.to_string()),
                None,
            ));
        }

        // C) Is the amount in the boundaries of the fee menu?
        if req.htlc.amount_msat.msat() < ds_rec.opening_fee_params.min_fee_msat.msat()
            || req.htlc.amount_msat.msat() > ds_rec.opening_fee_params.max_payment_size_msat.msat()
        {
            // No! reject the HTLC.
            debug!("amount_msat for scid: {}, was too low or to high", scid);
            return Ok(HtlcAcceptedResponse::fail(
                Some(UNKNOWN_NEXT_PEER.to_string()),
                None,
            ));
        }

        // D) Check that the amount_msat covers the opening fee (only for non-mpp right now)
        let opening_fee = if let Some(opening_fee) = compute_opening_fee(
            req.htlc.amount_msat.msat(),
            ds_rec.opening_fee_params.min_fee_msat.msat(),
            ds_rec.opening_fee_params.proportional.ppm() as u64,
        ) {
            if opening_fee + self.htlc_minimum_msat >= req.htlc.amount_msat.msat() {
                debug!("amount_msat for scid: {}, does not cover opening fee", scid);
                return Ok(HtlcAcceptedResponse::fail(
                    Some(UNKNOWN_NEXT_PEER.to_string()),
                    None,
                ));
            }
            opening_fee
        } else {
            // The computation overflowed.
            debug!("amount_msat for scid: {}, was too low or to high", scid);
            return Ok(HtlcAcceptedResponse::fail(
                Some(UNKNOWN_NEXT_PEER.to_string()),
                None,
            ));
        };

        // E) We made it, open a channel to the peer.
        let ch_cap_req = Lsps2PolicyGetChannelCapacityRequest {
            opening_fee_params: ds_rec.opening_fee_params,
            init_payment_size: Msat::from_msat(req.htlc.amount_msat.msat()),
            scid,
        };
        let ch_cap_res = match self.api.get_channel_capacity(&ch_cap_req).await {
            Ok(r) => r,
            Err(e) => {
                warn!("failed to get channel capacity for scid {}: {}", scid, e);
                return Ok(HtlcAcceptedResponse::fail(
                    Some(UNKNOWN_NEXT_PEER.to_string()),
                    None,
                ));
            }
        };

        let cap = match ch_cap_res.channel_capacity_msat {
            Some(c) => Msat::from_msat(c),
            None => {
                debug!("policy giver does not allow channel for scid {}", scid);
                return Ok(HtlcAcceptedResponse::fail(
                    Some(UNKNOWN_NEXT_PEER.to_string()),
                    None,
                ));
            }
        };

        // We take the policy-giver seriously, if the capacity is too low, we
        // still try to open the channel.
        // Fixme: We may check that the capacity is ge than the
        // (amount_msat - opening fee) in the future.
        // Fixme: Make this configurable, maybe return the whole request from
        // the policy giver?
        let channel_id = match self.api.fund_jit_channel(&ds_rec.peer_id, &cap).await {
            Ok((channel_id, _)) => channel_id,
            Err(_) => {
                return Ok(HtlcAcceptedResponse::fail(
                    Some(UNKNOWN_NEXT_PEER.to_string()),
                    None,
                ));
            }
        };

        // F) Wait for the peer to send `channel_ready`.
        // Fixme: Use event to check for channel ready,
        // Fixme: Check for htlc timeout if peer refuses to send "ready".
        // Fixme: handle unexpected channel states.
        loop {
            match self
                .api
                .is_channel_ready(&ds_rec.peer_id, &channel_id)
                .await
            {
                Ok(true) => break,
                Ok(false) | Err(_) => tokio::time::sleep(self.backoff_listpeerchannels).await,
            };
        }

        // G) We got a working channel, deduct fee and forward htlc.
        let deducted_amt_msat = req.htlc.amount_msat.msat() - opening_fee;
        let mut payload = req.onion.payload.clone();
        payload.set_tu64(TLV_FORWARD_AMT, deducted_amt_msat);

        // It is okay to unwrap the next line as we do not have duplicate entries.
        let payload_bytes = payload.to_bytes().unwrap();
        debug!("about to send payload: {:02x?}", &payload_bytes);

        let mut extra_tlvs = req.htlc.extra_tlvs.unwrap_or_default().clone();
        extra_tlvs.set_u64(65537, opening_fee);
        let extra_tlvs_bytes = extra_tlvs.to_bytes().unwrap();
        debug!("extra_tlv: {:02x?}", extra_tlvs_bytes);

        Ok(HtlcAcceptedResponse::continue_(
            Some(payload_bytes),
            Some(channel_id.as_byte_array().to_vec()),
            Some(extra_tlvs_bytes),
        ))
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        lsps2::cln::{tlv::TlvStream, HtlcAcceptedResult},
        proto::{
            jsonrpc,
            lsps0::Ppm,
            lsps2::{Lsps2PolicyGetInfoResponse, PolicyOpeningFeeParams},
        },
    };
    use anyhow::bail;
    use chrono::{TimeZone, Utc};
    use cln_rpc::primitives::{Amount, PublicKey};
    use cln_rpc::RpcError as ClnRpcError;
    use std::sync::{Arc, Mutex};

    const PUBKEY: [u8; 33] = [
        0x02, 0x79, 0xbe, 0x66, 0x7e, 0xf9, 0xdc, 0xbb, 0xac, 0x55, 0xa0, 0x62, 0x95, 0xce, 0x87,
        0x0b, 0x07, 0x02, 0x9b, 0xfc, 0xdb, 0x2d, 0xce, 0x28, 0xd9, 0x59, 0xf2, 0x81, 0x5b, 0x16,
        0xf8, 0x17, 0x98,
    ];

    fn create_peer_id() -> PublicKey {
        PublicKey::from_slice(&PUBKEY).expect("Valid pubkey")
    }

    /// Build a pair: policy params + buy params with a Promise derived from `secret`
    fn params_with_promise(secret: &[u8; 32]) -> (PolicyOpeningFeeParams, OpeningFeeParams) {
        let policy = PolicyOpeningFeeParams {
            min_fee_msat: Msat(2_000),
            proportional: Ppm(10_000),
            valid_until: Utc.with_ymd_and_hms(2100, 1, 1, 0, 0, 0).unwrap(),
            min_lifetime: 1000,
            max_client_to_self_delay: 42,
            min_payment_size_msat: Msat(1_000_000),
            max_payment_size_msat: Msat(100_000_000),
        };
        let hex = policy.get_hmac_hex(secret);
        let promise: Promise = hex.try_into().expect("hex->Promise");
        let buy = OpeningFeeParams {
            min_fee_msat: policy.min_fee_msat,
            proportional: policy.proportional,
            valid_until: policy.valid_until,
            min_lifetime: policy.min_lifetime,
            max_client_to_self_delay: policy.max_client_to_self_delay,
            min_payment_size_msat: policy.min_payment_size_msat,
            max_payment_size_msat: policy.max_payment_size_msat,
            promise,
        };
        (policy, buy)
    }

    #[derive(Clone, Default)]
    struct FakeCln {
        lsps2_getpolicy_response: Arc<Mutex<Option<Lsps2PolicyGetInfoResponse>>>,
        lsps2_getpolicy_error: Arc<Mutex<Option<ClnRpcError>>>,
        blockheight_response: Option<u32>,
        blockheight_error: Arc<Mutex<Option<anyhow::Error>>>,
        store_buy_request_response: bool,
        get_buy_request_response: Arc<Mutex<Option<DatastoreEntry>>>,
        get_buy_request_error: Arc<Mutex<Option<anyhow::Error>>>,
        fund_channel_error: Arc<Mutex<Option<anyhow::Error>>>,
        fund_channel_response: Arc<Mutex<Option<(Sha256, String)>>>,
        lsps2_getchannelcapacity_response:
            Arc<Mutex<Option<Lsps2PolicyGetChannelCapacityResponse>>>,
        lsps2_getchannelcapacity_error: Arc<Mutex<Option<ClnRpcError>>>,
    }

    #[async_trait]
    impl Lsps2OfferProvider for FakeCln {
        async fn get_offer(
            &self,
            _request: &Lsps2PolicyGetInfoRequest,
        ) -> AnyResult<Lsps2PolicyGetInfoResponse> {
            if let Some(err) = self.lsps2_getpolicy_error.lock().unwrap().take() {
                return Err(anyhow::Error::new(err).context("from fake api"));
            };
            if let Some(res) = self.lsps2_getpolicy_response.lock().unwrap().take() {
                return Ok(Lsps2PolicyGetInfoResponse {
                    policy_opening_fee_params_menu: res.policy_opening_fee_params_menu,
                    client_rejected: false,
                });
            };
            panic!("No lsps2 response defined");
        }

        async fn get_channel_capacity(
            &self,
            _params: &Lsps2PolicyGetChannelCapacityRequest,
        ) -> AnyResult<Lsps2PolicyGetChannelCapacityResponse> {
            if let Some(err) = self.lsps2_getchannelcapacity_error.lock().unwrap().take() {
                return Err(anyhow::Error::new(err).context("from fake api"));
            }
            if let Some(res) = self
                .lsps2_getchannelcapacity_response
                .lock()
                .unwrap()
                .take()
            {
                return Ok(res);
            }
            panic!("No lsps2 getchannelcapacity response defined");
        }
    }

    #[async_trait]
    impl BlockheightProvider for FakeCln {
        async fn get_blockheight(&self) -> AnyResult<Blockheight> {
            if let Some(err) = self.blockheight_error.lock().unwrap().take() {
                return Err(err);
            };
            if let Some(blockheight) = self.blockheight_response {
                return Ok(blockheight);
            };
            panic!("No cln getinfo response defined");
        }
    }

    #[async_trait]
    impl DatastoreProvider for FakeCln {
        async fn store_buy_request(
            &self,
            _scid: &ShortChannelId,
            _peer_id: &PublicKey,
            _offer: &OpeningFeeParams,
            _payment_size_msat: &Option<Msat>,
        ) -> AnyResult<bool> {
            Ok(self.store_buy_request_response)
        }

        async fn get_buy_request(&self, _scid: &ShortChannelId) -> AnyResult<DatastoreEntry> {
            if let Some(err) = self.get_buy_request_error.lock().unwrap().take() {
                return Err(err);
            }
            if let Some(res) = self.get_buy_request_response.lock().unwrap().take() {
                return Ok(res);
            } else {
                bail!("request not found")
            }
        }

        async fn del_buy_request(&self, _scid: &ShortChannelId) -> AnyResult<()> {
            Ok(())
        }
    }

    #[async_trait]
    impl LightningProvider for FakeCln {
        async fn fund_jit_channel(
            &self,
            _peer_id: &PublicKey,
            _amount: &Msat,
        ) -> AnyResult<(Sha256, String)> {
            if let Some(err) = self.fund_channel_error.lock().unwrap().take() {
                return Err(err);
            }
            if let Some(res) = self.fund_channel_response.lock().unwrap().take() {
                return Ok(res);
            } else {
                bail!("request not found")
            }
        }

        async fn is_channel_ready(
            &self,
            _peer_id: &PublicKey,
            _channel_id: &Sha256,
        ) -> AnyResult<bool> {
            Ok(true)
        }
    }

    fn create_test_htlc_request(
        scid: Option<ShortChannelId>,
        amount_msat: u64,
    ) -> HtlcAcceptedRequest {
        let payload = TlvStream::default();

        HtlcAcceptedRequest {
            onion: crate::lsps2::cln::Onion {
                short_channel_id: scid,
                payload,
                next_onion: vec![],
                forward_msat: None,
                outgoing_cltv_value: None,
                shared_secret: vec![],
                total_msat: None,
                type_: None,
            },
            htlc: crate::lsps2::cln::Htlc {
                amount_msat: Amount::from_msat(amount_msat),
                cltv_expiry: 100,
                cltv_expiry_relative: 10,
                payment_hash: vec![],
                extra_tlvs: None,
                short_channel_id: ShortChannelId::from(123456789u64),
                id: 0,
            },
            forward_to: None,
        }
    }

    fn create_test_datastore_entry(
        peer_id: PublicKey,
        expected_payment_size: Option<Msat>,
    ) -> DatastoreEntry {
        let (_, policy) = params_with_promise(&[0u8; 32]);
        DatastoreEntry {
            peer_id,
            opening_fee_params: policy,
            expected_payment_size,
        }
    }

    fn test_promise_secret() -> [u8; 32] {
        [0x42; 32]
    }

    #[tokio::test]
    async fn test_successful_get_info() {
        let promise_secret = test_promise_secret();
        let params = Lsps2PolicyGetInfoResponse {
            client_rejected: false,
            policy_opening_fee_params_menu: vec![PolicyOpeningFeeParams {
                min_fee_msat: Msat(2000),
                proportional: Ppm(10000),
                valid_until: Utc.with_ymd_and_hms(1970, 1, 1, 0, 0, 0).unwrap(),
                min_lifetime: 1000,
                max_client_to_self_delay: 42,
                min_payment_size_msat: Msat(1000000),
                max_payment_size_msat: Msat(100000000),
            }],
        };
        let promise = params.policy_opening_fee_params_menu[0].get_hmac_hex(&promise_secret);
        let fake = FakeCln::default();
        *fake.lsps2_getpolicy_response.lock().unwrap() = Some(params);

        let handler = Lsps2ServiceHandler {
            api: Arc::new(fake),
            promise_secret,
        };

        let request = Lsps2GetInfoRequest { token: None };
        let result = handler.handle_get_info(request).await.unwrap();

        assert_eq!(
            result.opening_fee_params_menu[0].min_payment_size_msat,
            Msat(1000000)
        );
        assert_eq!(
            result.opening_fee_params_menu[0].max_payment_size_msat,
            Msat(100000000)
        );
        assert_eq!(
            result.opening_fee_params_menu[0].promise,
            promise.try_into().unwrap()
        );
    }

    #[tokio::test]
    async fn test_get_info_rpc_error_handling() {
        let promise_secret = test_promise_secret();
        let fake = FakeCln::default();
        *fake.lsps2_getpolicy_error.lock().unwrap() = Some(ClnRpcError {
            code: Some(-1),
            message: "not found".to_string(),
            data: None,
        });

        let handler = Lsps2ServiceHandler {
            api: Arc::new(fake),
            promise_secret,
        };

        let request = Lsps2GetInfoRequest { token: None };
        let result = handler.handle_get_info(request).await;

        assert!(result.is_err());
        let error = result.unwrap_err();
        assert_eq!(error.code, jsonrpc::INTERNAL_ERROR);
        assert!(error.message.contains("internal error"));
    }

    #[tokio::test]
    async fn buy_ok_fixed_amount() {
        let promise_secret = test_promise_secret();
        let mut fake = FakeCln::default();
        fake.blockheight_response = Some(900_000);
        fake.store_buy_request_response = true;

        let handler = Lsps2ServiceHandler {
            api: Arc::new(fake),
            promise_secret,
        };

        let (_policy, buy) = params_with_promise(&promise_secret);

        // Set payment_size_msat => "MPP+fixed-invoice" mode.
        let request = Lsps2BuyRequest {
            opening_fee_params: buy,
            payment_size_msat: Some(Msat(2_000_000)),
        };
        let peer_id = create_peer_id();

        let result = handler.handle_buy(peer_id, request).await.unwrap();

        assert_eq!(result.lsp_cltv_expiry_delta, DEFAULT_CLTV_EXPIRY_DELTA);
        assert!(!result.client_trusts_lsp);
        assert!(result.jit_channel_scid.to_u64() > 0);
    }

    #[tokio::test]
    async fn buy_ok_variable_amount_no_payment_size() {
        let promise_secret = test_promise_secret();
        let mut fake = FakeCln::default();
        fake.blockheight_response = Some(900_100);
        fake.store_buy_request_response = true;

        let handler = Lsps2ServiceHandler {
            api: Arc::new(fake),
            promise_secret,
        };

        let (_policy, buy) = params_with_promise(&promise_secret);

        // No payment_size_msat => "no-MPP+var-invoice" mode.
        let request = Lsps2BuyRequest {
            opening_fee_params: buy,
            payment_size_msat: None,
        };
        let peer_id = create_peer_id();

        let result = handler.handle_buy(peer_id, request).await;

        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn buy_rejects_invalid_promise_or_past_valid_until_with_201() {
        let promise_secret = test_promise_secret();
        let handler = Lsps2ServiceHandler {
            api: Arc::new(FakeCln::default()),
            promise_secret,
        };

        // Case A: wrong promise (derive with different secret)
        let (_policy_wrong, mut buy_wrong) = params_with_promise(&[9u8; 32]);
        buy_wrong.valid_until = Utc.with_ymd_and_hms(2100, 1, 1, 0, 0, 0).unwrap(); // future, so only promise is wrong
        let req_wrong = Lsps2BuyRequest {
            opening_fee_params: buy_wrong,
            payment_size_msat: Some(Msat(2_000_000)),
        };
        let peer_id = create_peer_id();

        let err1 = handler.handle_buy(peer_id, req_wrong).await.unwrap_err();
        assert_eq!(err1.code, 201);

        // Case B: past valid_until
        let (_policy, mut buy_past) = params_with_promise(&promise_secret);
        buy_past.valid_until = Utc.with_ymd_and_hms(1970, 1, 1, 0, 0, 0).unwrap(); // past
        let req_past = Lsps2BuyRequest {
            opening_fee_params: buy_past,
            payment_size_msat: Some(Msat(2_000_000)),
        };
        let err2 = handler.handle_buy(peer_id, req_past).await.unwrap_err();
        assert_eq!(err2.code, 201);
    }

    #[tokio::test]
    async fn buy_rejects_when_opening_fee_ge_payment_size_with_202() {
        let promise_secret = test_promise_secret();
        let handler = Lsps2ServiceHandler {
            api: Arc::new(FakeCln::default()),
            promise_secret,
        };

        // Make min_fee already >= payment_size to trigger 202
        let policy = PolicyOpeningFeeParams {
            min_fee_msat: Msat(10_000),
            proportional: Ppm(0), // no extra percentage
            valid_until: Utc.with_ymd_and_hms(2100, 1, 1, 0, 0, 0).unwrap(),
            min_lifetime: 1000,
            max_client_to_self_delay: 42,
            min_payment_size_msat: Msat(1),
            max_payment_size_msat: Msat(u64::MAX / 2),
        };
        let hex = policy.get_hmac_hex(&promise_secret);
        let promise: Promise = hex.try_into().unwrap();
        let buy = OpeningFeeParams {
            min_fee_msat: policy.min_fee_msat,
            proportional: policy.proportional,
            valid_until: policy.valid_until,
            min_lifetime: policy.min_lifetime,
            max_client_to_self_delay: policy.max_client_to_self_delay,
            min_payment_size_msat: policy.min_payment_size_msat,
            max_payment_size_msat: policy.max_payment_size_msat,
            promise,
        };

        let request = Lsps2BuyRequest {
            opening_fee_params: buy,
            payment_size_msat: Some(Msat(9_999)), // strictly less than min_fee => opening_fee >= payment_size
        };
        let peer_id = create_peer_id();
        let err = handler.handle_buy(peer_id, request).await.unwrap_err();

        assert_eq!(err.code, 202);
    }

    #[tokio::test]
    async fn buy_rejects_on_fee_overflow_with_203() {
        let promise_secret = test_promise_secret();
        let handler = Lsps2ServiceHandler {
            api: Arc::new(FakeCln::default()),
            promise_secret,
        };

        // Choose values likely to overflow if multiplication isn't checked:
        // opening_fee = min_fee + payment_size * proportional / 1_000_000
        let policy = PolicyOpeningFeeParams {
            min_fee_msat: Msat(u64::MAX / 2),
            proportional: Ppm(u32::MAX), // 4_294_967_295 ppm
            valid_until: Utc.with_ymd_and_hms(2100, 1, 1, 0, 0, 0).unwrap(),
            min_lifetime: 1000,
            max_client_to_self_delay: 42,
            min_payment_size_msat: Msat(1),
            max_payment_size_msat: Msat(u64::MAX),
        };
        let hex = policy.get_hmac_hex(&promise_secret);
        let promise: Promise = hex.try_into().unwrap();
        let buy = OpeningFeeParams {
            min_fee_msat: policy.min_fee_msat,
            proportional: policy.proportional,
            valid_until: policy.valid_until,
            min_lifetime: policy.min_lifetime,
            max_client_to_self_delay: policy.max_client_to_self_delay,
            min_payment_size_msat: policy.min_payment_size_msat,
            max_payment_size_msat: policy.max_payment_size_msat,
            promise,
        };

        let request = Lsps2BuyRequest {
            opening_fee_params: buy,
            payment_size_msat: Some(Msat(u64::MAX / 2)),
        };
        let peer_id = create_peer_id();
        let err = handler.handle_buy(peer_id, request).await.unwrap_err();

        assert_eq!(err.code, 203);
    }
    #[tokio::test]
    async fn test_htlc_no_scid_continues() {
        let fake = FakeCln::default();
        let handler = HtlcAcceptedHookHandler::new(fake, 1000);

        // HTLC with no short_channel_id (final destination)
        let req = create_test_htlc_request(None, 1000000);

        let result = handler.handle(req).await.unwrap();
        assert_eq!(result.result, HtlcAcceptedResult::Continue);
    }

    #[tokio::test]
    async fn test_htlc_unknown_scid_continues() {
        let fake = FakeCln::default();

        let handler = HtlcAcceptedHookHandler::new(fake.clone(), 1000);
        let scid = ShortChannelId::from(123456789u64);

        let req = create_test_htlc_request(Some(scid), 1000000);

        let result = handler.handle(req).await.unwrap();
        assert_eq!(result.result, HtlcAcceptedResult::Continue);
    }

    #[tokio::test]
    async fn test_htlc_expired_fee_menu_fails() {
        let fake = FakeCln::default();
        let handler = HtlcAcceptedHookHandler::new(fake.clone(), 1000);
        let peer_id = create_peer_id();
        let scid = ShortChannelId::from(123456789u64);

        // Create datastore entry with expired fee menu
        let mut ds_entry = create_test_datastore_entry(peer_id, None);
        ds_entry.opening_fee_params.valid_until =
            Utc.with_ymd_and_hms(1970, 1, 1, 0, 0, 0).unwrap(); // expired

        *fake.get_buy_request_response.lock().unwrap() = Some(ds_entry);

        let req = create_test_htlc_request(Some(scid), 1000000);

        let result = handler.handle(req).await.unwrap();
        assert_eq!(result.result, HtlcAcceptedResult::Fail);
        assert_eq!(
            result.failure_message.unwrap(),
            TEMPORARY_CHANNEL_FAILURE.to_string()
        );
    }

    #[tokio::test]
    async fn test_htlc_amount_too_low_fails() {
        let fake = FakeCln::default();
        let handler = HtlcAcceptedHookHandler::new(fake.clone(), 1000);
        let peer_id = create_peer_id();
        let scid = ShortChannelId::from(123456789u64);

        let ds_entry = create_test_datastore_entry(peer_id, None);
        *fake.get_buy_request_response.lock().unwrap() = Some(ds_entry);

        // HTLC amount below minimum
        let req = create_test_htlc_request(Some(scid), 100);

        let result = handler.handle(req).await.unwrap();
        assert_eq!(result.result, HtlcAcceptedResult::Fail);
        assert_eq!(
            result.failure_message.unwrap(),
            UNKNOWN_NEXT_PEER.to_string()
        );
    }

    #[tokio::test]
    async fn test_htlc_amount_too_high_fails() {
        let fake = FakeCln::default();
        let handler = HtlcAcceptedHookHandler::new(fake.clone(), 1000);
        let peer_id = create_peer_id();
        let scid = ShortChannelId::from(123456789u64);

        let ds_entry = create_test_datastore_entry(peer_id, None);
        *fake.get_buy_request_response.lock().unwrap() = Some(ds_entry);

        // HTLC amount above maximum
        let req = create_test_htlc_request(Some(scid), 200_000_000);

        let result = handler.handle(req).await.unwrap();
        assert_eq!(result.result, HtlcAcceptedResult::Fail);
        assert_eq!(
            result.failure_message.unwrap(),
            UNKNOWN_NEXT_PEER.to_string()
        );
    }

    #[tokio::test]
    async fn test_htlc_amount_doesnt_cover_fee_fails() {
        let fake = FakeCln::default();
        let handler = HtlcAcceptedHookHandler::new(fake.clone(), 1000);
        let peer_id = create_peer_id();
        let scid = ShortChannelId::from(123456789u64);

        let ds_entry = create_test_datastore_entry(peer_id, None);
        *fake.get_buy_request_response.lock().unwrap() = Some(ds_entry);

        // HTLC amount just barely covers minimum fee but not minimum HTLC
        let req = create_test_htlc_request(Some(scid), 2500); // min_fee is 2000, htlc_minimum is 1000

        let result = handler.handle(req).await.unwrap();
        assert_eq!(result.result, HtlcAcceptedResult::Fail);
        assert_eq!(
            result.failure_message.unwrap(),
            UNKNOWN_NEXT_PEER.to_string()
        );
    }

    #[tokio::test]
    async fn test_htlc_channel_capacity_request_fails() {
        let fake = FakeCln::default();
        let handler = HtlcAcceptedHookHandler::new(fake.clone(), 1000);
        let peer_id = create_peer_id();
        let scid = ShortChannelId::from(123456789u64);

        let ds_entry = create_test_datastore_entry(peer_id, None);
        *fake.get_buy_request_response.lock().unwrap() = Some(ds_entry);

        *fake.lsps2_getchannelcapacity_error.lock().unwrap() = Some(ClnRpcError {
            code: Some(-1),
            message: "capacity check failed".to_string(),
            data: None,
        });

        let req = create_test_htlc_request(Some(scid), 10_000_000);

        let result = handler.handle(req).await.unwrap();
        assert_eq!(result.result, HtlcAcceptedResult::Fail);
        assert_eq!(
            result.failure_message.unwrap(),
            UNKNOWN_NEXT_PEER.to_string()
        );
    }

    #[tokio::test]
    async fn test_htlc_policy_denies_channel() {
        let fake = FakeCln::default();
        let handler = HtlcAcceptedHookHandler::new(fake.clone(), 1000);
        let peer_id = create_peer_id();
        let scid = ShortChannelId::from(123456789u64);

        let ds_entry = create_test_datastore_entry(peer_id, None);
        *fake.get_buy_request_response.lock().unwrap() = Some(ds_entry);

        // Policy response with no channel capacity (denied)
        *fake.lsps2_getchannelcapacity_response.lock().unwrap() =
            Some(Lsps2PolicyGetChannelCapacityResponse {
                channel_capacity_msat: None,
            });

        let req = create_test_htlc_request(Some(scid), 10_000_000);

        let result = handler.handle(req).await.unwrap();
        assert_eq!(result.result, HtlcAcceptedResult::Fail);
        assert_eq!(
            result.failure_message.unwrap(),
            UNKNOWN_NEXT_PEER.to_string()
        );
    }

    #[tokio::test]
    async fn test_htlc_fund_channel_fails() {
        let fake = FakeCln::default();
        let handler = HtlcAcceptedHookHandler::new(fake.clone(), 1000);
        let peer_id = create_peer_id();
        let scid = ShortChannelId::from(123456789u64);

        let ds_entry = create_test_datastore_entry(peer_id, None);
        *fake.get_buy_request_response.lock().unwrap() = Some(ds_entry);

        *fake.lsps2_getchannelcapacity_response.lock().unwrap() =
            Some(Lsps2PolicyGetChannelCapacityResponse {
                channel_capacity_msat: Some(50_000_000),
            });

        *fake.fund_channel_error.lock().unwrap() = Some(anyhow::anyhow!("insufficient funds"));

        let req = create_test_htlc_request(Some(scid), 10_000_000);

        let result = handler.handle(req).await.unwrap();
        assert_eq!(result.result, HtlcAcceptedResult::Fail);
        assert_eq!(
            result.failure_message.unwrap(),
            UNKNOWN_NEXT_PEER.to_string()
        );
    }

    #[tokio::test]
    async fn test_htlc_successful_flow() {
        let fake = FakeCln::default();
        let handler = HtlcAcceptedHookHandler {
            api: fake.clone(),
            htlc_minimum_msat: 1000,
            backoff_listpeerchannels: Duration::from_millis(10),
        };
        let peer_id = create_peer_id();
        let scid = ShortChannelId::from(123456789u64);

        let ds_entry = create_test_datastore_entry(peer_id, None);
        *fake.get_buy_request_response.lock().unwrap() = Some(ds_entry);

        *fake.lsps2_getchannelcapacity_response.lock().unwrap() =
            Some(Lsps2PolicyGetChannelCapacityResponse {
                channel_capacity_msat: Some(50_000_000),
            });

        *fake.fund_channel_response.lock().unwrap() =
            Some((*Sha256::from_bytes_ref(&[1u8; 32]), String::default()));

        let req = create_test_htlc_request(Some(scid), 10_000_000);

        let result = handler.handle(req).await.unwrap();
        assert_eq!(result.result, HtlcAcceptedResult::Continue);

        assert!(result.payload.is_some());
        assert!(result.extra_tlvs.is_some());
        assert!(result.forward_to.is_some());

        // The payload should have the deducted amount
        let payload_bytes = result.payload.unwrap();
        let payload_tlv = TlvStream::from_bytes(&payload_bytes).unwrap();

        // Should contain forward amount.
        assert!(payload_tlv.get(TLV_FORWARD_AMT).is_some());
    }

    #[tokio::test]
    #[ignore] // We deactivate the mpp check on the experimental server for
              // client side checks.
    async fn test_htlc_mpp_not_implemented() {
        let fake = FakeCln::default();
        let handler = HtlcAcceptedHookHandler::new(fake.clone(), 1000);
        let peer_id = create_peer_id();
        let scid = ShortChannelId::from(123456789u64);

        // Create entry with expected_payment_size (MPP mode)
        let mut ds_entry = create_test_datastore_entry(peer_id, None);
        ds_entry.expected_payment_size = Some(Msat::from_msat(1000000));
        *fake.get_buy_request_response.lock().unwrap() = Some(ds_entry);

        let req = create_test_htlc_request(Some(scid), 10_000_000);

        let result = handler.handle(req).await.unwrap();
        assert_eq!(result.result, HtlcAcceptedResult::Fail);
        assert_eq!(
            result.failure_message.unwrap(),
            UNKNOWN_NEXT_PEER.to_string()
        );
    }
}
