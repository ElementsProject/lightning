use crate::{
    jsonrpc::{server::RequestHandler, JsonRpcResponse as _, RequestObject, RpcError},
    lsps0::primitives::{Msat, ShortChannelId},
    lsps2::{
        cln::{HtlcAcceptedRequest, HtlcAcceptedResponse, TLV_FORWARD_AMT},
        model::{
            compute_opening_fee,
            failure_codes::{TEMPORARY_CHANNEL_FAILURE, UNKNOWN_NEXT_PEER},
            DatastoreEntry, Lsps2BuyRequest, Lsps2BuyResponse, Lsps2GetInfoRequest,
            Lsps2GetInfoResponse, Lsps2PolicyGetChannelCapacityRequest,
            Lsps2PolicyGetChannelCapacityResponse, Lsps2PolicyGetInfoRequest,
            Lsps2PolicyGetInfoResponse, OpeningFeeParams, Promise,
        },
        DS_MAIN_KEY, DS_SUB_KEY,
    },
    util::unwrap_payload_with_peer_id,
};
use anyhow::{Context, Result as AnyResult};
use async_trait::async_trait;
use bitcoin::hashes::Hash as _;
use chrono::Utc;
use cln_rpc::{
    model::{
        requests::{
            DatastoreMode, DatastoreRequest, DeldatastoreRequest, FundchannelRequest,
            GetinfoRequest, ListdatastoreRequest, ListpeerchannelsRequest,
        },
        responses::{
            DatastoreResponse, DeldatastoreResponse, FundchannelResponse, GetinfoResponse,
            ListdatastoreResponse, ListpeerchannelsResponse,
        },
    },
    primitives::{Amount, AmountOrAll, ChannelState},
    ClnRpc,
};
use log::{debug, warn};
use rand::{rng, Rng as _};
use std::{fmt, path::PathBuf, time::Duration};

#[async_trait]
pub trait ClnApi: Send + Sync {
    async fn lsps2_getpolicy(
        &self,
        params: &Lsps2PolicyGetInfoRequest,
    ) -> AnyResult<Lsps2PolicyGetInfoResponse>;

    async fn lsps2_getchannelcapacity(
        &self,
        params: &Lsps2PolicyGetChannelCapacityRequest,
    ) -> AnyResult<Lsps2PolicyGetChannelCapacityResponse>;

    async fn cln_getinfo(&self, params: &GetinfoRequest) -> AnyResult<GetinfoResponse>;

    async fn cln_datastore(&self, params: &DatastoreRequest) -> AnyResult<DatastoreResponse>;

    async fn cln_listdatastore(
        &self,
        params: &ListdatastoreRequest,
    ) -> AnyResult<ListdatastoreResponse>;

    async fn cln_deldatastore(
        &self,
        params: &DeldatastoreRequest,
    ) -> AnyResult<DeldatastoreResponse>;

    async fn cln_fundchannel(&self, params: &FundchannelRequest) -> AnyResult<FundchannelResponse>;

    async fn cln_listpeerchannels(
        &self,
        params: &ListpeerchannelsRequest,
    ) -> AnyResult<ListpeerchannelsResponse>;
}

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
impl ClnApi for ClnApiRpc {
    async fn lsps2_getpolicy(
        &self,
        params: &Lsps2PolicyGetInfoRequest,
    ) -> AnyResult<Lsps2PolicyGetInfoResponse> {
        let mut rpc = self.create_rpc().await?;
        rpc.call_raw("dev-lsps2-getpolicy", params)
            .await
            .map_err(anyhow::Error::new)
            .with_context(|| "calling dev-lsps2-getpolicy")
    }

    async fn lsps2_getchannelcapacity(
        &self,
        params: &Lsps2PolicyGetChannelCapacityRequest,
    ) -> AnyResult<Lsps2PolicyGetChannelCapacityResponse> {
        let mut rpc = self.create_rpc().await?;
        rpc.call_raw("dev-lsps2-getchannelcapacity", params)
            .await
            .map_err(anyhow::Error::new)
            .with_context(|| "calling dev-lsps2-getchannelcapacity")
    }

    async fn cln_getinfo(&self, params: &GetinfoRequest) -> AnyResult<GetinfoResponse> {
        let mut rpc = self.create_rpc().await?;
        rpc.call_typed(params)
            .await
            .map_err(anyhow::Error::new)
            .with_context(|| "calling getinfo")
    }

    async fn cln_datastore(&self, params: &DatastoreRequest) -> AnyResult<DatastoreResponse> {
        let mut rpc = self.create_rpc().await?;
        rpc.call_typed(params)
            .await
            .map_err(anyhow::Error::new)
            .with_context(|| "calling datastore")
    }

    async fn cln_listdatastore(
        &self,
        params: &ListdatastoreRequest,
    ) -> AnyResult<ListdatastoreResponse> {
        let mut rpc = self.create_rpc().await?;
        rpc.call_typed(params)
            .await
            .map_err(anyhow::Error::new)
            .with_context(|| "calling listdatastore")
    }

    async fn cln_deldatastore(
        &self,
        params: &DeldatastoreRequest,
    ) -> AnyResult<DeldatastoreResponse> {
        let mut rpc = self.create_rpc().await?;
        rpc.call_typed(params)
            .await
            .map_err(anyhow::Error::new)
            .with_context(|| "calling deldatastore")
    }

    async fn cln_fundchannel(&self, params: &FundchannelRequest) -> AnyResult<FundchannelResponse> {
        let mut rpc = self.create_rpc().await?;
        rpc.call_typed(params)
            .await
            .map_err(anyhow::Error::new)
            .with_context(|| "calling fundchannel")
    }

    async fn cln_listpeerchannels(
        &self,
        params: &ListpeerchannelsRequest,
    ) -> AnyResult<ListpeerchannelsResponse> {
        let mut rpc = self.create_rpc().await?;
        rpc.call_typed(params)
            .await
            .map_err(anyhow::Error::new)
            .with_context(|| "calling listpeerchannels")
    }
}

/// Handler for the `lsps2.get_info` method.
pub struct Lsps2GetInfoHandler<A: ClnApi> {
    pub api: A,
    pub promise_secret: [u8; 32],
}

impl<A: ClnApi> Lsps2GetInfoHandler<A> {
    pub fn new(api: A, promise_secret: [u8; 32]) -> Self {
        Self {
            api,
            promise_secret,
        }
    }
}

/// The RequestHandler calls the internal rpc command `dev-lsps2-getinfo`. It
/// expects a plugin has registered this command and manages policies for the
/// LSPS2 service.
#[async_trait]
impl<T: ClnApi + 'static> RequestHandler for Lsps2GetInfoHandler<T> {
    async fn handle(&self, payload: &[u8]) -> core::result::Result<Vec<u8>, RpcError> {
        let (payload, _) = unwrap_payload_with_peer_id(payload);

        let req: RequestObject<Lsps2GetInfoRequest> = serde_json::from_slice(&payload)
            .map_err(|e| RpcError::parse_error(format!("failed to parse request: {e}")))?;

        if req.id.is_none() {
            // Is a notification we can not reply so we just return
            return Ok(vec![]);
        }
        let params = req
            .params
            .ok_or(RpcError::invalid_params("expected params but was missing"))?;

        let policy_params: Lsps2PolicyGetInfoRequest = params.into();
        let res_data: Lsps2PolicyGetInfoResponse = self
            .api
            .lsps2_getpolicy(&policy_params)
            .await
            .map_err(|e| RpcError {
            code: 200,
            message: format!("failed to fetch policy {e:#}"),
            data: None,
        })?;

        let opening_fee_params_menu = res_data
            .policy_opening_fee_params_menu
            .iter()
            .map(|v| {
                let promise: Promise = v
                    .get_hmac_hex(&self.promise_secret)
                    .try_into()
                    .map_err(|e| RpcError::internal_error(format!("invalid promise: {e}")))?;
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
            })
            .collect::<Result<Vec<_>, RpcError>>()?;

        let res = Lsps2GetInfoResponse {
            opening_fee_params_menu,
        }
        .into_response(req.id.unwrap()); // We checked that we got an id before.

        serde_json::to_vec(&res)
            .map_err(|e| RpcError::internal_error(format!("Failed to serialize response: {}", e)))
    }
}

pub struct Lsps2BuyHandler<A: ClnApi> {
    pub api: A,
    pub promise_secret: [u8; 32],
}

impl<A: ClnApi> Lsps2BuyHandler<A> {
    pub fn new(api: A, promise_secret: [u8; 32]) -> Self {
        Self {
            api,
            promise_secret,
        }
    }
}

#[async_trait]
impl<A: ClnApi + 'static> RequestHandler for Lsps2BuyHandler<A> {
    async fn handle(&self, payload: &[u8]) -> core::result::Result<Vec<u8>, RpcError> {
        let (payload, peer_id) = unwrap_payload_with_peer_id(payload);

        let req: RequestObject<Lsps2BuyRequest> = serde_json::from_slice(&payload)
            .map_err(|e| RpcError::parse_error(format!("Failed to parse request: {}", e)))?;

        if req.id.is_none() {
            // Is a notification we can not reply so we just return
            return Ok(vec![]);
        }

        let req_params = req
            .params
            .ok_or_else(|| RpcError::invalid_request("Missing params field"))?;

        let fee_params = req_params.opening_fee_params;

        // FIXME: In the future we should replace the \`None\` with a meaningful
        // value that reflects the inbound capacity for this node from the
        // public network for a better pre-condition check on the payment_size.
        fee_params.validate(&self.promise_secret, req_params.payment_size_msat, None)?;

        // Generate a tmp scid to identify jit channel request in htlc.
        let get_info_req = GetinfoRequest {};
        let info = self.api.cln_getinfo(&get_info_req).await.map_err(|e| {
            warn!("Failed to call getinfo via rpc {}", e);
            RpcError::internal_error("Internal error")
        })?;

        // FIXME: Future task: Check that we don't conflict with any jit scid we
        // already handed out -> Check datastore entries.
        let jit_scid_u64 = generate_jit_scid(info.blockheight);
        let jit_scid = ShortChannelId::from(jit_scid_u64);
        let ds_data = DatastoreEntry {
            peer_id,
            opening_fee_params: fee_params,
            expected_payment_size: req_params.payment_size_msat,
        };
        let ds_json = serde_json::to_string(&ds_data).map_err(|e| {
            warn!("Failed to serialize opening fee params to string {}", e);
            RpcError::internal_error("Internal error")
        })?;

        let ds_req = DatastoreRequest {
            generation: None,
            hex: None,
            mode: Some(DatastoreMode::MUST_CREATE),
            string: Some(ds_json),
            key: vec![
                DS_MAIN_KEY.to_string(),
                DS_SUB_KEY.to_string(),
                jit_scid.to_string(),
            ],
        };

        let _ds_res = self.api.cln_datastore(&ds_req).await.map_err(|e| {
            warn!("Failed to store jit request in ds via rpc {}", e);
            RpcError::internal_error("Internal error")
        })?;

        let res = Lsps2BuyResponse {
            jit_channel_scid: jit_scid,
            // We can make this configurable if necessary.
            lsp_cltv_expiry_delta: DEFAULT_CLTV_EXPIRY_DELTA,
            // We can implement the other mode later on as we might have to do
            // some additional work on core-lightning to enable this.
            client_trusts_lsp: false,
        }
        .into_response(req.id.unwrap()); // We checked that we got an id before.

        serde_json::to_vec(&res)
            .map_err(|e| RpcError::internal_error(format!("Failed to serialize response: {}", e)))
    }
}

fn generate_jit_scid(best_blockheigt: u32) -> u64 {
    let mut rng = rng();
    let block = best_blockheigt + 6; // Approx 1 hour in the future and should avoid collision with confirmed channels
    let tx_idx: u32 = rng.random_range(0..5000);
    let output_idx: u16 = rng.random_range(0..10);

    ((block as u64) << 40) | ((tx_idx as u64) << 16) | (output_idx as u64)
}

pub struct HtlcAcceptedHookHandler<A: ClnApi> {
    api: A,
    htlc_minimum_msat: u64,
    backoff_listpeerchannels: Duration,
}

impl<A: ClnApi> HtlcAcceptedHookHandler<A> {
    pub fn new(api: A, htlc_minimum_msat: u64) -> Self {
        Self {
            api,
            htlc_minimum_msat,
            backoff_listpeerchannels: Duration::from_secs(10),
        }
    }

    pub async fn handle(&self, req: HtlcAcceptedRequest) -> AnyResult<HtlcAcceptedResponse> {
        let scid = match req.onion.short_channel_id {
            Some(scid) => scid,
            None => {
                // We are the final destination of this htlc.
                return Ok(HtlcAcceptedResponse::continue_(None, None, None));
            }
        };

        // A) Is this SCID one that we care about?
        let ds_req = ListdatastoreRequest {
            key: Some(scid_ds_key(scid)),
        };
        let ds_res = self.api.cln_listdatastore(&ds_req).await.map_err(|e| {
            warn!("Failed to listpeerchannels via rpc {}", e);
            RpcError::internal_error("Internal error")
        })?;

        let (ds_rec, ds_gen) = match deserialize_by_key(&ds_res, scid_ds_key(scid)) {
            Ok(r) => r,
            Err(DsError::NotFound { .. }) => {
                // We don't know the scid, continue.
                return Ok(HtlcAcceptedResponse::continue_(None, None, None));
            }
            Err(e @ DsError::MissingValue { .. })
            | Err(e @ DsError::HexDecode { .. })
            | Err(e @ DsError::JsonParse { .. }) => {
                // We have a data issue, log and continue.
                // Note: We may want to actually reject the htlc here or throw
                // an error alltogether but we will try to fulfill this htlc for
                // now.
                warn!("datastore issue: {}", e);
                return Ok(HtlcAcceptedResponse::continue_(None, None, None));
            }
        };

        // Fixme: Check that we don't have a channel yet with the peer that we await to
        // become READY to use.
        // ---

        // Fixme: We only accept no-mpp for now, mpp and other flows will be added later on
        if ds_rec.expected_payment_size.is_some() {
            warn!("mpp payments are not implemented yet");
            return Ok(HtlcAcceptedResponse::fail(
                Some(UNKNOWN_NEXT_PEER.to_string()),
                None,
            ));
        }

        // B) Is the fee option menu still valid?
        let now = Utc::now();
        if now >= ds_rec.opening_fee_params.valid_until {
            // Not valid anymore, remove from DS and fail HTLC.
            let ds_req = DeldatastoreRequest {
                generation: ds_gen,
                key: scid_ds_key(scid),
            };
            match self.api.cln_deldatastore(&ds_req).await {
                Ok(_) => debug!("removed datastore for scid: {}, wasn't valid anymore", scid),
                Err(e) => warn!("could not remove datastore for scid: {}: {}", scid, e),
            };
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
        let ch_cap_res = match self.api.lsps2_getchannelcapacity(&ch_cap_req).await {
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
            Some(c) => c,
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
        let fund_ch_req = FundchannelRequest {
            announce: Some(false),
            close_to: None,
            compact_lease: None,
            feerate: None,
            minconf: None,
            mindepth: Some(0),
            push_msat: None,
            request_amt: None,
            reserve: None,
            channel_type: Some(vec![12, 22, 50]),
            utxos: None,
            amount: AmountOrAll::Amount(Amount::from_msat(cap)),
            id: ds_rec.peer_id,
        };

        let fund_ch_res = match self.api.cln_fundchannel(&fund_ch_req).await {
            Ok(r) => r,
            Err(e) => {
                // Fixme: Retry to fund the channel.
                warn!("could not fund jit channel for scid {}: {}", scid, e);
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
        let mut is_active = false;
        while !is_active {
            let ls_ch_req = ListpeerchannelsRequest {
                id: Some(ds_rec.peer_id),
                short_channel_id: None,
            };
            let ls_ch_res = match self.api.cln_listpeerchannels(&ls_ch_req).await {
                Ok(r) => r,
                Err(e) => {
                    warn!("failed to fetch peer channels for scid {}: {}", scid, e);
                    tokio::time::sleep(self.backoff_listpeerchannels).await;
                    continue;
                }
            };
            let chs = ls_ch_res
                .channels
                .iter()
                .find(|&ch| ch.channel_id.is_some_and(|id| id == fund_ch_res.channel_id));
            if let Some(ch) = chs {
                debug!("jit channel for scid {} has state {:?}", scid, ch.state);
                if ch.state == ChannelState::CHANNELD_NORMAL {
                    is_active = true;
                }
            }
            tokio::time::sleep(self.backoff_listpeerchannels).await;
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
            Some(fund_ch_res.channel_id.as_byte_array().to_vec()),
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

fn scid_ds_key(scid: ShortChannelId) -> Vec<String> {
    vec![
        DS_MAIN_KEY.to_string(),
        DS_SUB_KEY.to_string(),
        scid.to_string(),
    ]
}

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
    use std::sync::{Arc, Mutex};

    use super::*;
    use crate::{
        jsonrpc::{JsonRpcRequest, ResponseObject},
        lsps0::primitives::{Msat, Ppm},
        lsps2::{
            cln::{tlv::TlvStream, HtlcAcceptedResult},
            model::PolicyOpeningFeeParams,
        },
        util::wrap_payload_with_peer_id,
    };
    use chrono::{TimeZone, Utc};
    use cln_rpc::{model::responses::ListdatastoreDatastore, RpcError as ClnRpcError};
    use cln_rpc::{
        model::responses::ListpeerchannelsChannels,
        primitives::{Amount, PublicKey, Sha256},
    };
    use serde::Serialize;

    const PUBKEY: [u8; 33] = [
        0x02, 0x79, 0xbe, 0x66, 0x7e, 0xf9, 0xdc, 0xbb, 0xac, 0x55, 0xa0, 0x62, 0x95, 0xce, 0x87,
        0x0b, 0x07, 0x02, 0x9b, 0xfc, 0xdb, 0x2d, 0xce, 0x28, 0xd9, 0x59, 0xf2, 0x81, 0x5b, 0x16,
        0xf8, 0x17, 0x98,
    ];

    fn create_peer_id() -> PublicKey {
        PublicKey::from_slice(&PUBKEY).expect("Valid pubkey")
    }

    fn create_wrapped_request<T: Serialize>(request: &RequestObject<T>) -> Vec<u8> {
        let payload = serde_json::to_vec(request).expect("Failed to serialize request");
        wrap_payload_with_peer_id(&payload, create_peer_id())
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
        cln_getinfo_response: Arc<Mutex<Option<GetinfoResponse>>>,
        cln_getinfo_error: Arc<Mutex<Option<ClnRpcError>>>,
        cln_datastore_response: Arc<Mutex<Option<DatastoreResponse>>>,
        cln_datastore_error: Arc<Mutex<Option<ClnRpcError>>>,
        cln_listdatastore_response: Arc<Mutex<Option<ListdatastoreResponse>>>,
        cln_listdatastore_error: Arc<Mutex<Option<ClnRpcError>>>,
        cln_deldatastore_response: Arc<Mutex<Option<DeldatastoreResponse>>>,
        cln_deldatastore_error: Arc<Mutex<Option<ClnRpcError>>>,
        cln_fundchannel_response: Arc<Mutex<Option<FundchannelResponse>>>,
        cln_fundchannel_error: Arc<Mutex<Option<ClnRpcError>>>,
        cln_listpeerchannels_response: Arc<Mutex<Option<ListpeerchannelsResponse>>>,
        cln_listpeerchannels_error: Arc<Mutex<Option<ClnRpcError>>>,
        lsps2_getchannelcapacity_response:
            Arc<Mutex<Option<Lsps2PolicyGetChannelCapacityResponse>>>,
        lsps2_getchannelcapacity_error: Arc<Mutex<Option<ClnRpcError>>>,
    }

    #[async_trait]
    impl ClnApi for FakeCln {
        async fn lsps2_getpolicy(
            &self,
            _params: &Lsps2PolicyGetInfoRequest,
        ) -> Result<Lsps2PolicyGetInfoResponse, anyhow::Error> {
            if let Some(err) = self.lsps2_getpolicy_error.lock().unwrap().take() {
                return Err(anyhow::Error::new(err).context("from fake api"));
            };
            if let Some(res) = self.lsps2_getpolicy_response.lock().unwrap().take() {
                return Ok(res);
            };
            panic!("No lsps2 response defined");
        }

        async fn lsps2_getchannelcapacity(
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

        async fn cln_getinfo(
            &self,
            _params: &GetinfoRequest,
        ) -> Result<GetinfoResponse, anyhow::Error> {
            if let Some(err) = self.cln_getinfo_error.lock().unwrap().take() {
                return Err(anyhow::Error::new(err).context("from fake api"));
            };
            if let Some(res) = self.cln_getinfo_response.lock().unwrap().take() {
                return Ok(res);
            };
            panic!("No cln getinfo response defined");
        }

        async fn cln_datastore(
            &self,
            _params: &DatastoreRequest,
        ) -> Result<DatastoreResponse, anyhow::Error> {
            if let Some(err) = self.cln_datastore_error.lock().unwrap().take() {
                return Err(anyhow::Error::new(err).context("from fake api"));
            };
            if let Some(res) = self.cln_datastore_response.lock().unwrap().take() {
                return Ok(res);
            };
            panic!("No cln datastore response defined");
        }

        async fn cln_listdatastore(
            &self,
            _params: &ListdatastoreRequest,
        ) -> AnyResult<ListdatastoreResponse> {
            if let Some(err) = self.cln_listdatastore_error.lock().unwrap().take() {
                return Err(anyhow::Error::new(err).context("from fake api"));
            }
            if let Some(res) = self.cln_listdatastore_response.lock().unwrap().take() {
                return Ok(res);
            }
            panic!("No cln listdatastore response defined");
        }

        async fn cln_deldatastore(
            &self,
            _params: &DeldatastoreRequest,
        ) -> AnyResult<DeldatastoreResponse> {
            if let Some(err) = self.cln_deldatastore_error.lock().unwrap().take() {
                return Err(anyhow::Error::new(err).context("from fake api"));
            }
            if let Some(res) = self.cln_deldatastore_response.lock().unwrap().take() {
                return Ok(res);
            }
            panic!("No cln deldatastore response defined");
        }

        async fn cln_fundchannel(
            &self,
            _params: &FundchannelRequest,
        ) -> AnyResult<FundchannelResponse> {
            if let Some(err) = self.cln_fundchannel_error.lock().unwrap().take() {
                return Err(anyhow::Error::new(err).context("from fake api"));
            }
            if let Some(res) = self.cln_fundchannel_response.lock().unwrap().take() {
                return Ok(res);
            }
            panic!("No cln fundchannel response defined");
        }

        async fn cln_listpeerchannels(
            &self,
            _params: &ListpeerchannelsRequest,
        ) -> AnyResult<ListpeerchannelsResponse> {
            if let Some(err) = self.cln_listpeerchannels_error.lock().unwrap().take() {
                return Err(anyhow::Error::new(err).context("from fake api"));
            }

            if let Some(res) = self.cln_listpeerchannels_response.lock().unwrap().take() {
                return Ok(res);
            }

            // Default: return a ready channel
            let channel = ListpeerchannelsChannels {
                channel_id: Some(*Sha256::from_bytes_ref(&[1u8; 32])),
                state: ChannelState::CHANNELD_NORMAL,
                peer_id: create_peer_id(),
                peer_connected: true,
                alias: None,
                closer: None,
                funding: None,
                funding_outnum: None,
                funding_txid: None,
                htlcs: None,
                in_offered_msat: None,
                initial_feerate: None,
                last_feerate: None,
                last_stable_connection: None,
                last_tx_fee_msat: None,
                lost_state: None,
                max_accepted_htlcs: None,
                minimum_htlc_in_msat: None,
                next_feerate: None,
                next_fee_step: None,
                out_fulfilled_msat: None,
                out_offered_msat: None,
                owner: None,
                private: None,
                receivable_msat: None,
                reestablished: None,
                scratch_txid: None,
                short_channel_id: None,
                spendable_msat: None,
                status: None,
                their_reserve_msat: None,
                to_us_msat: None,
                total_msat: None,
                close_to: None,
                close_to_addr: None,
                direction: None,
                dust_limit_msat: None,
                fee_base_msat: None,
                fee_proportional_millionths: None,
                feerate: None,
                ignore_fee_limits: None,
                in_fulfilled_msat: None,
                in_payments_fulfilled: None,
                in_payments_offered: None,
                max_to_us_msat: None,
                maximum_htlc_out_msat: None,
                min_to_us_msat: None,
                minimum_htlc_out_msat: None,
                our_max_htlc_value_in_flight_msat: None,
                our_reserve_msat: None,
                our_to_self_delay: None,
                out_payments_fulfilled: None,
                out_payments_offered: None,
                their_max_htlc_value_in_flight_msat: None,
                their_to_self_delay: None,
                updates: None,
                inflight: None,
                #[allow(deprecated)]
                max_total_htlc_in_msat: None,
                opener: cln_rpc::primitives::ChannelSide::LOCAL,
            };

            Ok(ListpeerchannelsResponse {
                channels: vec![channel],
            })
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

    fn minimal_getinfo(height: u32) -> GetinfoResponse {
        GetinfoResponse {
            lightning_dir: String::default(),
            alias: None,
            our_features: None,
            warning_bitcoind_sync: None,
            warning_lightningd_sync: None,
            address: None,
            binding: None,
            blockheight: height,
            color: String::default(),
            fees_collected_msat: Amount::from_msat(0),
            id: PublicKey::from_slice(&PUBKEY).expect("pubkey from slice"),
            network: String::default(),
            num_active_channels: u32::default(),
            num_inactive_channels: u32::default(),
            num_peers: u32::default(),
            num_pending_channels: u32::default(),
            version: String::default(),
        }
    }

    #[tokio::test]
    async fn test_successful_get_info() {
        let promise_secret = [0u8; 32];
        let params = Lsps2PolicyGetInfoResponse {
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
        let handler = Lsps2GetInfoHandler::new(fake, promise_secret);

        let request = Lsps2GetInfoRequest { token: None }.into_request(Some("test-id".to_string()));
        let payload = create_wrapped_request(&request);

        let result = handler.handle(&payload).await.unwrap();
        let response: ResponseObject<Lsps2GetInfoResponse> =
            serde_json::from_slice(&result).unwrap();
        let response = response.into_inner().unwrap();

        assert_eq!(
            response.opening_fee_params_menu[0].min_payment_size_msat,
            Msat(1000000)
        );
        assert_eq!(
            response.opening_fee_params_menu[0].max_payment_size_msat,
            Msat(100000000)
        );
        assert_eq!(
            response.opening_fee_params_menu[0].promise,
            promise.try_into().unwrap()
        );
    }

    #[tokio::test]
    async fn test_get_info_rpc_error_handling() {
        let fake = FakeCln::default();
        *fake.lsps2_getpolicy_error.lock().unwrap() = Some(ClnRpcError {
            code: Some(-1),
            message: "not found".to_string(),
            data: None,
        });
        let handler = Lsps2GetInfoHandler::new(fake, [0; 32]);
        let request = Lsps2GetInfoRequest { token: None }.into_request(Some("test-id".to_string()));
        let payload = create_wrapped_request(&request);

        let result = handler.handle(&payload).await;

        assert!(result.is_err());
        let error = result.unwrap_err();
        assert_eq!(error.code, 200);
        assert!(error.message.contains("failed to fetch policy"));
    }

    #[tokio::test]
    async fn buy_ok_fixed_amount() {
        let secret = [0u8; 32];
        let fake = FakeCln::default();
        *fake.cln_getinfo_response.lock().unwrap() = Some(minimal_getinfo(900_000));
        *fake.cln_datastore_response.lock().unwrap() = Some(DatastoreResponse {
            generation: Some(0),
            hex: None,
            string: None,
            key: vec![],
        });

        let handler = Lsps2BuyHandler::new(fake, secret);
        let (_policy, buy) = params_with_promise(&secret);

        // Set payment_size_msat => "MPP+fixed-invoice" mode.
        let req = Lsps2BuyRequest {
            opening_fee_params: buy,
            payment_size_msat: Some(Msat(2_000_000)),
        }
        .into_request(Some("ok-fixed".into()));
        let payload = create_wrapped_request(&req);

        let out = handler.handle(&payload).await.unwrap();
        let resp: ResponseObject<Lsps2BuyResponse> = serde_json::from_slice(&out).unwrap();
        let resp = resp.into_inner().unwrap();

        assert_eq!(resp.lsp_cltv_expiry_delta, DEFAULT_CLTV_EXPIRY_DELTA);
        assert!(!resp.client_trusts_lsp);
        assert!(resp.jit_channel_scid.to_u64() > 0);
    }

    #[tokio::test]
    async fn buy_ok_variable_amount_no_payment_size() {
        let secret = [2u8; 32];
        let fake = FakeCln::default();
        *fake.cln_getinfo_response.lock().unwrap() = Some(minimal_getinfo(900_100));
        *fake.cln_datastore_response.lock().unwrap() = Some(DatastoreResponse {
            generation: Some(0),
            hex: None,
            string: None,
            key: vec![],
        });

        let handler = Lsps2BuyHandler::new(fake, secret);
        let (_policy, buy) = params_with_promise(&secret);

        // No payment_size_msat => "no-MPP+var-invoice" mode.
        let req = Lsps2BuyRequest {
            opening_fee_params: buy,
            payment_size_msat: None,
        }
        .into_request(Some("ok-var".into()));
        let payload = create_wrapped_request(&req);

        let out = handler.handle(&payload).await.unwrap();
        let resp: ResponseObject<Lsps2BuyResponse> = serde_json::from_slice(&out).unwrap();
        assert!(resp.into_inner().is_ok());
    }

    #[tokio::test]
    async fn buy_rejects_invalid_promise_or_past_valid_until_with_201() {
        let secret = [3u8; 32];
        let handler = Lsps2BuyHandler::new(FakeCln::default(), secret);

        // Case A: wrong promise (derive with different secret)
        let (_policy_wrong, mut buy_wrong) = params_with_promise(&[9u8; 32]);
        buy_wrong.valid_until = Utc.with_ymd_and_hms(2100, 1, 1, 0, 0, 0).unwrap(); // future, so only promise is wrong
        let req_wrong = Lsps2BuyRequest {
            opening_fee_params: buy_wrong,
            payment_size_msat: Some(Msat(2_000_000)),
        }
        .into_request(Some("bad-promise".into()));
        let err1 = handler
            .handle(&create_wrapped_request(&req_wrong))
            .await
            .unwrap_err();
        assert_eq!(err1.code, 201);

        // Case B: past valid_until
        let (_policy, mut buy_past) = params_with_promise(&secret);
        buy_past.valid_until = Utc.with_ymd_and_hms(1970, 1, 1, 0, 0, 0).unwrap(); // past
        let req_past = Lsps2BuyRequest {
            opening_fee_params: buy_past,
            payment_size_msat: Some(Msat(2_000_000)),
        }
        .into_request(Some("past-valid".into()));
        let err2 = handler
            .handle(&create_wrapped_request(&req_past))
            .await
            .unwrap_err();
        assert_eq!(err2.code, 201);
    }

    #[tokio::test]
    async fn buy_rejects_when_opening_fee_ge_payment_size_with_202() {
        let secret = [4u8; 32];
        let handler = Lsps2BuyHandler::new(FakeCln::default(), secret);

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
        let hex = policy.get_hmac_hex(&secret);
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

        let req = Lsps2BuyRequest {
            opening_fee_params: buy,
            payment_size_msat: Some(Msat(9_999)), // strictly less than min_fee => opening_fee >= payment_size
        }
        .into_request(Some("too-small".into()));

        let err = handler
            .handle(&create_wrapped_request(&req))
            .await
            .unwrap_err();
        assert_eq!(err.code, 202);
    }

    #[tokio::test]
    async fn buy_rejects_on_fee_overflow_with_203() {
        let secret = [5u8; 32];
        let handler = Lsps2BuyHandler::new(FakeCln::default(), secret);

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
        let hex = policy.get_hmac_hex(&secret);
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

        let req = Lsps2BuyRequest {
            opening_fee_params: buy,
            payment_size_msat: Some(Msat(u64::MAX / 2)),
        }
        .into_request(Some("overflow".into()));

        let err = handler
            .handle(&create_wrapped_request(&req))
            .await
            .unwrap_err();
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

        // Return empty datastore response (SCID not found)
        *fake.cln_listdatastore_response.lock().unwrap() =
            Some(ListdatastoreResponse { datastore: vec![] });

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

        let ds_entry_json = serde_json::to_string(&ds_entry).unwrap();
        *fake.cln_listdatastore_response.lock().unwrap() = Some(ListdatastoreResponse {
            datastore: vec![ListdatastoreDatastore {
                key: scid_ds_key(scid),
                generation: Some(1),
                hex: None,
                string: Some(ds_entry_json),
            }],
        });

        // Mock successful deletion
        *fake.cln_deldatastore_response.lock().unwrap() = Some(DeldatastoreResponse {
            generation: Some(1),
            hex: None,
            string: None,
            key: scid_ds_key(scid),
        });

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
        let ds_entry_json = serde_json::to_string(&ds_entry).unwrap();

        *fake.cln_listdatastore_response.lock().unwrap() = Some(ListdatastoreResponse {
            datastore: vec![ListdatastoreDatastore {
                key: scid_ds_key(scid),
                generation: Some(1),
                hex: None,
                string: Some(ds_entry_json),
            }],
        });

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
        let ds_entry_json = serde_json::to_string(&ds_entry).unwrap();

        *fake.cln_listdatastore_response.lock().unwrap() = Some(ListdatastoreResponse {
            datastore: vec![ListdatastoreDatastore {
                key: scid_ds_key(scid),
                generation: Some(1),
                hex: None,
                string: Some(ds_entry_json),
            }],
        });

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
        let ds_entry_json = serde_json::to_string(&ds_entry).unwrap();

        *fake.cln_listdatastore_response.lock().unwrap() = Some(ListdatastoreResponse {
            datastore: vec![ListdatastoreDatastore {
                key: scid_ds_key(scid),
                generation: Some(1),
                hex: None,
                string: Some(ds_entry_json),
            }],
        });

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
        let ds_entry_json = serde_json::to_string(&ds_entry).unwrap();

        *fake.cln_listdatastore_response.lock().unwrap() = Some(ListdatastoreResponse {
            datastore: vec![ListdatastoreDatastore {
                key: scid_ds_key(scid),
                generation: Some(1),
                hex: None,
                string: Some(ds_entry_json),
            }],
        });

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
        let ds_entry_json = serde_json::to_string(&ds_entry).unwrap();

        *fake.cln_listdatastore_response.lock().unwrap() = Some(ListdatastoreResponse {
            datastore: vec![ListdatastoreDatastore {
                key: scid_ds_key(scid),
                generation: Some(1),
                hex: None,
                string: Some(ds_entry_json),
            }],
        });

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
        let ds_entry_json = serde_json::to_string(&ds_entry).unwrap();

        *fake.cln_listdatastore_response.lock().unwrap() = Some(ListdatastoreResponse {
            datastore: vec![ListdatastoreDatastore {
                key: scid_ds_key(scid),
                generation: Some(1),
                hex: None,
                string: Some(ds_entry_json),
            }],
        });

        *fake.lsps2_getchannelcapacity_response.lock().unwrap() =
            Some(Lsps2PolicyGetChannelCapacityResponse {
                channel_capacity_msat: Some(50_000_000),
            });

        *fake.cln_fundchannel_error.lock().unwrap() = Some(ClnRpcError {
            code: Some(-1),
            message: "insufficient funds".to_string(),
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
        let ds_entry_json = serde_json::to_string(&ds_entry).unwrap();

        *fake.cln_listdatastore_response.lock().unwrap() = Some(ListdatastoreResponse {
            datastore: vec![ListdatastoreDatastore {
                key: scid_ds_key(scid),
                generation: Some(1),
                hex: None,
                string: Some(ds_entry_json),
            }],
        });

        *fake.lsps2_getchannelcapacity_response.lock().unwrap() =
            Some(Lsps2PolicyGetChannelCapacityResponse {
                channel_capacity_msat: Some(50_000_000),
            });

        *fake.cln_fundchannel_response.lock().unwrap() = Some(FundchannelResponse {
            channel_id: *Sha256::from_bytes_ref(&[1u8; 32]),
            outnum: 0,
            txid: String::default(),
            channel_type: None,
            close_to: None,
            mindepth: None,
            tx: String::default(),
        });

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
    async fn test_htlc_mpp_not_implemented() {
        let fake = FakeCln::default();
        let handler = HtlcAcceptedHookHandler::new(fake.clone(), 1000);
        let peer_id = create_peer_id();
        let scid = ShortChannelId::from(123456789u64);

        // Create entry with expected_payment_size (MPP mode)
        let mut ds_entry = create_test_datastore_entry(peer_id, None);
        ds_entry.expected_payment_size = Some(Msat::from_msat(1000000));
        let ds_entry_json = serde_json::to_string(&ds_entry).unwrap();

        *fake.cln_listdatastore_response.lock().unwrap() = Some(ListdatastoreResponse {
            datastore: vec![ListdatastoreDatastore {
                key: scid_ds_key(scid),
                generation: Some(1),
                hex: None,
                string: Some(ds_entry_json),
            }],
        });

        let req = create_test_htlc_request(Some(scid), 10_000_000);

        let result = handler.handle(req).await.unwrap();
        assert_eq!(result.result, HtlcAcceptedResult::Fail);
        assert_eq!(
            result.failure_message.unwrap(),
            UNKNOWN_NEXT_PEER.to_string()
        );
    }
}
