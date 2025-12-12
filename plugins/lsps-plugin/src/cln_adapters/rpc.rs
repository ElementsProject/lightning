use crate::{
    core::lsps2::provider::{
        Blockheight, BlockheightProvider, DatastoreProvider, LightningProvider, Lsps2OfferProvider,
    },
    proto::{
        lsps0::Msat,
        lsps2::{
            DatastoreEntry, Lsps2PolicyGetChannelCapacityRequest,
            Lsps2PolicyGetChannelCapacityResponse, Lsps2PolicyGetInfoRequest,
            Lsps2PolicyGetInfoResponse, OpeningFeeParams,
        },
    },
};
use anyhow::{Context, Result};
use async_trait::async_trait;
use bitcoin::secp256k1::PublicKey;
use cln_rpc::{
    model::{
        requests::{
            DatastoreMode, DatastoreRequest, DeldatastoreRequest, FundchannelRequest,
            GetinfoRequest, ListdatastoreRequest, ListpeerchannelsRequest,
        },
        responses::ListdatastoreResponse,
    },
    primitives::{Amount, AmountOrAll, ChannelState, Sha256, ShortChannelId},
    ClnRpc,
};
use core::fmt;
use serde::Serialize;
use std::path::PathBuf;

pub const DS_MAIN_KEY: &'static str = "lsps";
pub const DS_SUB_KEY: &'static str = "lsps2";

#[derive(Clone)]
pub struct ClnApiRpc {
    rpc_path: PathBuf,
}

impl ClnApiRpc {
    pub fn new(rpc_path: PathBuf) -> Self {
        Self { rpc_path }
    }

    async fn create_rpc(&self) -> Result<ClnRpc> {
        ClnRpc::new(&self.rpc_path).await
    }
}

#[async_trait]
impl LightningProvider for ClnApiRpc {
    async fn fund_jit_channel(
        &self,
        peer_id: &PublicKey,
        amount: &Msat,
    ) -> Result<(Sha256, String)> {
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

    async fn is_channel_ready(&self, peer_id: &PublicKey, channel_id: &Sha256) -> Result<bool> {
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
    ) -> Result<bool> {
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

    async fn get_buy_request(&self, scid: &ShortChannelId) -> Result<DatastoreEntry> {
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

    async fn del_buy_request(&self, scid: &ShortChannelId) -> Result<()> {
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
    ) -> Result<Lsps2PolicyGetInfoResponse> {
        let mut rpc = self.create_rpc().await?;
        rpc.call_raw("lsps2-policy-getpolicy", request)
            .await
            .context("failed to call lsps2-policy-getpolicy")
    }

    async fn get_channel_capacity(
        &self,
        params: &Lsps2PolicyGetChannelCapacityRequest,
    ) -> Result<Lsps2PolicyGetChannelCapacityResponse> {
        let mut rpc = self.create_rpc().await?;
        rpc.call_raw("lsps2-policy-getchannelcapacity", params)
            .await
            .map_err(anyhow::Error::new)
            .with_context(|| "calling lsps2-policy-getchannelcapacity")
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
