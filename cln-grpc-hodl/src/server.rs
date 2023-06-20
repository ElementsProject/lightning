use crate::pb::hodl_server::Hodl;
use crate::short_channel_id_to_string;
use crate::{
    datastore_new_state, datastore_update_state_forced, listdatastore_htlc_expiry,
    listdatastore_state, pb, Hodlstate,
};
use anyhow::Result;
use cln_rpc::model::{
    requests, ListinvoicesInvoicesStatus, ListinvoicesRequest, ListpeerchannelsRequest,
};
use cln_rpc::primitives::{Amount, Routehint, Routehop, ShortChannelId};
use cln_rpc::{ClnRpc, Request, Response};
use lightning_invoice::{Invoice, InvoiceDescription, SignedRawInvoice};
use log::{debug, trace};
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::str::FromStr;
use std::time::Duration;
use tokio::time::{self, Instant};
use tonic::{Code, Status};

#[derive(Clone)]
pub struct Server {
    rpc_path: PathBuf,
}

impl Server {
    pub async fn new(path: &Path) -> Result<Self> {
        Ok(Self {
            rpc_path: path.to_path_buf(),
        })
    }
}

#[tonic::async_trait]
impl Hodl for Server {
    async fn hodl_invoice(
        &self,
        request: tonic::Request<pb::InvoiceRequest>,
    ) -> Result<tonic::Response<pb::InvoiceResponse>, tonic::Status> {
        let req = request.into_inner();
        let req: requests::InvoiceRequest = req.into();
        debug!("Client asked for hodlinvoice");
        trace!("hodlinvoice request: {:?}", req);
        let mut rpc = ClnRpc::new(&self.rpc_path)
            .await
            .map_err(|e| Status::new(Code::Internal, e.to_string()))?;
        let result = rpc.call(Request::Invoice(req)).await.map_err(|e| {
            Status::new(
                Code::Unknown,
                format!("Error calling method Invoice: {:?}", e),
            )
        })?;
        match result {
            Response::Invoice(r) => {
                trace!("Invoice response: {:?}", r);
                match datastore_new_state(
                    &self.rpc_path,
                    r.payment_hash.to_string(),
                    Hodlstate::Open.to_string(),
                )
                .await
                {
                    Ok(_o) => Ok(tonic::Response::new(r.into())),
                    Err(e) => Err(Status::new(
                        Code::Internal,
                        format!(
                            "Unexpected result {:?} to method call datastore_new_state",
                            e
                        ),
                    )),
                }
            }
            r => Err(Status::new(
                Code::Internal,
                format!("Unexpected result {:?} to method call Invoice", r),
            )),
        }
    }

    async fn hodl_invoice_settle(
        &self,
        request: tonic::Request<pb::HodlInvoiceSettleRequest>,
    ) -> Result<tonic::Response<pb::HodlInvoiceSettleResponse>, tonic::Status> {
        let req = request.into_inner();
        let req: pb::HodlInvoiceSettleRequest = req.into();
        debug!("Client asked for hodlinvoicesettle");
        trace!("hodlinvoicesettle request: {:?}", req);
        let pay_hash = hex::encode(req.payment_hash.clone());
        let data = match listdatastore_state(&self.rpc_path, pay_hash.clone()).await {
            Ok(store) => store,
            Err(e) => {
                return Err(Status::new(
                    Code::Internal,
                    format!(
                        "Unexpected result {:?} to method call listdatastore_state",
                        e
                    ),
                ))
            }
        };

        let hodlstate = match Hodlstate::from_str(&data.string.unwrap()) {
            Ok(hs) => hs,
            Err(e) => {
                return Err(Status::new(
                    Code::Internal,
                    format!(
                        "Unexpected result {:?} to method call Hodlstate::from_str",
                        e
                    ),
                ))
            }
        };

        if hodlstate.is_valid_transition(&Hodlstate::Settled) {
            let result = datastore_update_state_forced(
                &self.rpc_path,
                pay_hash.clone(),
                Hodlstate::Settled.to_string(),
            )
            .await;
            match result {
                Ok(_r) => Ok(tonic::Response::new(pb::HodlInvoiceSettleResponse {
                    state: Hodlstate::Settled.as_i32(),
                })),
                Err(e) => Err(Status::new(
                    Code::Internal,
                    format!(
                        "Unexpected result {:?} to method call datastore_update_state_forced",
                        e
                    ),
                )),
            }
        } else {
            Err(Status::new(
                Code::Internal,
                format!(
                    "Hodl-Invoice is in wrong state: `{}`. Payment_hash: {}",
                    hodlstate.to_string(),
                    pay_hash
                ),
            ))
        }
    }

    async fn hodl_invoice_cancel(
        &self,
        request: tonic::Request<pb::HodlInvoiceCancelRequest>,
    ) -> Result<tonic::Response<pb::HodlInvoiceCancelResponse>, tonic::Status> {
        let req = request.into_inner();
        let req: pb::HodlInvoiceCancelRequest = req.into();
        debug!("Client asked for hodlinvoiceCancel");
        trace!("hodlinvoiceCancel request: {:?}", req);
        let pay_hash = hex::encode(req.payment_hash.clone());
        let data = match listdatastore_state(&self.rpc_path, pay_hash.clone()).await {
            Ok(st) => st,
            Err(e) => {
                return Err(Status::new(
                    Code::Internal,
                    format!(
                        "Unexpected result {:?} to method call listdatastore_state",
                        e
                    ),
                ))
            }
        };

        let hodlstate = match Hodlstate::from_str(&data.string.unwrap()) {
            Ok(hs) => hs,
            Err(e) => {
                return Err(Status::new(
                    Code::Internal,
                    format!(
                        "Unexpected result {:?} to method call Hodlstate::from_str",
                        e
                    ),
                ))
            }
        };

        if hodlstate.is_valid_transition(&Hodlstate::Canceled) {
            let result = datastore_update_state_forced(
                &self.rpc_path,
                pay_hash.clone(),
                Hodlstate::Canceled.to_string(),
            )
            .await;
            match result {
                Ok(_r) => Ok(tonic::Response::new(pb::HodlInvoiceCancelResponse {
                    state: Hodlstate::Canceled.as_i32(),
                })),
                Err(e) => Err(Status::new(
                    Code::Internal,
                    format!(
                        "Unexpected result {:?} to method call datastore_update_state_forced",
                        e
                    ),
                )),
            }
        } else {
            Err(Status::new(
                Code::Internal,
                format!(
                    "Hodl-Invoice is in wrong state: `{}`. Payment_hash: {}",
                    hodlstate.to_string(),
                    pay_hash
                ),
            ))
        }
    }

    async fn hodl_invoice_lookup(
        &self,
        request: tonic::Request<pb::HodlInvoiceLookupRequest>,
    ) -> Result<tonic::Response<pb::HodlInvoiceLookupResponse>, tonic::Status> {
        let req = request.into_inner();
        let req: pb::HodlInvoiceLookupRequest = req.into();
        debug!("Client asked for hodlinvoiceLookup");
        trace!("hodlinvoiceLookup request: {:?}", req);
        let mut rpc = ClnRpc::new(&self.rpc_path)
            .await
            .map_err(|e| Status::new(Code::Internal, e.to_string()))?;
        let pay_hash = hex::encode(req.payment_hash.clone());
        let data = match listdatastore_state(&self.rpc_path, pay_hash.clone()).await {
            Ok(st) => st,
            Err(e) => {
                return Err(Status::new(
                    Code::Internal,
                    format!(
                        "Unexpected result {:?} to method call listdatastore_state",
                        e
                    ),
                ))
            }
        };

        let hodlstate = match Hodlstate::from_str(&data.string.unwrap()) {
            Ok(hs) => hs,
            Err(e) => {
                return Err(Status::new(
                    Code::Internal,
                    format!(
                        "Unexpected result {:?} to method call Hodlstate::from_str",
                        e
                    ),
                ))
            }
        };

        let mut htlc_expiry = None;
        match hodlstate {
            Hodlstate::Open => (),
            Hodlstate::Accepted => {
                htlc_expiry =
                    match listdatastore_htlc_expiry(&self.rpc_path, pay_hash.clone()).await {
                        Ok(cltv) => Some(cltv),
                        Err(e) => {
                            return Err(Status::new(
                                Code::Internal,
                                format!(
                                "Unexpected result {:?} to method call listdatastore_htlc_expiry",
                                e
                            ),
                            ))
                        }
                    }
            }
            Hodlstate::Canceled => {
                let now = Instant::now();
                loop {
                    let mut all_cancelled = true;
                    let channels_response = rpc.call(Request::ListPeerChannels(ListpeerchannelsRequest{
                        id: None,
                    })).await.map_err(|e| {
                        Status::new(
                            Code::Unknown,
                            format!(
                                "Error calling method ListPeerChannels in hodl_invoice_lookup: {:?}",
                                e
                            ),
                        )
                    })?;

                    let channels = match channels_response {
                        Response::ListPeerChannels(c) => match c.channels {
                            Some(chans) => chans,
                            None => break,
                        },
                        r => {
                            return Err(Status::new(
                                Code::Internal,
                                format!(
                                    "Unexpected result {:?} to method call ListPeerChannels",
                                    r
                                ),
                            ))
                        }
                    };

                    for chan in channels {
                        if let Some(htlcs) = chan.htlcs {
                            for htlc in htlcs {
                                if let Some(ph) = htlc.payment_hash {
                                    if ph.to_string() == pay_hash {
                                        all_cancelled = false;
                                    }
                                }
                            }
                        }
                    }

                    if all_cancelled {
                        break;
                    }

                    if now.elapsed().as_secs() > 20 {
                        return Err(Status::new(
                            Code::Internal,
                            format!("hodl_invoice_lookup: Timed out before cancellation could be confirmed"),
                        ));
                    }

                    time::sleep(Duration::from_secs(1)).await
                }
            }
            Hodlstate::Settled => {
                let now = Instant::now();
                loop {
                    let invoice = rpc
                        .call(Request::ListInvoices(ListinvoicesRequest {
                            label: None,
                            invstring: None,
                            payment_hash: Some(pay_hash.clone()),
                            offer_id: None,
                        }))
                        .await
                        .map_err(|e| {
                            Status::new(
                                Code::Unknown,
                                format!(
                                "Error calling method ListInvoices in hodl_invoice_lookup: {:?}",
                                e
                            ),
                            )
                        })?;

                    if let Response::ListInvoices(i) = invoice {
                        if let Some(inv) = i.invoices.first() {
                            match inv.status{
                                    ListinvoicesInvoicesStatus::PAID => {
                                        break;
                                    },
                                    ListinvoicesInvoicesStatus::EXPIRED => {
                                        return Err(Status::new(
                                            Code::Internal,
                                            format!("hodl_invoice_lookup: Invoice expired while trying to settle!"),
                                        ))
                                    },
                                    _ => (),
                               }
                        }
                    }

                    if now.elapsed().as_secs() > 20 {
                        return Err(Status::new(
                            Code::Internal,
                            format!("hodl_invoice_lookup: Timed out before settlement could be confirmed"),
                        ));
                    }

                    time::sleep(Duration::from_secs(1)).await
                }
            }
        }
        Ok(tonic::Response::new(pb::HodlInvoiceLookupResponse {
            state: hodlstate.as_i32(),
            htlc_expiry,
        }))
    }

    async fn decode_bolt11(
        &self,
        request: tonic::Request<pb::DecodeBolt11Request>,
    ) -> Result<tonic::Response<pb::DecodeBolt11Response>, tonic::Status> {
        let req = request.into_inner();
        let req: pb::DecodeBolt11Request = req.into();
        debug!("Client asked for decode_bolt11");
        trace!("decode_bolt11 request: {:?}", req);
        let raw_invoice = match SignedRawInvoice::from_str(&req.bolt11).map_err(|e| e.to_string()) {
            Ok(b11) => b11,
            Err(e) => {
                return Err(Status::new(
                    Code::Internal,
                    format!(
                        "Invalid bolt11 string in method call decode_bolt11: {:?}",
                        e
                    ),
                ))
            }
        };
        let invoice = match Invoice::from_signed(raw_invoice) {
            Ok(iv) => iv,
            Err(e) => {
                return Err(Status::new(
                    Code::Internal,
                    format!("Invalid invoice in method call decode_bolt11: {:?}", e),
                ))
            }
        };
        let amount_msat = match invoice.amount_milli_satoshis() {
            Some(amt) => Some(Amount::from_msat(amt).into()),
            None => None,
        };
        let mut description = None;
        let mut description_hash = None;
        match invoice.description() {
            InvoiceDescription::Direct(desc) => {
                description = Some(desc.clone().into_inner());
            }
            InvoiceDescription::Hash(hash) => {
                description_hash = Some(hash.0.to_vec());
            }
        }

        let mut pb_route_hints = Vec::new();

        for hint in &invoice.route_hints() {
            let mut scid_vec = HashMap::new();
            for hop in &hint.0 {
                match ShortChannelId::from_str(&short_channel_id_to_string(hop.short_channel_id)) {
                    Ok(o) => scid_vec.insert(hop.short_channel_id, o),
                    Err(e) => {
                        return Err(Status::new(
                            Code::InvalidArgument,
                            format!("Error parsing short channel id: {:?}", e),
                        ))
                    }
                };
            }

            let pb_route_hops = hint
                .0
                .iter()
                .map(|hop| {
                    let scid = scid_vec.get(&hop.short_channel_id).unwrap();
                    Routehop {
                        id: hop.src_node_id,
                        scid: *scid,
                        feebase: Amount::from_msat(hop.fees.base_msat as u64),
                        feeprop: hop.fees.proportional_millionths,
                        expirydelta: hop.cltv_expiry_delta,
                    }
                })
                .collect();

            pb_route_hints.push(
                Routehint {
                    hops: pb_route_hops,
                }
                .into(),
            );
        }

        Ok(tonic::Response::new(pb::DecodeBolt11Response {
            description,
            description_hash,
            payment_hash: invoice.payment_hash().to_vec(),
            expiry: invoice.expiry_time().as_secs(),
            amount_msat,
            route_hints: Some(pb::RoutehintList {
                hints: pb_route_hints,
            }),
            timestamp: invoice.duration_since_epoch().as_secs() as u32,
        }))
    }
}
