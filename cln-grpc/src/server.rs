use crate::pb::node_server::Node;
use crate::pb;
use cln_rpc::{Request, Response, ClnRpc};
use anyhow::Result;
use std::path::{Path, PathBuf};
use cln_rpc::model::requests;
use log::{debug, trace};
use tonic::{Code, Status};

#[derive(Clone)]
pub struct Server
{
    rpc_path: PathBuf,
}

impl Server
{
    pub async fn new(path: &Path) -> Result<Self>
    {
        Ok(Self {
            rpc_path: path.to_path_buf(),
        })
    }
}

#[tonic::async_trait]
impl Node for Server
{
async fn getinfo(
    &self,
    request: tonic::Request<pb::GetinfoRequest>,
) -> Result<tonic::Response<pb::GetinfoResponse>, tonic::Status> {
    let req = request.into_inner();
    let req: requests::GetinfoRequest = req.into();
    debug!("Client asked for getinfo");
    trace!("getinfo request: {:?}", req);
    let mut rpc = ClnRpc::new(&self.rpc_path)
        .await
        .map_err(|e| Status::new(Code::Internal, e.to_string()))?;
    let result = rpc.call(Request::Getinfo(req))
        .await
        .map_err(|e| Status::new(
           Code::Unknown,
           format!("Error calling method Getinfo: {:?}", e)))?;
    match result {
        Response::Getinfo(r) => {
           trace!("getinfo response: {:?}", r);
           Ok(tonic::Response::new(r.into()))
        },
        r => Err(Status::new(
            Code::Internal,
            format!(
                "Unexpected result {:?} to method call Getinfo",
                r
            )
        )),
    }

}

async fn list_peers(
    &self,
    request: tonic::Request<pb::ListpeersRequest>,
) -> Result<tonic::Response<pb::ListpeersResponse>, tonic::Status> {
    let req = request.into_inner();
    let req: requests::ListpeersRequest = req.into();
    debug!("Client asked for list_peers");
    trace!("list_peers request: {:?}", req);
    let mut rpc = ClnRpc::new(&self.rpc_path)
        .await
        .map_err(|e| Status::new(Code::Internal, e.to_string()))?;
    let result = rpc.call(Request::ListPeers(req))
        .await
        .map_err(|e| Status::new(
           Code::Unknown,
           format!("Error calling method ListPeers: {:?}", e)))?;
    match result {
        Response::ListPeers(r) => {
           trace!("list_peers response: {:?}", r);
           Ok(tonic::Response::new(r.into()))
        },
        r => Err(Status::new(
            Code::Internal,
            format!(
                "Unexpected result {:?} to method call ListPeers",
                r
            )
        )),
    }

}

async fn list_funds(
    &self,
    request: tonic::Request<pb::ListfundsRequest>,
) -> Result<tonic::Response<pb::ListfundsResponse>, tonic::Status> {
    let req = request.into_inner();
    let req: requests::ListfundsRequest = req.into();
    debug!("Client asked for list_funds");
    trace!("list_funds request: {:?}", req);
    let mut rpc = ClnRpc::new(&self.rpc_path)
        .await
        .map_err(|e| Status::new(Code::Internal, e.to_string()))?;
    let result = rpc.call(Request::ListFunds(req))
        .await
        .map_err(|e| Status::new(
           Code::Unknown,
           format!("Error calling method ListFunds: {:?}", e)))?;
    match result {
        Response::ListFunds(r) => {
           trace!("list_funds response: {:?}", r);
           Ok(tonic::Response::new(r.into()))
        },
        r => Err(Status::new(
            Code::Internal,
            format!(
                "Unexpected result {:?} to method call ListFunds",
                r
            )
        )),
    }

}

async fn send_pay(
    &self,
    request: tonic::Request<pb::SendpayRequest>,
) -> Result<tonic::Response<pb::SendpayResponse>, tonic::Status> {
    let req = request.into_inner();
    let req: requests::SendpayRequest = req.into();
    debug!("Client asked for send_pay");
    trace!("send_pay request: {:?}", req);
    let mut rpc = ClnRpc::new(&self.rpc_path)
        .await
        .map_err(|e| Status::new(Code::Internal, e.to_string()))?;
    let result = rpc.call(Request::SendPay(req))
        .await
        .map_err(|e| Status::new(
           Code::Unknown,
           format!("Error calling method SendPay: {:?}", e)))?;
    match result {
        Response::SendPay(r) => {
           trace!("send_pay response: {:?}", r);
           Ok(tonic::Response::new(r.into()))
        },
        r => Err(Status::new(
            Code::Internal,
            format!(
                "Unexpected result {:?} to method call SendPay",
                r
            )
        )),
    }

}

async fn list_channels(
    &self,
    request: tonic::Request<pb::ListchannelsRequest>,
) -> Result<tonic::Response<pb::ListchannelsResponse>, tonic::Status> {
    let req = request.into_inner();
    let req: requests::ListchannelsRequest = req.into();
    debug!("Client asked for list_channels");
    trace!("list_channels request: {:?}", req);
    let mut rpc = ClnRpc::new(&self.rpc_path)
        .await
        .map_err(|e| Status::new(Code::Internal, e.to_string()))?;
    let result = rpc.call(Request::ListChannels(req))
        .await
        .map_err(|e| Status::new(
           Code::Unknown,
           format!("Error calling method ListChannels: {:?}", e)))?;
    match result {
        Response::ListChannels(r) => {
           trace!("list_channels response: {:?}", r);
           Ok(tonic::Response::new(r.into()))
        },
        r => Err(Status::new(
            Code::Internal,
            format!(
                "Unexpected result {:?} to method call ListChannels",
                r
            )
        )),
    }

}

async fn add_gossip(
    &self,
    request: tonic::Request<pb::AddgossipRequest>,
) -> Result<tonic::Response<pb::AddgossipResponse>, tonic::Status> {
    let req = request.into_inner();
    let req: requests::AddgossipRequest = req.into();
    debug!("Client asked for add_gossip");
    trace!("add_gossip request: {:?}", req);
    let mut rpc = ClnRpc::new(&self.rpc_path)
        .await
        .map_err(|e| Status::new(Code::Internal, e.to_string()))?;
    let result = rpc.call(Request::AddGossip(req))
        .await
        .map_err(|e| Status::new(
           Code::Unknown,
           format!("Error calling method AddGossip: {:?}", e)))?;
    match result {
        Response::AddGossip(r) => {
           trace!("add_gossip response: {:?}", r);
           Ok(tonic::Response::new(r.into()))
        },
        r => Err(Status::new(
            Code::Internal,
            format!(
                "Unexpected result {:?} to method call AddGossip",
                r
            )
        )),
    }

}

async fn auto_clean_invoice(
    &self,
    request: tonic::Request<pb::AutocleaninvoiceRequest>,
) -> Result<tonic::Response<pb::AutocleaninvoiceResponse>, tonic::Status> {
    let req = request.into_inner();
    let req: requests::AutocleaninvoiceRequest = req.into();
    debug!("Client asked for auto_clean_invoice");
    trace!("auto_clean_invoice request: {:?}", req);
    let mut rpc = ClnRpc::new(&self.rpc_path)
        .await
        .map_err(|e| Status::new(Code::Internal, e.to_string()))?;
    let result = rpc.call(Request::AutoCleanInvoice(req))
        .await
        .map_err(|e| Status::new(
           Code::Unknown,
           format!("Error calling method AutoCleanInvoice: {:?}", e)))?;
    match result {
        Response::AutoCleanInvoice(r) => {
           trace!("auto_clean_invoice response: {:?}", r);
           Ok(tonic::Response::new(r.into()))
        },
        r => Err(Status::new(
            Code::Internal,
            format!(
                "Unexpected result {:?} to method call AutoCleanInvoice",
                r
            )
        )),
    }

}

async fn check_message(
    &self,
    request: tonic::Request<pb::CheckmessageRequest>,
) -> Result<tonic::Response<pb::CheckmessageResponse>, tonic::Status> {
    let req = request.into_inner();
    let req: requests::CheckmessageRequest = req.into();
    debug!("Client asked for check_message");
    trace!("check_message request: {:?}", req);
    let mut rpc = ClnRpc::new(&self.rpc_path)
        .await
        .map_err(|e| Status::new(Code::Internal, e.to_string()))?;
    let result = rpc.call(Request::CheckMessage(req))
        .await
        .map_err(|e| Status::new(
           Code::Unknown,
           format!("Error calling method CheckMessage: {:?}", e)))?;
    match result {
        Response::CheckMessage(r) => {
           trace!("check_message response: {:?}", r);
           Ok(tonic::Response::new(r.into()))
        },
        r => Err(Status::new(
            Code::Internal,
            format!(
                "Unexpected result {:?} to method call CheckMessage",
                r
            )
        )),
    }

}

async fn close(
    &self,
    request: tonic::Request<pb::CloseRequest>,
) -> Result<tonic::Response<pb::CloseResponse>, tonic::Status> {
    let req = request.into_inner();
    let req: requests::CloseRequest = req.into();
    debug!("Client asked for close");
    trace!("close request: {:?}", req);
    let mut rpc = ClnRpc::new(&self.rpc_path)
        .await
        .map_err(|e| Status::new(Code::Internal, e.to_string()))?;
    let result = rpc.call(Request::Close(req))
        .await
        .map_err(|e| Status::new(
           Code::Unknown,
           format!("Error calling method Close: {:?}", e)))?;
    match result {
        Response::Close(r) => {
           trace!("close response: {:?}", r);
           Ok(tonic::Response::new(r.into()))
        },
        r => Err(Status::new(
            Code::Internal,
            format!(
                "Unexpected result {:?} to method call Close",
                r
            )
        )),
    }

}

async fn connect_peer(
    &self,
    request: tonic::Request<pb::ConnectRequest>,
) -> Result<tonic::Response<pb::ConnectResponse>, tonic::Status> {
    let req = request.into_inner();
    let req: requests::ConnectRequest = req.into();
    debug!("Client asked for connect_peer");
    trace!("connect_peer request: {:?}", req);
    let mut rpc = ClnRpc::new(&self.rpc_path)
        .await
        .map_err(|e| Status::new(Code::Internal, e.to_string()))?;
    let result = rpc.call(Request::Connect(req))
        .await
        .map_err(|e| Status::new(
           Code::Unknown,
           format!("Error calling method Connect: {:?}", e)))?;
    match result {
        Response::Connect(r) => {
           trace!("connect_peer response: {:?}", r);
           Ok(tonic::Response::new(r.into()))
        },
        r => Err(Status::new(
            Code::Internal,
            format!(
                "Unexpected result {:?} to method call Connect",
                r
            )
        )),
    }

}

async fn create_invoice(
    &self,
    request: tonic::Request<pb::CreateinvoiceRequest>,
) -> Result<tonic::Response<pb::CreateinvoiceResponse>, tonic::Status> {
    let req = request.into_inner();
    let req: requests::CreateinvoiceRequest = req.into();
    debug!("Client asked for create_invoice");
    trace!("create_invoice request: {:?}", req);
    let mut rpc = ClnRpc::new(&self.rpc_path)
        .await
        .map_err(|e| Status::new(Code::Internal, e.to_string()))?;
    let result = rpc.call(Request::CreateInvoice(req))
        .await
        .map_err(|e| Status::new(
           Code::Unknown,
           format!("Error calling method CreateInvoice: {:?}", e)))?;
    match result {
        Response::CreateInvoice(r) => {
           trace!("create_invoice response: {:?}", r);
           Ok(tonic::Response::new(r.into()))
        },
        r => Err(Status::new(
            Code::Internal,
            format!(
                "Unexpected result {:?} to method call CreateInvoice",
                r
            )
        )),
    }

}

async fn datastore(
    &self,
    request: tonic::Request<pb::DatastoreRequest>,
) -> Result<tonic::Response<pb::DatastoreResponse>, tonic::Status> {
    let req = request.into_inner();
    let req: requests::DatastoreRequest = req.into();
    debug!("Client asked for datastore");
    trace!("datastore request: {:?}", req);
    let mut rpc = ClnRpc::new(&self.rpc_path)
        .await
        .map_err(|e| Status::new(Code::Internal, e.to_string()))?;
    let result = rpc.call(Request::Datastore(req))
        .await
        .map_err(|e| Status::new(
           Code::Unknown,
           format!("Error calling method Datastore: {:?}", e)))?;
    match result {
        Response::Datastore(r) => {
           trace!("datastore response: {:?}", r);
           Ok(tonic::Response::new(r.into()))
        },
        r => Err(Status::new(
            Code::Internal,
            format!(
                "Unexpected result {:?} to method call Datastore",
                r
            )
        )),
    }

}

async fn datastore_usage(
    &self,
    request: tonic::Request<pb::DatastoreusageRequest>,
) -> Result<tonic::Response<pb::DatastoreusageResponse>, tonic::Status> {
    let req = request.into_inner();
    let req: requests::DatastoreusageRequest = req.into();
    debug!("Client asked for datastore_usage");
    trace!("datastore_usage request: {:?}", req);
    let mut rpc = ClnRpc::new(&self.rpc_path)
        .await
        .map_err(|e| Status::new(Code::Internal, e.to_string()))?;
    let result = rpc.call(Request::DatastoreUsage(req))
        .await
        .map_err(|e| Status::new(
           Code::Unknown,
           format!("Error calling method DatastoreUsage: {:?}", e)))?;
    match result {
        Response::DatastoreUsage(r) => {
           trace!("datastore_usage response: {:?}", r);
           Ok(tonic::Response::new(r.into()))
        },
        r => Err(Status::new(
            Code::Internal,
            format!(
                "Unexpected result {:?} to method call DatastoreUsage",
                r
            )
        )),
    }

}

async fn create_onion(
    &self,
    request: tonic::Request<pb::CreateonionRequest>,
) -> Result<tonic::Response<pb::CreateonionResponse>, tonic::Status> {
    let req = request.into_inner();
    let req: requests::CreateonionRequest = req.into();
    debug!("Client asked for create_onion");
    trace!("create_onion request: {:?}", req);
    let mut rpc = ClnRpc::new(&self.rpc_path)
        .await
        .map_err(|e| Status::new(Code::Internal, e.to_string()))?;
    let result = rpc.call(Request::CreateOnion(req))
        .await
        .map_err(|e| Status::new(
           Code::Unknown,
           format!("Error calling method CreateOnion: {:?}", e)))?;
    match result {
        Response::CreateOnion(r) => {
           trace!("create_onion response: {:?}", r);
           Ok(tonic::Response::new(r.into()))
        },
        r => Err(Status::new(
            Code::Internal,
            format!(
                "Unexpected result {:?} to method call CreateOnion",
                r
            )
        )),
    }

}

async fn del_datastore(
    &self,
    request: tonic::Request<pb::DeldatastoreRequest>,
) -> Result<tonic::Response<pb::DeldatastoreResponse>, tonic::Status> {
    let req = request.into_inner();
    let req: requests::DeldatastoreRequest = req.into();
    debug!("Client asked for del_datastore");
    trace!("del_datastore request: {:?}", req);
    let mut rpc = ClnRpc::new(&self.rpc_path)
        .await
        .map_err(|e| Status::new(Code::Internal, e.to_string()))?;
    let result = rpc.call(Request::DelDatastore(req))
        .await
        .map_err(|e| Status::new(
           Code::Unknown,
           format!("Error calling method DelDatastore: {:?}", e)))?;
    match result {
        Response::DelDatastore(r) => {
           trace!("del_datastore response: {:?}", r);
           Ok(tonic::Response::new(r.into()))
        },
        r => Err(Status::new(
            Code::Internal,
            format!(
                "Unexpected result {:?} to method call DelDatastore",
                r
            )
        )),
    }

}

async fn del_expired_invoice(
    &self,
    request: tonic::Request<pb::DelexpiredinvoiceRequest>,
) -> Result<tonic::Response<pb::DelexpiredinvoiceResponse>, tonic::Status> {
    let req = request.into_inner();
    let req: requests::DelexpiredinvoiceRequest = req.into();
    debug!("Client asked for del_expired_invoice");
    trace!("del_expired_invoice request: {:?}", req);
    let mut rpc = ClnRpc::new(&self.rpc_path)
        .await
        .map_err(|e| Status::new(Code::Internal, e.to_string()))?;
    let result = rpc.call(Request::DelExpiredInvoice(req))
        .await
        .map_err(|e| Status::new(
           Code::Unknown,
           format!("Error calling method DelExpiredInvoice: {:?}", e)))?;
    match result {
        Response::DelExpiredInvoice(r) => {
           trace!("del_expired_invoice response: {:?}", r);
           Ok(tonic::Response::new(r.into()))
        },
        r => Err(Status::new(
            Code::Internal,
            format!(
                "Unexpected result {:?} to method call DelExpiredInvoice",
                r
            )
        )),
    }

}

async fn del_invoice(
    &self,
    request: tonic::Request<pb::DelinvoiceRequest>,
) -> Result<tonic::Response<pb::DelinvoiceResponse>, tonic::Status> {
    let req = request.into_inner();
    let req: requests::DelinvoiceRequest = req.into();
    debug!("Client asked for del_invoice");
    trace!("del_invoice request: {:?}", req);
    let mut rpc = ClnRpc::new(&self.rpc_path)
        .await
        .map_err(|e| Status::new(Code::Internal, e.to_string()))?;
    let result = rpc.call(Request::DelInvoice(req))
        .await
        .map_err(|e| Status::new(
           Code::Unknown,
           format!("Error calling method DelInvoice: {:?}", e)))?;
    match result {
        Response::DelInvoice(r) => {
           trace!("del_invoice response: {:?}", r);
           Ok(tonic::Response::new(r.into()))
        },
        r => Err(Status::new(
            Code::Internal,
            format!(
                "Unexpected result {:?} to method call DelInvoice",
                r
            )
        )),
    }

}

async fn invoice(
    &self,
    request: tonic::Request<pb::InvoiceRequest>,
) -> Result<tonic::Response<pb::InvoiceResponse>, tonic::Status> {
    let req = request.into_inner();
    let req: requests::InvoiceRequest = req.into();
    debug!("Client asked for invoice");
    trace!("invoice request: {:?}", req);
    let mut rpc = ClnRpc::new(&self.rpc_path)
        .await
        .map_err(|e| Status::new(Code::Internal, e.to_string()))?;
    let result = rpc.call(Request::Invoice(req))
        .await
        .map_err(|e| Status::new(
           Code::Unknown,
           format!("Error calling method Invoice: {:?}", e)))?;
    match result {
        Response::Invoice(r) => {
           trace!("invoice response: {:?}", r);
           Ok(tonic::Response::new(r.into()))
        },
        r => Err(Status::new(
            Code::Internal,
            format!(
                "Unexpected result {:?} to method call Invoice",
                r
            )
        )),
    }

}

async fn list_datastore(
    &self,
    request: tonic::Request<pb::ListdatastoreRequest>,
) -> Result<tonic::Response<pb::ListdatastoreResponse>, tonic::Status> {
    let req = request.into_inner();
    let req: requests::ListdatastoreRequest = req.into();
    debug!("Client asked for list_datastore");
    trace!("list_datastore request: {:?}", req);
    let mut rpc = ClnRpc::new(&self.rpc_path)
        .await
        .map_err(|e| Status::new(Code::Internal, e.to_string()))?;
    let result = rpc.call(Request::ListDatastore(req))
        .await
        .map_err(|e| Status::new(
           Code::Unknown,
           format!("Error calling method ListDatastore: {:?}", e)))?;
    match result {
        Response::ListDatastore(r) => {
           trace!("list_datastore response: {:?}", r);
           Ok(tonic::Response::new(r.into()))
        },
        r => Err(Status::new(
            Code::Internal,
            format!(
                "Unexpected result {:?} to method call ListDatastore",
                r
            )
        )),
    }

}

async fn list_invoices(
    &self,
    request: tonic::Request<pb::ListinvoicesRequest>,
) -> Result<tonic::Response<pb::ListinvoicesResponse>, tonic::Status> {
    let req = request.into_inner();
    let req: requests::ListinvoicesRequest = req.into();
    debug!("Client asked for list_invoices");
    trace!("list_invoices request: {:?}", req);
    let mut rpc = ClnRpc::new(&self.rpc_path)
        .await
        .map_err(|e| Status::new(Code::Internal, e.to_string()))?;
    let result = rpc.call(Request::ListInvoices(req))
        .await
        .map_err(|e| Status::new(
           Code::Unknown,
           format!("Error calling method ListInvoices: {:?}", e)))?;
    match result {
        Response::ListInvoices(r) => {
           trace!("list_invoices response: {:?}", r);
           Ok(tonic::Response::new(r.into()))
        },
        r => Err(Status::new(
            Code::Internal,
            format!(
                "Unexpected result {:?} to method call ListInvoices",
                r
            )
        )),
    }

}

async fn send_onion(
    &self,
    request: tonic::Request<pb::SendonionRequest>,
) -> Result<tonic::Response<pb::SendonionResponse>, tonic::Status> {
    let req = request.into_inner();
    let req: requests::SendonionRequest = req.into();
    debug!("Client asked for send_onion");
    trace!("send_onion request: {:?}", req);
    let mut rpc = ClnRpc::new(&self.rpc_path)
        .await
        .map_err(|e| Status::new(Code::Internal, e.to_string()))?;
    let result = rpc.call(Request::SendOnion(req))
        .await
        .map_err(|e| Status::new(
           Code::Unknown,
           format!("Error calling method SendOnion: {:?}", e)))?;
    match result {
        Response::SendOnion(r) => {
           trace!("send_onion response: {:?}", r);
           Ok(tonic::Response::new(r.into()))
        },
        r => Err(Status::new(
            Code::Internal,
            format!(
                "Unexpected result {:?} to method call SendOnion",
                r
            )
        )),
    }

}

async fn list_send_pays(
    &self,
    request: tonic::Request<pb::ListsendpaysRequest>,
) -> Result<tonic::Response<pb::ListsendpaysResponse>, tonic::Status> {
    let req = request.into_inner();
    let req: requests::ListsendpaysRequest = req.into();
    debug!("Client asked for list_send_pays");
    trace!("list_send_pays request: {:?}", req);
    let mut rpc = ClnRpc::new(&self.rpc_path)
        .await
        .map_err(|e| Status::new(Code::Internal, e.to_string()))?;
    let result = rpc.call(Request::ListSendPays(req))
        .await
        .map_err(|e| Status::new(
           Code::Unknown,
           format!("Error calling method ListSendPays: {:?}", e)))?;
    match result {
        Response::ListSendPays(r) => {
           trace!("list_send_pays response: {:?}", r);
           Ok(tonic::Response::new(r.into()))
        },
        r => Err(Status::new(
            Code::Internal,
            format!(
                "Unexpected result {:?} to method call ListSendPays",
                r
            )
        )),
    }

}

async fn list_transactions(
    &self,
    request: tonic::Request<pb::ListtransactionsRequest>,
) -> Result<tonic::Response<pb::ListtransactionsResponse>, tonic::Status> {
    let req = request.into_inner();
    let req: requests::ListtransactionsRequest = req.into();
    debug!("Client asked for list_transactions");
    trace!("list_transactions request: {:?}", req);
    let mut rpc = ClnRpc::new(&self.rpc_path)
        .await
        .map_err(|e| Status::new(Code::Internal, e.to_string()))?;
    let result = rpc.call(Request::ListTransactions(req))
        .await
        .map_err(|e| Status::new(
           Code::Unknown,
           format!("Error calling method ListTransactions: {:?}", e)))?;
    match result {
        Response::ListTransactions(r) => {
           trace!("list_transactions response: {:?}", r);
           Ok(tonic::Response::new(r.into()))
        },
        r => Err(Status::new(
            Code::Internal,
            format!(
                "Unexpected result {:?} to method call ListTransactions",
                r
            )
        )),
    }

}

async fn pay(
    &self,
    request: tonic::Request<pb::PayRequest>,
) -> Result<tonic::Response<pb::PayResponse>, tonic::Status> {
    let req = request.into_inner();
    let req: requests::PayRequest = req.into();
    debug!("Client asked for pay");
    trace!("pay request: {:?}", req);
    let mut rpc = ClnRpc::new(&self.rpc_path)
        .await
        .map_err(|e| Status::new(Code::Internal, e.to_string()))?;
    let result = rpc.call(Request::Pay(req))
        .await
        .map_err(|e| Status::new(
           Code::Unknown,
           format!("Error calling method Pay: {:?}", e)))?;
    match result {
        Response::Pay(r) => {
           trace!("pay response: {:?}", r);
           Ok(tonic::Response::new(r.into()))
        },
        r => Err(Status::new(
            Code::Internal,
            format!(
                "Unexpected result {:?} to method call Pay",
                r
            )
        )),
    }

}

async fn list_nodes(
    &self,
    request: tonic::Request<pb::ListnodesRequest>,
) -> Result<tonic::Response<pb::ListnodesResponse>, tonic::Status> {
    let req = request.into_inner();
    let req: requests::ListnodesRequest = req.into();
    debug!("Client asked for list_nodes");
    trace!("list_nodes request: {:?}", req);
    let mut rpc = ClnRpc::new(&self.rpc_path)
        .await
        .map_err(|e| Status::new(Code::Internal, e.to_string()))?;
    let result = rpc.call(Request::ListNodes(req))
        .await
        .map_err(|e| Status::new(
           Code::Unknown,
           format!("Error calling method ListNodes: {:?}", e)))?;
    match result {
        Response::ListNodes(r) => {
           trace!("list_nodes response: {:?}", r);
           Ok(tonic::Response::new(r.into()))
        },
        r => Err(Status::new(
            Code::Internal,
            format!(
                "Unexpected result {:?} to method call ListNodes",
                r
            )
        )),
    }

}

async fn wait_any_invoice(
    &self,
    request: tonic::Request<pb::WaitanyinvoiceRequest>,
) -> Result<tonic::Response<pb::WaitanyinvoiceResponse>, tonic::Status> {
    let req = request.into_inner();
    let req: requests::WaitanyinvoiceRequest = req.into();
    debug!("Client asked for wait_any_invoice");
    trace!("wait_any_invoice request: {:?}", req);
    let mut rpc = ClnRpc::new(&self.rpc_path)
        .await
        .map_err(|e| Status::new(Code::Internal, e.to_string()))?;
    let result = rpc.call(Request::WaitAnyInvoice(req))
        .await
        .map_err(|e| Status::new(
           Code::Unknown,
           format!("Error calling method WaitAnyInvoice: {:?}", e)))?;
    match result {
        Response::WaitAnyInvoice(r) => {
           trace!("wait_any_invoice response: {:?}", r);
           Ok(tonic::Response::new(r.into()))
        },
        r => Err(Status::new(
            Code::Internal,
            format!(
                "Unexpected result {:?} to method call WaitAnyInvoice",
                r
            )
        )),
    }

}

async fn wait_invoice(
    &self,
    request: tonic::Request<pb::WaitinvoiceRequest>,
) -> Result<tonic::Response<pb::WaitinvoiceResponse>, tonic::Status> {
    let req = request.into_inner();
    let req: requests::WaitinvoiceRequest = req.into();
    debug!("Client asked for wait_invoice");
    trace!("wait_invoice request: {:?}", req);
    let mut rpc = ClnRpc::new(&self.rpc_path)
        .await
        .map_err(|e| Status::new(Code::Internal, e.to_string()))?;
    let result = rpc.call(Request::WaitInvoice(req))
        .await
        .map_err(|e| Status::new(
           Code::Unknown,
           format!("Error calling method WaitInvoice: {:?}", e)))?;
    match result {
        Response::WaitInvoice(r) => {
           trace!("wait_invoice response: {:?}", r);
           Ok(tonic::Response::new(r.into()))
        },
        r => Err(Status::new(
            Code::Internal,
            format!(
                "Unexpected result {:?} to method call WaitInvoice",
                r
            )
        )),
    }

}

async fn wait_send_pay(
    &self,
    request: tonic::Request<pb::WaitsendpayRequest>,
) -> Result<tonic::Response<pb::WaitsendpayResponse>, tonic::Status> {
    let req = request.into_inner();
    let req: requests::WaitsendpayRequest = req.into();
    debug!("Client asked for wait_send_pay");
    trace!("wait_send_pay request: {:?}", req);
    let mut rpc = ClnRpc::new(&self.rpc_path)
        .await
        .map_err(|e| Status::new(Code::Internal, e.to_string()))?;
    let result = rpc.call(Request::WaitSendPay(req))
        .await
        .map_err(|e| Status::new(
           Code::Unknown,
           format!("Error calling method WaitSendPay: {:?}", e)))?;
    match result {
        Response::WaitSendPay(r) => {
           trace!("wait_send_pay response: {:?}", r);
           Ok(tonic::Response::new(r.into()))
        },
        r => Err(Status::new(
            Code::Internal,
            format!(
                "Unexpected result {:?} to method call WaitSendPay",
                r
            )
        )),
    }

}

async fn new_addr(
    &self,
    request: tonic::Request<pb::NewaddrRequest>,
) -> Result<tonic::Response<pb::NewaddrResponse>, tonic::Status> {
    let req = request.into_inner();
    let req: requests::NewaddrRequest = req.into();
    debug!("Client asked for new_addr");
    trace!("new_addr request: {:?}", req);
    let mut rpc = ClnRpc::new(&self.rpc_path)
        .await
        .map_err(|e| Status::new(Code::Internal, e.to_string()))?;
    let result = rpc.call(Request::NewAddr(req))
        .await
        .map_err(|e| Status::new(
           Code::Unknown,
           format!("Error calling method NewAddr: {:?}", e)))?;
    match result {
        Response::NewAddr(r) => {
           trace!("new_addr response: {:?}", r);
           Ok(tonic::Response::new(r.into()))
        },
        r => Err(Status::new(
            Code::Internal,
            format!(
                "Unexpected result {:?} to method call NewAddr",
                r
            )
        )),
    }

}

async fn withdraw(
    &self,
    request: tonic::Request<pb::WithdrawRequest>,
) -> Result<tonic::Response<pb::WithdrawResponse>, tonic::Status> {
    let req = request.into_inner();
    let req: requests::WithdrawRequest = req.into();
    debug!("Client asked for withdraw");
    trace!("withdraw request: {:?}", req);
    let mut rpc = ClnRpc::new(&self.rpc_path)
        .await
        .map_err(|e| Status::new(Code::Internal, e.to_string()))?;
    let result = rpc.call(Request::Withdraw(req))
        .await
        .map_err(|e| Status::new(
           Code::Unknown,
           format!("Error calling method Withdraw: {:?}", e)))?;
    match result {
        Response::Withdraw(r) => {
           trace!("withdraw response: {:?}", r);
           Ok(tonic::Response::new(r.into()))
        },
        r => Err(Status::new(
            Code::Internal,
            format!(
                "Unexpected result {:?} to method call Withdraw",
                r
            )
        )),
    }

}

async fn key_send(
    &self,
    request: tonic::Request<pb::KeysendRequest>,
) -> Result<tonic::Response<pb::KeysendResponse>, tonic::Status> {
    let req = request.into_inner();
    let req: requests::KeysendRequest = req.into();
    debug!("Client asked for key_send");
    trace!("key_send request: {:?}", req);
    let mut rpc = ClnRpc::new(&self.rpc_path)
        .await
        .map_err(|e| Status::new(Code::Internal, e.to_string()))?;
    let result = rpc.call(Request::KeySend(req))
        .await
        .map_err(|e| Status::new(
           Code::Unknown,
           format!("Error calling method KeySend: {:?}", e)))?;
    match result {
        Response::KeySend(r) => {
           trace!("key_send response: {:?}", r);
           Ok(tonic::Response::new(r.into()))
        },
        r => Err(Status::new(
            Code::Internal,
            format!(
                "Unexpected result {:?} to method call KeySend",
                r
            )
        )),
    }

}

async fn fund_psbt(
    &self,
    request: tonic::Request<pb::FundpsbtRequest>,
) -> Result<tonic::Response<pb::FundpsbtResponse>, tonic::Status> {
    let req = request.into_inner();
    let req: requests::FundpsbtRequest = req.into();
    debug!("Client asked for fund_psbt");
    trace!("fund_psbt request: {:?}", req);
    let mut rpc = ClnRpc::new(&self.rpc_path)
        .await
        .map_err(|e| Status::new(Code::Internal, e.to_string()))?;
    let result = rpc.call(Request::FundPsbt(req))
        .await
        .map_err(|e| Status::new(
           Code::Unknown,
           format!("Error calling method FundPsbt: {:?}", e)))?;
    match result {
        Response::FundPsbt(r) => {
           trace!("fund_psbt response: {:?}", r);
           Ok(tonic::Response::new(r.into()))
        },
        r => Err(Status::new(
            Code::Internal,
            format!(
                "Unexpected result {:?} to method call FundPsbt",
                r
            )
        )),
    }

}

async fn send_psbt(
    &self,
    request: tonic::Request<pb::SendpsbtRequest>,
) -> Result<tonic::Response<pb::SendpsbtResponse>, tonic::Status> {
    let req = request.into_inner();
    let req: requests::SendpsbtRequest = req.into();
    debug!("Client asked for send_psbt");
    trace!("send_psbt request: {:?}", req);
    let mut rpc = ClnRpc::new(&self.rpc_path)
        .await
        .map_err(|e| Status::new(Code::Internal, e.to_string()))?;
    let result = rpc.call(Request::SendPsbt(req))
        .await
        .map_err(|e| Status::new(
           Code::Unknown,
           format!("Error calling method SendPsbt: {:?}", e)))?;
    match result {
        Response::SendPsbt(r) => {
           trace!("send_psbt response: {:?}", r);
           Ok(tonic::Response::new(r.into()))
        },
        r => Err(Status::new(
            Code::Internal,
            format!(
                "Unexpected result {:?} to method call SendPsbt",
                r
            )
        )),
    }

}

async fn sign_psbt(
    &self,
    request: tonic::Request<pb::SignpsbtRequest>,
) -> Result<tonic::Response<pb::SignpsbtResponse>, tonic::Status> {
    let req = request.into_inner();
    let req: requests::SignpsbtRequest = req.into();
    debug!("Client asked for sign_psbt");
    trace!("sign_psbt request: {:?}", req);
    let mut rpc = ClnRpc::new(&self.rpc_path)
        .await
        .map_err(|e| Status::new(Code::Internal, e.to_string()))?;
    let result = rpc.call(Request::SignPsbt(req))
        .await
        .map_err(|e| Status::new(
           Code::Unknown,
           format!("Error calling method SignPsbt: {:?}", e)))?;
    match result {
        Response::SignPsbt(r) => {
           trace!("sign_psbt response: {:?}", r);
           Ok(tonic::Response::new(r.into()))
        },
        r => Err(Status::new(
            Code::Internal,
            format!(
                "Unexpected result {:?} to method call SignPsbt",
                r
            )
        )),
    }

}

async fn utxo_psbt(
    &self,
    request: tonic::Request<pb::UtxopsbtRequest>,
) -> Result<tonic::Response<pb::UtxopsbtResponse>, tonic::Status> {
    let req = request.into_inner();
    let req: requests::UtxopsbtRequest = req.into();
    debug!("Client asked for utxo_psbt");
    trace!("utxo_psbt request: {:?}", req);
    let mut rpc = ClnRpc::new(&self.rpc_path)
        .await
        .map_err(|e| Status::new(Code::Internal, e.to_string()))?;
    let result = rpc.call(Request::UtxoPsbt(req))
        .await
        .map_err(|e| Status::new(
           Code::Unknown,
           format!("Error calling method UtxoPsbt: {:?}", e)))?;
    match result {
        Response::UtxoPsbt(r) => {
           trace!("utxo_psbt response: {:?}", r);
           Ok(tonic::Response::new(r.into()))
        },
        r => Err(Status::new(
            Code::Internal,
            format!(
                "Unexpected result {:?} to method call UtxoPsbt",
                r
            )
        )),
    }

}

async fn tx_discard(
    &self,
    request: tonic::Request<pb::TxdiscardRequest>,
) -> Result<tonic::Response<pb::TxdiscardResponse>, tonic::Status> {
    let req = request.into_inner();
    let req: requests::TxdiscardRequest = req.into();
    debug!("Client asked for tx_discard");
    trace!("tx_discard request: {:?}", req);
    let mut rpc = ClnRpc::new(&self.rpc_path)
        .await
        .map_err(|e| Status::new(Code::Internal, e.to_string()))?;
    let result = rpc.call(Request::TxDiscard(req))
        .await
        .map_err(|e| Status::new(
           Code::Unknown,
           format!("Error calling method TxDiscard: {:?}", e)))?;
    match result {
        Response::TxDiscard(r) => {
           trace!("tx_discard response: {:?}", r);
           Ok(tonic::Response::new(r.into()))
        },
        r => Err(Status::new(
            Code::Internal,
            format!(
                "Unexpected result {:?} to method call TxDiscard",
                r
            )
        )),
    }

}

async fn tx_prepare(
    &self,
    request: tonic::Request<pb::TxprepareRequest>,
) -> Result<tonic::Response<pb::TxprepareResponse>, tonic::Status> {
    let req = request.into_inner();
    let req: requests::TxprepareRequest = req.into();
    debug!("Client asked for tx_prepare");
    trace!("tx_prepare request: {:?}", req);
    let mut rpc = ClnRpc::new(&self.rpc_path)
        .await
        .map_err(|e| Status::new(Code::Internal, e.to_string()))?;
    let result = rpc.call(Request::TxPrepare(req))
        .await
        .map_err(|e| Status::new(
           Code::Unknown,
           format!("Error calling method TxPrepare: {:?}", e)))?;
    match result {
        Response::TxPrepare(r) => {
           trace!("tx_prepare response: {:?}", r);
           Ok(tonic::Response::new(r.into()))
        },
        r => Err(Status::new(
            Code::Internal,
            format!(
                "Unexpected result {:?} to method call TxPrepare",
                r
            )
        )),
    }

}

async fn tx_send(
    &self,
    request: tonic::Request<pb::TxsendRequest>,
) -> Result<tonic::Response<pb::TxsendResponse>, tonic::Status> {
    let req = request.into_inner();
    let req: requests::TxsendRequest = req.into();
    debug!("Client asked for tx_send");
    trace!("tx_send request: {:?}", req);
    let mut rpc = ClnRpc::new(&self.rpc_path)
        .await
        .map_err(|e| Status::new(Code::Internal, e.to_string()))?;
    let result = rpc.call(Request::TxSend(req))
        .await
        .map_err(|e| Status::new(
           Code::Unknown,
           format!("Error calling method TxSend: {:?}", e)))?;
    match result {
        Response::TxSend(r) => {
           trace!("tx_send response: {:?}", r);
           Ok(tonic::Response::new(r.into()))
        },
        r => Err(Status::new(
            Code::Internal,
            format!(
                "Unexpected result {:?} to method call TxSend",
                r
            )
        )),
    }

}

async fn list_peer_channels(
    &self,
    request: tonic::Request<pb::ListpeerchannelsRequest>,
) -> Result<tonic::Response<pb::ListpeerchannelsResponse>, tonic::Status> {
    let req = request.into_inner();
    let req: requests::ListpeerchannelsRequest = req.into();
    debug!("Client asked for list_peer_channels");
    trace!("list_peer_channels request: {:?}", req);
    let mut rpc = ClnRpc::new(&self.rpc_path)
        .await
        .map_err(|e| Status::new(Code::Internal, e.to_string()))?;
    let result = rpc.call(Request::ListPeerChannels(req))
        .await
        .map_err(|e| Status::new(
           Code::Unknown,
           format!("Error calling method ListPeerChannels: {:?}", e)))?;
    match result {
        Response::ListPeerChannels(r) => {
           trace!("list_peer_channels response: {:?}", r);
           Ok(tonic::Response::new(r.into()))
        },
        r => Err(Status::new(
            Code::Internal,
            format!(
                "Unexpected result {:?} to method call ListPeerChannels",
                r
            )
        )),
    }

}

async fn list_closed_channels(
    &self,
    request: tonic::Request<pb::ListclosedchannelsRequest>,
) -> Result<tonic::Response<pb::ListclosedchannelsResponse>, tonic::Status> {
    let req = request.into_inner();
    let req: requests::ListclosedchannelsRequest = req.into();
    debug!("Client asked for list_closed_channels");
    trace!("list_closed_channels request: {:?}", req);
    let mut rpc = ClnRpc::new(&self.rpc_path)
        .await
        .map_err(|e| Status::new(Code::Internal, e.to_string()))?;
    let result = rpc.call(Request::ListClosedChannels(req))
        .await
        .map_err(|e| Status::new(
           Code::Unknown,
           format!("Error calling method ListClosedChannels: {:?}", e)))?;
    match result {
        Response::ListClosedChannels(r) => {
           trace!("list_closed_channels response: {:?}", r);
           Ok(tonic::Response::new(r.into()))
        },
        r => Err(Status::new(
            Code::Internal,
            format!(
                "Unexpected result {:?} to method call ListClosedChannels",
                r
            )
        )),
    }

}

async fn decode_pay(
    &self,
    request: tonic::Request<pb::DecodepayRequest>,
) -> Result<tonic::Response<pb::DecodepayResponse>, tonic::Status> {
    let req = request.into_inner();
    let req: requests::DecodepayRequest = req.into();
    debug!("Client asked for decode_pay");
    trace!("decode_pay request: {:?}", req);
    let mut rpc = ClnRpc::new(&self.rpc_path)
        .await
        .map_err(|e| Status::new(Code::Internal, e.to_string()))?;
    let result = rpc.call(Request::DecodePay(req))
        .await
        .map_err(|e| Status::new(
           Code::Unknown,
           format!("Error calling method DecodePay: {:?}", e)))?;
    match result {
        Response::DecodePay(r) => {
           trace!("decode_pay response: {:?}", r);
           Ok(tonic::Response::new(r.into()))
        },
        r => Err(Status::new(
            Code::Internal,
            format!(
                "Unexpected result {:?} to method call DecodePay",
                r
            )
        )),
    }

}

async fn decode(
    &self,
    request: tonic::Request<pb::DecodeRequest>,
) -> Result<tonic::Response<pb::DecodeResponse>, tonic::Status> {
    let req = request.into_inner();
    let req: requests::DecodeRequest = req.into();
    debug!("Client asked for decode");
    trace!("decode request: {:?}", req);
    let mut rpc = ClnRpc::new(&self.rpc_path)
        .await
        .map_err(|e| Status::new(Code::Internal, e.to_string()))?;
    let result = rpc.call(Request::Decode(req))
        .await
        .map_err(|e| Status::new(
           Code::Unknown,
           format!("Error calling method Decode: {:?}", e)))?;
    match result {
        Response::Decode(r) => {
           trace!("decode response: {:?}", r);
           Ok(tonic::Response::new(r.into()))
        },
        r => Err(Status::new(
            Code::Internal,
            format!(
                "Unexpected result {:?} to method call Decode",
                r
            )
        )),
    }

}

async fn disconnect(
    &self,
    request: tonic::Request<pb::DisconnectRequest>,
) -> Result<tonic::Response<pb::DisconnectResponse>, tonic::Status> {
    let req = request.into_inner();
    let req: requests::DisconnectRequest = req.into();
    debug!("Client asked for disconnect");
    trace!("disconnect request: {:?}", req);
    let mut rpc = ClnRpc::new(&self.rpc_path)
        .await
        .map_err(|e| Status::new(Code::Internal, e.to_string()))?;
    let result = rpc.call(Request::Disconnect(req))
        .await
        .map_err(|e| Status::new(
           Code::Unknown,
           format!("Error calling method Disconnect: {:?}", e)))?;
    match result {
        Response::Disconnect(r) => {
           trace!("disconnect response: {:?}", r);
           Ok(tonic::Response::new(r.into()))
        },
        r => Err(Status::new(
            Code::Internal,
            format!(
                "Unexpected result {:?} to method call Disconnect",
                r
            )
        )),
    }

}

async fn feerates(
    &self,
    request: tonic::Request<pb::FeeratesRequest>,
) -> Result<tonic::Response<pb::FeeratesResponse>, tonic::Status> {
    let req = request.into_inner();
    let req: requests::FeeratesRequest = req.into();
    debug!("Client asked for feerates");
    trace!("feerates request: {:?}", req);
    let mut rpc = ClnRpc::new(&self.rpc_path)
        .await
        .map_err(|e| Status::new(Code::Internal, e.to_string()))?;
    let result = rpc.call(Request::Feerates(req))
        .await
        .map_err(|e| Status::new(
           Code::Unknown,
           format!("Error calling method Feerates: {:?}", e)))?;
    match result {
        Response::Feerates(r) => {
           trace!("feerates response: {:?}", r);
           Ok(tonic::Response::new(r.into()))
        },
        r => Err(Status::new(
            Code::Internal,
            format!(
                "Unexpected result {:?} to method call Feerates",
                r
            )
        )),
    }

}

async fn fetch_invoice(
    &self,
    request: tonic::Request<pb::FetchinvoiceRequest>,
) -> Result<tonic::Response<pb::FetchinvoiceResponse>, tonic::Status> {
    let req = request.into_inner();
    let req: requests::FetchinvoiceRequest = req.into();
    debug!("Client asked for fetch_invoice");
    trace!("fetch_invoice request: {:?}", req);
    let mut rpc = ClnRpc::new(&self.rpc_path)
        .await
        .map_err(|e| Status::new(Code::Internal, e.to_string()))?;
    let result = rpc.call(Request::FetchInvoice(req))
        .await
        .map_err(|e| Status::new(
           Code::Unknown,
           format!("Error calling method FetchInvoice: {:?}", e)))?;
    match result {
        Response::FetchInvoice(r) => {
           trace!("fetch_invoice response: {:?}", r);
           Ok(tonic::Response::new(r.into()))
        },
        r => Err(Status::new(
            Code::Internal,
            format!(
                "Unexpected result {:?} to method call FetchInvoice",
                r
            )
        )),
    }

}

async fn fund_channel(
    &self,
    request: tonic::Request<pb::FundchannelRequest>,
) -> Result<tonic::Response<pb::FundchannelResponse>, tonic::Status> {
    let req = request.into_inner();
    let req: requests::FundchannelRequest = req.into();
    debug!("Client asked for fund_channel");
    trace!("fund_channel request: {:?}", req);
    let mut rpc = ClnRpc::new(&self.rpc_path)
        .await
        .map_err(|e| Status::new(Code::Internal, e.to_string()))?;
    let result = rpc.call(Request::FundChannel(req))
        .await
        .map_err(|e| Status::new(
           Code::Unknown,
           format!("Error calling method FundChannel: {:?}", e)))?;
    match result {
        Response::FundChannel(r) => {
           trace!("fund_channel response: {:?}", r);
           Ok(tonic::Response::new(r.into()))
        },
        r => Err(Status::new(
            Code::Internal,
            format!(
                "Unexpected result {:?} to method call FundChannel",
                r
            )
        )),
    }

}

async fn get_route(
    &self,
    request: tonic::Request<pb::GetrouteRequest>,
) -> Result<tonic::Response<pb::GetrouteResponse>, tonic::Status> {
    let req = request.into_inner();
    let req: requests::GetrouteRequest = req.into();
    debug!("Client asked for get_route");
    trace!("get_route request: {:?}", req);
    let mut rpc = ClnRpc::new(&self.rpc_path)
        .await
        .map_err(|e| Status::new(Code::Internal, e.to_string()))?;
    let result = rpc.call(Request::GetRoute(req))
        .await
        .map_err(|e| Status::new(
           Code::Unknown,
           format!("Error calling method GetRoute: {:?}", e)))?;
    match result {
        Response::GetRoute(r) => {
           trace!("get_route response: {:?}", r);
           Ok(tonic::Response::new(r.into()))
        },
        r => Err(Status::new(
            Code::Internal,
            format!(
                "Unexpected result {:?} to method call GetRoute",
                r
            )
        )),
    }

}

async fn list_forwards(
    &self,
    request: tonic::Request<pb::ListforwardsRequest>,
) -> Result<tonic::Response<pb::ListforwardsResponse>, tonic::Status> {
    let req = request.into_inner();
    let req: requests::ListforwardsRequest = req.into();
    debug!("Client asked for list_forwards");
    trace!("list_forwards request: {:?}", req);
    let mut rpc = ClnRpc::new(&self.rpc_path)
        .await
        .map_err(|e| Status::new(Code::Internal, e.to_string()))?;
    let result = rpc.call(Request::ListForwards(req))
        .await
        .map_err(|e| Status::new(
           Code::Unknown,
           format!("Error calling method ListForwards: {:?}", e)))?;
    match result {
        Response::ListForwards(r) => {
           trace!("list_forwards response: {:?}", r);
           Ok(tonic::Response::new(r.into()))
        },
        r => Err(Status::new(
            Code::Internal,
            format!(
                "Unexpected result {:?} to method call ListForwards",
                r
            )
        )),
    }

}

async fn list_pays(
    &self,
    request: tonic::Request<pb::ListpaysRequest>,
) -> Result<tonic::Response<pb::ListpaysResponse>, tonic::Status> {
    let req = request.into_inner();
    let req: requests::ListpaysRequest = req.into();
    debug!("Client asked for list_pays");
    trace!("list_pays request: {:?}", req);
    let mut rpc = ClnRpc::new(&self.rpc_path)
        .await
        .map_err(|e| Status::new(Code::Internal, e.to_string()))?;
    let result = rpc.call(Request::ListPays(req))
        .await
        .map_err(|e| Status::new(
           Code::Unknown,
           format!("Error calling method ListPays: {:?}", e)))?;
    match result {
        Response::ListPays(r) => {
           trace!("list_pays response: {:?}", r);
           Ok(tonic::Response::new(r.into()))
        },
        r => Err(Status::new(
            Code::Internal,
            format!(
                "Unexpected result {:?} to method call ListPays",
                r
            )
        )),
    }

}

async fn list_htlcs(
    &self,
    request: tonic::Request<pb::ListhtlcsRequest>,
) -> Result<tonic::Response<pb::ListhtlcsResponse>, tonic::Status> {
    let req = request.into_inner();
    let req: requests::ListhtlcsRequest = req.into();
    debug!("Client asked for list_htlcs");
    trace!("list_htlcs request: {:?}", req);
    let mut rpc = ClnRpc::new(&self.rpc_path)
        .await
        .map_err(|e| Status::new(Code::Internal, e.to_string()))?;
    let result = rpc.call(Request::ListHtlcs(req))
        .await
        .map_err(|e| Status::new(
           Code::Unknown,
           format!("Error calling method ListHtlcs: {:?}", e)))?;
    match result {
        Response::ListHtlcs(r) => {
           trace!("list_htlcs response: {:?}", r);
           Ok(tonic::Response::new(r.into()))
        },
        r => Err(Status::new(
            Code::Internal,
            format!(
                "Unexpected result {:?} to method call ListHtlcs",
                r
            )
        )),
    }

}

async fn ping(
    &self,
    request: tonic::Request<pb::PingRequest>,
) -> Result<tonic::Response<pb::PingResponse>, tonic::Status> {
    let req = request.into_inner();
    let req: requests::PingRequest = req.into();
    debug!("Client asked for ping");
    trace!("ping request: {:?}", req);
    let mut rpc = ClnRpc::new(&self.rpc_path)
        .await
        .map_err(|e| Status::new(Code::Internal, e.to_string()))?;
    let result = rpc.call(Request::Ping(req))
        .await
        .map_err(|e| Status::new(
           Code::Unknown,
           format!("Error calling method Ping: {:?}", e)))?;
    match result {
        Response::Ping(r) => {
           trace!("ping response: {:?}", r);
           Ok(tonic::Response::new(r.into()))
        },
        r => Err(Status::new(
            Code::Internal,
            format!(
                "Unexpected result {:?} to method call Ping",
                r
            )
        )),
    }

}

async fn send_custom_msg(
    &self,
    request: tonic::Request<pb::SendcustommsgRequest>,
) -> Result<tonic::Response<pb::SendcustommsgResponse>, tonic::Status> {
    let req = request.into_inner();
    let req: requests::SendcustommsgRequest = req.into();
    debug!("Client asked for send_custom_msg");
    trace!("send_custom_msg request: {:?}", req);
    let mut rpc = ClnRpc::new(&self.rpc_path)
        .await
        .map_err(|e| Status::new(Code::Internal, e.to_string()))?;
    let result = rpc.call(Request::SendCustomMsg(req))
        .await
        .map_err(|e| Status::new(
           Code::Unknown,
           format!("Error calling method SendCustomMsg: {:?}", e)))?;
    match result {
        Response::SendCustomMsg(r) => {
           trace!("send_custom_msg response: {:?}", r);
           Ok(tonic::Response::new(r.into()))
        },
        r => Err(Status::new(
            Code::Internal,
            format!(
                "Unexpected result {:?} to method call SendCustomMsg",
                r
            )
        )),
    }

}

async fn set_channel(
    &self,
    request: tonic::Request<pb::SetchannelRequest>,
) -> Result<tonic::Response<pb::SetchannelResponse>, tonic::Status> {
    let req = request.into_inner();
    let req: requests::SetchannelRequest = req.into();
    debug!("Client asked for set_channel");
    trace!("set_channel request: {:?}", req);
    let mut rpc = ClnRpc::new(&self.rpc_path)
        .await
        .map_err(|e| Status::new(Code::Internal, e.to_string()))?;
    let result = rpc.call(Request::SetChannel(req))
        .await
        .map_err(|e| Status::new(
           Code::Unknown,
           format!("Error calling method SetChannel: {:?}", e)))?;
    match result {
        Response::SetChannel(r) => {
           trace!("set_channel response: {:?}", r);
           Ok(tonic::Response::new(r.into()))
        },
        r => Err(Status::new(
            Code::Internal,
            format!(
                "Unexpected result {:?} to method call SetChannel",
                r
            )
        )),
    }

}

async fn sign_invoice(
    &self,
    request: tonic::Request<pb::SigninvoiceRequest>,
) -> Result<tonic::Response<pb::SigninvoiceResponse>, tonic::Status> {
    let req = request.into_inner();
    let req: requests::SigninvoiceRequest = req.into();
    debug!("Client asked for sign_invoice");
    trace!("sign_invoice request: {:?}", req);
    let mut rpc = ClnRpc::new(&self.rpc_path)
        .await
        .map_err(|e| Status::new(Code::Internal, e.to_string()))?;
    let result = rpc.call(Request::SignInvoice(req))
        .await
        .map_err(|e| Status::new(
           Code::Unknown,
           format!("Error calling method SignInvoice: {:?}", e)))?;
    match result {
        Response::SignInvoice(r) => {
           trace!("sign_invoice response: {:?}", r);
           Ok(tonic::Response::new(r.into()))
        },
        r => Err(Status::new(
            Code::Internal,
            format!(
                "Unexpected result {:?} to method call SignInvoice",
                r
            )
        )),
    }

}

async fn sign_message(
    &self,
    request: tonic::Request<pb::SignmessageRequest>,
) -> Result<tonic::Response<pb::SignmessageResponse>, tonic::Status> {
    let req = request.into_inner();
    let req: requests::SignmessageRequest = req.into();
    debug!("Client asked for sign_message");
    trace!("sign_message request: {:?}", req);
    let mut rpc = ClnRpc::new(&self.rpc_path)
        .await
        .map_err(|e| Status::new(Code::Internal, e.to_string()))?;
    let result = rpc.call(Request::SignMessage(req))
        .await
        .map_err(|e| Status::new(
           Code::Unknown,
           format!("Error calling method SignMessage: {:?}", e)))?;
    match result {
        Response::SignMessage(r) => {
           trace!("sign_message response: {:?}", r);
           Ok(tonic::Response::new(r.into()))
        },
        r => Err(Status::new(
            Code::Internal,
            format!(
                "Unexpected result {:?} to method call SignMessage",
                r
            )
        )),
    }

}

async fn wait_block_height(
    &self,
    request: tonic::Request<pb::WaitblockheightRequest>,
) -> Result<tonic::Response<pb::WaitblockheightResponse>, tonic::Status> {
    let req = request.into_inner();
    let req: requests::WaitblockheightRequest = req.into();
    debug!("Client asked for wait_block_height");
    trace!("wait_block_height request: {:?}", req);
    let mut rpc = ClnRpc::new(&self.rpc_path)
        .await
        .map_err(|e| Status::new(Code::Internal, e.to_string()))?;
    let result = rpc.call(Request::WaitBlockHeight(req))
        .await
        .map_err(|e| Status::new(
           Code::Unknown,
           format!("Error calling method WaitBlockHeight: {:?}", e)))?;
    match result {
        Response::WaitBlockHeight(r) => {
           trace!("wait_block_height response: {:?}", r);
           Ok(tonic::Response::new(r.into()))
        },
        r => Err(Status::new(
            Code::Internal,
            format!(
                "Unexpected result {:?} to method call WaitBlockHeight",
                r
            )
        )),
    }

}

async fn wait(
    &self,
    request: tonic::Request<pb::WaitRequest>,
) -> Result<tonic::Response<pb::WaitResponse>, tonic::Status> {
    let req = request.into_inner();
    let req: requests::WaitRequest = req.into();
    debug!("Client asked for wait");
    trace!("wait request: {:?}", req);
    let mut rpc = ClnRpc::new(&self.rpc_path)
        .await
        .map_err(|e| Status::new(Code::Internal, e.to_string()))?;
    let result = rpc.call(Request::Wait(req))
        .await
        .map_err(|e| Status::new(
           Code::Unknown,
           format!("Error calling method Wait: {:?}", e)))?;
    match result {
        Response::Wait(r) => {
           trace!("wait response: {:?}", r);
           Ok(tonic::Response::new(r.into()))
        },
        r => Err(Status::new(
            Code::Internal,
            format!(
                "Unexpected result {:?} to method call Wait",
                r
            )
        )),
    }

}

async fn stop(
    &self,
    request: tonic::Request<pb::StopRequest>,
) -> Result<tonic::Response<pb::StopResponse>, tonic::Status> {
    let req = request.into_inner();
    let req: requests::StopRequest = req.into();
    debug!("Client asked for stop");
    trace!("stop request: {:?}", req);
    let mut rpc = ClnRpc::new(&self.rpc_path)
        .await
        .map_err(|e| Status::new(Code::Internal, e.to_string()))?;
    let result = rpc.call(Request::Stop(req))
        .await
        .map_err(|e| Status::new(
           Code::Unknown,
           format!("Error calling method Stop: {:?}", e)))?;
    match result {
        Response::Stop(r) => {
           trace!("stop response: {:?}", r);
           Ok(tonic::Response::new(r.into()))
        },
        r => Err(Status::new(
            Code::Internal,
            format!(
                "Unexpected result {:?} to method call Stop",
                r
            )
        )),
    }

}

async fn pre_approve_keysend(
    &self,
    request: tonic::Request<pb::PreapprovekeysendRequest>,
) -> Result<tonic::Response<pb::PreapprovekeysendResponse>, tonic::Status> {
    let req = request.into_inner();
    let req: requests::PreapprovekeysendRequest = req.into();
    debug!("Client asked for pre_approve_keysend");
    trace!("pre_approve_keysend request: {:?}", req);
    let mut rpc = ClnRpc::new(&self.rpc_path)
        .await
        .map_err(|e| Status::new(Code::Internal, e.to_string()))?;
    let result = rpc.call(Request::PreApproveKeysend(req))
        .await
        .map_err(|e| Status::new(
           Code::Unknown,
           format!("Error calling method PreApproveKeysend: {:?}", e)))?;
    match result {
        Response::PreApproveKeysend(r) => {
           trace!("pre_approve_keysend response: {:?}", r);
           Ok(tonic::Response::new(r.into()))
        },
        r => Err(Status::new(
            Code::Internal,
            format!(
                "Unexpected result {:?} to method call PreApproveKeysend",
                r
            )
        )),
    }

}

async fn pre_approve_invoice(
    &self,
    request: tonic::Request<pb::PreapproveinvoiceRequest>,
) -> Result<tonic::Response<pb::PreapproveinvoiceResponse>, tonic::Status> {
    let req = request.into_inner();
    let req: requests::PreapproveinvoiceRequest = req.into();
    debug!("Client asked for pre_approve_invoice");
    trace!("pre_approve_invoice request: {:?}", req);
    let mut rpc = ClnRpc::new(&self.rpc_path)
        .await
        .map_err(|e| Status::new(Code::Internal, e.to_string()))?;
    let result = rpc.call(Request::PreApproveInvoice(req))
        .await
        .map_err(|e| Status::new(
           Code::Unknown,
           format!("Error calling method PreApproveInvoice: {:?}", e)))?;
    match result {
        Response::PreApproveInvoice(r) => {
           trace!("pre_approve_invoice response: {:?}", r);
           Ok(tonic::Response::new(r.into()))
        },
        r => Err(Status::new(
            Code::Internal,
            format!(
                "Unexpected result {:?} to method call PreApproveInvoice",
                r
            )
        )),
    }

}

async fn static_backup(
    &self,
    request: tonic::Request<pb::StaticbackupRequest>,
) -> Result<tonic::Response<pb::StaticbackupResponse>, tonic::Status> {
    let req = request.into_inner();
    let req: requests::StaticbackupRequest = req.into();
    debug!("Client asked for static_backup");
    trace!("static_backup request: {:?}", req);
    let mut rpc = ClnRpc::new(&self.rpc_path)
        .await
        .map_err(|e| Status::new(Code::Internal, e.to_string()))?;
    let result = rpc.call(Request::StaticBackup(req))
        .await
        .map_err(|e| Status::new(
           Code::Unknown,
           format!("Error calling method StaticBackup: {:?}", e)))?;
    match result {
        Response::StaticBackup(r) => {
           trace!("static_backup response: {:?}", r);
           Ok(tonic::Response::new(r.into()))
        },
        r => Err(Status::new(
            Code::Internal,
            format!(
                "Unexpected result {:?} to method call StaticBackup",
                r
            )
        )),
    }

}

async fn bkpr_list_income(
    &self,
    request: tonic::Request<pb::BkprlistincomeRequest>,
) -> Result<tonic::Response<pb::BkprlistincomeResponse>, tonic::Status> {
    let req = request.into_inner();
    let req: requests::BkprlistincomeRequest = req.into();
    debug!("Client asked for bkpr_list_income");
    trace!("bkpr_list_income request: {:?}", req);
    let mut rpc = ClnRpc::new(&self.rpc_path)
        .await
        .map_err(|e| Status::new(Code::Internal, e.to_string()))?;
    let result = rpc.call(Request::BkprListIncome(req))
        .await
        .map_err(|e| Status::new(
           Code::Unknown,
           format!("Error calling method BkprListIncome: {:?}", e)))?;
    match result {
        Response::BkprListIncome(r) => {
           trace!("bkpr_list_income response: {:?}", r);
           Ok(tonic::Response::new(r.into()))
        },
        r => Err(Status::new(
            Code::Internal,
            format!(
                "Unexpected result {:?} to method call BkprListIncome",
                r
            )
        )),
    }

}

}
