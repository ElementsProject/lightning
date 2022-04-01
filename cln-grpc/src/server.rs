use crate::pb::node_server::Node;
use crate::pb;
use cln_rpc::{Request, Response, ClnRpc};
use anyhow::Result;
use std::path::{Path, PathBuf};
use cln_rpc::model::requests;
use log::debug;
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
    let req: requests::GetinfoRequest = (&req).into();
    debug!("Client asked for getinfo");
    let mut rpc = ClnRpc::new(&self.rpc_path)
        .await
        .map_err(|e| Status::new(Code::Internal, e.to_string()))?;
    let result = rpc.call(Request::Getinfo(req))
        .await
        .map_err(|e| Status::new(
           Code::Unknown,
           format!("Error calling method Getinfo: {:?}", e)))?;
    match result {
        Response::Getinfo(r) => Ok(
            tonic::Response::new((&r).into())
        ),
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
    let req: requests::ListpeersRequest = (&req).into();
    debug!("Client asked for getinfo");
    let mut rpc = ClnRpc::new(&self.rpc_path)
        .await
        .map_err(|e| Status::new(Code::Internal, e.to_string()))?;
    let result = rpc.call(Request::ListPeers(req))
        .await
        .map_err(|e| Status::new(
           Code::Unknown,
           format!("Error calling method ListPeers: {:?}", e)))?;
    match result {
        Response::ListPeers(r) => Ok(
            tonic::Response::new((&r).into())
        ),
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
    let req: requests::ListfundsRequest = (&req).into();
    debug!("Client asked for getinfo");
    let mut rpc = ClnRpc::new(&self.rpc_path)
        .await
        .map_err(|e| Status::new(Code::Internal, e.to_string()))?;
    let result = rpc.call(Request::ListFunds(req))
        .await
        .map_err(|e| Status::new(
           Code::Unknown,
           format!("Error calling method ListFunds: {:?}", e)))?;
    match result {
        Response::ListFunds(r) => Ok(
            tonic::Response::new((&r).into())
        ),
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
    let req: requests::SendpayRequest = (&req).into();
    debug!("Client asked for getinfo");
    let mut rpc = ClnRpc::new(&self.rpc_path)
        .await
        .map_err(|e| Status::new(Code::Internal, e.to_string()))?;
    let result = rpc.call(Request::SendPay(req))
        .await
        .map_err(|e| Status::new(
           Code::Unknown,
           format!("Error calling method SendPay: {:?}", e)))?;
    match result {
        Response::SendPay(r) => Ok(
            tonic::Response::new((&r).into())
        ),
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
    let req: requests::ListchannelsRequest = (&req).into();
    debug!("Client asked for getinfo");
    let mut rpc = ClnRpc::new(&self.rpc_path)
        .await
        .map_err(|e| Status::new(Code::Internal, e.to_string()))?;
    let result = rpc.call(Request::ListChannels(req))
        .await
        .map_err(|e| Status::new(
           Code::Unknown,
           format!("Error calling method ListChannels: {:?}", e)))?;
    match result {
        Response::ListChannels(r) => Ok(
            tonic::Response::new((&r).into())
        ),
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
    let req: requests::AddgossipRequest = (&req).into();
    debug!("Client asked for getinfo");
    let mut rpc = ClnRpc::new(&self.rpc_path)
        .await
        .map_err(|e| Status::new(Code::Internal, e.to_string()))?;
    let result = rpc.call(Request::AddGossip(req))
        .await
        .map_err(|e| Status::new(
           Code::Unknown,
           format!("Error calling method AddGossip: {:?}", e)))?;
    match result {
        Response::AddGossip(r) => Ok(
            tonic::Response::new((&r).into())
        ),
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
    let req: requests::AutocleaninvoiceRequest = (&req).into();
    debug!("Client asked for getinfo");
    let mut rpc = ClnRpc::new(&self.rpc_path)
        .await
        .map_err(|e| Status::new(Code::Internal, e.to_string()))?;
    let result = rpc.call(Request::AutoCleanInvoice(req))
        .await
        .map_err(|e| Status::new(
           Code::Unknown,
           format!("Error calling method AutoCleanInvoice: {:?}", e)))?;
    match result {
        Response::AutoCleanInvoice(r) => Ok(
            tonic::Response::new((&r).into())
        ),
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
    let req: requests::CheckmessageRequest = (&req).into();
    debug!("Client asked for getinfo");
    let mut rpc = ClnRpc::new(&self.rpc_path)
        .await
        .map_err(|e| Status::new(Code::Internal, e.to_string()))?;
    let result = rpc.call(Request::CheckMessage(req))
        .await
        .map_err(|e| Status::new(
           Code::Unknown,
           format!("Error calling method CheckMessage: {:?}", e)))?;
    match result {
        Response::CheckMessage(r) => Ok(
            tonic::Response::new((&r).into())
        ),
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
    let req: requests::CloseRequest = (&req).into();
    debug!("Client asked for getinfo");
    let mut rpc = ClnRpc::new(&self.rpc_path)
        .await
        .map_err(|e| Status::new(Code::Internal, e.to_string()))?;
    let result = rpc.call(Request::Close(req))
        .await
        .map_err(|e| Status::new(
           Code::Unknown,
           format!("Error calling method Close: {:?}", e)))?;
    match result {
        Response::Close(r) => Ok(
            tonic::Response::new((&r).into())
        ),
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
    let req: requests::ConnectRequest = (&req).into();
    debug!("Client asked for getinfo");
    let mut rpc = ClnRpc::new(&self.rpc_path)
        .await
        .map_err(|e| Status::new(Code::Internal, e.to_string()))?;
    let result = rpc.call(Request::ConnectPeer(req))
        .await
        .map_err(|e| Status::new(
           Code::Unknown,
           format!("Error calling method ConnectPeer: {:?}", e)))?;
    match result {
        Response::ConnectPeer(r) => Ok(
            tonic::Response::new((&r).into())
        ),
        r => Err(Status::new(
            Code::Internal,
            format!(
                "Unexpected result {:?} to method call ConnectPeer",
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
    let req: requests::CreateinvoiceRequest = (&req).into();
    debug!("Client asked for getinfo");
    let mut rpc = ClnRpc::new(&self.rpc_path)
        .await
        .map_err(|e| Status::new(Code::Internal, e.to_string()))?;
    let result = rpc.call(Request::CreateInvoice(req))
        .await
        .map_err(|e| Status::new(
           Code::Unknown,
           format!("Error calling method CreateInvoice: {:?}", e)))?;
    match result {
        Response::CreateInvoice(r) => Ok(
            tonic::Response::new((&r).into())
        ),
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
    let req: requests::DatastoreRequest = (&req).into();
    debug!("Client asked for getinfo");
    let mut rpc = ClnRpc::new(&self.rpc_path)
        .await
        .map_err(|e| Status::new(Code::Internal, e.to_string()))?;
    let result = rpc.call(Request::Datastore(req))
        .await
        .map_err(|e| Status::new(
           Code::Unknown,
           format!("Error calling method Datastore: {:?}", e)))?;
    match result {
        Response::Datastore(r) => Ok(
            tonic::Response::new((&r).into())
        ),
        r => Err(Status::new(
            Code::Internal,
            format!(
                "Unexpected result {:?} to method call Datastore",
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
    let req: requests::CreateonionRequest = (&req).into();
    debug!("Client asked for getinfo");
    let mut rpc = ClnRpc::new(&self.rpc_path)
        .await
        .map_err(|e| Status::new(Code::Internal, e.to_string()))?;
    let result = rpc.call(Request::CreateOnion(req))
        .await
        .map_err(|e| Status::new(
           Code::Unknown,
           format!("Error calling method CreateOnion: {:?}", e)))?;
    match result {
        Response::CreateOnion(r) => Ok(
            tonic::Response::new((&r).into())
        ),
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
    let req: requests::DeldatastoreRequest = (&req).into();
    debug!("Client asked for getinfo");
    let mut rpc = ClnRpc::new(&self.rpc_path)
        .await
        .map_err(|e| Status::new(Code::Internal, e.to_string()))?;
    let result = rpc.call(Request::DelDatastore(req))
        .await
        .map_err(|e| Status::new(
           Code::Unknown,
           format!("Error calling method DelDatastore: {:?}", e)))?;
    match result {
        Response::DelDatastore(r) => Ok(
            tonic::Response::new((&r).into())
        ),
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
    let req: requests::DelexpiredinvoiceRequest = (&req).into();
    debug!("Client asked for getinfo");
    let mut rpc = ClnRpc::new(&self.rpc_path)
        .await
        .map_err(|e| Status::new(Code::Internal, e.to_string()))?;
    let result = rpc.call(Request::DelExpiredInvoice(req))
        .await
        .map_err(|e| Status::new(
           Code::Unknown,
           format!("Error calling method DelExpiredInvoice: {:?}", e)))?;
    match result {
        Response::DelExpiredInvoice(r) => Ok(
            tonic::Response::new((&r).into())
        ),
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
    let req: requests::DelinvoiceRequest = (&req).into();
    debug!("Client asked for getinfo");
    let mut rpc = ClnRpc::new(&self.rpc_path)
        .await
        .map_err(|e| Status::new(Code::Internal, e.to_string()))?;
    let result = rpc.call(Request::DelInvoice(req))
        .await
        .map_err(|e| Status::new(
           Code::Unknown,
           format!("Error calling method DelInvoice: {:?}", e)))?;
    match result {
        Response::DelInvoice(r) => Ok(
            tonic::Response::new((&r).into())
        ),
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
    let req: requests::InvoiceRequest = (&req).into();
    debug!("Client asked for getinfo");
    let mut rpc = ClnRpc::new(&self.rpc_path)
        .await
        .map_err(|e| Status::new(Code::Internal, e.to_string()))?;
    let result = rpc.call(Request::Invoice(req))
        .await
        .map_err(|e| Status::new(
           Code::Unknown,
           format!("Error calling method Invoice: {:?}", e)))?;
    match result {
        Response::Invoice(r) => Ok(
            tonic::Response::new((&r).into())
        ),
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
    let req: requests::ListdatastoreRequest = (&req).into();
    debug!("Client asked for getinfo");
    let mut rpc = ClnRpc::new(&self.rpc_path)
        .await
        .map_err(|e| Status::new(Code::Internal, e.to_string()))?;
    let result = rpc.call(Request::ListDatastore(req))
        .await
        .map_err(|e| Status::new(
           Code::Unknown,
           format!("Error calling method ListDatastore: {:?}", e)))?;
    match result {
        Response::ListDatastore(r) => Ok(
            tonic::Response::new((&r).into())
        ),
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
    let req: requests::ListinvoicesRequest = (&req).into();
    debug!("Client asked for getinfo");
    let mut rpc = ClnRpc::new(&self.rpc_path)
        .await
        .map_err(|e| Status::new(Code::Internal, e.to_string()))?;
    let result = rpc.call(Request::ListInvoices(req))
        .await
        .map_err(|e| Status::new(
           Code::Unknown,
           format!("Error calling method ListInvoices: {:?}", e)))?;
    match result {
        Response::ListInvoices(r) => Ok(
            tonic::Response::new((&r).into())
        ),
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
    let req: requests::SendonionRequest = (&req).into();
    debug!("Client asked for getinfo");
    let mut rpc = ClnRpc::new(&self.rpc_path)
        .await
        .map_err(|e| Status::new(Code::Internal, e.to_string()))?;
    let result = rpc.call(Request::SendOnion(req))
        .await
        .map_err(|e| Status::new(
           Code::Unknown,
           format!("Error calling method SendOnion: {:?}", e)))?;
    match result {
        Response::SendOnion(r) => Ok(
            tonic::Response::new((&r).into())
        ),
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
    let req: requests::ListsendpaysRequest = (&req).into();
    debug!("Client asked for getinfo");
    let mut rpc = ClnRpc::new(&self.rpc_path)
        .await
        .map_err(|e| Status::new(Code::Internal, e.to_string()))?;
    let result = rpc.call(Request::ListSendPays(req))
        .await
        .map_err(|e| Status::new(
           Code::Unknown,
           format!("Error calling method ListSendPays: {:?}", e)))?;
    match result {
        Response::ListSendPays(r) => Ok(
            tonic::Response::new((&r).into())
        ),
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
    let req: requests::ListtransactionsRequest = (&req).into();
    debug!("Client asked for getinfo");
    let mut rpc = ClnRpc::new(&self.rpc_path)
        .await
        .map_err(|e| Status::new(Code::Internal, e.to_string()))?;
    let result = rpc.call(Request::ListTransactions(req))
        .await
        .map_err(|e| Status::new(
           Code::Unknown,
           format!("Error calling method ListTransactions: {:?}", e)))?;
    match result {
        Response::ListTransactions(r) => Ok(
            tonic::Response::new((&r).into())
        ),
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
    let req: requests::PayRequest = (&req).into();
    debug!("Client asked for getinfo");
    let mut rpc = ClnRpc::new(&self.rpc_path)
        .await
        .map_err(|e| Status::new(Code::Internal, e.to_string()))?;
    let result = rpc.call(Request::Pay(req))
        .await
        .map_err(|e| Status::new(
           Code::Unknown,
           format!("Error calling method Pay: {:?}", e)))?;
    match result {
        Response::Pay(r) => Ok(
            tonic::Response::new((&r).into())
        ),
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
    let req: requests::ListnodesRequest = (&req).into();
    debug!("Client asked for getinfo");
    let mut rpc = ClnRpc::new(&self.rpc_path)
        .await
        .map_err(|e| Status::new(Code::Internal, e.to_string()))?;
    let result = rpc.call(Request::ListNodes(req))
        .await
        .map_err(|e| Status::new(
           Code::Unknown,
           format!("Error calling method ListNodes: {:?}", e)))?;
    match result {
        Response::ListNodes(r) => Ok(
            tonic::Response::new((&r).into())
        ),
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
    let req: requests::WaitanyinvoiceRequest = (&req).into();
    debug!("Client asked for getinfo");
    let mut rpc = ClnRpc::new(&self.rpc_path)
        .await
        .map_err(|e| Status::new(Code::Internal, e.to_string()))?;
    let result = rpc.call(Request::WaitAnyInvoice(req))
        .await
        .map_err(|e| Status::new(
           Code::Unknown,
           format!("Error calling method WaitAnyInvoice: {:?}", e)))?;
    match result {
        Response::WaitAnyInvoice(r) => Ok(
            tonic::Response::new((&r).into())
        ),
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
    let req: requests::WaitinvoiceRequest = (&req).into();
    debug!("Client asked for getinfo");
    let mut rpc = ClnRpc::new(&self.rpc_path)
        .await
        .map_err(|e| Status::new(Code::Internal, e.to_string()))?;
    let result = rpc.call(Request::WaitInvoice(req))
        .await
        .map_err(|e| Status::new(
           Code::Unknown,
           format!("Error calling method WaitInvoice: {:?}", e)))?;
    match result {
        Response::WaitInvoice(r) => Ok(
            tonic::Response::new((&r).into())
        ),
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
    let req: requests::WaitsendpayRequest = (&req).into();
    debug!("Client asked for getinfo");
    let mut rpc = ClnRpc::new(&self.rpc_path)
        .await
        .map_err(|e| Status::new(Code::Internal, e.to_string()))?;
    let result = rpc.call(Request::WaitSendPay(req))
        .await
        .map_err(|e| Status::new(
           Code::Unknown,
           format!("Error calling method WaitSendPay: {:?}", e)))?;
    match result {
        Response::WaitSendPay(r) => Ok(
            tonic::Response::new((&r).into())
        ),
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
    let req: requests::NewaddrRequest = (&req).into();
    debug!("Client asked for getinfo");
    let mut rpc = ClnRpc::new(&self.rpc_path)
        .await
        .map_err(|e| Status::new(Code::Internal, e.to_string()))?;
    let result = rpc.call(Request::NewAddr(req))
        .await
        .map_err(|e| Status::new(
           Code::Unknown,
           format!("Error calling method NewAddr: {:?}", e)))?;
    match result {
        Response::NewAddr(r) => Ok(
            tonic::Response::new((&r).into())
        ),
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
    let req: requests::WithdrawRequest = (&req).into();
    debug!("Client asked for getinfo");
    let mut rpc = ClnRpc::new(&self.rpc_path)
        .await
        .map_err(|e| Status::new(Code::Internal, e.to_string()))?;
    let result = rpc.call(Request::Withdraw(req))
        .await
        .map_err(|e| Status::new(
           Code::Unknown,
           format!("Error calling method Withdraw: {:?}", e)))?;
    match result {
        Response::Withdraw(r) => Ok(
            tonic::Response::new((&r).into())
        ),
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
    let req: requests::KeysendRequest = (&req).into();
    debug!("Client asked for getinfo");
    let mut rpc = ClnRpc::new(&self.rpc_path)
        .await
        .map_err(|e| Status::new(Code::Internal, e.to_string()))?;
    let result = rpc.call(Request::KeySend(req))
        .await
        .map_err(|e| Status::new(
           Code::Unknown,
           format!("Error calling method KeySend: {:?}", e)))?;
    match result {
        Response::KeySend(r) => Ok(
            tonic::Response::new((&r).into())
        ),
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
    let req: requests::FundpsbtRequest = (&req).into();
    debug!("Client asked for getinfo");
    let mut rpc = ClnRpc::new(&self.rpc_path)
        .await
        .map_err(|e| Status::new(Code::Internal, e.to_string()))?;
    let result = rpc.call(Request::FundPsbt(req))
        .await
        .map_err(|e| Status::new(
           Code::Unknown,
           format!("Error calling method FundPsbt: {:?}", e)))?;
    match result {
        Response::FundPsbt(r) => Ok(
            tonic::Response::new((&r).into())
        ),
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
    let req: requests::SendpsbtRequest = (&req).into();
    debug!("Client asked for getinfo");
    let mut rpc = ClnRpc::new(&self.rpc_path)
        .await
        .map_err(|e| Status::new(Code::Internal, e.to_string()))?;
    let result = rpc.call(Request::SendPsbt(req))
        .await
        .map_err(|e| Status::new(
           Code::Unknown,
           format!("Error calling method SendPsbt: {:?}", e)))?;
    match result {
        Response::SendPsbt(r) => Ok(
            tonic::Response::new((&r).into())
        ),
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
    let req: requests::SignpsbtRequest = (&req).into();
    debug!("Client asked for getinfo");
    let mut rpc = ClnRpc::new(&self.rpc_path)
        .await
        .map_err(|e| Status::new(Code::Internal, e.to_string()))?;
    let result = rpc.call(Request::SignPsbt(req))
        .await
        .map_err(|e| Status::new(
           Code::Unknown,
           format!("Error calling method SignPsbt: {:?}", e)))?;
    match result {
        Response::SignPsbt(r) => Ok(
            tonic::Response::new((&r).into())
        ),
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
    let req: requests::UtxopsbtRequest = (&req).into();
    debug!("Client asked for getinfo");
    let mut rpc = ClnRpc::new(&self.rpc_path)
        .await
        .map_err(|e| Status::new(Code::Internal, e.to_string()))?;
    let result = rpc.call(Request::UtxoPsbt(req))
        .await
        .map_err(|e| Status::new(
           Code::Unknown,
           format!("Error calling method UtxoPsbt: {:?}", e)))?;
    match result {
        Response::UtxoPsbt(r) => Ok(
            tonic::Response::new((&r).into())
        ),
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
    let req: requests::TxdiscardRequest = (&req).into();
    debug!("Client asked for getinfo");
    let mut rpc = ClnRpc::new(&self.rpc_path)
        .await
        .map_err(|e| Status::new(Code::Internal, e.to_string()))?;
    let result = rpc.call(Request::TxDiscard(req))
        .await
        .map_err(|e| Status::new(
           Code::Unknown,
           format!("Error calling method TxDiscard: {:?}", e)))?;
    match result {
        Response::TxDiscard(r) => Ok(
            tonic::Response::new((&r).into())
        ),
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
    let req: requests::TxprepareRequest = (&req).into();
    debug!("Client asked for getinfo");
    let mut rpc = ClnRpc::new(&self.rpc_path)
        .await
        .map_err(|e| Status::new(Code::Internal, e.to_string()))?;
    let result = rpc.call(Request::TxPrepare(req))
        .await
        .map_err(|e| Status::new(
           Code::Unknown,
           format!("Error calling method TxPrepare: {:?}", e)))?;
    match result {
        Response::TxPrepare(r) => Ok(
            tonic::Response::new((&r).into())
        ),
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
    let req: requests::TxsendRequest = (&req).into();
    debug!("Client asked for getinfo");
    let mut rpc = ClnRpc::new(&self.rpc_path)
        .await
        .map_err(|e| Status::new(Code::Internal, e.to_string()))?;
    let result = rpc.call(Request::TxSend(req))
        .await
        .map_err(|e| Status::new(
           Code::Unknown,
           format!("Error calling method TxSend: {:?}", e)))?;
    match result {
        Response::TxSend(r) => Ok(
            tonic::Response::new((&r).into())
        ),
        r => Err(Status::new(
            Code::Internal,
            format!(
                "Unexpected result {:?} to method call TxSend",
                r
            )
        )),
    }

}

}
