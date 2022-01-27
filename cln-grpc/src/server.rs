use crate::pb::node_server::Node;
use crate::pb;
use cln_rpc::{Request, Response, ClnRpc};
use anyhow::Result;
use std::path::{Path, PathBuf};
use cln_rpc::model::requests;
use log::debug;
use crate::convert::*;
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

}
