use crate::pb::node_server::Node;
use crate::pb;
use cln_rpc::{Request, Response, ClnRpc};
use cln_rpc::notifications::Notification;
use anyhow::Result;
use std::path::{Path, PathBuf};
use std::pin::Pin;
use std::task::{Context, Poll};
use cln_rpc::model::requests;
use log::{debug, trace};
use tonic::{Code, Status};
use tokio::sync::broadcast;
use tokio_stream::wrappers::errors::BroadcastStreamRecvError;
use tokio_stream::wrappers::BroadcastStream;


#[derive(Clone)]
pub struct Server
{
    rpc_path: PathBuf,
    events : broadcast::Sender<Notification>
}

impl Server
{
    pub async fn new(
        path: &Path,
        events : broadcast::Sender<Notification>
    ) -> Result<Self>
    {
        Ok(Self {
            rpc_path: path.to_path_buf(),
            events : events
        })
    }
}

pub struct NotificationStream<T> {
    inner : Pin<Box<BroadcastStream<Notification>>>,
    fn_filter_map : fn(Notification) -> Option<T>
}

impl<T : 'static + Send + Clone> tokio_stream::Stream for NotificationStream<T> {

    type Item = Result<T, tonic::Status>;

    fn poll_next(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        while let Poll::Ready(result) = self.inner.as_mut().poll_next(cx) {
            // None is used here to signal that we have reached the end of stream
            // If inner ends the stream by returning None we do the same
            if result.is_none() {
                return Poll::Ready(None)
            }
            let result: Result<cln_rpc::Notification, BroadcastStreamRecvError> = result.unwrap();

            match result {
                Err(BroadcastStreamRecvError::Lagged(lag)) => {
                    // In this error case we've missed some notifications
                    // We log the error to core lightning and forward
                    // this information to the client
                    log::warn!("Due to lag the grpc-server skipped {} notifications", lag);
                    return Poll::Ready(Some(Err(
                        Status::data_loss(
                            format!("Skipped up to {} notifications", lag)))))
                }
                Ok(notification) => {
                    let filtered = (self.fn_filter_map)(notification);
                    match filtered {
                        Some(n) => return Poll::Ready(Some(Ok(n))),
                        None => {
                            // We ignore the message if it isn't a match.
                            // e.g: A `ChannelOpenedStream` will ignore `CustomMsgNotifications`
                        }
                    }
                }
            }
        }
        Poll::Pending
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

    async fn add_psbt_output(
        &self,
        request: tonic::Request<pb::AddpsbtoutputRequest>,
    ) -> Result<tonic::Response<pb::AddpsbtoutputResponse>, tonic::Status> {
        let req = request.into_inner();
        let req: requests::AddpsbtoutputRequest = req.into();
        debug!("Client asked for add_psbt_output");
        trace!("add_psbt_output request: {:?}", req);
        let mut rpc = ClnRpc::new(&self.rpc_path)
            .await
            .map_err(|e| Status::new(Code::Internal, e.to_string()))?;
        let result = rpc.call(Request::AddPsbtOutput(req))
            .await
            .map_err(|e| Status::new(
               Code::Unknown,
               format!("Error calling method AddPsbtOutput: {:?}", e)))?;
        match result {
            Response::AddPsbtOutput(r) => {
               trace!("add_psbt_output response: {:?}", r);
               Ok(tonic::Response::new(r.into()))
            },
            r => Err(Status::new(
                Code::Internal,
                format!(
                    "Unexpected result {:?} to method call AddPsbtOutput",
                    r
                )
            )),
        }

    }

    async fn auto_clean_once(
        &self,
        request: tonic::Request<pb::AutocleanonceRequest>,
    ) -> Result<tonic::Response<pb::AutocleanonceResponse>, tonic::Status> {
        let req = request.into_inner();
        let req: requests::AutocleanonceRequest = req.into();
        debug!("Client asked for auto_clean_once");
        trace!("auto_clean_once request: {:?}", req);
        let mut rpc = ClnRpc::new(&self.rpc_path)
            .await
            .map_err(|e| Status::new(Code::Internal, e.to_string()))?;
        let result = rpc.call(Request::AutoCleanOnce(req))
            .await
            .map_err(|e| Status::new(
               Code::Unknown,
               format!("Error calling method AutoCleanOnce: {:?}", e)))?;
        match result {
            Response::AutoCleanOnce(r) => {
               trace!("auto_clean_once response: {:?}", r);
               Ok(tonic::Response::new(r.into()))
            },
            r => Err(Status::new(
                Code::Internal,
                format!(
                    "Unexpected result {:?} to method call AutoCleanOnce",
                    r
                )
            )),
        }

    }

    async fn auto_clean_status(
        &self,
        request: tonic::Request<pb::AutocleanstatusRequest>,
    ) -> Result<tonic::Response<pb::AutocleanstatusResponse>, tonic::Status> {
        let req = request.into_inner();
        let req: requests::AutocleanstatusRequest = req.into();
        debug!("Client asked for auto_clean_status");
        trace!("auto_clean_status request: {:?}", req);
        let mut rpc = ClnRpc::new(&self.rpc_path)
            .await
            .map_err(|e| Status::new(Code::Internal, e.to_string()))?;
        let result = rpc.call(Request::AutoCleanStatus(req))
            .await
            .map_err(|e| Status::new(
               Code::Unknown,
               format!("Error calling method AutoCleanStatus: {:?}", e)))?;
        match result {
            Response::AutoCleanStatus(r) => {
               trace!("auto_clean_status response: {:?}", r);
               Ok(tonic::Response::new(r.into()))
            },
            r => Err(Status::new(
                Code::Internal,
                format!(
                    "Unexpected result {:?} to method call AutoCleanStatus",
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

    async fn dev_forget_channel(
        &self,
        request: tonic::Request<pb::DevforgetchannelRequest>,
    ) -> Result<tonic::Response<pb::DevforgetchannelResponse>, tonic::Status> {
        let req = request.into_inner();
        let req: requests::DevforgetchannelRequest = req.into();
        debug!("Client asked for dev_forget_channel");
        trace!("dev_forget_channel request: {:?}", req);
        let mut rpc = ClnRpc::new(&self.rpc_path)
            .await
            .map_err(|e| Status::new(Code::Internal, e.to_string()))?;
        let result = rpc.call(Request::DevForgetChannel(req))
            .await
            .map_err(|e| Status::new(
               Code::Unknown,
               format!("Error calling method DevForgetChannel: {:?}", e)))?;
        match result {
            Response::DevForgetChannel(r) => {
               trace!("dev_forget_channel response: {:?}", r);
               Ok(tonic::Response::new(r.into()))
            },
            r => Err(Status::new(
                Code::Internal,
                format!(
                    "Unexpected result {:?} to method call DevForgetChannel",
                    r
                )
            )),
        }

    }

    async fn emergency_recover(
        &self,
        request: tonic::Request<pb::EmergencyrecoverRequest>,
    ) -> Result<tonic::Response<pb::EmergencyrecoverResponse>, tonic::Status> {
        let req = request.into_inner();
        let req: requests::EmergencyrecoverRequest = req.into();
        debug!("Client asked for emergency_recover");
        trace!("emergency_recover request: {:?}", req);
        let mut rpc = ClnRpc::new(&self.rpc_path)
            .await
            .map_err(|e| Status::new(Code::Internal, e.to_string()))?;
        let result = rpc.call(Request::EmergencyRecover(req))
            .await
            .map_err(|e| Status::new(
               Code::Unknown,
               format!("Error calling method EmergencyRecover: {:?}", e)))?;
        match result {
            Response::EmergencyRecover(r) => {
               trace!("emergency_recover response: {:?}", r);
               Ok(tonic::Response::new(r.into()))
            },
            r => Err(Status::new(
                Code::Internal,
                format!(
                    "Unexpected result {:?} to method call EmergencyRecover",
                    r
                )
            )),
        }

    }

    async fn get_emergency_recover_data(
        &self,
        request: tonic::Request<pb::GetemergencyrecoverdataRequest>,
    ) -> Result<tonic::Response<pb::GetemergencyrecoverdataResponse>, tonic::Status> {
        let req = request.into_inner();
        let req: requests::GetemergencyrecoverdataRequest = req.into();
        debug!("Client asked for get_emergency_recover_data");
        trace!("get_emergency_recover_data request: {:?}", req);
        let mut rpc = ClnRpc::new(&self.rpc_path)
            .await
            .map_err(|e| Status::new(Code::Internal, e.to_string()))?;
        let result = rpc.call(Request::GetEmergencyRecoverData(req))
            .await
            .map_err(|e| Status::new(
               Code::Unknown,
               format!("Error calling method GetEmergencyRecoverData: {:?}", e)))?;
        match result {
            Response::GetEmergencyRecoverData(r) => {
               trace!("get_emergency_recover_data response: {:?}", r);
               Ok(tonic::Response::new(r.into()))
            },
            r => Err(Status::new(
                Code::Internal,
                format!(
                    "Unexpected result {:?} to method call GetEmergencyRecoverData",
                    r
                )
            )),
        }

    }

    async fn expose_secret(
        &self,
        request: tonic::Request<pb::ExposesecretRequest>,
    ) -> Result<tonic::Response<pb::ExposesecretResponse>, tonic::Status> {
        let req = request.into_inner();
        let req: requests::ExposesecretRequest = req.into();
        debug!("Client asked for expose_secret");
        trace!("expose_secret request: {:?}", req);
        let mut rpc = ClnRpc::new(&self.rpc_path)
            .await
            .map_err(|e| Status::new(Code::Internal, e.to_string()))?;
        let result = rpc.call(Request::ExposeSecret(req))
            .await
            .map_err(|e| Status::new(
               Code::Unknown,
               format!("Error calling method ExposeSecret: {:?}", e)))?;
        match result {
            Response::ExposeSecret(r) => {
               trace!("expose_secret response: {:?}", r);
               Ok(tonic::Response::new(r.into()))
            },
            r => Err(Status::new(
                Code::Internal,
                format!(
                    "Unexpected result {:?} to method call ExposeSecret",
                    r
                )
            )),
        }

    }

    async fn recover(
        &self,
        request: tonic::Request<pb::RecoverRequest>,
    ) -> Result<tonic::Response<pb::RecoverResponse>, tonic::Status> {
        let req = request.into_inner();
        let req: requests::RecoverRequest = req.into();
        debug!("Client asked for recover");
        trace!("recover request: {:?}", req);
        let mut rpc = ClnRpc::new(&self.rpc_path)
            .await
            .map_err(|e| Status::new(Code::Internal, e.to_string()))?;
        let result = rpc.call(Request::Recover(req))
            .await
            .map_err(|e| Status::new(
               Code::Unknown,
               format!("Error calling method Recover: {:?}", e)))?;
        match result {
            Response::Recover(r) => {
               trace!("recover response: {:?}", r);
               Ok(tonic::Response::new(r.into()))
            },
            r => Err(Status::new(
                Code::Internal,
                format!(
                    "Unexpected result {:?} to method call Recover",
                    r
                )
            )),
        }

    }

    async fn recover_channel(
        &self,
        request: tonic::Request<pb::RecoverchannelRequest>,
    ) -> Result<tonic::Response<pb::RecoverchannelResponse>, tonic::Status> {
        let req = request.into_inner();
        let req: requests::RecoverchannelRequest = req.into();
        debug!("Client asked for recover_channel");
        trace!("recover_channel request: {:?}", req);
        let mut rpc = ClnRpc::new(&self.rpc_path)
            .await
            .map_err(|e| Status::new(Code::Internal, e.to_string()))?;
        let result = rpc.call(Request::RecoverChannel(req))
            .await
            .map_err(|e| Status::new(
               Code::Unknown,
               format!("Error calling method RecoverChannel: {:?}", e)))?;
        match result {
            Response::RecoverChannel(r) => {
               trace!("recover_channel response: {:?}", r);
               Ok(tonic::Response::new(r.into()))
            },
            r => Err(Status::new(
                Code::Internal,
                format!(
                    "Unexpected result {:?} to method call RecoverChannel",
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

    async fn create_invoice_request(
        &self,
        request: tonic::Request<pb::InvoicerequestRequest>,
    ) -> Result<tonic::Response<pb::InvoicerequestResponse>, tonic::Status> {
        let req = request.into_inner();
        let req: requests::InvoicerequestRequest = req.into();
        debug!("Client asked for create_invoice_request");
        trace!("create_invoice_request request: {:?}", req);
        let mut rpc = ClnRpc::new(&self.rpc_path)
            .await
            .map_err(|e| Status::new(Code::Internal, e.to_string()))?;
        let result = rpc.call(Request::InvoiceRequest(req))
            .await
            .map_err(|e| Status::new(
               Code::Unknown,
               format!("Error calling method InvoiceRequest: {:?}", e)))?;
        match result {
            Response::InvoiceRequest(r) => {
               trace!("create_invoice_request response: {:?}", r);
               Ok(tonic::Response::new(r.into()))
            },
            r => Err(Status::new(
                Code::Internal,
                format!(
                    "Unexpected result {:?} to method call InvoiceRequest",
                    r
                )
            )),
        }

    }

    async fn disable_invoice_request(
        &self,
        request: tonic::Request<pb::DisableinvoicerequestRequest>,
    ) -> Result<tonic::Response<pb::DisableinvoicerequestResponse>, tonic::Status> {
        let req = request.into_inner();
        let req: requests::DisableinvoicerequestRequest = req.into();
        debug!("Client asked for disable_invoice_request");
        trace!("disable_invoice_request request: {:?}", req);
        let mut rpc = ClnRpc::new(&self.rpc_path)
            .await
            .map_err(|e| Status::new(Code::Internal, e.to_string()))?;
        let result = rpc.call(Request::DisableInvoiceRequest(req))
            .await
            .map_err(|e| Status::new(
               Code::Unknown,
               format!("Error calling method DisableInvoiceRequest: {:?}", e)))?;
        match result {
            Response::DisableInvoiceRequest(r) => {
               trace!("disable_invoice_request response: {:?}", r);
               Ok(tonic::Response::new(r.into()))
            },
            r => Err(Status::new(
                Code::Internal,
                format!(
                    "Unexpected result {:?} to method call DisableInvoiceRequest",
                    r
                )
            )),
        }

    }

    async fn list_invoice_requests(
        &self,
        request: tonic::Request<pb::ListinvoicerequestsRequest>,
    ) -> Result<tonic::Response<pb::ListinvoicerequestsResponse>, tonic::Status> {
        let req = request.into_inner();
        let req: requests::ListinvoicerequestsRequest = req.into();
        debug!("Client asked for list_invoice_requests");
        trace!("list_invoice_requests request: {:?}", req);
        let mut rpc = ClnRpc::new(&self.rpc_path)
            .await
            .map_err(|e| Status::new(Code::Internal, e.to_string()))?;
        let result = rpc.call(Request::ListInvoiceRequests(req))
            .await
            .map_err(|e| Status::new(
               Code::Unknown,
               format!("Error calling method ListInvoiceRequests: {:?}", e)))?;
        match result {
            Response::ListInvoiceRequests(r) => {
               trace!("list_invoice_requests response: {:?}", r);
               Ok(tonic::Response::new(r.into()))
            },
            r => Err(Status::new(
                Code::Internal,
                format!(
                    "Unexpected result {:?} to method call ListInvoiceRequests",
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

    async fn make_secret(
        &self,
        request: tonic::Request<pb::MakesecretRequest>,
    ) -> Result<tonic::Response<pb::MakesecretResponse>, tonic::Status> {
        let req = request.into_inner();
        let req: requests::MakesecretRequest = req.into();
        debug!("Client asked for make_secret");
        trace!("make_secret request: {:?}", req);
        let mut rpc = ClnRpc::new(&self.rpc_path)
            .await
            .map_err(|e| Status::new(Code::Internal, e.to_string()))?;
        let result = rpc.call(Request::MakeSecret(req))
            .await
            .map_err(|e| Status::new(
               Code::Unknown,
               format!("Error calling method MakeSecret: {:?}", e)))?;
        match result {
            Response::MakeSecret(r) => {
               trace!("make_secret response: {:?}", r);
               Ok(tonic::Response::new(r.into()))
            },
            r => Err(Status::new(
                Code::Internal,
                format!(
                    "Unexpected result {:?} to method call MakeSecret",
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

    async fn del_pay(
        &self,
        request: tonic::Request<pb::DelpayRequest>,
    ) -> Result<tonic::Response<pb::DelpayResponse>, tonic::Status> {
        let req = request.into_inner();
        let req: requests::DelpayRequest = req.into();
        debug!("Client asked for del_pay");
        trace!("del_pay request: {:?}", req);
        let mut rpc = ClnRpc::new(&self.rpc_path)
            .await
            .map_err(|e| Status::new(Code::Internal, e.to_string()))?;
        let result = rpc.call(Request::DelPay(req))
            .await
            .map_err(|e| Status::new(
               Code::Unknown,
               format!("Error calling method DelPay: {:?}", e)))?;
        match result {
            Response::DelPay(r) => {
               trace!("del_pay response: {:?}", r);
               Ok(tonic::Response::new(r.into()))
            },
            r => Err(Status::new(
                Code::Internal,
                format!(
                    "Unexpected result {:?} to method call DelPay",
                    r
                )
            )),
        }

    }

    async fn del_forward(
        &self,
        request: tonic::Request<pb::DelforwardRequest>,
    ) -> Result<tonic::Response<pb::DelforwardResponse>, tonic::Status> {
        let req = request.into_inner();
        let req: requests::DelforwardRequest = req.into();
        debug!("Client asked for del_forward");
        trace!("del_forward request: {:?}", req);
        let mut rpc = ClnRpc::new(&self.rpc_path)
            .await
            .map_err(|e| Status::new(Code::Internal, e.to_string()))?;
        let result = rpc.call(Request::DelForward(req))
            .await
            .map_err(|e| Status::new(
               Code::Unknown,
               format!("Error calling method DelForward: {:?}", e)))?;
        match result {
            Response::DelForward(r) => {
               trace!("del_forward response: {:?}", r);
               Ok(tonic::Response::new(r.into()))
            },
            r => Err(Status::new(
                Code::Internal,
                format!(
                    "Unexpected result {:?} to method call DelForward",
                    r
                )
            )),
        }

    }

    async fn disable_offer(
        &self,
        request: tonic::Request<pb::DisableofferRequest>,
    ) -> Result<tonic::Response<pb::DisableofferResponse>, tonic::Status> {
        let req = request.into_inner();
        let req: requests::DisableofferRequest = req.into();
        debug!("Client asked for disable_offer");
        trace!("disable_offer request: {:?}", req);
        let mut rpc = ClnRpc::new(&self.rpc_path)
            .await
            .map_err(|e| Status::new(Code::Internal, e.to_string()))?;
        let result = rpc.call(Request::DisableOffer(req))
            .await
            .map_err(|e| Status::new(
               Code::Unknown,
               format!("Error calling method DisableOffer: {:?}", e)))?;
        match result {
            Response::DisableOffer(r) => {
               trace!("disable_offer response: {:?}", r);
               Ok(tonic::Response::new(r.into()))
            },
            r => Err(Status::new(
                Code::Internal,
                format!(
                    "Unexpected result {:?} to method call DisableOffer",
                    r
                )
            )),
        }

    }

    async fn enable_offer(
        &self,
        request: tonic::Request<pb::EnableofferRequest>,
    ) -> Result<tonic::Response<pb::EnableofferResponse>, tonic::Status> {
        let req = request.into_inner();
        let req: requests::EnableofferRequest = req.into();
        debug!("Client asked for enable_offer");
        trace!("enable_offer request: {:?}", req);
        let mut rpc = ClnRpc::new(&self.rpc_path)
            .await
            .map_err(|e| Status::new(Code::Internal, e.to_string()))?;
        let result = rpc.call(Request::EnableOffer(req))
            .await
            .map_err(|e| Status::new(
               Code::Unknown,
               format!("Error calling method EnableOffer: {:?}", e)))?;
        match result {
            Response::EnableOffer(r) => {
               trace!("enable_offer response: {:?}", r);
               Ok(tonic::Response::new(r.into()))
            },
            r => Err(Status::new(
                Code::Internal,
                format!(
                    "Unexpected result {:?} to method call EnableOffer",
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

    async fn fund_channel_cancel(
        &self,
        request: tonic::Request<pb::FundchannelCancelRequest>,
    ) -> Result<tonic::Response<pb::FundchannelCancelResponse>, tonic::Status> {
        let req = request.into_inner();
        let req: requests::FundchannelCancelRequest = req.into();
        debug!("Client asked for fund_channel_cancel");
        trace!("fund_channel_cancel request: {:?}", req);
        let mut rpc = ClnRpc::new(&self.rpc_path)
            .await
            .map_err(|e| Status::new(Code::Internal, e.to_string()))?;
        let result = rpc.call(Request::FundChannelCancel(req))
            .await
            .map_err(|e| Status::new(
               Code::Unknown,
               format!("Error calling method FundChannelCancel: {:?}", e)))?;
        match result {
            Response::FundChannelCancel(r) => {
               trace!("fund_channel_cancel response: {:?}", r);
               Ok(tonic::Response::new(r.into()))
            },
            r => Err(Status::new(
                Code::Internal,
                format!(
                    "Unexpected result {:?} to method call FundChannelCancel",
                    r
                )
            )),
        }

    }

    async fn fund_channel_complete(
        &self,
        request: tonic::Request<pb::FundchannelCompleteRequest>,
    ) -> Result<tonic::Response<pb::FundchannelCompleteResponse>, tonic::Status> {
        let req = request.into_inner();
        let req: requests::FundchannelCompleteRequest = req.into();
        debug!("Client asked for fund_channel_complete");
        trace!("fund_channel_complete request: {:?}", req);
        let mut rpc = ClnRpc::new(&self.rpc_path)
            .await
            .map_err(|e| Status::new(Code::Internal, e.to_string()))?;
        let result = rpc.call(Request::FundChannelComplete(req))
            .await
            .map_err(|e| Status::new(
               Code::Unknown,
               format!("Error calling method FundChannelComplete: {:?}", e)))?;
        match result {
            Response::FundChannelComplete(r) => {
               trace!("fund_channel_complete response: {:?}", r);
               Ok(tonic::Response::new(r.into()))
            },
            r => Err(Status::new(
                Code::Internal,
                format!(
                    "Unexpected result {:?} to method call FundChannelComplete",
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

    async fn fund_channel_start(
        &self,
        request: tonic::Request<pb::FundchannelStartRequest>,
    ) -> Result<tonic::Response<pb::FundchannelStartResponse>, tonic::Status> {
        let req = request.into_inner();
        let req: requests::FundchannelStartRequest = req.into();
        debug!("Client asked for fund_channel_start");
        trace!("fund_channel_start request: {:?}", req);
        let mut rpc = ClnRpc::new(&self.rpc_path)
            .await
            .map_err(|e| Status::new(Code::Internal, e.to_string()))?;
        let result = rpc.call(Request::FundChannelStart(req))
            .await
            .map_err(|e| Status::new(
               Code::Unknown,
               format!("Error calling method FundChannelStart: {:?}", e)))?;
        match result {
            Response::FundChannelStart(r) => {
               trace!("fund_channel_start response: {:?}", r);
               Ok(tonic::Response::new(r.into()))
            },
            r => Err(Status::new(
                Code::Internal,
                format!(
                    "Unexpected result {:?} to method call FundChannelStart",
                    r
                )
            )),
        }

    }

    async fn get_log(
        &self,
        request: tonic::Request<pb::GetlogRequest>,
    ) -> Result<tonic::Response<pb::GetlogResponse>, tonic::Status> {
        let req = request.into_inner();
        let req: requests::GetlogRequest = req.into();
        debug!("Client asked for get_log");
        trace!("get_log request: {:?}", req);
        let mut rpc = ClnRpc::new(&self.rpc_path)
            .await
            .map_err(|e| Status::new(Code::Internal, e.to_string()))?;
        let result = rpc.call(Request::GetLog(req))
            .await
            .map_err(|e| Status::new(
               Code::Unknown,
               format!("Error calling method GetLog: {:?}", e)))?;
        match result {
            Response::GetLog(r) => {
               trace!("get_log response: {:?}", r);
               Ok(tonic::Response::new(r.into()))
            },
            r => Err(Status::new(
                Code::Internal,
                format!(
                    "Unexpected result {:?} to method call GetLog",
                    r
                )
            )),
        }

    }

    async fn funder_update(
        &self,
        request: tonic::Request<pb::FunderupdateRequest>,
    ) -> Result<tonic::Response<pb::FunderupdateResponse>, tonic::Status> {
        let req = request.into_inner();
        let req: requests::FunderupdateRequest = req.into();
        debug!("Client asked for funder_update");
        trace!("funder_update request: {:?}", req);
        let mut rpc = ClnRpc::new(&self.rpc_path)
            .await
            .map_err(|e| Status::new(Code::Internal, e.to_string()))?;
        let result = rpc.call(Request::FunderUpdate(req))
            .await
            .map_err(|e| Status::new(
               Code::Unknown,
               format!("Error calling method FunderUpdate: {:?}", e)))?;
        match result {
            Response::FunderUpdate(r) => {
               trace!("funder_update response: {:?}", r);
               Ok(tonic::Response::new(r.into()))
            },
            r => Err(Status::new(
                Code::Internal,
                format!(
                    "Unexpected result {:?} to method call FunderUpdate",
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

    async fn list_addresses(
        &self,
        request: tonic::Request<pb::ListaddressesRequest>,
    ) -> Result<tonic::Response<pb::ListaddressesResponse>, tonic::Status> {
        let req = request.into_inner();
        let req: requests::ListaddressesRequest = req.into();
        debug!("Client asked for list_addresses");
        trace!("list_addresses request: {:?}", req);
        let mut rpc = ClnRpc::new(&self.rpc_path)
            .await
            .map_err(|e| Status::new(Code::Internal, e.to_string()))?;
        let result = rpc.call(Request::ListAddresses(req))
            .await
            .map_err(|e| Status::new(
               Code::Unknown,
               format!("Error calling method ListAddresses: {:?}", e)))?;
        match result {
            Response::ListAddresses(r) => {
               trace!("list_addresses response: {:?}", r);
               Ok(tonic::Response::new(r.into()))
            },
            r => Err(Status::new(
                Code::Internal,
                format!(
                    "Unexpected result {:?} to method call ListAddresses",
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

    async fn list_offers(
        &self,
        request: tonic::Request<pb::ListoffersRequest>,
    ) -> Result<tonic::Response<pb::ListoffersResponse>, tonic::Status> {
        let req = request.into_inner();
        let req: requests::ListoffersRequest = req.into();
        debug!("Client asked for list_offers");
        trace!("list_offers request: {:?}", req);
        let mut rpc = ClnRpc::new(&self.rpc_path)
            .await
            .map_err(|e| Status::new(Code::Internal, e.to_string()))?;
        let result = rpc.call(Request::ListOffers(req))
            .await
            .map_err(|e| Status::new(
               Code::Unknown,
               format!("Error calling method ListOffers: {:?}", e)))?;
        match result {
            Response::ListOffers(r) => {
               trace!("list_offers response: {:?}", r);
               Ok(tonic::Response::new(r.into()))
            },
            r => Err(Status::new(
                Code::Internal,
                format!(
                    "Unexpected result {:?} to method call ListOffers",
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

    async fn multi_fund_channel(
        &self,
        request: tonic::Request<pb::MultifundchannelRequest>,
    ) -> Result<tonic::Response<pb::MultifundchannelResponse>, tonic::Status> {
        let req = request.into_inner();
        let req: requests::MultifundchannelRequest = req.into();
        debug!("Client asked for multi_fund_channel");
        trace!("multi_fund_channel request: {:?}", req);
        let mut rpc = ClnRpc::new(&self.rpc_path)
            .await
            .map_err(|e| Status::new(Code::Internal, e.to_string()))?;
        let result = rpc.call(Request::MultiFundChannel(req))
            .await
            .map_err(|e| Status::new(
               Code::Unknown,
               format!("Error calling method MultiFundChannel: {:?}", e)))?;
        match result {
            Response::MultiFundChannel(r) => {
               trace!("multi_fund_channel response: {:?}", r);
               Ok(tonic::Response::new(r.into()))
            },
            r => Err(Status::new(
                Code::Internal,
                format!(
                    "Unexpected result {:?} to method call MultiFundChannel",
                    r
                )
            )),
        }

    }

    async fn multi_withdraw(
        &self,
        request: tonic::Request<pb::MultiwithdrawRequest>,
    ) -> Result<tonic::Response<pb::MultiwithdrawResponse>, tonic::Status> {
        let req = request.into_inner();
        let req: requests::MultiwithdrawRequest = req.into();
        debug!("Client asked for multi_withdraw");
        trace!("multi_withdraw request: {:?}", req);
        let mut rpc = ClnRpc::new(&self.rpc_path)
            .await
            .map_err(|e| Status::new(Code::Internal, e.to_string()))?;
        let result = rpc.call(Request::MultiWithdraw(req))
            .await
            .map_err(|e| Status::new(
               Code::Unknown,
               format!("Error calling method MultiWithdraw: {:?}", e)))?;
        match result {
            Response::MultiWithdraw(r) => {
               trace!("multi_withdraw response: {:?}", r);
               Ok(tonic::Response::new(r.into()))
            },
            r => Err(Status::new(
                Code::Internal,
                format!(
                    "Unexpected result {:?} to method call MultiWithdraw",
                    r
                )
            )),
        }

    }

    async fn offer(
        &self,
        request: tonic::Request<pb::OfferRequest>,
    ) -> Result<tonic::Response<pb::OfferResponse>, tonic::Status> {
        let req = request.into_inner();
        let req: requests::OfferRequest = req.into();
        debug!("Client asked for offer");
        trace!("offer request: {:?}", req);
        let mut rpc = ClnRpc::new(&self.rpc_path)
            .await
            .map_err(|e| Status::new(Code::Internal, e.to_string()))?;
        let result = rpc.call(Request::Offer(req))
            .await
            .map_err(|e| Status::new(
               Code::Unknown,
               format!("Error calling method Offer: {:?}", e)))?;
        match result {
            Response::Offer(r) => {
               trace!("offer response: {:?}", r);
               Ok(tonic::Response::new(r.into()))
            },
            r => Err(Status::new(
                Code::Internal,
                format!(
                    "Unexpected result {:?} to method call Offer",
                    r
                )
            )),
        }

    }

    async fn open_channel_abort(
        &self,
        request: tonic::Request<pb::OpenchannelAbortRequest>,
    ) -> Result<tonic::Response<pb::OpenchannelAbortResponse>, tonic::Status> {
        let req = request.into_inner();
        let req: requests::OpenchannelAbortRequest = req.into();
        debug!("Client asked for open_channel_abort");
        trace!("open_channel_abort request: {:?}", req);
        let mut rpc = ClnRpc::new(&self.rpc_path)
            .await
            .map_err(|e| Status::new(Code::Internal, e.to_string()))?;
        let result = rpc.call(Request::OpenChannelAbort(req))
            .await
            .map_err(|e| Status::new(
               Code::Unknown,
               format!("Error calling method OpenChannelAbort: {:?}", e)))?;
        match result {
            Response::OpenChannelAbort(r) => {
               trace!("open_channel_abort response: {:?}", r);
               Ok(tonic::Response::new(r.into()))
            },
            r => Err(Status::new(
                Code::Internal,
                format!(
                    "Unexpected result {:?} to method call OpenChannelAbort",
                    r
                )
            )),
        }

    }

    async fn open_channel_bump(
        &self,
        request: tonic::Request<pb::OpenchannelBumpRequest>,
    ) -> Result<tonic::Response<pb::OpenchannelBumpResponse>, tonic::Status> {
        let req = request.into_inner();
        let req: requests::OpenchannelBumpRequest = req.into();
        debug!("Client asked for open_channel_bump");
        trace!("open_channel_bump request: {:?}", req);
        let mut rpc = ClnRpc::new(&self.rpc_path)
            .await
            .map_err(|e| Status::new(Code::Internal, e.to_string()))?;
        let result = rpc.call(Request::OpenChannelBump(req))
            .await
            .map_err(|e| Status::new(
               Code::Unknown,
               format!("Error calling method OpenChannelBump: {:?}", e)))?;
        match result {
            Response::OpenChannelBump(r) => {
               trace!("open_channel_bump response: {:?}", r);
               Ok(tonic::Response::new(r.into()))
            },
            r => Err(Status::new(
                Code::Internal,
                format!(
                    "Unexpected result {:?} to method call OpenChannelBump",
                    r
                )
            )),
        }

    }

    async fn open_channel_init(
        &self,
        request: tonic::Request<pb::OpenchannelInitRequest>,
    ) -> Result<tonic::Response<pb::OpenchannelInitResponse>, tonic::Status> {
        let req = request.into_inner();
        let req: requests::OpenchannelInitRequest = req.into();
        debug!("Client asked for open_channel_init");
        trace!("open_channel_init request: {:?}", req);
        let mut rpc = ClnRpc::new(&self.rpc_path)
            .await
            .map_err(|e| Status::new(Code::Internal, e.to_string()))?;
        let result = rpc.call(Request::OpenChannelInit(req))
            .await
            .map_err(|e| Status::new(
               Code::Unknown,
               format!("Error calling method OpenChannelInit: {:?}", e)))?;
        match result {
            Response::OpenChannelInit(r) => {
               trace!("open_channel_init response: {:?}", r);
               Ok(tonic::Response::new(r.into()))
            },
            r => Err(Status::new(
                Code::Internal,
                format!(
                    "Unexpected result {:?} to method call OpenChannelInit",
                    r
                )
            )),
        }

    }

    async fn open_channel_signed(
        &self,
        request: tonic::Request<pb::OpenchannelSignedRequest>,
    ) -> Result<tonic::Response<pb::OpenchannelSignedResponse>, tonic::Status> {
        let req = request.into_inner();
        let req: requests::OpenchannelSignedRequest = req.into();
        debug!("Client asked for open_channel_signed");
        trace!("open_channel_signed request: {:?}", req);
        let mut rpc = ClnRpc::new(&self.rpc_path)
            .await
            .map_err(|e| Status::new(Code::Internal, e.to_string()))?;
        let result = rpc.call(Request::OpenChannelSigned(req))
            .await
            .map_err(|e| Status::new(
               Code::Unknown,
               format!("Error calling method OpenChannelSigned: {:?}", e)))?;
        match result {
            Response::OpenChannelSigned(r) => {
               trace!("open_channel_signed response: {:?}", r);
               Ok(tonic::Response::new(r.into()))
            },
            r => Err(Status::new(
                Code::Internal,
                format!(
                    "Unexpected result {:?} to method call OpenChannelSigned",
                    r
                )
            )),
        }

    }

    async fn open_channel_update(
        &self,
        request: tonic::Request<pb::OpenchannelUpdateRequest>,
    ) -> Result<tonic::Response<pb::OpenchannelUpdateResponse>, tonic::Status> {
        let req = request.into_inner();
        let req: requests::OpenchannelUpdateRequest = req.into();
        debug!("Client asked for open_channel_update");
        trace!("open_channel_update request: {:?}", req);
        let mut rpc = ClnRpc::new(&self.rpc_path)
            .await
            .map_err(|e| Status::new(Code::Internal, e.to_string()))?;
        let result = rpc.call(Request::OpenChannelUpdate(req))
            .await
            .map_err(|e| Status::new(
               Code::Unknown,
               format!("Error calling method OpenChannelUpdate: {:?}", e)))?;
        match result {
            Response::OpenChannelUpdate(r) => {
               trace!("open_channel_update response: {:?}", r);
               Ok(tonic::Response::new(r.into()))
            },
            r => Err(Status::new(
                Code::Internal,
                format!(
                    "Unexpected result {:?} to method call OpenChannelUpdate",
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

    async fn plugin(
        &self,
        request: tonic::Request<pb::PluginRequest>,
    ) -> Result<tonic::Response<pb::PluginResponse>, tonic::Status> {
        let req = request.into_inner();
        let req: requests::PluginRequest = req.into();
        debug!("Client asked for plugin");
        trace!("plugin request: {:?}", req);
        let mut rpc = ClnRpc::new(&self.rpc_path)
            .await
            .map_err(|e| Status::new(Code::Internal, e.to_string()))?;
        let result = rpc.call(Request::Plugin(req))
            .await
            .map_err(|e| Status::new(
               Code::Unknown,
               format!("Error calling method Plugin: {:?}", e)))?;
        match result {
            Response::Plugin(r) => {
               trace!("plugin response: {:?}", r);
               Ok(tonic::Response::new(r.into()))
            },
            r => Err(Status::new(
                Code::Internal,
                format!(
                    "Unexpected result {:?} to method call Plugin",
                    r
                )
            )),
        }

    }

    async fn rene_pay_status(
        &self,
        request: tonic::Request<pb::RenepaystatusRequest>,
    ) -> Result<tonic::Response<pb::RenepaystatusResponse>, tonic::Status> {
        let req = request.into_inner();
        let req: requests::RenepaystatusRequest = req.into();
        debug!("Client asked for rene_pay_status");
        trace!("rene_pay_status request: {:?}", req);
        let mut rpc = ClnRpc::new(&self.rpc_path)
            .await
            .map_err(|e| Status::new(Code::Internal, e.to_string()))?;
        let result = rpc.call(Request::RenePayStatus(req))
            .await
            .map_err(|e| Status::new(
               Code::Unknown,
               format!("Error calling method RenePayStatus: {:?}", e)))?;
        match result {
            Response::RenePayStatus(r) => {
               trace!("rene_pay_status response: {:?}", r);
               Ok(tonic::Response::new(r.into()))
            },
            r => Err(Status::new(
                Code::Internal,
                format!(
                    "Unexpected result {:?} to method call RenePayStatus",
                    r
                )
            )),
        }

    }

    async fn rene_pay(
        &self,
        request: tonic::Request<pb::RenepayRequest>,
    ) -> Result<tonic::Response<pb::RenepayResponse>, tonic::Status> {
        let req = request.into_inner();
        let req: requests::RenepayRequest = req.into();
        debug!("Client asked for rene_pay");
        trace!("rene_pay request: {:?}", req);
        let mut rpc = ClnRpc::new(&self.rpc_path)
            .await
            .map_err(|e| Status::new(Code::Internal, e.to_string()))?;
        let result = rpc.call(Request::RenePay(req))
            .await
            .map_err(|e| Status::new(
               Code::Unknown,
               format!("Error calling method RenePay: {:?}", e)))?;
        match result {
            Response::RenePay(r) => {
               trace!("rene_pay response: {:?}", r);
               Ok(tonic::Response::new(r.into()))
            },
            r => Err(Status::new(
                Code::Internal,
                format!(
                    "Unexpected result {:?} to method call RenePay",
                    r
                )
            )),
        }

    }

    async fn reserve_inputs(
        &self,
        request: tonic::Request<pb::ReserveinputsRequest>,
    ) -> Result<tonic::Response<pb::ReserveinputsResponse>, tonic::Status> {
        let req = request.into_inner();
        let req: requests::ReserveinputsRequest = req.into();
        debug!("Client asked for reserve_inputs");
        trace!("reserve_inputs request: {:?}", req);
        let mut rpc = ClnRpc::new(&self.rpc_path)
            .await
            .map_err(|e| Status::new(Code::Internal, e.to_string()))?;
        let result = rpc.call(Request::ReserveInputs(req))
            .await
            .map_err(|e| Status::new(
               Code::Unknown,
               format!("Error calling method ReserveInputs: {:?}", e)))?;
        match result {
            Response::ReserveInputs(r) => {
               trace!("reserve_inputs response: {:?}", r);
               Ok(tonic::Response::new(r.into()))
            },
            r => Err(Status::new(
                Code::Internal,
                format!(
                    "Unexpected result {:?} to method call ReserveInputs",
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

    async fn send_invoice(
        &self,
        request: tonic::Request<pb::SendinvoiceRequest>,
    ) -> Result<tonic::Response<pb::SendinvoiceResponse>, tonic::Status> {
        let req = request.into_inner();
        let req: requests::SendinvoiceRequest = req.into();
        debug!("Client asked for send_invoice");
        trace!("send_invoice request: {:?}", req);
        let mut rpc = ClnRpc::new(&self.rpc_path)
            .await
            .map_err(|e| Status::new(Code::Internal, e.to_string()))?;
        let result = rpc.call(Request::SendInvoice(req))
            .await
            .map_err(|e| Status::new(
               Code::Unknown,
               format!("Error calling method SendInvoice: {:?}", e)))?;
        match result {
            Response::SendInvoice(r) => {
               trace!("send_invoice response: {:?}", r);
               Ok(tonic::Response::new(r.into()))
            },
            r => Err(Status::new(
                Code::Internal,
                format!(
                    "Unexpected result {:?} to method call SendInvoice",
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

    async fn set_config(
        &self,
        request: tonic::Request<pb::SetconfigRequest>,
    ) -> Result<tonic::Response<pb::SetconfigResponse>, tonic::Status> {
        let req = request.into_inner();
        let req: requests::SetconfigRequest = req.into();
        debug!("Client asked for set_config");
        trace!("set_config request: {:?}", req);
        let mut rpc = ClnRpc::new(&self.rpc_path)
            .await
            .map_err(|e| Status::new(Code::Internal, e.to_string()))?;
        let result = rpc.call(Request::SetConfig(req))
            .await
            .map_err(|e| Status::new(
               Code::Unknown,
               format!("Error calling method SetConfig: {:?}", e)))?;
        match result {
            Response::SetConfig(r) => {
               trace!("set_config response: {:?}", r);
               Ok(tonic::Response::new(r.into()))
            },
            r => Err(Status::new(
                Code::Internal,
                format!(
                    "Unexpected result {:?} to method call SetConfig",
                    r
                )
            )),
        }

    }

    async fn set_psbt_version(
        &self,
        request: tonic::Request<pb::SetpsbtversionRequest>,
    ) -> Result<tonic::Response<pb::SetpsbtversionResponse>, tonic::Status> {
        let req = request.into_inner();
        let req: requests::SetpsbtversionRequest = req.into();
        debug!("Client asked for set_psbt_version");
        trace!("set_psbt_version request: {:?}", req);
        let mut rpc = ClnRpc::new(&self.rpc_path)
            .await
            .map_err(|e| Status::new(Code::Internal, e.to_string()))?;
        let result = rpc.call(Request::SetPsbtVersion(req))
            .await
            .map_err(|e| Status::new(
               Code::Unknown,
               format!("Error calling method SetPsbtVersion: {:?}", e)))?;
        match result {
            Response::SetPsbtVersion(r) => {
               trace!("set_psbt_version response: {:?}", r);
               Ok(tonic::Response::new(r.into()))
            },
            r => Err(Status::new(
                Code::Internal,
                format!(
                    "Unexpected result {:?} to method call SetPsbtVersion",
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

    async fn splice_init(
        &self,
        request: tonic::Request<pb::SpliceInitRequest>,
    ) -> Result<tonic::Response<pb::SpliceInitResponse>, tonic::Status> {
        let req = request.into_inner();
        let req: requests::SpliceInitRequest = req.into();
        debug!("Client asked for splice_init");
        trace!("splice_init request: {:?}", req);
        let mut rpc = ClnRpc::new(&self.rpc_path)
            .await
            .map_err(|e| Status::new(Code::Internal, e.to_string()))?;
        let result = rpc.call(Request::SpliceInit(req))
            .await
            .map_err(|e| Status::new(
               Code::Unknown,
               format!("Error calling method SpliceInit: {:?}", e)))?;
        match result {
            Response::SpliceInit(r) => {
               trace!("splice_init response: {:?}", r);
               Ok(tonic::Response::new(r.into()))
            },
            r => Err(Status::new(
                Code::Internal,
                format!(
                    "Unexpected result {:?} to method call SpliceInit",
                    r
                )
            )),
        }

    }

    async fn splice_signed(
        &self,
        request: tonic::Request<pb::SpliceSignedRequest>,
    ) -> Result<tonic::Response<pb::SpliceSignedResponse>, tonic::Status> {
        let req = request.into_inner();
        let req: requests::SpliceSignedRequest = req.into();
        debug!("Client asked for splice_signed");
        trace!("splice_signed request: {:?}", req);
        let mut rpc = ClnRpc::new(&self.rpc_path)
            .await
            .map_err(|e| Status::new(Code::Internal, e.to_string()))?;
        let result = rpc.call(Request::SpliceSigned(req))
            .await
            .map_err(|e| Status::new(
               Code::Unknown,
               format!("Error calling method SpliceSigned: {:?}", e)))?;
        match result {
            Response::SpliceSigned(r) => {
               trace!("splice_signed response: {:?}", r);
               Ok(tonic::Response::new(r.into()))
            },
            r => Err(Status::new(
                Code::Internal,
                format!(
                    "Unexpected result {:?} to method call SpliceSigned",
                    r
                )
            )),
        }

    }

    async fn splice_update(
        &self,
        request: tonic::Request<pb::SpliceUpdateRequest>,
    ) -> Result<tonic::Response<pb::SpliceUpdateResponse>, tonic::Status> {
        let req = request.into_inner();
        let req: requests::SpliceUpdateRequest = req.into();
        debug!("Client asked for splice_update");
        trace!("splice_update request: {:?}", req);
        let mut rpc = ClnRpc::new(&self.rpc_path)
            .await
            .map_err(|e| Status::new(Code::Internal, e.to_string()))?;
        let result = rpc.call(Request::SpliceUpdate(req))
            .await
            .map_err(|e| Status::new(
               Code::Unknown,
               format!("Error calling method SpliceUpdate: {:?}", e)))?;
        match result {
            Response::SpliceUpdate(r) => {
               trace!("splice_update response: {:?}", r);
               Ok(tonic::Response::new(r.into()))
            },
            r => Err(Status::new(
                Code::Internal,
                format!(
                    "Unexpected result {:?} to method call SpliceUpdate",
                    r
                )
            )),
        }

    }

    async fn dev_splice(
        &self,
        request: tonic::Request<pb::DevspliceRequest>,
    ) -> Result<tonic::Response<pb::DevspliceResponse>, tonic::Status> {
        let req = request.into_inner();
        let req: requests::DevspliceRequest = req.into();
        debug!("Client asked for dev_splice");
        trace!("dev_splice request: {:?}", req);
        let mut rpc = ClnRpc::new(&self.rpc_path)
            .await
            .map_err(|e| Status::new(Code::Internal, e.to_string()))?;
        let result = rpc.call(Request::DevSplice(req))
            .await
            .map_err(|e| Status::new(
               Code::Unknown,
               format!("Error calling method DevSplice: {:?}", e)))?;
        match result {
            Response::DevSplice(r) => {
               trace!("dev_splice response: {:?}", r);
               Ok(tonic::Response::new(r.into()))
            },
            r => Err(Status::new(
                Code::Internal,
                format!(
                    "Unexpected result {:?} to method call DevSplice",
                    r
                )
            )),
        }

    }

    async fn unreserve_inputs(
        &self,
        request: tonic::Request<pb::UnreserveinputsRequest>,
    ) -> Result<tonic::Response<pb::UnreserveinputsResponse>, tonic::Status> {
        let req = request.into_inner();
        let req: requests::UnreserveinputsRequest = req.into();
        debug!("Client asked for unreserve_inputs");
        trace!("unreserve_inputs request: {:?}", req);
        let mut rpc = ClnRpc::new(&self.rpc_path)
            .await
            .map_err(|e| Status::new(Code::Internal, e.to_string()))?;
        let result = rpc.call(Request::UnreserveInputs(req))
            .await
            .map_err(|e| Status::new(
               Code::Unknown,
               format!("Error calling method UnreserveInputs: {:?}", e)))?;
        match result {
            Response::UnreserveInputs(r) => {
               trace!("unreserve_inputs response: {:?}", r);
               Ok(tonic::Response::new(r.into()))
            },
            r => Err(Status::new(
                Code::Internal,
                format!(
                    "Unexpected result {:?} to method call UnreserveInputs",
                    r
                )
            )),
        }

    }

    async fn upgrade_wallet(
        &self,
        request: tonic::Request<pb::UpgradewalletRequest>,
    ) -> Result<tonic::Response<pb::UpgradewalletResponse>, tonic::Status> {
        let req = request.into_inner();
        let req: requests::UpgradewalletRequest = req.into();
        debug!("Client asked for upgrade_wallet");
        trace!("upgrade_wallet request: {:?}", req);
        let mut rpc = ClnRpc::new(&self.rpc_path)
            .await
            .map_err(|e| Status::new(Code::Internal, e.to_string()))?;
        let result = rpc.call(Request::UpgradeWallet(req))
            .await
            .map_err(|e| Status::new(
               Code::Unknown,
               format!("Error calling method UpgradeWallet: {:?}", e)))?;
        match result {
            Response::UpgradeWallet(r) => {
               trace!("upgrade_wallet response: {:?}", r);
               Ok(tonic::Response::new(r.into()))
            },
            r => Err(Status::new(
                Code::Internal,
                format!(
                    "Unexpected result {:?} to method call UpgradeWallet",
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

    async fn list_configs(
        &self,
        request: tonic::Request<pb::ListconfigsRequest>,
    ) -> Result<tonic::Response<pb::ListconfigsResponse>, tonic::Status> {
        let req = request.into_inner();
        let req: requests::ListconfigsRequest = req.into();
        debug!("Client asked for list_configs");
        trace!("list_configs request: {:?}", req);
        let mut rpc = ClnRpc::new(&self.rpc_path)
            .await
            .map_err(|e| Status::new(Code::Internal, e.to_string()))?;
        let result = rpc.call(Request::ListConfigs(req))
            .await
            .map_err(|e| Status::new(
               Code::Unknown,
               format!("Error calling method ListConfigs: {:?}", e)))?;
        match result {
            Response::ListConfigs(r) => {
               trace!("list_configs response: {:?}", r);
               Ok(tonic::Response::new(r.into()))
            },
            r => Err(Status::new(
                Code::Internal,
                format!(
                    "Unexpected result {:?} to method call ListConfigs",
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

    async fn help(
        &self,
        request: tonic::Request<pb::HelpRequest>,
    ) -> Result<tonic::Response<pb::HelpResponse>, tonic::Status> {
        let req = request.into_inner();
        let req: requests::HelpRequest = req.into();
        debug!("Client asked for help");
        trace!("help request: {:?}", req);
        let mut rpc = ClnRpc::new(&self.rpc_path)
            .await
            .map_err(|e| Status::new(Code::Internal, e.to_string()))?;
        let result = rpc.call(Request::Help(req))
            .await
            .map_err(|e| Status::new(
               Code::Unknown,
               format!("Error calling method Help: {:?}", e)))?;
        match result {
            Response::Help(r) => {
               trace!("help response: {:?}", r);
               Ok(tonic::Response::new(r.into()))
            },
            r => Err(Status::new(
                Code::Internal,
                format!(
                    "Unexpected result {:?} to method call Help",
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

    async fn bkpr_channels_apy(
        &self,
        request: tonic::Request<pb::BkprchannelsapyRequest>,
    ) -> Result<tonic::Response<pb::BkprchannelsapyResponse>, tonic::Status> {
        let req = request.into_inner();
        let req: requests::BkprchannelsapyRequest = req.into();
        debug!("Client asked for bkpr_channels_apy");
        trace!("bkpr_channels_apy request: {:?}", req);
        let mut rpc = ClnRpc::new(&self.rpc_path)
            .await
            .map_err(|e| Status::new(Code::Internal, e.to_string()))?;
        let result = rpc.call(Request::BkprChannelsApy(req))
            .await
            .map_err(|e| Status::new(
               Code::Unknown,
               format!("Error calling method BkprChannelsApy: {:?}", e)))?;
        match result {
            Response::BkprChannelsApy(r) => {
               trace!("bkpr_channels_apy response: {:?}", r);
               Ok(tonic::Response::new(r.into()))
            },
            r => Err(Status::new(
                Code::Internal,
                format!(
                    "Unexpected result {:?} to method call BkprChannelsApy",
                    r
                )
            )),
        }

    }

    async fn bkpr_dump_income_csv(
        &self,
        request: tonic::Request<pb::BkprdumpincomecsvRequest>,
    ) -> Result<tonic::Response<pb::BkprdumpincomecsvResponse>, tonic::Status> {
        let req = request.into_inner();
        let req: requests::BkprdumpincomecsvRequest = req.into();
        debug!("Client asked for bkpr_dump_income_csv");
        trace!("bkpr_dump_income_csv request: {:?}", req);
        let mut rpc = ClnRpc::new(&self.rpc_path)
            .await
            .map_err(|e| Status::new(Code::Internal, e.to_string()))?;
        let result = rpc.call(Request::BkprDumpIncomeCsv(req))
            .await
            .map_err(|e| Status::new(
               Code::Unknown,
               format!("Error calling method BkprDumpIncomeCsv: {:?}", e)))?;
        match result {
            Response::BkprDumpIncomeCsv(r) => {
               trace!("bkpr_dump_income_csv response: {:?}", r);
               Ok(tonic::Response::new(r.into()))
            },
            r => Err(Status::new(
                Code::Internal,
                format!(
                    "Unexpected result {:?} to method call BkprDumpIncomeCsv",
                    r
                )
            )),
        }

    }

    async fn bkpr_inspect(
        &self,
        request: tonic::Request<pb::BkprinspectRequest>,
    ) -> Result<tonic::Response<pb::BkprinspectResponse>, tonic::Status> {
        let req = request.into_inner();
        let req: requests::BkprinspectRequest = req.into();
        debug!("Client asked for bkpr_inspect");
        trace!("bkpr_inspect request: {:?}", req);
        let mut rpc = ClnRpc::new(&self.rpc_path)
            .await
            .map_err(|e| Status::new(Code::Internal, e.to_string()))?;
        let result = rpc.call(Request::BkprInspect(req))
            .await
            .map_err(|e| Status::new(
               Code::Unknown,
               format!("Error calling method BkprInspect: {:?}", e)))?;
        match result {
            Response::BkprInspect(r) => {
               trace!("bkpr_inspect response: {:?}", r);
               Ok(tonic::Response::new(r.into()))
            },
            r => Err(Status::new(
                Code::Internal,
                format!(
                    "Unexpected result {:?} to method call BkprInspect",
                    r
                )
            )),
        }

    }

    async fn bkpr_list_account_events(
        &self,
        request: tonic::Request<pb::BkprlistaccounteventsRequest>,
    ) -> Result<tonic::Response<pb::BkprlistaccounteventsResponse>, tonic::Status> {
        let req = request.into_inner();
        let req: requests::BkprlistaccounteventsRequest = req.into();
        debug!("Client asked for bkpr_list_account_events");
        trace!("bkpr_list_account_events request: {:?}", req);
        let mut rpc = ClnRpc::new(&self.rpc_path)
            .await
            .map_err(|e| Status::new(Code::Internal, e.to_string()))?;
        let result = rpc.call(Request::BkprListAccountEvents(req))
            .await
            .map_err(|e| Status::new(
               Code::Unknown,
               format!("Error calling method BkprListAccountEvents: {:?}", e)))?;
        match result {
            Response::BkprListAccountEvents(r) => {
               trace!("bkpr_list_account_events response: {:?}", r);
               Ok(tonic::Response::new(r.into()))
            },
            r => Err(Status::new(
                Code::Internal,
                format!(
                    "Unexpected result {:?} to method call BkprListAccountEvents",
                    r
                )
            )),
        }

    }

    async fn bkpr_list_balances(
        &self,
        request: tonic::Request<pb::BkprlistbalancesRequest>,
    ) -> Result<tonic::Response<pb::BkprlistbalancesResponse>, tonic::Status> {
        let req = request.into_inner();
        let req: requests::BkprlistbalancesRequest = req.into();
        debug!("Client asked for bkpr_list_balances");
        trace!("bkpr_list_balances request: {:?}", req);
        let mut rpc = ClnRpc::new(&self.rpc_path)
            .await
            .map_err(|e| Status::new(Code::Internal, e.to_string()))?;
        let result = rpc.call(Request::BkprListBalances(req))
            .await
            .map_err(|e| Status::new(
               Code::Unknown,
               format!("Error calling method BkprListBalances: {:?}", e)))?;
        match result {
            Response::BkprListBalances(r) => {
               trace!("bkpr_list_balances response: {:?}", r);
               Ok(tonic::Response::new(r.into()))
            },
            r => Err(Status::new(
                Code::Internal,
                format!(
                    "Unexpected result {:?} to method call BkprListBalances",
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

    async fn bkpr_edit_description_by_payment_id(
        &self,
        request: tonic::Request<pb::BkpreditdescriptionbypaymentidRequest>,
    ) -> Result<tonic::Response<pb::BkpreditdescriptionbypaymentidResponse>, tonic::Status> {
        let req = request.into_inner();
        let req: requests::BkpreditdescriptionbypaymentidRequest = req.into();
        debug!("Client asked for bkpr_edit_description_by_payment_id");
        trace!("bkpr_edit_description_by_payment_id request: {:?}", req);
        let mut rpc = ClnRpc::new(&self.rpc_path)
            .await
            .map_err(|e| Status::new(Code::Internal, e.to_string()))?;
        let result = rpc.call(Request::BkprEditDescriptionByPaymentId(req))
            .await
            .map_err(|e| Status::new(
               Code::Unknown,
               format!("Error calling method BkprEditDescriptionByPaymentId: {:?}", e)))?;
        match result {
            Response::BkprEditDescriptionByPaymentId(r) => {
               trace!("bkpr_edit_description_by_payment_id response: {:?}", r);
               Ok(tonic::Response::new(r.into()))
            },
            r => Err(Status::new(
                Code::Internal,
                format!(
                    "Unexpected result {:?} to method call BkprEditDescriptionByPaymentId",
                    r
                )
            )),
        }

    }

    async fn bkpr_edit_description_by_outpoint(
        &self,
        request: tonic::Request<pb::BkpreditdescriptionbyoutpointRequest>,
    ) -> Result<tonic::Response<pb::BkpreditdescriptionbyoutpointResponse>, tonic::Status> {
        let req = request.into_inner();
        let req: requests::BkpreditdescriptionbyoutpointRequest = req.into();
        debug!("Client asked for bkpr_edit_description_by_outpoint");
        trace!("bkpr_edit_description_by_outpoint request: {:?}", req);
        let mut rpc = ClnRpc::new(&self.rpc_path)
            .await
            .map_err(|e| Status::new(Code::Internal, e.to_string()))?;
        let result = rpc.call(Request::BkprEditDescriptionByOutpoint(req))
            .await
            .map_err(|e| Status::new(
               Code::Unknown,
               format!("Error calling method BkprEditDescriptionByOutpoint: {:?}", e)))?;
        match result {
            Response::BkprEditDescriptionByOutpoint(r) => {
               trace!("bkpr_edit_description_by_outpoint response: {:?}", r);
               Ok(tonic::Response::new(r.into()))
            },
            r => Err(Status::new(
                Code::Internal,
                format!(
                    "Unexpected result {:?} to method call BkprEditDescriptionByOutpoint",
                    r
                )
            )),
        }

    }

    async fn blacklist_rune(
        &self,
        request: tonic::Request<pb::BlacklistruneRequest>,
    ) -> Result<tonic::Response<pb::BlacklistruneResponse>, tonic::Status> {
        let req = request.into_inner();
        let req: requests::BlacklistruneRequest = req.into();
        debug!("Client asked for blacklist_rune");
        trace!("blacklist_rune request: {:?}", req);
        let mut rpc = ClnRpc::new(&self.rpc_path)
            .await
            .map_err(|e| Status::new(Code::Internal, e.to_string()))?;
        let result = rpc.call(Request::BlacklistRune(req))
            .await
            .map_err(|e| Status::new(
               Code::Unknown,
               format!("Error calling method BlacklistRune: {:?}", e)))?;
        match result {
            Response::BlacklistRune(r) => {
               trace!("blacklist_rune response: {:?}", r);
               Ok(tonic::Response::new(r.into()))
            },
            r => Err(Status::new(
                Code::Internal,
                format!(
                    "Unexpected result {:?} to method call BlacklistRune",
                    r
                )
            )),
        }

    }

    async fn check_rune(
        &self,
        request: tonic::Request<pb::CheckruneRequest>,
    ) -> Result<tonic::Response<pb::CheckruneResponse>, tonic::Status> {
        let req = request.into_inner();
        let req: requests::CheckruneRequest = req.into();
        debug!("Client asked for check_rune");
        trace!("check_rune request: {:?}", req);
        let mut rpc = ClnRpc::new(&self.rpc_path)
            .await
            .map_err(|e| Status::new(Code::Internal, e.to_string()))?;
        let result = rpc.call(Request::CheckRune(req))
            .await
            .map_err(|e| Status::new(
               Code::Unknown,
               format!("Error calling method CheckRune: {:?}", e)))?;
        match result {
            Response::CheckRune(r) => {
               trace!("check_rune response: {:?}", r);
               Ok(tonic::Response::new(r.into()))
            },
            r => Err(Status::new(
                Code::Internal,
                format!(
                    "Unexpected result {:?} to method call CheckRune",
                    r
                )
            )),
        }

    }

    async fn create_rune(
        &self,
        request: tonic::Request<pb::CreateruneRequest>,
    ) -> Result<tonic::Response<pb::CreateruneResponse>, tonic::Status> {
        let req = request.into_inner();
        let req: requests::CreateruneRequest = req.into();
        debug!("Client asked for create_rune");
        trace!("create_rune request: {:?}", req);
        let mut rpc = ClnRpc::new(&self.rpc_path)
            .await
            .map_err(|e| Status::new(Code::Internal, e.to_string()))?;
        let result = rpc.call(Request::CreateRune(req))
            .await
            .map_err(|e| Status::new(
               Code::Unknown,
               format!("Error calling method CreateRune: {:?}", e)))?;
        match result {
            Response::CreateRune(r) => {
               trace!("create_rune response: {:?}", r);
               Ok(tonic::Response::new(r.into()))
            },
            r => Err(Status::new(
                Code::Internal,
                format!(
                    "Unexpected result {:?} to method call CreateRune",
                    r
                )
            )),
        }

    }

    async fn show_runes(
        &self,
        request: tonic::Request<pb::ShowrunesRequest>,
    ) -> Result<tonic::Response<pb::ShowrunesResponse>, tonic::Status> {
        let req = request.into_inner();
        let req: requests::ShowrunesRequest = req.into();
        debug!("Client asked for show_runes");
        trace!("show_runes request: {:?}", req);
        let mut rpc = ClnRpc::new(&self.rpc_path)
            .await
            .map_err(|e| Status::new(Code::Internal, e.to_string()))?;
        let result = rpc.call(Request::ShowRunes(req))
            .await
            .map_err(|e| Status::new(
               Code::Unknown,
               format!("Error calling method ShowRunes: {:?}", e)))?;
        match result {
            Response::ShowRunes(r) => {
               trace!("show_runes response: {:?}", r);
               Ok(tonic::Response::new(r.into()))
            },
            r => Err(Status::new(
                Code::Internal,
                format!(
                    "Unexpected result {:?} to method call ShowRunes",
                    r
                )
            )),
        }

    }

    async fn ask_rene_unreserve(
        &self,
        request: tonic::Request<pb::AskreneunreserveRequest>,
    ) -> Result<tonic::Response<pb::AskreneunreserveResponse>, tonic::Status> {
        let req = request.into_inner();
        let req: requests::AskreneunreserveRequest = req.into();
        debug!("Client asked for ask_rene_unreserve");
        trace!("ask_rene_unreserve request: {:?}", req);
        let mut rpc = ClnRpc::new(&self.rpc_path)
            .await
            .map_err(|e| Status::new(Code::Internal, e.to_string()))?;
        let result = rpc.call(Request::AskReneUnreserve(req))
            .await
            .map_err(|e| Status::new(
               Code::Unknown,
               format!("Error calling method AskReneUnreserve: {:?}", e)))?;
        match result {
            Response::AskReneUnreserve(r) => {
               trace!("ask_rene_unreserve response: {:?}", r);
               Ok(tonic::Response::new(r.into()))
            },
            r => Err(Status::new(
                Code::Internal,
                format!(
                    "Unexpected result {:?} to method call AskReneUnreserve",
                    r
                )
            )),
        }

    }

    async fn ask_rene_list_layers(
        &self,
        request: tonic::Request<pb::AskrenelistlayersRequest>,
    ) -> Result<tonic::Response<pb::AskrenelistlayersResponse>, tonic::Status> {
        let req = request.into_inner();
        let req: requests::AskrenelistlayersRequest = req.into();
        debug!("Client asked for ask_rene_list_layers");
        trace!("ask_rene_list_layers request: {:?}", req);
        let mut rpc = ClnRpc::new(&self.rpc_path)
            .await
            .map_err(|e| Status::new(Code::Internal, e.to_string()))?;
        let result = rpc.call(Request::AskReneListLayers(req))
            .await
            .map_err(|e| Status::new(
               Code::Unknown,
               format!("Error calling method AskReneListLayers: {:?}", e)))?;
        match result {
            Response::AskReneListLayers(r) => {
               trace!("ask_rene_list_layers response: {:?}", r);
               Ok(tonic::Response::new(r.into()))
            },
            r => Err(Status::new(
                Code::Internal,
                format!(
                    "Unexpected result {:?} to method call AskReneListLayers",
                    r
                )
            )),
        }

    }

    async fn ask_rene_create_layer(
        &self,
        request: tonic::Request<pb::AskrenecreatelayerRequest>,
    ) -> Result<tonic::Response<pb::AskrenecreatelayerResponse>, tonic::Status> {
        let req = request.into_inner();
        let req: requests::AskrenecreatelayerRequest = req.into();
        debug!("Client asked for ask_rene_create_layer");
        trace!("ask_rene_create_layer request: {:?}", req);
        let mut rpc = ClnRpc::new(&self.rpc_path)
            .await
            .map_err(|e| Status::new(Code::Internal, e.to_string()))?;
        let result = rpc.call(Request::AskReneCreateLayer(req))
            .await
            .map_err(|e| Status::new(
               Code::Unknown,
               format!("Error calling method AskReneCreateLayer: {:?}", e)))?;
        match result {
            Response::AskReneCreateLayer(r) => {
               trace!("ask_rene_create_layer response: {:?}", r);
               Ok(tonic::Response::new(r.into()))
            },
            r => Err(Status::new(
                Code::Internal,
                format!(
                    "Unexpected result {:?} to method call AskReneCreateLayer",
                    r
                )
            )),
        }

    }

    async fn ask_rene_remove_layer(
        &self,
        request: tonic::Request<pb::AskreneremovelayerRequest>,
    ) -> Result<tonic::Response<pb::AskreneremovelayerResponse>, tonic::Status> {
        let req = request.into_inner();
        let req: requests::AskreneremovelayerRequest = req.into();
        debug!("Client asked for ask_rene_remove_layer");
        trace!("ask_rene_remove_layer request: {:?}", req);
        let mut rpc = ClnRpc::new(&self.rpc_path)
            .await
            .map_err(|e| Status::new(Code::Internal, e.to_string()))?;
        let result = rpc.call(Request::AskReneRemoveLayer(req))
            .await
            .map_err(|e| Status::new(
               Code::Unknown,
               format!("Error calling method AskReneRemoveLayer: {:?}", e)))?;
        match result {
            Response::AskReneRemoveLayer(r) => {
               trace!("ask_rene_remove_layer response: {:?}", r);
               Ok(tonic::Response::new(r.into()))
            },
            r => Err(Status::new(
                Code::Internal,
                format!(
                    "Unexpected result {:?} to method call AskReneRemoveLayer",
                    r
                )
            )),
        }

    }

    async fn ask_rene_reserve(
        &self,
        request: tonic::Request<pb::AskrenereserveRequest>,
    ) -> Result<tonic::Response<pb::AskrenereserveResponse>, tonic::Status> {
        let req = request.into_inner();
        let req: requests::AskrenereserveRequest = req.into();
        debug!("Client asked for ask_rene_reserve");
        trace!("ask_rene_reserve request: {:?}", req);
        let mut rpc = ClnRpc::new(&self.rpc_path)
            .await
            .map_err(|e| Status::new(Code::Internal, e.to_string()))?;
        let result = rpc.call(Request::AskReneReserve(req))
            .await
            .map_err(|e| Status::new(
               Code::Unknown,
               format!("Error calling method AskReneReserve: {:?}", e)))?;
        match result {
            Response::AskReneReserve(r) => {
               trace!("ask_rene_reserve response: {:?}", r);
               Ok(tonic::Response::new(r.into()))
            },
            r => Err(Status::new(
                Code::Internal,
                format!(
                    "Unexpected result {:?} to method call AskReneReserve",
                    r
                )
            )),
        }

    }

    async fn ask_rene_age(
        &self,
        request: tonic::Request<pb::AskreneageRequest>,
    ) -> Result<tonic::Response<pb::AskreneageResponse>, tonic::Status> {
        let req = request.into_inner();
        let req: requests::AskreneageRequest = req.into();
        debug!("Client asked for ask_rene_age");
        trace!("ask_rene_age request: {:?}", req);
        let mut rpc = ClnRpc::new(&self.rpc_path)
            .await
            .map_err(|e| Status::new(Code::Internal, e.to_string()))?;
        let result = rpc.call(Request::AskReneAge(req))
            .await
            .map_err(|e| Status::new(
               Code::Unknown,
               format!("Error calling method AskReneAge: {:?}", e)))?;
        match result {
            Response::AskReneAge(r) => {
               trace!("ask_rene_age response: {:?}", r);
               Ok(tonic::Response::new(r.into()))
            },
            r => Err(Status::new(
                Code::Internal,
                format!(
                    "Unexpected result {:?} to method call AskReneAge",
                    r
                )
            )),
        }

    }

    async fn get_routes(
        &self,
        request: tonic::Request<pb::GetroutesRequest>,
    ) -> Result<tonic::Response<pb::GetroutesResponse>, tonic::Status> {
        let req = request.into_inner();
        let req: requests::GetroutesRequest = req.into();
        debug!("Client asked for get_routes");
        trace!("get_routes request: {:?}", req);
        let mut rpc = ClnRpc::new(&self.rpc_path)
            .await
            .map_err(|e| Status::new(Code::Internal, e.to_string()))?;
        let result = rpc.call(Request::GetRoutes(req))
            .await
            .map_err(|e| Status::new(
               Code::Unknown,
               format!("Error calling method GetRoutes: {:?}", e)))?;
        match result {
            Response::GetRoutes(r) => {
               trace!("get_routes response: {:?}", r);
               Ok(tonic::Response::new(r.into()))
            },
            r => Err(Status::new(
                Code::Internal,
                format!(
                    "Unexpected result {:?} to method call GetRoutes",
                    r
                )
            )),
        }

    }

    async fn ask_rene_disable_node(
        &self,
        request: tonic::Request<pb::AskrenedisablenodeRequest>,
    ) -> Result<tonic::Response<pb::AskrenedisablenodeResponse>, tonic::Status> {
        let req = request.into_inner();
        let req: requests::AskrenedisablenodeRequest = req.into();
        debug!("Client asked for ask_rene_disable_node");
        trace!("ask_rene_disable_node request: {:?}", req);
        let mut rpc = ClnRpc::new(&self.rpc_path)
            .await
            .map_err(|e| Status::new(Code::Internal, e.to_string()))?;
        let result = rpc.call(Request::AskReneDisableNode(req))
            .await
            .map_err(|e| Status::new(
               Code::Unknown,
               format!("Error calling method AskReneDisableNode: {:?}", e)))?;
        match result {
            Response::AskReneDisableNode(r) => {
               trace!("ask_rene_disable_node response: {:?}", r);
               Ok(tonic::Response::new(r.into()))
            },
            r => Err(Status::new(
                Code::Internal,
                format!(
                    "Unexpected result {:?} to method call AskReneDisableNode",
                    r
                )
            )),
        }

    }

    async fn ask_rene_inform_channel(
        &self,
        request: tonic::Request<pb::AskreneinformchannelRequest>,
    ) -> Result<tonic::Response<pb::AskreneinformchannelResponse>, tonic::Status> {
        let req = request.into_inner();
        let req: requests::AskreneinformchannelRequest = req.into();
        debug!("Client asked for ask_rene_inform_channel");
        trace!("ask_rene_inform_channel request: {:?}", req);
        let mut rpc = ClnRpc::new(&self.rpc_path)
            .await
            .map_err(|e| Status::new(Code::Internal, e.to_string()))?;
        let result = rpc.call(Request::AskReneInformChannel(req))
            .await
            .map_err(|e| Status::new(
               Code::Unknown,
               format!("Error calling method AskReneInformChannel: {:?}", e)))?;
        match result {
            Response::AskReneInformChannel(r) => {
               trace!("ask_rene_inform_channel response: {:?}", r);
               Ok(tonic::Response::new(r.into()))
            },
            r => Err(Status::new(
                Code::Internal,
                format!(
                    "Unexpected result {:?} to method call AskReneInformChannel",
                    r
                )
            )),
        }

    }

    async fn ask_rene_create_channel(
        &self,
        request: tonic::Request<pb::AskrenecreatechannelRequest>,
    ) -> Result<tonic::Response<pb::AskrenecreatechannelResponse>, tonic::Status> {
        let req = request.into_inner();
        let req: requests::AskrenecreatechannelRequest = req.into();
        debug!("Client asked for ask_rene_create_channel");
        trace!("ask_rene_create_channel request: {:?}", req);
        let mut rpc = ClnRpc::new(&self.rpc_path)
            .await
            .map_err(|e| Status::new(Code::Internal, e.to_string()))?;
        let result = rpc.call(Request::AskReneCreateChannel(req))
            .await
            .map_err(|e| Status::new(
               Code::Unknown,
               format!("Error calling method AskReneCreateChannel: {:?}", e)))?;
        match result {
            Response::AskReneCreateChannel(r) => {
               trace!("ask_rene_create_channel response: {:?}", r);
               Ok(tonic::Response::new(r.into()))
            },
            r => Err(Status::new(
                Code::Internal,
                format!(
                    "Unexpected result {:?} to method call AskReneCreateChannel",
                    r
                )
            )),
        }

    }

    async fn ask_rene_update_channel(
        &self,
        request: tonic::Request<pb::AskreneupdatechannelRequest>,
    ) -> Result<tonic::Response<pb::AskreneupdatechannelResponse>, tonic::Status> {
        let req = request.into_inner();
        let req: requests::AskreneupdatechannelRequest = req.into();
        debug!("Client asked for ask_rene_update_channel");
        trace!("ask_rene_update_channel request: {:?}", req);
        let mut rpc = ClnRpc::new(&self.rpc_path)
            .await
            .map_err(|e| Status::new(Code::Internal, e.to_string()))?;
        let result = rpc.call(Request::AskReneUpdateChannel(req))
            .await
            .map_err(|e| Status::new(
               Code::Unknown,
               format!("Error calling method AskReneUpdateChannel: {:?}", e)))?;
        match result {
            Response::AskReneUpdateChannel(r) => {
               trace!("ask_rene_update_channel response: {:?}", r);
               Ok(tonic::Response::new(r.into()))
            },
            r => Err(Status::new(
                Code::Internal,
                format!(
                    "Unexpected result {:?} to method call AskReneUpdateChannel",
                    r
                )
            )),
        }

    }

    async fn ask_rene_bias_channel(
        &self,
        request: tonic::Request<pb::AskrenebiaschannelRequest>,
    ) -> Result<tonic::Response<pb::AskrenebiaschannelResponse>, tonic::Status> {
        let req = request.into_inner();
        let req: requests::AskrenebiaschannelRequest = req.into();
        debug!("Client asked for ask_rene_bias_channel");
        trace!("ask_rene_bias_channel request: {:?}", req);
        let mut rpc = ClnRpc::new(&self.rpc_path)
            .await
            .map_err(|e| Status::new(Code::Internal, e.to_string()))?;
        let result = rpc.call(Request::AskReneBiasChannel(req))
            .await
            .map_err(|e| Status::new(
               Code::Unknown,
               format!("Error calling method AskReneBiasChannel: {:?}", e)))?;
        match result {
            Response::AskReneBiasChannel(r) => {
               trace!("ask_rene_bias_channel response: {:?}", r);
               Ok(tonic::Response::new(r.into()))
            },
            r => Err(Status::new(
                Code::Internal,
                format!(
                    "Unexpected result {:?} to method call AskReneBiasChannel",
                    r
                )
            )),
        }

    }

    async fn ask_rene_list_reservations(
        &self,
        request: tonic::Request<pb::AskrenelistreservationsRequest>,
    ) -> Result<tonic::Response<pb::AskrenelistreservationsResponse>, tonic::Status> {
        let req = request.into_inner();
        let req: requests::AskrenelistreservationsRequest = req.into();
        debug!("Client asked for ask_rene_list_reservations");
        trace!("ask_rene_list_reservations request: {:?}", req);
        let mut rpc = ClnRpc::new(&self.rpc_path)
            .await
            .map_err(|e| Status::new(Code::Internal, e.to_string()))?;
        let result = rpc.call(Request::AskReneListReservations(req))
            .await
            .map_err(|e| Status::new(
               Code::Unknown,
               format!("Error calling method AskReneListReservations: {:?}", e)))?;
        match result {
            Response::AskReneListReservations(r) => {
               trace!("ask_rene_list_reservations response: {:?}", r);
               Ok(tonic::Response::new(r.into()))
            },
            r => Err(Status::new(
                Code::Internal,
                format!(
                    "Unexpected result {:?} to method call AskReneListReservations",
                    r
                )
            )),
        }

    }

    async fn inject_payment_onion(
        &self,
        request: tonic::Request<pb::InjectpaymentonionRequest>,
    ) -> Result<tonic::Response<pb::InjectpaymentonionResponse>, tonic::Status> {
        let req = request.into_inner();
        let req: requests::InjectpaymentonionRequest = req.into();
        debug!("Client asked for inject_payment_onion");
        trace!("inject_payment_onion request: {:?}", req);
        let mut rpc = ClnRpc::new(&self.rpc_path)
            .await
            .map_err(|e| Status::new(Code::Internal, e.to_string()))?;
        let result = rpc.call(Request::InjectPaymentOnion(req))
            .await
            .map_err(|e| Status::new(
               Code::Unknown,
               format!("Error calling method InjectPaymentOnion: {:?}", e)))?;
        match result {
            Response::InjectPaymentOnion(r) => {
               trace!("inject_payment_onion response: {:?}", r);
               Ok(tonic::Response::new(r.into()))
            },
            r => Err(Status::new(
                Code::Internal,
                format!(
                    "Unexpected result {:?} to method call InjectPaymentOnion",
                    r
                )
            )),
        }

    }

    async fn inject_onion_message(
        &self,
        request: tonic::Request<pb::InjectonionmessageRequest>,
    ) -> Result<tonic::Response<pb::InjectonionmessageResponse>, tonic::Status> {
        let req = request.into_inner();
        let req: requests::InjectonionmessageRequest = req.into();
        debug!("Client asked for inject_onion_message");
        trace!("inject_onion_message request: {:?}", req);
        let mut rpc = ClnRpc::new(&self.rpc_path)
            .await
            .map_err(|e| Status::new(Code::Internal, e.to_string()))?;
        let result = rpc.call(Request::InjectOnionMessage(req))
            .await
            .map_err(|e| Status::new(
               Code::Unknown,
               format!("Error calling method InjectOnionMessage: {:?}", e)))?;
        match result {
            Response::InjectOnionMessage(r) => {
               trace!("inject_onion_message response: {:?}", r);
               Ok(tonic::Response::new(r.into()))
            },
            r => Err(Status::new(
                Code::Internal,
                format!(
                    "Unexpected result {:?} to method call InjectOnionMessage",
                    r
                )
            )),
        }

    }

    async fn xpay(
        &self,
        request: tonic::Request<pb::XpayRequest>,
    ) -> Result<tonic::Response<pb::XpayResponse>, tonic::Status> {
        let req = request.into_inner();
        let req: requests::XpayRequest = req.into();
        debug!("Client asked for xpay");
        trace!("xpay request: {:?}", req);
        let mut rpc = ClnRpc::new(&self.rpc_path)
            .await
            .map_err(|e| Status::new(Code::Internal, e.to_string()))?;
        let result = rpc.call(Request::Xpay(req))
            .await
            .map_err(|e| Status::new(
               Code::Unknown,
               format!("Error calling method Xpay: {:?}", e)))?;
        match result {
            Response::Xpay(r) => {
               trace!("xpay response: {:?}", r);
               Ok(tonic::Response::new(r.into()))
            },
            r => Err(Status::new(
                Code::Internal,
                format!(
                    "Unexpected result {:?} to method call Xpay",
                    r
                )
            )),
        }

    }

    async fn sign_message_with_key(
        &self,
        request: tonic::Request<pb::SignmessagewithkeyRequest>,
    ) -> Result<tonic::Response<pb::SignmessagewithkeyResponse>, tonic::Status> {
        let req = request.into_inner();
        let req: requests::SignmessagewithkeyRequest = req.into();
        debug!("Client asked for sign_message_with_key");
        trace!("sign_message_with_key request: {:?}", req);
        let mut rpc = ClnRpc::new(&self.rpc_path)
            .await
            .map_err(|e| Status::new(Code::Internal, e.to_string()))?;
        let result = rpc.call(Request::SignMessageWithKey(req))
            .await
            .map_err(|e| Status::new(
               Code::Unknown,
               format!("Error calling method SignMessageWithKey: {:?}", e)))?;
        match result {
            Response::SignMessageWithKey(r) => {
               trace!("sign_message_with_key response: {:?}", r);
               Ok(tonic::Response::new(r.into()))
            },
            r => Err(Status::new(
                Code::Internal,
                format!(
                    "Unexpected result {:?} to method call SignMessageWithKey",
                    r
                )
            )),
        }

    }



    type SubscribeBlockAddedStream = NotificationStream<pb::BlockAddedNotification>;

    async fn subscribe_block_added(
        &self,
        _request : tonic::Request<pb::StreamBlockAddedRequest>
    ) -> Result<tonic::Response<Self::SubscribeBlockAddedStream>, tonic::Status> {
        let receiver = self.events.subscribe();
        let stream = BroadcastStream::new(receiver);
        let boxed = Box::pin(stream);

        let result = NotificationStream {
            inner : boxed,
            fn_filter_map : |x| {
                match x {
                    Notification::BlockAdded(x) => {
                        Some(x.into())
                    }
                    _ => None
                }
            }
        };
        Ok(tonic::Response::new(result))
    }


    type SubscribeChannelOpenFailedStream = NotificationStream<pb::ChannelOpenFailedNotification>;

    async fn subscribe_channel_open_failed(
        &self,
        _request : tonic::Request<pb::StreamChannelOpenFailedRequest>
    ) -> Result<tonic::Response<Self::SubscribeChannelOpenFailedStream>, tonic::Status> {
        let receiver = self.events.subscribe();
        let stream = BroadcastStream::new(receiver);
        let boxed = Box::pin(stream);

        let result = NotificationStream {
            inner : boxed,
            fn_filter_map : |x| {
                match x {
                    Notification::ChannelOpenFailed(x) => {
                        Some(x.into())
                    }
                    _ => None
                }
            }
        };
        Ok(tonic::Response::new(result))
    }


    type SubscribeChannelOpenedStream = NotificationStream<pb::ChannelOpenedNotification>;

    async fn subscribe_channel_opened(
        &self,
        _request : tonic::Request<pb::StreamChannelOpenedRequest>
    ) -> Result<tonic::Response<Self::SubscribeChannelOpenedStream>, tonic::Status> {
        let receiver = self.events.subscribe();
        let stream = BroadcastStream::new(receiver);
        let boxed = Box::pin(stream);

        let result = NotificationStream {
            inner : boxed,
            fn_filter_map : |x| {
                match x {
                    Notification::ChannelOpened(x) => {
                        Some(x.into())
                    }
                    _ => None
                }
            }
        };
        Ok(tonic::Response::new(result))
    }


    type SubscribeConnectStream = NotificationStream<pb::PeerConnectNotification>;

    async fn subscribe_connect(
        &self,
        _request : tonic::Request<pb::StreamConnectRequest>
    ) -> Result<tonic::Response<Self::SubscribeConnectStream>, tonic::Status> {
        let receiver = self.events.subscribe();
        let stream = BroadcastStream::new(receiver);
        let boxed = Box::pin(stream);

        let result = NotificationStream {
            inner : boxed,
            fn_filter_map : |x| {
                match x {
                    Notification::Connect(x) => {
                        Some(x.into())
                    }
                    _ => None
                }
            }
        };
        Ok(tonic::Response::new(result))
    }


    type SubscribeCustomMsgStream = NotificationStream<pb::CustomMsgNotification>;

    async fn subscribe_custom_msg(
        &self,
        _request : tonic::Request<pb::StreamCustomMsgRequest>
    ) -> Result<tonic::Response<Self::SubscribeCustomMsgStream>, tonic::Status> {
        let receiver = self.events.subscribe();
        let stream = BroadcastStream::new(receiver);
        let boxed = Box::pin(stream);

        let result = NotificationStream {
            inner : boxed,
            fn_filter_map : |x| {
                match x {
                    Notification::CustomMsg(x) => {
                        Some(x.into())
                    }
                    _ => None
                }
            }
        };
        Ok(tonic::Response::new(result))
    }


    type SubscribeChannelStateChangedStream = NotificationStream<pb::ChannelStateChangedNotification>;

    async fn subscribe_channel_state_changed(
        &self,
        _request : tonic::Request<pb::StreamChannelStateChangedRequest>
    ) -> Result<tonic::Response<Self::SubscribeChannelStateChangedStream>, tonic::Status> {
        let receiver = self.events.subscribe();
        let stream = BroadcastStream::new(receiver);
        let boxed = Box::pin(stream);

        let result = NotificationStream {
            inner : boxed,
            fn_filter_map : |x| {
                match x {
                    Notification::ChannelStateChanged(x) => {
                        Some(x.into())
                    }
                    _ => None
                }
            }
        };
        Ok(tonic::Response::new(result))
    }
}