use std::sync::Arc;

use crate::{
    cln_adapters::sender::ClnSender,
    core::{
        server::LspsService,
        transport::{MultiplexedTransport, PendingRequests},
    },
};

pub trait ClientState {
    fn transport(&self) -> MultiplexedTransport<ClnSender>;
    fn pending(&self) -> &PendingRequests;
}

pub trait ServiceState {
    fn service(&self) -> Arc<LspsService>;
    fn sender(&self) -> ClnSender;
}
