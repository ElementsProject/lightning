use crate::{
    cln_adapters::sender::ClnSender,
    core::transport::{MultiplexedTransport, PendingRequests},
};

pub trait ClientState {
    fn transport(&self) -> MultiplexedTransport<ClnSender>;
    fn pending(&self) -> &PendingRequests;
}
