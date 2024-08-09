// Huge json!() macros require lots of recursion
#![recursion_limit = "1024"]

pub use tonic;

#[cfg(feature = "server")]
mod convert;
pub mod pb;

#[cfg(feature = "server")]
mod server;

#[cfg(feature = "server")]
pub use crate::server::Server;

#[cfg(test)]
mod test;
