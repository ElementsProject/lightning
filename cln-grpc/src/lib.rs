// Huge json!() macros require lots of recursion
#![recursion_limit = "1024"]

mod convert;
pub mod pb;
mod serde_convert;
mod server;

pub use crate::server::Server;

#[cfg(test)]
mod test;
