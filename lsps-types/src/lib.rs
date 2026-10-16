//! Protocol types for the Lightning Service Provider specifications
//! [LSPS0] (bLIP-50) and [LSPS2] (bLIP-52).
//!
//! This crate is shared by LSPS clients and services so that both sides
//! use one implementation of the message types and of the LSPS2 opening
//! fee computation, and can never disagree on amounts.
//!
//! [LSPS0]: https://github.com/lightning/blips/blob/master/blip-0050.md
//! [LSPS2]: https://github.com/lightning/blips/blob/master/blip-0052.md

#[macro_use]
pub mod jsonrpc;
pub mod lsps0;
pub mod lsps2;
