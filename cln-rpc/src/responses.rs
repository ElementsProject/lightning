//! Messages that we might get from `lightningd` as a response to a
//! query.

use serde::{Deserialize, Serialize};

mod getinfo;

pub use getinfo::*;
