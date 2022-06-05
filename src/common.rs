use crate::oracle::EventDescriptor;
use serde::{Deserialize, Serialize};
use std::fmt::{self, Debug, Display, Formatter};

#[derive(Copy, Clone, Debug, Deserialize, Eq, Hash, PartialEq, Serialize)]
pub enum AssetPair {
    BTCUSD,
}

#[derive(Clone, Deserialize)]
pub struct AssetPairInfo {
    pub asset_pair: AssetPair,
    pub event_descriptor: EventDescriptor,
}

impl Display for AssetPair {
    fn fmt(&self, f: &mut Formatter) -> fmt::Result {
        Debug::fmt(self, f)
    }
}
