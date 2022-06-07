use crate::AssetPairInfo;
use log::info;
use secp256k1_zkp::KeyPair;
use serde::{Deserialize, Serialize};
use sled::Db;

mod error;
pub use error::OracleError;
pub use error::Result;

#[derive(Clone, Deserialize, Serialize)]
// outstanding_sk_nonces?, announcement, attetstation?, outcome?
pub struct DbValue(
    pub Option<Vec<[u8; 32]>>,
    pub Vec<u8>,
    pub Option<Vec<u8>>,
    pub Option<u64>,
);

#[derive(Clone)]
pub struct Oracle {
    asset_pair_info: AssetPairInfo,
    pub event_database: Db,
    keypair: KeyPair,
}

impl Oracle {
    pub fn new(asset_pair_info: AssetPairInfo, keypair: KeyPair) -> Result<Oracle> {
        // setup event database
        let path = format!("events/{}", asset_pair_info.asset_pair);
        info!("creating sled at {}", path);
        let event_database = sled::open(path)?;

        Ok(Oracle {
            asset_pair_info,
            event_database,
            keypair,
        })
    }
}

pub mod oracle_scheduler;
pub use oracle_scheduler::messaging::EventDescriptor;

pub mod pricefeeds;
