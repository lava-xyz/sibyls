use crate::AssetPairInfo;
use secp256k1_zkp::KeyPair;
use serde::{Deserialize, Serialize};
use sled::Db;

pub mod error;

pub use error::OracleError;
pub use error::Result;

#[derive(Clone, Deserialize, Serialize)]
pub struct DbValue(pub Vec<u8>, pub Option<Vec<u8>>);

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
        let event_database = sled::open(path)?;

        Ok(Oracle {
            asset_pair_info,
            event_database,
            keypair,
        })
    }
}

pub mod oracle_scheduler;
pub use oracle_scheduler::EventDescriptor;

pub mod pricefeeds;
