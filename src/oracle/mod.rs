use crate::AssetPairInfo;
use secp256k1_zkp::KeyPair;
use serde::Serialize;
use sled::Db;

pub mod error;

use error::OracleError;
pub use error::Result;

#[derive(Clone, Serialize)]
struct DbValue(String, Option<String>);

#[derive(Clone)]
pub struct Oracle {
    asset_pair_info: AssetPairInfo,
    event_database: Db,
    keypair: KeyPair,
}

impl Oracle {
    pub fn new(asset_pair_info: AssetPairInfo, keypair: KeyPair) -> Result<Oracle> {
        // setup event database
        let path = format!("events/{}", asset_pair_info.asset_pair.to_string());
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

mod pricefeeds;
