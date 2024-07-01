use crate::{AssetPair, AssetPairInfo, OracleConfig};
use log::info;
use secp256k1_zkp::KeyPair;

mod error;
pub use error::OracleError;
pub use error::Result;

#[derive(Clone)]
pub struct EventData {
    pub maturation: OffsetDateTime,
    pub asset_pair: AssetPair,
    pub outstanding_sk_nonces: Vec<[u8; 32]>,
}

#[derive(Clone)]
pub struct Oracle {
    pub oracle_config: OracleConfig,
    asset_pair_info: AssetPairInfo,
    pub event_database: SledEventStorage,
    keypair: KeyPair,
}

impl Oracle {
    pub fn new(
        oracle_config: OracleConfig,
        asset_pair_info: AssetPairInfo,
        keypair: KeyPair,
    ) -> Result<Oracle> {
        if !oracle_config.announcement_offset.is_positive() {
            return Err(OracleError::InvalidAnnouncementTimeError(
                oracle_config.announcement_offset,
            ));
        }

        // setup event database
        let path = format!("events/{}", asset_pair_info.asset_pair);
        info!("creating sled at {}", path);
        let event_database = SledEventStorage::new(sled::open(path)?);

        Ok(Oracle {
            oracle_config,
            asset_pair_info,
            event_database,
            keypair,
        })
    }
}

use crate::db::SledEventStorage;
pub use dlc_messages::oracle_msgs::EventDescriptor;
use time::OffsetDateTime;

pub mod oracle_scheduler;
pub mod pricefeeds;
