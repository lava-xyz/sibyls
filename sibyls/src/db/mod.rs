use crate::db::postgres::PgEventStorage;
use crate::db::sled::SledEventStorage;
use crate::error::SibylsError;
use crate::{AssetPair, Filters, OracleEvent};
use dlc_messages::oracle_msgs::{OracleAnnouncement, OracleAttestation};
use time::OffsetDateTime;

pub(crate) mod postgres;
pub(crate) mod sled;

#[derive(Debug, Clone)]
pub enum EventStorage {
    Sled(SledEventStorage),
    Pg(PgEventStorage),
}

impl EventStorage {
    pub fn new(database_url: &String, asset_pair: AssetPair) -> Result<EventStorage, SibylsError> {
        match database_url.split(":").collect::<Vec<&str>>().first() {
            Some(scheme) => {
                if scheme == &"sled" {
                    Ok(EventStorage::Sled(SledEventStorage::new(asset_pair)?))
                } else if scheme == &"postgres" {
                    Ok(EventStorage::Pg(PgEventStorage::new(database_url)?))
                } else {
                    Err(SibylsError::InternalError(format!(
                        "unknown database scheme: {database_url}"
                    )))
                }
            }
            None => Err(SibylsError::InternalError(format!(
                "invalid database URL: {database_url}"
            ))),
        }
    }

    pub fn get_oracle_event(
        &self,
        maturation: &OffsetDateTime,
        asset_pair: AssetPair,
    ) -> Result<OracleEvent, SibylsError> {
        match self {
            EventStorage::Sled(storage) => storage.get_oracle_event(maturation, asset_pair),
            EventStorage::Pg(storage) => storage.get_oracle_event(maturation, asset_pair),
        }
    }

    pub fn list_oracle_events(&self, filters: Filters) -> Result<Vec<OracleEvent>, SibylsError> {
        match self {
            EventStorage::Sled(storage) => storage.list_oracle_events(filters),
            EventStorage::Pg(storage) => storage.list_oracle_events(filters),
        }
    }

    pub fn store_announcement(
        &self,
        maturation: &OffsetDateTime,
        asset_pair: AssetPair,
        ann: &OracleAnnouncement,
        outstanding_sk_nonces: &Vec<[u8; 32]>,
    ) -> Result<(), SibylsError> {
        match self {
            EventStorage::Sled(storage) => {
                storage.store_announcement(maturation, asset_pair, ann, outstanding_sk_nonces)
            }
            EventStorage::Pg(storage) => {
                storage.store_announcement(maturation, asset_pair, ann, outstanding_sk_nonces)
            }
        }
    }

    pub fn store_attestation(
        &self,
        maturation: &OffsetDateTime,
        asset_pair: AssetPair,
        att: &OracleAttestation,
        price: u64,
    ) -> Result<(), SibylsError> {
        match self {
            EventStorage::Sled(storage) => {
                storage.store_attestation(maturation, asset_pair, att, price)
            }
            EventStorage::Pg(storage) => {
                storage.store_attestation(maturation, asset_pair, att, price)
            }
        }
    }
}
