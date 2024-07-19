use crate::db::dual::DualDbEventStorage;
use crate::db::postgres::PgEventStorage;
use crate::db::sled::SledEventStorage;
use crate::error::SibylsError;
use crate::{AssetPair, DatabaseBackend, Filters, OracleEvent};
use dlc_messages::oracle_msgs::{OracleAnnouncement, OracleAttestation};
use time::OffsetDateTime;

mod dual;
pub(crate) mod postgres;
pub(crate) mod sled;

#[derive(Debug, Clone)]
pub enum EventStorage {
    Sled(SledEventStorage),
    Pg(PgEventStorage),
    Dual(DualDbEventStorage),
}

impl EventStorage {
    pub fn new(
        database_url: &Option<String>,
        database_backend: &DatabaseBackend,
        asset_pair: AssetPair,
    ) -> Result<EventStorage, SibylsError> {
        match database_backend {
            DatabaseBackend::Sled => Ok(EventStorage::Sled(SledEventStorage::new(asset_pair)?)),
            DatabaseBackend::Pg => {
                let url = Self::extract_database_url(database_url)?;
                Ok(EventStorage::Pg(PgEventStorage::new(&url)?))
            }
            DatabaseBackend::Dual => {
                let url = Self::extract_database_url(database_url)?;
                let pg = PgEventStorage::new(url)?;
                let sled = SledEventStorage::new(asset_pair)?;
                Ok(EventStorage::Dual(DualDbEventStorage::new(sled, pg)?))
            }
        }
    }

    fn extract_database_url(database_url: &Option<String>) -> Result<&String, SibylsError> {
        if let Some(url) = database_url {
            Ok(url)
        } else {
            Err(SibylsError::InternalError("The database URL is not set. Use --database-url command line option or DATABASE_URL environment variable to set it".to_string()))
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
            EventStorage::Dual(storage) => storage.get_oracle_event(maturation, asset_pair),
        }
    }

    pub fn list_oracle_events(&self, filters: Filters) -> Result<Vec<OracleEvent>, SibylsError> {
        match self {
            EventStorage::Sled(storage) => storage.list_oracle_events(filters),
            EventStorage::Pg(storage) => storage.list_oracle_events(filters),
            EventStorage::Dual(storage) => storage.list_oracle_events(filters),
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
            EventStorage::Dual(storage) => {
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
            EventStorage::Dual(storage) => {
                storage.store_attestation(maturation, asset_pair, att, price)
            }
        }
    }
}
