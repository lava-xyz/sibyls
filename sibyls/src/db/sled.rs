use crate::error::DbError::SledDatabaseError;
use crate::error::SibylsError;
use crate::{AssetPair, Filters, OracleEvent, SortOrder, PAGE_SIZE};
use dlc_messages::oracle_msgs::{EventDescriptor, OracleAnnouncement, OracleAttestation};
use dlc_messages::ser_impls::{read_as_tlv, write_as_tlv};
use log::info;
use serde::{Deserialize, Serialize};
use sled::{Db, IVec};
use std::env;
use time::format_description::well_known::Rfc3339;
use time::{Duration, OffsetDateTime};

#[derive(Clone, Deserialize, Serialize)]
// outstanding_sk_nonces?, announcement, attestation?, outcome?
struct DbValue(
    pub Option<Vec<[u8; 32]>>,
    pub Vec<u8>,
    pub Option<Vec<u8>>,
    pub Option<u64>,
);

#[derive(Debug, Clone)]
pub struct SledEventStorage {
    pub(crate) event_database: Db,
}

impl SledEventStorage {
    pub fn new(asset_pair: AssetPair) -> Result<Self, SibylsError> {
        let base_path = env::var("STORAGE_PATH").unwrap_or_else(|_| "events".to_string());
        let path = format!("{}/{}", base_path, asset_pair);
        info!("creating sled at {}", path);
        let event_database = sled::open(path).map_err(|e| SledDatabaseError(e))?;
        Ok(SledEventStorage { event_database })
    }

    fn parse_database_entry(
        asset_pair: AssetPair,
        (maturation, event): (IVec, IVec),
    ) -> OracleEvent {
        let maturation = String::from_utf8_lossy(&maturation).to_string();
        let maturation = OffsetDateTime::parse(maturation.as_str(), &Rfc3339).expect("");
        let event: DbValue = serde_json::from_str(&String::from_utf8_lossy(&event)).unwrap();

        let announcement: OracleAnnouncement = read_as_tlv(&mut event.1.as_slice()).expect("");
        let attestation: Option<OracleAttestation> = event
            .2
            .map(|att| read_as_tlv(&mut att.as_slice()).expect(""));

        OracleEvent {
            asset_pair,
            announcement,
            attestation,
            maturation,
            outcome: event.3,
            outstanding_sk_nonces: event.0,
        }
    }

    pub(crate) fn get_oracle_event(
        &self,
        maturation: &OffsetDateTime,
        asset_pair: AssetPair,
    ) -> Result<OracleEvent, SibylsError> {
        let id = maturation.format(&Rfc3339).unwrap();
        info!("retrieving oracle event from {id}");
        match self
            .event_database
            .get(id.to_owned().into_bytes())
            .map_err(|e| SledDatabaseError(e))?
        {
            Some(event) => Ok(crate::db::SledEventStorage::parse_database_entry(
                asset_pair,
                (id.as_str().into(), event),
            )),
            None => return Err(SibylsError::OracleEventNotFoundError(id.to_string()).into()),
        }
    }

    pub(crate) fn list_oracle_events(
        &self,
        filters: Filters,
    ) -> Result<Vec<OracleEvent>, SibylsError> {
        if self.event_database.is_empty() {
            return Ok(vec![]);
        }

        let start = filters.page * PAGE_SIZE;

        match filters.sort_by {
            SortOrder::Insertion => loop {
                let init_key = self
                    .event_database
                    .first()
                    .map_err(|e| SledDatabaseError(e))?
                    .unwrap()
                    .0;
                let start_key =
                    OffsetDateTime::parse(&String::from_utf8_lossy(&init_key), &Rfc3339).unwrap();
                let start_key = start_key + Duration::days(start.into());
                let end_key = start_key + Duration::days(PAGE_SIZE.into());
                let start_key = start_key.format(&Rfc3339).unwrap().into_bytes();
                let end_key = end_key.format(&Rfc3339).unwrap().into_bytes();
                if init_key
                    == self
                        .event_database
                        .first()
                        .map_err(|e| SledDatabaseError(e))?
                        .unwrap()
                        .0
                {
                    // don't know if range can change while iterating due to another thread modifying
                    info!(
                        "retrieving oracle events from {} to {}",
                        String::from_utf8_lossy(&start_key),
                        String::from_utf8_lossy(&end_key),
                    );
                    return Ok(self
                        .event_database
                        .range(start_key..end_key)
                        .map(|result| {
                            crate::db::SledEventStorage::parse_database_entry(
                                filters.asset_pair,
                                result.unwrap(),
                            )
                        })
                        .collect::<Vec<_>>());
                }
            },
            SortOrder::ReverseInsertion => loop {
                let init_key = self
                    .event_database
                    .last()
                    .map_err(|e| SledDatabaseError(e))?
                    .unwrap()
                    .0;
                let end_key =
                    OffsetDateTime::parse(&String::from_utf8_lossy(&init_key), &Rfc3339).unwrap();
                let end_key = end_key - Duration::days(start.into());
                let start_key = end_key - Duration::days(PAGE_SIZE.into());
                let start_key = start_key.format(&Rfc3339).unwrap().into_bytes();
                let end_key = end_key.format(&Rfc3339).unwrap().into_bytes();
                if init_key
                    == self
                        .event_database
                        .last()
                        .map_err(|e| SledDatabaseError(e))?
                        .unwrap()
                        .0
                {
                    // don't know if range can change while iterating due to another thread modifying
                    info!(
                        "retrieving oracle events from {} to {}",
                        String::from_utf8_lossy(&start_key),
                        String::from_utf8_lossy(&end_key),
                    );
                    return Ok(self
                        .event_database
                        .range(start_key..end_key)
                        .map(|result| {
                            crate::db::SledEventStorage::parse_database_entry(
                                filters.asset_pair,
                                result.unwrap(),
                            )
                        })
                        .collect::<Vec<_>>());
                }
            },
        }
    }

    pub(crate) fn store_announcement(
        &self,
        maturation: &OffsetDateTime,
        _: AssetPair,
        announcement: &OracleAnnouncement,
        outstanding_sk_nonces: &Vec<[u8; 32]>,
    ) -> Result<(), SibylsError> {
        if announcement.oracle_event.event_maturity_epoch as i64 != maturation.unix_timestamp() {
            return Err(SibylsError::InternalError(format!(
                "invalid event maturity epoch: {} expected {}",
                announcement.oracle_event.event_maturity_epoch,
                maturation.unix_timestamp()
            )));
        }
        match &announcement.oracle_event.event_descriptor {
            EventDescriptor::EnumEvent(_) => {
                return Err(SibylsError::InternalError(
                    "enum events are not supported".into(),
                ))
            }
            EventDescriptor::DigitDecompositionEvent(desc) => {
                let unit = format!("\"{}\"", &desc.unit);
                if let Err(err) = serde_json::from_str::<AssetPair>(&unit) {
                    return Err(SibylsError::InternalError(format!(
                        "unsupported asset pair: {};  {}",
                        unit, err
                    )));
                }
            }
        }
        let id = maturation.format(&Rfc3339).unwrap();
        let mut announcement_bytes = Vec::new();
        write_as_tlv(announcement, &mut announcement_bytes)
            .map_err(|_| SibylsError::InternalError("Invalid announcement".to_string()))?;

        let db_value = DbValue(
            Some(outstanding_sk_nonces.clone()),
            announcement_bytes,
            None,
            None,
        );
        match self.event_database.insert(
            id.into_bytes(),
            serde_json::to_string(&db_value).unwrap().into_bytes(),
        ) {
            Ok(_) => Ok(()),
            Err(err) => Err(SibylsError::from(SledDatabaseError(err))),
        }
    }

    pub(crate) fn store_attestation(
        &self,
        maturation: &OffsetDateTime,
        _: AssetPair,
        attestation: &OracleAttestation,
        price: u64,
    ) -> Result<(), SibylsError> {
        let id = maturation.format(&Rfc3339).unwrap();
        match self
            .event_database
            .get(id.to_owned().into_bytes())
            .map_err(|e| SledDatabaseError(e))?
        {
            Some(event) => {
                let mut db_value: DbValue =
                    serde_json::from_str(&String::from_utf8_lossy(&event)).unwrap();
                let mut attestation_bytes = Vec::new();
                write_as_tlv(attestation, &mut attestation_bytes)
                    .map_err(|_| SibylsError::InternalError("Invalid attestation".to_string()))?;
                db_value.0 = None;
                db_value.2 = Some(attestation_bytes);
                db_value.3 = Some(price);
                match self.event_database.insert(
                    id.into_bytes(),
                    serde_json::to_string(&db_value).unwrap().into_bytes(),
                ) {
                    Ok(_) => Ok(()),
                    Err(err) => Err(SibylsError::from(SledDatabaseError(err))),
                }
            }
            None => return Err(SibylsError::OracleEventNotFoundError(id.to_string()).into()),
        }
    }
}
#[cfg(test)]
mod tests {
    use std::path::Path;

    use dlc_messages::oracle_msgs::{OracleAnnouncement, OracleAttestation};
    use secp256k1::{rand, All, KeyPair, Secp256k1};
    use time::format_description::well_known::Rfc3339;
    use time::{Duration, OffsetDateTime};

    use crate::db::SledEventStorage;
    use crate::error::SibylsError;
    use crate::{
        build_announcement, build_attestation, AssetPair, AssetPairInfo, Filters,
        SerializableEventDescriptor, SigningVersion, SortOrder,
    };

    const ASSET_PAIR: AssetPair = AssetPair::BTCUSD;
    const DB_PATH: &str = "events_db/test";

    fn setup_sled() -> (KeyPair, Secp256k1<All>, SledEventStorage) {
        if Path::new(DB_PATH).exists() {
            std::fs::remove_dir_all(DB_PATH).expect("to remove the db dir");
        }
        let event_database = sled::open(DB_PATH).unwrap();
        let db: SledEventStorage = SledEventStorage { event_database };
        let secp = Secp256k1::new();
        let mut rng = rand::thread_rng();
        let (secret_key, _) = secp.generate_keypair(&mut rng);
        (KeyPair::from_secret_key(&secp, &secret_key), secp, db)
    }

    pub(crate) fn build_test_announcement(
        maturation: &OffsetDateTime,
        keypair: &KeyPair,
        secp: &Secp256k1<All>,
        signing_version: SigningVersion,
    ) -> (OracleAnnouncement, Vec<[u8; 32]>) {
        let (announcement, outstanding_sk_nonces) = build_announcement(
            &AssetPairInfo {
                asset_pair: AssetPair::BTCUSD,
                event_descriptor: SerializableEventDescriptor {
                    base: 2,
                    is_signed: false,
                    unit: "BTCUSD".to_string(),
                    precision: 0,
                    num_digits: 18,
                },
                include_price_feeds: vec![],
                exclude_price_feeds: vec![],
            },
            &keypair,
            &secp,
            maturation,
            signing_version,
        )
        .unwrap();
        (announcement, outstanding_sk_nonces)
    }

    pub(crate) fn build_test_attestation(
        outstanding_sk_nonces: &[[u8; 32]],
        price: u64,
        keypair: &KeyPair,
        secp: &Secp256k1<All>,
        signing_version: SigningVersion,
    ) -> OracleAttestation {
        let avg_price_binary = format!("{:0width$b}", price, width = 18);
        let outcomes = avg_price_binary
            .chars()
            .map(|char| char.to_string())
            .collect::<Vec<_>>();

        build_attestation(
            outstanding_sk_nonces,
            keypair,
            secp,
            outcomes,
            signing_version,
        )
    }

    #[test]
    fn sled_happy_path() {
        let (keypar, secp, db) = setup_sled();

        let res = db.list_oracle_events(Filters {
            sort_by: SortOrder::Insertion,
            page: 0,
            asset_pair: ASSET_PAIR,
        });
        assert!(res.is_ok());
        assert_eq!(res.unwrap().len(), 0);

        let maturation = OffsetDateTime::now_utc().replace_millisecond(0).unwrap();
        let id = maturation.format(&Rfc3339).unwrap();

        let res = db.get_oracle_event(&maturation, ASSET_PAIR);

        assert!(res.is_err());
        assert_eq!(res, Err(SibylsError::OracleEventNotFoundError(id)));

        let (ann, sk_nonces) =
            build_test_announcement(&maturation, &keypar, &secp, SigningVersion::Basic);
        let res = db.store_announcement(&maturation, ASSET_PAIR, &ann, &sk_nonces);
        assert!(res.is_ok());

        let event = db.get_oracle_event(&maturation, ASSET_PAIR);
        assert!(event.is_ok());
        let event = event.unwrap();
        assert_eq!(event.announcement, ann);
        assert!(event.attestation.is_none());
        assert_eq!(event.maturation, maturation);
        assert_eq!(event.outcome, None);
        assert_eq!(event.outstanding_sk_nonces, Some(sk_nonces.clone()));

        let res = db.list_oracle_events(Filters {
            sort_by: SortOrder::Insertion,
            page: 0,
            asset_pair: ASSET_PAIR,
        });
        assert!(res.is_ok());
        assert_eq!(res.unwrap().len(), 1);

        let price = 12345;

        let att = build_test_attestation(&sk_nonces, price, &keypar, &secp, SigningVersion::Basic);

        let res = db.store_attestation(&maturation, ASSET_PAIR, &att, price);
        assert!(res.is_ok());

        let event = db.get_oracle_event(&maturation, ASSET_PAIR);
        assert!(event.is_ok());
        let event = event.unwrap();
        assert_eq!(event.announcement, ann);
        assert_eq!(event.attestation, Some(att));
        assert_eq!(event.maturation, maturation);
        assert_eq!(event.outcome, Some(price));

        let maturation = maturation + Duration::days(1);

        let (ann, sk_nonces) =
            build_test_announcement(&maturation, &keypar, &secp, SigningVersion::Basic);
        let res = db.store_announcement(&maturation, ASSET_PAIR, &ann, &sk_nonces);
        assert!(res.is_ok());

        let res = db.list_oracle_events(Filters {
            sort_by: SortOrder::Insertion,
            page: 0,
            asset_pair: ASSET_PAIR,
        });

        assert!(res.is_ok());
        let vec = res.unwrap();
        assert_eq!(vec.len(), 2);

        assert_ne!(vec[0], vec[1]);
    }
}
