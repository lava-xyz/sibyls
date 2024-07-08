use diesel::r2d2::{ConnectionManager, Pool};
use diesel::{
    Connection, ExpressionMethods, Insertable, OptionalExtension, PgConnection, Queryable,
    Selectable, SelectableHelper,
};
use dlc_messages::oracle_msgs::{EventDescriptor, OracleAnnouncement, OracleAttestation};
use dlc_messages::ser_impls::{read_as_tlv, write_as_tlv};
use hex::FromHex;
use hex::ToHex;
use log::info;
use serde::{Deserialize, Serialize};
use sled::{Db, IVec};
use std::str::FromStr;
use time::format_description::well_known::Rfc3339;
use time::{Duration, OffsetDateTime};

use crate::error::SibylsError;
use crate::Filters;
use crate::{AssetPair, OracleEvent, SortOrder, PAGE_SIZE};

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

#[derive(Queryable, Selectable)]
#[diesel(table_name = crate::schema::events)]
#[diesel(check_for_backend(diesel::pg::Pg))]
pub struct EventDTO {
    maturation: OffsetDateTime,
    asset_pair: String,
    announcement: String,
    outstanding_sk_nonces: String,
    attestation: Option<String>,
    price: Option<i64>,
}

#[derive(Insertable)]
#[diesel(table_name = crate::schema::events)]
struct NewEvent {
    pub maturation: OffsetDateTime,
    pub asset_pair: String,
    pub announcement: String,
    pub outstanding_sk_nonces: String,
}

impl EventDTO {
    pub fn to_oracle_event(&self) -> Result<OracleEvent, SibylsError> {
        let maturation = self.maturation.clone();
        let outcome = self.price.clone().map(|x| x as u64);
        let asset_pair = AssetPair::from_str(&self.asset_pair)?;
        let outstanding_sk_nonces = self
            .outstanding_sk_nonces
            .split(",")
            .map(|hex| FromHex::from_hex(hex))
            .collect::<Result<Vec<[u8; 32]>, _>>()
            .map_err(|_| {
                SibylsError::InternalError("Invalid outstanding_sk_nonces hex".to_string())
            })?;
        let announcement_bytes: Vec<u8> = FromHex::from_hex(&self.announcement)
            .map_err(|_| SibylsError::InternalError("Invalid announcement hex".to_string()))?;
        let announcement: OracleAnnouncement = read_as_tlv(&mut announcement_bytes.as_slice())
            .map_err(|_| SibylsError::InternalError("Invalid announcement".to_string()))?;
        let attestation_bytes: Option<Vec<u8>> =
            match self.attestation.clone() {
                None => None,
                Some(a) => Some(FromHex::from_hex(a).map_err(|_| {
                    SibylsError::InternalError("Invalid attestation hex".to_string())
                })?),
            };

        let attestation: Option<OracleAttestation> = match attestation_bytes {
            None => None,
            Some(a) => Some(
                read_as_tlv(&mut a.as_slice())
                    .map_err(|_| SibylsError::InternalError("Invalid attestation ".to_string()))?,
            ),
        };

        Ok(OracleEvent {
            asset_pair,
            maturation,
            outstanding_sk_nonces,
            announcement,
            attestation,
            outcome,
        })
    }
}

#[derive(Debug, Clone)]
pub struct PgEventStorage {
    pool: Pool<ConnectionManager<PgConnection>>,
}

impl PgEventStorage {
    pub fn new(database_url: &String) -> Result<Self, SibylsError> {
        let manager = ConnectionManager::<PgConnection>::new(database_url);
        let pool = Pool::builder().build(manager).map_err(|_| {
            SibylsError::InternalError("Invalid Database Connection pool".to_string())
        })?;
        Ok(Self { pool })
    }

    fn get_oracle_event(
        &self,
        maturation: &OffsetDateTime,
        asset_pair: AssetPair,
    ) -> Result<OracleEvent, SibylsError> {
        use crate::schema::events::dsl::events;
        use diesel::QueryDsl;
        use diesel::RunQueryDsl;

        let mut conn = self
            .pool
            .get()
            .map_err(|e| SibylsError::PgDatabasePoolError(e.to_string()))?;
        let result = events
            .find((maturation, asset_pair.to_string()))
            .select(EventDTO::as_select())
            .first(&mut conn)
            .optional()?;

        if let Some(event) = result {
            event.to_oracle_event()
        } else {
            return Err(SibylsError::OracleEventNotFoundError(format!(
                "{} {asset_pair}",
                maturation.format(&Rfc3339).unwrap()
            ))
            .into());
        }
    }

    fn list_oracle_events(&self, filters: Filters) -> Result<Vec<OracleEvent>, SibylsError> {
        use crate::schema::events::asset_pair;
        use crate::schema::events::dsl::events;
        use crate::schema::events::dsl::maturation;

        use diesel::QueryDsl;
        use diesel::RunQueryDsl;
        let mut conn = self
            .pool
            .get()
            .map_err(|e| SibylsError::PgDatabasePoolError(e.to_string()))?;
        let results = match filters.sort_by {
            SortOrder::Insertion => events
                .filter(asset_pair.eq(filters.asset_pair.to_string()))
                .select(EventDTO::as_select())
                .order(maturation.asc())
                .limit(PAGE_SIZE as i64)
                .offset((filters.page * PAGE_SIZE) as i64)
                .load(&mut conn)?,
            SortOrder::ReverseInsertion => events
                .filter(asset_pair.eq(filters.asset_pair.to_string()))
                .select(EventDTO::as_select())
                .order(maturation.desc())
                .limit(PAGE_SIZE as i64)
                .offset((filters.page * PAGE_SIZE) as i64)
                .load(&mut conn)?,
        };

        let mut res = vec![];
        for event in results {
            res.push(event.to_oracle_event()?);
        }
        Ok(res)
    }

    fn store_announcement(
        &self,
        maturation: &OffsetDateTime,
        asset_pair: AssetPair,
        ann: &OracleAnnouncement,
        sk_nonces: &Vec<[u8; 32]>,
    ) -> Result<(), SibylsError> {
        use crate::schema::events::dsl::announcement;
        use crate::schema::events::dsl::events;
        use crate::schema::events::dsl::outstanding_sk_nonces;
        use diesel::QueryDsl;
        use diesel::RunQueryDsl;
        let mut conn = self
            .pool
            .get()
            .map_err(|e| SibylsError::PgDatabasePoolError(e.to_string()))?;
        let mut announcement_bytes = Vec::new();
        write_as_tlv(ann, &mut announcement_bytes)
            .map_err(|_| SibylsError::InternalError("Invalid announcement".to_string()))?;
        let announcement_hex = announcement_bytes.encode_hex::<String>();

        let sk_nonces_hex = sk_nonces
            .iter()
            .map(|bytes| bytes.encode_hex::<String>())
            .collect::<Vec<String>>()
            .join(",");

        // BEGIN
        conn.transaction(|connection| {
            let results = {
                events
                    .find((maturation, asset_pair.to_string()))
                    .select(EventDTO::as_select())
                    .first(connection)
                    .optional()?
            };

            if results.is_some() {
                diesel::update(events.find((maturation, asset_pair.to_string())))
                    .set((
                        announcement.eq(announcement_hex),
                        outstanding_sk_nonces.eq(sk_nonces_hex),
                    ))
                    .returning(EventDTO::as_returning())
                    .get_result(connection)?;
            } else {
                let new_event = NewEvent {
                    maturation: maturation.clone(),
                    asset_pair: asset_pair.to_string(),
                    announcement: announcement_hex,
                    outstanding_sk_nonces: sk_nonces_hex,
                };
                diesel::insert_into(crate::schema::events::table)
                    .values(new_event)
                    .returning(EventDTO::as_returning())
                    .get_result(connection)?;
            }
            Ok(())
        })
        // COMMIT
        // Ok(())
    }

    fn store_attestation(
        &self,
        maturation: &OffsetDateTime,
        asset_pair: AssetPair,
        att: &OracleAttestation,
        outcome: u64,
    ) -> Result<(), SibylsError> {
        use crate::schema::events::dsl::attestation;
        use crate::schema::events::dsl::events;
        use crate::schema::events::dsl::price;
        use diesel::QueryDsl;
        use diesel::RunQueryDsl;

        let mut conn = self
            .pool
            .get()
            .map_err(|e| SibylsError::PgDatabasePoolError(e.to_string()))?;

        let mut attestation_bytes = Vec::new();
        write_as_tlv(att, &mut attestation_bytes)
            .map_err(|_| SibylsError::InternalError("Invalid announcement".to_string()))?;
        let attestation_hex = attestation_bytes.encode_hex::<String>();

        let p = outcome as i64;

        diesel::update(events.find((maturation, asset_pair.to_string())))
            .set((attestation.eq(attestation_hex), price.eq(p)))
            .execute(&mut conn)?;
        Ok(())
    }
}

#[derive(Clone, Deserialize, Serialize)]
// outstanding_sk_nonces?, announcement, attetstation?, outcome?
struct DbValue(
    pub Option<Vec<[u8; 32]>>,
    pub Vec<u8>,
    pub Option<Vec<u8>>,
    pub Option<u64>,
);

#[derive(Debug, Clone)]
pub struct SledEventStorage {
    event_database: Db,
}

impl SledEventStorage {
    pub fn new(asset_pair: AssetPair) -> Result<Self, SibylsError> {
        let path = format!("events/{}", asset_pair);
        info!("creating sled at {}", path);
        let event_database = sled::open(path)?;
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
            outstanding_sk_nonces: event.0.unwrap(),
        }
    }

    fn get_oracle_event(
        &self,
        maturation: &OffsetDateTime,
        asset_pair: AssetPair,
    ) -> Result<OracleEvent, SibylsError> {
        let id = maturation.format(&Rfc3339).unwrap();
        match self
            .event_database
            .get(id.to_owned().into_bytes())
            .map_err(SibylsError::SledDatabaseError)?
        {
            Some(event) => Ok(SledEventStorage::parse_database_entry(
                asset_pair,
                (id.as_str().into(), event),
            )),
            None => return Err(SibylsError::OracleEventNotFoundError(id.to_string()).into()),
        }
    }

    fn list_oracle_events(&self, filters: Filters) -> Result<Vec<OracleEvent>, SibylsError> {
        if self.event_database.is_empty() {
            return Ok(vec![]);
        }

        let start = filters.page * PAGE_SIZE;

        match filters.sort_by {
            SortOrder::Insertion => loop {
                let init_key = self
                    .event_database
                    .first()
                    .map_err(SibylsError::SledDatabaseError)?
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
                        .map_err(SibylsError::SledDatabaseError)?
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
                            SledEventStorage::parse_database_entry(
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
                    .map_err(SibylsError::SledDatabaseError)?
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
                        .map_err(SibylsError::SledDatabaseError)?
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
                            SledEventStorage::parse_database_entry(
                                filters.asset_pair,
                                result.unwrap(),
                            )
                        })
                        .collect::<Vec<_>>());
                }
            },
        }
    }

    fn store_announcement(
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
            Err(err) => Err(SibylsError::SledDatabaseError(err)),
        }
    }

    fn store_attestation(
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
            .map_err(SibylsError::SledDatabaseError)?
        {
            Some(event) => {
                let mut db_value: DbValue =
                    serde_json::from_str(&String::from_utf8_lossy(&event)).unwrap();
                let mut attestation_bytes = Vec::new();
                write_as_tlv(attestation, &mut attestation_bytes)
                    .map_err(|_| SibylsError::InternalError("Invalid attestation".to_string()))?;
                db_value.2 = Some(attestation_bytes);
                db_value.3 = Some(price);
                match self.event_database.insert(
                    id.into_bytes(),
                    serde_json::to_string(&db_value).unwrap().into_bytes(),
                ) {
                    Ok(_) => Ok(()),
                    Err(err) => Err(SibylsError::SledDatabaseError(err)),
                }
            }
            None => return Err(SibylsError::OracleEventNotFoundError(id.to_string()).into()),
        }
    }
}

#[cfg(test)]
mod tests {
    use diesel::{Connection, PgConnection, RunQueryDsl};
    use std::path::Path;

    use dlc_messages::oracle_msgs::{OracleAnnouncement, OracleAttestation};
    use secp256k1::{rand, All, KeyPair, Secp256k1};
    use time::format_description::well_known::Rfc3339;
    use time::{Duration, OffsetDateTime};

    use crate::db::{PgEventStorage, SledEventStorage};
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

    fn setup_pg() -> (KeyPair, Secp256k1<All>, PgEventStorage) {
        use crate::schema::events::dsl::events;
        use std::env;
        let database_url = env::var("TEST_DATABASE_URL").expect("TEST_DATABASE_URL is not set");
        let mut connection = PgConnection::establish(&database_url).unwrap();
        let _ = diesel::delete(events)
            .execute(&mut connection)
            .expect("Error deleting posts");
        let db: PgEventStorage = PgEventStorage::new(&database_url.to_string()).unwrap();
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
        assert_eq!(event.outstanding_sk_nonces, sk_nonces);

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
        println!("{vec:?}");
        assert_eq!(vec.len(), 2);

        assert_ne!(vec[0], vec[1]);
    }

    // To run this test you first need to
    // 1. Create a database
    // 2. Run this command to create the tables: diesel migration run
    // 3. Run this command to run the test: TEST_DATABASE_URL=postgres://user:password@database_host/database_name cargo test -- --include-ignored
    #[test]
    #[ignore]
    fn pg_happy_path() {
        let (keypar, secp, db) = setup_pg();

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
        assert_eq!(
            res,
            Err(SibylsError::OracleEventNotFoundError(format!(
                "{id} BTCUSD"
            )))
        );

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
        assert_eq!(event.outstanding_sk_nonces, sk_nonces);

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

        let res = db.list_oracle_events(Filters {
            sort_by: SortOrder::ReverseInsertion,
            page: 0,
            asset_pair: ASSET_PAIR,
        });

        assert!(res.is_ok());
        let rev_vec = res.unwrap();
        assert_eq!(rev_vec.len(), 2);

        assert_eq!(vec[0], rev_vec[1]);
        assert_eq!(vec[1], rev_vec[0]);
    }
}
