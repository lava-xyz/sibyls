use crate::error::SibylsError;
use crate::{AssetPair, Filters, OracleEvent, SortOrder, PAGE_SIZE};
use diesel::r2d2::{ConnectionManager, Pool};
use diesel::{
    ExpressionMethods, Insertable, OptionalExtension, PgConnection, Queryable, Selectable,
    SelectableHelper,
};
use dlc_messages::oracle_msgs::{OracleAnnouncement, OracleAttestation};
use dlc_messages::ser_impls::{read_as_tlv, write_as_tlv};
use hex::{FromHex, ToHex};
use std::str::FromStr;
use time::format_description::well_known::Rfc3339;
use time::OffsetDateTime;

#[derive(Queryable, Selectable, Insertable)]
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

    pub(crate) fn get_oracle_event(
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

    pub(crate) fn list_oracle_events(
        &self,
        filters: Filters,
    ) -> Result<Vec<OracleEvent>, SibylsError> {
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

    pub(crate) fn store_announcement(
        &self,
        maturation: &OffsetDateTime,
        asset_pair: AssetPair,
        ann: &OracleAnnouncement,
        sk_nonces: &Vec<[u8; 32]>,
    ) -> Result<(), SibylsError> {
        use diesel::RunQueryDsl;
        let mut announcement_bytes = Vec::new();
        write_as_tlv(ann, &mut announcement_bytes)
            .map_err(|_| SibylsError::InternalError("Invalid announcement".to_string()))?;
        let announcement_hex = announcement_bytes.encode_hex::<String>();

        let sk_nonces_hex = sk_nonces
            .iter()
            .map(|bytes| bytes.encode_hex::<String>())
            .collect::<Vec<String>>()
            .join(",");

        let new_event = EventDTO {
            maturation: maturation.clone(),
            asset_pair: asset_pair.to_string(),
            announcement: announcement_hex,
            outstanding_sk_nonces: sk_nonces_hex,
            attestation: None,
            price: None,
        };

        let mut conn = self
            .pool
            .get()
            .map_err(|e| SibylsError::PgDatabasePoolError(e.to_string()))?;

        diesel::insert_into(crate::schema::events::table)
            .values(new_event)
            .returning(EventDTO::as_returning())
            .get_result(&mut conn)?;
        Ok(())
    }

    pub(crate) fn store_attestation(
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
#[cfg(test)]
mod tests {
    use diesel::{Connection, PgConnection, RunQueryDsl};

    use dlc_messages::oracle_msgs::{OracleAnnouncement, OracleAttestation};
    use secp256k1::{rand, All, KeyPair, Secp256k1};
    use time::format_description::well_known::Rfc3339;
    use time::{Duration, OffsetDateTime};

    use crate::db::PgEventStorage;
    use crate::error::SibylsError;
    use crate::{
        build_announcement, build_attestation, AssetPair, AssetPairInfo, Filters,
        SerializableEventDescriptor, SigningVersion, SortOrder,
    };

    const ASSET_PAIR: AssetPair = AssetPair::BTCUSD;

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
