use crate::db::postgres::PgEventStorage;
use crate::db::sled::SledEventStorage;
use crate::error::SibylsError;
use crate::error::SibylsError::OracleEventNotFoundError;
use crate::{AssetPair, Filters, OracleEvent, PAGE_SIZE};
use dlc_messages::oracle_msgs::{OracleAnnouncement, OracleAttestation};
use time::OffsetDateTime;

#[derive(Debug, Clone)]
pub struct DualDbEventStorage {
    sled: SledEventStorage,
    pg: PgEventStorage,
}

impl DualDbEventStorage {
    pub fn new(sled: SledEventStorage, pg: PgEventStorage) -> Result<Self, SibylsError> {
        Ok(Self { sled, pg })
    }

    pub fn get_oracle_event(
        &self,
        maturation: &OffsetDateTime,
        asset_pair: AssetPair,
    ) -> Result<OracleEvent, SibylsError> {
        let res = self.pg.get_oracle_event(maturation, asset_pair);
        match res {
            Err(OracleEventNotFoundError(_)) => self.sled.get_oracle_event(maturation, asset_pair),
            _ => res,
        }
    }
    pub fn list_oracle_events(&self, filters: Filters) -> Result<Vec<OracleEvent>, SibylsError> {
        match self.pg.list_oracle_events(filters.clone()) {
            Ok(pg_list) => {
                if pg_list.len() == PAGE_SIZE as usize {
                    Ok(pg_list)
                } else {
                    match self.sled.list_oracle_events(filters) {
                        Ok(sled_list) => {
                            if sled_list.len() > pg_list.len() {
                                Ok(sled_list)
                            } else {
                                Ok(pg_list)
                            }
                        }
                        Err(err) => Err(err),
                    }
                }
            }
            Err(err) => Err(err),
        }
    }
    pub fn store_announcement(
        &self,
        maturation: &OffsetDateTime,
        asset_pair: AssetPair,
        ann: &OracleAnnouncement,
        outstanding_sk_nonces: &Vec<[u8; 32]>,
    ) -> Result<(), SibylsError> {
        self.sled
            .store_announcement(maturation, asset_pair, ann, outstanding_sk_nonces)
            .and_then(|_| {
                self.pg
                    .store_announcement(maturation, asset_pair, ann, outstanding_sk_nonces)
            })
    }
    pub fn store_attestation(
        &self,
        maturation: &OffsetDateTime,
        asset_pair: AssetPair,
        att: &OracleAttestation,
        price: u64,
    ) -> Result<(), SibylsError> {
        self.sled
            .store_attestation(maturation, asset_pair, att, price)
            .and_then(|_| {
                self.pg
                    .store_attestation(maturation, asset_pair, att, price)
            })
    }
}

#[cfg(test)]
mod tests {
    use crate::db::dual::DualDbEventStorage;
    use crate::db::postgres::PgEventStorage;
    use crate::db::sled::SledEventStorage;
    use crate::error::SibylsError;
    use crate::{
        build_announcement, build_attestation, AssetPair, AssetPairInfo, Filters,
        SerializableEventDescriptor, SigningVersion, SortOrder,
    };
    use diesel::{Connection, PgConnection, RunQueryDsl};
    use secp256k1::{rand, All, KeyPair, Secp256k1};

    use dlc_messages::oracle_msgs::{OracleAnnouncement, OracleAttestation};
    use std::path::Path;
    use time::format_description::well_known::Rfc3339;
    use time::{Duration, OffsetDateTime};

    fn setup(
        test: &str,
    ) -> (
        KeyPair,
        Secp256k1<All>,
        PgEventStorage,
        SledEventStorage,
        DualDbEventStorage,
    ) {
        use crate::schema::events::dsl::events;
        use std::env;
        let database_url = env::var("TEST_DATABASE_URL").expect("TEST_DATABASE_URL is not set");
        let mut connection = PgConnection::establish(&database_url).unwrap();
        let _ = diesel::delete(events)
            .execute(&mut connection)
            .expect("Error deleting posts");
        let pg: PgEventStorage = PgEventStorage::new(&database_url.to_string()).unwrap();
        let db_path = format!("{}_{}", DB_PATH, test);
        if Path::new(&db_path).exists() {
            std::fs::remove_dir_all(&db_path).expect("to remove the db dir");
        }
        let event_database = sled::open(&db_path).unwrap();
        let sled: SledEventStorage = SledEventStorage { event_database };
        let dual = DualDbEventStorage {
            sled: sled.clone(),
            pg: pg.clone(),
        };
        let secp = Secp256k1::new();
        let mut rng = rand::thread_rng();
        let (secret_key, _) = secp.generate_keypair(&mut rng);
        (
            KeyPair::from_secret_key(&secp, &secret_key),
            secp,
            pg,
            sled,
            dual,
        )
    }

    const DB_PATH: &str = "events_db/test";

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
    #[ignore]
    pub fn test_dual_db() {
        let (keypar, secp, pg, sled, dual) = setup("test_get_oracle_event");

        let maturation = OffsetDateTime::now_utc()
            .replace_millisecond(0)
            .unwrap()
            .checked_add(Duration::days(1))
            .unwrap();
        let id = maturation.format(&Rfc3339).unwrap();

        let res = sled.get_oracle_event(&maturation, AssetPair::BTCUSD);

        assert!(res.is_err());
        assert_eq!(
            res,
            Err(SibylsError::OracleEventNotFoundError(format!("{id}")))
        );

        let res = pg.get_oracle_event(&maturation, AssetPair::BTCUSD);

        assert!(res.is_err());
        assert_eq!(
            res,
            Err(SibylsError::OracleEventNotFoundError(format!(
                "{id} BTCUSD"
            )))
        );

        let res = dual.get_oracle_event(&maturation, AssetPair::BTCUSD);

        assert!(res.is_err());
        assert_eq!(
            res,
            Err(SibylsError::OracleEventNotFoundError(format!("{id}")))
        );

        let (ann, sk_nonces) =
            build_test_announcement(&maturation, &keypar, &secp, SigningVersion::Basic);
        let res = sled.store_announcement(&maturation, AssetPair::BTCUSD, &ann, &sk_nonces);
        assert!(res.is_ok());

        let event = sled.get_oracle_event(&maturation, AssetPair::BTCUSD);
        assert!(event.is_ok());

        let res = pg.get_oracle_event(&maturation, AssetPair::BTCUSD);
        assert!(res.is_err());
        assert_eq!(
            res,
            Err(SibylsError::OracleEventNotFoundError(format!(
                "{id} BTCUSD"
            )))
        );

        let res = dual.get_oracle_event(&maturation, AssetPair::BTCUSD);
        assert!(res.is_ok());

        assert_eq!(res, event);

        let res = pg.store_announcement(&maturation, AssetPair::BTCUSD, &ann, &sk_nonces);
        assert!(res.is_ok());

        let event = sled.get_oracle_event(&maturation, AssetPair::BTCUSD);
        assert!(event.is_ok());

        let res = pg.get_oracle_event(&maturation, AssetPair::BTCUSD);
        assert!(res.is_ok());

        let result = dual.get_oracle_event(&maturation, AssetPair::BTCUSD);
        assert!(res.is_ok());

        assert_eq!(event, res);
        assert_eq!(res, result);

        let maturation = maturation.checked_add(Duration::days(1)).unwrap();
        let id = maturation.format(&Rfc3339).unwrap();

        let (ann, sk_nonces) =
            build_test_announcement(&maturation, &keypar, &secp, SigningVersion::Basic);

        let price = 12345;

        let att = build_test_attestation(&sk_nonces, price, &keypar, &secp, SigningVersion::Basic);

        let res = sled.get_oracle_event(&maturation, AssetPair::BTCUSD);
        assert!(res.is_err());
        assert_eq!(
            res,
            Err(SibylsError::OracleEventNotFoundError(format!("{id}")))
        );

        let res = pg.get_oracle_event(&maturation, AssetPair::BTCUSD);

        assert!(res.is_err());
        assert_eq!(
            res,
            Err(SibylsError::OracleEventNotFoundError(format!(
                "{id} BTCUSD"
            )))
        );

        let res = dual.get_oracle_event(&maturation, AssetPair::BTCUSD);

        assert!(res.is_err());
        assert_eq!(
            res,
            Err(SibylsError::OracleEventNotFoundError(format!("{id}")))
        );

        let event = dual.store_announcement(&maturation, AssetPair::BTCUSD, &ann, &sk_nonces);
        assert!(event.is_ok());

        let res_sled = sled.get_oracle_event(&maturation, AssetPair::BTCUSD);
        assert!(res_sled.is_ok());

        let res_pg = pg.get_oracle_event(&maturation, AssetPair::BTCUSD);
        assert!(res_pg.is_ok());

        let res_dual = dual.get_oracle_event(&maturation, AssetPair::BTCUSD);
        assert!(res_dual.is_ok());

        assert_eq!(res_sled, res_pg);
        assert_eq!(res_pg, res_dual);

        let event = dual.store_attestation(&maturation, AssetPair::BTCUSD, &att, price);
        assert!(event.is_ok());

        let res_sled = sled.get_oracle_event(&maturation, AssetPair::BTCUSD);
        assert!(res_sled.is_ok());

        let res_pg = pg.get_oracle_event(&maturation, AssetPair::BTCUSD);
        assert!(res_pg.is_ok());

        let res_dual = dual.get_oracle_event(&maturation, AssetPair::BTCUSD);
        assert!(res_dual.is_ok());

        assert_eq!(res_sled, res_pg);
        assert_eq!(res_pg, res_dual);

        let maturation = maturation.checked_add(Duration::days(2)).unwrap();

        let (ann, sk_nonces) =
            build_test_announcement(&maturation, &keypar, &secp, SigningVersion::Basic);

        let res = dual.list_oracle_events(Filters {
            sort_by: SortOrder::ReverseInsertion,
            page: 0,
            asset_pair: AssetPair::BTCUSD,
        });
        assert!(res.is_ok());
        assert_eq!(res.unwrap().len(), 2);

        let res = pg.list_oracle_events(Filters {
            sort_by: SortOrder::ReverseInsertion,
            page: 0,
            asset_pair: AssetPair::BTCUSD,
        });
        assert!(res.is_ok());
        assert_eq!(res.unwrap().len(), 2);

        let res = sled.list_oracle_events(Filters {
            sort_by: SortOrder::ReverseInsertion,
            page: 0,
            asset_pair: AssetPair::BTCUSD,
        });
        assert!(res.is_ok());
        assert_eq!(res.unwrap().len(), 1);

        let event = sled.store_announcement(&maturation, AssetPair::BTCUSD, &ann, &sk_nonces);
        assert!(event.is_ok());

        let res = dual.list_oracle_events(Filters {
            sort_by: SortOrder::ReverseInsertion,
            page: 0,
            asset_pair: AssetPair::BTCUSD,
        });
        assert!(res.is_ok());
        assert_eq!(res.unwrap().len(), 2);

        let maturation = maturation.checked_add(Duration::days(3)).unwrap();
        let (ann, sk_nonces) =
            build_test_announcement(&maturation, &keypar, &secp, SigningVersion::Basic);

        let event = sled.store_announcement(&maturation, AssetPair::BTCUSD, &ann, &sk_nonces);
        assert!(event.is_ok());

        let res = dual.list_oracle_events(Filters {
            sort_by: SortOrder::ReverseInsertion,
            page: 0,
            asset_pair: AssetPair::BTCUSD,
        });
        assert!(res.is_ok());
        assert_eq!(res.unwrap().len(), 3);
    }
}
