use crate::AssetPairInfo;
use chrono::Utc;
use clokwerk::AsyncScheduler;
use event_structs::*;
use queues::{CircularBuffer, IsQueue};
use secp256k1_zkp::{
    hashes::*,
    rand::{self, rngs::ThreadRng, RngCore},
    All, KeyPair, Message, Secp256k1, XOnlyPublicKey as SchnorrPublicKey,
};
use serde::Serialize;
use serde_json;
use sled::Db;
use time::{Duration, OffsetDateTime, Time};
use tokio::task::JoinHandle;

pub mod error;

use error::OracleError;
pub use error::Result;

mod event_structs {
    use secp256k1_zkp::{
        hashes::*, schnorr::Signature as SchnorrSignature, ThirtyTwoByteHash,
        XOnlyPublicKey as SchnorrPublicKey,
    };
    use serde::Deserialize;
    use time::OffsetDateTime;

    const ORACLE_ANNOUNCEMENT_MIDSTATE: [u8; 32] = [
        0x83, 0x7c, 0xc9, 0x00, 0xdb, 0xfe, 0x98, 0xdf, 0x28, 0xe3, 0x32, 0x3e, 0x21, 0xcb, 0x85,
        0x8f, 0x59, 0xb4, 0xad, 0x7a, 0xa8, 0xd6, 0xe5, 0x8c, 0xe9, 0x3f, 0x9f, 0xef, 0x80, 0xaf,
        0xfb, 0x0f,
    ];

    sha256t_hash_newtype!(
        OracleAnnouncementHash,
        OracleAnnouncementHashTag,
        ORACLE_ANNOUNCEMENT_MIDSTATE,
        64,
        doc = "oracle announcement tagged hash",
        true
    );

    impl ThirtyTwoByteHash for OracleAnnouncementHash {
        fn into_32(self) -> [u8; 32] {
            self.into_inner()
        }
    }

    #[derive(Clone, Debug)]
    pub struct Announcement {
        pub signature: SchnorrSignature,
        pub oracle_pubkey: SchnorrPublicKey,
        pub oracle_event: OracleEvent,
    }

    #[derive(Clone, Debug)]
    pub struct OracleEvent {
        pub nonces: Vec<SchnorrPublicKey>,
        pub maturation: OffsetDateTime,
        pub event_descriptor: EventDescriptor,
    }

    #[derive(Clone, Debug, Deserialize)]
    pub struct EventDescriptor {
        pub base: u64,
        pub is_signed: bool,
        pub unit: String,
        pub precision: u32,
        pub num_digits: u16,
    }

    #[derive(Clone, Debug)]
    pub struct Attestation {
        pub oracle_pubkey: SchnorrPublicKey,
        pub signatures: Vec<SchnorrSignature>,
        pub outcomes: Vec<String>,
    }

    impl Announcement {
        pub fn encode(&self) -> String {
            todo!()
        }
    }

    impl OracleEvent {
        pub fn encode(&self) -> String {
            todo!()
        }
    }

    impl Attestation {
        pub fn encode(&self) -> String {
            todo!()
        }
    }
}

pub use event_structs::EventDescriptor;

#[derive(Serialize)]
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

pub struct OracleScheduler {
    oracle: Oracle,
    scheduler: AsyncScheduler<Utc>,
    secp: Secp256k1<All>,
    attestation_time: Time,
    announcement_offset: Duration,
    outstanding_sk_nonces: CircularBuffer<Vec<[u8; 32]>>,
}

impl OracleScheduler {
    fn init(
        oracle: Oracle,
        attestation_time: Time,
        announcement_offset: Duration,
    ) -> JoinHandle<Result<()>> {
        let clone = oracle.clone();
        // start event creation task
        tokio::spawn(async move {
            OracleScheduler {
                oracle: clone,
                scheduler: AsyncScheduler::with_tz(Utc),
                secp: Secp256k1::new(),
                attestation_time,
                announcement_offset,
                outstanding_sk_nonces: CircularBuffer::new(0),
            }
            .create_events(attestation_time, announcement_offset)
            .await
        })
    }

    async fn create_events(
        &mut self,
        attestation_time: Time,
        announcement_offset: Duration,
    ) -> Result<()> {
        let now = OffsetDateTime::now_utc();
        let mut next_attestation = now.clone().replace_time(attestation_time);
        if next_attestation < now {
            next_attestation += Duration::DAY;
        }
        let mut next_announcement = next_attestation - announcement_offset;
        self.outstanding_sk_nonces = CircularBuffer::new(
            ((now - next_announcement).whole_days() + 1)
                .try_into()
                .expect("should not happen"),
        );
        while next_announcement <= now {
            let oracle_event =
                self.build_oracle_event(next_announcement + announcement_offset, false)?;

            let announcement = Announcement {
                signature: self.secp.sign_schnorr(
                    &Message::from_hashed_data::<OracleAnnouncementHash>(
                        &oracle_event.encode().into_bytes(),
                    ),
                    &self.oracle.keypair,
                ),
                oracle_pubkey: self.oracle.keypair.public_key(),
                oracle_event,
            };
            self.oracle.event_database.insert(
                next_attestation.to_string().into_bytes(),
                serde_json::to_string(&DbValue(announcement.encode(), None))?.into_bytes(),
            );
            next_announcement += Duration::DAY;
        }

        todo!()
    }

    fn build_oracle_event(
        &mut self,
        maturation: OffsetDateTime,
        should_circulate: bool,
    ) -> Result<OracleEvent> {
        let secp = Secp256k1::new();
        let mut rng = rand::thread_rng();
        let digits = self.oracle.asset_pair_info.event_descriptor.num_digits;
        let mut sk_nonces = Vec::with_capacity(digits.into());
        let mut nonces = Vec::with_capacity(digits.into());
        for _ in 0..digits {
            let mut sk_nonce = [0u8; 32];
            rng.fill_bytes(&mut sk_nonce);
            let oracle_r_kp = secp256k1_zkp::KeyPair::from_seckey_slice(&secp, &sk_nonce)?;
            let nonce = SchnorrPublicKey::from_keypair(&oracle_r_kp);
            sk_nonces.push(sk_nonce);
            nonces.push(nonce);
        }
        assert_eq!(
            match self
                .outstanding_sk_nonces
                .add(sk_nonces)
                .expect("should not happen")
            {
                None => false,
                Some(_) => true,
            },
            should_circulate
        );
        Ok(OracleEvent {
            nonces,
            maturation,
            event_descriptor: self.oracle.asset_pair_info.event_descriptor.clone(),
        })
    }
}

mod pricefeeds;
