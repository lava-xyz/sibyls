use crate::AssetPairInfo;
use secp256k1_zkp::KeyPair;
use serde::Serialize;
use sled::Db;

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

pub mod oracle_scheduler;

mod pricefeeds;
