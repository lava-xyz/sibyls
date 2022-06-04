use super::{pricefeeds::PriceFeed, DbValue, Oracle, OracleError, Result as OracleResult};
use chrono::Utc;
use clokwerk::{AsyncScheduler, Job, TimeUnits};
use core::ptr;
use parking_lot::Mutex;
use queues::{queue, IsQueue, Queue};
use secp256k1_sys::{
    types::{c_int, c_uchar, c_void, size_t},
    CPtr, SchnorrSigExtraParams,
};
use secp256k1_zkp::{
    constants::SCHNORR_SIGNATURE_SIZE,
    hashes::*,
    rand::{self, RngCore},
    schnorr::Signature as SchnorrSignature,
    All, KeyPair, Message, Secp256k1, Signing, ThirtyTwoByteHash,
    XOnlyPublicKey as SchnorrPublicKey,
};
use serde::Deserialize;
use serde_json;
use std::sync::Arc;
use time::{ext::NumericalDuration, macros::format_description, Duration, OffsetDateTime, Time};
use tokio::{sync::mpsc, task::JoinHandle, time::sleep};

const SCHEDULER_SLEEP_TIME: std::time::Duration = std::time::Duration::from_millis(100);
const ORACLE_ANNOUNCEMENT_MIDSTATE: [u8; 32] = [
    0x83, 0x7c, 0xc9, 0x00, 0xdb, 0xfe, 0x98, 0xdf, 0x28, 0xe3, 0x32, 0x3e, 0x21, 0xcb, 0x85, 0x8f,
    0x59, 0xb4, 0xad, 0x7a, 0xa8, 0xd6, 0xe5, 0x8c, 0xe9, 0x3f, 0x9f, 0xef, 0x80, 0xaf, 0xfb, 0x0f,
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

extern "C" fn constant_nonce_fn(
    nonce32: *mut c_uchar,
    _: *const c_uchar,
    _: size_t,
    _: *const c_uchar,
    _: *const c_uchar,
    _: *const c_uchar,
    _: size_t,
    data: *mut c_void,
) -> c_int {
    unsafe {
        ptr::copy_nonoverlapping(data as *const c_uchar, nonce32, 32);
    }
    1
}

fn sign_schnorr_with_nonce<S: Signing>(
    secp: &Secp256k1<S>,
    msg: &Message,
    keypair: &KeyPair,
    nonce: &[u8; 32],
) -> SchnorrSignature {
    unsafe {
        let mut sig = [0u8; SCHNORR_SIGNATURE_SIZE];
        let nonce_params =
            SchnorrSigExtraParams::new(Some(constant_nonce_fn), nonce.as_c_ptr() as *const c_void);
        assert_eq!(
            1,
            secp256k1_sys::secp256k1_schnorrsig_sign_custom(
                *secp.ctx(),
                sig.as_mut_c_ptr(),
                msg.as_c_ptr(),
                msg.len(),
                keypair.as_ptr(),
                &nonce_params as *const SchnorrSigExtraParams
            )
        );

        SchnorrSignature::from_slice(&sig).unwrap()
    }
}

#[derive(Clone)]
struct EventInfo {
    outstanding_sk_nonces: Vec<[u8; 32]>,
    db_value: DbValue,
}

struct OracleScheduler {
    oracle: Oracle,
    secp: Secp256k1<All>,
    pricefeeds: Vec<Box<dyn PriceFeed + Send>>,
    attestation_time: Time,
    announcement_offset: Duration,
    event_infos: Queue<EventInfo>,
    next_announcement: OffsetDateTime,
    next_attestation: OffsetDateTime,
}

impl OracleScheduler {
    fn create_scheduler_event(&mut self) -> OracleResult<()> {
        create_event(
            &mut self.oracle,
            &self.secp,
            &mut self.event_infos,
            self.next_announcement + self.announcement_offset,
        )?;
        self.next_announcement += Duration::DAY;
        Ok(())
    }

    fn attest(&mut self) -> OracleResult<()> {
        let prices = self.pricefeeds.iter().filter_map(|pricefeed| {
            pricefeed.retrieve_price(
                self.oracle.asset_pair_info.asset_pair,
                self.next_attestation,
            )
        });
        let avg_price = prices.clone().sum::<u32>() as f64 / prices.count() as f64;
        let avg_price = avg_price.round() as u32;
        let avg_price_binary = format!(
            "{:0width$b}",
            avg_price,
            width = self.oracle.asset_pair_info.event_descriptor.num_digits as usize
        );
        let outcomes = avg_price_binary
            .chars()
            .map(|char| char.to_string())
            .collect::<Vec<_>>();
        let mut event_info = self
            .event_infos
            .remove()
            .expect("event_infos should never be empty");
        let signatures = outcomes
            .iter()
            .zip(event_info.outstanding_sk_nonces.iter())
            .map(|(outcome, outstanding_sk_nonce)| {
                sign_schnorr_with_nonce(
                    &self.secp,
                    &Message::from_hashed_data::<sha256::Hash>(outcome.as_bytes()),
                    &self.oracle.keypair,
                    outstanding_sk_nonce,
                )
            })
            .collect::<Vec<_>>();
        let attestation = Attestation {
            oracle_pubkey: self.oracle.keypair.public_key(),
            signatures,
            outcomes,
        };
        event_info.db_value.1 = Some(attestation.encode());
        self.oracle.event_database.insert(
            self.next_attestation.to_string().into_bytes(),
            serde_json::to_string(&event_info.db_value)?.into_bytes(),
        );
        self.next_attestation += Duration::DAY;
        Ok(())
    }
}

pub fn init(
    oracle: Oracle,
    pricefeeds: Vec<Box<dyn PriceFeed + Send>>,
    attestation_time: Time,
    announcement_offset: Duration,
) -> OracleResult<()> {
    if !announcement_offset.is_positive() {
        return Err(OracleError::InvalidAnnouncementTimeError(
            announcement_offset,
        ));
    }

    // start event creation task
    tokio::spawn(async move {
        let (tx, mut rx) = mpsc::unbounded_channel();
        create_events(
            oracle,
            pricefeeds,
            attestation_time,
            announcement_offset,
            tx,
        );
        while let Some(err) = rx.recv().await {
            panic!("oracle scheduler error: {}", err);
        }
        // never be reached
        unreachable!()
    });
    Ok(())
}

fn create_events(
    mut oracle: Oracle,
    pricefeeds: Vec<Box<dyn PriceFeed + Send>>,
    attestation_time: Time,
    announcement_offset: Duration,
    error_transmitter: mpsc::UnboundedSender<OracleError>,
) -> OracleResult<()> {
    let now = OffsetDateTime::now_utc();
    let mut next_attestation = now.clone().replace_time(attestation_time);
    if next_attestation <= now {
        next_attestation += Duration::DAY;
    }
    let mut next_announcement = next_attestation - announcement_offset;
    let secp = Secp256k1::new();
    let mut event_infos = queue![];
    // create all events that should have already been made
    while next_announcement <= now {
        create_event(
            &mut oracle,
            &secp,
            &mut event_infos,
            next_announcement + announcement_offset,
        )?;
        next_announcement += Duration::DAY;
    }
    let oracle_scheduler = Arc::new(Mutex::new(OracleScheduler {
        oracle,
        secp,
        pricefeeds,
        attestation_time,
        announcement_offset,
        event_infos,
        next_announcement,
        next_attestation,
    }));

    let mut scheduler = AsyncScheduler::with_tz(Utc);
    // schedule announcements
    let error_transmitter_clone = error_transmitter.clone();
    let oracle_scheduler_clone = oracle_scheduler.clone();
    scheduler
        .every(1.day())
        .at(&(attestation_time - announcement_offset)
            .format(&format_description!("[hour]:[minute]:[second]"))
            .unwrap())
        .run(move || {
            let oracle_scheduler_clone = oracle_scheduler_clone.clone();
            let error_transmitter_clone = error_transmitter_clone.clone();
            async move {
                if let Err(err) = oracle_scheduler_clone.lock().create_scheduler_event() {
                    error_transmitter_clone.send(err);
                }
            }
        });
    // schedule attestations
    scheduler
        .every(1.day())
        .at(&attestation_time
            .format(&format_description!("[hour]:[minute]:[second]"))
            .unwrap())
        .run(move || {
            let oracle_scheduler_clone = oracle_scheduler.clone();
            let error_transmitter_clone = error_transmitter.clone();
            async move {
                if let Err(err) = oracle_scheduler_clone.lock().attest() {
                    error_transmitter_clone.send(err);
                }
            }
        });
    // busy checking scheduler
    tokio::spawn(async move {
        loop {
            scheduler.run_pending().await;
            sleep(SCHEDULER_SLEEP_TIME).await;
        }
    });
    Ok(())
}

fn create_event(
    oracle: &mut Oracle,
    secp: &Secp256k1<All>,
    event_infos: &mut Queue<EventInfo>,
    maturation: OffsetDateTime,
) -> OracleResult<()> {
    let (oracle_event, outstanding_sk_nonces) = build_oracle_event(oracle, maturation)?;

    let announcement = Announcement {
        signature: secp.sign_schnorr(
            &Message::from_hashed_data::<OracleAnnouncementHash>(oracle_event.encode().as_bytes()),
            &oracle.keypair,
        ),
        oracle_pubkey: oracle.keypair.public_key(),
        oracle_event,
    };
    let db_value = DbValue(announcement.encode(), None);
    oracle.event_database.insert(
        maturation.to_string().into_bytes(),
        serde_json::to_string(&db_value)?.into_bytes(),
    );
    event_infos
        .add(EventInfo {
            outstanding_sk_nonces,
            db_value,
        })
        .expect("should never not be successful");
    Ok(())
}

fn build_oracle_event(
    oracle: &mut Oracle,
    maturation: OffsetDateTime,
) -> OracleResult<(OracleEvent, Vec<[u8; 32]>)> {
    let secp = Secp256k1::new();
    let mut rng = rand::thread_rng();
    let digits = oracle.asset_pair_info.event_descriptor.num_digits;
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
    Ok((
        OracleEvent {
            nonces,
            maturation,
            event_descriptor: oracle.asset_pair_info.event_descriptor.clone(),
        },
        sk_nonces,
    ))
}
