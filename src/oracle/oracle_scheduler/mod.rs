use super::{
    pricefeeds::{PriceFeed, Result as PriceFeedResult},
    DbValue, Oracle,
};
use chrono::Utc;
use clokwerk::{AsyncScheduler, Job, TimeUnits};
use core::ptr;
use futures::{stream, StreamExt};
use log::info;
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
    All, KeyPair, Message, Secp256k1, Signing, XOnlyPublicKey as SchnorrPublicKey,
};
use serde_json;
use std::sync::Arc;
use time::{
    format_description::well_known::Rfc3339, macros::format_description, Duration, OffsetDateTime,
    Time,
};
use tokio::{
    sync::{mpsc, Mutex},
    time::sleep,
};

mod error;
pub use error::OracleSchedulerError;
pub use error::Result;

pub mod messaging;
use messaging::{Announcement, Attestation, OracleAnnouncementHash, OracleEvent};

const SCHEDULER_SLEEP_TIME: std::time::Duration = std::time::Duration::from_millis(100);

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
    pricefeeds: Vec<Box<dyn PriceFeed + Send + Sync>>,
    announcement_offset: Duration,
    event_infos: Queue<EventInfo>,
    next_announcement: OffsetDateTime,
    next_attestation: OffsetDateTime,
}

impl OracleScheduler {
    fn create_scheduler_event(&mut self) -> Result<()> {
        create_event(
            &mut self.oracle,
            &self.secp,
            &mut self.event_infos,
            self.next_announcement + self.announcement_offset,
        )?;
        self.next_announcement += Duration::DAY;
        Ok(())
    }

    async fn attest(&mut self) -> Result<()> {
        info!("retrieving pricefeeds for attestation");
        let prices = stream::iter(self.pricefeeds.iter())
            .then(|pricefeed| async {
                pricefeed
                    .retrieve_price(
                        self.oracle.asset_pair_info.asset_pair,
                        self.next_attestation,
                    )
                    .await
            })
            .collect::<Vec<PriceFeedResult<_>>>()
            .await
            .into_iter()
            .collect::<PriceFeedResult<Vec<_>>>()?;
        let avg_price = prices.iter().sum::<f64>() / prices.len() as f64;
        let avg_price = avg_price.round() as u32;
        info!(
            "average price of {} is {}",
            self.oracle.asset_pair_info.asset_pair, avg_price
        );
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
        info!(
            "attesting with maturation {} and attestation {:#?}",
            self.next_attestation, attestation
        );
        self.oracle.event_database.insert(
            self.next_attestation.format(&Rfc3339).unwrap().into_bytes(),
            serde_json::to_string(&event_info.db_value)?.into_bytes(),
        )?;
        self.next_attestation += Duration::DAY;
        Ok(())
    }
}

pub fn init(
    oracle: Oracle,
    secp: Secp256k1<All>,
    pricefeeds: Vec<Box<dyn PriceFeed + Send + Sync>>,
    attestation_time: Time,
    announcement_offset: Duration,
) -> Result<()> {
    if !announcement_offset.is_positive() {
        return Err(OracleSchedulerError::InvalidAnnouncementTimeError(
            announcement_offset,
        ));
    }

    // start event creation task
    info!("creating oracle events and schedules");
    tokio::spawn(async move {
        let (tx, mut rx) = mpsc::unbounded_channel();
        if let Err(err) = create_events(
            oracle,
            secp,
            pricefeeds,
            attestation_time,
            announcement_offset,
            tx,
        ) {
            panic!("oracle scheduler create_events error: {}", err);
        }
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
    secp: Secp256k1<All>,
    pricefeeds: Vec<Box<dyn PriceFeed + Send + Sync>>,
    attestation_time: Time,
    announcement_offset: Duration,
    error_transmitter: mpsc::UnboundedSender<OracleSchedulerError>,
) -> Result<()> {
    let now = OffsetDateTime::now_utc();
    let mut next_attestation = now.replace_time(attestation_time);
    if next_attestation <= now {
        next_attestation += Duration::DAY;
    }
    let mut next_announcement = next_attestation - announcement_offset;
    let mut event_infos = queue![];
    // create all events that should have already been made
    info!("creating events that should have already been made");
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
        announcement_offset,
        event_infos,
        next_announcement,
        next_attestation,
    }));
    info!(
        "created new oracle scheduler with\n\tannouncements at {}\n\tattestations at {}\n\tnext announcement at {}\n\tnext attestation at {}",
        attestation_time - announcement_offset,
        attestation_time,
        next_announcement,
        next_attestation
    );

    let mut scheduler = AsyncScheduler::with_tz(Utc);
    // schedule announcements
    let error_transmitter_clone = error_transmitter.clone();
    let oracle_scheduler_clone = oracle_scheduler.clone();
    info!("starting announcement scheduler");
    scheduler
        .every(1.day())
        .at(&(attestation_time - announcement_offset)
            .format(&format_description!("[hour]:[minute]:[second]"))
            .unwrap())
        .run(move || {
            let oracle_scheduler_clone = oracle_scheduler_clone.clone();
            let error_transmitter_clone = error_transmitter_clone.clone();
            async move {
                if let Err(err) = oracle_scheduler_clone.lock().await.create_scheduler_event() {
                    info!("error from announcement scheduler");
                    error_transmitter_clone.send(err).unwrap();
                }
            }
        });
    // schedule attestations
    info!("starting attestation scheduler");
    scheduler
        .every(1.day())
        .at(&attestation_time
            .format(&format_description!("[hour]:[minute]:[second]"))
            .unwrap())
        .run(move || {
            let oracle_scheduler_clone = oracle_scheduler.clone();
            let error_transmitter_clone = error_transmitter.clone();
            async move {
                if let Err(err) = oracle_scheduler_clone.lock().await.attest().await {
                    info!("error from attestation scheduler");
                    error_transmitter_clone.send(err).unwrap();
                }
            }
        });
    // busy checking scheduler
    info!("starting busy checking");
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
) -> Result<()> {
    let (oracle_event, outstanding_sk_nonces) = build_oracle_event(oracle, maturation)?;

    let announcement = Announcement {
        signature: secp.sign_schnorr(
            &Message::from_hashed_data::<OracleAnnouncementHash>(&oracle_event.encode()),
            &oracle.keypair,
        ),
        oracle_pubkey: oracle.keypair.public_key(),
        oracle_event,
    };
    let db_value = DbValue(announcement.encode(), None);
    info!(
        "creating oracle event (announcement only) with maturation {} and announcement {:#?}",
        maturation, announcement
    );
    oracle.event_database.insert(
        maturation.format(&Rfc3339).unwrap().into_bytes(),
        serde_json::to_string(&db_value)?.into_bytes(),
    )?;
    event_infos
        .add(EventInfo {
            outstanding_sk_nonces,
            db_value,
        })
        .unwrap();
    Ok(())
}

fn build_oracle_event(
    oracle: &mut Oracle,
    maturation: OffsetDateTime,
) -> Result<(OracleEvent, Vec<[u8; 32]>)> {
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
