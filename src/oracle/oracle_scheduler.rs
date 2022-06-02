use crate::oracle::{event_structs::*, DbValue, Oracle, OracleError, Result};
use chrono::Utc;
use clokwerk::{AsyncScheduler, Job, TimeUnits};
use parking_lot::Mutex;
use queues::{CircularBuffer, IsQueue};
use secp256k1_zkp::{
    rand::{self, RngCore},
    All, Message, Secp256k1, XOnlyPublicKey as SchnorrPublicKey,
};
use serde_json;
use std::sync::Arc;
use time::{macros::format_description, Duration, OffsetDateTime, Time};
use tokio::{sync::mpsc, task::JoinHandle, time::sleep};

const SCHEDULER_SLEEP_TIME: std::time::Duration = std::time::Duration::from_millis(100);

struct OracleScheduler {
    oracle: Oracle,
    secp: Secp256k1<All>,
    attestation_time: Time,
    announcement_offset: Duration,
    outstanding_sk_nonces: CircularBuffer<Vec<[u8; 32]>>,
    next_attestation: OffsetDateTime,
}

impl OracleScheduler {
    fn create_scheduler_event(&mut self) -> Result<()> {
        create_event(
            &mut self.oracle,
            &self.secp,
            &mut self.outstanding_sk_nonces,
            self.next_attestation,
            true,
        )
    }
}

pub fn init(
    oracle: Oracle,
    attestation_time: Time,
    announcement_offset: Duration,
) -> JoinHandle<Result<()>> {
    if !announcement_offset.is_positive() {
        return tokio::spawn(async move {
            Err(OracleError::InvalidAnnouncementTimeError(
                announcement_offset,
            ))
        });
    }

    // start event creation task
    tokio::spawn(async move {
        let (tx, mut rx) = mpsc::unbounded_channel();
        create_events(oracle, attestation_time, announcement_offset, tx);
        while let Some(err) = rx.recv().await {
            return Err(err);
        }
        Ok(())
    })
}

fn create_events(
    mut oracle: Oracle,
    attestation_time: Time,
    announcement_offset: Duration,
    error_transmitter: mpsc::UnboundedSender<OracleError>,
) -> Result<()> {
    let now = OffsetDateTime::now_utc();
    let mut next_attestation = now.clone().replace_time(attestation_time);
    if next_attestation < now {
        next_attestation += Duration::DAY;
    }
    let mut next_announcement = next_attestation - announcement_offset;
    let secp = Secp256k1::new();
    let mut outstanding_sk_nonces = CircularBuffer::new(
        ((now - next_announcement).whole_days() + 1)
            .try_into()
            .expect("should not happen"),
    );
    // create all events that should have already been made
    while next_announcement <= now {
        create_event(
            &mut oracle,
            &secp,
            &mut outstanding_sk_nonces,
            next_announcement + announcement_offset,
            false,
        )?;
        next_announcement += Duration::DAY;
    }
    let oracle_scheduler = Arc::new(Mutex::new(OracleScheduler {
        oracle,
        secp,
        attestation_time,
        announcement_offset,
        outstanding_sk_nonces,
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
            .expect("should not happen"))
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
            .expect("should not happen"))
        .run(|| async { todo!() });
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
    outstanding_sk_nonces: &mut CircularBuffer<Vec<[u8; 32]>>,
    maturation: OffsetDateTime,
    should_circulate: bool,
) -> Result<()> {
    let oracle_event =
        build_oracle_event(oracle, outstanding_sk_nonces, maturation, should_circulate)?;

    let announcement = Announcement {
        signature: secp.sign_schnorr(
            &Message::from_hashed_data::<OracleAnnouncementHash>(
                &oracle_event.encode().into_bytes(),
            ),
            &oracle.keypair,
        ),
        oracle_pubkey: oracle.keypair.public_key(),
        oracle_event,
    };
    oracle.event_database.insert(
        maturation.to_string().into_bytes(),
        serde_json::to_string(&DbValue(announcement.encode(), None))?.into_bytes(),
    );
    Ok(())
}

fn build_oracle_event(
    oracle: &mut Oracle,
    outstanding_sk_nonces: &mut CircularBuffer<Vec<[u8; 32]>>,
    maturation: OffsetDateTime,
    should_circulate: bool,
) -> Result<OracleEvent> {
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
    assert_eq!(
        match outstanding_sk_nonces
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
        event_descriptor: oracle.asset_pair_info.event_descriptor.clone(),
    })
}
