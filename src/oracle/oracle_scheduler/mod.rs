use super::{
    pricefeeds::{PriceFeed, Result as PriceFeedResult},
    DbValue, Oracle,
};
use crate::AssetPairInfo;
use chrono::Utc;
use clokwerk::{AsyncScheduler, Interval, Job};
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
use time::{format_description::well_known::Rfc3339, macros::format_description, OffsetDateTime};
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

struct OracleScheduler {
    oracle: Oracle,
    secp: Secp256k1<All>,
    pricefeeds: Vec<Box<dyn PriceFeed + Send + Sync>>,
    db_values: Queue<DbValue>,
    next_announcement: OffsetDateTime,
    next_attestation: OffsetDateTime,
}

impl OracleScheduler {
    fn create_scheduler_event(&mut self) -> Result<()> {
        let announcement_offset = self.oracle.oracle_config.announcement_offset;
        create_event(
            &mut self.oracle,
            &self.secp,
            &mut self.db_values,
            self.next_announcement + announcement_offset,
        )?;
        self.next_announcement += self.oracle.oracle_config.frequency;
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
        let avg_price = avg_price.round() as u64;
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
        let mut db_value = self
            .db_values
            .remove()
            .expect("db_values should never be empty");
        let attestation = build_attestation(
            db_value
                .0
                .take()
                .expect("immature db_values should always have outstanding_sk_nonces"),
            &self.oracle.keypair,
            &self.secp,
            outcomes,
        );

        db_value.2 = Some(attestation.encode());
        db_value.3 = Some(avg_price);
        info!(
            "attesting with maturation {} and attestation {:#?}",
            self.next_attestation, attestation
        );
        self.oracle.event_database.insert(
            self.next_attestation.format(&Rfc3339).unwrap().into_bytes(),
            serde_json::to_string(&db_value)?.into_bytes(),
        )?;
        self.next_attestation += self.oracle.oracle_config.frequency;
        Ok(())
    }
}

pub fn init(
    oracle: Oracle,
    secp: Secp256k1<All>,
    pricefeeds: Vec<Box<dyn PriceFeed + Send + Sync>>,
) -> Result<()> {
    // start event creation task
    info!("creating oracle events and schedules");
    tokio::spawn(async move {
        let (tx, mut rx) = mpsc::unbounded_channel();
        if let Err(err) = create_events(oracle, secp, pricefeeds, tx) {
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
    error_transmitter: mpsc::UnboundedSender<OracleSchedulerError>,
) -> Result<()> {
    let now = OffsetDateTime::now_utc();
    let mut next_attestation = now.replace_time(oracle.oracle_config.attestation_time);
    if next_attestation <= now {
        next_attestation += oracle.oracle_config.frequency;
    }
    let mut next_announcement = next_attestation - oracle.oracle_config.announcement_offset;
    let mut db_values = queue![];
    // create all events that should have already been made
    info!("creating events that should have already been made");
    while next_announcement <= now {
        let next_attestation = next_announcement + oracle.oracle_config.announcement_offset;
        match oracle
            .event_database
            .get(next_attestation.format(&Rfc3339).unwrap())?
        {
            None => create_event(&mut oracle, &secp, &mut db_values, next_attestation)?,
            Some(val) => {
                info!(
                    "existing oracle event found in db with maturation {}, skipping creation",
                    next_attestation
                );
                db_values
                    .add(serde_json::from_str(&String::from_utf8_lossy(&val))?)
                    .unwrap();
            }
        };
        next_announcement += oracle.oracle_config.frequency;
    }
    let oracle_scheduler = Arc::new(Mutex::new(OracleScheduler {
        oracle: oracle.clone(),
        secp,
        pricefeeds,
        db_values,
        next_announcement,
        next_attestation,
    }));
    info!(
        "created new oracle scheduler with\n\tannouncements at {}\n\tattestations at {}\n\tfrequency of {}\n\tnext announcement at {}\n\tnext attestation at {}",
        oracle.oracle_config.attestation_time - oracle.oracle_config.announcement_offset,
        oracle.oracle_config.attestation_time,
        oracle.oracle_config.frequency,
        next_announcement,
        next_attestation
    );

    let mut scheduler = AsyncScheduler::with_tz(Utc);
    // schedule announcements
    let error_transmitter_clone = error_transmitter.clone();
    let oracle_scheduler_clone = oracle_scheduler.clone();
    let interval = Interval::Seconds(
        oracle
            .oracle_config
            .frequency
            .whole_seconds()
            .try_into()
            .unwrap(),
    );
    info!("starting announcement scheduler");
    scheduler
        .every(interval)
        .at(
            &(oracle.oracle_config.attestation_time - oracle.oracle_config.announcement_offset)
                .format(&format_description!("[hour]:[minute]:[second]"))
                .unwrap(),
        )
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
        .every(interval)
        .at(&oracle
            .oracle_config
            .attestation_time
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
    db_values: &mut Queue<DbValue>,
    maturation: OffsetDateTime,
) -> Result<()> {
    let (announcement, outstanding_sk_nonces) =
        build_announcement(&oracle.asset_pair_info, &oracle.keypair, secp, maturation)?;

    let db_value = DbValue(
        Some(outstanding_sk_nonces),
        announcement.encode(),
        None,
        None,
    );
    info!(
        "creating oracle event (announcement only) with maturation {} and announcement {:#?}",
        maturation, announcement
    );
    oracle.event_database.insert(
        maturation.format(&Rfc3339).unwrap().into_bytes(),
        serde_json::to_string(&db_value)?.into_bytes(),
    )?;
    db_values.add(db_value).unwrap();
    Ok(())
}

pub fn build_announcement(
    asset_pair_info: &AssetPairInfo,
    keypair: &KeyPair,
    secp: &Secp256k1<All>,
    maturation: OffsetDateTime,
) -> Result<(Announcement, Vec<[u8; 32]>)> {
    let mut rng = rand::thread_rng();
    let digits = asset_pair_info.event_descriptor.num_digits;
    let mut sk_nonces = Vec::with_capacity(digits.into());
    let mut nonces = Vec::with_capacity(digits.into());
    for _ in 0..digits {
        let mut sk_nonce = [0u8; 32];
        rng.fill_bytes(&mut sk_nonce);
        let oracle_r_kp = secp256k1_zkp::KeyPair::from_seckey_slice(secp, &sk_nonce)?;
        let nonce = SchnorrPublicKey::from_keypair(&oracle_r_kp);
        sk_nonces.push(sk_nonce);
        nonces.push(nonce);
    }

    let oracle_event = OracleEvent {
        nonces,
        maturation,
        event_descriptor: asset_pair_info.event_descriptor.clone(),
    };

    Ok((
        Announcement {
            signature: secp.sign_schnorr(
                &Message::from_hashed_data::<OracleAnnouncementHash>(&oracle_event.encode()),
                keypair,
            ),
            oracle_pubkey: keypair.public_key(),
            oracle_event,
        },
        sk_nonces,
    ))
}

pub fn build_attestation(
    outstanding_sk_nonces: Vec<[u8; 32]>,
    keypair: &KeyPair,
    secp: &Secp256k1<All>,
    outcomes: Vec<String>,
) -> Attestation {
    let signatures = outcomes
        .iter()
        .zip(outstanding_sk_nonces.iter())
        .map(|(outcome, outstanding_sk_nonce)| {
            sign_schnorr_with_nonce(
                secp,
                &Message::from_hashed_data::<sha256::Hash>(outcome.as_bytes()),
                keypair,
                outstanding_sk_nonce,
            )
        })
        .collect::<Vec<_>>();
    Attestation {
        oracle_pubkey: keypair.public_key(),
        signatures,
        outcomes,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{oracle::EventDescriptor, AssetPair};
    use dlc::OracleInfo;
    use secp256k1_zkp::rand::{distributions::Alphanumeric, Rng};

    fn setup() -> (KeyPair, Secp256k1<All>) {
        let secp = Secp256k1::new();
        let mut rng = rand::thread_rng();
        let (secret_key, _) = secp.generate_keypair(&mut rng);
        (KeyPair::from_secret_key(&secp, secret_key), secp)
    }

    fn setup_v5() -> (
        secp256k1_zkp_5::SecretKey,
        secp256k1_zkp_5::PublicKey,
        secp256k1_zkp_5::Secp256k1<secp256k1_zkp_5::All>,
    ) {
        let secp = secp256k1_zkp_5::Secp256k1::new();
        let mut rng = rand::thread_rng();
        let (secret_key, public_key) = secp.generate_keypair(&mut rng);
        (secret_key, public_key, secp)
    }

    fn signatures_to_secret(signatures: &[SchnorrSignature]) -> secp256k1_zkp_5::SecretKey {
        let s_values: Vec<&[u8]> = signatures
            .iter()
            .map(|x| {
                let bytes = x.as_ref();
                &bytes[32..64]
            })
            .collect();
        let mut secret = secp256k1_zkp_5::SecretKey::from_slice(s_values[0]).unwrap();
        for s in s_values.iter().skip(1) {
            secret.add_assign(s).unwrap();
        }

        secret
    }

    #[test]
    fn announcement_signature_verifies() {
        let (keypair, secp) = setup();

        let announcement = build_announcement(
            &AssetPairInfo {
                asset_pair: AssetPair::BTCUSD,
                event_descriptor: EventDescriptor {
                    base: 2,
                    is_signed: false,
                    unit: "BTCUSD".to_string(),
                    precision: 0,
                    num_digits: 18,
                },
                disabled_price_feeds: vec![],
            },
            &keypair,
            &secp,
            OffsetDateTime::now_utc(),
        )
        .unwrap()
        .0;

        let tag_hash = sha256::Hash::hash(b"DLC/oracle/announcement/v0");
        secp.verify_schnorr(
            &announcement.signature,
            &Message::from_hashed_data::<sha256::Hash>(
                &[
                    tag_hash.to_vec(),
                    tag_hash.to_vec(),
                    announcement.oracle_event.encode(),
                ]
                .concat(),
            ),
            &keypair.public_key(),
        )
        .unwrap();
    }

    #[test]
    fn attestation_signature_verifies() {
        let (keypair, secp) = setup();

        let mut outstanding_sk_nonce = vec![[0u8; 32]];
        let mut rng = rand::thread_rng();
        rng.fill_bytes(&mut outstanding_sk_nonce[0]);
        let outcome = rng
            .sample_iter(&Alphanumeric)
            .take(32)
            .map(char::from)
            .collect();
        let outcome = vec![outcome];
        let attestation = build_attestation(outstanding_sk_nonce, &keypair, &secp, outcome);
        secp.verify_schnorr(
            &attestation.signatures[0],
            &Message::from_hashed_data::<sha256::Hash>(attestation.outcomes[0].as_bytes()),
            &keypair.public_key(),
        )
        .unwrap();
    }

    #[test]
    fn valid_adaptor_signature() {
        let (keypair, secp) = setup();

        let (announcement, outstanding_sk_nonces) = build_announcement(
            &AssetPairInfo {
                asset_pair: AssetPair::BTCUSD,
                event_descriptor: EventDescriptor {
                    base: 2,
                    is_signed: false,
                    unit: "BTCUSD".to_string(),
                    precision: 0,
                    num_digits: 18,
                },
                disabled_price_feeds: vec![],
            },
            &keypair,
            &secp,
            OffsetDateTime::now_utc(),
        )
        .unwrap();

        let outcomes: Vec<String> = vec![
            "0", "0", "0", "1", "1", "1", "0", "1", "0", "0", "0", "1", "0", "1", "0", "0", "0",
            "1",
        ]
        .iter()
        .map(ToString::to_string)
        .collect();
        let attestation =
            build_attestation(outstanding_sk_nonces, &keypair, &secp, outcomes.clone());

        let (funding_secret_key, funding_public_key, secp_5) = setup_v5();

        let adaptor_point = dlc::get_adaptor_point_from_oracle_info(
            &secp_5,
            &[OracleInfo {
                public_key: secp256k1_zkp_5::schnorrsig::PublicKey::from_slice(
                    &keypair.public_key().serialize(),
                )
                .unwrap(),
                nonces: announcement
                    .oracle_event
                    .nonces
                    .iter()
                    .map(|nonce| {
                        secp256k1_zkp_5::schnorrsig::PublicKey::from_slice(&nonce.serialize())
                            .unwrap()
                    })
                    .collect(),
            }],
            &[outcomes
                .iter()
                .map(|outcome| {
                    secp256k1_zkp_5::Message::from_hashed_data::<
                        secp256k1_zkp_5::bitcoin_hashes::sha256::Hash,
                    >(outcome.as_bytes())
                })
                .collect::<Vec<_>>()],
        )
        .unwrap();

        let test_msg = secp256k1_zkp_5::Message::from_hashed_data::<
            secp256k1_zkp_5::bitcoin_hashes::sha256::Hash,
        >("test".as_bytes());
        let adaptor_sig = secp256k1_zkp_5::EcdsaAdaptorSignature::encrypt(
            &secp_5,
            &test_msg,
            &funding_secret_key,
            &adaptor_point,
        );

        adaptor_sig
            .verify(&secp_5, &test_msg, &funding_public_key, &adaptor_point)
            .unwrap();

        let adapted_sig = adaptor_sig
            .decrypt(&signatures_to_secret(&attestation.signatures))
            .unwrap();

        secp_5
            .verify(&test_msg, &adapted_sig, &funding_public_key)
            .unwrap();
    }
}
