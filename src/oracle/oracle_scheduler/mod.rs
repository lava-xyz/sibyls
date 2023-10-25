use super::{
    pricefeeds::{PriceFeed, PriceFeedError},
    DbValue, Oracle,
};
use crate::{AssetPairInfo, SigningVersion};
use chrono::Utc;
use clokwerk::{AsyncScheduler, Interval, Job};
use core::ptr;
use futures::{stream, StreamExt};
use lightning::util::ser::Writeable;
use log::{error, info};
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

use dlc_messages::oracle_msgs::{OracleAnnouncement, OracleAttestation, OracleEvent};
use dlc_messages::ser_impls::write_as_tlv;

mod messaging;
use crate::oracle::oracle_scheduler::messaging::{DLCV0AnnouncementHash, DLCV0AttestationHash};

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
    signing_version: SigningVersion,
}

impl OracleScheduler {
    fn create_scheduler_event(&mut self) -> Result<()> {
        let announcement_offset = self.oracle.oracle_config.announcement_offset;
        create_event(
            &mut self.oracle,
            &self.secp,
            &mut self.db_values,
            self.next_announcement + announcement_offset,
            self.signing_version,
        )?;
        self.next_announcement += self.oracle.oracle_config.frequency;
        Ok(())
    }

    async fn attest(&mut self, signing_version: SigningVersion) -> Result<()> {
        info!("retrieving pricefeeds for attestation");
        let prices = stream::iter(self.pricefeeds.iter())
            .then(|pricefeed| async {
                pricefeed
                    .retrieve_price(
                        self.oracle.asset_pair_info.asset_pair,
                        self.next_attestation,
                    )
                    .await
                    .map_err(|err| {
                        error!("cannot retrieve price {}", err);
                        err
                    })
                    .ok()
            })
            .collect::<Vec<Option<f64>>>()
            .await
            .into_iter()
            .flatten()
            .collect::<Vec<f64>>();

        if prices.is_empty() {
            Err(OracleSchedulerError::PriceFeedError(
                PriceFeedError::InternalError("it seems all price feeds have failed".to_string()),
            ))
        } else {
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
                &db_value
                    .0
                    .take()
                    .expect("immature db_values should always have outstanding_sk_nonces"),
                &self.oracle.keypair,
                &self.secp,
                outcomes,
                signing_version,
            );

            let mut attestation_bytes = Vec::new();
            write_as_tlv(&attestation, &mut attestation_bytes).expect("Error writing attestation");

            db_value.2 = Some(attestation_bytes);
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
}

pub fn init(
    oracle: Oracle,
    secp: Secp256k1<All>,
    pricefeeds: Vec<Box<dyn PriceFeed + Send + Sync>>,
    signing_version: SigningVersion,
) -> Result<()> {
    // start event creation task
    info!("creating oracle events and schedules");
    tokio::spawn(async move {
        let (tx, mut rx) = mpsc::unbounded_channel();
        if let Err(err) = create_events(oracle, secp, pricefeeds, tx, signing_version) {
            error!("oracle scheduler create_events error: {}", err);
        } else {
            while let Some(err) = rx.recv().await {
                error!("oracle scheduler error: {}", err);
            }
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
    signing_version: SigningVersion,
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
            None => create_event(
                &mut oracle,
                &secp,
                &mut db_values,
                next_attestation,
                signing_version,
            )?,
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
        signing_version,
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
                if let Err(err) = oracle_scheduler_clone
                    .lock()
                    .await
                    .attest(signing_version)
                    .await
                {
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
    signing_version: SigningVersion,
) -> Result<()> {
    let (announcement, outstanding_sk_nonces) = build_announcement(
        &oracle.asset_pair_info,
        &oracle.keypair,
        secp,
        maturation,
        signing_version,
    )?;

    let mut announcement_bytes = Vec::new();
    write_as_tlv(&announcement, &mut announcement_bytes).expect("Error writing announcement");

    let db_value = DbValue(Some(outstanding_sk_nonces), announcement_bytes, None, None);
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
    signing_version: SigningVersion,
) -> Result<(OracleAnnouncement, Vec<[u8; 32]>)> {
    let mut rng = rand::thread_rng();
    let digits = asset_pair_info.event_descriptor.num_digits;
    let mut sk_nonces = Vec::with_capacity(digits.into());
    let mut oracle_nonces = Vec::with_capacity(digits.into());
    for _ in 0..digits {
        let mut sk_nonce = [0u8; 32];
        rng.fill_bytes(&mut sk_nonce);
        let oracle_r_kp = secp256k1_zkp::KeyPair::from_seckey_slice(secp, &sk_nonce)?;
        let nonce = SchnorrPublicKey::from_keypair(&oracle_r_kp).0;
        sk_nonces.push(sk_nonce);
        oracle_nonces.push(nonce);
    }

    let oracle_event = OracleEvent {
        oracle_nonces,
        event_maturity_epoch: maturation.unix_timestamp() as u32,
        event_descriptor: asset_pair_info.clone().event_descriptor.into(),
        event_id: "".to_string(),
    };

    let msg = match signing_version {
        SigningVersion::Basic => {
            let mut event_bytes = Vec::new();
            oracle_event
                .write(&mut event_bytes)
                .expect("Error writing oracle event");
            Message::from_hashed_data::<sha256::Hash>(&event_bytes)
        }
        SigningVersion::DLCv0 => {
            let mut event_bytes = Vec::new();
            write_as_tlv(&oracle_event, &mut event_bytes).expect("Error writing oracle event");
            Message::from_hashed_data::<DLCV0AnnouncementHash>(&event_bytes)
        }
    };

    let announcement_signature = secp.sign_schnorr(&msg, keypair);

    Ok((
        OracleAnnouncement {
            announcement_signature,
            oracle_public_key: keypair.x_only_public_key().0,
            oracle_event,
        },
        sk_nonces,
    ))
}

pub fn build_attestation(
    outstanding_sk_nonces: &[[u8; 32]],
    keypair: &KeyPair,
    secp: &Secp256k1<All>,
    outcomes: Vec<String>,
    signing_version: SigningVersion,
) -> OracleAttestation {
    let signatures = outcomes
        .iter()
        .zip(outstanding_sk_nonces.iter())
        .map(|(outcome, outstanding_sk_nonce)| {
            let msg = match signing_version {
                SigningVersion::Basic => {
                    Message::from_hashed_data::<sha256::Hash>(outcome.as_bytes())
                }
                SigningVersion::DLCv0 => {
                    Message::from_hashed_data::<DLCV0AttestationHash>(outcome.as_bytes())
                }
            };
            sign_schnorr_with_nonce(secp, &msg, keypair, outstanding_sk_nonce)
        })
        .collect::<Vec<_>>();
    OracleAttestation {
        oracle_public_key: keypair.public_key().x_only_public_key().0,
        signatures,
        outcomes,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{AssetPair, SerializableEventDescriptor};
    use dlc::OracleInfo;
    use dlc_messages::ser_impls::write_as_tlv;
    use secp256k1::Scalar;
    use secp256k1_zkp::rand::{distributions::Alphanumeric, Rng};
    use std::fmt::Write as _;

    fn setup() -> (KeyPair, Secp256k1<All>) {
        let secp = Secp256k1::new();
        let mut rng = rand::thread_rng();
        let (secret_key, _) = secp.generate_keypair(&mut rng);
        (KeyPair::from_secret_key(&secp, &secret_key), secp)
    }

    fn setup_adaptor_signatures(
        secp: &Secp256k1<All>,
    ) -> (secp256k1_zkp::SecretKey, secp256k1_zkp::PublicKey) {
        let mut rng = rand::thread_rng();
        let (secret_key, public_key) = secp.generate_keypair(&mut rng);
        (secret_key, public_key)
    }

    fn signatures_to_secret(signatures: &[SchnorrSignature]) -> secp256k1_zkp::SecretKey {
        let s_values: Vec<Scalar> = signatures
            .iter()
            .map(|x| {
                let bytes = x.as_ref();
                Scalar::from_le_bytes(bytes[32..64].try_into().unwrap()).unwrap()
            })
            .collect();
        let secret = secp256k1_zkp::SecretKey::from_slice(&s_values[0].to_le_bytes()).unwrap();
        for s in s_values.iter().skip(1) {
            secret.add_tweak(s).unwrap();
        }

        secret
    }

    pub fn hex_str(value: &[u8]) -> String {
        let mut res = String::with_capacity(64);
        for v in value {
            write!(res, "{:02x}", v).unwrap();
        }
        res
    }

    #[test]
    fn announcement_signature_verifies_basic() {
        let (keypair, secp) = setup();
        let announcement = build_test_announcement(&keypair, &secp, SigningVersion::Basic).0;

        // let mut announcement_bytes = vec![];
        // write_as_tlv(&announcement, &mut announcement_bytes).unwrap();
        // println!("{}", hex_str(&announcement_bytes));

        announcement.validate(&secp).unwrap();
    }

    #[test]
    fn announcement_signature_verifies_dlc_v0() {
        let (keypair, secp) = setup();
        let announcement = build_test_announcement(&keypair, &secp, SigningVersion::DLCv0).0;

        // let mut announcement_bytes = vec![];
        // write_as_tlv(&announcement, &mut announcement_bytes).unwrap();
        // println!("{}", hex_str(&announcement_bytes));

        let mut event_bytes = Vec::new();
        write_as_tlv(&announcement.oracle_event, &mut event_bytes)
            .expect("Error writing oracle event");

        let msg = Message::from_hashed_data::<DLCV0AnnouncementHash>(&event_bytes);
        secp.verify_schnorr(
            &announcement.announcement_signature,
            &msg,
            &announcement.oracle_public_key,
        )
        .unwrap();
    }

    #[test]
    fn attestation_signature_verifies_basic() {
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
        let attestation = build_attestation(
            &outstanding_sk_nonce,
            &keypair,
            &secp,
            outcome,
            SigningVersion::Basic,
        );
        secp.verify_schnorr(
            &attestation.signatures[0],
            &Message::from_hashed_data::<sha256::Hash>(attestation.outcomes[0].as_bytes()),
            &keypair.public_key().x_only_public_key().0,
        )
        .unwrap();
    }

    #[test]
    fn attestation_signature_verifies_dlc_v0() {
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
        let attestation = build_attestation(
            &outstanding_sk_nonce,
            &keypair,
            &secp,
            outcome,
            SigningVersion::DLCv0,
        );
        secp.verify_schnorr(
            &attestation.signatures[0],
            &Message::from_hashed_data::<DLCV0AttestationHash>(attestation.outcomes[0].as_bytes()),
            &keypair.public_key().x_only_public_key().0,
        )
        .unwrap();
    }

    #[ignore]
    #[test]
    fn valid_adaptor_signature() {
        let (keypair, secp) = setup();

        let (announcement, outstanding_sk_nonces) =
            build_test_announcement(&keypair, &secp, SigningVersion::Basic);

        let outcomes: Vec<String> = vec![
            "0", "0", "0", "1", "1", "1", "0", "1", "0", "0", "0", "1", "0", "1", "0", "0", "0",
            "1",
        ]
        .iter()
        .map(ToString::to_string)
        .collect();
        let attestation = build_attestation(
            &outstanding_sk_nonces,
            &keypair,
            &secp,
            outcomes.clone(),
            SigningVersion::Basic,
        );

        let (funding_secret_key, funding_public_key) = setup_adaptor_signatures(&secp);

        let adaptor_point = dlc::get_adaptor_point_from_oracle_info(
            &secp,
            &[OracleInfo {
                public_key: keypair.public_key().x_only_public_key().0,
                nonces: announcement.oracle_event.oracle_nonces,
            }],
            &[outcomes
                .iter()
                .map(|outcome| Message::from_hashed_data::<sha256::Hash>(outcome.as_bytes()))
                .collect::<Vec<_>>()],
        )
        .unwrap();

        let test_msg = secp256k1_zkp::Message::from_hashed_data::<
            secp256k1_zkp::hashes::sha256::Hash,
        >("test".as_bytes());
        let adaptor_sig = secp256k1_zkp::EcdsaAdaptorSignature::encrypt(
            &secp,
            &test_msg,
            &funding_secret_key,
            &adaptor_point,
        );

        adaptor_sig
            .verify(&secp, &test_msg, &funding_public_key, &adaptor_point)
            .unwrap();

        let adapted_sig = adaptor_sig
            .decrypt(&signatures_to_secret(&attestation.signatures))
            .unwrap();

        secp.verify_ecdsa(&test_msg, &adapted_sig, &funding_public_key)
            .unwrap();
    }

    fn build_test_announcement(
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
                exclude_price_feeds: vec![],
            },
            &keypair,
            &secp,
            OffsetDateTime::now_utc(),
            signing_version,
        )
        .unwrap();
        (announcement, outstanding_sk_nonces)
    }
}
