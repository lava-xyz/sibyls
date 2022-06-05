use lightning::util::ser::Writeable;
use secp256k1_zkp::{
    hashes::*, schnorr::Signature as SchnorrSignature, ThirtyTwoByteHash,
    XOnlyPublicKey as SchnorrPublicKey,
};
use serde::Deserialize;
use time::OffsetDateTime;

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
    pub base: u16,
    pub is_signed: bool,
    pub unit: String,
    pub precision: i32,
    pub num_digits: u16,
}

#[derive(Clone, Debug)]
pub struct Attestation {
    pub oracle_pubkey: SchnorrPublicKey,
    pub signatures: Vec<SchnorrSignature>,
    pub outcomes: Vec<String>,
}

impl From<&Announcement> for dlc_messages::oracle_msgs::OracleAnnouncement {
    fn from(ann: &Announcement) -> Self {
        let announcement_signature =
            secp256k1_zkp_5::schnorrsig::Signature::from_slice(ann.signature.as_ref()).unwrap();
        let oracle_public_key =
            secp256k1_zkp_5::schnorrsig::PublicKey::from_slice(&ann.oracle_pubkey.serialize())
                .unwrap();
        let oracle_event = (&ann.oracle_event).into();
        Self {
            announcement_signature,
            oracle_public_key,
            oracle_event,
        }
    }
}

impl From<&OracleEvent> for dlc_messages::oracle_msgs::OracleEvent {
    fn from(event: &OracleEvent) -> Self {
        let oracle_nonces = event
            .nonces
            .iter()
            .map(|nonce| {
                secp256k1_zkp_5::schnorrsig::PublicKey::from_slice(&nonce.serialize()).unwrap()
            })
            .collect::<Vec<_>>();
        let event_maturity_epoch = event.maturation.unix_timestamp().try_into().unwrap();
        let event_descriptor = (&event.event_descriptor).into();
        Self {
            oracle_nonces,
            event_maturity_epoch,
            event_descriptor,
            event_id: String::new(), // todo?
        }
    }
}

impl From<&EventDescriptor> for dlc_messages::oracle_msgs::EventDescriptor {
    fn from(event: &EventDescriptor) -> Self {
        let base = event.base;
        let is_signed = event.is_signed;
        let unit = event.unit.clone();
        let precision = event.precision;
        let nb_digits = event.num_digits;
        let numerical_descriptor = dlc_messages::oracle_msgs::DigitDecompositionEventDescriptor {
            base,
            is_signed,
            unit,
            precision,
            nb_digits,
        };
        Self::DigitDecompositionEvent(numerical_descriptor)
    }
}

impl From<&Attestation> for dlc_messages::oracle_msgs::OracleAttestation {
    fn from(att: &Attestation) -> Self {
        let oracle_public_key =
            secp256k1_zkp_5::schnorrsig::PublicKey::from_slice(&att.oracle_pubkey.serialize())
                .unwrap();
        let signatures = att
            .signatures
            .iter()
            .map(|sig| secp256k1_zkp_5::schnorrsig::Signature::from_slice(sig.as_ref()).unwrap())
            .collect::<Vec<_>>();
        let outcomes = att.outcomes.to_vec();
        Self {
            oracle_public_key,
            signatures,
            outcomes,
        }
    }
}

impl Announcement {
    pub fn encode(&self) -> Vec<u8> {
        dlc_messages::oracle_msgs::OracleAnnouncement::from(self).encode()
    }
}

impl OracleEvent {
    pub fn encode(&self) -> Vec<u8> {
        dlc_messages::oracle_msgs::OracleEvent::from(self).encode()
    }
}

impl Attestation {
    pub fn encode(&self) -> Vec<u8> {
        dlc_messages::oracle_msgs::OracleAttestation::from(self).encode()
    }
}
