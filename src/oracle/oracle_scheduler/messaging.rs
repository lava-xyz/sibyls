use lightning::util::ser::{Writeable, Writer};
use secp256k1_zkp::{
    hashes::*, schnorr::Signature as SchnorrSignature, ThirtyTwoByteHash,
    XOnlyPublicKey as SchnorrPublicKey,
};
use serde::Deserialize;
use time::OffsetDateTime;

const ORACLE_ANNOUNCEMENT_MIDSTATE: [u8; 32] = [
    0x0f, 0xfb, 0xaf, 0x80, 0xef, 0x9f, 0x3f, 0xe9, 0x8c, 0xe5, 0xd6, 0xa8, 0x7a, 0xad, 0xb4, 0x59,
    0x8f, 0x85, 0xcb, 0x21, 0x3e, 0x32, 0xe3, 0x28, 0xdf, 0x98, 0xfe, 0xdb, 0x00, 0xc9, 0x7c, 0x83,
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

struct BigSize(u64);
impl Writeable for BigSize {
    #[inline]
    fn write<W: Writer>(&self, writer: &mut W) -> std::io::Result<()> {
        match self.0 {
            0..=0xFC => (self.0 as u8).write(writer),
            0xFD..=0xFFFF => {
                0xFDu8.write(writer)?;
                (self.0 as u16).write(writer)
            }
            0x10000..=0xFFFFFFFF => {
                0xFEu8.write(writer)?;
                (self.0 as u32).write(writer)
            }
            _ => {
                0xFFu8.write(writer)?;
                (self.0 as u64).write(writer)
            }
        }
    }
}

impl Announcement {
    pub fn encode(&self) -> Vec<u8> {
        let mut out = vec![];
        BigSize(55332_u64).write(&mut out).unwrap();
        let v = dlc_messages::oracle_msgs::OracleAnnouncement::from(self).encode();
        BigSize(v.len() as u64).write(&mut out).unwrap();
        // extend manually for announcement to be consistent w suredbits decoding
        out.extend_from_slice(&v);
        out
    }
}

impl OracleEvent {
    pub fn encode(&self) -> Vec<u8> {
        dlc_messages::oracle_msgs::OracleEvent::from(self).encode()
    }
}

impl Attestation {
    pub fn encode(&self) -> Vec<u8> {
        let mut out = vec![];
        BigSize(55400_u64).write(&mut out).unwrap();
        let mut v = dlc_messages::oracle_msgs::OracleAttestation::from(self).encode();

        // remove duplicate length encoding from tibo's implementation
        let end = v.len() - 36;
        v.drain(end - 2..end);

        BigSize((v.len() + 1) as u64).write(&mut out).unwrap();
        // extend manually for attestation to be consistent w suredbits decoding
        // also extend w dummy event id
        BigSize(0_u64).write(&mut out).unwrap();
        out.extend_from_slice(&v);
        out
    }
}

// todo: update to test w James' decoding
#[cfg(test)]
mod tests {
    use super::*;
    use time::format_description::well_known::Rfc3339;

    // does not work yet because suredbits and tibo's implementations must be unified first
    #[ignore]
    #[test]
    fn suredbits_announcement_encodes_correctly() {
        let oracle_event = OracleEvent {
            nonces: vec![
                "bf0b6c97a9a33f7499511b68b0c1e5a758ad51df9330b4b6d4fd841af141bb91",
                "5d25e99260cec3e1a74257aa1edffbb2c718091d8eecd77f7dd078c69782938e",
                "6b49f9c7b8b7aa815f2c2d646a0fffd713491a6af3506aa83b3eb7122a1a502d",
                "2a2a83f8121013eeb1131f6f6b805e79f6cc066cae938d7873a5979d2f4888ce",
                "0b6d548fa7fff606ec1d3668f4f407da02e3ed3090919a77c5efcb25874c1102",
                "ac38396a26028d6e4203b6bb684b49bf95c5a67fe126a46cdd0c5287f1c37799",
                "88059ddfddc40bd7d4bd03f59d2df492f903b45557d6382c5e3931a34ebd175e",
                "32c1cc1b591cafb4fa6065948300e485d939bf405128dcc096eca3f4d5b68d6c",
                "0d77575d4c7342025e04f4de78f188808a85ebb3791a75c34ebdcd54104f8a73",
                "86e831876500d92aefe123c511b003c5aaee355a47ee076685687ca3549d5ccb",
                "15c56b9e1ad5e300888671ba60e16fc4c2b77617982e42ab401a1f313834b7d1",
                "7785aed84409206be3b0e62d8f735466007aa1d3709015506d31f497de0eaa43",
                "b8530f83ae8bf455069d4754847512de24892a789a3bc90904255ebd27ee78cd",
                "c68b2063ee08249682665644146af85f375f4967d5693cbc7473286180ad8629",
                "0bd0d39fbb1846496cd7acb8bde77131fb1a2ecd8b2430bf84e61e13bd1b6d7d",
                "3cd13b98d0ebf476b1ab067135e8d70334bc72ff454b617d48d0851ba01b4b32",
                "7b37e1c81bafed68ae1f951dc340ae6cd036b67212847aed94322d3397d4e233",
                "5c4e560486f6daa8c6074f258e3a348e2937ecba83fa8d80196f23a486cf0a30",
            ]
            .iter()
            .map(|nonce| SchnorrPublicKey::from_slice(&::hex::decode(nonce).unwrap()).unwrap())
            .collect(),
            maturation: OffsetDateTime::parse("2022-04-11T08:00:00Z", &Rfc3339).unwrap(),
            event_descriptor: EventDescriptor {
                base: 2,
                is_signed: false,
                unit: "BTCUSD".to_string(),
                precision: 0,
                num_digits: 18,
            },
        };

        let announcement = Announcement {
            signature: SchnorrSignature::from_slice(
                &::hex::decode("e15edeeb14a6bfa3995eeb65208c6698690bb497f22446b0505981ec202bcbc8584077c9f7209a2cf7d459c6a891a3eb863a78355868760455845f1a15fd6858").unwrap()
            ).unwrap(),
            oracle_pubkey: SchnorrPublicKey::from_slice(&::hex::decode("04ba9838623f02c940d20d7b185d410178cff7990c7fcf19186c7f58c7c4b8de").unwrap()).unwrap(),
            oracle_event,
        };

        assert_eq!(
            ::hex::decode(
                "fdd824fd02d4e15edeeb14a6bfa3995eeb65208c6698690bb497f22446b0505981ec202bcbc8584077c9f7209a2cf7d459c6a891a3eb863a78355868760455845f1a15fd685804ba9838623f02c940d20d7b185d410178cff7990c7fcf19186c7f58c7c4b8defdd822fd026e0012bf0b6c97a9a33f7499511b68b0c1e5a758ad51df9330b4b6d4fd841af141bb915d25e99260cec3e1a74257aa1edffbb2c718091d8eecd77f7dd078c69782938e6b49f9c7b8b7aa815f2c2d646a0fffd713491a6af3506aa83b3eb7122a1a502d2a2a83f8121013eeb1131f6f6b805e79f6cc066cae938d7873a5979d2f4888ce0b6d548fa7fff606ec1d3668f4f407da02e3ed3090919a77c5efcb25874c1102ac38396a26028d6e4203b6bb684b49bf95c5a67fe126a46cdd0c5287f1c3779988059ddfddc40bd7d4bd03f59d2df492f903b45557d6382c5e3931a34ebd175e32c1cc1b591cafb4fa6065948300e485d939bf405128dcc096eca3f4d5b68d6c0d77575d4c7342025e04f4de78f188808a85ebb3791a75c34ebdcd54104f8a7386e831876500d92aefe123c511b003c5aaee355a47ee076685687ca3549d5ccb15c56b9e1ad5e300888671ba60e16fc4c2b77617982e42ab401a1f313834b7d17785aed84409206be3b0e62d8f735466007aa1d3709015506d31f497de0eaa43b8530f83ae8bf455069d4754847512de24892a789a3bc90904255ebd27ee78cdc68b2063ee08249682665644146af85f375f4967d5693cbc7473286180ad86290bd0d39fbb1846496cd7acb8bde77131fb1a2ecd8b2430bf84e61e13bd1b6d7d3cd13b98d0ebf476b1ab067135e8d70334bc72ff454b617d48d0851ba01b4b327b37e1c81bafed68ae1f951dc340ae6cd036b67212847aed94322d3397d4e2335c4e560486f6daa8c6074f258e3a348e2937ecba83fa8d80196f23a486cf0a306253e000fdd80a100002000642544355534400000000001213446572696269742d4254432d31314150523232"
            ).unwrap(),
            announcement.encode(),
        );
    }

    // does not work yet because suredbits and tibo's implementations must be unified first
    #[ignore]
    #[test]
    fn suredbits_attestation_encodes_correctly() {
        let attestation = Attestation {
            oracle_pubkey: SchnorrPublicKey::from_slice(&::hex::decode("04ba9838623f02c940d20d7b185d410178cff7990c7fcf19186c7f58c7c4b8de").unwrap()).unwrap(),
            signatures: vec![
                "bf0b6c97a9a33f7499511b68b0c1e5a758ad51df9330b4b6d4fd841af141bb9195cad468377a389ce8b46d508b16a81ee4a43e074999777717b8208801f41772",
                "5d25e99260cec3e1a74257aa1edffbb2c718091d8eecd77f7dd078c69782938e233b3c4cbcbcca11b35127d77e35cfffc10f7c09e5cb547b334e71f10fe29c35",
                "6b49f9c7b8b7aa815f2c2d646a0fffd713491a6af3506aa83b3eb7122a1a502dd6945e7a18e975fba732be0f09d42553f16bee156896dca058e8aeafb9609b9b",
                "2a2a83f8121013eeb1131f6f6b805e79f6cc066cae938d7873a5979d2f4888cedbd8dafecccbfd279056c3b9e6b4cb981fd8a76ba5a0cd835bd514d357cdae5f",
                "0b6d548fa7fff606ec1d3668f4f407da02e3ed3090919a77c5efcb25874c11020ea572df9b34d6836b360a014a5523ec11eecf5611e5aa66cea4b9fede0d22fb",
                "ac38396a26028d6e4203b6bb684b49bf95c5a67fe126a46cdd0c5287f1c37799d6e17cd3e395402885538c1b0f711da9b5879d977ccc7fe4b3c92f789ccae531",
                "88059ddfddc40bd7d4bd03f59d2df492f903b45557d6382c5e3931a34ebd175e0a061aef29d81c824582f5375dbc6f28edcd8428e3e0b32f31abc98de34cd2fd",
                "32c1cc1b591cafb4fa6065948300e485d939bf405128dcc096eca3f4d5b68d6c3ba1cbe15e85555143190164296075bd29c468733bfee2dc97205b6a56d2f81e",
                "0d77575d4c7342025e04f4de78f188808a85ebb3791a75c34ebdcd54104f8a735938c8fa09e89345260dc7e694d79163029285cc0b09379edf179af01a442b07",
                "86e831876500d92aefe123c511b003c5aaee355a47ee076685687ca3549d5ccb30ca20cf1544862294a87d46d72fb73cc03e483102b12770d86cc157123109bd",
                "15c56b9e1ad5e300888671ba60e16fc4c2b77617982e42ab401a1f313834b7d1afe18b838fe7a9ee6e6f5edf10eec22cdbfa8ca619ad91987a6012f472b19941",
                "7785aed84409206be3b0e62d8f735466007aa1d3709015506d31f497de0eaa43e010f31e41525eda44819b5659a24d5d64e99205e7abf81015923ae12e55b085",
                "b8530f83ae8bf455069d4754847512de24892a789a3bc90904255ebd27ee78cdb5da94763dda5c30e5d218779a99ff5272237d9e00f3b19cf2870715f84dd8fe",
                "c68b2063ee08249682665644146af85f375f4967d5693cbc7473286180ad8629efa8cb6bc07194b0b1bead68891c95e80977eb9e0e6d4a2c88f8dbd1629df6d7",
                "0bd0d39fbb1846496cd7acb8bde77131fb1a2ecd8b2430bf84e61e13bd1b6d7d4b22c794c83623922ae658d94ea2910af92b858f57222038dbe788cba48e202e",
                "3cd13b98d0ebf476b1ab067135e8d70334bc72ff454b617d48d0851ba01b4b32415ae5a55f8f2a594dcfd92d8a737a0f8c49f05d2040d29cd26d06075884d231",
                "7b37e1c81bafed68ae1f951dc340ae6cd036b67212847aed94322d3397d4e233fe6988151ded6eef0a57cc0e76a80d54c61ccedf179ebfb41f4fe9f2355fb3d8",
                "5c4e560486f6daa8c6074f258e3a348e2937ecba83fa8d80196f23a486cf0a30e8bc2a1eeb140c04e132c02ef69a81e88e73582a8be4b788ffd0aef4a1113dad" 
            ]
            .iter()
            .map(|signature| SchnorrSignature::from_slice(&::hex::decode(signature).unwrap()).unwrap())
            .collect(),
            outcomes: vec!["0", "0", "1", "0", "1", "0", "0", "1", "0", "1", "0", "1", "0", "0", "1", "1", "1", "0"].iter().map(ToString::to_string).collect(),
        };

        assert_eq!(
            ::hex::decode(
                "fdd868fd04da13446572696269742d4254432d3131415052323204ba9838623f02c940d20d7b185d410178cff7990c7fcf19186c7f58c7c4b8de0012bf0b6c97a9a33f7499511b68b0c1e5a758ad51df9330b4b6d4fd841af141bb9195cad468377a389ce8b46d508b16a81ee4a43e074999777717b8208801f417725d25e99260cec3e1a74257aa1edffbb2c718091d8eecd77f7dd078c69782938e233b3c4cbcbcca11b35127d77e35cfffc10f7c09e5cb547b334e71f10fe29c356b49f9c7b8b7aa815f2c2d646a0fffd713491a6af3506aa83b3eb7122a1a502dd6945e7a18e975fba732be0f09d42553f16bee156896dca058e8aeafb9609b9b2a2a83f8121013eeb1131f6f6b805e79f6cc066cae938d7873a5979d2f4888cedbd8dafecccbfd279056c3b9e6b4cb981fd8a76ba5a0cd835bd514d357cdae5f0b6d548fa7fff606ec1d3668f4f407da02e3ed3090919a77c5efcb25874c11020ea572df9b34d6836b360a014a5523ec11eecf5611e5aa66cea4b9fede0d22fbac38396a26028d6e4203b6bb684b49bf95c5a67fe126a46cdd0c5287f1c37799d6e17cd3e395402885538c1b0f711da9b5879d977ccc7fe4b3c92f789ccae53188059ddfddc40bd7d4bd03f59d2df492f903b45557d6382c5e3931a34ebd175e0a061aef29d81c824582f5375dbc6f28edcd8428e3e0b32f31abc98de34cd2fd32c1cc1b591cafb4fa6065948300e485d939bf405128dcc096eca3f4d5b68d6c3ba1cbe15e85555143190164296075bd29c468733bfee2dc97205b6a56d2f81e0d77575d4c7342025e04f4de78f188808a85ebb3791a75c34ebdcd54104f8a735938c8fa09e89345260dc7e694d79163029285cc0b09379edf179af01a442b0786e831876500d92aefe123c511b003c5aaee355a47ee076685687ca3549d5ccb30ca20cf1544862294a87d46d72fb73cc03e483102b12770d86cc157123109bd15c56b9e1ad5e300888671ba60e16fc4c2b77617982e42ab401a1f313834b7d1afe18b838fe7a9ee6e6f5edf10eec22cdbfa8ca619ad91987a6012f472b199417785aed84409206be3b0e62d8f735466007aa1d3709015506d31f497de0eaa43e010f31e41525eda44819b5659a24d5d64e99205e7abf81015923ae12e55b085b8530f83ae8bf455069d4754847512de24892a789a3bc90904255ebd27ee78cdb5da94763dda5c30e5d218779a99ff5272237d9e00f3b19cf2870715f84dd8fec68b2063ee08249682665644146af85f375f4967d5693cbc7473286180ad8629efa8cb6bc07194b0b1bead68891c95e80977eb9e0e6d4a2c88f8dbd1629df6d70bd0d39fbb1846496cd7acb8bde77131fb1a2ecd8b2430bf84e61e13bd1b6d7d4b22c794c83623922ae658d94ea2910af92b858f57222038dbe788cba48e202e3cd13b98d0ebf476b1ab067135e8d70334bc72ff454b617d48d0851ba01b4b32415ae5a55f8f2a594dcfd92d8a737a0f8c49f05d2040d29cd26d06075884d2317b37e1c81bafed68ae1f951dc340ae6cd036b67212847aed94322d3397d4e233fe6988151ded6eef0a57cc0e76a80d54c61ccedf179ebfb41f4fe9f2355fb3d85c4e560486f6daa8c6074f258e3a348e2937ecba83fa8d80196f23a486cf0a30e8bc2a1eeb140c04e132c02ef69a81e88e73582a8be4b788ffd0aef4a1113dad013001300131013001310130013001310130013101300131013001300131013101310130"
            ).unwrap(),
            attestation.encode(),
        );
    }
}
