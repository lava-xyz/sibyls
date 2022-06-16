use crate::oracle::EventDescriptor;
use serde::{
    de::{self, Visitor},
    Deserialize, Deserializer, Serialize,
};
use std::fmt::{self, Debug, Display, Formatter};
use time::{serde::format_description, Duration, Time};

#[derive(Copy, Clone, Debug, Deserialize, Eq, Hash, PartialEq, Serialize)]
pub enum AssetPair {
    BTCUSD,
}

#[derive(Clone, Debug, Deserialize)]
pub struct AssetPairInfo {
    pub asset_pair: AssetPair,
    pub event_descriptor: EventDescriptor,
}

impl Display for AssetPair {
    fn fmt(&self, f: &mut Formatter) -> fmt::Result {
        Debug::fmt(self, f)
    }
}

format_description!(standard_time, Time, "[hour]:[minute]");

fn deserialize_duration<'de, D>(deserializer: D) -> Result<Duration, D::Error>
where
    D: Deserializer<'de>,
{
    struct DurationVisitor;

    impl<'de> Visitor<'de> for DurationVisitor {
        type Value = Duration;

        fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
            formatter.write_str("string that parses to time::Duration")
        }

        fn visit_str<E>(self, v: &str) -> Result<Self::Value, E>
        where
            E: de::Error,
        {
            Ok(Duration::nanoseconds(
                humantime::parse_duration(v)
                    .map_err(E::custom)?
                    .as_nanos()
                    .try_into()
                    .unwrap(),
            ))
        }
    }

    deserializer.deserialize_any(DurationVisitor)
}

#[derive(Clone, Debug, Deserialize)]
pub struct OracleConfig {
    #[serde(with = "standard_time")]
    pub attestation_time: Time,
    #[serde(deserialize_with = "deserialize_duration")]
    pub frequency: Duration,
    #[serde(deserialize_with = "deserialize_duration")]
    pub announcement_offset: Duration,
}
