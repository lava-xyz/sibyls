use dlc_messages::oracle_msgs::EventDescriptor::{DigitDecompositionEvent, EnumEvent};
use dlc_messages::oracle_msgs::{DigitDecompositionEventDescriptor, EventDescriptor};
use serde::{Deserialize, Serialize};
use std::fmt::{self, Debug, Display, Formatter};
use time::{serde::format_description, Duration, Time};

#[derive(Copy, Clone, Debug, Deserialize, Eq, Hash, PartialEq, Serialize)]
pub enum AssetPair {
    BTCUSD,
    BTCUSDT,
}

#[derive(Clone, Debug, Deserialize)]
pub struct SerializableEventDescriptor {
    pub base: u16,
    pub is_signed: bool,
    pub unit: String,
    pub precision: i32,
    pub num_digits: u16,
}

impl From<&EventDescriptor> for SerializableEventDescriptor {
    fn from(ed: &EventDescriptor) -> SerializableEventDescriptor {
        match ed {
            DigitDecompositionEvent(e) => SerializableEventDescriptor {
                base: e.base,
                is_signed: e.is_signed,
                unit: e.unit.clone(),
                precision: e.precision,
                num_digits: e.nb_digits,
            },
            EnumEvent(_) => SerializableEventDescriptor {
                base: 0,
                is_signed: false,
                unit: "".to_string(),
                precision: 0,
                num_digits: 0,
            },
        }
    }
}

impl From<SerializableEventDescriptor> for EventDescriptor {
    fn from(val: SerializableEventDescriptor) -> Self {
        DigitDecompositionEvent(DigitDecompositionEventDescriptor {
            base: val.base,
            is_signed: val.is_signed,
            unit: val.unit.clone(),
            precision: val.precision,
            nb_digits: val.num_digits,
        })
    }
}

#[derive(Clone, Debug, Deserialize)]
pub struct AssetPairInfo {
    pub asset_pair: AssetPair,
    pub event_descriptor: SerializableEventDescriptor,
    pub include_price_feeds: Vec<String>,
    pub exclude_price_feeds: Vec<String>,
}

impl Display for AssetPair {
    fn fmt(&self, f: &mut Formatter) -> fmt::Result {
        Debug::fmt(self, f)
    }
}

format_description!(standard_time, Time, "[hour]:[minute]");

mod standard_duration {
    use serde::{
        de::{self, Visitor},
        Deserializer, Serializer,
    };
    use std::fmt;
    use time::Duration;

    pub fn serialize<S>(value: &Duration, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(
            &humantime::format_duration(std::time::Duration::from_nanos(
                value.whole_nanoseconds().try_into().unwrap(),
            ))
            .to_string(),
        )
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<Duration, D::Error>
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
}

#[derive(Copy, Clone, Debug, Deserialize, Serialize)]
pub enum SigningVersion {
    #[serde(rename = "basic")]
    Basic,
    #[serde(rename = "dlc_v0")]
    DLCv0,
}

#[derive(Copy, Clone, Debug, Deserialize, Serialize)]
pub enum AggregationType {
    #[serde(rename = "avg")]
    Average,
    #[serde(rename = "median")]
    Median,
}

#[derive(Copy, Clone, Debug, Deserialize, Serialize)]
pub struct OracleConfig {
    #[serde(with = "standard_time")]
    pub attestation_time: Time,
    #[serde(with = "standard_duration")]
    pub frequency: Duration,
    #[serde(with = "standard_duration")]
    pub announcement_offset: Duration,
    pub signing_version: SigningVersion,
    pub price_aggregation_type: AggregationType,
}
