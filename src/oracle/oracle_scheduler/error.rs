use displaydoc::Display;
use thiserror::Error;

pub type Result<T> = std::result::Result<T, OracleSchedulerError>;

#[derive(Debug, Display, Error)]
pub enum OracleSchedulerError {
    /// nonpositive announcement time offset: {0}; announcement must happen before attestation
    InvalidAnnouncementTimeError(time::Duration),

    /// database error: {0}
    DatabaseError(#[from] sled::Error),

    /// secp256k1 upstream error: {0}
    Secp256k1UpstreamError(#[from] secp256k1_zkp::UpstreamError),

    /// json serialization/deserialization error: {0}
    SerdeJsonError(#[from] serde_json::Error),

    /// tokio join error: {0}
    JoinError(#[from] tokio::task::JoinError),

    /// pricefeed error: {0}
    PriceFeedError(#[from] crate::oracle::pricefeeds::PriceFeedError),
}
