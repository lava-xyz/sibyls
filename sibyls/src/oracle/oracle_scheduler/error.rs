use displaydoc::Display;
use thiserror::Error;

pub type Result<T> = std::result::Result<T, OracleSchedulerError>;

#[derive(Debug, Display, Error)]
pub enum OracleSchedulerError {
    /// secp256k1 upstream error: {0}
    Secp256k1UpstreamError(#[from] secp256k1_zkp::UpstreamError),

    /// json serialization/deserialization error: {0}
    SerdeJsonError(#[from] serde_json::Error),

    /// tokio join error: {0}
    JoinError(#[from] tokio::task::JoinError),

    /// pricefeed error: {0}
    PriceFeedError(#[from] crate::oracle::pricefeeds::PriceFeedError),

    /// internal error: {0}
    InternalError(String),
}
