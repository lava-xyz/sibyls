use displaydoc::Display;
use thiserror::Error;

pub type Result<T> = std::result::Result<T, OracleError>;

#[derive(Debug, Display, Error)]
pub enum OracleError {
    /// nonpositive announcement time offset: {0}; announcement must happen before attestation
    InvalidAnnouncementTimeError(time::Duration),

    /// database error: {0}
    DatabaseError(#[from] sled::Error),

    /// secp256k1 upstream error: {0}
    Secp256k1UpstreamError(#[from] secp256k1_zkp::UpstreamError),

    /// json serialization/deserialization error: {0}
    SerdeJsonError(#[from] serde_json::Error),
}
