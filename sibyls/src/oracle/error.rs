use crate::error::SibylsError;
use displaydoc::Display;
use thiserror::Error;

pub type Result<T> = std::result::Result<T, OracleError>;

#[derive(Debug, Display, Error)]
pub enum OracleError {
    /// nonpositive announcement time offset: {0}; announcement must happen before attestation
    InvalidAnnouncementTimeError(time::Duration),

    /// database error: {0}
    DatabaseError(#[from] sled::Error),

    /// {0}
    SibylsError(#[from] SibylsError),

    /// {0}
    Error(String),
}
