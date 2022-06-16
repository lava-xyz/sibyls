use displaydoc::Display;
use thiserror::Error;

pub type Result<T> = std::result::Result<T, SybilsError>;

#[allow(clippy::enum_variant_names)]
#[derive(Debug, Display, Error)]
pub enum SybilsError {
    /// oracle event with maturation {0} not found
    OracleEventNotFoundError(String),

    /// datetime RFC3339 parsing error: {0}
    DatetimeParseError(#[from] time::error::Parse),

    /// database error: {0}
    DatabaseError(#[from] sled::Error),

    /// internal oracle error: {0}
    InternalOracleError(#[from] sybils::oracle::OracleError),

    /// internal oracle scheduler error: {0}
    InternalOracleSchedulerError(#[from] sybils::oracle::oracle_scheduler::OracleSchedulerError),
}
