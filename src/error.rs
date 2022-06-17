use displaydoc::Display;
use thiserror::Error;

#[allow(clippy::enum_variant_names)]
#[derive(Debug, Display, Error)]
pub enum SybilsError {
    /// asset pair {0} not recorded
    UnrecordedAssetPairError(sybils::AssetPair),

    /// oracle event with maturation {0} not found
    OracleEventNotFoundError(String),

    /// database error: {0}
    DatabaseError(#[from] sled::Error),
}

impl actix_web::error::ResponseError for SybilsError {}

#[derive(Debug, Display, Error)]
pub enum SybilsValidationError {
    /// datetime RFC3339 parsing error: {0}
    DatetimeParseError(#[from] time::error::Parse),
}

impl actix_web::error::ResponseError for SybilsValidationError {
    fn status_code(&self) -> actix_web::http::StatusCode {
        actix_web::http::StatusCode::BAD_REQUEST
    }
}
