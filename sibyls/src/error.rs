use displaydoc::Display;
use thiserror::Error;

#[allow(clippy::enum_variant_names)]
#[derive(Debug, Display, Error)]
pub enum SibylsError {
    /// asset pair {0} not recorded
    UnrecordedAssetPairError(sibyls::AssetPair),

    /// datetime RFC3339 parsing error: {0}
    DatetimeParseError(#[from] time::error::Parse),

    /// oracle event with maturation {0} not found
    OracleEventNotFoundError(String),

    /// database error: {0}
    DatabaseError(#[from] sled::Error),
}

impl actix_web::error::ResponseError for SibylsError {
    fn status_code(&self) -> actix_web::http::StatusCode {
        if let SibylsError::DatetimeParseError(_) = self {
            return actix_web::http::StatusCode::BAD_REQUEST;
        }
        actix_web::http::StatusCode::INTERNAL_SERVER_ERROR
    }
}
