use crate::AssetPair;
use displaydoc::Display;
use thiserror::Error;
use time::OffsetDateTime;

pub type Result<T> = std::result::Result<T, PriceFeedError>;

#[derive(Debug, Display, Error)]
pub enum PriceFeedError {
    /// internal error: {0}
    InternalError(String),

    /// price not available for {0} at {1}
    PriceNotAvailableError(AssetPair, OffsetDateTime),

    /// http error: {0}
    HttpError(#[from] reqwest::Error),
}
