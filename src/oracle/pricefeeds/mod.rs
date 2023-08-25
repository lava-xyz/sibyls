use async_trait::async_trait;
use time::OffsetDateTime;

pub use bitstamp::Bitstamp;
pub use error::PriceFeedError;
pub use error::Result;
pub use gateio::GateIo;
pub use kraken::Kraken;

use crate::oracle::pricefeeds::PriceFeedError::InternalError;
use crate::AssetPair;

mod error;

#[async_trait]
pub trait PriceFeed {
    fn id(&self) -> &'static str;
    fn translate_asset_pair(&self, asset_pair: AssetPair) -> &'static str;
    async fn retrieve_price(&self, asset_pair: AssetPair, datetime: OffsetDateTime) -> Result<f64>;
}

pub static ALL_PRICE_FEEDS: &'static [&str] = &["bitstamp", "gateio", "kraken"];

pub fn create_price_feed(feed_id: &str) -> Result<Box<dyn PriceFeed + Send + Sync>> {
    match feed_id {
        "bitstamp" => Ok(Box::new(Bitstamp {})),
        "gateio" => Ok(Box::new(GateIo {})),
        "kraken" => Ok(Box::new(Kraken {})),
        _ => Err(InternalError(format!("unknown price feed {}", feed_id))),
    }
}

mod bitstamp;
mod gateio;
mod kraken;
