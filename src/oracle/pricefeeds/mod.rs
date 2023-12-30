use async_trait::async_trait;
use time::OffsetDateTime;

pub use bitfinex::Bitfinex;
pub use bitstamp::Bitstamp;
pub use deribit::Deribit;
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
    fn translate_asset_pair(&self, asset_pair: AssetPair) -> Result<&'static str>;
    async fn retrieve_price(&self, asset_pair: AssetPair, datetime: OffsetDateTime) -> Result<f64>;
}

pub static ALL_PRICE_FEEDS: &[&str] = &["bitstamp", "gateio", "kraken", "bitfinex", "deribit"];

pub fn create_price_feed(feed_id: &str) -> Result<Box<dyn PriceFeed + Send + Sync>> {
    match feed_id {
        "bitstamp" => Ok(Box::new(Bitstamp {})),
        "gateio" => Ok(Box::new(GateIo {})),
        "kraken" => Ok(Box::new(Kraken {})),
        "bitfinex" => Ok(Box::new(Bitfinex {})),
        "deribit" => Ok(Box::new(Deribit {})),
        _ => Err(InternalError(format!("unknown price feed {}", feed_id))),
    }
}

mod bitfinex;
mod bitstamp;
mod deribit;
mod gateio;
mod kraken;
