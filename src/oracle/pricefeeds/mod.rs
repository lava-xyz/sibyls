use crate::AssetPair;
use async_trait::async_trait;
use time::OffsetDateTime;

mod error;
pub use error::PriceFeedError;
pub use error::Result;

#[async_trait]
pub trait PriceFeed {
    fn translate_asset_pair(&self, asset_pair: AssetPair) -> &'static str;
    async fn retrieve_price(&self, asset_pair: AssetPair, datetime: OffsetDateTime) -> Result<f64>;
}

mod bitstamp;
mod gateio;
mod kraken;

pub use bitstamp::Bitstamp;
pub use gateio::GateIo;
pub use kraken::Kraken;
