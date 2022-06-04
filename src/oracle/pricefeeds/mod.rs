use crate::AssetPair;
use time::OffsetDateTime;

pub trait PriceFeed {
    fn retrieve_price(&self, asset_pair: AssetPair, datetime: OffsetDateTime) -> Option<u32>;
}

mod binanceus;
mod kraken;
