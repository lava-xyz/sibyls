use super::PriceFeed;
use crate::AssetPair;
use time::OffsetDateTime;

struct Kraken {}

impl PriceFeed for Kraken {
    fn retrieve_price(&self, _: AssetPair, _: OffsetDateTime) -> std::option::Option<u32> {
        todo!()
    }
}
