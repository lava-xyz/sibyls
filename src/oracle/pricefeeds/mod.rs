use async_trait::async_trait;
use futures::StreamExt;
use log::{error, info};
use serde::Deserialize;
use serde::Serialize;
use time::OffsetDateTime;

pub use bitfinex::Bitfinex;
pub use bitstamp::Bitstamp;
pub use deribit::Deribit;
pub use error::PriceFeedError;
pub use error::Result;
pub use gateio::GateIo;
pub use kraken::Kraken;
#[cfg(feature = "test-feed")]
pub use test_feed::TestFeed;

use crate::AggregationType;
use crate::AssetPair;

mod error;

#[async_trait]
pub trait PriceFeed {
    fn id(&self) -> &'static str;
    fn translate_asset_pair(&self, asset_pair: AssetPair) -> Result<&'static str>;
    async fn retrieve_price(&self, asset_pair: AssetPair, datetime: OffsetDateTime) -> Result<f64>;
}

#[cfg(not(feature = "test-feed"))]
pub static ALL_PRICE_FEEDS: &[FeedId] = &[
    FeedId::Bitstamp,
    FeedId::GateIO,
    FeedId::Kraken,
    FeedId::Bitfinex,
    FeedId::Deribit,
];

#[cfg(not(feature = "test-feed"))]
#[derive(Clone, Debug, Serialize, Deserialize, Eq, PartialEq)]
pub enum FeedId {
    Bitstamp,
    GateIO,
    Kraken,
    Bitfinex,
    Deribit,
}

#[cfg(feature = "test-feed")]
#[derive(Clone, Debug, Serialize, Deserialize, Eq, PartialEq)]
pub enum FeedId {
    Test,
}

pub struct ParseFeedIdError;

#[cfg(not(feature = "test-feed"))]
pub fn create_price_feed(feed_id: &FeedId) -> Box<dyn PriceFeed + Send + Sync> {
    match feed_id {
        FeedId::Bitstamp => Box::new(Bitstamp {}),
        FeedId::GateIO => Box::new(GateIo {}),
        FeedId::Kraken => Box::new(Kraken {}),
        FeedId::Bitfinex => Box::new(Bitfinex {}),
        FeedId::Deribit => Box::new(Deribit {}),
    }
}

#[cfg(feature = "test-feed")]
pub fn create_price_feed(feed_id: &FeedId) -> Box<dyn PriceFeed + Send + Sync> {
    match feed_id {
        FeedId::Test => Box::new(TestFeed {}),
    }
}

pub fn create_price_feeds(feed_ids: &[FeedId]) -> Vec<Box<dyn PriceFeed + Send + Sync>> {
    feed_ids.iter().map(|x| create_price_feed(x)).collect()
}

pub async fn get_prices(
    price_feeds: &[Box<dyn PriceFeed + Send + Sync>],
    timestamp: OffsetDateTime,
    asset_pair: AssetPair,
) -> Vec<f64> {
    futures::stream::iter(price_feeds.iter())
        .then(|pricefeed| async {
            pricefeed
                .retrieve_price(asset_pair, timestamp)
                .await
                .map_err(|err| {
                    error!("cannot retrieve price {}", err);
                    err
                })
                .ok()
        })
        .collect::<Vec<Option<f64>>>()
        .await
        .into_iter()
        .flatten()
        .collect::<Vec<f64>>()
}

pub fn aggregate_price(
    prices: &Vec<f64>,
    aggregation_type: AggregationType,
    asset_pair: AssetPair,
) -> Option<f64> {
    if prices.is_empty() {
        None
    } else {
        match aggregation_type {
            AggregationType::Average => {
                let avg_price = prices.iter().sum::<f64>() / prices.len() as f64;
                let avg_price = avg_price.round();
                info!("average price of {} is {}", asset_pair, avg_price);
                Some(avg_price)
            }
            AggregationType::Median => {
                let mut sorted_prices = prices.to_vec();
                sorted_prices.sort_by(|a, b| a.partial_cmp(b).unwrap());
                if sorted_prices.len() % 2 == 0 {
                    let i = sorted_prices.len() / 2 - 1;
                    let j = sorted_prices.len() / 2;
                    let median_price = (sorted_prices[i] + sorted_prices[j]) / 2.0;
                    info!(
                        "median price of {} is {} (avg of {} and {})",
                        asset_pair, median_price, sorted_prices[i], sorted_prices[j]
                    );
                    Some(median_price)
                } else {
                    let median_price = sorted_prices[sorted_prices.len() / 2];
                    info!("median price of {} is {}", asset_pair, median_price);
                    Some(median_price)
                }
            }
        }
    }
}

/// Returns the aggregated price obtained from the given price feeds, or `None` of none of the
/// feeds could be queried.
pub async fn get_aggregate_price_from_feeds(
    price_feeds: &[Box<dyn PriceFeed + Send + Sync>],
    timestamp: OffsetDateTime,
    asset_pair: AssetPair,
    aggregation_type: AggregationType,
) -> Option<f64> {
    let prices = get_prices(price_feeds, timestamp, asset_pair).await;
    aggregate_price(&prices, aggregation_type, asset_pair)
}

mod bitfinex;
mod bitstamp;
mod deribit;
mod gateio;
mod kraken;
mod test_feed;

#[cfg(test)]
mod tests {
    use crate::{oracle::pricefeeds::aggregate_price, AggregationType, AssetPair};

    #[test]
    fn test_aggregate() {
        assert_eq!(
            None,
            aggregate_price(&vec![], AggregationType::Average, AssetPair::BTCUSD)
        );
        assert_eq!(
            None,
            aggregate_price(&vec![], AggregationType::Median, AssetPair::BTCUSD)
        );
        assert_eq!(
            Some(10.0),
            aggregate_price(&vec![10.0], AggregationType::Average, AssetPair::BTCUSD)
        );
        assert_eq!(
            Some(10.0),
            aggregate_price(&vec![10.0], AggregationType::Median, AssetPair::BTCUSD)
        );
        assert_eq!(
            Some(15.0),
            aggregate_price(
                &vec![10.0, 20.0],
                AggregationType::Average,
                AssetPair::BTCUSD
            )
        );
        assert_eq!(
            Some(15.0),
            aggregate_price(
                &vec![10.0, 20.0],
                AggregationType::Median,
                AssetPair::BTCUSD
            )
        );
        assert_eq!(
            Some(20.0),
            aggregate_price(
                &vec![10.0, 20.0, 30.0],
                AggregationType::Average,
                AssetPair::BTCUSD
            )
        );
        assert_eq!(
            Some(20.0),
            aggregate_price(
                &vec![10.0, 30.0, 20.0],
                AggregationType::Median,
                AssetPair::BTCUSD
            )
        );
        assert_eq!(
            Some(35.0),
            aggregate_price(
                &vec![20.0, 30.0, 40.0, 50.0],
                AggregationType::Average,
                AssetPair::BTCUSD
            )
        );
        assert_eq!(
            Some(35.0),
            aggregate_price(
                &vec![40.0, 50.0, 20.0, 30.0],
                AggregationType::Median,
                AssetPair::BTCUSD
            )
        );
        assert_eq!(
            Some(30.0),
            aggregate_price(
                &vec![10.0, 20.0, 30.0, 40.0, 50.0],
                AggregationType::Average,
                AssetPair::BTCUSD
            )
        );
        assert_eq!(
            Some(40.0),
            aggregate_price(
                &vec![20.0, 40.0, 50.0, 30.0, 60.0],
                AggregationType::Median,
                AssetPair::BTCUSD
            )
        );
    }
}
