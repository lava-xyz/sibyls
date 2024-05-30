use crate::oracle::pricefeeds::{PriceFeed, PriceFeedError};
use crate::AssetPair;
use async_trait::async_trait;
use log::error;
use std::fs;
use time::OffsetDateTime;

pub struct TestFeed {}

#[async_trait]
impl PriceFeed for TestFeed {
    fn id(&self) -> &'static str {
        "test"
    }

    fn translate_asset_pair(
        &self,
        asset_pair: AssetPair,
    ) -> crate::oracle::pricefeeds::Result<&'static str> {
        match asset_pair {
            AssetPair::BTCUSD => Ok("BTCUSD"),
            AssetPair::BTCUSDT => Ok("BTCUSDT"),
        }
    }

    async fn retrieve_price(
        &self,
        asset_pair: AssetPair,
        datetime: OffsetDateTime,
    ) -> crate::oracle::pricefeeds::Result<f64> {
        let path = "events/test_feed";
        fs::create_dir_all(path).map_err(|err| {
            error!("test_feed: cannot create feed dir {path}: {err}");
            PriceFeedError::PriceNotAvailableError(asset_pair, datetime)
        })?;
        let path = format!("{path}/{asset_pair}");
        let data = std::fs::read_to_string(&path).map_err(|err| {
            error!("test_feed: cannot read feed file {path}: {err}");
            PriceFeedError::PriceNotAvailableError(asset_pair, datetime)
        })?;

        if let Some(line) = data.lines().nth(0) {
            line.parse::<f64>().map_err(|err| {
                error!("test_feed: cannot parse a f64 number from {path} `{line}`: {err}");
                PriceFeedError::PriceNotAvailableError(asset_pair, datetime)
            })
        } else {
            error!("test_feed: feed file {path} is empty");
            Err(PriceFeedError::PriceNotAvailableError(asset_pair, datetime))
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::AssetPair::*;
    use std::fs;
    use std::fs::File;

    use super::*;
    use std::io::Write;

    #[tokio::test]
    async fn retrieve() {
        let path = "events/test_feed/BTCUSD";

        let _ = fs::remove_file(path);

        let feed = TestFeed {};

        let price = feed.retrieve_price(BTCUSD, OffsetDateTime::now_utc()).await;
        assert!(price.is_err());

        let mut output = File::create(path).unwrap();
        let _ = write!(output, "ABC");

        let price = feed.retrieve_price(BTCUSD, OffsetDateTime::now_utc()).await;
        assert!(price.is_err());

        let mut output = File::create(path).unwrap();
        let _ = write!(output, "123");

        let price = feed.retrieve_price(BTCUSD, OffsetDateTime::now_utc()).await;
        match price {
            Ok(value) => assert_eq!(123., value),
            Err(_) => assert!(false, "{:#?}", &price),
        }

        let mut output = File::create(path).unwrap();
        let _ = write!(output, "456.789");

        let price = feed.retrieve_price(BTCUSD, OffsetDateTime::now_utc()).await;
        match price {
            Ok(value) => assert_eq!(456.789, value),
            Err(_) => assert!(false, "{:#?}", &price),
        }

        let _ = fs::remove_file(path);
    }
}
