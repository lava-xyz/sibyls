use super::{PriceFeed, PriceFeedError, Result};
use crate::AssetPair;
use async_trait::async_trait;
use log::{debug, info};
use reqwest::Client;
use time::OffsetDateTime;

pub struct Bitfinex {}

type Response = Vec<Vec<f64>>;

#[async_trait]
impl PriceFeed for Bitfinex {
    fn id(&self) -> &'static str {
        "bitfinex"
    }

    fn translate_asset_pair(&self, asset_pair: AssetPair) -> Result<&'static str> {
        match asset_pair {
            AssetPair::BTCUSD => Ok("tBTCUSD"),
            AssetPair::BTCUSDT => Ok("tBTCUST"),
        }
    }

    async fn retrieve_price(&self, asset_pair: AssetPair, instant: OffsetDateTime) -> Result<f64> {
        let client = Client::new();
        let asset_pair_translation = self.translate_asset_pair(asset_pair).unwrap();
        let start_time: i64 = instant.unix_timestamp();

        info!("sending bitfinex http request {asset_pair} {instant}");
        let res: Response = client
            .get(format!(
                "https://api-pub.bitfinex.com/v2/trades/{}/hist",
                asset_pair_translation
            ))
            .query(&[("start", &start_time.to_string())])
            .send()
            .await?
            .json()
            .await?;

        if res.is_empty() {
            return Err(PriceFeedError::InternalError(
                "Invalid response from Bitfinex".to_string(),
            ));
        }

        debug!("received bitfinex response: {:#?}", res);
        let price = res
            .get(0)
            .ok_or(PriceFeedError::PriceNotAvailableError(asset_pair, instant))?
            .get(3)
            .ok_or(PriceFeedError::PriceNotAvailableError(asset_pair, instant))?
            .to_string()
            .parse()
            .unwrap();
        info!("bitfinex price: {price}");
        Ok(price)
    }
}

#[cfg(test)]
mod tests {
    use crate::AssetPair::BTCUSD;

    use super::*;

    #[tokio::test]
    async fn retrieve() {
        let feed = Bitfinex {};
        let price = feed.retrieve_price(BTCUSD, OffsetDateTime::now_utc()).await;
        match price {
            Ok(_) => assert!(true),
            Err(_) => assert!(false, "{:#?}", &price),
        }
    }
}
