use super::{PriceFeed, PriceFeedError, Result};
use crate::AssetPair;
use async_trait::async_trait;
use log::info;
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

        info!("sending bitfinex http request");
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

        info!("received response: {:#?}", res[0][3]);
        Ok(res[0][3].to_string().parse().unwrap())
    }
}

mod tests {
    use crate::AssetPair::*;

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
