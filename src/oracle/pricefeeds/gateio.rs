use super::{PriceFeed, PriceFeedError, Result};
use crate::AssetPair;
use async_trait::async_trait;
use log::info;
use reqwest::Client;
use serde_json::Value;
use time::OffsetDateTime;

pub struct GateIo {}

#[async_trait]
impl PriceFeed for GateIo {
    fn translate_asset_pair(&self, asset_pair: AssetPair) -> &'static str {
        match asset_pair {
            AssetPair::BTCUSD => "BTC_USD",
        }
    }

    async fn retrieve_price(&self, asset_pair: AssetPair, instant: OffsetDateTime) -> Result<f64> {
        let client = Client::new();
        let start_time = instant.unix_timestamp();
        info!("sending gateio http request");
        println!("{}", self.translate_asset_pair(asset_pair));
        println!("{}", &start_time.to_string());
        let res: Vec<Vec<Value>> = client
            .get("https://api.gateio.ws/api/v4/spot/candlesticks")
            .query(&[
                ("currency_pair", self.translate_asset_pair(asset_pair)),
                ("from", &start_time.to_string()),
                ("limit", "1"),
            ])
            .send()
            .await?
            .json()
            .await?;
        info!("received response: {:#?}", res);

        if res.is_empty() {
            return Err(PriceFeedError::PriceNotAvailableError(asset_pair, instant));
        }

        Ok(res[0][5].as_str().unwrap().parse().unwrap())
    }
}

#[cfg(test)]
mod tests {
    use crate::AssetPair::BTCUSD;

    use super::*;

    #[tokio::test]
    async fn retrieve() {
        let feed = GateIo {};
        let price = feed.retrieve_price(BTCUSD, OffsetDateTime::now_utc()).await;
        match price {
            Ok(_) => assert!(true),
            Err(_) => assert!(false, "{:#?}", &price)
        }
    }
}