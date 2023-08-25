use std::collections::HashMap;

use async_trait::async_trait;
use log::info;
use reqwest::Client;
use serde::Deserialize;
use serde_json::Value;
use time::OffsetDateTime;

use crate::AssetPair;

use super::{PriceFeed, PriceFeedError, Result};

pub struct Kraken {}

#[derive(Debug, Deserialize)]
struct Response {
    error: Vec<String>,
    result: HashMap<String, Value>,
}

#[async_trait]
impl PriceFeed for Kraken {
    fn id(&self) -> &'static str {
        "kraken"
    }

    fn translate_asset_pair(&self, asset_pair: AssetPair) -> &'static str {
        match asset_pair {
            AssetPair::BTCUSD => "XXBTZUSD",
        }
    }

    async fn retrieve_price(&self, asset_pair: AssetPair, instant: OffsetDateTime) -> Result<f64> {
        let client = Client::new();
        let asset_pair_translation = self.translate_asset_pair(asset_pair);
        let start_time = instant.unix_timestamp();
        info!("sending kraken http request");
        let res: Response = client
            .get("https://api.kraken.com/0/public/OHLC")
            .query(&[
                ("pair", asset_pair_translation),
                ("since", &start_time.to_string()),
            ])
            .send()
            .await?
            .json()
            .await?;
        info!("received response: {:#?}", res);

        if !res.error.is_empty() {
            return Err(PriceFeedError::InternalError(format!(
                "kraken error: {:#?}",
                res.error
            )));
        }

        let res = res
            .result
            .get(asset_pair_translation)
            .ok_or(PriceFeedError::PriceNotAvailableError(asset_pair, instant))?;

        Ok(res[0][1].as_str().unwrap().parse().unwrap())
    }
}

#[cfg(test)]
mod tests {
    use crate::AssetPair::BTCUSD;

    use super::*;

    #[tokio::test]
    async fn retrieve() {
        let feed = Kraken {};
        let price = feed.retrieve_price(BTCUSD, OffsetDateTime::now_utc()).await;
        match price {
            Ok(_) => assert!(true),
            Err(_) => assert!(false, "{:#?}", &price)
        }
    }
}