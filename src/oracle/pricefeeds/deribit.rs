use super::{PriceFeed, PriceFeedError, Result};
use crate::AssetPair;
use reqwest::Client;
use serde::Deserialize;
use time::OffsetDateTime;
use serde_json::Value;
use log::info;

#[derive(Deserialize, Debug)]
struct Response {
    result: Option<DeribitResult>,
    error: Option<Value>,
}

#[derive(Deserialize, Debug)]
struct DeribitResult {
    settlements: Vec<DeribitSettlement>,
}

#[derive(Deserialize, Debug)]
struct DeribitSettlement {
    index_price: f64,
}

use async_trait::async_trait;

pub struct Deribit {}

#[async_trait]
impl PriceFeed for Deribit {
    fn id(&self) -> &'static str {
        "deribit"
    }

    fn translate_asset_pair(&self, asset_pair: AssetPair) -> Result<&'static str> {
        match asset_pair {
            AssetPair::BTCUSD => Ok("BTC"),
            AssetPair::BTCUSDT => return Err(PriceFeedError::InternalError(format!("deribit does not support USDT"))),
        }
    }

    async fn retrieve_price(&self, asset_pair: AssetPair, instant: OffsetDateTime) -> Result<f64> {
        let client = Client::new();
        let asset_pair_translation = self.translate_asset_pair(asset_pair).unwrap();
        let start_time = instant.unix_timestamp() * 1000;
        info!("sending deribit http request");
        let res: Response = client
            .get("https://www.deribit.com/api/v2/public/get_last_settlements_by_currency")
            .query(&[
                ("currency", asset_pair_translation),
                ("type", "delivery"),
                ("count", "1"),
                ("search_start_timestamp", &start_time.to_string()),
            ])
            .send()
            .await?
            .json()
            .await?;
        
        info!("received response: {:#?}", res);

        if let Some(error) = res.error {
            return Err(PriceFeedError::InternalError(format!(
                "deribit error: {:#?}",
                error
            )));
        }

        let res = res
            .result
            .ok_or(PriceFeedError::PriceNotAvailableError(asset_pair, instant))?;

        let index_price = res.settlements[0].index_price;
        Ok(index_price)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use time::OffsetDateTime;

    #[tokio::test]
    async fn test_retrieve_price() {
        let deribit = Deribit {};
        let now = OffsetDateTime::now_utc();
        let result = deribit.retrieve_price(AssetPair::BTCUSD, now).await;

        match result {
            Ok(price) => {
                println!("The price is: {}", price);
                assert!(price > 0.0);
            }
            Err(e) => panic!("API call failed with error: {:?}", e),
        }
    }
}
