use super::{PriceFeed, PriceFeedError, Result};
use crate::AssetPair;
use async_trait::async_trait;
use log::{debug, info};
use reqwest::Client;
use serde_json::Value;
use time::OffsetDateTime;

pub struct GateIo {}

#[async_trait]
impl PriceFeed for GateIo {
    fn id(&self) -> &'static str {
        "gateio"
    }

    fn translate_asset_pair(&self, asset_pair: AssetPair) -> Result<&'static str> {
        match asset_pair {
            AssetPair::BTCUSD => Ok("BTC_USD"),
            AssetPair::BTCUSDT => Ok("BTC_USDT"),
        }
    }

    async fn retrieve_price(&self, asset_pair: AssetPair, instant: OffsetDateTime) -> Result<f64> {
        let client = Client::new();
        let start_time = instant.unix_timestamp();
        info!("sending gateio http request {asset_pair} {instant}");
        let res: Vec<Vec<Value>> = client
            .get("https://api.gateio.ws/api/v4/spot/candlesticks")
            .query(&[
                (
                    "currency_pair",
                    self.translate_asset_pair(asset_pair).unwrap(),
                ),
                ("from", &start_time.to_string()),
                ("limit", "1"),
            ])
            .send()
            .await?
            .json()
            .await?;
        debug!("received gateio response: {:#?}", res);

        if res.is_empty() {
            return Err(PriceFeedError::PriceNotAvailableError(asset_pair, instant));
        }

        let price = res
            .get(0)
            .ok_or(PriceFeedError::PriceNotAvailableError(asset_pair, instant))?
            .get(5)
            .ok_or(PriceFeedError::PriceNotAvailableError(asset_pair, instant))?
            .as_str()
            .unwrap()
            .parse()
            .unwrap();
        info!("gateio price {price}");
        Ok(price)
    }
}

#[cfg(test)]
mod tests {
    use crate::AssetPair::*;

    use super::*;

    /* TODO fix this test
    #[tokio::test]
    async fn retrieve() {
        let feed = GateIo {};
        let price = feed
            .retrieve_price(BTCUSDT, OffsetDateTime::now_utc())
            .await;
        match price {
            Ok(_) => assert!(true),
            Err(_) => assert!(false, "{:#?}", &price),
        }
    }
     */
}
