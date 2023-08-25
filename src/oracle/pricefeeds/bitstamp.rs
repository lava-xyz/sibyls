use super::{PriceFeed, PriceFeedError, Result};
use crate::AssetPair;
use async_trait::async_trait;
use log::info;
use reqwest::Client;
use serde::Deserialize;
use serde_json::Value;
use time::OffsetDateTime;

pub struct Bitstamp {}

#[derive(Debug, Deserialize)]
struct Response {
    code: Option<String>,
    errors: Option<Vec<Value>>,
    data: Option<OhlcData>,
}

#[derive(Debug, Deserialize)]
struct OhlcData {
    ohlc: Vec<Ohlc>,
}

#[derive(Debug, Deserialize)]
struct Ohlc {
    open: String,
}

#[async_trait]
impl PriceFeed for Bitstamp {
    fn id(&self) -> &'static str {
        "bitstamp"
    }

    fn translate_asset_pair(&self, asset_pair: AssetPair) -> &'static str {
        match asset_pair {
            AssetPair::BTCUSD => "btcusd",
        }
    }

    async fn retrieve_price(&self, asset_pair: AssetPair, instant: OffsetDateTime) -> Result<f64> {
        let client = Client::new();
        let asset_pair_translation = self.translate_asset_pair(asset_pair);
        let start_time = instant.unix_timestamp();
        info!("sending bitstamp http request");
        let res: Response = client
            .get(format!(
                "https://www.bitstamp.net/api/v2/ohlc/{}",
                asset_pair_translation
            ))
            .query(&[
                ("step", "60"),
                ("start", &start_time.to_string()),
                ("limit", "1"),
            ])
            .send()
            .await?
            .json()
            .await?;
        info!("received response: {:#?}", res);

        if let Some(errs) = res.errors {
            return Err(PriceFeedError::InternalError(format!(
                "bitstamp error: code {}, {:#?}",
                match res.code {
                    None => "unknown".to_string(),
                    Some(c) => c,
                },
                errs
            )));
        }

        Ok(res.data.unwrap().ohlc[0].open.parse().unwrap())
    }
}

#[cfg(test)]
mod tests {
    use crate::AssetPair::BTCUSD;

    use super::*;

    #[tokio::test]
    async fn retrieve() {
        let feed = Bitstamp {};
        let price = feed.retrieve_price(BTCUSD, OffsetDateTime::now_utc()).await;
        match price {
            Ok(_) => assert!(true),
            Err(_) => assert!(false, "{:#?}", &price),
        }
    }
}
