use super::{PriceFeed, PriceFeedError, Result};
use crate::AssetPair;
use async_trait::async_trait;
use reqwest::Client;
use serde::Deserialize;
use serde_json::Value;
use std::collections::HashMap;
use time::OffsetDateTime;

pub struct Bitstamp {}

#[derive(Deserialize)]
struct Response {
    code: Option<String>,
    errors: Option<Vec<Value>>,
    data: Option<OhlcData>,
}

#[derive(Deserialize)]
struct OhlcData {
    pair: String,
    ohlc: Vec<Ohlc>,
}

#[derive(Deserialize)]
struct Ohlc {
    open: String,
}

#[async_trait]
impl PriceFeed for Bitstamp {
    fn translate_asset_pair(&self, asset_pair: AssetPair) -> &'static str {
        match asset_pair {
            AssetPair::BTCUSD => "btcusd",
        }
    }

    async fn retrieve_price(&self, asset_pair: AssetPair, instant: OffsetDateTime) -> Result<f64> {
        let client = Client::new();
        let asset_pair_translation = self.translate_asset_pair(asset_pair);
        let start_time = instant.unix_timestamp();
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
