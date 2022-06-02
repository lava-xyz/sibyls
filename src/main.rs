use actix_web::{get, web, App, HttpServer, HttpResponse, Responder};
use anyhow;
use serde::Deserialize;
use sled::Db;
use std::collections::HashMap;
use std::fmt::{self, Debug, Display, Formatter};

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
enum SortOrder {
    Insertion,
    ReverseInsertion
}

impl Default for SortOrder {
    fn default() -> Self {
        SortOrder::Insertion
    }
}

#[derive(Deserialize)]
struct Filters {
    #[serde(default)]
    sortBy: SortOrder,
}

#[derive(Copy, Clone, Debug, Eq, Hash, PartialEq)]
enum AssetPair {
    BTCUSD,
}

impl Display for AssetPair {
    fn fmt(&self, f: &mut Formatter) -> fmt::Result {
        Debug::fmt(self, f)
    }
}

#[get("/announcements")]
async fn announcements(filters: web::Query<Filters>) -> impl Responder {
    HttpResponse::Ok().body("Hello world!")
}

#[actix_web::main]
async fn main() -> anyhow::Result<()> {
    let asset_pairs = [AssetPair::BTCUSD];

    // setup event databases
    let mut event_databases: HashMap<AssetPair, Db> = HashMap::new();
    for asset_pair in asset_pairs {
        let path = format!("events/{}", asset_pair.to_string());
        event_databases.insert(asset_pair, sled::open(path)?);
    }

    // start retrieving price feeds

    // setup and run server
    HttpServer::new(|| {
        App::new().service(
            web::scope("/v1")
                .service(announcements)
        )
    })
    .bind(("127.0.0.1", 8080))?
    .run()
    .await?;

    Ok(())
}
