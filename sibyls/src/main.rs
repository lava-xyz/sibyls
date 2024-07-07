#[macro_use]
extern crate log;

use actix_web::{get, web, App, HttpResponse, HttpServer};
use clap::Parser;
use dlc_messages::ser_impls::write_as_tlv;
use hex::ToHex;
use secp256k1_zkp::{KeyPair, Secp256k1, SecretKey};
use serde::Serialize;
use sibyls::oracle::pricefeeds::create_price_feeds;
use std::process::exit;
use std::{collections::HashMap, env, fs::File, io::Read, path::PathBuf, str::FromStr};
use time::{format_description::well_known::Rfc3339, OffsetDateTime};

use sibyls::{
    oracle::{oracle_scheduler, Oracle},
    AssetPair, AssetPairInfo, OracleConfig,
};

use sibyls::common::*;

#[cfg(not(feature = "test-feed"))]
use sibyls::oracle::pricefeeds::ALL_PRICE_FEEDS;

mod error;
use error::SibylsError;

#[derive(Serialize)]
struct ApiOracleEvent {
    asset_pair: AssetPair,
    announcement: String,
    attestation: Option<String>,
    maturation: String,
    outcome: Option<u64>,
}

impl From<&OracleEvent> for ApiOracleEvent {
    fn from(value: &OracleEvent) -> Self {
        let mut announcement_bytes = Vec::new();
        write_as_tlv(&value.announcement, &mut announcement_bytes)
            .expect("Error writing announcement");
        let announcement_hex = announcement_bytes.encode_hex::<String>();

        let attestation_hex = value.attestation.clone().map(|att| {
            let mut attestation_bytes = Vec::new();
            write_as_tlv(&att, &mut attestation_bytes).expect("Error writing attestation");
            attestation_bytes.encode_hex::<String>()
        });

        ApiOracleEvent {
            asset_pair: value.asset_pair,
            announcement: announcement_hex,
            attestation: attestation_hex,
            maturation: value.maturation.format(&Rfc3339).unwrap(),
            outcome: value.outcome,
        }
    }
}

#[get("/announcements")]
async fn announcements(
    oracles: web::Data<HashMap<AssetPair, Oracle>>,
    filters: web::Query<Filters>,
) -> actix_web::Result<HttpResponse, actix_web::Error> {
    info!("GET /announcements: {:#?}", filters);
    let oracle = match oracles.get(&filters.asset_pair) {
        None => return Err(SibylsError::UnrecordedAssetPairError(filters.asset_pair).into()),
        Some(val) => val,
    };

    let events = oracle.event_database.list_oracle_events(filters.0)?;
    let events = events
        .iter()
        .map(|e| e.into())
        .collect::<Vec<ApiOracleEvent>>();
    Ok(HttpResponse::Ok().json(events))
}

#[get("/announcement/{rfc3339_time}")]
async fn announcement(
    oracles: web::Data<HashMap<AssetPair, Oracle>>,
    filters: web::Query<Filters>,
    path: web::Path<String>,
) -> actix_web::Result<HttpResponse, actix_web::Error> {
    info!("GET /announcement/{}: {:#?}", path, filters);
    let maturation =
        OffsetDateTime::parse(&path, &Rfc3339).map_err(SibylsError::DatetimeParseError)?;

    let oracle = match oracles.get(&filters.asset_pair) {
        None => return Err(SibylsError::UnrecordedAssetPairError(filters.asset_pair).into()),
        Some(val) => val,
    };

    info!("retrieving oracle event with maturation {}", path);

    let event = oracle
        .event_database
        .get_oracle_event(&maturation, filters.asset_pair)?;
    let event = Into::<ApiOracleEvent>::into(&event);

    Ok(HttpResponse::Ok().json(event))
}

#[get("/config")]
async fn config(
    oracles: web::Data<HashMap<AssetPair, Oracle>>,
) -> actix_web::Result<HttpResponse, actix_web::Error> {
    info!("GET /config");
    Ok(HttpResponse::Ok().json(
        oracles
            .values()
            .next()
            .expect("no asset pairs recorded")
            .oracle_config,
    ))
}

fn get_default_oracle_config_path() -> PathBuf {
    let mut path = env::current_dir().unwrap();
    path.push("config");
    path.push("oracle.json");
    path
}

fn get_default_asset_pair_config_path() -> PathBuf {
    let mut path = env::current_dir().unwrap();
    path.push("config");
    path.push("asset_pair.json");
    path
}

fn get_default_keystore_path() -> PathBuf {
    let mut path = env::current_dir().unwrap();
    path.push("config");
    path.push("keystore");
    path
}

#[derive(Parser)]
#[clap(author, version, about)]
/// Simple DLC oracle implementation
struct Args {
    /// Secret key (can be a string or a file path)
    #[clap(short, long, env, value_name = "KEY")]
    #[arg(default_value= get_default_keystore_path().into_os_string())]
    key: String, // KEY environment variable
    /// The asset pair config file
    #[clap(short, long, value_name = "FILE", value_hint = clap::ValueHint::FilePath)]
    #[arg(default_value= get_default_asset_pair_config_path().into_os_string())]
    asset_pair_config_file: PathBuf,
    /// The oracle config file
    #[clap(short, long, value_name = "FILE", value_hint = clap::ValueHint::FilePath)]
    #[arg(default_value= get_default_oracle_config_path().into_os_string())]
    oracle_config_file: PathBuf,
    /// The oracle config file
    #[clap(short, long, env, value_name = "DATABASE_URL")]
    #[arg(default_value = "sled")]
    database_url: String,
}

#[actix_web::main]
async fn main() -> anyhow::Result<()> {
    env_logger::init();

    let args = Args::parse();

    // Read the secret key, either directly or from a file
    let secret_key_found = if PathBuf::from(&args.key).exists() {
        let mut secret_key_str = String::new();
        File::open(args.key)?.read_to_string(&mut secret_key_str)?;
        secret_key_str.trim().to_string()
    } else {
        args.key
    };

    let secp = Secp256k1::new();
    let keypair: KeyPair =
        KeyPair::from_secret_key(&secp, &SecretKey::from_str(&secret_key_found).unwrap());
    info!(
        "oracle keypair successfully generated, pubkey is {}",
        keypair.public_key().serialize().encode_hex::<String>()
    );

    // read asset pair config from file
    info!(
        "reading asset pair config from {}",
        args.asset_pair_config_file.as_os_str().to_string_lossy()
    );
    let mut asset_pair_config_str = String::new();
    File::open(args.asset_pair_config_file)?.read_to_string(&mut asset_pair_config_str)?;
    let asset_pair_infos: Vec<AssetPairInfo> = serde_json::from_str(&asset_pair_config_str)?;
    info!(
        "asset pair config successfully read: {:#?}",
        asset_pair_infos
    );

    // read oracle config from file
    info!(
        "reading oracle config from {}",
        args.oracle_config_file.as_os_str().to_string_lossy()
    );
    let mut oracle_config_str = String::new();
    File::open(args.oracle_config_file)?.read_to_string(&mut oracle_config_str)?;
    let oracle_config: OracleConfig = serde_json::from_str(&oracle_config_str)?;
    info!("oracle config successfully read: {:#?}", oracle_config);

    // setup event databases
    let oracles = asset_pair_infos
        .iter()
        .map(|asset_pair_info| asset_pair_info.asset_pair)
        .zip(asset_pair_infos.iter().cloned().map(|asset_pair_info| {
            let asset_pair = asset_pair_info.asset_pair;
            let include_price_feeds = asset_pair_info.include_price_feeds.clone();
            let exclude_price_feeds = asset_pair_info.exclude_price_feeds.clone();

            // create oracle
            info!("creating oracle for {}", asset_pair);
            // setup event database

            let oracle = Oracle::new(oracle_config, asset_pair_info, keypair, &args.database_url)?;

            // pricefeed retrieval
            info!("creating pricefeeds for {asset_pair}");
            let mut feed_ids = if include_price_feeds.is_empty() {
                #[cfg(not(feature = "test-feed"))]
                let ret = ALL_PRICE_FEEDS.to_vec();
                #[cfg(feature = "test-feed")]
                let ret = vec![sibyls::oracle::pricefeeds::FeedId::Test];
                ret
            } else {
                include_price_feeds
            };

            feed_ids.retain(|x| !exclude_price_feeds.contains(x));

            if feed_ids.is_empty() {
                error!("all pricefeeds for {asset_pair} are disabled");
                exit(-2);
            }

            info!("Using following price feeds: {feed_ids:?}");

            let pricefeeds = create_price_feeds(&feed_ids);

            info!("scheduling oracle events for {asset_pair}");
            // schedule oracle events (announcements/attestations)
            oracle_scheduler::init(
                oracle.clone(),
                secp.clone(),
                pricefeeds,
                oracle_config.signing_version,
                oracle_config.price_aggregation_type,
            )?;

            Ok(oracle)
        }))
        .map(|(asset_pair, oracle)| oracle.map(|ok| (asset_pair, ok)))
        .collect::<anyhow::Result<HashMap<_, _>>>()?;

    // setup and run server
    let rpc_bind = env::var("SIBYLS_RPC_BIND").unwrap_or("0.0.0.0:8080".to_string());
    info!("starting server at {rpc_bind}");
    HttpServer::new(move || {
        App::new()
            .app_data(web::Data::new(oracles.clone()))
            .service(
                web::scope("/v1")
                    .service(announcements)
                    .service(announcement)
                    .service(config),
            )
    })
    .bind(rpc_bind)?
    .run()
    .await?;

    Ok(())
}
