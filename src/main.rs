#[macro_use]
extern crate log;

use actix_web::{get, web, App, HttpResponse, HttpServer};
use clap::{Parser, Subcommand};
use hex::ToHex;
use rand::rngs::OsRng;
use secp256k1_zkp::{rand, KeyPair, Secp256k1, SecretKey};
use serde::{Deserialize, Serialize};
use sibyls::oracle::pricefeeds::create_price_feeds;
use sled::IVec;
use std::process::exit;
use std::{
    collections::HashMap,
    env,
    fs::File,
    io::Read,
    path::PathBuf,
    str::FromStr,
};
use time::{format_description::well_known::Rfc3339, Duration, OffsetDateTime};

use sibyls::{
    oracle::{oracle_scheduler, DbValue, Oracle},
    AssetPair, AssetPairInfo, OracleConfig,
};

#[cfg(not(feature = "test-feed"))]
use sibyls::oracle::pricefeeds::ALL_PRICE_FEEDS;

mod error;
use error::SibylsError;

const PAGE_SIZE: u32 = 100;

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
enum SortOrder {
    Insertion,
    ReverseInsertion,
}

#[derive(Debug, Deserialize)]
#[serde(default, rename_all = "camelCase")]
struct Filters {
    sort_by: SortOrder,
    page: u32,
    asset_pair: AssetPair,
}

impl Default for Filters {
    fn default() -> Self {
        Filters {
            sort_by: SortOrder::ReverseInsertion,
            page: 0,
            asset_pair: AssetPair::BTCUSD,
        }
    }
}

#[derive(Serialize)]
struct ApiOracleEvent {
    asset_pair: AssetPair,
    announcement: String,
    attestation: Option<String>,
    maturation: String,
    outcome: Option<u64>,
}

fn parse_database_entry(
    asset_pair: AssetPair,
    (maturation, event): (IVec, IVec),
) -> ApiOracleEvent {
    let maturation = String::from_utf8_lossy(&maturation).to_string();
    let event: DbValue = serde_json::from_str(&String::from_utf8_lossy(&event)).unwrap();
    ApiOracleEvent {
        asset_pair,
        announcement: event.1.encode_hex::<String>(),
        attestation: event.2.map(|att| att.encode_hex::<String>()),
        maturation,
        outcome: event.3,
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

    if oracle.event_database.is_empty() {
        info!("no oracle events found");
        return Ok(HttpResponse::Ok().json(Vec::<ApiOracleEvent>::new()));
    }

    let start = filters.page * PAGE_SIZE;

    match filters.sort_by {
        SortOrder::Insertion => loop {
            let init_key = oracle
                .event_database
                .first()
                .map_err(SibylsError::DatabaseError)?
                .unwrap()
                .0;
            let start_key = OffsetDateTime::parse(&String::from_utf8_lossy(&init_key), &Rfc3339)
                .unwrap()
                + Duration::days(start.into());
            let end_key = start_key + Duration::days(PAGE_SIZE.into());
            let start_key = start_key.format(&Rfc3339).unwrap().into_bytes();
            let end_key = end_key.format(&Rfc3339).unwrap().into_bytes();
            if init_key
                == oracle
                    .event_database
                    .first()
                    .map_err(SibylsError::DatabaseError)?
                    .unwrap()
                    .0
            {
                // don't know if range can change while iterating due to another thread modifying
                info!(
                    "retrieving oracle events from {} to {}",
                    String::from_utf8_lossy(&start_key),
                    String::from_utf8_lossy(&end_key),
                );
                return Ok(HttpResponse::Ok().json(
                    oracle
                        .event_database
                        .range(start_key..end_key)
                        .map(|result| parse_database_entry(filters.asset_pair, result.unwrap()))
                        .collect::<Vec<_>>(),
                ));
            }
        },
        SortOrder::ReverseInsertion => loop {
            let init_key = oracle
                .event_database
                .last()
                .map_err(SibylsError::DatabaseError)?
                .unwrap()
                .0;
            let end_key = OffsetDateTime::parse(&String::from_utf8_lossy(&init_key), &Rfc3339)
                .unwrap()
                - Duration::days(start.into());
            let start_key = end_key - Duration::days(PAGE_SIZE.into());
            let start_key = start_key.format(&Rfc3339).unwrap().into_bytes();
            let end_key = end_key.format(&Rfc3339).unwrap().into_bytes();
            if init_key
                == oracle
                    .event_database
                    .last()
                    .map_err(SibylsError::DatabaseError)?
                    .unwrap()
                    .0
            {
                // don't know if range can change while iterating due to another thread modifying
                info!(
                    "retrieving oracle events from {} to {}",
                    String::from_utf8_lossy(&start_key),
                    String::from_utf8_lossy(&end_key),
                );
                return Ok(HttpResponse::Ok().json(
                    oracle
                        .event_database
                        .range(start_key..end_key)
                        .map(|result| parse_database_entry(filters.asset_pair, result.unwrap()))
                        .collect::<Vec<_>>(),
                ));
            }
        },
    }
}

#[get("/announcement/{rfc3339_time}")]
async fn announcement(
    oracles: web::Data<HashMap<AssetPair, Oracle>>,
    filters: web::Query<Filters>,
    path: web::Path<String>,
) -> actix_web::Result<HttpResponse, actix_web::Error> {
    info!("GET /announcement/{}: {:#?}", path, filters);
    let _ = OffsetDateTime::parse(&path, &Rfc3339).map_err(SibylsError::DatetimeParseError)?;

    let oracle = match oracles.get(&filters.asset_pair) {
        None => return Err(SibylsError::UnrecordedAssetPairError(filters.asset_pair).into()),
        Some(val) => val,
    };

    if oracle.event_database.is_empty() {
        info!("no oracle events found");
        return Err(SibylsError::OracleEventNotFoundError(path.to_string()).into());
    }

    info!("retrieving oracle event with maturation {}", path);
    let event = match oracle
        .event_database
        .get(path.as_bytes())
        .map_err(SibylsError::DatabaseError)?
    {
        Some(val) => val,
        None => return Err(SibylsError::OracleEventNotFoundError(path.to_string()).into()),
    };
    Ok(HttpResponse::Ok().json(parse_database_entry(
        filters.asset_pair,
        ((&**path).into(), event),
    )))
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
    let mut path = env::current_exe().unwrap();
    path.pop(); // remove the exe name
    path.pop(); // remove the debug/release directory
    path.pop(); // remove the target directory
    path.push("config");
    path.push("oracle.json");
    path}

fn get_default_asset_pair_config_path() -> PathBuf {
    let mut path = env::current_exe().unwrap();
    path.pop(); // remove the exe name
    path.pop(); // remove the debug/release directory
    path.pop(); // remove the target directory
    path.push("config");
    path.push("asset_pair.json");
    path
}

#[derive(Parser)]
/// Simple DLC oracle implementation
struct Args {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Debug, Subcommand)]
enum Commands {
    /// Serves the API
    #[command(arg_required_else_help = true)]
    Serve {
        /// Secret key
        #[clap(short, long, env, value_name = "SECRET_KEY")]
        secret_key: String, // SECRET_KEY environment variable 
        /// The asset pair config file
        #[clap(short, long, value_name = "FILE", value_hint = clap::ValueHint::FilePath)]
        #[arg(default_value= get_default_asset_pair_config_path().into_os_string())]
        asset_pair_config_file: PathBuf,
        /// The oracle config file
        #[clap(short, long, value_name = "FILE", value_hint = clap::ValueHint::FilePath)]
        #[arg(default_value= get_default_oracle_config_path().into_os_string())]
        oracle_config_file: PathBuf,
    },
    /// Generates a new keypair
    GenerateKey,
}

#[actix_web::main]
async fn main() -> anyhow::Result<()> {
    env_logger::init();

    let args = Args::parse();

    match args.command {
        Commands::Serve { asset_pair_config_file, oracle_config_file, secret_key } => {
            let secp = Secp256k1::new();
            let keypair = KeyPair::from_secret_key(&secp, &SecretKey::from_str(&secret_key).unwrap());
            info!(
                "oracle keypair successfully generated, pubkey is {}",
                keypair.public_key().serialize().encode_hex::<String>()
            );

            // read asset pair config from file
            info!("reading asset pair config from {}", asset_pair_config_file.as_os_str().to_string_lossy());
            let mut asset_pair_config_str = String::new();
            File::open(asset_pair_config_file)?.read_to_string(&mut asset_pair_config_str)?;
            let asset_pair_infos: Vec<AssetPairInfo> = serde_json::from_str(&asset_pair_config_str)?;
            info!("asset pair config successfully read: {:#?}", asset_pair_infos);
        
            // read oracle config from file
            info!("reading oracle config from {}", oracle_config_file.as_os_str().to_string_lossy());
            let mut oracle_config_str = String::new();
            File::open(oracle_config_file)?.read_to_string(&mut oracle_config_str)?;
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
                    let oracle = Oracle::new(oracle_config, asset_pair_info, keypair)?;
        
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
        
        }
        Commands::GenerateKey => {
            let secp = Secp256k1::new();
            let (secret_key, public_key) = secp.generate_keypair(&mut OsRng);

            let secret_key_hex = hex::encode(secret_key.as_ref());
            let public_key_hex = hex::encode(public_key.serialize());

            println!("Secret Key: {}", secret_key_hex);
            println!("Public Key: {}", public_key_hex);
        }
    }
    
    Ok(())
}
