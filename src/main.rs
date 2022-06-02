use actix_web::{get, web, App, HttpResponse, HttpServer, Responder};
use anyhow;
use clap::Parser;
use secp256k1_zkp::{rand, PublicKey, Secp256k1, SecretKey};
use serde::Deserialize;
use std::{
    collections::HashMap,
    fs::{self, File},
    io::Read,
    path::PathBuf,
    str::FromStr,
};

use sybils::{
    oracle::{EventDescriptor, Oracle, Result},
    AssetPairInfo,
};

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
enum SortOrder {
    Insertion,
    ReverseInsertion,
}

impl Default for SortOrder {
    fn default() -> Self {
        SortOrder::Insertion
    }
}

#[derive(Deserialize)]
struct Filters {
    #[serde(default)]
    #[serde(rename = "sortBy")]
    sort_by: SortOrder,
}

#[get("/announcements")]
async fn announcements(filters: web::Query<Filters>) -> impl Responder {
    HttpResponse::Ok()
}

#[derive(Parser)]
/// Simple DLC oracle implementation
struct Args {
    /// Optional private key file; if not provided, one is generated
    #[clap(short, long = "secret-key-file", parse(from_os_str), value_name = "FILE", value_hint = clap::ValueHint::FilePath)]
    secret_key_file: Option<std::path::PathBuf>,

    /// Optional asset pair config file; if not provided, it is assumed to exist at "config/asset_pair.json"
    #[clap(short, long = "asset-pair-config-file", parse(from_os_str), value_name = "FILE", value_hint = clap::ValueHint::FilePath)]
    asset_pair_config_file: Option<std::path::PathBuf>,
}

#[actix_web::main]
async fn main() -> anyhow::Result<()> {
    let args = Args::parse();

    let mut secret_key = String::new();
    let secp = Secp256k1::new();

    let secret_key = match args.secret_key_file {
        None => secp.generate_keypair(&mut rand::thread_rng()).0,
        Some(path) => {
            File::open(path)?.read_to_string(&mut secret_key)?;
            let secret_key = SecretKey::from_str(&secret_key)?;
            secret_key
        }
    };

    let asset_pair_infos: Vec<AssetPairInfo> = match args.asset_pair_config_file {
        None => serde_json::from_str(&fs::read_to_string("config/asset_pair.json")?)?,
        Some(path) => {
            let mut asset_pair_info = String::new();
            File::open(path)?.read_to_string(&mut asset_pair_info)?;
            serde_json::from_str(&asset_pair_info)?
        }
    };

    // setup event databases
    let mut oracles = asset_pair_infos
        .iter()
        .map(|asset_pair_info| asset_pair_info.asset_pair)
        .zip(asset_pair_infos.iter().map(Oracle::new))
        .map(|(asset_pair, oracle)| oracle.map(|ok| (asset_pair, ok)))
        .collect::<Result<HashMap<_, _>>>()?;

    // setup and run server
    HttpServer::new(|| App::new().service(web::scope("/v1").service(announcements)))
        .bind(("127.0.0.1", 8080))?
        .run()
        .await?;

    Ok(())
}
