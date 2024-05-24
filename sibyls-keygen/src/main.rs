use clap::{Parser, Subcommand, ValueEnum};
use hex;
use secp256k1::{rand, Secp256k1, SecretKey, PublicKey};
use std::{fs::File, io::{Read, Write}, path::PathBuf, env};

fn get_default_keystore_path() -> PathBuf {
    let mut path = env::current_dir().unwrap();
    path.push("keystore");
    path
}

#[derive(Parser)]
#[clap(author, version, about)]
struct Args {
    #[clap(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Generates a new keypair
    Generate {
        /// Output the key to the console or save to a file
        #[clap(short='o', long, value_enum, default_value = "console")]
        output: OutputType,
        /// Path and filename to save the key, required if output is "file"
        #[clap(short='f', long, value_name = "FILE", value_hint = clap::ValueHint::FilePath, requires_if("output", "file"))]
        #[arg(default_value= get_default_keystore_path().into_os_string())]
        output_file: Option<PathBuf>,
    },
    /// Inspects a private key and prints the corresponding public key
    Inspect {
        /// Private key as a file, environment variable, or command line argument
        #[clap(short, long, env, value_name = "KEY")]
        key: String,
    },
}

#[derive(Debug, ValueEnum, Clone)]
enum OutputType {
    Console,
    File,
}

fn main() {
    // Initialize the logger
    env_logger::init();

    let args = Args::parse();
    let secp = Secp256k1::new();

    match args.command {
        Commands::Generate { output, output_file } => {
            let secret_key = SecretKey::new(&mut rand::thread_rng());
            let public_key = PublicKey::from_secret_key(&secp, &secret_key);

            let secret_key_hex = hex::encode(secret_key.as_ref());
            let public_key_hex = hex::encode(public_key.serialize());

            match output {
                OutputType::Console => {
                    println!("Secret Key: {}", secret_key_hex);
                    println!("Public Key: {}", public_key_hex);
                },
                OutputType::File => {
                    if let Some(path) = output_file {
                        let mut file = File::create(path.clone()).expect("Unable to create file");
                        writeln!(file, "{}", secret_key_hex).expect("Unable to write to file");
                        println!("Private key has been saved to the file: {}", path.display());
                    } else {
                        eprintln!("Output file path is required when output type is 'file'.");
                    }
                },
            }
        },
        Commands::Inspect { key } => {
            let secret_key_hex = if PathBuf::from(&key).exists() {
                let mut file = File::open(key).expect("Unable to open file");
                let mut contents = String::new();
                file.read_to_string(&mut contents).expect("Unable to read file");
                contents.trim().to_string()
            } else if let Ok(env_key) = env::var(&key) {
                env_key
            } else {
                key
            };

            let secret_key_bytes = hex::decode(secret_key_hex).expect("Invalid hex string");
            let secret_key = SecretKey::from_slice(&secret_key_bytes).expect("Invalid secret key");
            let public_key = PublicKey::from_secret_key(&secp, &secret_key);
            let public_key_hex = hex::encode(public_key.serialize());

            println!("Public Key: {}", public_key_hex);
        },
    }
}