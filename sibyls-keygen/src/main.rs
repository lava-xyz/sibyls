use clap::{Parser, Subcommand};
use secp256k1::{rand, Secp256k1, SecretKey, PublicKey};
use std::{fs::File, io::{self, Read, Write}, path::{Path, PathBuf}, env};

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
        /// Path and filename to save the key, if not provided, key will be printed to console
        #[clap(short='f', long, value_name = "FILE", value_hint = clap::ValueHint::FilePath)]
        output_file: Option<PathBuf>,

        /// Overwrite the file if it already exists
        #[clap(long)]
        overwrite: bool,
    },
    /// Inspects a private key and prints the corresponding public key
    Inspect {
        /// Private key as a file, environment variable, or command line argument
        #[clap(short, long, env, value_name = "KEY")]
        key: String,
    },
}

fn main() {
    // Initialize the logger
    env_logger::init();

    let args = Args::parse();
    let secp = Secp256k1::new();

    match args.command {
        Commands::Generate { output_file, overwrite } => {
            match generate_keypair(&secp, output_file.as_deref(), overwrite) {
                Ok((secret_key_hex, public_key_hex)) => {
                    if output_file.is_none() {
                        println!("Secret Key: {}", secret_key_hex);
                        println!("Public Key: {}", public_key_hex);
                    }
                },
                Err(e) => eprintln!("Error: {}", e),
            }
        },
        Commands::Inspect { key } => {
            match inspect_key(&secp, &key) {
                Ok(public_key_hex) => println!("Public Key: {}", public_key_hex),
                Err(e) => eprintln!("Error: {}", e),
            }
        },
    }
}

fn generate_keypair(secp: &Secp256k1<secp256k1::All>, output_file: Option<&Path>, overwrite: bool) -> Result<(String, String), io::Error> {
    let secret_key = SecretKey::new(&mut rand::thread_rng());
    let secret_key_hex = hex::encode(secret_key.as_ref());

    let public_key = PublicKey::from_secret_key(secp, &secret_key);
    let public_key_hex = hex::encode(public_key.serialize());

    if let Some(path) = output_file {
        if path.exists() && !overwrite {
            return Err(io::Error::new(io::ErrorKind::AlreadyExists, format!("File {} already exists", path.display())));
        }
        let mut file = File::create(path)?;
        writeln!(file, "{}", secret_key_hex)?;
        println!("Private key has been saved to the file: {}", path.display());
    }

    Ok((secret_key_hex, public_key_hex))
}

fn inspect_key(secp: &Secp256k1<secp256k1::All>, key: &str) -> Result<String, io::Error> {
    let secret_key_hex = if Path::new(key).exists() {
        let mut file = File::open(key)?;
        let mut contents = String::new();
        file.read_to_string(&mut contents)?;
        contents.trim().to_string()
    } else if let Ok(env_key) = env::var(key) {
        env_key
    } else {
        key.to_string()
    };

    let secret_key_bytes = hex::decode(&secret_key_hex).map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "Invalid hex string"))?;
    let secret_key = SecretKey::from_slice(&secret_key_bytes).map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "Invalid secret key"))?;
    let public_key = PublicKey::from_secret_key(secp, &secret_key);
    let public_key_hex = hex::encode(public_key.serialize());

    Ok(public_key_hex)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    #[test]
    fn test_generate_keypair_console() {
        let secp = Secp256k1::new();
        let (secret_key_hex, public_key_hex) = generate_keypair(&secp, None, false).unwrap();
        
        assert_eq!(secret_key_hex.len(), 64);
        assert_eq!(public_key_hex.len(), 66);
    }

    #[test]
    fn test_inspect_key_from_str() {
        let secp = Secp256k1::new();
        let secret_key_hex = "c1b8c027c89bb2c8b8db0b93721e1e9885e92b6b68d44c1f9026f83e5a2763df";
        let expected_public_key_hex = "0244990384b935f24a9c0babd4642113678c3dde5dc7904589497bc435f90bfe1f";
        let public_key_hex = inspect_key(&secp, secret_key_hex).unwrap();
                
        assert_eq!(public_key_hex.len(), 66);
        assert_eq!(public_key_hex, expected_public_key_hex);
    }

    #[test]
    fn test_generate_keypair_file() {
        use secp256k1::rand::Rng;
        let secp = Secp256k1::new();
        let random_filename: String = rand::thread_rng()
            .sample_iter(&rand::distributions::Alphanumeric)
            .take(10)
            .map(char::from)
            .collect();
        let path = env::current_dir().unwrap().join(random_filename);

        let (secret_key_hex, public_key_hex) = generate_keypair(&secp, Some(&path), false).unwrap();

        let mut read_contents = String::new();
        File::open(&path).expect("Unable to open file")
            .read_to_string(&mut read_contents).expect("Unable to read file");

        assert_eq!(read_contents.trim(), secret_key_hex);
        assert_eq!(secret_key_hex.len(), 64);
        assert_eq!(public_key_hex.len(), 66);

        fs::remove_file(&path).expect("Unable to delete test file");
    }

    #[test]
    fn test_generate_keypair_file_overwrite() {
        use secp256k1::rand::Rng;
        let secp = Secp256k1::new();
        let random_filename: String = rand::thread_rng()
            .sample_iter(&rand::distributions::Alphanumeric)
            .take(10)
            .map(char::from)
            .collect();
        let path = env::current_dir().unwrap().join(random_filename);

        // First, create the file without overwriting
        let (secret_key_hex1, public_key_hex1) = generate_keypair(&secp, Some(&path), false).unwrap();

        // Ensure file content is as expected
        let mut read_contents = String::new();
        File::open(&path).expect("Unable to open file")
            .read_to_string(&mut read_contents).expect("Unable to read file");

        assert_eq!(read_contents.trim(), secret_key_hex1);

        // Now, overwrite the file
        let (secret_key_hex2, public_key_hex2) = generate_keypair(&secp, Some(&path), true).unwrap();

        // Ensure file content is updated
        let mut read_contents = String::new();
        File::open(&path).expect("Unable to open file")
            .read_to_string(&mut read_contents).expect("Unable to read file");

        assert_eq!(read_contents.trim(), secret_key_hex2);

        assert_ne!(secret_key_hex1, secret_key_hex2);
        assert_ne!(public_key_hex1, public_key_hex2);

        fs::remove_file(&path).expect("Unable to delete test file");
    }
}