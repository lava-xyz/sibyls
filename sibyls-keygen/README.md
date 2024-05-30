# `sibyls-keygen`

`sibyls-keygen` is a command-line tool for generating and inspecting secp256k1 key pairs. It allows you to generate a new key pair and either print it to the console or save it to a file. Additionally, you can inspect a private key to obtain the corresponding public key.

## Build

To build the project, you need to have Rust installed. Clone the repository and build the project using Cargo:
```sh
git clone https://github.com/sibyls/sibyls-keygen.git
cd sibyls-keygen
cargo build --release
```

## Usage
The application supports two main commands: `generate` and `inspect`.

### Generate Command
The `generate` command creates a new secp256k1 key pair. You can choose to output the key pair to the console or save it to a file.

#### Examples

1. **Generate a key pair and print to console:**
```sh
./target/release/sibyls-keygen generate
```
**Sample Output**
```
Secret Key: 8581870e0d207b7aaf3ef5df60e3c483fee150b16689e158ea9437554c0d4d6e
Public Key: 02f3c64779a7c570bb6fbe297226de0286649b3266fb18aeaf3906aeb3de11c8ff
```

2. **Generate a key pair and save to a file:**
```sh
./target/release/sibyls-keygen generate --output-file /path/to/your/keystore.txt
```
If the file already exists, the command will fail unless the `--overwrite` flag is provided.

### Inspect Command
The `inspect` command accepts a private key from a file, environment variable, or command line argument and prints the corresponding public key.

#### Examples
1. **Inspect a private key from a file:**
```sh
./target/release/sibyls-keygen inspect --key /path/to/your/keystore.txt
```

2. **Inspect a private key from an environment variable:**
```sh
KEY=8581870e0d207b7aaf3ef5df60e3c483fee150b16689e158ea9437554c0d4d6e ./sibyls-keygen inspect
```
**Sample Output**
```
Public Key: 02f3c64779a7c570bb6fbe297226de0286649b3266fb18aeaf3906aeb3de11c8ff
```

3. **Inspect a private key from a command line argument:**
```sh
./target/release/sibyls-keygen inspect --key your_private_key_in_hex
```

