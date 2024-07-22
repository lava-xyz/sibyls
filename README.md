# sibyls
oracle implementation for bitcoin.

## API Description

A working version of this oracle is hosted at https://oracle.lava.xyz/v1/announcements.

### List all oracle events (announcements)

```sh
curl -X GET http://localhost:8080/v1/announcements
```

This endpoint returns a JSON array of oracle event objects. Oracle event objects contain the following fields:

| name          | type               | description                                               |
|---------------|--------------------|-----------------------------------------------------------|
| `asset_pair`  | `AssetPair` enum   | asset pair                                                |
| `announcement`| `String`           | hex-encoded TLV of [`oracle_announcement`](https://github.com/discreetlogcontracts/dlcspecs/blob/master/Messaging.md#the-oracle_announcement-type)           |
| `attestation` | `String` or `null` | hex-encoded TLV of [`oracle_attestation`](https://github.com/discreetlogcontracts/dlcspecs/blob/master/Messaging.md#the-oracle_attestation-type), if exists |
| `maturation`  | `String`           | [RFC3339](https://datatracker.ietf.org/doc/html/rfc3339)-encoded time of maturation (attestation)          |
| `outcome`     | `u64` or `null`    | outcome value, if exists                                  |

Each oracle is associated with one `AssetPair`, e.g. BTCUSD. Currently, the defined asset pairs are

| `AssetPair` |
|-------------|
| `BTCUSD`    |

To define more, see [Asset Pairs](#asset-pairs).

Output example:

```json
[
    {
        "announcement": "fdd824fd02c12673b7bfb25156649cca9392fd141fb8522513aa55def9e7c52b7676a99f2425fad0000ee160c6d25912201bb63d29e9ed07c477d5e41a404ae410a2c4e00f28f48cc73e5c7f5314c2687420afce8f0aef392e5fdb347cf27aee16530dbbf055fdd822fd025b00127be0ae742cd646641f7c1bdf6f9e3866e5680cbbc726f71461702329d3661f473465e6ee5d334fccc9c2cb7a6d229196a97eb79838e9a22f4ea3d0bd09c0fbf7f0bda5cd0482e379bd421a3b06c31bf3e28aae8dd3fd62835883cafcbb1cf957c82f79edcc9c65764315bdb4960e401c8d46346d85a6c44088cd3e22d4c91baa3c1961efa57146e53693d6700753e3e9838ac0b2e4feeb9d5d1579041489d0dc0caed2c87b9cb61fbe8877b4ce877eb0e7cd4984c93c0b90502ebe1a00185e27c1a4de36b326660829959ac002256c08885b76c79d74bcb5d874f8c8c97b2b5c1bbcb1a5905f5038f856e88c526abd60f6e0cffb368ebe195d7d4b06747794cace7c9474b0b0b0d002aa9445c73801b109bbd1bd9c755cc49f06440b795fe2504014a6a967735c22774923d6317569d165c9cc13567fe43ef2210ac9cf2a44863016f1aa4e3bb0ba798e37c0fb966a0d4b4109c4098480b9b8bbd4521eb0231d6f5811a2c173a39863101f82fd30c0ff5da2333a944f51c76a8352b0c14ae22d659ee72ed221a6977625bcb4b47ae8534f476e8a4043ac460ea942d92a3e18f6ebd42b71609f8f504953d6b01dc1493ece93c44a0dd067b96bd7e3322b731a95dadfb0f2f60d31cdd0bb9eb8faf4a7b2334a4607cac109e93f2d28b82affabd60a75ba317d2ec79f72a569fd5d5441942129c257873e5d197ce789ef3f0b7e687b2d9488277d025ce327b8763f6bf3273f206dbd97f5b6a7bc60ac710b89c65c470f1d7223b36b9851b4d0f0d0827b2337102030d5eb2a87a9efbb8dc6b4287f62968e00fdd80a100002000642544355534400000000001200",
        "asset_pair": "BTCUSD",
        "attestation": "fdd868fd04c700f48cc73e5c7f5314c2687420afce8f0aef392e5fdb347cf27aee16530dbbf05500127be0ae742cd646641f7c1bdf6f9e3866e5680cbbc726f71461702329d3661f47681cca8c347a39737b84a0c53cc4b3f17582dad6b8b91aa2466384aaba148bdb3465e6ee5d334fccc9c2cb7a6d229196a97eb79838e9a22f4ea3d0bd09c0fbf7e8f0b206fd7d3869ed18beeb280d12942292076409ec41af87653ca17f29fbf6f0bda5cd0482e379bd421a3b06c31bf3e28aae8dd3fd62835883cafcbb1cf9578854cc682afd35ab7058cc527305d206b4a0b009765d6ecd552fee4cca94d9c1c82f79edcc9c65764315bdb4960e401c8d46346d85a6c44088cd3e22d4c91baadd439252fed5704e7122fbc8bc788b6abb107cc4273657f218bda9782b05248d3c1961efa57146e53693d6700753e3e9838ac0b2e4feeb9d5d1579041489d0dcbe9959454ec190f32f3f4d7b93236b58da1b68fb8a416f0d7a6c9a6589ccacfb0caed2c87b9cb61fbe8877b4ce877eb0e7cd4984c93c0b90502ebe1a00185e273403a81cb0ea30825c660424d6cdcf452d2e5f2f7696cbf258bf3395b4cf36dbc1a4de36b326660829959ac002256c08885b76c79d74bcb5d874f8c8c97b2b5c6e5f6851b4538ec1b56d2736dd9bf9aa60e2c242de498ab7cf2eb2a6fe3ac37c1bbcb1a5905f5038f856e88c526abd60f6e0cffb368ebe195d7d4b06747794cabc7aecd60c7c5390a91e6f72ca487e0cffa4056c3c1dbc3c2764824a1aac00b2ce7c9474b0b0b0d002aa9445c73801b109bbd1bd9c755cc49f06440b795fe25078ccb5ecdd6187240d7d882a0d3766970ec34a7e4c20bd41610f7b4e6855852a4014a6a967735c22774923d6317569d165c9cc13567fe43ef2210ac9cf2a44867ca2d62f83827a7621fdc9b58fd2e8698f557896d9acb9521147454eab058d8c3016f1aa4e3bb0ba798e37c0fb966a0d4b4109c4098480b9b8bbd4521eb0231d4c29c2bf89149c8744771d0be40a309c7ee92962cdcefaaa01bb5468f2e67e276f5811a2c173a39863101f82fd30c0ff5da2333a944f51c76a8352b0c14ae22d7b0c43c87bc54ae172dff30a747e03a8c5b6187eba61190a2f6c268a49f88876659ee72ed221a6977625bcb4b47ae8534f476e8a4043ac460ea942d92a3e18f6acaeae727b9441aafe84180d093702859cb152089bd4c78c9f07aebb42f65a62ebd42b71609f8f504953d6b01dc1493ece93c44a0dd067b96bd7e3322b731a95955771a3aa57b6b03a36b86bae213702bc984b888203db796dd201044e7df38cdadfb0f2f60d31cdd0bb9eb8faf4a7b2334a4607cac109e93f2d28b82affabd60baa3eada7e44a8353d461030e9e72d5048cb923c99073b6613b82a63246bde10a75ba317d2ec79f72a569fd5d5441942129c257873e5d197ce789ef3f0b7e689599242f998d5baf3d80fa5aa26550588aa12aa5d1d9b16dd0e9051abaa95dcc7b2d9488277d025ce327b8763f6bf3273f206dbd97f5b6a7bc60ac710b89c65cf691a0c954c4a3e62b0ec434cd218acfb9df6c51b466f5964024ad7eae183353470f1d7223b36b9851b4d0f0d0827b2337102030d5eb2a87a9efbb8dc6b4287f1bb83e2f185e4a1413f147c484681ef9b09125c2aa81329fd5c91cdd1cf5b71a013001300130013101310131013101310130013001300130013001300130013001310131",
        "maturation": "2022-05-31T08:00:00Z",
        "outcome": 30236
    }
]
```

Query string parameters may be specified to filter requests and reorganize response data. Query parameters supported are:

| name        | type                              | optional | default            | description                                          |
|-------------|-----------------------------------|----------|--------------------|------------------------------------------------------|
| `sortBy`    | `insertion` or `reverseInsertion` | yes      | `reverseInsertion` | sort order (`reverseInsertion` is most recent first) |
| `page`      | `u32`                             | yes      | 0                  | page to start retrieval from (**page size is 100**)  |
| `assetPair` | `AssetPair` enum                  | yes      | BTCUSD             | asset pair                                           |

Example:

```sh
curl -X GET http://localhost:8080/v1/announcements?sortBy=insertion&page=1
```

### Get oracle event (announcement)

```sh
curl -X GET http://localhost:8080/v1/announcement/{rfc3339_time}
```

This endpoint returns an [oracle event object](#list-all-oracle-events-announcements) with maturation `rfc3339_time`. This path parameter is a `String` that is the RFC3339-encoded time of maturation (attestation) for the oracle event, e.g. `2022-05-31T08:00:00Z`. You can get this directly from the `maturation` field of the oracle event objects returned from listing announcements or make your own RFC3339-compliant string.

Output example:

```json
{
    "announcement": "fdd824fd02c12673b7bfb25156649cca9392fd141fb8522513aa55def9e7c52b7676a99f2425fad0000ee160c6d25912201bb63d29e9ed07c477d5e41a404ae410a2c4e00f28f48cc73e5c7f5314c2687420afce8f0aef392e5fdb347cf27aee16530dbbf055fdd822fd025b00127be0ae742cd646641f7c1bdf6f9e3866e5680cbbc726f71461702329d3661f473465e6ee5d334fccc9c2cb7a6d229196a97eb79838e9a22f4ea3d0bd09c0fbf7f0bda5cd0482e379bd421a3b06c31bf3e28aae8dd3fd62835883cafcbb1cf957c82f79edcc9c65764315bdb4960e401c8d46346d85a6c44088cd3e22d4c91baa3c1961efa57146e53693d6700753e3e9838ac0b2e4feeb9d5d1579041489d0dc0caed2c87b9cb61fbe8877b4ce877eb0e7cd4984c93c0b90502ebe1a00185e27c1a4de36b326660829959ac002256c08885b76c79d74bcb5d874f8c8c97b2b5c1bbcb1a5905f5038f856e88c526abd60f6e0cffb368ebe195d7d4b06747794cace7c9474b0b0b0d002aa9445c73801b109bbd1bd9c755cc49f06440b795fe2504014a6a967735c22774923d6317569d165c9cc13567fe43ef2210ac9cf2a44863016f1aa4e3bb0ba798e37c0fb966a0d4b4109c4098480b9b8bbd4521eb0231d6f5811a2c173a39863101f82fd30c0ff5da2333a944f51c76a8352b0c14ae22d659ee72ed221a6977625bcb4b47ae8534f476e8a4043ac460ea942d92a3e18f6ebd42b71609f8f504953d6b01dc1493ece93c44a0dd067b96bd7e3322b731a95dadfb0f2f60d31cdd0bb9eb8faf4a7b2334a4607cac109e93f2d28b82affabd60a75ba317d2ec79f72a569fd5d5441942129c257873e5d197ce789ef3f0b7e687b2d9488277d025ce327b8763f6bf3273f206dbd97f5b6a7bc60ac710b89c65c470f1d7223b36b9851b4d0f0d0827b2337102030d5eb2a87a9efbb8dc6b4287f62968e00fdd80a100002000642544355534400000000001200",
    "asset_pair": "BTCUSD",
    "attestation": "fdd868fd04c700f48cc73e5c7f5314c2687420afce8f0aef392e5fdb347cf27aee16530dbbf05500127be0ae742cd646641f7c1bdf6f9e3866e5680cbbc726f71461702329d3661f47681cca8c347a39737b84a0c53cc4b3f17582dad6b8b91aa2466384aaba148bdb3465e6ee5d334fccc9c2cb7a6d229196a97eb79838e9a22f4ea3d0bd09c0fbf7e8f0b206fd7d3869ed18beeb280d12942292076409ec41af87653ca17f29fbf6f0bda5cd0482e379bd421a3b06c31bf3e28aae8dd3fd62835883cafcbb1cf9578854cc682afd35ab7058cc527305d206b4a0b009765d6ecd552fee4cca94d9c1c82f79edcc9c65764315bdb4960e401c8d46346d85a6c44088cd3e22d4c91baadd439252fed5704e7122fbc8bc788b6abb107cc4273657f218bda9782b05248d3c1961efa57146e53693d6700753e3e9838ac0b2e4feeb9d5d1579041489d0dcbe9959454ec190f32f3f4d7b93236b58da1b68fb8a416f0d7a6c9a6589ccacfb0caed2c87b9cb61fbe8877b4ce877eb0e7cd4984c93c0b90502ebe1a00185e273403a81cb0ea30825c660424d6cdcf452d2e5f2f7696cbf258bf3395b4cf36dbc1a4de36b326660829959ac002256c08885b76c79d74bcb5d874f8c8c97b2b5c6e5f6851b4538ec1b56d2736dd9bf9aa60e2c242de498ab7cf2eb2a6fe3ac37c1bbcb1a5905f5038f856e88c526abd60f6e0cffb368ebe195d7d4b06747794cabc7aecd60c7c5390a91e6f72ca487e0cffa4056c3c1dbc3c2764824a1aac00b2ce7c9474b0b0b0d002aa9445c73801b109bbd1bd9c755cc49f06440b795fe25078ccb5ecdd6187240d7d882a0d3766970ec34a7e4c20bd41610f7b4e6855852a4014a6a967735c22774923d6317569d165c9cc13567fe43ef2210ac9cf2a44867ca2d62f83827a7621fdc9b58fd2e8698f557896d9acb9521147454eab058d8c3016f1aa4e3bb0ba798e37c0fb966a0d4b4109c4098480b9b8bbd4521eb0231d4c29c2bf89149c8744771d0be40a309c7ee92962cdcefaaa01bb5468f2e67e276f5811a2c173a39863101f82fd30c0ff5da2333a944f51c76a8352b0c14ae22d7b0c43c87bc54ae172dff30a747e03a8c5b6187eba61190a2f6c268a49f88876659ee72ed221a6977625bcb4b47ae8534f476e8a4043ac460ea942d92a3e18f6acaeae727b9441aafe84180d093702859cb152089bd4c78c9f07aebb42f65a62ebd42b71609f8f504953d6b01dc1493ece93c44a0dd067b96bd7e3322b731a95955771a3aa57b6b03a36b86bae213702bc984b888203db796dd201044e7df38cdadfb0f2f60d31cdd0bb9eb8faf4a7b2334a4607cac109e93f2d28b82affabd60baa3eada7e44a8353d461030e9e72d5048cb923c99073b6613b82a63246bde10a75ba317d2ec79f72a569fd5d5441942129c257873e5d197ce789ef3f0b7e689599242f998d5baf3d80fa5aa26550588aa12aa5d1d9b16dd0e9051abaa95dcc7b2d9488277d025ce327b8763f6bf3273f206dbd97f5b6a7bc60ac710b89c65cf691a0c954c4a3e62b0ec434cd218acfb9df6c51b466f5964024ad7eae183353470f1d7223b36b9851b4d0f0d0827b2337102030d5eb2a87a9efbb8dc6b4287f1bb83e2f185e4a1413f147c484681ef9b09125c2aa81329fd5c91cdd1cf5b71a013001300130013101310131013101310130013001300130013001300130013001310131",
    "maturation": "2022-05-31T08:00:00Z",
    "outcome": 30236
}
```

Query parameters supported are:

| name        | type                              | optional | default            | description                                          |
|-------------|-----------------------------------|----------|--------------------|------------------------------------------------------|
| `assetPair` | `AssetPair` enum                  | yes      | BTCUSD             | asset pair                                           |

Example:

```sh
curl -X GET http://localhost:8080/v1/announcement/2022-05-31T08:00:00Z?asset_pair=ETHUSD
```

### Get configuration

```sh
curl -X GET http://localhost:8080/v1/config
```

This endpoint returns the [oracle config](#configure).

Output example:

```json
{
    "announcement_offset": "7days 8h",
    "attestation_time": "08:00",
    "frequency": "1day"
}
```

## Run

To run, first clone the repository and build:

```sh
git clone https://github.com/lava-xyz/sibyls.git
cargo build --release
```

If you don't already have a key, generate one with [sibyls-keygen](https://github.com/lava-xyz/sibyls/tree/main/sibyls-keygen).

Then, you can run by executing:
```sh
./target/release/sibyls --key config/keystore
```

To specify a file to read asset pair configs from (more on this in [Asset Pairs](#asset-pairs)), execute:

```sh
./target/release/sibyls -a <FILE>
```

One is expected at `config/asset_pair.json` if not provided.

To specify a file to read oracle configs from (more on this in [Configure](#configure)), execute:

```sh
./target/release/sibyls -o <FILE>
```

One is expected at `config/oracle.json` if not provided.

For help, execute:

```sh
./target/release/sibyls -h
```

For optional logging, you can run the above commands with the `RUST_LOG` environment variable set (see [`env_logger`](https://docs.rs/env_logger/0.9.0/env_logger/) for more), for example:

```sh
RUST_LOG=INFO ./target/release/sibyls
```

Currently, the only logging done is at the `INFO` and `DEBUG` levels.

### Configure

Asset pair configs will be discussed in [Asset Pairs](#asset-pairs).

There are three configurable parameters for the oracle:

| name                  | type                                                                                                                                                                         | description                                                                                                           |
|-----------------------|------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|-----------------------------------------------------------------------------------------------------------------------|
| `attestation_time`    | `([0-1][0-9]\|2[0-3]):[0-5][0-9]`                                                                                                                                            | time of attestation, in 24-hour format                                                                                |
| `frequency`           | `(\d+(nsec\|ns\|usec\|us\|msec\|ms\|seconds\|second\|sec\|s\|minutes\|minute\|min\|m\|hours\|hour\|hr\|h\|days\|day\|d\|weeks\|week\|w\|months\|month\|M\|years\|year\|y))+` | frequency of attestation                                                                                              |
| `announcement_offset` | `(\d+(nsec\|ns\|usec\|us\|msec\|ms\|seconds\|second\|sec\|s\|minutes\|minute\|min\|m\|hours\|hour\|hr\|h\|days\|day\|d\|weeks\|week\|w\|months\|month\|M\|years\|year\|y))+` | offset from attestation for announcement, e.g. with an offset of `5h` announcements happen at `attestation_time - 5h` |
| `price_aggregation_type` | `(avg\|median)` | method for aggregating prices collected from pricefeeds |

The program defaults are located in `config/oracle.json`.

## Extend

This oracle implementation is extensible to using other pricefeeds, asset pairs, and [event descriptors](https://github.com/discreetlogcontracts/dlcspecs/blob/master/Oracle.md#event-descriptor) rather than just BTC price feeds and digit decomposition.

### Pricefeeds

Pricefeeds can be easily added as needed. In the future, they will have their own crate associated to their implementation, but for now they will reside here. To add a new pricefeed, say, Binance, you must implement the `oracle::pricefeeds::PriceFeed` trait. Note that you will have to implement `translate_asset_pair` for all possible variants of `AssetPair`, regardless of whether you use all of their announcements/attestations. Create `binance.rs` in the `src/oracle/pricefeeds` directory, implement it, and add the module `binance` in `src/oracle/mod.rs` and re-export it:

```rust
// snip
mod kraken;
mod binance; // <<

// snip
pub use kraken::Kraken;
pub use binance::Binance; // <<
```

Available `PriceFeedError` variants are in `src/oracle/pricefeeds/error.rs`. Then, add a line initializing it in `src/main.rs`:

```rust
// snip
// pricefeed retreival
info!("creating pricefeeds for {}", asset_pair);
let pricefeeds: Vec<Box<dyn PriceFeed + Send + Sync>> = vec![
    Box::new(Bitstamp {}),
    Box::new(GateIo {}),
    Box::new(Kraken {}),
    Box::new(Binance {}), // <<
];
// snip
```

After this, you are good to go!

### Asset Pairs

Asset pairs may also be added, although it is a bit more involved. To add a new asset pair, say, ETHUSD, you must first add an entry in `config/asset_pair.json`, or whatever file you are using for asset pair config. There, you will add an `AssetPairInfo` object to the outermost array. `AssetPairInfo`s contain the following fields:

| name               | type                                                                                                                      | description      |
|--------------------|---------------------------------------------------------------------------------------------------------------------------|------------------|
| `asset_pair`       | `AssetPair` enum                                                                                                          | asset pair       |
| `event_descriptor` | [`event_descriptor`](https://github.com/discreetlogcontracts/dlcspecs/blob/master/Oracle.md#event-descriptor) | event descriptor |

For now, the only `event_descriptor` supported is `digit_decomposition_event_descriptor` because that is the most immediate use case (for bitcoin). However, `enum_event_descriptor` will be added in the future. Furthermore, note that because of a quirk in the encodings of attestations due to inconsistencies between encoding libraries and [DLC spec](https://github.com/discreetlogcontracts/dlcspecs/blob/master/Messaging.md), currently `event_descriptor.base` must be 2 (binary) or else decoding will be incorrect. This will be changed in the future.

An example of a valid addition in `config/asset_pair.json` is the following:

```json
[
    {
        "asset_pair": "ETHUSD",
        "event_descriptor": {
            "base": 2,
            "is_signed": false,
            "unit": "ETHUSD",
            "precision": 0,
            "num_digits": 14
        }
    },
]
```

Then, you must add a variant to `AssetPair` in `src/oracle/common.rs`:

```rust
// snip
#[derive(Copy, Clone, Debug, Deserialize, Eq, Hash, PartialEq, Serialize)]
pub enum AssetPair {
    BTCUSD,
    ETHUSD, // <<
}
// snip
```

and finally add match arms to **every** pricefeed in their implementation of the trait method `translate_asset_pair`, for example:

```rust
// snip
impl PriceFeed for Kraken {
    fn translate_asset_pair(&self, asset_pair: AssetPair) -> &'static str {
        match asset_pair {
            AssetPair::BTCUSD => "XXBTZUSD",
            AssetPair::ETHUSD => "XETHZUSD", // <<
        }
    }

    //snip
}
```
# Persistence



Sibyls supports two backends for data persistence:

1. [Sled](https://sled.rs/) - A modern, high-performance embedded database that offers a simple and efficient way to store and manage data locally.

2. [PostgreSQL](https://www.postgresql.org/) - A powerful, open-source relational database system that provides robust features and scalability for more complex data storage needs.

These options allow Sibyls to be flexible and adaptable, catering to the diverse needs of its users.


### Sled

Sled is an embedded database that stores data on the local file system. 
The Sibyls database backend stores data in `events/{AssetPair}` (eg. `events/BTCUSD`). 
Sled is the default database, no additional configurations are needed to use it. 
The user can also enable it explicitly by using the command line argument: `--database_backend sled`.

### PostgreSQL

PostgreSQL is a full futured RDBMS, it can be used in enterprise settings. 
To use PostgreSQL as the database, the user will need to use the command line argument `--database_backend pg` and `--database_url postgres://user:password@database_host/database_name`.
The `DATABASE_URL` environment variable can also be used to set the database URL.

### Dual Database Backend

The dual database backend is useful for transitioning from Sled to PostgreSQL.
If data is stored in PostgreSQL, it reads from the PostgreSQL backend. 
If not, data is read from the Sled backend and added to the PostgreSQL backend.
To enable it, the user must include the `--database_backend dual` parameter 
and set the database URL as it is done for PostgreSQL.

## Run Sibyls

If you are running Sibyls, or want to run Sibyls and need help, please email us. You can find our contact info at lava.xyz. 

# TODO
The following todos are in decreasing priority.
## Key Handling
Additional functionality can be added to make working with the key easier. 
### Encryption at Rest
Encrypt the keystore on disk with a password. When Sibyls starts, require the password to decrypt the keystore. 
### Key Injection via POST
Create a POST endpoint to inject a key into a running instance of Sibyls. This allows for the scenario where the sysadmin is separate from the key owner. The sysadmin is responsible for setting up Sibyls and the key owner is responsible for maintaining the key and running the `curl` command when Sibyls is up and running.
## Additional Data Feeds
Currently, there are several data feeds supported out of the box. Additional feeds may be useful and added to `src/oracle/pricefeeds`.
## Separate Attestation Signing from Hosting
The current implementation hosts both attestation signing and hosting in the same instance. It may be more secure to have them separated so that the signing can occur on a more secure instance that has write access to the database. The hosting instance could be more open/public.
## Better Documentation, Testing, and Logging
Suggestions to documentation, testing, and logging are welcome.
