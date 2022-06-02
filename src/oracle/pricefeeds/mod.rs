mod binanceus;
mod kraken;

trait PriceFeed {}

struct Kraken {}

impl PriceFeed for Kraken {}
