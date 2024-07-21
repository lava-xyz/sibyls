CREATE TABLE events (
    maturation TIMESTAMPTZ NOT NULL,
    asset_pair VARCHAR NOT NULL,
    announcement TEXT NOT NULL,
    outstanding_sk_nonces TEXT,
    attestation TEXT,
    price BIGINT,
    PRIMARY KEY (maturation, asset_pair)
)
