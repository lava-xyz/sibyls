// @generated automatically by Diesel CLI.

diesel::table! {
    events (maturation, asset_pair) {
        maturation -> Timestamptz,
        asset_pair -> Varchar,
        announcement -> Text,
        outstanding_sk_nonces -> Nullable<Text>,
        attestation -> Nullable<Text>,
        price -> Nullable<Int8>,
    }
}
