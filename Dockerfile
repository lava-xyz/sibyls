FROM rust:latest

WORKDIR /usr/src/sibyls

COPY . .

RUN cargo build --release

ENTRYPOINT ["./target/release/sibyls"]

CMD ["--help"]
