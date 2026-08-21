FROM rust:1.89-slim-bookworm AS build
WORKDIR /src
COPY Cargo.toml Cargo.lock ./
COPY src ./src
RUN cargo fetch --locked
RUN rustup component add rustfmt clippy
RUN cargo build --locked --release --bins

FROM build AS checks
COPY . .
CMD ["sh", "-c", "cargo fmt --all -- --check && cargo clippy --locked --all-targets -- -D warnings && cargo test --locked --all-targets"]

FROM debian:bookworm-slim AS host
COPY --from=build /src/target/release/opaque_host /usr/local/bin/opaque-host
COPY fixtures/shell-host.sh /usr/local/bin/shell-host
USER 65532:65532
ENTRYPOINT ["/usr/local/bin/opaque-host"]
