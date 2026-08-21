FROM rust:1.89-alpine AS rust-build
RUN apk add --no-cache musl-dev
WORKDIR /src
COPY Cargo.toml Cargo.lock ./
COPY src ./src
RUN cargo build --locked --release --bin native_fixture

FROM python:3.12-alpine
WORKDIR /porter
COPY --from=porter_reference pyproject.toml ./
COPY --from=porter_reference porter ./porter
RUN pip install --no-cache-dir .
COPY --from=rust-build /src/target/release/native_fixture /usr/local/bin/native_fixture
COPY fixtures/python-native-interop.py /interop.py
ENTRYPOINT ["python", "/interop.py"]
