FROM rust:1.89-alpine AS rust-build
RUN apk add --no-cache musl-dev
WORKDIR /src
COPY PorterNet/Cargo.toml PorterNet/Cargo.lock ./
COPY PorterNet/src ./src
RUN cargo build --locked --release --bin native_fixture

FROM python:3.12-alpine
WORKDIR /porter
COPY porter/pyproject.toml ./
COPY porter/porter ./porter
RUN pip install --no-cache-dir .
COPY --from=rust-build /src/target/release/native_fixture /usr/local/bin/native_fixture
COPY PorterNet/fixtures/python-native-interop.py /interop.py
ENTRYPOINT ["python", "/interop.py"]
