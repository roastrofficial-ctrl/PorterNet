FROM rust:1.89-alpine AS rust-build
RUN apk add --no-cache musl-dev
WORKDIR /src
COPY Cargo.toml Cargo.lock ./
COPY src ./src
RUN cargo build --locked --release --bin native_fixture --bin host_attention --bin canonical_fixture

FROM python:3.12-alpine
WORKDIR /porter
COPY --from=porter_reference pyproject.toml ./
COPY --from=porter_reference porter ./porter
RUN pip install --no-cache-dir .
COPY --from=rust-build /src/target/release/native_fixture /usr/local/bin/native_fixture
COPY --from=rust-build /src/target/release/host_attention /usr/local/bin/host_attention
COPY --from=rust-build /src/target/release/canonical_fixture /usr/local/bin/canonical_fixture
COPY spec /spec
COPY fixtures/verify-canonical.py /verify-canonical.py
COPY fixtures/canonical-interop.py /canonical-interop.py
COPY fixtures/verify-receipt.py /verify-receipt.py
COPY fixtures/verify-possession.py /verify-possession.py
COPY fixtures/opaque-adapter.py /opaque-adapter.py
COPY fixtures/roundtrip.py /roundtrip.py
COPY fixtures/roundtrip-worker.py /roundtrip-worker.py
COPY fixtures/return-adapter.py /return-adapter.py
COPY fixtures/python-native-interop.py /interop.py
ENTRYPOINT ["python", "/interop.py"]
