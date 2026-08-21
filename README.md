# PorterNet

PorterNet is an independent Generation Zero implementation experiment for the
frozen PORTER architecture. It is not a Rust translation of the Python
laboratory.

Read [`PORTERNET-CHARTER.md`](PORTERNET-CHARTER.md) before implementation or
review. The project is not yet licensed for public distribution.

## Isolated checks and Host fixtures

The pinned Compose laboratory gives checks and Host fixtures no network:

```sh
docker compose run --rm checks
docker compose run --rm rust-host /exchange/package.json /exchange/rust-observation.json
docker compose run --rm shell-host /exchange/package.json /exchange/shell-observation.json
docker compose run --rm native-interop
```

The two fixtures are deliberately unlike one another. Neither owns a listener
or receives an arrival signal: starting either command is explicit Host
attention. Its output is application-owned observation, not PORTER disposition.

`native-interop` independently exercises protected carriage in both directions:
Python opens a Rust `PACKAGE` frame and Rust opens a Python `CEREMONY_RESULT`
frame. The reference source is an explicit pinned external build context, never
a sibling runtime dependency. To test a local reference checkout instead, use:

```sh
PORTER_REFERENCE_CONTEXT=/absolute/path/to/python-porter \
  docker compose run --rm --build native-interop
```

The service has no network while the fixture runs.
