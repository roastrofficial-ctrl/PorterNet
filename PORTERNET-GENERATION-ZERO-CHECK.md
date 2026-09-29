# Generation Zero: Package boundary experiment

Date: 2026-09-29. Status: **BLOCKED before AC; Generation Zero not established.**

## Question and result

Can a Python-lodged opaque Package cross protected carriage into Rust AC, then
reach CL through later independent Host attention and the frozen adapter?

The experiment reaches authenticated Rust decoding, then exposes D-006:
Python's structured admission evidence cannot deserialize into Rust's string
field. Work stops at this disagreement under the initiating brief's stop rule.
No adapter or Collection step is substituted for the missing AC.

## Provenance

| Boundary | Contract | Consulted evidence |
|---|---|---|
| LG | Python reference `CONFORMANCE.md` | `porter/lodgement.py::lodge`, surviving LG containing exact Package |
| Protected carriage | `NATIVE-CARRIAGE.md` | Python `native.seal`, Rust `NativeFrame::open` |
| Possession and AC | `INTRODUCTIONS.md` | Python `introduction.proof`, Rust `node.rs::PackageCarriage` and `standing.rs` |
| Later CL and offer | `PORTER-HOST-RUNTIME-1.md`, `PORTER-HOST-ADAPTER-1.md` | Not reached |

Contract paths above refer to `../porter/`. Python implementation consultation
is recorded in D-006. Reference revision:
`3fa7166781944e3afa3eaba25a97cdffd07fa8a5`. Rust base revision:
`4a57d9f845f6070581a324a15793798ccdfa9842`, plus this experiment's changes.

## Interpretation

- Canonical truth: Python LG exists; Rust AC and CL do not.
- Responsibility: origin retains lodged correspondence; recipient has not
  accepted custody and Host custody has not crossed.
- Reconstruction: the surviving LG contains the exact Package for later
  carriage. The fixture verifies that content before attempting carriage.
- Unknown: compatible admission, returned AC evidence, later CL, adapter
  opportunity, and crash recovery across that full journey remain unproved.

The node probe deliberately has no standing configured. Its rejection alone
would be insufficient to diagnose the cause. The separate deserialization test
isolates the earlier object/string failure; the Python proof is also verified
with the Python verifier. This does not demonstrate successful Rust authority
checking. Hosts are never launched, so absence of Host activity here is not a
complete isolation proof.

## Executed checks

Docker execution on 2026-09-29 against the local reference revision above:

```text
Python ↔ Rust protected native carriage: PASS
D-006 reproduced: Python LG -> protected Rust decode -> pre-AC refusal
Lifecycle: BLOCKED; AC absent; CL absent; Host not started
```

`cargo fmt --all -- --check`, `cargo clippy --locked --all-targets -- -D warnings`,
and `cargo test --locked --all-targets` passed: 24 tests, zero failures.
`git diff --check` also passed. These results preserve the known incompatibility
as an explicit regression; they do not claim the requested lifecycle succeeded.

## Reproduction

From `systems/PorterNet`:

```sh
PORTER_REFERENCE_CONTEXT=../porter docker compose build native-interop checks
docker compose run --rm native-interop
docker compose run --rm checks
```

Both test services use `network_mode: none` at execution. Build may fetch
dependencies. An exit-zero negative regression means D-006 was reproduced;
the printed lifecycle result remains BLOCKED. Temporary custody facts are
removed after assertions. This is a boundary experiment, not a performance or
power-loss durability measurement.

## Exactly one next experiment

Bind one Package-bound possession test vector to the normative Introduction
requirements, including the JSON envelope, digest bytes, HMAC input, and proof
encoding. Have both implementations verify that same vector before attempting
the deferred AC → independent attention → CL → adapter journey. The observed
shape and HMAC-input differences make this the first blocking boundary.
