# Generation Zero: the first independent correspondence boundary

Date: 2026-09-29. **The specified Python → Rust → local Host journey passes.**
Full Generation Zero conformance remains unestablished.

## Specification before implementation

The Introduction documents require HMAC-SHA256 possession over the canonical
Package digest. They did not uniquely determine the digest's representation
inside HMAC, the proof encoding, or the admission object. D-006 was a
**SPECIFICATION AMBIGUITY**, not evidence that Python behavior was normative.

[PACKAGE-POSSESSION-1](spec/PACKAGE-POSSESSION-1.md), linked from the reference
Introduction specification, now binds those bytes. The
[stored normative vector](spec/vectors/package-possession-1.json) specifies:

- exact Package identity and canonical UTF-8 Package bytes, also in hex;
- the 32 SHA-256 bytes in hex, and `sha256:<lowercase hex>` digest text;
- exact capability bytes, HMAC-SHA256, and the unprefixed 64 ASCII digest-hex
  bytes as HMAC input;
- exact resulting proof bytes, `hmac-sha256:<lowercase hex>` proof encoding,
  complete structured admission, and `PORTER-INTRODUCTION/1` vocabulary.

The choice separates digest value from its descriptive algorithm label and
makes all verification inputs explicit. It introduces no standing or custody
semantics. Rust's former prefixed HMAC input and base64 admission string are
**RUST DEFECTS against this amendment** and were replaced. Python's production
proof implementation already matches the selected representation and is
unchanged. Neither has a compatibility fallback.

The amendment fixes canonical bytes for this vector directly. It deliberately
does not claim to settle D-001 for arbitrary JSON values.

## Independent gate

Python uses its own `canonical`, `proof`, and `verify_proof` functions and
standard-library SHA-256/HMAC. Rust uses its own canonical serializer and the
`possession` module, backed by Rust SHA-256/HMAC crates. They consume the same
stored JSON file; neither translates the other's evidence or calls the other's
verifier. Both recompute the positive intermediate values and independently
verify the positive case and reject all 11 negative cases.

The negative cases each change one property: prefixed-digest HMAC input,
raw-digest HMAC input, base64 proof instead of an object, JSON string instead of
an object, vocabulary, digest label, one proof bit, proof hex case, one key byte,
Package identity, or payload. The two alternate HMAC inputs are supplied in
explicit hex. The fixture cannot attempt AC until both vector checks pass.

## Executed correspondence evidence

[Captured output and checks](evidence/package-possession-1.txt).
[Source and artifact hashes](evidence/package-possession-1-manifest.json).

| Threshold or boundary | Observed result |
|---|---|
| Python LG | Reference `lodge` publishes a recoverable LG containing the exact vector Package. |
| Protected carriage | Python seals the unchanged Package plus its generated admission; Rust authenticates and decrypts it. |
| Negative admission | All 11 negative cases also traverse the Rust node; each is refused with no AC or CL. |
| Rust possession and AC | Explicitly provisioned local standing is checked by the normal `StandingStore::admit` path; one canonical AC contains the exact Package and normative digest. |
| Receiver restart and replay | A new receiver process recovers byte-identical AC for the same Package. |
| Before Host attention | No CL or application directory exists. Arrival does not launch the attention or adapter executable. |
| Independent attention and CL | A separately invoked `host_attention` command validates canonical AC and durably publishes CL. |
| Stop before offer | That command exits after CL, before starting the adapter; CL and its Package remain recoverable. |
| Adapter death | An adapter exits before readiness; attention reports an operational error and leaves CL byte-identical. |
| Later adapter opportunity | A subsequent attention command recovers the same CL, exchanges readiness/offer/control through `PORTER-HOST-ADAPTER/1`, and the opaque application records the exact offered Collection. |
| Duplicate opportunity | A further attention invocation offers the same CL; the application tolerates it without any new custody fact. |

The Host fixture receives only a dispatch identity and Collection over local
stdio, plus a local observation path. It has no network listener, remote Porter
location, carriage identity, capability, or arrival callback. It runs only after
explicit Host attention. The runtime is generic: its adapter command is local
configuration, with no branch on fixture, Kind, or application meaning.

## What became true, and what remains unknown

- Before AC, origin LG exists and recipient has no custody.
- After AC and before CL, the Rust recipient is responsible; the Host remains
  absent from correspondence handling.
- After CL, Host custody is recoverable even if no adapter offer happened.
- Adapter control return is only a local control observation. Application
  observation is application-owned; no generic processing result is claimed.
- The origin's durable knowledge of AC is **not** established by this harness.
  Rust queues evidence, but Python receipt validation/retention is not exercised.
  The harness inspects recipient facts as test evidence.

## Scope and reproduction

This proves one fixed-byte Package across independently implemented possession,
protected carriage, recipient custody, and a private local application boundary.
It uses a deterministic fixture clock (AC at 1, CL at 2); it is not an expiry or
time-unit interoperability result. Standing is explicitly provisioned locally;
Introduction schema interchange is not claimed. The existing one-identity
fixture topology is retained.

Protected native frames move through subprocess arguments, not a live TCP
connection. The Compose service has `network_mode: none`, including the Host;
this establishes a non-networked laboratory Host, not a production sandbox
against a malicious same-privilege process. The post-CL stop is a deliberate
process exit, and adapter death is a real child exit; neither simulates power
loss or filesystem failure. Custody facts are inspected before temporary
storage is removed. No performance claims follow.

From `systems/PorterNet`:

```sh
PORTER_REFERENCE_CONTEXT=../porter docker compose build native-interop checks
docker compose run --rm native-interop
docker compose run --rm checks
```

The recorded run used the absolute local reference path, at commit
`3fa7166781944e3afa3eaba25a97cdffd07fa8a5`, with only `INTRODUCTIONS.md` amended.
Rust base was `049fd9750279b524c1f4178f6beb6436add3c440`, plus this experiment.
Builds may fetch dependencies; execution has networking disabled. Formatting,
strict Clippy, and all 24 Rust tests passed. The vector is also exercised by
`cargo test`; Python verification is a mandatory first step in native interop.
No benchmark, full reverse journey, general schema, or full canonical JSON
conformance claim is made.

## Conclusion and exactly one next experiment

**Yes: Generation Zero has crossed its first true independently implemented
correspondence boundary for the specified bytes.** Conformance to this possession
binding cannot accept either side of the original D-006 disagreement. Successful
decoding, AC, CL, and application opportunity are separately asserted.

Next experiment: define a language-neutral canonical Package encoding vector
set covering numeric and Unicode edge cases (D-001). The present result depends
on explicitly fixed canonical bytes; broadening that input domain without a
binding would let two otherwise conforming possession verifiers disagree again.
