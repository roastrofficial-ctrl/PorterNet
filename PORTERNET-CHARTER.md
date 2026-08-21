# PorterNet Implementation Charter

Status: Generation Zero implementation boundary, 2026-08-21.

## Purpose

PorterNet is an independent implementation experiment for the frozen PORTER
architecture. Its success criterion is behavioural convergence and native
interoperability with the Python reference—not source-level resemblance,
benchmark victory, or feature count.

PorterNet will be built primarily from normative specifications, invariants and
implementation-independent conformance vectors. The Python implementation is
consulted only where a wire representation, canonical encoding, or executable
reference behaviour must be identified. Every such dependency is recorded.

Generation Zero succeeds only if this statement can be defended:

> PORTER is no longer merely the behaviour of its Python laboratory
> implementation. An independently constructed PorterNet preserves its
> correspondence, custody, identity, security, isolation, attention and
> application boundaries.

## Physical boundary

```text
NETWORK
   │
   ▼
PORTER
   │ private local Host boundary
   ▼
HOST
```

The Porter owns network participation, native carriage, admission and durable
responsibility until CL. The Host need not have network identity or connectivity
and cannot be invoked, awakened or notified by arrival. Only Host-local policy
chooses inspection and Collection. PorterNet never infers application meaning.

## Source classification

### Normative

- `CONFORMANCE.md`: frozen PORTER/1 identity, evidence, custody, isolation,
  carriage and observation statements.
- `INTRODUCTIONS.md`: recipient-local standing, admission ordering, exact
  replay, possession proof and relationship custody allowance.
- `STANDING-SUCCESSION.md`: immutable IN/SC history, unique predecessor slot,
  historical replay and continuous relationship budgets.
- `CEREMONIES.md`: distinct bounded ceremonial authority, CM/SC thresholds,
  replay, ordering and absence of Host custody.
- `NATIVE-CARRIAGE.md`: bounded frame, mutually authenticated protected Units,
  asynchronous evidence and stable Porter identity.
- `RENDEZVOUS-CONTINUITY.md`: immutable signed RV chain, predecessor ordering,
  conflict suspension, expiry and identity/location separation.
- `PORTER-HOST-RUNTIME-1.md` and `PORTER-HOST-ADAPTER-1.md`: frozen local
  attention and application boundary.
- `HOST-RUNTIME-CONFORMANCE.md`: implementation-independent Runtime vectors.
- Normative assertions embedded in the security/native/continuity checks where
  they clarify a frozen hostile or crash observation.

### Reference behaviour

- Python module boundaries, class names and call graphs.
- UUID generation choices where identity is specified only as stable and unique.
- Filesystem directory names, JSON formatting, SQLite projections and lock-file
  placement except where a compatibility fixture explicitly consumes them.
- Python exception types, process lifecycle details and diagnostic narration.
- The current canonical-JSON routine and exact native-envelope JSON shape until
  promoted into an explicit cross-implementation binding.
- The current HMAC capability, AES-GCM/HKDF/X25519 library composition and key
  serialization as specified scaffolding/binding, not bespoke architecture.

### Operational policy

- Batch sizes, candidate ordering and polling intervals.
- Serial, fixed and elastic opportunity capacity.
- Evidence windows, shedding intervals and acquisition retry cooldowns.
- Adapter process lifetime and supervision strategy.
- Disposable candidate projections, recovery frontiers and audit acceleration.
- Flat filesystem layout, fsync implementation and telemetry.
- Native retry cadence, connection reuse and concurrency limits beyond normative
  boundedness.

### Butterfly-specific integration

- Find Me, HarmonicDB, HDBE and Technical Passport adapters.
- MailWeb/Postbox, MailTube and journey-specific Kinds/payloads.
- Butterfly Compose topology, Docker DNS names, ports and volume paths.
- PHP/Laravel wiring, application tickets and Stack Inspector presentation.

Categories two through four are not PORTER semantics and must not silently enter
PorterNet's public core API.

## Generation Zero responsibilities

Implementation structure will follow responsibilities rather than Python files:

- canonical correspondence and evidence records;
- crash-safe publication and exact-identity replay;
- recipient admission and recoverable custody transfer;
- Porter identity and protected native Units;
- Introduction, standing succession and ceremony;
- rendezvous continuity knowledge;
- private Host boundary and locally chosen Runtime attention;
- adapter supervision without disposition;
- disposable inspection/recovery projections.

Names may change when Rust ownership boundaries expose a better decomposition.
No module is required to correspond to a Python module.

## Hard prohibitions

PorterNet must not introduce:

- a Host HTTP listener, callback, push path or arrival-triggered wake mechanism;
- a generic job queue or durable pending/running/worker state;
- application `RUNNING`, `PROCESSING`, `SUCCEEDED`, `FAILED`, `COMPLETED` or
  `RETRYABLE` claims;
- synchronous transport completion masquerading as returned AC/ceremony
  knowledge;
- Kind-to-handler routing in the Porter or Runtime;
- live identity/discovery dependencies for ordinary admitted correspondence;
- Package identity mutation across retry, movement or recovery;
- Butterfly application branches in the core.

## Rust discipline

- Stable Rust, formatted with `rustfmt`, warning-clean under `clippy` where the
  toolchain is available.
- `unsafe` is forbidden in Generation Zero (`#![forbid(unsafe_code)]`).
- Bounded parsing and allocation precede hostile input decoding.
- Cryptography comes from reviewed crates; no custom primitive.
- Canonical thresholds use explicit durable publication helpers and crash-point
  tests.
- Public types distinguish canonical facts, disposable observations and
  operational policy.
- Errors describe boundary failures without inventing application semantics.
- Dependencies remain small and justified in the Generation Zero check.

No open-source licence is assumed by implementation. A licence must be chosen
explicitly by the project owner before public distribution.

## Local Host mechanisms

The architecture requires a private, Host-local boundary; it does not mandate
one OS mechanism. Generation Zero will document and test subprocess stdio and a
filesystem mail slot. Unix sockets, inherited descriptors, separate users,
sandbox profiles, namespaces and containers remain deployment mechanisms to
evaluate without weakening the invariant. A Unix socket is local IPC only when
permissions and namespace prevent network-style remote participation.

## Conformance strategy

1. Express normative vectors independently in Rust.
2. Reuse language-neutral fixtures only when their bytes are part of an explicit
   binding.
3. Maintain a divergence register from the first disagreement onward.
4. Classify each divergence as PorterNet defect, accidental Python behaviour,
   specification ambiguity or non-portable supposedly frozen concept.
5. Prefer cross-implementation protected carriage in both directions over two
   isolated green suites.

At minimum Generation Zero must pressure every vector named in the initiating
brief, including LG/AC/CL crash thresholds, exact replay, standing/ceremony,
native hostile frames, rendezvous movement/conflict, dormant Hosts, Runtime and
adapter crashes, and absence of durable scheduler/application claims.

## Fixtures

The first fixture records an application-owned observation and optionally lodges
an opaque Return. The second must be implemented differently enough to expose
accidental coupling—for example, a shell/stdin transformer beside a native Rust
fixture. PorterNet core may know neither fixture's purpose.

## Generation Zero exclusions

No relay service, control plane, accounts, dashboard, Kubernetes operator,
registry, automatic public discovery, elaborate CLI, product integration or
MailTube. Minimal operation and inspection commands are allowed only to run and
verify the substrate.

## Deliverables and stop rule

Generation Zero produces the charter, independent Rust implementation,
conformance runner, two Host fixtures, interoperability evidence where feasible,
divergence register, baseline measurements and
`PORTERNET-GENERATION-ZERO-CHECK.md`.

Correctness precedes optimization. A divergence is reported before it is fixed.
If independent convergence cannot yet be defended, the check must say precisely
which architectural statement remains Python-dependent and end with exactly one
experiment justified by that strongest pressure.
