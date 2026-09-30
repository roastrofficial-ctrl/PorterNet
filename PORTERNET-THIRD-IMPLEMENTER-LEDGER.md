# Third Implementer ledger

Date: 2026-09-30. Scope: canonical complete Package → possession → native carriage
→ AC evidence → independent CL → opaque Return. Source was consulted to locate
production paths and expose disagreements, never to give either language authority.

“Yes now” is limited to the stated boundary. It does not close the whole protocol.
The normative reading set is [CANONICAL-JSON-1](spec/CANONICAL-JSON-1.md),
[PACKAGE-POSSESSION-1](spec/PACKAGE-POSSESSION-1.md),
[CORRESPONDENCE-WIRE-1](spec/CORRESPONDENCE-WIRE-1.md), their stored vectors,
[custody conformance](../porter/CONFORMANCE.md),
[Host Runtime](../porter/PORTER-HOST-RUNTIME-1.md) and
[adapter contract](../porter/PORTER-HOST-ADAPTER-1.md).

## 1. What are canonical Package bytes?

- **Normative documents sufficient before?** No: numeric model, Unicode order,
  duplicate names and escaping were unbound.
- **Python consulted?** Yes: `canonical.py`, `introduction.py`, `carriage.py`,
  `native.py` to trace actual possession, AC and strict ingress paths. Python
  previously had inconsistent Unicode digest paths.
- **Rust consulted?** Yes: `canonical.rs`, `native.rs`, `node.rs`, `model.rs` to
  trace parse → typed model → digest and discover nested nonfinite conversion.
- **Specification change required?** CANONICAL-JSON-1 adopts RFC 8785 with explicit
  binary64 input and rejection rules. All Package fields contribute.
- **Can a third implementer now proceed without source?** Yes for C and D. Stored
  vectors include 28 positive Package answers and 17 invalid raw texts. These are
  examples of the complete rule, not a whitelist of supported values.

## 2. What exact possession evidence is constructed and verified?

- **Normative documents sufficient before?** No: representation was unspecified.
- **Python consulted?** Yes: `introduction.py::proof/verify_proof` to observe the
  original object, hex digest message and production call path.
- **Rust consulted?** Yes: `possession.rs`, `standing.rs` and the original encoded
  proof path to observe the prefixed message and string disagreement.
- **Specification change required?** PACKAGE-POSSESSION-1 fixes C, SHA-256 D,
  exact K, ASCII lowercase digest hex M, HMAC-SHA256, proof hex/prefix and full
  admission object. Literal source, intermediate bytes and local standing label
  are stored. Unknown members are ignored; duplicate decoded names are invalid.
- **Can a third implementer now proceed without source?** Yes given locally
  provisioned standing. Both producers match the stored answer, then each of the
  two verifiers independently consumes both outputs without translation.

## 3. Which Introduction selects the capability?

- **Normative documents sufficient before?** Semantics yes; portable record
  schema no. Proof cannot establish its own standing or select another key.
- **Python consulted?** Yes: Admission provisioning and refresh for fixture setup.
- **Rust consulted?** Yes: StandingStore establishment, succession and replay order.
- **Specification change required?** Explicit local selection in
  PACKAGE-POSSESSION-1: fixture IN identity is a local provisioning label, absent
  from admission and HMAC. Relationship/current standing/terms select K.
- **Can a third implementer now proceed without source?** Yes for possession
  given K and standing. No for exchanging IN/SC histories; D-005 remains open.

## 4. May a typed implementation discard unfamiliar Package fields?

- **Normative documents sufficient before?** Complete-Package identity says no;
  earlier examples did not exercise unknown envelope members.
- **Python consulted?** Yes: envelope validation and retained AC Package.
- **Rust consulted?** Yes: serde Package model and raw-versus-typed digest guard.
- **Specification change required?** CORRESPONDENCE-WIRE-1 states preservation
  explicitly. No new application meaning: unknown values contribute to C and
  survive custody. Rust now retains flattened extension members, including null.
- **Can a third implementer now proceed without source?** Yes for preservation.
  Full field domains and validation grammar remain the distinct D-003 audit.
  That audit already has a concrete finding: Rust standing compares Package
  expiry seconds directly against its millisecond clock argument. Fixed logical
  clocks avoid this case; no wall-clock expiry agreement is claimed here.

## 5. Is AC evidence the recipient's local storage record?

- **Normative documents sufficient before?** No. A receipt and a nested local AC
  both expressed responsibility, but the old prose did not select a wire shape.
- **Python consulted?** Yes: `carriage.acceptance_evidence`, native receipt
  validation/retention and origin carriage knowledge.
- **Rust consulted?** Yes: Node queueing, UnitSpool validation/retention/recovery.
- **Specification change required?** CORRESPONDENCE-WIRE-1 binds the nine-member
  receipt, original AC identity/time, peer/subject/digest matching and retention
  before settlement. Fixed vectors include malformed type/tag/subject examples.
- **Can a third implementer now proceed without source?** Yes for this receipt
  boundary. Rust's local AC file is no longer its wire representation. Neither
  implementation accepts the old nested AC as a compatibility alternative.

## 6. What bytes protect the native Unit?

- **Normative documents sufficient before?** No for exact HKDF info/salt and
  encrypted-envelope placement; D-004 recorded the gap.
- **Python consulted?** Yes: native seal/open and queue/receive call boundaries.
- **Rust consulted?** Yes: NativeFrame metadata, frame parser and key derivation.
- **Specification change required?** CORRESPONDENCE-WIRE-1 records header, AAD,
  X25519/HKDF inputs, AES-GCM nonce/tag layout and base64 construction explicitly.
- **Can a third implementer now proceed without source?** Yes to construct and
  open the exercised Package/receipt frames. No claim of complete adversarial
  envelope grammar conformance: identity alphabets, integer domains and all
  rejection limits need a separate schema audit. Other Unit plaintext classes
  are not specified by this amendment. No key discovery claim is made.

## 7. What crosses LG, AC and CL, and what does silence mean?

- **Normative documents sufficient before?** Yes for custody meanings and
  independent attention. No for a universal filesystem durability contract.
- **Python consulted?** Yes: lodgement/custody recovery and HostRuntime adapter
  APIs to drive actual thresholds, not fixture-made facts.
- **Rust consulted?** Yes: PorterStore crash points and Host attention entry point.
- **Specification change required?** No new state. Wire amendment restates that
  protected receipt is knowledge, AC is responsibility and CL precedes offer.
- **Can a third implementer now proceed without source?** Yes for these semantics.
  D-002 still limits claims about power loss and filesystem portability. This
  experiment tests separate process exits and replay, not arbitrary storage loss.

## 8. Does returned adapter control mean processed? How does Return travel?

- **Normative documents sufficient before?** Yes: frozen adapter JSON-lines
  contract and new Package/LG semantics. Returned control has no processing claim.
- **Python consulted?** Yes: Adapter and HostRuntime invocation for the reverse CL.
- **Rust consulted?** Yes: existing host_attention and local lodge entry point.
- **Specification change required?** None beyond preserving complete Package
  fields and separating the receipt. The application chooses opaque Return LG
  and deterministic Return identity. Runtime invents no result state.
- **Can a third implementer now proceed without source?** Yes for this custody
  journey. The fixture's idempotence is application policy, not a PORTER promise.

## 9. What happens to historical facts?

- **Normative documents sufficient before?** No migration rule for these new bindings.
- **Python consulted?** Yes: authority serializers to avoid changing unrelated
  signed records while replacing Package canonicalisation.
- **Rust consulted?** Yes: record encoders and persisted sentinel values.
- **Specification change required?** Fresh stores for this experiment; no rehash,
  dual verification or legacy fallback. Old facts retain their original bytes.
- **Can a third implementer now proceed without source?** Yes for fresh-store
  conformance. No for migration; it remains deliberately unimplemented.
