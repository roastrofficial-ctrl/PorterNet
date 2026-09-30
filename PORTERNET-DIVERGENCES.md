# PorterNet Divergence Register

Status: live Generation Zero register. Entries are recorded before resolution.

## D-006 — Package-bound possession representation

- Initial attribution: **SPECIFICATION AMBIGUITY**. `INTRODUCTIONS.md` binds
  HMAC-SHA256 to the canonical Package digest, but neither it,
  `SECURITY-CHECK.md`, nor `NATIVE-CARRIAGE.md` uniquely selects the message
  encoding or admission shape. Neither original implementation was uniquely
  required by the pre-amendment prose.
- Observed difference: Python sent a structured `vocabulary` / `package_digest`
  / `proof` object and HMACed unprefixed lowercase digest hex. Rust sent a base64
  proof string and HMACed `sha256:` plus hex. The original experiment stopped
  before AC, despite successful protected decoding.
- Normative resolution: [PACKAGE-POSSESSION-1](spec/PACKAGE-POSSESSION-1.md),
  linked from `../porter/INTRODUCTIONS.md`, fixes exact capability octets,
  SHA-256(C), lowercase unprefixed digest hex as HMAC input, HMAC-SHA256,
  lowercase hex proof with `hmac-sha256:` evidence prefix, the complete
  structured admission shape, and `PORTER-INTRODUCTION/1` vocabulary. Its
  [fixed vector](spec/vectors/package-possession-1.json) supplies C byte for byte.
- Final classification: **MULTIPLE**: specification ambiguity resolved normatively,
  followed by a Rust correction against that amendment.
- Final implementation attribution: **RUST DEFECT against the new amendment**.
  Rust's old representation and message are replaced by one normative binding
  in `src/possession.rs`, used by both standing and native node admission.
  Python's production proof implementation already conforms and is unchanged.
  Neither implementation accepts a compatibility fallback.
- Evidence: both independent verifiers pass the identical positive vector and
  11 negative cases in the original run; the Third Implementer run extends
  this to 13 cases before the lifecycle harness can attempt AC. Negative cases
  specifically retain the former Rust HMAC input and encoded-proof shape as
  rejected inputs. The receiver is then tested independently for pre-AC refusal.
- Python consultations: `porter/introduction.py::{canonical,proof,verify_proof,
  verify_encoded_proof}`, `porter/lodgement.py::lodge`, and
  `porter/native.py::{seal,open_frame,queue_package_custodian,receive}` at
  `3fa7166781944e3afa3eaba25a97cdffd07fa8a5`. These construct reference carriage
  and check the new normative vector; they are not the source of its authority.
- Status: **RESOLVED for possession given the specified canonical bytes**.
  D-001 now has a separate canonical binding; D-005 standing schemas remain open.
  Original lifecycle results are in `PORTERNET-GENERATION-ZERO-CHECK.md`.
  The Third Implementer amendment adds literal source JSON and local standing
  selection, without changing C, D, M or P. All four producer/verifier pairs pass.
- Historical consequence: old Rust proof strings/prefixed-message proofs are not
  admissible under the new binding. Existing AC facts are not revoked or
  recomputed. Migration is **not implemented**; fresh stores only. No fallback.

## D-001 — Canonical Package bytes

- Final classification: **MULTIPLE**. The previous specification was ambiguous;
  both implementations require corrections against the new binding.
- Initial classification: **SPECIFICATION AMBIGUITY**. Existing documents require
  canonical Package digests without uniquely fixing numbers, escaping or key
  ordering. Neither language's serializer defaults were normative.
- Additional reference inconsistency: Python possession used UTF-8 while
  `carriage.package_digest` used ASCII escaping. Non-ASCII Packages therefore
  had different possession and AC digests even within Python.
- Amendment: [CANONICAL-JSON-1](spec/CANONICAL-JSON-1.md) adopts RFC 8785 JCS,
  strict UTF-8 JSON parsing and an explicit binary64 numeric model. Duplicate
  decoded names, invalid Unicode, invalid JSON and non-finite numbers fail
  before admission. The whole Package contributes; no typed projection may be
  hashed in its place. Binary64 rounding and unchanged Unicode normalization
  forms are deliberate decisions, with fixed equivalence/distinction vectors.
- Attribution against that amendment: **PYTHON DEFECT** (different digest paths,
  default numeric formatting/order and permissive decoding) and **RUST DEFECT**
  (default numeric formatting/order and permissive mapping construction).
  Both use independently implemented JCS libraries with their own strict
  parsers; there is no peer-specific or alternate Package digest path.
- The Package binding must not rewrite local authority records. A trial global
  serializer change rounded Rust's `i64::MAX` rendezvous sentinel and failed six
  existing tests. Local record encoding and existing non-Package authority
  bindings were explicitly separated and preserved, not numerically rewritten.
  This is protocol scope separation, never a Package verification fallback.
- Reference consultation: Python `introduction.py`, `carriage.py`, `native.py`,
  and their imported authority serializers at base
  `9750b4ce019c2f7337420824794d3ecf48b20684`; Rust base
  `e43d876ca3ded19c89306053991768d7a49181fa`. RFC 8785 is the normative authority,
  not the observed implementations. The vector fixes 27 positive byte/digest/
  proof cases and 17 rejected raw inputs in the initial run. The next phase adds
  a 28th case for unknown fields, null and optional Package members.
- Status: **RESOLVED for the new Package canonical binding**; evidence recorded in
  `PORTERNET-CANONICAL-JSON-CHECK.md`. Migration of old histories and the full
  Package schema are separate unresolved questions. D-007 records a dependency
  defect found before expanded custody could run.
- Historical consequence: some former number, ordering and Unicode digest bytes
  differ from both old implementations. Old LG/AC/CL and unrelated authority
  records remain unchanged. Migration is **not implemented**; fresh stores only.
  No dual digest or legacy verification is present.

## D-002 — Canonical threshold durability is expressed semantically, not as an OS contract

- Classification: portability pressure.
- Rust first observation: atomic rename plus file and parent-directory sync is
  a strong POSIX implementation, but the normative material does not define
  behavior on filesystems lacking equivalent durability.
- PorterNet provisional behavior: write-new temporary, sync file, rename, sync
  parent; crash vectors test before/after visibility.
- Status: open documentation question, not currently a semantic disagreement.

## D-003 — Fact schemas are distributed across prose and Python records

- Classification: specification ambiguity.
- Rust first observation: LG/AC/CL meanings and thresholds are normative, but
  complete required/optional field schemas and integer domains are not collected
  in one versioned language-independent document.
- PorterNet provisional behavior: minimal fields observed in frozen examples and
  conformance; no Python-only diagnostics.
- Status: open; schema fixtures will distinguish normative fields from reference
  narration before interoperability claims. The current wire amendment closes
  complete-Package preservation and AC receipts, not the full grammar.
- Concrete remaining observation: Rust StandingStore compares `package.expires`
  directly with `at_ms`, although Package time is seconds and the local clock
  argument is milliseconds. The fixed logical-clock fixture does not exercise
  wall-clock expiry; this is an implementation defect to address in the next
  timestamp/schema pressure, not evidence of complete admission conformance.

## D-004 — Native protected-envelope byte binding requires extraction

- Classification: reference binding not yet independently specified.
- Rust first observation: frame header, algorithms, AAD concepts and limits are
  normative, but exact HKDF info/salt, nonce placement, key ordering and envelope
  JSON bytes must be extracted from compatibility evidence.
- Resolution evidence: the Generation Zero fixture now proves both directions:
  Python opens a Rust-sealed `PACKAGE`, and Rust opens a Python-sealed
  `CEREMONY_RESULT`, using the frozen header, metadata AAD, X25519/HKDF binding,
  nonce/ciphertext envelope and canonical JSON common subset.
- Status: resolved for the exercised JSON domain. D-001 remains open for the
  full canonical-JSON value space in that historical run. D-001 is now bound;
  CORRESPONDENCE-WIRE-1 makes the cryptographic construction explicit. Complete
  adversarial envelope grammar conformance remains part of the D-003 audit.

## D-005 — Introduction and standing fact schemas are not fully bound

- Classification: specification ambiguity.
- Rust first observation: admission ordering, standing history and custody
  continuity are explicit, but complete language-neutral IN/SC field names,
  protocol tags, integer domains and canonical secret-file binding are not.
- PorterNet provisional behavior: minimal immutable `Introduction`, `Terms` and
  predecessor-keyed `StandingChange` records implement the stated semantics;
  their serialized representation is not yet claimed interoperable.
- Status: open; compare language-neutral fixtures before promoting these Rust
  records or Python records into the PORTER/1 binding.

## D-007 — Nested non-finite floats become null in a JCS dependency

- Classification: RUST DEFECT against CANONICAL-JSON-1, including a dependency
  behavior exposed by the independent rejection gate.
- Observed: `serde_jcs` 0.2.0 rejects top-level NaN but serializes
  `vec![f64::INFINITY]` as `[null]`. `serde_json::to_value` also loses this
  distinction. This is not a permissible canonical equivalence.
- The canonical gate failed before any expanded AC experiment ran.
- Correction: capture typed values with `serde-value` 0.7.0, recursively reject
  non-finite values and non-string object names, then use JCS for encoding.
  No invalid value is repaired or mapped to null.
- Regression: direct and nested invalid values are tested in addition to raw
  hostile JSON vectors. Runtime network decoding rejects invalid tokens before
  this step. Status: **RESOLVED**; independent vectors and all 25 Rust tests pass.

## D-008 — AC evidence wire shape and validation

- Initial attribution: **SPECIFICATION AMBIGUITY**. Recipient responsibility and
  returned knowledge were defined, but no complete common wire shape selected
  Python's receipt or Rust's serialized local Acceptance.
- Observed: Rust sent a nested Package/local AC record; Python required a
  nine-member receipt naming the Package identity and canonical digest.
- Final classification: **MULTIPLE**. CORRESPONDENCE-WIRE-1 now selects the compact
  receipt independently of local fact storage. Rust construction and validation
  were defective against that amendment and are corrected. Python additionally
  accepted boolean/negative time and an empty AC suffix; those checks are fixed.
- Reason: the receipt conveys original AC identity/time and exact Package digest,
  without copying the opaque payload. It adds no custody or processing meaning.
- Fixed evidence: two positive receipts (including ignored unknown member), eleven
  single-property negatives; both production validators consume the same file.
  Both real directions durably retain independently carried AC evidence.
- Historical consequence: old nested Rust wire evidence is not accepted. Existing
  local AC records are untouched. No migration or legacy acceptance is added.
- Status: resolved for this receipt boundary; full envelope validation is still
  recorded separately in D-003 and the Third Implementer ledger.
