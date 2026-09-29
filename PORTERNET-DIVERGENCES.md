# PorterNet Divergence Register

Status: live Generation Zero register. Entries are recorded before resolution.

## D-006 — Protected Package decoding does not imply admission interoperability

- Classification: SPECIFICATION AMBIGUITY; incompatible reference bindings
  confirmed, final defect attribution pending specification review.
- Python consultation: `porter/native.py` (`queue_package_custodian`, `receive`),
  `porter/introduction.py` (`proof`, `verify_encoded_proof`), and
  `porter/lodgement.py` (`lodge`) in reference commit
  `3fa7166781944e3afa3eaba25a97cdffd07fa8a5`.
- Python carries `admission` as an object containing `vocabulary`,
  `package_digest`, and `proof`. Rust `node.rs::PackageCarriage` requires a
  string holding base64 proof bytes. The authenticated Python payload therefore
  fails Rust deserialization before standing lookup and before AC.
- A second difference exists behind that failure: Python HMACs the unprefixed
  hexadecimal SHA-256 digest; Rust `standing.rs` HMACs `sha256:` plus that digest.
  Changing only the JSON shape cannot establish interoperability.
- Evidence: `fixtures/python-native-interop.py` now lodges a real Python Package,
  constructs reference possession evidence, seals it, proves Rust can decrypt
  the unchanged payload, and sends the frame to `PorterNode::receive`. The
  regression expects refusal and absence of AC/CL. A focused Rust test isolates
  the object/string parse mismatch from missing relationship configuration.
- Status: OPEN. No schema translation, admission bypass, or semantic fix applied.
  The existing D-004 envelope result remains valid within its stated scope;
  it does not establish Package admission or the correspondence lifecycle.

## D-001 — Canonical JSON is architecturally required but incompletely bound

- Classification: specification ambiguity / reference binding.
- Rust first observation: Package identity, proof and replay require identical
  canonical bytes, while the frozen prose does not fully specify Unicode,
  numeric and escaping rules.
- Python reference: recursively sorted keys with compact `json.dumps` output.
- PorterNet provisional behavior: recursively sorted UTF-8 compact JSON through
  `serde_json`; interoperability fixtures must prove the common subset.
- Resolution required: publish an explicit `PORTER-CANONICAL-JSON/1` binding or
  replace representation-dependent identity with a specified canonical format.
- Status: open; must be resolved before cross-language identity conformance can
  be claimed generally.

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
  narration before interoperability claims.

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
  full canonical-JSON value space and therefore still bounds general claims.

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
