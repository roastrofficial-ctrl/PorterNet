# Canonical Package bytes: D-001

Status: normative binding and independent evidence established for the tested
Package domain. Checks completed 2026-09-30; specification work began 2026-09-29.

## Result

[CANONICAL-JSON-1](spec/CANONICAL-JSON-1.md) adopts RFC 8785 JCS and strict native
JSON decoding. The fixed suite contains stored bytes, SHA-256 digests, complete
Package bytes and possession evidence. Python and Rust independently pass it
through the same codecs used by production Package possession and AC.

The initial completed run covered 27 positive vectors, 17 invalid raw inputs,
27 Python LG → Rust AC/replay → independently invoked CL/adapter journeys,
27 reverse protected-frame/Python admission checks, and 18 authenticated hostile
native JSON inputs. All were successful. Rust formatting, strict Clippy and
25 tests passed. The affected Python suites passed 111 tests.

Raw evidence is retained in `evidence/canonical-json-1-interop.txt`,
`evidence/canonical-json-1-rust.txt`, and `evidence/canonical-json-1-python.txt`.
The Third Implementer phase extends these checks; its report records final
counts. Existing possession-vector evidence remains a historical record.

## Findings and attribution

D-001 is **MULTIPLE**: the earlier specification was ambiguous; both serializer
implementations differ from the newly selected rule. Python also used different
Unicode escaping for possession and AC digests. Both now use one Package digest.

D-007 is a **RUST DEFECT** involving a dependency: `serde_jcs` 0.2.0 converted
nested infinity into null. A typed-value validation pass now rejects it before
JCS encoding. This gate failure was observed before expanded custody ran.

A trial global serializer replacement rounded an internal Rust rendezvous
`i64::MAX` sentinel and broke six existing tests. Lossless local record storage
and pre-existing authority signatures were separated from Package canonical
encoding. They are never alternative Package verification paths.

One Python test sampled expiry terms twice across a wall-clock second. It now
reuses the same policy value when testing repeated establishment. Its initial
failure is retained in `evidence/canonical-json-1-python-initial.txt`.

## Compatibility and limits

The amendment explicitly adopts binary64 rounding, negative-zero equivalence,
UTF-16 property ordering and unchanged Unicode normalization forms. Consequently
some old digest/proof bytes change. No old fact was rehashed, no dual-digest
verification was introduced, and migration is not implemented. Fresh stores are
used throughout. Fixed logical Rust clock values are not an expiry-interoperation
claim. Protected frames are exchanged by the fixture; this is not TCP deployment
proof. Returned control does not establish application processing.

The Third Implementer phase now governs further work: complete the specification
ledger, prove timed silence, complete the Return, and record interruptions.
