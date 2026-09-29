# PorterNet Source Inventory

The controlling classification is in `PORTERNET-CHARTER.md`. This index records
where Generation Zero obtains evidence without promoting reference choices.

| Area | Normative sources | Executable reference vectors |
|---|---|---|
| LG/AC/CL, replay, isolation | `CONFORMANCE.md` | generation 1–6, history, custody tests |
| Canonical Package bytes | `spec/CANONICAL-JSON-1.md`, RFC 8785 | `spec/vectors/canonical-json-1.json`; independent codecs and native custody journeys |
| Package-bound possession bytes | `spec/PACKAGE-POSSESSION-1.md` (normative amendment) | `spec/vectors/package-possession-1.json`; independent Python and Rust verifiers |
| Introduction/admission | `INTRODUCTIONS.md`, `SECURITY-CHECK.md` normative assertions | introduction and renewal tests |
| Succession | `STANDING-SUCCESSION.md` | renewal tests |
| Ceremony | `CEREMONIES.md` | ceremony tests |
| Native carriage | `NATIVE-CARRIAGE.md` | native hostile-frame tests |
| Rendezvous | `RENDEZVOUS-CONTINUITY.md` | rendezvous tests |
| Host boundary | frozen Runtime and Adapter contracts | host-runtime conformance vectors |

Python source is consulted after these documents only to extract a missing byte
binding or construct cross-implementation fixtures. Every such consultation
creates or updates a divergence-register entry.
