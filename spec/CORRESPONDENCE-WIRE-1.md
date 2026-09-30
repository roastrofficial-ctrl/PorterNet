# PORTER correspondence wire binding/1

Status: normative Generation Zero amendment, 2026-09-30.
This document binds the Package, admission and AC evidence boundaries used by the
round-trip experiment. Local filesystem layouts and fact storage are not wire
requirements. Read CANONICAL-JSON-1 and PACKAGE-POSSESSION-1 first.

## Package

A Package is a JSON object containing `protocol` = `PORTER/1`, `package` (a
stable nonempty `PKG-` identity), `from`, `to`, `kind`, `created`, `expires`, and
`payload`. `from`, `to` and `kind` are strings matching
`[a-z][a-z0-9.-]{0,127}`. `payload` is an opaque JSON object. `created` and
`expires` are integer Unix seconds, with expiry later than creation. The vector
uses times well within the exact binary64 integer domain. Safe-integer bounds
and full envelope grammar beyond the exercised values remain a schema audit
item, not an excuse to alter any signed Package.

All additional fields MUST survive canonicalisation, possession, carriage,
AC and CL unchanged as JSON values. They contribute to C and its digest.
Unknown fields do not create application policy or permission. A recipient may
refuse a Package under local policy before AC, but MUST NOT accept a projection
that removed fields. `in_reply_to`, when used by this experiment, names the
original Package identity as a string. It is correspondence association, not
processing status. A Return is a new full Package with its own identity and LG.

## PACKAGE native plaintext

```json
{"package": <complete Package object>, "admission": <PACKAGE-POSSESSION-1 object>}
```

No capability or local standing identity is transmitted in this object. The
recipient selects standing for the Package sender/recipient relationship.
Carriage authenticates Porters; Package addresses identify correspondents. The
fixture uses a one-to-one identity configuration. Identity mapping for general
multi-custodian operation is not established by that fixture.

## ACCEPTANCE_EVIDENCE native plaintext

The complete required receipt shape is:

```json
{
  "protocol":"PORTER/1",
  "kind":"RECEIPT",
  "package":"PKG-00000000000000000000000000000001",
  "state":"REMOTE_PORTER_DURABLY_ACCEPTED",
  "recipient":"recipient",
  "acceptance":"AC-00000000000000000000000000000001",
  "accepted_at_ms":1,
  "package_digest":"sha256:581ef853c3812e0d6ae100a72d72ed018bb1fea69e2a5ab5ae5948e904f8057a",
  "attests":"RECIPIENT_PORTER_ACCEPTED_RESPONSIBILITY"
}
```

The identity/digest here refer to the fixed possession vector; the AC identity
and time are literal example values, not values to use for new acceptances.
For a real AC, `acceptance` and `accepted_at_ms` MUST identify the original
immutable recipient AC. `package` is its Package identity string, not a nested
Package. `recipient` is the Package recipient. Time is integer Unix milliseconds.
The remaining literal tags are exact and case-sensitive. Unknown receipt
members have no authority and MUST be ignored; required values cannot be coerced
from other types. Boolean time is invalid. An AC identity needs at least one
character after `AC-`. Fixed receipt vectors are in
[vectors/acceptance-evidence-1.json](vectors/acceptance-evidence-1.json).

This is returned knowledge about AC. A local AC fact may contain more data;
sending the whole local fact is not a substitute for this wire shape. Generation
Zero adopts this compact evidence representation because it binds the exact
responsibility without duplicating the opaque payload. The former Rust local-AC
wire shape and Python receipt shape were not distinguished by the old prose.

Evidence is a separate protected Unit, never the response to Package send.
Before retaining it the origin MUST match authenticated peer, intended local
identity, Unit class, outstanding Package identity, expected recipient and
recomputed canonical digest. It MUST validate every required literal, a nonempty
`AC-` identity and nonnegative integer time. It MUST retain the validated receipt
durably before settling the outgoing Unit. Mere carriage success proves none of
this. Exact Package replay recovers the same original AC and regenerates its
receipt; no new acceptance is created.

## Native protected frame bytes

The frame is `"PRTR"` (ASCII 4 octets), version `0x01` (one octet), unsigned
32-bit big-endian protected-envelope byte length, then that many envelope bytes.
The envelope ceiling is 524288 bytes. No trailing frame bytes are permitted.
The envelope is CANONICAL-JSON-1 JSON with these required members:
`protocol`=`PORTER-CARRIAGE/1`, integer `version`=1, `unit`, `class`, `from`, `to`,
`nonce`, `ciphertext`. Unit identity is a stable nonempty `CU-` string. Class is
`PACKAGE`, `ACCEPTANCE_EVIDENCE`, `REFUSAL_EVIDENCE`, `CEREMONY`, or
`CEREMONY_RESULT`; this document binds only the first two plaintext shapes.

Let A be CANONICAL-JSON-1 bytes of the object with exactly `protocol`, `version`,
`unit`, `class`, `from`, `to` from the envelope. Nonce/ciphertext are not in A.
Retained local configuration maps authenticated peer identity to its raw 32-byte
X25519 public key. X25519 with local raw 32-byte private key and peer public key
produces the shared secret. HKDF-SHA256 uses no supplied salt (the standard
32-zero-octet salt), input key material = shared secret, info = ASCII
`PORTER-CARRIAGE/1` followed by one NUL octet followed by A, output length 32.
AES-256-GCM uses that key, a fresh 12-byte nonce, A as authenticated additional
data, and canonical plaintext bytes. `ciphertext` is ciphertext followed by the
16-byte authentication tag. `nonce` and `ciphertext` use standard RFC 4648 base64
with `+`, `/` and `=` padding, no whitespace. The envelope itself is strict JSON;
authentication and strict plaintext parsing precede admission.

The intended recipient and authenticated sender must match retained identity
configuration; Unit/class/identities cannot be replaced without invalidating
A. Key provisioning and secure Introduction capability delivery remain local
preconditions, not newly solved discovery protocols.

## Custody and silence

LG makes the exact Package recoverable at its origin. AC commits recipient
responsibility. Independent local attention validates a candidate against AC,
then publishes or recovers one CL before offering its complete Package through
PORTER-HOST-ADAPTER/1. No native receive path may invoke that local attention or
adapter. CL is custody, and adapter control return has no processing meaning.
A missing Return is only absence of Return LG.
