# PORTER Package-bound possession/1

Status: normative binding amendment, 2026-09-29. Vocabulary: `PORTER-INTRODUCTION/1`.
Normative vector: [package-possession-1.json](vectors/package-possession-1.json).

## Authority and scope

`../../porter/INTRODUCTIONS.md` requires HMAC-SHA256 possession covering the
canonical Package digest before new AC. Its admission ordering and
`../../porter/SECURITY-CHECK.md` do not specify the HMAC message representation,
key encoding, admission shape, or proof encoding. `NATIVE-CARRIAGE.md` binds
protected transport, not those missing bytes. Neither existing implementation
was uniquely selected by those documents. D-006 was a SPECIFICATION AMBIGUITY.

This amendment binds possession given canonical Package octets C. The vector
supplies C in full as UTF-8 text and hexadecimal bytes, with no BOM or trailing
LF. Its object keys are recursively sorted, separators are comma and colon
without whitespace, and its only numbers are decimal integers. The complete
Package, including its identity, participates. No envelope field is removed.
The vector's C is authoritative; regenerating expected outputs at test time is
not conformance evidence. The subsequent [CANONICAL-JSON-1 amendment](CANONICAL-JSON-1.md) binds the
numeric and Unicode rules beyond this original vector. Its original positive bytes remain
unchanged and must still pass; later metadata and negative cases extend it.

## Required bytes and representation

1. K is the capability's exact octet sequence. It MUST NOT be trimmed, hashed,
   normalized, or implicitly base64-decoded. A local string capability is UTF-8
   encoded exactly once. This vector carries K in hex for unambiguous provision;
   that hex is not itself the key and is not sent in admission.
2. D = SHA-256(C), exactly 32 bytes.
3. H = lowercase hexadecimal encoding of D, exactly 64 ASCII bytes, no LF.
4. M = H. In particular M is neither raw D nor `sha256:` concatenated with H.
5. P = HMAC-SHA256(K, M), exactly 32 bytes, without truncation.
6. Admission MUST be a JSON object with these required string members:

   ```json
   {"vocabulary":"PORTER-INTRODUCTION/1","package_digest":"sha256:<H>","proof":"hmac-sha256:<lowercase hex P>"}
   ```

   The angle-bracket substitutions above are explanatory, not literal bytes.
   The vector supplies the complete object. `sha256:` and `hmac-sha256:` are
   case-sensitive descriptive prefixes in evidence, not bytes signed by HMAC.
   No whitespace, padding, uppercase hex, or alternative proof encoding is
   permitted inside these values. Object order and inter-token JSON whitespace
   are immaterial. Unknown members have no authority and are ignored; duplicate
   member names MUST be rejected by CANONICAL-JSON-1 decoding.
7. Verification MUST check the vocabulary, recompute D from the exact Package,
   compare the complete digest representation, and verify P using K and M with
   constant-time cryptographic comparison. A base64 string containing P is NOT
   admission, even if P is valid. A string containing serialized admission is
   NOT admission. No alternate representation or legacy verification fallback
   is allowed.

## Why this choice

H is a fixed-length, encoding-independent ASCII message that can be recorded
and audited byte for byte. Keeping descriptive algorithm prefixes outside M
separates the digest value from its display label. A structured object keeps
version, claimed digest and proof distinct and makes verification explicit.
These are representation choices; the prior prose did not favor them over
other injective encodings. Python happens to implement this choice already.
That fact is evidence of feasibility, not its normative authority. Retaining
its existing vocabulary avoids introducing a second admission protocol for the
same earned meaning. Rust's former shape and HMAC message are defective against
this amendment, and must be replaced, never accepted as alternatives.

The proof still demonstrates possession of local standing's capability for one
exact Package. It does not establish standing, override terms, authorize its
own replacement, create AC/CL, or attest application execution. Exact historical
AC replay retains its existing precedence over current possession verification.

## Conformance gate

Both implementations MUST independently consume the same stored vector file,
recompute every positive intermediate byte and proof through their own code,
and reject each negative case. No cross-language translator or shared verifier
is allowed. Only after both pass may the experiment attempt new AC.

Each negative case starts from the positive case and replaces exactly the
property named in `change`. Cases include changed Package identity and payload,
key bytes, digest text, vocabulary, a proof octet, uppercase proof encoding,
raw-digest and prefixed-digest HMAC inputs, and string admission representations.
The prefixed-input case explicitly fixes the observed D-006 counterexample.

## Standing selection (Third Implementer amendment, 2026-09-30)

The recipient retains an Introduction identity and capability K for the
Package's sender/recipient relationship. The current standing, local terms and
succession history select K before new admission. A peer-supplied Introduction
identity cannot choose a different capability. `introduction` is deliberately
NOT a member of admission and is NOT concatenated into the HMAC message.
The Package already binds sender and recipient. The fixed vector's local
Introduction is `IN-possession-vector-1`; it is a provisioning label, not a
portable key derivation rule. The `standing` section records the local fixture
precondition; it is not transmitted. Exact historical AC replay keeps its
existing precedence over current standing/proof checks. Unknown, expired or
insufficient standing may refuse before AC even when this MAC is valid.

The vector now includes literal source JSON as well as C. Construction and
verification MUST both consume this binding. The four producer/verifier
combinations are checked without translation. Neither a digest-only verifier
nor a successful native decryption constitutes admission.
