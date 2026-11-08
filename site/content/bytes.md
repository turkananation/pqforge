---
title: Bytes
description: SHA-1, SHA-2, HMAC, length prefixes, and the constant-time compare.
---

`PqBytes` is the byte layer under the envelopes. `PqForgeBytes` is the
same functions under the older name. Prefer `PqBytes`.

## Digests

| Call | Bytes | Stream form | Use |
| --- | --- | --- | --- |
| `sha256` | 32 | `sha256OfStream` | New work. Envelope AAD hashes. Artifact pre-hash. |
| `sha384` | 48 | `sha384OfStream` | When the protocol names SHA-384. |
| `sha512` | 64 | `sha512OfStream` | When the protocol names SHA-512. ECDSA-P521's hash. |
| `sha1` | 20 | `sha1OfStream` | Only where a standard still names SHA-1. |

SHA-1 collision resistance is broken. It is in 0.4.11 because DNSSEC NSEC3
(RFC 5155) and DS digest type 1 (RFC 4034) still name it. It is not a
signature and not a hash for a new protocol. The stream forms update one
chunk at a time and do not buffer the input. That is what lets the CLI
pre-hash a large artifact before a digest-mode signature.

`uint64` and `readUint64` use two big-endian uint32 halves so they run on
dart2js. A value at or above 2^53 is rejected on read. No pqforge frame
counter is that large.

`concat`, `lengthPrefixed`, and `decodeLengthPrefixed` are the envelope
field codec. A truncated length throws `PqForgeException`. `constantTimeEquals`
compares two MACs without returning on the first mismatch.

## HMAC

`hmacSha256`, `hmacSha384`, and `hmacSha512` are one-shot. HKDF-Extract
and HKDF-Expand for SHA-256 and SHA-384 are on `PqSymmetricPrimitives`.
HPKE's SHA-512 schedule uses the HMAC-SHA512 already in this class. The
combiner uses HKDF, not a raw HMAC. See [Agreement](agreement) and
[Symmetric](symmetric).

`PqBytes.randomBytes` reads `PqRandom.generator`. A negative length throws.
`utf8Bytes` is `utf8.encode` into a `Uint8List`.

[Envelopes](envelopes) · [Claim boundary](claim-boundary)
