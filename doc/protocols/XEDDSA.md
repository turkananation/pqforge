# XEdDSA

Status: shipped. `PqXeddsa` signs and verifies. There is no CLI command.

This is Curve25519 XEdDSA as libsignal ships it, not the paper's variant
that forces the Edwards sign bit to 0 by negating the scalar. libsignal
stores that sign bit in the high bit of `S`
(`PrivateKey::calculate_signature`). A signature is 64 bytes, `R || S`.

The secret is a 32-byte X25519 private key. It is clamped on use
(`secret[0] &= 248`, `secret[31] &= 127`, `secret[31] |= 64`), then
reduced modulo the Ed25519 order L. `sign` draws 64 bytes from
`PqBytes.randomBytes` when `randomness` is omitted. Those bytes are `Z`.
The same secret, message, and `Z` match libsignal byte for byte.

```text
prefix = 0xFE || 0xFF * 31
r = SHA-512(prefix || clamped_secret || M || Z) mod L
R = r * B
h = SHA-512(R || A_edwards || M) mod L
S = (h * a + r) mod L
signature = R || S, with A's Edwards sign bit in signature[63]
```

`verify` clears that bit, rejects `S` when bit 253 or 254 is set, then
reduces `S` modulo L (`Scalar::from_bytes_mod_order`). The public key is
the Montgomery u-coordinate. It must be canonical and have a clear high
bit. The map to Edwards is `y = (u - 1) / (u + 1)` with the sign bit from
the signature. `verify` returns false and does not throw.

`signAll` and `verifyAll` take a batch. `Z` is drawn on the caller
isolate, so a custom `PqRandom.generator` is honored. Two or more items
use at most four isolates when `dart:isolate` exists, and run inline on
dart2wasm. One item always runs inline.

`Pqxdh.signedPrekeyAuthentic` verifies a signed prekey. The message is
the 32-byte prekey public key, which is what libsignal signs.
`Pqxdh.initiate` and `Pqxdh.accept` still throw. That handshake is not
this signature.

Not VXEdDSA. Not XEd448. Not Ed25519. Not a FIPS signature. The field is
sixteen 16-bit limbs. A limb product does not fit in a signed `Int32x4`
lane, so the multiply is not the Dart 3.14 SIMD path. Inversion is the
ref10 addition chain. Scalar multiplication is a variable-time 4-bit
window. Canonical byte compares use `Uint8List.rangeEquals`. None of that
is a constant-time claim.

Vectors live in `test/pq_xeddsa_test.dart`, including libsignal's
published verify vector and `calculate_signature` bytes for fixed `Z`.
