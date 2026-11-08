---
title: Agreement
description: Brainpool, RFC 7919 FFDHE, NIST ECDH, X25519, and X448. Key agreement only.
---

These functions produce a shared secret. None of them signs, none of them
negotiates TLS, and none of them is constant-time. A TLS stack that wants
one of these groups has to do the handshake itself.

`PqBrainpool` and `PqFfdhe` arrived in 0.4.12. `PqNistEcdh`, `PqX448`, and
the X25519 path were already here. OpenSSL 4.1.0 is the byte check for
every group in the table. BoringSSL is not: it does not offer brainpool or
FFDHE.

## What you can call

| API | Groups | Public key | Shared secret |
| --- | --- | --- | --- |
| `PqBrainpool` | brainpoolP256r1, P384r1, P512r1 | uncompressed SEC1, `0x04\|\|X\|\|Y` | x-coordinate |
| `PqFfdhe` | ffdhe2048, 3072, 4096, 6144, 8192 | big-endian, left-padded to the prime | same width as the prime |
| `PqNistEcdh` | P-256, P-384, P-521 | uncompressed SEC1 | x-coordinate |
| `PqClassical` X25519 | X25519 | 32 bytes, little-endian | 32 bytes |
| `PqX448` | X448 | 56 bytes, little-endian | 56 bytes |

There is no NIST P-512. OpenSSL's name "P-512" is brainpoolP512r1, which is
RFC 5639, not FIPS 186. P-521 is 521 bits. Its private key and its shared
secret are 66 bytes. That is `PqNistEcdh`, and it was already on `main`
before 0.4.12.

## Brainpool

RFC 8734 code points 31, 32, and 33. The 160, 192, 224, and 320-bit
brainpool curves, and every twisted `t1` curve, are not TLS groups and are
not implemented.

| Curve | Code point | Scalar | Public key | Secret |
| --- | --- | --- | --- | --- |
| brainpoolP256r1 | 31 | 32 | 65 | 32 |
| brainpoolP384r1 | 32 | 48 | 97 | 48 |
| brainpoolP512r1 | 33 | 64 | 129 | 64 |

```dart
final alice = PqBrainpool.p256GenerateKeyPair();
final bob = PqBrainpool.p256GenerateKeyPair();
final shared = PqBrainpool.p256SharedSecret(
  secretKey: alice.secretKey,
  remotePublicKey: bob.publicKey,
);
```

`p384GenerateKeyPair` / `p384SharedSecret` and `p512GenerateKeyPair` /
`p512SharedSecret` are the other two widths. `p256PublicKeyFromPrivate`
rebuilds the point from a scalar you already hold.

A scalar outside `[1, n)` is rejected. A peer point is rejected unless it
is the right length, starts with `0x04`, is in field range, satisfies the
curve equation, and is not infinity. The field arithmetic is PointyCastle's.

## Finite-field Diffie-Hellman

FFDHE means Finite Field Diffie-Hellman Ephemeral. RFC 7919 fixes the
primes so both sides do not send parameters. The generator is 2. IANA code
points are 256 through 260.

| Group | Code point | Prime, public key, secret |
| --- | --- | --- |
| `PqFfdheGroup.ffdhe2048` | 256 | 256 bytes |
| `PqFfdheGroup.ffdhe3072` | 257 | 384 bytes |
| `PqFfdheGroup.ffdhe4096` | 258 | 512 bytes |
| `PqFfdheGroup.ffdhe6144` | 259 | 768 bytes |
| `PqFfdheGroup.ffdhe8192` | 260 | 1024 bytes |

```dart
final alice = PqFfdhe.generateKeyPair(PqFfdheGroup.ffdhe2048);
final bob = PqFfdhe.generateKeyPair(PqFfdheGroup.ffdhe2048);
final shared = PqFfdhe.sharedSecret(
  group: PqFfdheGroup.ffdhe2048,
  secretKey: alice.secretKey,
  remotePublicKey: bob.publicKey,
);
```

A key this class generates uses an exponent in `[1, q)`, where
`q = (p - 1) / 2`. An imported exponent, including one OpenSSL wrote, may
be any value in `[1, p - 1)`. A peer public value is rejected unless
`1 < Y < p - 1` and `Y^q ≡ 1 (mod p)`. That is the safe-prime subgroup
check. `Y = 1` fails it.

The exponentiation is `BigInt.modPow`. The random buffer used to draw the
exponent is wiped with `secureZero`. The exponent itself is a `BigInt` and
cannot be wiped. An 8192-bit agreement is a full-size modular
exponentiation. Do not put it on a request path that has a small budget.

## NIST curves and Montgomery

`PqNistEcdh.p256SharedSecret`, `p384SharedSecret`, and `p521SharedSecret`
are the same byte contract as brainpool: uncompressed point in, x
coordinate out. P-256 and P-384 are the shares a TLS hybrid group uses.
P-521 ECDH is the HPKE share. It is not a TLS named group in RFC 8446, and
it is not `PqEcdsaP521`. Signing and agreeing are different functions even
when the curve is the same. See [Classical](classical).

X25519 takes a 32-byte seed as the secret. X448 takes 56 unclamped bytes
and clamps inside `sharedSecret`, which is what
`DHKEM(X448, HKDF-SHA512)` calls. `PqX448` returns 56 zero bytes for the
all-zero output. HPKE aborts on that. `PqX448` itself does not.

## Combining two shares

`PqForgeCombiner` does not run a handshake. You bring it two shared
secrets you already computed.

`combine` concatenates classical then post-quantum, with no length prefix,
then HKDF. `PqHybridProfile.balanced` is SHA-256. `PqHybridProfile.heavy`
is SHA-512.

`concatenateSharedSecrets` with `PqHybridConcatOrder.pqThenClassical` is
the raw join RFC 10024 uses for X25519MLKEM768. That call must not HKDF.
TLS HKDF-Extract consumes the concatenation itself. The TLS handshake is
pqtransport, not this package.

[HPKE](hpke) · [Classical](classical) · [Bytes](bytes) · [Claim boundary](claim-boundary)
