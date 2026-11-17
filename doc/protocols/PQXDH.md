# PQXDH

Status: shipped. `Pqxdh.publish`, `Pqxdh.initiate`, and `Pqxdh.accept` run
revision 3 on Curve25519. The KEM is ML-KEM-1024 through `pqcrypto`, not
round-3 CRYSTALS-Kyber and not X-Wing. `Pqxdh.signedPrekeyAuthentic` and
`Pqxdh.kemPrekeyAuthentic` check the two XEdDSA signatures. A bad
signature throws and returns no `SK`. This is not Signal Messenger and
not libsignal's protobuf session.

Specification: [The PQXDH Key Agreement Protocol](https://signal.org/docs/specifications/pqxdh/),
revision 3, dated 2023-05-24, last updated 2024-01-23. The document is
in the public domain.

PQXDH is the authenticated setup. It produces one 32-byte secret. The
Double Ratchet consumes that secret. PQXDH does not encrypt the
conversation, and it does not ratchet.

## What each side does

Bob publishes a prekey bundle: an identity key, a signed prekey, an
optional one-time prekey, and a post-quantum prekey. Alice fetches the
bundle. The library does not fetch it. A future API takes the bundle as
bytes the caller already has. There is no server in this package.

Alice checks the signature on the signed prekey. The specification uses
XEdDSA so the identity key can be the X25519 key. She then runs three
X25519 exchanges, or four when a one-time prekey is present:

```text
DH1 = DH(IK_A, SPK_B)
DH2 = DH(EK_A, IK_B)
DH3 = DH(EK_A, SPK_B)
DH4 = DH(EK_A, OPK_B)   # only with a one-time prekey
```

She also encapsulates to Bob's post-quantum prekey and appends that shared
secret, `SS`.

## Combiner

```text
SK = HKDF(F || DH1 || DH2 || DH3 || [DH4 ||] SS)
```

`F` is 32 bytes of `0xFF` on Curve25519, and 57 bytes of `0xFF` on
Curve448. It is there so the start of the HKDF input is not a valid
scalar or curve point. The salt is zeros, as long as the hash output.
The info string joins the application info, the curve, the hash, and the
KEM name with `_`. The specification's example is
`MyProtocol_CURVE25519_SHA-512_CRYSTALS-KYBER-1024`.

The example KEM in the specification is CRYSTALS-Kyber-1024. This
profile runs ML-KEM-1024 (FIPS 203), which `pqcrypto` implements. The
HKDF info therefore names `ML-KEM-1024`, not `CRYSTALS-KYBER-1024`.
Replacing the KEM with X-Wing does not happen here. X-Wing's combiner is
`SHA3-256(ss_M || ss_X || ct_X || pk_X || label)` and has none of the
extra Diffie-Hellman outputs.

`EncodeEC` is the raw 32-byte key. `EncodeKEM` is the raw 1568-byte
encapsulation key. The ranges are disjoint by length. That is also the
byte string libsignal signs for a curve prekey. The specification's
recommended type byte is not used.

The first message is AES-256-GCM, or ChaCha20-Poly1305 when FIPS mode is
off, under `SK`, with a 12-byte zero nonce. The associated data is
`IK_A || IK_B || PQPK_B`, plus any extra bytes both sides pass. ML-KEM
does not bind `PQPK_B` into the ciphertext, so losing it fails the tag.
A [Double Ratchet](DOUBLE_RATCHET.md) is started from `SK`. Its next
message is not this initial ciphertext.

Authentication in this revision is classical. The post-quantum
contribution is confidentiality of `SK` against a later break of X25519.
`Pqxdh` does not claim post-quantum authentication, and it is not a FIPS
handshake. `PqFipsMode` only refuses ChaCha.

The pure-Dart ML-KEM call runs on a worker isolate when `dart:isolate`
exists, so a UI isolate stays responsive. A registered `PqLattice`
backend stays on the caller. There is no SIMD field multiply in this
handshake. The 16-bit limb product still does not fit in signed
`Int32x4`.

## API

```dart
final bob = await Pqxdh.publish();
final aliceKey = await RatchetKeyPair.generate();
final alice = await Pqxdh.initiate(
  identityKey: aliceKey,
  bundle: bob.bundle,          // already fetched; there is no server
  plaintext: utf8.encode('hello'),
);
final opened = await Pqxdh.accept(
  identityKey: bob.identityKey,
  signedPrekey: bob.signedPrekey,
  kemSecretKey: bob.kemSecretKey,
  initialMessage: alice.initialMessage!,
);
final session = opened.ratchet; // DoubleRatchet, already started from SK
```

`info` defaults to `pqforge01`. The HKDF info is
`pqforge01_CURVE25519_SHA-512_ML-KEM-1024`. Pass the same string to both
sides. It is printable ASCII, at least 8 characters, with no `_`.

`PqxdhKem.xWing` is not a value. A caller who wants X-Wing uses
[XWING.md](XWING.md) and passes the 32-byte result to
`DoubleRatchet.initiate`. The type is not named `Pqxdh`.

`bob.bundle` is a typed object. A raw 1216-byte buffer does not satisfy
it. That length is also an X-Wing public key and an `X25519MLKEM768`
share.

## Tests that gate it

- XEdDSA vectors live in `test/pq_xeddsa_test.dart`. They are not PQXDH.
- A bundle with a bad signed-prekey or KEM signature is rejected and no
  `SK` is returned.
- With fixed seeds and KEM coins, `SK` matches an HKDF computed in the
  test from `F || DH1 || DH2 || DH3 || SS`, not from `Pqxdh`'s private
  function. A one-time prekey changes that value.
- The same curve keys with different KEM coins do not match.
- An X-Wing public key is rejected by the bundle parser.
- The initial message opens under the responder's `SK` and fails if the
  associated data loses the post-quantum public key.
- The next Double Ratchet message opens. Feeding the PQXDH message to
  the ratchet does not.
