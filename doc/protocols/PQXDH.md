# PQXDH

Status: not implemented. `lib/` has X25519 and Ed25519. It does not have
XEdDSA. Ed25519 is not XEdDSA, and this protocol is not started until that
primitive exists and has its own vectors. This page is the contract, not
a call that works today. It lands after the [Double Ratchet](DOUBLE_RATCHET.md).

Specification: [The PQXDH Key Agreement Protocol](https://signal.org/docs/specifications/pqxdh/),
revision 3, dated 2023-05-24, last updated 2024-01-23.

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

The example KEM is CRYSTALS-Kyber-1024. Replacing that KEM with ML-KEM,
or with X-Wing, does not turn the handshake into X-Wing. The combiner is
still HKDF over several Diffie-Hellman outputs plus one KEM secret.
X-Wing's combiner is `SHA3-256(ss_M || ss_X || ct_X || pk_X || label)` and
has none of those extra Diffie-Hellman outputs.

The first message is authenticated encryption under `SK`. The associated
data binds the identity keys and the post-quantum public key. That binding
is how PQXDH stops a re-encapsulation from being silent. It is not the
X-Wing label.

Authentication in this revision is classical. The post-quantum contribution
is confidentiality of `SK` against a later break of X25519. A future
`Pqxdh` type does not claim post-quantum authentication.

## Proposed API

These symbols are not exported. They are also blocked on XEdDSA.

```dart
final secret = Pqxdh.initiate(
  identityKey: aliceIdentity,          // X25519 key, XEdDSA-capable
  bundle: bobBundle,                    // already fetched
  kem: PqxdhKem.kyber1024,              // the spec example, not X-Wing
);
final session = secret.ratchet;        // DoubleRatchet, already initialized
final message = secret.initialMessage; // header, ciphertext, Alice's ephemeral key
```

`PqxdhKem.xWing` is not a value. A caller who wants X-Wing uses
[XWING.md](XWING.md) and passes the 32-byte result to
`DoubleRatchet.initiate`. The type is not named `Pqxdh`.

`bobBundle` is a typed object: identity public key, signed prekey, the
XEdDSA signature, optional one-time prekey, post-quantum public key, and
the KEM id. A raw 1216-byte buffer does not satisfy it. That length is
also an X-Wing public key and an `X25519MLKEM768` share.

## Tests that gate it

- XEdDSA sign and verify against the XEdDSA specification vectors, before
  any PQXDH test.
- A bundle with a bad signed-prekey signature is rejected and no `SK` is
  returned.
- With a fixed identity, prekeys, ephemeral key, and KEM coins, `SK`
  matches a vector computed from the formula above.
- The same inputs with the KEM swapped do not match.
- An X-Wing public key is rejected by the bundle parser.
- The initial message opens under the responder's `SK` and fails if the
  associated data loses the post-quantum public key.
