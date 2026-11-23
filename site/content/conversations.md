---
title: Conversations
description: PQXDH, then a Double Ratchet or a Triple Ratchet. You pick the level. Not Signal.
---

`ConversationSession` is the direct-conversation recipe. It runs PQXDH
and then the ratchet you name. It returns bytes. You send them to
whatever server you run. It does not fetch prekeys, store mail, or
delete a spent one-time prekey.

| | |
| --- | --- |
| Level | `ConversationLevel`. Default ML-KEM-1024, ML-DSA-65, AES-256-GCM |
| Also | `compact`, `balanced`, `maximum`, `hashBased`, or `hash` for any SLH-DSA set |
| Ratchet | `doubleRatchet` or `tripleRatchet`. `accept` requires it |
| Trust | One bundle signature. Not mixed into SK. Pin the public key |
| First message | Sealed under SK, inside `PQX1` version 2 |
| Later messages | `DRH1` or `TRH1`, inside `CV01`. No SLH-DSA signature on them |
| Triple chunks | 4 per chain step, unless you pass another count |
| Session record | `CVS1`. The braid stores a 64-byte seed, not the expanded key |

`Pqxdh.initiate` is still the handshake without this recipe. It returns
a clear-header `DoubleRatchet`. This page does not replace that.

## Start

`trustPublicKey` is the identity you already trust. Compare happens
with `rangeEquals`, then `Pqxdh.trustAuthentic`. A key that came in the
same directory response is not a pin unless you stored it somewhere
that directory cannot write.

The default level is ML-KEM-1024 and ML-DSA-65. Pass `ConversationLevel.compact`
(ML-KEM-512, ML-DSA-44), `balanced` (ML-KEM-768, ML-DSA-65), `maximum`
(ML-KEM-1024, ML-DSA-87), or `hashBased` (ML-KEM-1024, SLH-DSA-SHAKE-128f).
`ConversationLevel.hash` takes any of the twelve sets, including an `s`
set. An `s` set is slow. The signature is on the bundle, once, so the
messages stay an AEAD. XEdDSA still checks the X25519 prekeys.

```dart
const level = ConversationLevel.hashBased;
final identity = PqSlhDsaPrimitives.generateKeyPair(
  PqSlhDsaAlgorithm.shake128f,
);
final bob = await Pqxdh.publish(
  signedPrekeyId: 7,
  kem: level.kem,
  trust: level.trust,
  trustKey: identity,
);
final started = await ConversationSession.start(
  conversationId: 'desk',
  ratchet: ConversationRatchet.tripleRatchet,
  identityKey: aliceKey,
  bundle: bob.bundle,
  plaintext: message,
  messageId: 'm0',
  trustPublicKey: identity.publicKey,
  level: level,
  offload: false,
);
```

`offload: false` keeps the KEM and the trust signature on this isolate.
Leave the default when the caller is a UI isolate and `dart:isolate`
exists. SLH-DSA still offloads when a custom lattice provider is
installed. It does not use that provider.

`accept` requires the same ratchet and the same level. A flipped kind
byte throws before a secret is returned.

```dart
final accepted = await ConversationSession.accept(
  conversationId: 'desk',
  ratchet: ConversationRatchet.tripleRatchet,
  identityKey: bob.identityKey,
  signedPrekey: bob.signedPrekey,
  kemSecretKey: bob.kemSecretKey,
  message: started.message,
  messageId: 'm0',
  trustPublicKey: identity.publicKey,
  level: level,
  offload: false,
);
```

The first plaintext is the one Alice passed to `start`. It is not a
ratchet message. `seal` and `open` are the messages after that.
`messageId` is associated data, 1 to 1024 bytes, and both sides must
use the same one.

## Headers and the braid

Header encryption is on for both ratchets. The layout follows Double
Ratchet revision 4, section 4. The header nonce is 12 random bytes,
because AES-GCM's nonce is 12 bytes, not 128 bits. A header key lasts
one sending chain. The body nonce stays 12 zero bytes. This is not
libsignal's header.

A triple session pulls four 32-byte braid chunks inside one chain step.
That shortens the stretch of traffic that is only X25519. It does not
encapsulate a fresh ML-KEM-768 ciphertext on every message. The braid
stays ML-KEM-768. The PQXDH KEM is whatever `ConversationLevel` says.
The default is ML-KEM-1024. `chunksPerMessage` is 1 to 64. The
`TripleRatchet` constructor still defaults to 1.

## Keep the record

`toBytes` is local state. A triple record stores the 64-byte ML-KEM
seed (`d || z`). `fromBytes` expands it again. The 2400-byte
decapsulation key is wiped and is not in the record. `wipe` drops the
session. Best-effort. Not a hard erasure claim.

You still supply transport, the prekey directory, deletion of the
one-time id, replay protection for the initial message, and a place to
put the session record.

Not Signal Messenger. Not libsignal bytes. Not a FIPS handshake. Not a
CLI command. `.pqf` and `.pqfs` are unchanged. The X25519 ladder stays
variable-time.

[HPKE](hpke) · [Recipes](recipes) · [Claim boundary](claim-boundary)
