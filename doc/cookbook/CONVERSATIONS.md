# Direct Conversations

Use for a two-party message stream after a PQXDH handshake. The package
seals and opens. You send the bytes to whatever server you run. You
supply transport, the prekey directory, and which one-time prekey id
has already been spent. This is a cookbook recipe, the same kind of
helper as `sealEmail`. It is not a messenger.

## What the package does

- `ConversationSession.start`, `accept`, `seal`, `open`, `toBytes`,
  `fromBytes`, `wipe`.
- `ConversationLevel` is the KEM, the trust algorithm, and the AEAD.
  Both sides pass the same value. The wire does not offer a menu.
  The default is ML-KEM-1024, ML-DSA-65, and AES-256-GCM.
  `compact` is ML-KEM-512 and ML-DSA-44. `balanced` is ML-KEM-768 and
  ML-DSA-65. `maximum` is ML-KEM-1024 and ML-DSA-87. `hashBased` is
  ML-KEM-1024 and SLH-DSA-SHAKE-128f, the fast hash identity.
  `hashCompact`, `hashBalanced`, and `hashMaximum` match the profile
  SHAKE-f sets. `ConversationLevel.hash` takes any of the twelve
  SLH-DSA sets. `ConversationLevel.fromProfile` takes the same choice.
- The ratchet is a separate argument: `ConversationRatchet.doubleRatchet`
  or `tripleRatchet`. `accept` requires it. Byte 5 of `CV01` has to
  match. The session is built from the argument, not from the byte.
  A flipped byte throws before SK is used.
- `start` requires prekey ids, the level you named, and `trustPublicKey`.
  That pin is compared with `rangeEquals` to the key on the bundle, then
  `Pqxdh.trustAuthentic` runs. A key that merely arrived in the same
  directory response is not a pin. XEdDSA still has to pass inside
  PQXDH. The trust signature is not mixed into SK. `Pqxdh.initiate`
  does not require it and still returns a clear-header `DoubleRatchet`.
- SLH-DSA and ML-DSA are the same kind of identity here. The signature
  is on the bundle, once. It is not attached to later messages, so an
  `f` set stays off the hot path. An `s` set is valid. It is slow, and
  signing it is allowed because you named it. `offload: true` runs that
  signature on a worker when `dart:isolate` exists.
- The first plaintext is sealed under SK, inside the PQXDH message.
  Later plaintexts are ratchet messages. `messageId` is in the
  associated data. Both strings are 1 to 1024 UTF-8 bytes.
- Both sessions encrypt headers (`DRH1`, `TRH1`). `PQX1` version 1
  stays ML-KEM-1024 with the ciphertext at byte 70. Any other KEM is
  version 2, ciphertext at byte 78, length of the KEM you passed.
- A triple session attaches `chunksPerMessage` braid chunks, default
  4, inside one chain step. The chunk size stays 32 bytes. The braid
  itself stays ML-KEM-768. `TripleRatchet` still defaults to 1 chunk.
- `toBytes` is the session record (`CVS1`), not a protocol message.
  A triple record stores the 64-byte ML-KEM seed, not the expanded
  decapsulation key. Wrap the record before it hits disk.

## What you supply

- Transport. The library returns bytes. It does not open a socket.
- A pin of the peer's trust public key, stored where the prekey
  directory cannot write it.
- The prekey directory, and deletion of a spent one-time prekey id.
- Replay protection for the initial message.
- Storage of the session record. Do not put it on the wire.
- The same `ConversationLevel` and the same `ConversationRatchet` on
  both sides. ChaCha20-Poly1305 is refused while `PqFipsMode` is on.
  The mode is not a FIPS handshake.

## Call

```dart
const level = ConversationLevel(); // or compact, balanced, maximum, hashBased
final identity = PqSignaturePrimitives.generateKeyPair(
  level.trust.mlDsa!,
);
final bob = await Pqxdh.publish(
  signedPrekeyId: 7,
  kem: level.kem,
  trust: level.trust,
  trustKey: identity,
);
final started = await ConversationSession.start(
  conversationId: 'desk',
  ratchet: ConversationRatchet.doubleRatchet,
  identityKey: aliceKey,
  bundle: bob.bundle,
  plaintext: Uint8List.fromList(utf8.encode('hello')),
  messageId: 'm0',
  trustPublicKey: identity.publicKey, // the pin, not a fresh fetch
  level: level,
  offload: false,
);
final accepted = await ConversationSession.accept(
  conversationId: 'desk',
  ratchet: ConversationRatchet.doubleRatchet,
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

A hash-based identity is the same calls with
`ConversationLevel.hashBased`, or `ConversationLevel.hash` and
`PqSlhDsaPrimitives.generateKeyPair`. `Pqxdh.initiate` is the handshake
without this recipe.

## Wire

`CV01 || version 1 || kind || id length (uint16) || UTF-8 id || payload`.

The first payload is `PQX1` version 2. Later payloads are `DRH1` or
`TRH1`. The handshake associated data is

```text
pqforge/conversation/v2\n{id}\n{messageId}\n{kind}\n{KEM}\n{trust id}\n{aead}\n
|| pinned public key
```

`kind` is `1` or `2`. A peer who passes a different ratchet, KEM, trust
algorithm, or pin fails the AEAD. The kind byte is also checked before
that, so a flipped byte does not open the first plaintext.

Later message associated data drops the pin:

```text
pqforge/conversation/v2\n{conversationId}\n{messageId}
```

Header encryption follows Double Ratchet revision 4 section 4, with one
honest deviation: the header nonce is 12 bytes because AES-GCM's nonce
is 12 bytes, not 128 bits. A header key lasts one sending chain. The
body nonce stays 12 zero bytes. This is not libsignal header encryption.

## Not this

Not Signal Messenger, not libsignal bytes, not a FIPS handshake, and
not a CLI command. No `.pqf` or `.pqfs` change. The X25519 ladder is
the variable-time 4-bit window. Owning these bytes does not make it
constant-time. The conversation id is in the clear. Hiding it is a
different protocol.
