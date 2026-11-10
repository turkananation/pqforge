# Double Ratchet

Status: shipped. `DoubleRatchet`, `DoubleRatchetMessage`, `SharedSecret32`,
`RatchetKeyPair`, and `RatchetPublicKey` are exported from
`package:pqforge/pqforge.dart`. This is Signal revision 4 over X25519 and
one pqforge AEAD. It is not PQXDH, not the Sparse Post-Quantum Ratchet,
not a libsignal byte match, and not a FIPS module.

Specification: [The Double Ratchet Algorithm](https://signal.org/docs/specifications/doubleratchet/),
revision 4, 2025-11-04. Sections 3 and 7.2 are the parts this session
implements. Section 5 (the Sparse Post-Quantum Ratchet) is not.

The Double Ratchet starts from a 32-byte shared secret that some other
protocol already agreed. [PQXDH](PQXDH.md) is one way to agree that
secret. `PqXWing.decapsulate` is another. Using that 32-byte result to
seed a ratchet is not PQXDH. The ratchet does not itself authenticate the peer.

## The two ratchets

The symmetric ratchet is a one-way chain. From a chain key `CK`:

```text
message key = HMAC(CK, 0x01)
next CK     = HMAC(CK, 0x02)
```

The hash is SHA-256 or SHA-512, chosen by the application and fixed for
the session. The message key encrypts one message and is deleted.

The Diffie-Hellman ratchet replaces the chains when a new ratchet public
key arrives. The specification's step is:

```text
PN = Ns
Ns = 0
Nr = 0
DHr = header.dh
RK, CKr = KDF_RK(RK, DH(DHs, DHr))
DHs = GENERATE_DH()
RK, CKs = KDF_RK(RK, DH(DHs, DHr))
```

`KDF_RK` is HKDF. The salt is the current root key. The input is the
Diffie-Hellman output. The info string is application-defined. The output
is 64 bytes: a new 32-byte root key and a new 32-byte chain key. The first
Diffie-Hellman uses the old local private key and opens the receiving
chain. The second uses a new local key pair and opens the sending chain.
The old root key and the old private key are discarded.

One reply therefore does two Diffie-Hellman operations, not one.

## Messages

The header carries the sender's current ratchet public key `dh`, the
message number in this sending chain `n`, and the number of messages in
the previous sending chain `pn`. The AEAD associated data is the caller's
associated data concatenated with the encoded header.

A message that arrives early is decrypted by walking the receiving chain
and storing unused message keys under `(dh, n)`. `MAX_SKIP` is a limit the
application sets so a header cannot force an unbounded store. The
specification does not pick the number. `DoubleRatchet.defaultMaxSkip` is
1000. A caller can pass a smaller `maxSkip`. A header past that cap throws
`PqForgeException` before any new skipped key is stored.

The header encoding is pqforge's. The specification does not fix the
bytes. It is 40 bytes, big-endian: `dh (32) || pn (uint32) || n (uint32)`.
The message is that header followed by `ciphertext || tag`. `parse` views
the buffer. It does not copy it. Associated data is the caller's bytes
concatenated with the header. An empty associated data is the header alone.

HMAC is `hmacSha256` or `hmacSha512` from `package:pqcrypto`. pqcrypto does
not export HKDF, so `KDF_RK` is RFC 5869 over that HMAC. HMAC-SHA-256 is
already 32 bytes. HMAC-SHA-512 is 64, and section 3 requires a 32-byte
chain key and a 32-byte message key, so those outputs are the leftmost 32
bytes. HKDF info defaults to the UTF-8 string `pqforge-double-ratchet-v1`.
That label is not used by the other HKDF calls in this package. A caller
may pass a different info of at most 1024 bytes. The hash and the info are
fixed for the session.

The AEAD is AES-256-GCM unless the session is constructed with
ChaCha20-Poly1305. The nonce is 12 zero bytes. Section 3 allows a constant
nonce because each message key is used once. This is not the section 7.2
CBC-HMAC recommendation, and the bytes are not libsignal's. A failed tag
throws `PqForgeAuthTagException`. The specification does not roll the chain
back, so the message key is consumed even when the tag fails.
`PqFipsMode` refuses ChaCha20-Poly1305 at `initiate`, `accept`, and
`fromBytes`. The Diffie-Hellman healing is X25519, so the ratchet itself
is not a FIPS construction.

Session bytes start with the magic `DR01`. Every secret field is 32 bytes.
There is no field for an expanded ML-KEM private key. `PqRatchetSecrets.copy32`
throws `PqForgeException` for the FIPS 203 private-key lengths 1632, 2400,
and 3168, and `ArgumentError` for a 1216-byte X-Wing public key.

The initiator already knows the responder's ratchet public key, mixes one
Diffie-Hellman into the shared secret, and can encrypt immediately. The
responder starts with the root key equal to that shared secret and no
remote ratchet key. The responder's sending chain appears only after the
first header.

Forward secrecy is the symmetric ratchet: a stolen message key does not
reveal earlier or later messages. Post-compromise security is the
Diffie-Hellman ratchet, and it is only as strong as that Diffie-Hellman.
For this implementation that is X25519, so the healing is classical. The
post-quantum healing is the separate
[Sparse Post-Quantum Ratchet](SPARSE_POST_QUANTUM_RATCHET.md). Revision 4
of the specification adds that beside this ratchet. It does not replace
the step above.

## API

```dart
final bobKey = await RatchetKeyPair.generate();
final secret = SharedSecret32(sharedSecretBytes); // 32 bytes
final alice = await DoubleRatchet.initiate(
  sharedSecret: secret,
  remoteRatchetKey: bobKey.publicKey,
);
final bob = DoubleRatchet.accept(
  sharedSecret: secret,
  ratchetKey: bobKey,
);
final sealed = alice.seal(plaintext, aad: aad);
final opened = await bob.open(sealed, aad: aad);
```

`initiate` does one X25519 and can `seal` immediately. `accept` does not.
Bob's sending chain appears only after the first header, and `seal` throws
until then. `sharedSecret` does not accept a public key, a ciphertext, or
a hybrid transcript. `seal` returns the header and the ciphertext. It does
not return the message key.

`PqXWing.decapsulate` returns 32 bytes and is a legal root. Passing the
1216-byte encapsulation key throws. That composition is not PQXDH.

`toBytes` / `fromBytes` round-trip the session, including skipped message
keys. `dispose` wipes the root, the ratchet secret, both chain keys, and
the skipped message keys.

## Tests that gate it

- Two parties exchange messages, including one that arrives out of order,
  and the late message opens.
- A message past `MAX_SKIP` is rejected and does not grow the skipped-key
  map.
- After a Diffie-Hellman step, the previous chain key does not derive the
  new message key.
- The 32-byte result of `PqXWing.decapsulate` is an acceptable root. A
  1216-byte X-Wing public key is not.
- The default `PqForgeHybridKeyAgreement` test vectors are unchanged.
