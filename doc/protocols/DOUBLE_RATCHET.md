# Double Ratchet

Status: not implemented. No ratchet type exists in `lib/`. This page is
the contract for a later release. It lands after X-Wing, not in 0.4.14.

Specification: [The Double Ratchet Algorithm](https://signal.org/docs/specifications/doubleratchet/),
revision 4, 2025-11-04.

The Double Ratchet starts from a 32-byte shared secret that some other
protocol already agreed. [PQXDH](PQXDH.md) is one way to agree that
secret. A future X-Wing decapsulation is another. Using X-Wing to seed a
ratchet is not PQXDH. The ratchet does not itself authenticate the peer.

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
specification does not pick the number. The implementation will, and the
test will pin it.

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

## Proposed API

These symbols are not exported.

```dart
final session = DoubleRatchet.initiate(
  sharedSecret: secret, // SharedSecret32, from PQXDH or from X-Wing
  remoteRatchetKey: bobRatchet.publicKey,
);
final sealed = session.seal(plaintext, aad: aad);
final opened = responder.open(sealed);
```

`sharedSecret` does not accept a public key, a ciphertext, or a pqforge
hybrid transcript. `seal` returns the header and the ciphertext. It does
not return the message key.

The AEAD is the existing AES-256-GCM engine unless a session is
constructed with ChaCha20-Poly1305. Either choice is pqforge's choice.
It is not a claim that the bytes match libsignal.

Skipped keys live on the session object, capped by `MAX_SKIP`.
Serialization, when it is added, writes the 32-byte seeds and chain keys
the specification allows, and refuses an expanded ML-KEM private key.
There is no ML-KEM private key in this protocol. That refusal belongs to
the Triple Ratchet page, and the serializer is shared so a later epoch
state cannot grow a second format.

## Tests that gate it

- Two parties exchange messages, including one that arrives out of order,
  and the late message opens.
- A message past `MAX_SKIP` is rejected and does not grow the skipped-key
  map.
- After a Diffie-Hellman step, the previous chain key does not derive the
  new message key.
- A `SharedSecret32` produced by the future X-Wing decapsulation is
  accepted. A 1216-byte X-Wing public key is not.
- The default `PqForgeHybridKeyAgreement` test vectors are unchanged.
