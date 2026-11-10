# Sparse Post-Quantum Ratchet

Status: scaffold. `TripleRatchet` and `SpqrKem` are exported.
`TripleRatchet.initiate` checks the 32-byte inputs, then throws. The braid
is not implemented. `pqcrypto` exposes ML-KEM key generation,
encapsulation, and decapsulation. It does not expose the incremental
interface the braid requires. A 1216-byte X-Wing key is rejected by
`RatchetPublicKey` before that throw. `SpqrKem.xWing` is not a value.

The Triple Ratchet is this protocol running beside the
[Double Ratchet](DOUBLE_RATCHET.md). It is not a separate KEM, and it is
not a replacement for the X25519 ratchet.

## Why it exists

[PQXDH](PQXDH.md) mixes one KEM secret into the first shared key. After
that, the Double Ratchet heals with X25519. A quantum adversary who later
learns a classical ratchet key can unwind that healing. The Sparse
Post-Quantum Ratchet keeps mixing new ML-KEM secrets into the same
session, without putting a full encapsulation key on every message.

Specification: section 5 of [The Double Ratchet Algorithm](https://signal.org/docs/specifications/doubleratchet/),
revision 4, 2025-11-04, and [The ML-KEM Braid Protocol](https://signal.org/docs/specifications/mlkembraid/),
revision 1, dated 2025-02-21, last updated 2025-09-26. The chunk picture
below is from the Signal write-up of 2025-10-02,
[Signal Protocol and Post-Quantum Ratchets](https://signal.org/blog/spqr/).
Where that write-up and the specification disagree, the specification wins.

## Sparse

ML-KEM-768's encapsulation key is 1184 bytes. Its ciphertext is 1088
bytes. Sending either object on every message is the thing this protocol
refuses to do.

The braid splits the encapsulation key into a 64-byte header (`ek_seed`
and a hash) and the remaining vector. Once the other side has the header
it can start its half of the ciphertext, and the two large halves travel
at the same time. The 2025-10-02 write-up erasure-codes those bytes into
chunks of about 100 bytes and attaches the chunks to ordinary messages.
The specification does not fix the chunk size. An implementation picks
one and tests it. It does not invent a second braid.

One finished epoch produces one 32-byte secret. The next epoch is already
moving. The secret is mixed into the root key:

```text
RK, CKs, CKr = KDF_SCKA_RK(RK, scka_output)
```

Message keys for that epoch come from the new chains. The X25519 ratchet
keeps advancing on its own. A message key depends on both.

The state added beside the Diffie-Hellman ratchet is an epoch counter, a
send chain and a receive chain per epoch, skipped message keys per epoch,
a direction flag, and the opaque braid state. The header becomes the
Double Ratchet header plus the braid chunk and its index.

## What it does not do

Forward secrecy against a quantum adversary starts once the ML-KEM secret
key for a mixed epoch is gone. Post-compromise security is slower than
X25519. A stolen current state still reads messages until a braid epoch
the attacker did not see has been mixed in. That takes a stretch of
traffic, not one reply.

SPQR does not authenticate the session. PQXDH already did that, and that
authentication is classical.

SPQR is not X-Wing. The braid uses ML-KEM-768 itself. There is no X25519
share inside the braid secret, and there is no
`SHA3-256(ss_M || ss_X || ct_X || pk_X || label)` step. Completing an
epoch by calling ordinary `encapsulate` on a full 1184-byte key, on every
message, is a different protocol. It must not be named this one.

## API

The symbols are exported. `initiate` throws. It does not encapsulate.

```dart
// Throws. The braid's incremental interface is not in pqcrypto.
final session = await TripleRatchet.initiate(
  sharedSecret: secret,             // SharedSecret32, from PQXDH
  remoteRatchetKey: bobRatchet.publicKey,
  kem: SpqrKem.mlKem768,            // the braid's KEM, not X-Wing
);
```

When the braid exists, `sealed` carries the Double Ratchet header and
whatever braid chunk this message is responsible for. `open` advances
either ratchet only when the bytes say it should. A chunk that fails its
epoch check is rejected and does not move the root key. None of that
runs today.

`SpqrKem.xWing` is not a value. X-Wing remains the one-shot KEM in
[XWING.md](XWING.md).

The session stores the braid's opaque state and 32-byte chain keys. It
does not store an expanded ML-KEM private key that could be serialized
and sent. The braid specification's binding properties do not hold for a
transmitted expanded key. That rule is the same one X-Wing states for its
own expanded key, and the two types do not share a serializer.

## Tests that gate it

- A full epoch, with fixed seeds, produces the 32-byte secret the braid
  test vector says, and `KDF_SCKA_RK` changes the root key.
- A missing chunk does not advance the epoch.
- After the epoch is mixed, the previous root key does not derive the new
  message key.
- The X25519 ratchet still heals on a reply that carries no completed
  epoch. Those message keys differ from the keys of a pure Double Ratchet
  only where a finished epoch has been mixed.
- Constructing the session with a 1216-byte X-Wing public key fails.
- No test calls ordinary ML-KEM `encapsulate` and treats the result as a
  braid epoch.
