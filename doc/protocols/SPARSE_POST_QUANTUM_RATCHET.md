# Sparse Post-Quantum Ratchet

Status: shipped. `TripleRatchet`, `MlKemBraid`, `MlKemIncremental`,
`SpqrKdf`, `BraidErasure`, and `SpqrKem` are exported.
`TripleRatchet.initiate` and `accept` run the public-domain ML-KEM Braid
beside an X25519 Double Ratchet. This is not Signal Messenger, not
libsignal bytes, and not a FIPS handshake. There is no CLI command.

`pqcrypto` exposes ML-KEM key generation, encapsulation, and
decapsulation. It does not expose Encaps1 or Encaps2. Those two steps,
and the braid's Fujisaki-Okamoto hash, live in this package. The NTT
stays in pqcrypto's `Indcpa`. A full `encapsulate` is a different
protocol and is not a braid epoch. `SpqrKem.xWing` is not a value. A
1216-byte X-Wing key is rejected by `RatchetPublicKey`.

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
The specification does not fix the chunk size. This package uses 32-byte
chunks: 16 little-endian GF(2^16) symbols. The index is a uint16 beside
the chunk, not one of those bytes. Parity is a systematic Cauchy
Reed-Solomon code over x^16 + x^5 + x^3 + x^2 + 1. The no-loss path
copies the message. The parity multiply is `Int32x4`, four coefficients
at a time. That is the only SIMD in this protocol. The NTT is not
rewritten. An Ed25519 limb product still does not fit a signed lane.

One finished epoch produces one 32-byte secret, `KDF_OK` of the raw
ML-KEM secret. The braid hash is SHA3-256(rho || t). FIPS 203 stores
SHA3-256(t || rho). `PqcKem.kyber768.decapsulate` therefore does not
open a braid ciphertext. The secret is mixed into the root key:

```text
RK, CKs, CKr = KDF_SCKA_RK(RK, scka_output)
```

Every message key is `KDF_HYBRID` of the X25519 message key and the SPQR
message key, including messages sent before the first epoch finishes.
The X25519 header (`dh`, `pn`, `n`) still matches a `DoubleRatchet`
started from the elliptic half of the split, with info
`pqforge-triple-ratchet-v1-ec`. The ciphertext does not match that
session. SPQR message numbers start at 1. Double Ratchet numbers still
start at 0. Wire magic is `TR01`. The nonce is 12 zero bytes and is not
on the wire. One AEAD. Not two encryptions.

Labels are `pqforge-braid-v1_MLKEM768_SHA-256`,
`pqforge-spqr-v1_MLKEM768_SHA-256`, and
`pqforge-triple-ratchet-v1_X25519_MLKEM768_SHA-256`. They are not Signal
strings. Section 7.2 of the Double Ratchet spec repeats the INIT inputs
for `KDF_SCKA_CK`. Those inputs do not depend on the chain key or the
counter. This package follows section 5.2.

The pure-Dart split runs on `Isolate.run` when `dart:isolate` exists.
Pass `offload: false` to stay on the caller isolate. `PqLattice.provider`
is not consulted: that provider only has a full encapsulate.
`chunksPerMessage` pulls that many codewords inside one chain step. The
default is 1, which is the `TR01` version 1 header. More than one chunk
is `TR01` version 2. `encryptHeaders` wraps that header as `TRH1`.
`toBytes` / `fromBytes` are the session record. A live epoch stores the
64-byte seed (`d || z`) and re-expands it. The expanded decapsulation
key is wiped when the epoch finishes or when `wipe` is called, and it
is not written. A bad MAC or a bad encapsulation-key hash throws
`PqForgeException` ("No secret was derived.") and closes the session.
`PqFipsMode` only refuses ChaCha20-Poly1305. It does not turn this into
a FIPS handshake.

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
authentication is classical. `ConversationSession` also checks an
ML-DSA-65 signature on the bundle. That check is not an input to this
ratchet and not an input to SK.

SPQR is not X-Wing. The braid uses ML-KEM-768 itself. There is no X25519
share inside the braid secret, and there is no
`SHA3-256(ss_M || ss_X || ct_X || pk_X || label)` step. Completing an
epoch by calling ordinary `encapsulate` on a full 1184-byte key, on every
message, is a different protocol. It must not be named this one.

## API

```dart
final bobKey = await RatchetKeyPair.generate();
final secret = SharedSecret32(sharedSecretBytes); // 32 bytes, from PQXDH
final alice = await TripleRatchet.initiate(
  sharedSecret: secret,
  remoteRatchetKey: bobKey.publicKey,
);
final bob = TripleRatchet.accept(
  sharedSecret: secret,
  ratchetKey: bobKey,
);
final sealed = await alice.seal(plaintext);
final opened = await bob.open(sealed);
alice.wipe();
```

`kem` defaults to `SpqrKem.mlKem768`. The suite defaults to AES-256-GCM.
`ratchetKey`, `ratchetKeys`, and `randomBytes` exist so tests can pin
the X25519 pairs and the braid coins. Production callers omit them.

`SpqrKem.xWing` is not a value. X-Wing remains the one-shot KEM in
[XWING.md](XWING.md).

## Tests that gate it

- Fixed seeds: both sides and an independent Encaps1/Encaps2/Decaps
  agree on `KDF_OK`. A dropped header chunk still finishes that epoch.
- Passing FIPS `H(pk)` into Encaps1 matches `PqcKem.kyber768.encapsulate`
  byte for byte. The braid's own hash does not, and
  `decapsulate` of a braid ciphertext does not return the braid secret.
- After a mix, the previous chain key does not derive the new message key.
- X25519 headers track a Double Ratchet on the elliptic half. The
  ciphertext differs on every message, because `KDF_HYBRID` always runs.
  A fork that missed the epoch cannot open the post-epoch message.
- A 1216-byte key is rejected. No test treats a full encapsulate as a
  braid epoch.
