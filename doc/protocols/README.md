# Protocols

These pages separate constructions that share ingredients and do not share
outputs. A matching length is not a matching protocol.

X-Wing, the Double Ratchet, XEdDSA, PQXDH, and the Sparse Post-Quantum
Ratchet are exported. The Triple Ratchet is the last of those beside the
Double Ratchet. It is not a fourth KEM. `ConversationSession` is the
recipe that starts either ratchet from a PQXDH secret. It is not another
KEM.

| Document | Shipped | When it can land |
| --- | --- | --- |
| [HPKE.md](HPKE.md) | Yes. `PqHpke` | Stays. X-Wing is `HpkeKem.xWing` beside the five DHKEMs |
| [XWING.md](XWING.md) | Yes. `PqXWing` | Draft-11 Appendix C matches. Not a `.pqf` algorithm |
| [DOUBLE_RATCHET.md](DOUBLE_RATCHET.md) | Yes. `DoubleRatchet` | A session, not a KEM. Not libsignal bytes |
| [XEDDSA.md](XEDDSA.md) | Yes. `PqXeddsa` | Curve25519. libsignal signature bytes. Not the handshake |
| [PQXDH.md](PQXDH.md) | Yes. `Pqxdh` | Revision 3, Curve25519, ML-KEM-1024. Version 2 adds prekey ids. Optional ML-DSA-65 is not mixed into SK. Not libsignal bytes |
| [SPARSE_POST_QUANTUM_RATCHET.md](SPARSE_POST_QUANTUM_RATCHET.md) | Yes. `TripleRatchet` | ML-KEM Braid, ML-KEM-768. Seed session record. Not libsignal bytes |

`PqForgeHybridKeyAgreement` is not one of these. It stays the default
hybrid. Implementing any page below must not change its `initiate` /
`accept` output, the `.pqf` / `.pqfs` layouts, or `PqForgeCombiner.combine`.

A name on this list is reserved for the cited specification. A nearby
construction is not shipped under that name.

## Order

1. X-Wing, as its own KEM, with HPKE id `0x647A`. The three draft-11
   Appendix C vectors match.
2. Double Ratchet, which can be seeded by any 32-byte shared secret,
   including `PqXWing.decapsulate`. That composition is not PQXDH.
3. PQXDH, which returns that 32-byte secret and a Double Ratchet already
   started. Its KEM parameter stays the KEM in the PQXDH spec. It is not
   X-Wing.
4. Sparse Post-Quantum Ratchet beside the Double Ratchet. That pair is the
   Triple Ratchet. It is not a fourth KEM, and it is not X-Wing.
5. `ConversationSession`, which runs PQXDH and then the ratchet the
   caller named (`doubleRatchet` or `tripleRatchet`). The choice is on
   the `CV01` frame. The bundle's ML-DSA-65 signature is required here
   and is still not an input to SK.

## Types

Future secrets are a fixed-length `Uint8List` inside a small class. They
are not `String`, not a growable `List<int>`, and not `BigInt`. Header
parsing uses a view of the existing buffer. A replaced chain key is wiped
in place. An expanded ML-KEM private key is wiped and is not written into
a session record. `TripleRatchet.toBytes` stores the 64-byte seed and
re-expands it on load. The expensive work is ML-KEM itself. The wrapper
is there so a 1216-byte X-Wing public key cannot be passed where a
ratchet public key or a PQXDH bundle is required.
