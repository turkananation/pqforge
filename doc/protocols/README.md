# Protocols

These pages separate constructions that share ingredients and do not share
outputs. A matching length is not a matching protocol.

X-Wing and the Double Ratchet are exported. PQXDH and the Sparse
Post-Quantum Ratchet are exported as fail-closed scaffolds: the types
check lengths, then throw. They do not run a handshake or a braid.

| Document | Shipped | When it can land |
| --- | --- | --- |
| [HPKE.md](HPKE.md) | Yes. `PqHpke` | Stays. X-Wing is `HpkeKem.xWing` beside the five DHKEMs |
| [XWING.md](XWING.md) | Yes. `PqXWing` | Draft-11 Appendix C matches. Not a `.pqf` algorithm |
| [DOUBLE_RATCHET.md](DOUBLE_RATCHET.md) | Yes. `DoubleRatchet` | A session, not a KEM. Not libsignal bytes |
| [PQXDH.md](PQXDH.md) | Scaffold. `Pqxdh` throws | Only once XEdDSA exists. Ed25519 is not XEdDSA |
| [SPARSE_POST_QUANTUM_RATCHET.md](SPARSE_POST_QUANTUM_RATCHET.md) | Scaffold. `TripleRatchet` throws | Last. The ML-KEM Braid needs an incremental ML-KEM interface this package does not have |

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

## Types

Future secrets are a fixed-length `Uint8List` inside a small class. They
are not `String`, not a growable `List<int>`, and not `BigInt`. Header
parsing uses a view of the existing buffer. A replaced chain key is wiped
in place. An expanded ML-KEM private key is not stored in a session object.
The expensive work is ML-KEM itself. The wrapper is there so a 1216-byte
X-Wing public key cannot be passed where a ratchet public key or a PQXDH
bundle is required.
