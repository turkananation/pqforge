# Protocols

These pages separate constructions that share ingredients and do not share
outputs. A matching length is not a matching protocol.

Nothing on the four roadmap pages is exported from `lib/pqforge.dart`. The
names in their proposed API blocks are the shape of a later release. They
are not calls that work in 0.4.13.

| Document | In 0.4.13 | When it can land |
| --- | --- | --- |
| [HPKE.md](HPKE.md) | Yes. `PqHpke` | Stays. A future X-Wing KEM id would be added beside the five DHKEMs |
| [XWING.md](XWING.md) | No | 0.4.14, and only after the three draft-11 Appendix C vectors match |
| [DOUBLE_RATCHET.md](DOUBLE_RATCHET.md) | No | The release after X-Wing. A session, not a KEM |
| [PQXDH.md](PQXDH.md) | No | After the Double Ratchet, and only once XEdDSA exists. Ed25519 is not XEdDSA |
| [SPARSE_POST_QUANTUM_RATCHET.md](SPARSE_POST_QUANTUM_RATCHET.md) | No | Last. The ML-KEM Braid needs an incremental ML-KEM interface this package does not have |

`PqForgeHybridKeyAgreement` is not one of these. It stays the default
hybrid. Implementing any page below must not change its `initiate` /
`accept` output, the `.pqf` / `.pqfs` layouts, or `PqForgeCombiner.combine`.

A name on this list is reserved for the cited specification. A nearby
construction is not shipped under that name.

## Order

1. X-Wing, as its own KEM, with HPKE id `0x647A` only after the KEM vectors
   pass.
2. Double Ratchet, which can be seeded by any 32-byte shared secret,
   including a future X-Wing secret. That composition is not PQXDH.
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
