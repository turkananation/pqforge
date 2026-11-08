---
title: What landed
description: Releases that were easy to miss. 0.4.12 brainpool and FFDHE, 0.4.11 SHA-1, 0.4.10 HPKE.
---

These releases did not change the `.pqf` or `.pqfs` wire format. None of
them is a FIPS 140 module.

| Release | You can call |
| --- | --- |
| 0.4.13 | `PqRsa` verifies a 1024-bit modulus, `PqRsaHash.sha1`, and `PqEd448`. Generation stays 2048 and up. Ed448 is not an X.509 algorithm. |
| 0.4.12 | `PqBrainpool` and `PqFfdhe`. brainpoolP256r1, P384r1, P512r1, and ffdhe2048 through ffdhe8192. Agreement only. Not a TLS stack, and not constant-time. |
| 0.4.11 | `PqBytes.sha1` and `sha1OfStream`. RFC 3174, 20 bytes. Collision resistance is broken. For a standard that still names SHA-1, such as DNSSEC NSEC3. Not a signature. |
| 0.4.10 | `PqHpke`. Base, PSK, auth, and authPSK. X25519, X448, P-256, P-384, P-521. |
| 0.4.10 | Signature legs. `slhDsa:` on detached recipes. `compose-sign` for a dual or a triple. Opt-in ECDSA-P384 and ECDSA-P521. |
| 0.4.9 | `PqX509`, `PqEcdsaP384`, `PqRsa`, `PqEd25519`, and `pqforge cert`. |
| 0.4.8 | `PqSymmetricPrimitives.chacha20`. RFC 8439 keystream, including a QUIC header-protection mask. |

The recipe catalog is unchanged: ML-KEM envelopes, ML-DSA and SLH-DSA
detached signatures, hybrid sessions, multi-recipient envelopes, Argon2id
key custody, and the CLI.

[HPKE](hpke) · [Signatures](signatures) · [Certificates](certificates) · [Symmetric](symmetric) · [Classical](classical)
