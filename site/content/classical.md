---
title: Classical
description: X25519, NIST ECDH, Ed25519, ECDSA, and RSA next to ML-KEM and ML-DSA.
---

Classical algorithms in pqforge are a tier next to pqcrypto, not a
replacement for it.

| API | Role |
| --- | --- |
| `PqClassical` X25519 | Key agreement. The secret is the 32-byte seed. Used by hybrid KEM-DEM and by HPKE. |
| `PqNistEcdh` | P-256 and P-384 ECDH. Uncompressed SEC1 points. The shared secret is the x-coordinate. This is the TLS hybrid-group share, not a signature. |
| `PqEcdsaP256`, `PqEcdsaP384` | Signatures. P-384 sign is not `p384SharedSecret`. |
| `PqEd25519` | RFC 8032 sign and verify, synchronous. |
| `PqRsa` | PKCS#1 v1.5 and RSASSA-PSS. |
| `PqForgeHybridKeyAgreement` | X25519 concatenated with ML-KEM, then a KDF. Confidentiality holds while either problem stands. |
| `PqForgeHybridSigner` | ML-DSA plus Ed25519 or ECDSA P-256 over the same message. |

HPKE's P-256 and P-384 KEMs call `PqNistEcdh`. They do not call the ECDSA
signers. An uncompressed public key that fails the curve check does not
produce a shared secret.

Hybrid encryption and hybrid signatures are application constructions.
They are not RFC 9180, and RFC 9180 is not a hybrid KEM in the TLS sense.
X25519MLKEM768 lives in pqtransport, which calls `PqForgeCombiner` for the
concatenation and uses this package's X25519 and ML-KEM.
