---
title: Classical
description: X25519, NIST ECDH, Ed25519, ECDSA, and RSA next to ML-KEM and ML-DSA.
---

Classical algorithms in pqforge are a tier next to pqcrypto, not a
replacement for it. Key agreement for brainpool, RFC 7919, NIST ECDH,
X25519, and X448 is documented on [Agreement](agreement), including the
byte widths and the rejection rules. This page is the signature tier and
the hybrid constructions that sit on top.

| API | Role |
| --- | --- |
| `PqClassical` X25519 | Key agreement. The secret is the 32-byte seed. Used by hybrid KEM-DEM and by HPKE. Widths and rejection rules are on [Agreement](agreement). |
| `PqX448` | RFC 7748 X448. 56-byte keys. Used by DHKEM(X448, HKDF-SHA512). Not a constant-time ladder. |
| `PqNistEcdh` | P-256, P-384, and P-521 ECDH. Uncompressed SEC1 points. The shared secret is the x-coordinate. P-256 and P-384 are the TLS hybrid-group shares. P-521 ECDH is the HPKE share, not a TLS group, and not a signature. |
| `PqEcdsaP256`, `PqEcdsaP384` | Signatures. P-384 sign is not `p384SharedSecret`. |
| `PqEcdsaP521` | Signature only. SHA-512, low-S on sign. Not `p521SharedSecret`, not HPKE, and not a TLS group. Opt in with `keygen --classical ecdsa-p521`. |
| `PqEd25519` | RFC 8032 sign and verify, synchronous. |
| `PqEd448` | RFC 8032 Ed448, synchronous. Empty context is DNSSEC algorithm 16. `preHash: true` is Ed448ph. Not an X.509 algorithm and not a TLS scheme. |
| `PqRsa` | PKCS#1 v1.5 and RSASSA-PSS. |
| `PqForgeHybridKeyAgreement` | X25519 concatenated with ML-KEM, then a KDF. Confidentiality holds while either problem stands. |
| `PqForgeHybridSigner` | ML-DSA plus one classical signature over the same message. The classical leg is Ed25519 or ECDSA-P256, and it may now also be ECDSA-P384 or ECDSA-P521. |
| `PqForgeSignatureComposer` | Opt-in dual (2) or triple (3). See [Signatures](signatures). |

HPKE's P-256, P-384, and P-521 KEMs call `PqNistEcdh`. DHKEM(X448) calls
`PqX448`. They do not call the ECDSA signers. An uncompressed public key
that fails the curve check does not produce a shared secret.

Hybrid encryption and hybrid signatures are application constructions.
They are not RFC 9180, and RFC 9180 is not a hybrid KEM in the TLS sense.
X25519MLKEM768 lives in pqtransport, which calls `PqForgeCombiner` for the
concatenation and uses this package's X25519 and ML-KEM.
