---
title: Claim boundary
description: What pqforge is allowed to say about itself.
---

Allowed:

- FIPS 203-aligned ML-KEM, FIPS 204-aligned ML-DSA, and FIPS 205-aligned
  SLH-DSA, through pqcrypto. SLH-DSA is keygen, custody, and detached
  sign/verify. Envelopes and hybrid-sign stay ML-DSA.
- Application composition: KEM-DEM, AEAD sessions, hybrids, streaming,
  multi-recipient envelopes, wrapped keys, recipes, X.509, PKCS#10,
  RFC 9180 HPKE, and the CLI.
- Best-effort zeroization through `package:zeroize`.

Not allowed:

- FIPS validated, FIPS 140 validated, CMVP validated, certified.
- A hard constant-time Dart guarantee.
- A hard memory-erasure guarantee. `dispose` on an HPKE context scrubs the
  buffers it holds. Copies the runtime already made are outside that call.
- "ML-KEM alone is secure transport." Transport is pqtransport.
- "AES signs documents." AES encrypts. ML-DSA, SLH-DSA, ECDSA, Ed25519, or
  RSA signs.
- RC4.
- HPKE as a FIPS module, as TLS, or as an OpenSSL interop claim.
- A certificate as a WebPKI CA or a trust store.

BoringSSL 0.20261020.0 is a checked HPKE peer for base and auth, X25519 and
P-256, HKDF-SHA256 and HKDF-SHA384, and the three AEADs. PSK, P-384 HPKE,
HKDF-SHA512 HPKE, X448, and P-521 are outside that sentence.

The repository copy of this boundary is
`doc/security/CLAIM_BOUNDARY.md`.
