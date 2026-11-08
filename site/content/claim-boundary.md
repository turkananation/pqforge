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
- Opt-in signature legs in the same release: `slhDsa:` on detached recipes,
  `compose-sign` (2 or 3 legs), and ECDSA-P384 / ECDSA-P521. `hybrid-sign`
  stays one ML-DSA leg plus one classical leg.
- Best-effort zeroization through `package:zeroize`.
- Brainpool ECDH (RFC 5639, the three TLS groups) and RFC 7919 FFDHE as
  agreement. The byte contract matches OpenSSL. Not a TLS stack.

Not allowed:

- FIPS validated, FIPS 140 validated, CMVP validated, certified.
- A hard constant-time Dart guarantee.
- A hard memory-erasure guarantee. `dispose` on an HPKE context scrubs the
  buffers it holds. Copies the runtime already made are outside that call.
- "ML-KEM alone is secure transport." Transport is pqtransport.
- "AES signs documents." AES encrypts. ML-DSA, SLH-DSA, ECDSA, Ed25519, or
  RSA signs.
- RC4.
- HPKE as a FIPS module or as TLS.
- An OpenSSL HPKE claim for X25519, P-256, or P-384.
- A BoringSSL HPKE claim for X448, P-521, PSK, or HKDF-SHA512.
- A certificate as a WebPKI CA or a trust store.
- ECDSA-P521 as a TLS group, or as the HPKE P-521 share. `PqEcdsaP521`
  signs. `PqNistEcdh.p521SharedSecret` is still the HPKE share.
- `compose-sign` as a FIPS module, or as a constant-time construction.
- SLH-DSA inside an envelope or inside `hybrid-sign`. A composite leg is
  opt-in and stays outside those two.
- `PqBrainpool` or `PqFfdhe` as a TLS handshake, as constant-time, or as
  a NIST curve. There is no NIST P-512. brainpoolP512r1 is RFC 5639.
- BoringSSL 0.20261020.0 as a check of ML-KEM-512 or of any SLH-DSA set
  other than SHA2-128s and SHAKE-256f. Those two, plus ML-KEM-768,
  ML-KEM-1024, and ML-DSA-44/65/87, are what that pin exports. The other
  ten SLH-DSA sets are checked against OpenSSL 4.1.0.

BoringSSL 0.20261020.0 is a checked HPKE peer for base and auth, X25519 and
P-256, HKDF-SHA256 and HKDF-SHA384, and the three AEADs.

OpenSSL 3.5.9 is a checked HPKE peer for all four modes, X448 and P-521,
HKDF-SHA256 and HKDF-SHA512, and the three AEADs. P-384 HPKE stays a round
trip. It is not in that OpenSSL sentence.

The repository copy of this boundary is
`doc/security/CLAIM_BOUNDARY.md`.
