# Claim Boundary

Allowed claims:

- FIPS 203-aligned ML-KEM through `pqcrypto`.
- FIPS 204-aligned ML-DSA through `pqcrypto`.
- FIPS 205-aligned SLH-DSA through `pqcrypto`. `pqforge` uses it for
  `keygen`, custody, detached `sign`/`verify`, conversation bundle trust,
  one header signature per envelope or `.pqfs` container, and `hybrid-sign`
  version 2. X.509 stays ML-DSA. An ML-DSA key still signs with ML-DSA.
- Application-layer composition helpers for KEM-DEM, AEAD sessions, wrapped key
  custody, signatures, recipes, and CLI workflows.
- X.509 certificates and PKCS#10 requests that `openssl req` can read. That
  is not a WebPKI CA and not a trust store.
- RFC 9180 HPKE over X25519, X448, P-256, P-384, and P-521. Not a FIPS
  module and not TLS. BoringSSL evidence is base and auth on X25519 and
  P-256. OpenSSL evidence is all four modes on X448 and P-521. `PqX448` is
  not a constant-time claim. X-Wing (`PqXWing`, `HpkeKem.xWing`, `0x647A`)
  is an additional KEM. It is not a FIPS construction, not an authenticated
  KEM, and not a `.pqf` algorithm. There is no BoringSSL or OpenSSL
  evidence for that id.
- Best-effort zeroization in Dart.

Forbidden claims:

- FIPS validated.
- FIPS 140 validated.
- CMVP validated.
- Certified.
- Hard constant-time Dart guarantee.
- Hard memory-erasure guarantee.
- ML-KEM alone is secure transport.
- AES signs documents.
- RC4 is supported.

RC4 is rejected. AES encrypts; ML-DSA or SLH-DSA signs. SLH-DSA is composed
into `keygen` and detached signatures, not into envelopes or `hybrid-sign`.
