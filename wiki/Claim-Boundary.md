# Claim Boundary

Allowed claims:

- FIPS 203-aligned ML-KEM through `pqcrypto`.
- FIPS 204-aligned ML-DSA through `pqcrypto`.
- Application-layer composition helpers for KEM-DEM, AEAD sessions, wrapped key
  custody, signatures, recipes, and CLI workflows.
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

RC4 is rejected. AES encrypts; ML-DSA signs.
