# Claim Boundary

Allowed wording:

- FIPS 203-aligned ML-KEM through `pqcrypto`.
- FIPS 204-aligned ML-DSA through `pqcrypto`.
- Checked evidence inherited from the upstream `pqcrypto` package.
- Best-effort cleanup in Dart.

Forbidden wording:

- FIPS validated.
- CMVP validated.
- Certified.
- Hard constant-time guarantee.
- Hard secure-erasure guarantee.
- ML-KEM alone is secure transport.
