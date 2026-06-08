# Claim Boundary

Allowed wording:

- FIPS 203-aligned ML-KEM through `pqcrypto`.
- FIPS 204-aligned ML-DSA through `pqcrypto`.
- Application-layer composition helpers for KEM-DEM, AEAD sessions, wrapped key
  custody, signatures, recipes, hybrid helpers, and CLI workflows.
- Best-effort cleanup in Dart.

Forbidden wording:

- FIPS validated.
- FIPS 140 validated.
- CMVP validated.
- Certified.
- Hard constant-time guarantee.
- Hard secure-erasure guarantee.
- ML-KEM alone is secure transport.
- AES signs documents.
- RC4 is supported.

`pqforge` can inherit algorithm-evidence wording from `pqcrypto`, but it must not
upgrade that into module-validation wording. Public-key trust, identity vetting,
authorization policy, replay stores, legal policy, and infrastructure custody
remain application responsibilities.
