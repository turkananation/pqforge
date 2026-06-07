# ADR-0002: Optional Classical Hybrid Tier

## Status

Accepted on 2026-06-07.

## Context

ADR-0001 keeps the core package boundary narrow: `pqforge` composes
post-quantum primitives from `pqcrypto` with KDF, AEAD, envelopes, and recipes,
while applications own public-key trust and most classical protocol choices.

The cookbook and universal framework still need a complete local/server path for
hybrid key exchange and hybrid signatures. Without that, users can compose the
pieces, but they do not get a fully runnable "batteries included" flow.

## Decision

Add a built-in classical hybrid tier behind
`package:pqforge/pqforge_cryptography.dart`.

- `PqForgeHybridKeyAgreement` owns X25519 + ML-KEM session derivation.
- `PqForgeHybridSigner` owns ML-DSA + Ed25519 dual signatures.
- `PqForgeSecureSession` continues to own AEAD wire packets for traffic keys.
- The default `package:pqforge/pqforge.dart` entrypoint remains focused on the
  core facade, PointyCastle-backed primitives, and app-supplied classical hooks.

## Consequences

- Server and CLI users can run a complete hybrid flow without writing their own
  X25519 or Ed25519 glue.
- The optional tier pulls in `package:cryptography`, so it remains outside the
  core entrypoint.
- ECDSA remains app-supplied through `dualSign` / `dualVerify` because
  `cryptography 2.9.0` does not implement Dart VM P-256 key generation.
- RC4 is not supported. It is not PQC, not AEAD, and not acceptable for new
  encrypted payloads.

## Validation

The tier is covered by `test/pq_classical_hybrid_test.dart`, which verifies:

- X25519 + ML-KEM client/server session-key agreement.
- Transcript tampering rejection.
- ML-DSA + Ed25519 dual signatures with JSON round trip.
