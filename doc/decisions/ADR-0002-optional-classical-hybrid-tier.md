# ADR-0002: Optional Classical Hybrid Tier

## Status

Accepted on 2026-06-07. Updated 2026-06-08: the classical hybrid tier was folded
into the single `package:pqforge/pqforge.dart` entrypoint — there is no longer a
separate `pqforge_cryptography.dart` import — and ECDSA-P256 was added as a
built-in classical signature option (see Consequences). The core decision stands.

## Context

ADR-0001 keeps the core package boundary narrow: `pqforge` composes
post-quantum primitives from `pqcrypto` with KDF, AEAD, envelopes, and recipes,
while applications own public-key trust and most classical protocol choices.

The cookbook and universal framework still need a complete local/server path for
hybrid key exchange and hybrid signatures. Without that, users can compose the
pieces, but they do not get a fully runnable "batteries included" flow.

## Decision

Add a built-in classical hybrid tier, exported from the single
`package:pqforge/pqforge.dart` entrypoint.

- `PqForgeHybridKeyAgreement` owns X25519 + ML-KEM session derivation.
- `PqForgeHybridSigner` owns ML-DSA + Ed25519 dual signatures.
- `PqForgeSecureSession` continues to own AEAD wire packets for traffic keys.
- The pure-Dart core (the facade, PointyCastle-backed primitives, and
  app-supplied classical hooks) keeps using only PointyCastle internally, so
  applications that avoid the hybrid APIs do not exercise `package:cryptography`.

## Consequences

- Server and CLI users can run a complete hybrid flow without writing their own
  X25519 or Ed25519 glue.
- The hybrid tier pulls in `package:cryptography`, which is now a standard
  dependency; unused backends are tree-shaken from release builds.
- ECDSA over NIST P-256 is a built-in classical option (`PqEcdsaP256`, pure-Dart
  PointyCastle with RFC 6979 deterministic nonces and low-S signatures), because
  `cryptography 2.9.0` cannot generate P-256 keys on the Dart VM. `dualSign` /
  `dualVerify` remain for any other app-supplied classical signature scheme.
- RC4 is not supported. It is not PQC, not AEAD, and not acceptable for new
  encrypted payloads.

## Validation

The tier is covered by `test/pq_classical_hybrid_test.dart`, which verifies:

- X25519 + ML-KEM client/server session-key agreement.
- Transcript tampering rejection.
- ML-DSA + Ed25519 dual signatures with JSON round trip.
