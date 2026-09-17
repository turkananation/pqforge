# Hybrid Sessions

Import `package:pqforge/pqforge.dart` when the app wants pqforge to
own the classical side too.

Use:

- `PqForgeHybridKeyAgreement` for X25519 + ML-KEM session key agreement;
- `PqNistEcdh` / `PqForgeHybridKeyAgreement.p256SharedSecret` /
  `p384SharedSecret` for NIST-curve ECDH (uncompressed SEC1, x-coordinate
  secret) — TLS hybrid groups, not the X25519 `initiate`/`accept` handshake;
- `PqForgeHybridSigner` for ML-DSA + Ed25519 or ECDSA-P256 dual signatures;
- `PqForgeSecureSession` for AES-256-GCM or ChaCha20-Poly1305 packets;
- `PqSymmetricPrimitives.chacha20Poly1305Encrypt` when the caller owns the
  nonce (TLS/QUIC records). Dart engine; dart2js-safe. Check
  `supportsChaCha20Poly1305` rather than PointyCastle's mantissa test.
- `SecretKey.deriveHybridSecretKey()` for `package:cryptography` users.

RFC 10024 X25519MLKEM768 concatenation is `ss_mlkem || ss_x25519` with **no**
inner HKDF. Use `PqForgeCombiner.concatenateSharedSecrets(order:
PqHybridConcatOrder.pqThenClassical)`. Do not call `combine()` for that group.

The application still owns public-key trust, replay protection, session storage,
authorization policy, and transport policy.

ECDSA over NIST P-256 is built in (`PqEcdsaP256`, pure-Dart PointyCastle);
`dualSign` / `dualVerify` remain for other app-supplied classical schemes.
ECDH over P-256/P-384 is `PqNistEcdh`, not `PqEcdsaP256`. SLH-DSA is a
composed detached-signature family (`keygen` / `sign`) and is not a
`PqForgeHybridSigner` leg.
