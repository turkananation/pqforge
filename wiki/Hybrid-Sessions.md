# Hybrid Sessions

Import `package:pqforge/pqforge.dart` when the app wants pqforge to
own the classical side too.

Use:

- `PqForgeHybridKeyAgreement` for X25519 + ML-KEM session key agreement;
- `PqForgeHybridSigner` for ML-DSA + Ed25519 dual signatures;
- `PqForgeSecureSession` for AES-256-GCM or ChaCha20-Poly1305 packets;
- `SecretKey.deriveHybridSecretKey()` for `package:cryptography` users.

The application still owns public-key trust, replay protection, session storage,
authorization policy, and transport policy.

ECDSA remains app-supplied through `dualSign` / `dualVerify`.
