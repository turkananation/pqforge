/// High-level post-quantum composition helpers for Dart, Flutter, and Serverpod.
///
/// `pqforge` exposes its entire public API through this single entrypoint:
///
/// ```dart
/// import 'package:pqforge/pqforge.dart';
/// ```
///
/// From here you get the full stack:
///
/// * the [PqForge] facade — key generation, ML-KEM/ML-DSA, KEM-DEM envelopes,
///   document/artifact signing, key custody, and recipes;
/// * hybrid key derivation — [PqForgeCombiner] (raw bytes) and the
///   [PqForgeCryptographyExtensions] `SecretKey.deriveHybridSecretKey` ergonomic;
/// * batteries-included classical + post-quantum hybrid —
///   [PqForgeHybridKeyAgreement] (X25519 + ML-KEM), [PqForgeHybridSigner]
///   (ML-DSA + Ed25519), and hybrid KEM-DEM envelopes ([PqForgeAsync]
///   `encryptAsync`/`decryptAsync` with [PqHybridKemDem]);
/// * AEAD wire packets — [PqForgeSecureSession] over AES-256-GCM or
///   ChaCha20-Poly1305, on either the pure-Dart PointyCastle or the native
///   `package:cryptography` backend ([PqForgeEngineProvider]).
///
/// The pure-Dart pieces ([PqForgeCombiner], [PqForgePointyCastleAeadEngine]) use
/// only PointyCastle internally; the hybrid, native-AEAD, and `SecretKey` pieces
/// use `package:cryptography`. Unused backends are tree-shaken from release
/// builds, so you only pay for the APIs you actually call.
library;

export 'src/cipher/pq_cipher_suite.dart';
export 'src/cipher/pq_cryptography_aead_engine.dart';
export 'src/cipher/pq_pointycastle_aead_engine.dart';
export 'src/cipher/pq_secure_session.dart';
export 'src/hybrid/pq_classical_hybrid.dart';
export 'src/hybrid/pq_cryptography_extensions.dart';
export 'src/hybrid/pq_ecdsa_p256.dart';
export 'src/hybrid/pq_hybrid_combiner.dart';
export 'src/pqforge_base.dart';
export 'src/services/pqforge_async_service.dart';
