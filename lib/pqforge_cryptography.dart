/// Optional `package:cryptography`-powered layer for pqforge.
///
/// Import this entrypoint (instead of, or alongside, `package:pqforge/pqforge.dart`)
/// when you want either:
///
/// * the type-safe `SecretKey` hybrid-combiner extension
///   ([PqForgeCryptographyExtensions] — combiner **Option B**), or
/// * the native (`package:cryptography`) AEAD backend for
///   [PqForgeSecureSession] ([PqForgeEngineProvider.nativeCryptography]).
///
/// ```dart
/// import 'package:pqforge/pqforge_cryptography.dart';
/// ```
///
/// The zero-dependency core — [PqForgeCombiner] / [PqHybridProfile], the cipher
/// enums, and the pure-Dart [PqForgePointyCastleAeadEngine] — is also available
/// on its own from `package:pqforge/pqforge.dart`, which does not pull in
/// `package:cryptography`. It is re-exported here for convenience.
library;

export 'src/cipher/pq_cipher_suite.dart';
export 'src/cipher/pq_cryptography_aead_engine.dart';
export 'src/cipher/pq_pointycastle_aead_engine.dart';
export 'src/cipher/pq_secure_session.dart';
export 'src/hybrid/pq_classical_hybrid.dart';
export 'src/hybrid/pq_cryptography_extensions.dart';
export 'src/hybrid/pq_hybrid_combiner.dart';
