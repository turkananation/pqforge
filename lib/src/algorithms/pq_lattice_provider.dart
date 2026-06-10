/// Swappable backend for the lattice (ML-KEM / ML-DSA) primitives.
///
/// Today every lattice operation runs as pure-Dart scalar NTT arithmetic in
/// `pqcrypto` — the throughput wall for per-file PQC in tight folder loops. This
/// seam lets a host register a hardware-accelerated backend (e.g. an FFI binding
/// to a NEON/AVX2-optimised PQClean or liboqs build) **without changing any
/// caller**: [PqKemPrimitives] and [PqSignaturePrimitives] delegate their raw
/// crypto here while keeping their own length/validation checks.
///
/// The default is [PqPureDartLatticeProvider]; a replacement must produce
/// byte-identical results for the deterministic operations (validate it with the
/// conformance/agreement harness in `test/support/lattice_conformance.dart`).
library;

import 'dart:typed_data';

import 'package:pqcrypto/pqcrypto.dart';

import 'pq_algorithms.dart';

/// The raw lattice operations behind [PqKemPrimitives] / [PqSignaturePrimitives].
///
/// Implementations perform **no** length validation (the primitives do that);
/// they own only the cryptography. Records are `(publicKey, secretKey)` and
/// `(ciphertext, sharedSecret)`.
abstract interface class PqLatticeProvider {
  /// A stable identifier for diagnostics/telemetry (e.g. `'pure-dart-pqcrypto'`,
  /// `'pqclean-ffi'`).
  String get name;

  (Uint8List publicKey, Uint8List secretKey) kemGenerateKeyPair(
    PqKemAlgorithm algorithm, {
    Uint8List? seed,
  });

  (Uint8List ciphertext, Uint8List sharedSecret) kemEncapsulate(
    PqKemAlgorithm algorithm,
    Uint8List publicKey, {
    Uint8List? nonce,
  });

  Uint8List kemDecapsulate(
    PqKemAlgorithm algorithm,
    Uint8List secretKey,
    Uint8List ciphertext,
  );

  (Uint8List publicKey, Uint8List secretKey) dsaGenerateKeyPair(
    PqSignatureAlgorithm algorithm,
  );

  (Uint8List publicKey, Uint8List secretKey) dsaGenerateKeyPairSeeded(
    PqSignatureAlgorithm algorithm,
    Uint8List seed,
  );

  Uint8List dsaSign(
    PqSignatureAlgorithm algorithm,
    Uint8List secretKey,
    Uint8List message, {
    Uint8List? context,
    bool preHash = false,
  });

  bool dsaVerify(
    PqSignatureAlgorithm algorithm,
    Uint8List publicKey,
    Uint8List message,
    Uint8List signature, {
    Uint8List? context,
    bool preHash = false,
  });
}

/// The built-in pure-Dart backend (`pqcrypto` on PointyCastle). Always present;
/// the fallback when no native provider is registered.
final class PqPureDartLatticeProvider implements PqLatticeProvider {
  const PqPureDartLatticeProvider();

  @override
  String get name => 'pure-dart-pqcrypto';

  @override
  (Uint8List, Uint8List) kemGenerateKeyPair(
    PqKemAlgorithm algorithm, {
    Uint8List? seed,
  }) => _kem(algorithm).generateKeyPair(seed);

  @override
  (Uint8List, Uint8List) kemEncapsulate(
    PqKemAlgorithm algorithm,
    Uint8List publicKey, {
    Uint8List? nonce,
  }) => _kem(algorithm).encapsulate(publicKey, nonce);

  @override
  Uint8List kemDecapsulate(
    PqKemAlgorithm algorithm,
    Uint8List secretKey,
    Uint8List ciphertext,
  ) => _kem(algorithm).decapsulate(secretKey, ciphertext);

  @override
  (Uint8List, Uint8List) dsaGenerateKeyPair(PqSignatureAlgorithm algorithm) =>
      MlDsa.generateKeyPair(_params(algorithm));

  @override
  (Uint8List, Uint8List) dsaGenerateKeyPairSeeded(
    PqSignatureAlgorithm algorithm,
    Uint8List seed,
  ) => MlDsa.generateKeyPairSeeded(_params(algorithm), seed);

  @override
  Uint8List dsaSign(
    PqSignatureAlgorithm algorithm,
    Uint8List secretKey,
    Uint8List message, {
    Uint8List? context,
    bool preHash = false,
  }) {
    final params = _params(algorithm);
    return preHash
        ? MlDsa.hashSign(secretKey, message, params, ctx: context)
        : MlDsa.sign(secretKey, message, params, ctx: context);
  }

  @override
  bool dsaVerify(
    PqSignatureAlgorithm algorithm,
    Uint8List publicKey,
    Uint8List message,
    Uint8List signature, {
    Uint8List? context,
    bool preHash = false,
  }) {
    final params = _params(algorithm);
    return preHash
        ? MlDsa.hashVerify(publicKey, message, signature, params, ctx: context)
        : MlDsa.verify(publicKey, message, signature, params, ctx: context);
  }

  static KyberKem _kem(PqKemAlgorithm algorithm) => switch (algorithm) {
    PqKemAlgorithm.mlKem512 => PqcKem.kyber512,
    PqKemAlgorithm.mlKem768 => PqcKem.kyber768,
    PqKemAlgorithm.mlKem1024 => PqcKem.kyber1024,
  };

  static DilithiumParams _params(PqSignatureAlgorithm algorithm) =>
      switch (algorithm) {
        PqSignatureAlgorithm.mlDsa44 => DilithiumParams.mlDsa44,
        PqSignatureAlgorithm.mlDsa65 => DilithiumParams.mlDsa65,
        PqSignatureAlgorithm.mlDsa87 => DilithiumParams.mlDsa87,
      };
}

/// Process-wide registry for the active [PqLatticeProvider].
///
/// Register a native backend once at startup, before any crypto:
///
/// ```dart
/// PqLattice.provider = MyPqCleanFfiProvider(); // validated by the conformance harness
/// ```
abstract final class PqLattice {
  /// The backend all lattice primitives currently delegate to. Defaults to the
  /// built-in pure-Dart provider; assign a native backend at startup.
  static PqLatticeProvider provider = const PqPureDartLatticeProvider();

  /// Restores the built-in pure-Dart backend.
  static void useDefault() => provider = const PqPureDartLatticeProvider();
}
