/// Swappable backend for the **classical** primitives of the hybrid layer —
/// X25519 key agreement, Ed25519 and ECDSA-P256 signatures.
///
/// This is the classical counterpart to [PqLatticeProvider]. Today these
/// operations run as pure-Dart `package:cryptography` (X25519/Ed25519) and
/// PointyCastle ([PqEcdsaP256]) code; this seam lets a host register a
/// hardware-accelerated backend (e.g. an FFI binding to AWS-LC / BoringSSL)
/// **without changing any caller**. The byte-oriented classical operations of
/// [PqForgeHybridSigner] and the static [PqForgeHybridKeyAgreement.x25519SharedSecret]
/// delegate their raw crypto here.
///
/// The default is [PqPureDartClassicalProvider]. A replacement is validated with
/// the conformance/agreement harness in `test/support/classical_conformance.dart`.
///
/// **Determinism contract (what a native backend must match byte-for-byte):**
/// * **X25519 ECDH** — deterministic; the shared secret must be identical.
/// * **Ed25519** — deterministic per RFC 8032; seeded keygen *and* signatures
///   must be identical.
/// * **ECDSA-P256** — implementation-dependent (pqforge uses RFC-6979 + low-S;
///   AWS-LC is randomized). Only **cross-verification** is required, not
///   byte-identical signatures.
///
/// All methods are async so a single interface serves both the naturally-async
/// `package:cryptography` backend and a synchronous FFI backend (which wraps its
/// results in `Future.value`).
library;

import 'dart:typed_data';

import 'package:cryptography/cryptography.dart' as crypto;

import 'pq_ecdsa_p256.dart';

/// The raw classical operations behind the hybrid layer. Implementations own
/// only the cryptography; the callers keep their own length/validation checks.
abstract interface class PqClassicalProvider {
  /// Stable identifier for diagnostics (e.g. `'pure-dart-cryptography'`).
  String get name;

  // --- X25519 key agreement (raw 32-byte keys & shared secret) ---

  Future<({Uint8List publicKey, Uint8List secretKey})> x25519GenerateKeyPair({
    Uint8List? seed,
  });

  /// X25519 ECDH between our 32-byte [secretKey] (which is also its seed) and a
  /// 32-byte [remotePublicKey], returning the 32-byte shared secret.
  Future<Uint8List> x25519SharedSecret({
    required Uint8List secretKey,
    required Uint8List remotePublicKey,
  });

  // --- Ed25519 signatures (32-byte public key & seed, 64-byte signature) ---

  Future<({Uint8List publicKey, Uint8List secretKey})> ed25519GenerateKeyPair({
    Uint8List? seed,
  });

  Future<Uint8List> ed25519PublicKeyFromSeed(Uint8List seed);

  Future<Uint8List> ed25519Sign({
    required Uint8List secretKey,
    required Uint8List publicKey,
    required Uint8List message,
  });

  Future<bool> ed25519Verify({
    required Uint8List publicKey,
    required Uint8List message,
    required Uint8List signature,
  });

  // --- ECDSA-P256 signatures (32-byte scalar, 65-byte SEC1 pk, 64-byte r||s) ---

  Future<({Uint8List publicKey, Uint8List secretKey})> ecdsaP256GenerateKeyPair();

  Future<Uint8List> ecdsaP256PublicKeyFromPrivate(Uint8List secretKey);

  Future<Uint8List> ecdsaP256Sign({
    required Uint8List secretKey,
    required Uint8List message,
  });

  Future<bool> ecdsaP256Verify({
    required Uint8List publicKey,
    required Uint8List message,
    required Uint8List signature,
  });
}

/// The built-in pure-Dart backend: `package:cryptography` for X25519/Ed25519 and
/// [PqEcdsaP256] (PointyCastle, RFC-6979) for ECDSA-P256. Always present; the
/// fallback when no native provider is registered.
final class PqPureDartClassicalProvider implements PqClassicalProvider {
  const PqPureDartClassicalProvider();

  @override
  String get name => 'pure-dart-cryptography';

  @override
  Future<({Uint8List publicKey, Uint8List secretKey})> x25519GenerateKeyPair({
    Uint8List? seed,
  }) async {
    final x25519 = crypto.X25519();
    final keyPair = seed == null
        ? await x25519.newKeyPair()
        : await x25519.newKeyPairFromSeed(seed);
    try {
      final publicKey = await keyPair.extractPublicKey();
      return (
        publicKey: Uint8List.fromList(publicKey.bytes),
        secretKey: Uint8List.fromList(await keyPair.extractPrivateKeyBytes()),
      );
    } finally {
      keyPair.destroy();
    }
  }

  @override
  Future<Uint8List> x25519SharedSecret({
    required Uint8List secretKey,
    required Uint8List remotePublicKey,
  }) async {
    final x25519 = crypto.X25519();
    // An X25519 secret key IS its seed, so the key pair is reconstructible.
    final keyPair = await x25519.newKeyPairFromSeed(secretKey);
    try {
      final shared = await x25519.sharedSecretKey(
        keyPair: keyPair,
        remotePublicKey: crypto.SimplePublicKey(
          remotePublicKey,
          type: crypto.KeyPairType.x25519,
        ),
      );
      return Uint8List.fromList(await shared.extractBytes());
    } finally {
      keyPair.destroy();
    }
  }

  @override
  Future<({Uint8List publicKey, Uint8List secretKey})> ed25519GenerateKeyPair({
    Uint8List? seed,
  }) async {
    final ed25519 = crypto.Ed25519();
    final keyPair = seed == null
        ? await ed25519.newKeyPair()
        : await ed25519.newKeyPairFromSeed(seed);
    try {
      final publicKey = await keyPair.extractPublicKey();
      return (
        publicKey: Uint8List.fromList(publicKey.bytes),
        secretKey: Uint8List.fromList(await keyPair.extractPrivateKeyBytes()),
      );
    } finally {
      keyPair.destroy();
    }
  }

  @override
  Future<Uint8List> ed25519PublicKeyFromSeed(Uint8List seed) async {
    final keyPair = await crypto.Ed25519().newKeyPairFromSeed(seed);
    try {
      final publicKey = await keyPair.extractPublicKey();
      return Uint8List.fromList(publicKey.bytes);
    } finally {
      keyPair.destroy();
    }
  }

  @override
  Future<Uint8List> ed25519Sign({
    required Uint8List secretKey,
    required Uint8List publicKey,
    required Uint8List message,
  }) async {
    final signature = await crypto.Ed25519().sign(
      message,
      keyPair: crypto.SimpleKeyPairData(
        secretKey,
        publicKey: crypto.SimplePublicKey(
          publicKey,
          type: crypto.KeyPairType.ed25519,
        ),
        type: crypto.KeyPairType.ed25519,
      ),
    );
    return Uint8List.fromList(signature.bytes);
  }

  @override
  Future<bool> ed25519Verify({
    required Uint8List publicKey,
    required Uint8List message,
    required Uint8List signature,
  }) {
    if (publicKey.length != 32 || signature.length != 64) {
      return Future.value(false);
    }
    return crypto.Ed25519().verify(
      message,
      signature: crypto.Signature(
        signature,
        publicKey: crypto.SimplePublicKey(
          publicKey,
          type: crypto.KeyPairType.ed25519,
        ),
      ),
    );
  }

  @override
  Future<({Uint8List publicKey, Uint8List secretKey})>
  ecdsaP256GenerateKeyPair() async {
    final pair = PqEcdsaP256.generateKeyPair();
    return (publicKey: pair.publicKey, secretKey: pair.secretKey);
  }

  @override
  Future<Uint8List> ecdsaP256PublicKeyFromPrivate(Uint8List secretKey) async =>
      PqEcdsaP256.publicKeyFromPrivate(secretKey);

  @override
  Future<Uint8List> ecdsaP256Sign({
    required Uint8List secretKey,
    required Uint8List message,
  }) async => PqEcdsaP256.sign(privateKey: secretKey, message: message);

  @override
  Future<bool> ecdsaP256Verify({
    required Uint8List publicKey,
    required Uint8List message,
    required Uint8List signature,
  }) async => PqEcdsaP256.verify(
    publicKey: publicKey,
    message: message,
    signature: signature,
  );
}

/// Process-wide registry for the active [PqClassicalProvider].
///
/// Register a native backend once at startup, before any hybrid crypto:
///
/// ```dart
/// PqClassical.provider = MyAwsLcClassicalProvider(); // validated by the harness
/// ```
abstract final class PqClassical {
  /// The backend the byte-oriented classical operations delegate to. Defaults to
  /// the built-in pure-Dart provider; assign a native backend at startup.
  static PqClassicalProvider provider = const PqPureDartClassicalProvider();

  /// Restores the built-in pure-Dart backend.
  static void useDefault() => provider = const PqPureDartClassicalProvider();
}
