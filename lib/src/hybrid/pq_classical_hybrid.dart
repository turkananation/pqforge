/// Batteries-included classical + post-quantum hybrid helpers.
///
/// Provides X25519 + ML-KEM key agreement (via `package:cryptography`) and
/// hybrid signatures pairing ML-DSA with a classical signature — Ed25519
/// (`package:cryptography`) or ECDSA over NIST P-256 ([PqEcdsaP256], pure-Dart
/// PointyCastle). Surfaced through the single `package:pqforge/pqforge.dart`
/// entrypoint.
library;

import 'dart:typed_data';

import 'package:pqforge/pqforge_io.dart';
import 'package:pqforge/src/exceptions/pqforge_exception.dart';

enum PqClassicalKeyAgreementAlgorithm {
  x25519(id: 'x25519', publicKeyBytes: 32, sharedSecretBytes: 32);

  const PqClassicalKeyAgreementAlgorithm({
    required this.id,
    required this.publicKeyBytes,
    required this.sharedSecretBytes,
  });

  final String id;
  final int publicKeyBytes;
  final int sharedSecretBytes;

  static PqClassicalKeyAgreementAlgorithm byId(String id) {
    for (final value in values) {
      if (value.id == id) return value;
    }
    throw PqForgeException('Unsupported classical KEX algorithm: $id');
  }
}

enum PqClassicalSignatureAlgorithm {
  ed25519(
    id: 'ed25519',
    publicKeyBytes: 32,
    secretKeyBytes: 32,
    signatureBytes: 64,
  ),
  ecdsaP256(
    id: 'ecdsa-p256',
    publicKeyBytes: 65,
    secretKeyBytes: 32,
    signatureBytes: 64,
  );

  const PqClassicalSignatureAlgorithm({
    required this.id,
    required this.publicKeyBytes,
    required this.secretKeyBytes,
    required this.signatureBytes,
  });

  final String id;

  /// Public-key length in bytes (Ed25519: 32; ECDSA-P256 uncompressed: 65).
  final int publicKeyBytes;

  /// Secret-key length in bytes (the 32-byte Ed25519 seed / EC scalar).
  final int secretKeyBytes;

  /// Signature length in bytes (Ed25519: 64; ECDSA-P256 raw `r||s`: 64).
  final int signatureBytes;

  static PqClassicalSignatureAlgorithm byId(String id) {
    for (final value in values) {
      if (value.id == id) return value;
    }
    throw PqForgeException('Unsupported classical signature algorithm: $id');
  }
}

/// A classical signature key pair as raw bytes, so both backends — Ed25519 via
/// `package:cryptography` and ECDSA-P256 via [PqEcdsaP256] — share one type.
class PqClassicalSignatureKeyPair {
  PqClassicalSignatureKeyPair({
    required this.algorithm,
    required Uint8List publicKey,
    required Uint8List secretKey,
  }) : publicKey = PqBytes.copy(publicKey),
       secretKey = PqBytes.copy(secretKey) {
    requireLength('publicKey', this.publicKey, algorithm.publicKeyBytes);
    requireLength('secretKey', this.secretKey, algorithm.secretKeyBytes);
  }

  final PqClassicalSignatureAlgorithm algorithm;
  final Uint8List publicKey;
  final Uint8List secretKey;
}
