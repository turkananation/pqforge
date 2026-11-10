/// Pure-Dart ECDSA over NIST P-521 (secp521r1) via PointyCastle.
///
/// This is a signature, not the P-521 ECDH share used by HPKE. [PqNistEcdh]
/// returns a 66-byte x-coordinate. This class takes the 133-byte uncompressed
/// point and a 132-byte `r || s`, and it hashes the message with SHA-512.
/// Do not pass it a key share or a shared secret.
///
/// Same hardening as [PqEcdsaP256]: RFC 6979 nonces, low-S on sign. Verify
/// accepts high-S. Not a constant-time implementation, and not a TLS group.
library;

import 'dart:typed_data';

import 'package:pointycastle/export.dart' as pc;

import 'pq_ecdsa.dart';

/// ECDSA over NIST P-521, byte-oriented and self-contained.
class PqEcdsaP521 {
  const PqEcdsaP521._();

  /// Private scalar length in bytes.
  static const int privateKeyBytes = 66;

  /// Uncompressed SEC1 public-key length in bytes (`0x04 || X || Y`).
  static const int publicKeyBytes = 133;

  /// Raw `r || s` signature length in bytes.
  static const int signatureBytes = 132;

  static final PqEcdsaCurve _curve = PqEcdsaCurve(
    domain: pc.ECCurve_secp521r1(),
    privateKeyBytes: privateKeyBytes,
    publicKeyBytes: publicKeyBytes,
    signatureBytes: signatureBytes,
    newDigest: pc.SHA512Digest.new,
    hmacBlockBytes: 128,
  );

  /// Generates a fresh P-521 key pair.
  static ({Uint8List publicKey, Uint8List secretKey}) generateKeyPair() =>
      _curve.generateKeyPair();

  /// Uncompressed SEC1 public key for a 66-byte private scalar.
  static Uint8List publicKeyFromPrivate(Uint8List privateKey) =>
      _curve.publicKeyFromPrivate(privateKey);

  /// Signs [message]. The signature is `r || s`, 132 bytes, low-S.
  static Uint8List sign({
    required Uint8List privateKey,
    required Uint8List message,
  }) => _curve.sign(privateKey: privateKey, message: message);

  /// Verifies `r || s`. High-S is accepted. Returns false on any malformed
  /// input instead of throwing.
  static bool verify({
    required Uint8List publicKey,
    required Uint8List message,
    required Uint8List signature,
  }) => _curve.verify(
    publicKey: publicKey,
    message: message,
    signature: signature,
  );

  /// Uncompressed point, or null when [encoded] is not a P-521 point.
  static Uint8List? normalizePoint(Uint8List encoded) =>
      _curve.normalizePoint(encoded);
}
