/// Pure-Dart ECDSA over NIST P-384 (secp384r1) via PointyCastle.
///
/// This is a signature, not the P-384 ECDH used by SecP384r1MLKEM1024.
/// [PqNistEcdh.p384SharedSecret] takes a 97-byte point and returns a 48-byte
/// x-coordinate. This class takes the same point encoding and a 96-byte
/// `r || s`, and it hashes the message with SHA-384. Do not pass it a key
/// share or a shared secret.
///
/// Same hardening as `PqEcdsaP256`: RFC 6979 nonces, low-S on sign. Verify
/// accepts high-S, which is what an X.509 certificate from OpenSSL carries.
library;

import 'dart:typed_data';

import 'package:pointycastle/export.dart' as pc;

import 'pq_ecdsa.dart';

/// ECDSA over NIST P-384, byte-oriented and self-contained.
class PqEcdsaP384 {
  const PqEcdsaP384._();

  /// Private scalar length in bytes.
  static const int privateKeyBytes = 48;

  /// Uncompressed SEC1 public-key length in bytes (`0x04 || X || Y`).
  static const int publicKeyBytes = 97;

  /// Raw `r || s` signature length in bytes.
  static const int signatureBytes = 96;

  static final PqEcdsaCurve _curve = PqEcdsaCurve(
    domain: pc.ECCurve_secp384r1(),
    privateKeyBytes: privateKeyBytes,
    publicKeyBytes: publicKeyBytes,
    signatureBytes: signatureBytes,
    newDigest: pc.SHA384Digest.new,
    hmacBlockBytes: 128,
  );

  /// Generates a fresh P-384 key pair.
  static ({Uint8List publicKey, Uint8List secretKey}) generateKeyPair() =>
      _curve.generateKeyPair();

  /// Uncompressed SEC1 public key for a 48-byte private scalar.
  static Uint8List publicKeyFromPrivate(Uint8List privateKey) =>
      _curve.publicKeyFromPrivate(privateKey);

  /// Signs [message]. The signature is `r || s`, 96 bytes, low-S.
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

  /// Uncompressed point, or null when [encoded] is not a P-384 point.
  static Uint8List? normalizePoint(Uint8List encoded) =>
      _curve.normalizePoint(encoded);
}
