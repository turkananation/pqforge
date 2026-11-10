/// Pure-Dart ECDSA over NIST P-256 (secp256r1) via PointyCastle.
///
/// This is the classical signature path that `package:cryptography` cannot
/// provide on the Dart VM (its `Ecdsa` key generation throws
/// `UnimplementedError`). PointyCastle implements the whole scheme in pure Dart,
/// so it works on every target — server, CLI, Flutter, and web.
///
/// Hardening choices:
/// * **Deterministic nonces (RFC 6979).** `k` is derived from the key and
///   message via HMAC-SHA-256, so there is no RNG dependency at signing time and
///   no catastrophic `k`-reuse failure mode.
/// * **Low-S normalization.** Signatures are emitted in canonical low-S form and
///   verification accepts the high-S form X.509 and TLS send. [sign] still
///   returns low-S.
///
/// Byte encodings:
/// * private key — the scalar `d` as a fixed 32-byte big-endian integer;
/// * public key — the uncompressed SEC1 point `0x04 || X || Y` (65 bytes);
/// * signature — raw `r || s`, 32 bytes each (64 bytes total).
library;

import 'dart:typed_data';

import 'package:pointycastle/export.dart' as pc;

import 'pq_ecdsa.dart';

/// ECDSA over NIST P-256, byte-oriented and self-contained.
class PqEcdsaP256 {
  const PqEcdsaP256._();

  /// Private scalar length in bytes.
  static const int privateKeyBytes = 32;

  /// Uncompressed SEC1 public-key length in bytes (`0x04 || X || Y`).
  static const int publicKeyBytes = 65;

  /// Raw `r || s` signature length in bytes.
  static const int signatureBytes = 64;

  static final PqEcdsaCurve _curve = PqEcdsaCurve(
    domain: pc.ECCurve_secp256r1(),
    privateKeyBytes: privateKeyBytes,
    publicKeyBytes: publicKeyBytes,
    signatureBytes: signatureBytes,
    newDigest: pc.SHA256Digest.new,
    hmacBlockBytes: 64,
  );

  /// Generates a fresh P-256 key pair.
  static ({Uint8List publicKey, Uint8List secretKey}) generateKeyPair() =>
      _curve.generateKeyPair();

  /// Derives the uncompressed SEC1 public key (`0x04 || X || Y`) for the
  /// 32-byte private scalar [privateKey] as `d · G`.
  ///
  /// This is the deterministic companion to [generateKeyPair]: given a stored
  /// secret key, recover the matching public key without persisting it. Throws
  /// [ArgumentError] if [privateKey] is the wrong length or not a valid scalar
  /// in `[1, n)`.
  static Uint8List publicKeyFromPrivate(Uint8List privateKey) =>
      _curve.publicKeyFromPrivate(privateKey);

  /// Signs [message] with [privateKey] (a 32-byte scalar), returning `r || s`.
  ///
  /// Uses RFC 6979 deterministic `k` and emits a canonical low-S signature.
  static Uint8List sign({
    required Uint8List privateKey,
    required Uint8List message,
  }) => _curve.sign(privateKey: privateKey, message: message);

  /// Verifies a raw `r || s` [signature] over [message] under [publicKey].
  ///
  /// [publicKey] may be uncompressed (`0x04`) or compressed (`0x02` / `0x03`).
  /// High-S is accepted. X.509 and TLS do not require low-S. Returns false
  /// for a bad length, an off-curve point, or a bad signature.
  static bool verify({
    required Uint8List publicKey,
    required Uint8List message,
    required Uint8List signature,
  }) => _curve.verify(
    publicKey: publicKey,
    message: message,
    signature: signature,
  );

  /// Uncompressed `0x04 || X || Y`, or null when [encoded] is not a P-256 point.
  ///
  /// Accepts the compressed SEC1 forms. Hybrid `0x06` / `0x07` is rejected.
  static Uint8List? normalizePoint(Uint8List encoded) =>
      _curve.normalizePoint(encoded);
}
