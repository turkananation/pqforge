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
///   verification rejects high-S, closing the ECDSA malleability gap.
///
/// Byte encodings:
/// * private key — the scalar `d` as a fixed 32-byte big-endian integer;
/// * public key — the uncompressed SEC1 point `0x04 || X || Y` (65 bytes);
/// * signature — raw `r || s`, 32 bytes each (64 bytes total).
library;

import 'dart:math';
import 'dart:typed_data';

import 'package:pointycastle/export.dart' as pc;

/// ECDSA over NIST P-256, byte-oriented and self-contained.
class PqEcdsaP256 {
  const PqEcdsaP256._();

  /// Private scalar length in bytes.
  static const int privateKeyBytes = 32;

  /// Uncompressed SEC1 public-key length in bytes (`0x04 || X || Y`).
  static const int publicKeyBytes = 65;

  /// Raw `r || s` signature length in bytes.
  static const int signatureBytes = 64;

  static final pc.ECDomainParameters _domain = pc.ECCurve_secp256r1();

  /// Generates a fresh P-256 key pair.
  static ({Uint8List publicKey, Uint8List secretKey}) generateKeyPair() {
    final generator = pc.ECKeyGenerator()
      ..init(
        pc.ParametersWithRandom(
          pc.ECKeyGeneratorParameters(_domain),
          _seededFortuna(),
        ),
      );
    final pair = generator.generateKeyPair();
    final privateKey = pair.privateKey;
    final publicKey = pair.publicKey;
    return (
      secretKey: _bigIntToFixed(privateKey.d!, privateKeyBytes),
      publicKey: publicKey.Q!.getEncoded(false),
    );
  }

  /// Signs [message] with [privateKey] (a 32-byte scalar), returning `r || s`.
  ///
  /// Uses RFC 6979 deterministic `k` and emits a canonical low-S signature.
  static Uint8List sign({
    required Uint8List privateKey,
    required Uint8List message,
  }) {
    if (privateKey.length != privateKeyBytes) {
      throw ArgumentError.value(
        privateKey.length,
        'privateKey',
        'expected $privateKeyBytes bytes',
      );
    }
    final signer = _newSigner()
      ..init(
        true,
        pc.PrivateKeyParameter<pc.ECPrivateKey>(
          pc.ECPrivateKey(_bytesToBigInt(privateKey), _domain),
        ),
      );
    final signature = signer.generateSignature(message) as pc.ECSignature;
    return Uint8List(signatureBytes)
      ..setRange(0, 32, _bigIntToFixed(signature.r, 32))
      ..setRange(32, 64, _bigIntToFixed(signature.s, 32));
  }

  /// Verifies a raw `r || s` [signature] over [message] under [publicKey].
  ///
  /// Returns `false` (never throws) for any malformed input, an off-curve point,
  /// a non-canonical high-S signature, or a genuine verification failure.
  static bool verify({
    required Uint8List publicKey,
    required Uint8List message,
    required Uint8List signature,
  }) {
    if (publicKey.length != publicKeyBytes ||
        signature.length != signatureBytes) {
      return false;
    }
    try {
      final point = _domain.curve.decodePoint(publicKey);
      if (point == null || point.isInfinity) return false;
      final verifier = _newSigner()
        ..init(
          false,
          pc.PublicKeyParameter<pc.ECPublicKey>(pc.ECPublicKey(point, _domain)),
        );
      final r = _bytesToBigInt(Uint8List.sublistView(signature, 0, 32));
      final s = _bytesToBigInt(Uint8List.sublistView(signature, 32, 64));
      return verifier.verifySignature(message, pc.ECSignature(r, s));
    } catch (_) {
      return false;
    }
  }

  // Deterministic (RFC 6979) ECDSA-SHA-256 signer that always normalizes to
  // low-S and rejects high-S on verification.
  static pc.NormalizedECDSASigner _newSigner() => pc.NormalizedECDSASigner(
    pc.ECDSASigner(pc.SHA256Digest(), pc.HMac(pc.SHA256Digest(), 64)),
    enforceNormalized: true,
  );

  static Uint8List _bigIntToFixed(BigInt value, int length) {
    final out = Uint8List(length);
    final mask = BigInt.from(0xff);
    var remaining = value;
    for (var i = length - 1; i >= 0; i--) {
      out[i] = (remaining & mask).toInt();
      remaining = remaining >> 8;
    }
    return out;
  }

  static BigInt _bytesToBigInt(List<int> bytes) {
    var result = BigInt.zero;
    for (final byte in bytes) {
      result = (result << 8) | BigInt.from(byte & 0xff);
    }
    return result;
  }

  static pc.SecureRandom _seededFortuna() {
    final fortuna = pc.FortunaRandom();
    final random = Random.secure();
    final seed = Uint8List(32);
    for (var i = 0; i < seed.length; i++) {
      seed[i] = random.nextInt(256);
    }
    fortuna.seed(pc.KeyParameter(seed));
    return fortuna;
  }
}
