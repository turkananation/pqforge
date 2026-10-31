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

import 'dart:math';
import 'dart:typed_data';

import 'package:pointycastle/export.dart' as pc;

/// ECDSA over NIST P-384, byte-oriented and self-contained.
class PqEcdsaP384 {
  const PqEcdsaP384._();

  /// Private scalar length in bytes.
  static const int privateKeyBytes = 48;

  /// Uncompressed SEC1 public-key length in bytes (`0x04 || X || Y`).
  static const int publicKeyBytes = 97;

  /// Raw `r || s` signature length in bytes.
  static const int signatureBytes = 96;

  static final pc.ECDomainParameters _domain = pc.ECCurve_secp384r1();

  /// Generates a fresh P-384 key pair.
  static ({Uint8List publicKey, Uint8List secretKey}) generateKeyPair() {
    final generator = pc.ECKeyGenerator()
      ..init(
        pc.ParametersWithRandom(
          pc.ECKeyGeneratorParameters(_domain),
          _seededFortuna(),
        ),
      );
    final pair = generator.generateKeyPair();
    return (
      secretKey: _bigIntToFixed(pair.privateKey.d!, privateKeyBytes),
      publicKey: pair.publicKey.Q!.getEncoded(false),
    );
  }

  /// Uncompressed SEC1 public key for a 48-byte private scalar.
  ///
  /// Throws [ArgumentError] if [privateKey] is the wrong length or not in
  /// `[1, n)`.
  static Uint8List publicKeyFromPrivate(Uint8List privateKey) {
    if (privateKey.length != privateKeyBytes) {
      throw ArgumentError.value(
        privateKey.length,
        'privateKey',
        'expected $privateKeyBytes bytes',
      );
    }
    final d = _bytesToBigInt(privateKey);
    if (d < BigInt.one || d >= _domain.n) {
      throw ArgumentError.value(
        privateKey,
        'privateKey',
        'scalar is not in the range [1, n)',
      );
    }
    final q = _domain.G * d;
    if (q == null || q.isInfinity) {
      throw ArgumentError.value(
        privateKey,
        'privateKey',
        'derived point at infinity',
      );
    }
    return q.getEncoded(false);
  }

  /// Signs [message] with [privateKey], returning raw `r || s`.
  ///
  /// SHA-384 is applied inside the signer. Do not pre-hash.
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
      ..setRange(0, 48, _bigIntToFixed(signature.r, 48))
      ..setRange(48, 96, _bigIntToFixed(signature.s, 48));
  }

  /// Verifies raw `r || s` over [message] under [publicKey].
  ///
  /// [publicKey] may be uncompressed or compressed SEC1. High-S is accepted.
  /// SHA-384 is applied inside the signer.
  static bool verify({
    required Uint8List publicKey,
    required Uint8List message,
    required Uint8List signature,
  }) {
    final encoded = normalizePoint(publicKey);
    if (encoded == null || signature.length != signatureBytes) return false;
    try {
      final point = _domain.curve.decodePoint(encoded);
      if (point == null || point.isInfinity) return false;
      final verifier = _verifier()
        ..init(
          false,
          pc.PublicKeyParameter<pc.ECPublicKey>(pc.ECPublicKey(point, _domain)),
        );
      final r = _bytesToBigInt(Uint8List.sublistView(signature, 0, 48));
      final s = _bytesToBigInt(Uint8List.sublistView(signature, 48, 96));
      if (r == BigInt.zero ||
          s == BigInt.zero ||
          r >= _domain.n ||
          s >= _domain.n) {
        return false;
      }
      return verifier.verifySignature(message, pc.ECSignature(r, s));
    } catch (_) {
      return false;
    }
  }

  /// Uncompressed `0x04 || X || Y`, or null when [encoded] is not a P-384 point.
  static Uint8List? normalizePoint(Uint8List encoded) =>
      _normalizePoint(encoded, _domain, publicKeyBytes);

  static pc.NormalizedECDSASigner _newSigner() => pc.NormalizedECDSASigner(
    pc.ECDSASigner(pc.SHA384Digest(), pc.HMac(pc.SHA384Digest(), 128)),
    enforceNormalized: true,
  );

  static pc.ECDSASigner _verifier() =>
      pc.ECDSASigner(pc.SHA384Digest(), pc.HMac(pc.SHA384Digest(), 128));

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

Uint8List? _normalizePoint(
  Uint8List encoded,
  pc.ECDomainParameters domain,
  int uncompressedLength,
) {
  if (encoded.isEmpty) return null;
  final tag = encoded[0];
  final compressed = tag == 0x02 || tag == 0x03;
  if (tag != 0x04 && !compressed) return null;
  final expected = compressed
      ? (uncompressedLength ~/ 2) + 1
      : uncompressedLength;
  if (encoded.length != expected) return null;
  try {
    final point = domain.curve.decodePoint(encoded);
    if (point == null || point.isInfinity) return null;
    final raw = point.getEncoded(false);
    if (raw.length != uncompressedLength || raw[0] != 0x04) return null;
    return Uint8List.fromList(raw);
  } catch (_) {
    return null;
  }
}
