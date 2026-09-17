/// Byte-oriented ECDH over NIST P-256 and P-384 (secp256r1 / secp384r1).
///
/// This is **key agreement**, not [PqEcdsaP256] signatures. Public keys are
/// uncompressed SEC1 (`0x04 || X || Y`). The shared secret is the
/// x-coordinate only (RFC 8446 / SP 800-56A), fixed-length, never the point
/// at infinity and never the all-zero coordinate.
///
/// PointyCastle `decodePoint` does not check the Weierstrass equation, so
/// this class performs full public-key validation (length, `0x04` prefix,
/// field range, on-curve, not infinity) before the scalar multiply.
///
/// Consumed by TLS hybrid groups (RFC 10024 SecP256r1MLKEM768 /
/// SecP384r1MLKEM1024) through [PqClassicalProvider] and
/// [PqForgeHybridKeyAgreement].
library;

import 'dart:math';
import 'dart:typed_data';

import 'package:pointycastle/export.dart' as pc;

import 'pq_ecdsa_p256.dart';

/// NIST-curve ECDH with a TLS/SP 800-56A byte contract.
abstract final class PqNistEcdh {
  /// P-256 private scalar length.
  static const int p256PrivateKeyBytes = 32;

  /// P-256 uncompressed SEC1 public key (`0x04 || X || Y`).
  static const int p256PublicKeyBytes = 65;

  /// P-256 shared secret (x-coordinate).
  static const int p256SharedSecretBytes = 32;

  /// P-384 private scalar length.
  static const int p384PrivateKeyBytes = 48;

  /// P-384 uncompressed SEC1 public key (`0x04 || X || Y`).
  static const int p384PublicKeyBytes = 97;

  /// P-384 shared secret (x-coordinate).
  static const int p384SharedSecretBytes = 48;

  static final pc.ECDomainParameters _p256 = pc.ECCurve_secp256r1();
  static final pc.ECDomainParameters _p384 = pc.ECCurve_secp384r1();

  /// Generates a P-256 ECDH key pair.
  ///
  /// When [seed] is omitted, the scalar is drawn from a Fortuna DRBG (same
  /// construction as [PqEcdsaP256.generateKeyPair] — the keys are interchangeable
  /// with the signature path). When [seed] is supplied it must be a 32-byte
  /// scalar in `[1, n)`.
  static ({Uint8List publicKey, Uint8List secretKey}) p256GenerateKeyPair({
    Uint8List? seed,
  }) {
    if (seed != null) {
      final publicKey = p256PublicKeyFromPrivate(seed);
      return (publicKey: publicKey, secretKey: Uint8List.fromList(seed));
    }
    return PqEcdsaP256.generateKeyPair();
  }

  /// `d · G` for a 32-byte P-256 scalar.
  static Uint8List p256PublicKeyFromPrivate(Uint8List secretKey) =>
      _publicKeyFromPrivate(_p256, secretKey, p256PrivateKeyBytes);

  /// P-256 ECDH: x-coordinate of `d · Q`. [remotePublicKey] must be 65-byte
  /// uncompressed SEC1.
  static Uint8List p256SharedSecret({
    required Uint8List secretKey,
    required Uint8List remotePublicKey,
  }) => _sharedSecret(
    domain: _p256,
    secretKey: secretKey,
    remotePublicKey: remotePublicKey,
    privateKeyBytes: p256PrivateKeyBytes,
    publicKeyBytes: p256PublicKeyBytes,
    sharedSecretBytes: p256SharedSecretBytes,
  );

  /// Generates a P-384 ECDH key pair. [seed], when present, is a 48-byte
  /// scalar in `[1, n)`.
  static ({Uint8List publicKey, Uint8List secretKey}) p384GenerateKeyPair({
    Uint8List? seed,
  }) {
    if (seed != null) {
      final publicKey = p384PublicKeyFromPrivate(seed);
      return (publicKey: publicKey, secretKey: Uint8List.fromList(seed));
    }
    return _generate(_p384, p384PrivateKeyBytes);
  }

  /// `d · G` for a 48-byte P-384 scalar.
  static Uint8List p384PublicKeyFromPrivate(Uint8List secretKey) =>
      _publicKeyFromPrivate(_p384, secretKey, p384PrivateKeyBytes);

  /// P-384 ECDH: x-coordinate of `d · Q`. [remotePublicKey] must be 97-byte
  /// uncompressed SEC1.
  static Uint8List p384SharedSecret({
    required Uint8List secretKey,
    required Uint8List remotePublicKey,
  }) => _sharedSecret(
    domain: _p384,
    secretKey: secretKey,
    remotePublicKey: remotePublicKey,
    privateKeyBytes: p384PrivateKeyBytes,
    publicKeyBytes: p384PublicKeyBytes,
    sharedSecretBytes: p384SharedSecretBytes,
  );

  static ({Uint8List publicKey, Uint8List secretKey}) _generate(
    pc.ECDomainParameters domain,
    int privateKeyBytes,
  ) {
    final generator = pc.ECKeyGenerator()
      ..init(
        pc.ParametersWithRandom(
          pc.ECKeyGeneratorParameters(domain),
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

  static Uint8List _publicKeyFromPrivate(
    pc.ECDomainParameters domain,
    Uint8List secretKey,
    int privateKeyBytes,
  ) {
    if (secretKey.length != privateKeyBytes) {
      throw ArgumentError.value(
        secretKey.length,
        'secretKey',
        'expected $privateKeyBytes bytes',
      );
    }
    final d = _requireScalar(domain, secretKey);
    final q = domain.G * d;
    if (q == null || q.isInfinity) {
      throw ArgumentError.value(
        secretKey,
        'secretKey',
        'derived point at infinity',
      );
    }
    return q.getEncoded(false);
  }

  static Uint8List _sharedSecret({
    required pc.ECDomainParameters domain,
    required Uint8List secretKey,
    required Uint8List remotePublicKey,
    required int privateKeyBytes,
    required int publicKeyBytes,
    required int sharedSecretBytes,
  }) {
    if (secretKey.length != privateKeyBytes) {
      throw ArgumentError.value(
        secretKey.length,
        'secretKey',
        'expected $privateKeyBytes bytes',
      );
    }
    if (remotePublicKey.length != publicKeyBytes) {
      throw ArgumentError.value(
        remotePublicKey.length,
        'remotePublicKey',
        'expected $publicKeyBytes-byte uncompressed SEC1',
      );
    }
    if (remotePublicKey[0] != 0x04) {
      throw ArgumentError.value(
        remotePublicKey[0],
        'remotePublicKey',
        'uncompressed SEC1 must start with 0x04',
      );
    }
    final d = _requireScalar(domain, secretKey);
    final q = _decodeValidatedPoint(domain, remotePublicKey);
    final p = q * d;
    if (p == null || p.isInfinity) {
      throw ArgumentError('ECDH produced the point at infinity');
    }
    final x = p.x!.toBigInteger()!;
    if (x == BigInt.zero) {
      throw ArgumentError('ECDH produced an all-zero shared secret');
    }
    return _bigIntToFixed(x, sharedSecretBytes);
  }

  /// Full public-key validation (SP 800-56A / RFC 8422). PointyCastle
  /// `decodePoint` accepts any (X, Y) of the right length; we still require
  /// the Weierstrass equation `y² = x³ + ax + b` and reject infinity.
  static pc.ECPoint _decodeValidatedPoint(
    pc.ECDomainParameters domain,
    Uint8List remotePublicKey,
  ) {
    late final pc.ECPoint q;
    try {
      final decoded = domain.curve.decodePoint(remotePublicKey);
      if (decoded == null) {
        throw ArgumentError.value(
          remotePublicKey,
          'remotePublicKey',
          'invalid public point',
        );
      }
      q = decoded;
    } catch (error) {
      if (error is ArgumentError) rethrow;
      throw ArgumentError.value(
        remotePublicKey,
        'remotePublicKey',
        'invalid public point ($error)',
      );
    }
    if (q.isInfinity) {
      throw ArgumentError.value(
        remotePublicKey,
        'remotePublicKey',
        'point at infinity',
      );
    }
    final x = q.x;
    final y = q.y;
    final a = domain.curve.a;
    final b = domain.curve.b;
    if (x == null || y == null || a == null || b == null) {
      throw ArgumentError.value(
        remotePublicKey,
        'remotePublicKey',
        'public point is missing coordinates',
      );
    }
    final left = y * y;
    final right = ((x * x) * x) + (a * x) + b;
    if (left != right) {
      throw ArgumentError.value(
        remotePublicKey,
        'remotePublicKey',
        'off-curve public point',
      );
    }
    return q;
  }

  static BigInt _requireScalar(
    pc.ECDomainParameters domain,
    Uint8List secretKey,
  ) {
    final d = _bytesToBigInt(secretKey);
    if (d < BigInt.one || d >= domain.n) {
      throw ArgumentError.value(
        secretKey,
        'secretKey',
        'scalar is not in the range [1, n)',
      );
    }
    return d;
  }

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
