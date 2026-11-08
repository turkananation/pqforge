/// ECDH over the three RFC 5639 curves OpenSSL offers as TLS 1.3 groups:
/// brainpoolP256r1, brainpoolP384r1, and brainpoolP512r1 (RFC 8734 code
/// points 31, 32, and 33).
///
/// There is no NIST P-512. OpenSSL's "P-512" is brainpoolP512r1.
/// The 160, 192, 224, and 320-bit curves, and every twisted `t1` curve,
/// are not TLS groups. They are not implemented.
///
/// Public keys are uncompressed SEC1 (`0x04 || X || Y`). The shared secret
/// is the fixed-length x-coordinate (RFC 8446). The scalar is rejected
/// outside `[1, n)`. The peer point is checked for length, the `0x04`
/// prefix, field range, the curve equation, and infinity before the
/// multiply. This is the same contract as [PqNistEcdh]. It is not a TLS
/// stack, and the field arithmetic is PointyCastle's, which is not
/// constant-time.
library;

import 'dart:math';
import 'dart:typed_data';

import 'package:pointycastle/export.dart' as pc;
import 'package:zeroize/zeroize.dart';

/// Brainpool ECDH with the TLS byte contract.
abstract final class PqBrainpool {
  static const int tlsGroupP256 = 31;
  static const int tlsGroupP384 = 32;
  static const int tlsGroupP512 = 33;

  static const int p256PrivateKeyBytes = 32;
  static const int p256PublicKeyBytes = 65;
  static const int p256SharedSecretBytes = 32;

  static const int p384PrivateKeyBytes = 48;
  static const int p384PublicKeyBytes = 97;
  static const int p384SharedSecretBytes = 48;

  static const int p512PrivateKeyBytes = 64;
  static const int p512PublicKeyBytes = 129;
  static const int p512SharedSecretBytes = 64;

  static final pc.ECDomainParameters _p256 = pc.ECCurve_brainpoolp256r1();
  static final pc.ECDomainParameters _p384 = pc.ECCurve_brainpoolp384r1();
  static final pc.ECDomainParameters _p512 = pc.ECCurve_brainpoolp512r1();

  static ({Uint8List publicKey, Uint8List secretKey}) p256GenerateKeyPair({
    Uint8List? seed,
  }) => _generate(_p256, p256PrivateKeyBytes, seed);

  static Uint8List p256PublicKeyFromPrivate(Uint8List secretKey) =>
      _publicKeyFromPrivate(_p256, secretKey, p256PrivateKeyBytes);

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

  static ({Uint8List publicKey, Uint8List secretKey}) p384GenerateKeyPair({
    Uint8List? seed,
  }) => _generate(_p384, p384PrivateKeyBytes, seed);

  static Uint8List p384PublicKeyFromPrivate(Uint8List secretKey) =>
      _publicKeyFromPrivate(_p384, secretKey, p384PrivateKeyBytes);

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

  static ({Uint8List publicKey, Uint8List secretKey}) p512GenerateKeyPair({
    Uint8List? seed,
  }) => _generate(_p512, p512PrivateKeyBytes, seed);

  static Uint8List p512PublicKeyFromPrivate(Uint8List secretKey) =>
      _publicKeyFromPrivate(_p512, secretKey, p512PrivateKeyBytes);

  static Uint8List p512SharedSecret({
    required Uint8List secretKey,
    required Uint8List remotePublicKey,
  }) => _sharedSecret(
    domain: _p512,
    secretKey: secretKey,
    remotePublicKey: remotePublicKey,
    privateKeyBytes: p512PrivateKeyBytes,
    publicKeyBytes: p512PublicKeyBytes,
    sharedSecretBytes: p512SharedSecretBytes,
  );

  static ({Uint8List publicKey, Uint8List secretKey}) _generate(
    pc.ECDomainParameters domain,
    int privateKeyBytes,
    Uint8List? seed,
  ) {
    if (seed != null) {
      final publicKey = _publicKeyFromPrivate(domain, seed, privateKeyBytes);
      return (publicKey: publicKey, secretKey: Uint8List.fromList(seed));
    }
    final generator = pc.ECKeyGenerator()
      ..init(
        pc.ParametersWithRandom(
          pc.ECKeyGeneratorParameters(domain),
          _seededFortuna(),
        ),
      );
    final pair = generator.generateKeyPair();
    return (
      secretKey: _bigIntToFixed(pair.privateKey.d!, privateKeyBytes),
      publicKey: pair.publicKey.Q!.getEncoded(false),
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
      throw ArgumentError.value(secretKey, 'secretKey', 'point at infinity');
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
    if (remotePublicKey.length != publicKeyBytes ||
        remotePublicKey[0] != 0x04) {
      throw ArgumentError.value(
        remotePublicKey,
        'remotePublicKey',
        'expected $publicKeyBytes-byte uncompressed SEC1',
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
    if (remaining != BigInt.zero) {
      secureZero(out);
      throw ArgumentError('integer does not fit in $length bytes');
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
    final seed = Uint8List(32);
    final random = Random.secure();
    for (var i = 0; i < seed.length; i++) {
      seed[i] = random.nextInt(256);
    }
    try {
      fortuna.seed(pc.KeyParameter(seed));
      return fortuna;
    } finally {
      secureZero(seed);
    }
  }
}
