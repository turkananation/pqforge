/// RFC 7748 X448, as a 56-byte Diffie-Hellman.
///
/// The private key is the unclamped 56-byte scalar. Clamping (clear the two
/// least-significant bits of the first byte, set the most-significant bit of
/// the last byte) happens inside [sharedSecret], which is what RFC 9180
/// `DHKEM(X448, HKDF-SHA512)` calls.
///
/// This is the RFC 7748 Montgomery ladder on Dart integers. It is not a
/// constant-time implementation, and a caller must not describe it as one.
/// An all-zero shared secret is returned as 56 zero bytes. HPKE aborts on
/// that output; this function does not.
library;

import 'dart:math';
import 'dart:typed_data';

/// X448 key agreement (RFC 7748 §5).
abstract final class PqX448 {
  /// Scalar, public key, and shared secret length.
  static const int keyBytes = 56;

  /// `u = 5`, the RFC 7748 base point, little-endian.
  static final Uint8List basePoint = Uint8List(keyBytes)..[0] = 5;

  static final BigInt _p =
      (BigInt.one << 448) - (BigInt.one << 224) - BigInt.one;
  static final BigInt _a24 = BigInt.from(39081);

  /// 56 random bytes and `X448(scalar, 5)`.
  static ({Uint8List publicKey, Uint8List secretKey}) generateKeyPair() {
    final random = Random.secure();
    final secretKey = Uint8List(keyBytes);
    for (var i = 0; i < secretKey.length; i++) {
      secretKey[i] = random.nextInt(256);
    }
    return (publicKey: publicKeyFromPrivate(secretKey), secretKey: secretKey);
  }

  /// `X448(secretKey, 5)`.
  static Uint8List publicKeyFromPrivate(Uint8List secretKey) =>
      sharedSecret(secretKey: secretKey, remotePublicKey: basePoint);

  /// `X448(secretKey, remotePublicKey)`. Both inputs are 56 bytes.
  static Uint8List sharedSecret({
    required Uint8List secretKey,
    required Uint8List remotePublicKey,
  }) {
    if (secretKey.length != keyBytes) {
      throw ArgumentError.value(
        secretKey.length,
        'secretKey',
        'expected $keyBytes bytes',
      );
    }
    if (remotePublicKey.length != keyBytes) {
      throw ArgumentError.value(
        remotePublicKey.length,
        'remotePublicKey',
        'expected $keyBytes bytes',
      );
    }
    final k = _decodeScalar(secretKey);
    final u = _decodeLittleEndian(remotePublicKey);
    return _encodeLittleEndian(_scalarmult(k, u));
  }

  static BigInt _decodeScalar(Uint8List scalar) {
    final clamped = Uint8List.fromList(scalar);
    clamped[0] &= 252;
    clamped[55] |= 128;
    return _decodeLittleEndian(clamped);
  }

  static BigInt _decodeLittleEndian(Uint8List bytes) {
    var value = BigInt.zero;
    for (var i = bytes.length - 1; i >= 0; i--) {
      value = (value << 8) | BigInt.from(bytes[i]);
    }
    return value;
  }

  static Uint8List _encodeLittleEndian(BigInt value) {
    final out = Uint8List(keyBytes);
    var rest = value;
    final mask = BigInt.from(0xff);
    for (var i = 0; i < keyBytes; i++) {
      out[i] = (rest & mask).toInt();
      rest >>= 8;
    }
    return out;
  }

  static BigInt _scalarmult(BigInt k, BigInt u) {
    final x1 = u % _p;
    var x2 = BigInt.one;
    var z2 = BigInt.zero;
    var x3 = x1;
    var z3 = BigInt.one;
    var swap = 0;
    for (var t = 447; t >= 0; t--) {
      final kt = ((k >> t) & BigInt.one).toInt();
      swap ^= kt;
      final swappedX = _cswap(swap, x2, x3);
      final swappedZ = _cswap(swap, z2, z3);
      x2 = swappedX.$1;
      x3 = swappedX.$2;
      z2 = swappedZ.$1;
      z3 = swappedZ.$2;
      swap = kt;

      final a = _add(x2, z2);
      final aa = _mul(a, a);
      final b = _sub(x2, z2);
      final bb = _mul(b, b);
      final e = _sub(aa, bb);
      final c = _add(x3, z3);
      final d = _sub(x3, z3);
      final da = _mul(d, a);
      final cb = _mul(c, b);
      x3 = _mul(_add(da, cb), _add(da, cb));
      z3 = _mul(x1, _mul(_sub(da, cb), _sub(da, cb)));
      x2 = _mul(aa, bb);
      z2 = _mul(e, _add(aa, _mul(_a24, e)));
    }
    final swappedX = _cswap(swap, x2, x3);
    final swappedZ = _cswap(swap, z2, z3);
    x2 = swappedX.$1;
    z2 = swappedZ.$1;
    return _mul(x2, z2.modPow(_p - BigInt.two, _p));
  }

  static (BigInt, BigInt) _cswap(int swap, BigInt left, BigInt right) {
    if (swap == 0) return (left, right);
    return (right, left);
  }

  static BigInt _add(BigInt a, BigInt b) => (a + b) % _p;

  static BigInt _sub(BigInt a, BigInt b) {
    final diff = (a - b) % _p;
    return diff.isNegative ? diff + _p : diff;
  }

  static BigInt _mul(BigInt a, BigInt b) => (a * b) % _p;
}
