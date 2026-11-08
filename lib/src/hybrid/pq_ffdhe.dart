/// RFC 7919 finite-field Diffie-Hellman, the five groups OpenSSL negotiates
/// in TLS 1.3: ffdhe2048, ffdhe3072, ffdhe4096, ffdhe6144, and ffdhe8192.
/// IANA code points are 256 through 260.
///
/// The public value and the shared secret are big-endian integers padded
/// on the left to the size of the prime (RFC 8446). A key this class
/// generates uses an exponent in `[1, q)`, where `q = (p - 1) / 2`. An
/// imported exponent, including one from OpenSSL, may be any value in
/// `[1, p - 1)`. A peer public value is rejected unless `1 < Y < p - 1`
/// and `Y^q ≡ 1 (mod p)`.
///
/// The exponentiation is `BigInt.modPow`. For an 8192-bit prime that is the
/// fast path: the operator is implemented in the VM, and a Dart limb loop
/// would be slower. The random buffer used to draw the exponent is wiped
/// with `secureZero`. The exponent itself is a `BigInt` and cannot be wiped.
/// This is not constant-time and not a TLS stack.
library;

import 'dart:math';
import 'dart:typed_data';

import 'package:zeroize/zeroize.dart';

import 'pq_ffdhe_primes.dart';

/// One RFC 7919 group.
enum PqFfdheGroup {
  ffdhe2048(256, 256, ffdhe2048PrimeHex),
  ffdhe3072(384, 257, ffdhe3072PrimeHex),
  ffdhe4096(512, 258, ffdhe4096PrimeHex),
  ffdhe6144(768, 259, ffdhe6144PrimeHex),
  ffdhe8192(1024, 260, ffdhe8192PrimeHex);

  const PqFfdheGroup(this.bytes, this.tlsCodepoint, this._primeHex);

  /// Prime size, and the size of a public key, a private key, and a secret.
  final int bytes;

  /// IANA TLS supported-group code point.
  final int tlsCodepoint;

  final String _primeHex;

  BigInt get prime => _primeOf(this);

  static final Map<PqFfdheGroup, BigInt> _primes = {};

  static BigInt _primeOf(PqFfdheGroup group) => _primes.putIfAbsent(
    group,
    () => BigInt.parse(group._primeHex, radix: 16),
  );
}

/// RFC 7919 key agreement. Generator is 2.
abstract final class PqFfdhe {
  static ({Uint8List publicKey, Uint8List secretKey}) generateKeyPair(
    PqFfdheGroup group,
  ) {
    final secretKey = _randomExponent(group);
    try {
      return (
        secretKey: Uint8List.fromList(secretKey),
        publicKey: publicKeyFromPrivate(group, secretKey),
      );
    } finally {
      secureZero(secretKey);
    }
  }

  /// `2^secret mod p`, padded to [PqFfdheGroup.bytes].
  static Uint8List publicKeyFromPrivate(
    PqFfdheGroup group,
    Uint8List secretKey,
  ) {
    final exponent = _requireExponent(group, secretKey);
    return _encode(BigInt.two.modPow(exponent, group.prime), group.bytes);
  }

  /// Shared secret `Y^secret mod p`, padded to [PqFfdheGroup.bytes].
  static Uint8List sharedSecret({
    required PqFfdheGroup group,
    required Uint8List secretKey,
    required Uint8List remotePublicKey,
  }) {
    final exponent = _requireExponent(group, secretKey);
    final peer = _requirePublic(group, remotePublicKey);
    return _encode(peer.modPow(exponent, group.prime), group.bytes);
  }

  static Uint8List _randomExponent(PqFfdheGroup group) {
    final random = Random.secure();
    final raw = Uint8List(group.bytes + 8);
    try {
      for (var i = 0; i < raw.length; i++) {
        raw[i] = random.nextInt(256);
      }
      final q = (group.prime - BigInt.one) >> 1;
      final exponent = (_bytes(raw) % (q - BigInt.one)) + BigInt.one;
      return _encode(exponent, group.bytes);
    } finally {
      secureZero(raw);
    }
  }

  static BigInt _requireExponent(PqFfdheGroup group, Uint8List secretKey) {
    if (secretKey.length != group.bytes) {
      throw ArgumentError.value(
        secretKey.length,
        'secretKey',
        'expected ${group.bytes} bytes',
      );
    }
    final exponent = _bytes(secretKey);
    final p = group.prime;
    if (exponent < BigInt.one || exponent >= p - BigInt.one) {
      throw ArgumentError.value(
        secretKey,
        'secretKey',
        'exponent is not in [1, p - 1)',
      );
    }
    return exponent;
  }

  static BigInt _requirePublic(PqFfdheGroup group, Uint8List remotePublicKey) {
    if (remotePublicKey.length != group.bytes) {
      throw ArgumentError.value(
        remotePublicKey.length,
        'remotePublicKey',
        'expected ${group.bytes} bytes',
      );
    }
    final y = _bytes(remotePublicKey);
    final p = group.prime;
    if (y <= BigInt.one || y >= p - BigInt.one) {
      throw ArgumentError.value(
        remotePublicKey,
        'remotePublicKey',
        'public value is outside (1, p - 1)',
      );
    }
    final q = (p - BigInt.one) >> 1;
    if (y.modPow(q, p) != BigInt.one) {
      throw ArgumentError.value(
        remotePublicKey,
        'remotePublicKey',
        'public value is not in the subgroup of order q',
      );
    }
    return y;
  }

  static BigInt _bytes(List<int> bytes) {
    var result = BigInt.zero;
    for (final byte in bytes) {
      result = (result << 8) | BigInt.from(byte & 0xff);
    }
    return result;
  }

  static Uint8List _encode(BigInt value, int length) {
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
}
