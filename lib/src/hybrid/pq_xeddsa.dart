part of 'pq_ed25519.dart';

/// XEdDSA on Curve25519, in the form libsignal ships.
///
/// This is [Signal's XEdDSA](https://signal.org/docs/specifications/xeddsa/)
/// Curve25519 instance, with the deviation recorded in
/// `libsignal` `PrivateKey::calculate_signature`: the Edwards sign bit is
/// copied into the high bit of `S` instead of being forced to 0 by negating
/// the scalar. That is the libsignal-protocol-java encoding. A signature is
/// 64 bytes, `R || S`.
///
/// The secret is a 32-byte X25519 private key. It is clamped on use
/// (`secret[0] &= 248`, `secret[31] &= 127`, `secret[31] |= 64`), then
/// reduced modulo the Ed25519 order. [sign] draws 64 random bytes from
/// [PqBytes.randomBytes] when [randomness] is omitted. Those bytes are the
/// specification's `Z`. The same secret, message, and `Z` match libsignal
/// byte for byte.
///
/// [verify] returns false and does not throw. This is not Ed25519, not
/// VXEdDSA, not XEd448, and not a FIPS signature. The scalar multiply is
/// the same variable-time Edwards ladder as [PqEd25519].
abstract final class PqXeddsa {
  static const int secretKeyBytes = 32;
  static const int publicKeyBytes = 32;
  static const int signatureBytes = 64;
  static const int randomnessBytes = 64;

  /// `2^256 - 2` as 32 little-endian bytes. `hash_1` in the XEdDSA paper.
  static final Uint8List _hash1Prefix = Uint8List.fromList(<int>[
    0xfe, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, //
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
  ]);

  static ({Uint8List publicKey, Uint8List secretKey}) generateKeyPair() {
    final secretKey = PqBytes.randomBytes(secretKeyBytes);
    _clamp(secretKey);
    return (publicKey: publicKeyFromSecret(secretKey), secretKey: secretKey);
  }

  /// Montgomery u-coordinate of the clamped secret. 32 bytes.
  static Uint8List publicKeyFromSecret(Uint8List secretKey) {
    final key = _clampedSecret(secretKey);
    try {
      final scratch = _Scratch();
      final point = _Pt();
      _ptMul(point, PqEd25519._base, _le(key) % PqEd25519._order, scratch);
      return _montgomeryU(point, scratch);
    } finally {
      secureZero(key);
    }
  }

  /// Signs [message]. [randomness] is the 64-byte `Z`. Omit it to draw one.
  static Uint8List sign({
    required Uint8List secretKey,
    required Uint8List message,
    Uint8List? randomness,
  }) {
    final key = _clampedSecret(secretKey);
    final random = randomness ?? PqBytes.randomBytes(randomnessBytes);
    if (random.length != randomnessBytes) {
      secureZero(key);
      throw ArgumentError.value(
        random.length,
        'randomness',
        'expected $randomnessBytes bytes',
      );
    }
    try {
      final order = PqEd25519._order;
      final a = _le(key) % order;
      final scratch = _Scratch();
      final point = _Pt();
      _ptMul(point, PqEd25519._base, a, scratch);
      final edwardsPublic = _ptCompress(point, scratch);
      final signBit = edwardsPublic[31] & 0x80;

      final r = _le(_sha512Parts([_hash1Prefix, key, message, random])) % order;
      _ptMul(point, PqEd25519._base, r, scratch);
      final rBytes = _ptCompress(point, scratch);
      final h = _le(_sha512Parts([rBytes, edwardsPublic, message])) % order;
      final s = (h * a + r) % order;

      final out = Uint8List(signatureBytes);
      out.setRange(0, 32, rBytes);
      out.setRange(32, 64, _leBytes(s));
      out[63] = (out[63] & 0x7f) | signBit;
      return out;
    } finally {
      secureZero(key);
      if (randomness == null) secureZero(random);
    }
  }

  /// Signs every message with the same secret.
  ///
  /// [randomness], when set, is one 64-byte `Z` per message, drawn by the
  /// caller. When it is omitted, each `Z` is drawn here, before any isolate
  /// starts, so a custom random generator on this isolate is the one that
  /// runs. Two or more messages use isolates when `dart:isolate` exists
  /// (at most four at a time) and run inline otherwise, including dart2wasm.
  /// One message always runs inline.
  static Future<List<Uint8List>> signAll({
    required Uint8List secretKey,
    required List<Uint8List> messages,
    List<Uint8List>? randomness,
  }) async {
    if (secretKey.length != secretKeyBytes) {
      throw ArgumentError.value(
        secretKey.length,
        'secretKey',
        'expected $secretKeyBytes bytes',
      );
    }
    if (randomness != null && randomness.length != messages.length) {
      throw ArgumentError.value(
        randomness.length,
        'randomness',
        'expected ${messages.length} values',
      );
    }
    final ownRandom = randomness == null;
    final zs = List<Uint8List>.generate(messages.length, (i) {
      final z = randomness?[i] ?? PqBytes.randomBytes(randomnessBytes);
      if (z.length != randomnessBytes) {
        throw ArgumentError.value(
          z.length,
          'randomness',
          'expected $randomnessBytes bytes',
        );
      }
      return z;
    }, growable: false);
    try {
      return await xeddsa_parallel.runJobs<Uint8List>([
        for (var i = 0; i < messages.length; i++)
          () => sign(
            secretKey: secretKey,
            message: messages[i],
            randomness: zs[i],
          ),
      ]);
    } finally {
      if (ownRandom) {
        for (final z in zs) {
          secureZero(z);
        }
      }
    }
  }

  /// Verifies each triple. A bad signature is `false`, not a throw.
  /// Lengths that differ throw. Scheduling matches [signAll].
  static Future<List<bool>> verifyAll({
    required List<Uint8List> publicKeys,
    required List<Uint8List> messages,
    required List<Uint8List> signatures,
  }) {
    if (publicKeys.length != messages.length ||
        signatures.length != messages.length) {
      throw ArgumentError('verifyAll lengths differ');
    }
    return xeddsa_parallel.runJobs<bool>([
      for (var i = 0; i < messages.length; i++)
        () => verify(
          publicKey: publicKeys[i],
          message: messages[i],
          signature: signatures[i],
        ),
    ]);
  }

  /// Returns false for a bad length, a non-canonical public key or `R`,
  /// an `S` with bit 253 or 254 set, or a signature that does not check.
  ///
  /// The high bit of `S` is the Edwards sign bit, not a scalar bit. After
  /// that bit is removed, `S` is reduced modulo L, which is what libsignal's
  /// `Scalar::from_bytes_mod_order` does.
  static bool verify({
    required Uint8List publicKey,
    required Uint8List message,
    required Uint8List signature,
  }) {
    if (publicKey.length != publicKeyBytes ||
        signature.length != signatureBytes) {
      return false;
    }
    final sBytes = Uint8List.sublistView(signature, 32, 64);
    final sign = (sBytes[31] >> 7) & 1;
    final scalarBytes = Uint8List.fromList(sBytes);
    scalarBytes[31] &= 0x7f;
    if ((scalarBytes[31] & 0xe0) != 0) return false;

    final scratch = _Scratch();
    final edwardsPublic = _montgomeryToEdwards(publicKey, sign, scratch);
    if (edwardsPublic == null) return false;
    final aBytes = _ptCompress(edwardsPublic, scratch);

    final rBytes = Uint8List.sublistView(signature, 0, 32);
    final rPoint = _ptDecompress(rBytes, scratch);
    if (rPoint == null || !_bytesEqual(_ptCompress(rPoint, scratch), rBytes)) {
      return false;
    }

    final h = _le(_sha512Parts([rBytes, aBytes, message])) % PqEd25519._order;
    final s = _le(scalarBytes) % PqEd25519._order;
    final left = _Pt();
    _ptMul(left, PqEd25519._base, s, scratch);
    final right = _Pt();
    _ptMul(right, edwardsPublic, h, scratch);
    _ptAdd(right, right, rPoint, scratch);
    return _ptEquals(left, right, scratch);
  }
}

Uint8List _clampedSecret(Uint8List secret) {
  if (secret.length != PqXeddsa.secretKeyBytes) {
    throw ArgumentError.value(
      secret.length,
      'secretKey',
      'expected ${PqXeddsa.secretKeyBytes} bytes',
    );
  }
  final out = Uint8List.fromList(secret);
  _clamp(out);
  return out;
}

/// `u = (Z + Y) / (Z - Y)`, the Montgomery u of an Edwards point.
Uint8List _montgomeryU(_Pt point, _Scratch scratch) {
  final sum = _Fe();
  _feAdd(sum, point.z, point.y);
  final difference = _Fe();
  _feSub(difference, point.z, point.y);
  final inverse = _Fe();
  _feInvert(inverse, difference, scratch);
  final u = _Fe();
  _feMul(u, sum, inverse, scratch);
  return _feToBytes(u);
}

/// Edwards point for a canonical Montgomery u and an Edwards x sign bit.
_Pt? _montgomeryToEdwards(Uint8List uBytes, int sign, _Scratch scratch) {
  if (uBytes.length != 32 || (uBytes[31] & 0x80) != 0) return null;
  final u = _Fe();
  _feFromBytes(u, uBytes);
  _feCarry(u);
  if (_geP(u) || !_bytesEqual(_feToBytes(u), uBytes)) return null;

  final one = _Fe()..setInt(1);
  final numerator = _Fe();
  _feSub(numerator, u, one);
  final denominator = _Fe();
  _feAdd(denominator, u, one);
  final inverse = _Fe();
  _feInvert(inverse, denominator, scratch);
  final y = _Fe();
  _feMul(y, numerator, inverse, scratch);
  final encoded = _feToBytes(y);
  if (sign != 0) encoded[31] |= 0x80;
  return _ptDecompress(encoded, scratch);
}

bool _bytesEqual(Uint8List a, Uint8List b) {
  if (a.length != b.length) return false;
  return a.rangeEquals(0, a.length, b);
}
