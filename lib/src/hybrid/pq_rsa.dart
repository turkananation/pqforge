/// RSA PKCS#1 v1.5 and RSASSA-PSS over SHA-256, SHA-384, and SHA-512.
///
/// PointyCastle already implements the padding. The modulus and exponent stay
/// byte strings at this boundary. A [BigInt] is built only after the modulus
/// is 2048, 3072, or 4096 bits and the exponent is an odd integer in
/// `3 .. 2^32-1`. Anything else makes verify return false, before that
/// conversion.
///
/// Verify hashes [message] itself. Do not pre-hash. Verify never throws.
library;

import 'dart:math';
import 'dart:typed_data';

import 'package:pointycastle/export.dart' as pc;

/// Digest used by [PqRsa]. The signer hashes the message.
enum PqRsaHash {
  sha256,
  sha384,
  sha512;

  int get digestBytes => switch (this) {
    PqRsaHash.sha256 => 32,
    PqRsaHash.sha384 => 48,
    PqRsaHash.sha512 => 64,
  };
}

/// RSA private key as unsigned big-endian integers.
///
/// [prime1] and [prime2] are required because the PointyCastle private-key
/// type checks `p * q == n`. They are not needed to verify.
class PqRsaPrivateKey {
  PqRsaPrivateKey({
    required this.modulus,
    required this.privateExponent,
    required this.prime1,
    required this.prime2,
    required this.publicExponent,
  });

  final Uint8List modulus;
  final Uint8List privateExponent;
  final Uint8List prime1;
  final Uint8List prime2;
  final Uint8List publicExponent;
}

/// PKCS#1 v1.5 and PSS signatures. Byte-oriented.
class PqRsa {
  const PqRsa._();

  static const _digestId = <PqRsaHash, String>{
    PqRsaHash.sha256: '0609608648016503040201',
    PqRsaHash.sha384: '0609608648016503040202',
    PqRsaHash.sha512: '0609608648016503040203',
  };

  /// Generates a key with a 2048, 3072, or 4096 bit modulus and `e = 65537`.
  static ({PqRsaPrivateKey privateKey, Uint8List modulus, Uint8List exponent})
  generateKeyPair({int modulusBits = 2048}) {
    if (modulusBits != 2048 && modulusBits != 3072 && modulusBits != 4096) {
      throw ArgumentError.value(
        modulusBits,
        'modulusBits',
        'expected 2048, 3072, or 4096',
      );
    }
    final generator = pc.RSAKeyGenerator()
      ..init(
        pc.ParametersWithRandom(
          pc.RSAKeyGeneratorParameters(BigInt.from(65537), modulusBits, 64),
          _seededFortuna(),
        ),
      );
    final pair = generator.generateKeyPair();
    final publicKey = pair.publicKey;
    final privateKey = pair.privateKey;
    final modulus = _fixed(publicKey.modulus!, modulusBits ~/ 8);
    final exponent = _minimal(publicKey.exponent!);
    return (
      modulus: modulus,
      exponent: exponent,
      privateKey: PqRsaPrivateKey(
        modulus: modulus,
        privateExponent: _minimal(privateKey.privateExponent!),
        prime1: _minimal(privateKey.p!),
        prime2: _minimal(privateKey.q!),
        publicExponent: exponent,
      ),
    );
  }

  /// PKCS#1 v1.5 signature. [hash] selects the DigestInfo. The message is
  /// hashed inside the signer.
  static Uint8List signPkcs1({
    required PqRsaPrivateKey privateKey,
    required Uint8List message,
    required PqRsaHash hash,
  }) {
    final signer = pc.RSASigner(_digest(hash), _digestId[hash]!)
      ..init(
        true,
        pc.PrivateKeyParameter<pc.RSAPrivateKey>(_private(privateKey)),
      );
    final signature = signer.generateSignature(message);
    return Uint8List.fromList(signature.bytes);
  }

  /// Returns false for a bad modulus, exponent, length, or signature.
  static bool verifyPkcs1({
    required Uint8List modulus,
    required Uint8List exponent,
    required Uint8List message,
    required Uint8List signature,
    required PqRsaHash hash,
  }) {
    final key = _public(modulus, exponent);
    if (key == null || signature.length != key.modulus!.bitLength ~/ 8) {
      return false;
    }
    try {
      final signer = pc.RSASigner(_digest(hash), _digestId[hash]!)
        ..init(false, pc.PublicKeyParameter<pc.RSAPublicKey>(key));
      return signer.verifySignature(message, pc.RSASignature(signature));
    } catch (_) {
      return false;
    }
  }

  /// RSASSA-PSS. The salt length equals the hash length. Trailer is `0xBC`.
  static Uint8List signPss({
    required PqRsaPrivateKey privateKey,
    required Uint8List message,
    required PqRsaHash hash,
  }) {
    final signer = pc.PSSSigner(pc.RSAEngine(), _digest(hash), _digest(hash))
      ..init(
        true,
        pc.ParametersWithSaltConfiguration(
          pc.PrivateKeyParameter<pc.RSAPrivateKey>(_private(privateKey)),
          _seededFortuna(),
          hash.digestBytes,
        ),
      );
    final signature = signer.generateSignature(message);
    return Uint8List.fromList(signature.bytes);
  }

  /// Returns false for a bad modulus, exponent, length, or signature.
  static bool verifyPss({
    required Uint8List modulus,
    required Uint8List exponent,
    required Uint8List message,
    required Uint8List signature,
    required PqRsaHash hash,
  }) {
    final key = _public(modulus, exponent);
    if (key == null || signature.length != key.modulus!.bitLength ~/ 8) {
      return false;
    }
    try {
      final signer = pc.PSSSigner(pc.RSAEngine(), _digest(hash), _digest(hash))
        ..init(
          false,
          pc.ParametersWithSaltConfiguration(
            pc.PublicKeyParameter<pc.RSAPublicKey>(key),
            _seededFortuna(),
            hash.digestBytes,
          ),
        );
      return signer.verifySignature(message, pc.PSSSignature(signature));
    } catch (_) {
      return false;
    }
  }

  static pc.RSAPublicKey? _public(Uint8List modulus, Uint8List exponent) {
    final n = _modulus(modulus);
    final e = _exponent(exponent);
    if (n == null || e == null) return null;
    return pc.RSAPublicKey(n, e);
  }

  static pc.RSAPrivateKey _private(PqRsaPrivateKey key) {
    final n = _modulus(key.modulus);
    final e = _exponent(key.publicExponent);
    if (n == null || e == null) {
      throw ArgumentError('RSA private key is not a supported size');
    }
    final built = pc.RSAPrivateKey(
      n,
      _unsigned(key.privateExponent),
      _unsigned(key.prime1),
      _unsigned(key.prime2),
    );
    if (built.publicExponent != e) {
      throw ArgumentError('RSA public exponent does not match the private key');
    }
    return built;
  }

  /// Null unless the unsigned integer is exactly 2048, 3072, or 4096 bits.
  static BigInt? _modulus(Uint8List bytes) {
    final stripped = _strip(bytes);
    if (stripped.isEmpty) return null;
    final bits = (stripped.length - 1) * 8 + _bitLength(stripped[0]);
    if (bits != 2048 && bits != 3072 && bits != 4096) return null;
    return _unsigned(stripped);
  }

  /// Null unless the value is odd and in `3 .. 2^32-1`.
  static BigInt? _exponent(Uint8List bytes) {
    final stripped = _strip(bytes);
    if (stripped.isEmpty || stripped.length > 4) return null;
    if (stripped.last.isEven) return null;
    final value = _unsigned(stripped);
    if (value < BigInt.from(3) || value > BigInt.from(0xffffffff)) return null;
    return value;
  }

  static int _bitLength(int top) {
    var n = 0;
    var v = top;
    while (v > 0) {
      n++;
      v >>= 1;
    }
    return n;
  }

  static Uint8List _strip(Uint8List bytes) {
    var start = 0;
    while (start < bytes.length - 1 && bytes[start] == 0) {
      start++;
    }
    if (start == 0) return bytes;
    return Uint8List.sublistView(bytes, start);
  }

  static BigInt _unsigned(Uint8List bytes) {
    var result = BigInt.zero;
    for (final byte in bytes) {
      result = (result << 8) | BigInt.from(byte & 0xff);
    }
    return result;
  }

  static Uint8List _minimal(BigInt value) {
    if (value.isNegative) {
      throw ArgumentError('RSA component is negative');
    }
    if (value == BigInt.zero) return Uint8List(1);
    final bytes = (value.bitLength + 7) >> 3;
    return _fixed(value, bytes);
  }

  static Uint8List _fixed(BigInt value, int length) {
    final out = Uint8List(length);
    final mask = BigInt.from(0xff);
    var remaining = value;
    for (var i = length - 1; i >= 0; i--) {
      out[i] = (remaining & mask).toInt();
      remaining >>= 8;
    }
    return out;
  }

  static pc.Digest _digest(PqRsaHash hash) => switch (hash) {
    PqRsaHash.sha256 => pc.SHA256Digest(),
    PqRsaHash.sha384 => pc.SHA384Digest(),
    PqRsaHash.sha512 => pc.SHA512Digest(),
  };

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
