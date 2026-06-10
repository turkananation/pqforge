/// Thin adapters over pqcrypto and Pointy Castle.
library;

import 'dart:convert';
import 'dart:math';
import 'dart:typed_data';

import 'package:pointycastle/export.dart' as pc;

import '../algorithms/pq_algorithms.dart';
import '../algorithms/pq_lattice_provider.dart';
import '../keys/pq_keys.dart';

final _secureRandom = Random.secure();

Uint8List _platformRandomBytes(int length) {
  final bytes = Uint8List(length);
  for (var i = 0; i < length; i++) {
    bytes[i] = _secureRandom.nextInt(256);
  }
  return bytes;
}

/// Process-wide source of cryptographic randomness.
///
/// Defaults to the platform CSPRNG (`Random.secure()`). FIPS 140-3 deployments
/// can point [generator] at a validated module's DRBG so every nonce, salt, and
/// seed pqforge draws comes from inside the module boundary:
///
/// ```dart
/// PqRandom.generator = myValidatedModule.randomBytes;
/// ```
abstract final class PqRandom {
  /// The active generator. Must return exactly the requested number of bytes.
  static Uint8List Function(int length) generator = _platformRandomBytes;

  /// Restores the platform CSPRNG default.
  static void useDefault() => generator = _platformRandomBytes;
}

class PqBytes {
  const PqBytes._();

  static Uint8List randomBytes(int length) {
    if (length < 0) {
      throw ArgumentError.value(length, 'length', 'must be non-negative');
    }
    final bytes = PqRandom.generator(length);
    if (bytes.length != length) {
      throw StateError(
        'PqRandom.generator returned ${bytes.length} bytes; expected $length',
      );
    }
    return bytes;
  }

  static Uint8List copy(Uint8List value) => Uint8List.fromList(value);

  static Uint8List utf8Bytes(String value) =>
      Uint8List.fromList(utf8.encode(value));

  static Uint8List uint32(int value) {
    RangeError.checkValueInInterval(value, 0, 0xFFFFFFFF, 'value');
    return Uint8List(4)..buffer.asByteData().setUint32(0, value, Endian.big);
  }

  static Uint8List uint64(int value) {
    RangeError.checkNotNegative(value, 'value');
    return Uint8List(8)..buffer.asByteData().setUint64(0, value, Endian.big);
  }

  static Uint8List concat(Iterable<Uint8List> chunks) {
    final total = chunks.fold<int>(0, (sum, chunk) => sum + chunk.length);
    final out = Uint8List(total);
    var offset = 0;
    for (final chunk in chunks) {
      out.setRange(offset, offset + chunk.length, chunk);
      offset += chunk.length;
    }
    return out;
  }

  static Uint8List lengthPrefixed(Iterable<Uint8List> fields) {
    final chunks = <Uint8List>[];
    for (final field in fields) {
      chunks
        ..add(uint32(field.length))
        ..add(field);
    }
    return concat(chunks);
  }

  /// Inverse of [lengthPrefixed]: splits `len‖field` records back into
  /// zero-copy views over [data]. Throws [PqForgeException] on truncation.
  static List<Uint8List> decodeLengthPrefixed(Uint8List data) {
    final fields = <Uint8List>[];
    var offset = 0;
    while (offset < data.length) {
      if (offset + 4 > data.length) {
        throw const PqForgeException('Truncated envelope field length');
      }
      final length = data.buffer
          .asByteData(data.offsetInBytes + offset, 4)
          .getUint32(0, Endian.big);
      offset += 4;
      if (offset + length > data.length) {
        throw const PqForgeException('Truncated envelope field body');
      }
      fields.add(Uint8List.sublistView(data, offset, offset + length));
      offset += length;
    }
    return fields;
  }

  static Uint8List sha256(Uint8List data) => pc.SHA256Digest().process(data);

  static Uint8List hmacSha256({
    required Uint8List key,
    required Uint8List data,
  }) {
    final hmac = pc.HMac(pc.SHA256Digest(), 64)..init(pc.KeyParameter(key));
    return hmac.process(data);
  }

  static bool constantTimeEquals(Uint8List expected, Uint8List supplied) {
    var nonEqual = expected.length ^ supplied.length;
    final len = min(expected.length, supplied.length);
    for (var i = 0; i < len; i++) {
      nonEqual |= expected[i] ^ supplied[i];
    }
    for (var i = len; i < supplied.length; i++) {
      nonEqual |= supplied[i] ^ ~supplied[i];
    }
    return nonEqual == 0;
  }
}

/// Backward-compatible byte utility name from the V0.1 facade.
class PqForgeBytes {
  const PqForgeBytes._();

  static Uint8List randomBytes(int length) => PqBytes.randomBytes(length);
  static Uint8List copy(Uint8List value) => PqBytes.copy(value);
  static Uint8List utf8Bytes(String value) => PqBytes.utf8Bytes(value);
  static Uint8List uint32(int value) => PqBytes.uint32(value);
  static Uint8List uint64(int value) => PqBytes.uint64(value);
  static Uint8List concat(Iterable<Uint8List> chunks) => PqBytes.concat(chunks);
  static Uint8List lengthPrefixed(Iterable<Uint8List> fields) =>
      PqBytes.lengthPrefixed(fields);
  static Uint8List sha256(Uint8List data) => PqBytes.sha256(data);
  static Uint8List hmacSha256({
    required Uint8List key,
    required Uint8List data,
  }) => PqBytes.hmacSha256(key: key, data: data);
  static bool constantTimeEquals(Uint8List expected, Uint8List supplied) =>
      PqBytes.constantTimeEquals(expected, supplied);
}

class PqKemPrimitives {
  const PqKemPrimitives._();

  static PqKeyPair generateKeyPair(
    PqKemAlgorithm algorithm, {
    Uint8List? seed,
  }) {
    if (seed != null && seed.length != 32 && seed.length != 64) {
      throw ArgumentError.value(seed.length, 'seed', 'expected 32 or 64 bytes');
    }
    final (publicKey, secretKey) = PqLattice.provider.kemGenerateKeyPair(
      algorithm,
      seed: seed,
    );
    return PqKeyPair(publicKey: publicKey, secretKey: secretKey);
  }

  static PqKemEncapsulation encapsulate(
    PqKemAlgorithm algorithm,
    Uint8List publicKey, {
    Uint8List? nonce,
  }) {
    requireLength('publicKey', publicKey, algorithm.publicKeyBytes);
    if (nonce != null) requireLength('nonce', nonce, 32);
    final (ciphertext, sharedSecret) = PqLattice.provider.kemEncapsulate(
      algorithm,
      publicKey,
      nonce: nonce,
    );
    return PqKemEncapsulation(
      algorithm: algorithm,
      ciphertext: ciphertext,
      sharedSecret: sharedSecret,
    );
  }

  static Uint8List decapsulate(
    PqKemAlgorithm algorithm,
    Uint8List secretKey,
    Uint8List ciphertext,
  ) {
    requireLength('secretKey', secretKey, algorithm.secretKeyBytes);
    requireLength('ciphertext', ciphertext, algorithm.ciphertextBytes);
    return PqLattice.provider.kemDecapsulate(algorithm, secretKey, ciphertext);
  }
}

class PqSignaturePrimitives {
  const PqSignaturePrimitives._();

  static PqKeyPair generateKeyPair(PqSignatureAlgorithm algorithm) {
    final (publicKey, secretKey) = PqLattice.provider.dsaGenerateKeyPair(
      algorithm,
    );
    return PqKeyPair(publicKey: publicKey, secretKey: secretKey);
  }

  static PqKeyPair generateKeyPairSeeded(
    PqSignatureAlgorithm algorithm,
    Uint8List seed,
  ) {
    requireLength('seed', seed, 32);
    final (publicKey, secretKey) = PqLattice.provider.dsaGenerateKeyPairSeeded(
      algorithm,
      seed,
    );
    return PqKeyPair(publicKey: publicKey, secretKey: secretKey);
  }

  static Uint8List sign(
    PqSignatureAlgorithm algorithm,
    Uint8List secretKey,
    Uint8List message, {
    Uint8List? context,
    bool preHash = false,
  }) {
    requireLength('secretKey', secretKey, algorithm.secretKeyBytes);
    requireDsaContext(context);
    return PqLattice.provider.dsaSign(
      algorithm,
      secretKey,
      message,
      context: context,
      preHash: preHash,
    );
  }

  static bool verify(
    PqSignatureAlgorithm algorithm,
    Uint8List publicKey,
    Uint8List message,
    Uint8List signature, {
    Uint8List? context,
    bool preHash = false,
  }) {
    if (publicKey.length != algorithm.publicKeyBytes ||
        signature.length != algorithm.signatureBytes ||
        (context?.length ?? 0) > 255) {
      return false;
    }
    return PqLattice.provider.dsaVerify(
      algorithm,
      publicKey,
      message,
      signature,
      context: context,
      preHash: preHash,
    );
  }
}

class PqSymmetricPrimitives {
  const PqSymmetricPrimitives._();

  static Uint8List hkdfSha256({
    required Uint8List ikm,
    required Uint8List salt,
    required Uint8List info,
    int outputBytes = pqForgeDefaultSessionKeyBytes,
  }) {
    RangeError.checkValueInInterval(outputBytes, 1, 255 * 32, 'outputBytes');
    final derivator = pc.HKDFKeyDerivator(pc.SHA256Digest())
      ..init(pc.HkdfParameters(ikm, outputBytes, salt, info));
    final out = Uint8List(outputBytes);
    derivator.deriveKey(null, 0, out, 0);
    return out;
  }

  static Uint8List aesGcmEncrypt({
    required Uint8List key,
    required Uint8List nonce,
    required Uint8List plaintext,
    Uint8List? aad,
  }) {
    requireLength('key', key, pqForgeDefaultSessionKeyBytes);
    requireLength('nonce', nonce, pqForgeDefaultAeadNonceBytes);
    final cipher = pc.GCMBlockCipher(pc.AESEngine())
      ..init(
        true,
        pc.AEADParameters(
          pc.KeyParameter(key),
          128,
          nonce,
          aad ?? Uint8List(0),
        ),
      );
    return cipher.process(plaintext);
  }

  static Uint8List aesGcmDecrypt({
    required Uint8List key,
    required Uint8List nonce,
    required Uint8List ciphertext,
    Uint8List? aad,
  }) {
    requireLength('key', key, pqForgeDefaultSessionKeyBytes);
    requireLength('nonce', nonce, pqForgeDefaultAeadNonceBytes);
    final cipher = pc.GCMBlockCipher(pc.AESEngine())
      ..init(
        false,
        pc.AEADParameters(
          pc.KeyParameter(key),
          128,
          nonce,
          aad ?? Uint8List(0),
        ),
      );
    return cipher.process(ciphertext);
  }

  static Uint8List argon2id({
    required String password,
    required Uint8List salt,
    int outputBytes = pqForgeDefaultSessionKeyBytes,
    int iterations = 2,
    int memoryPowerOf2 = 16,
    int lanes = 4,
  }) {
    final params = pc.Argon2Parameters(
      pc.Argon2Parameters.ARGON2_id,
      salt,
      desiredKeyLength: outputBytes,
      iterations: iterations,
      memoryPowerOf2: memoryPowerOf2,
      lanes: lanes,
    );
    final generator = pc.Argon2BytesGenerator()..init(params);
    return generator.process(Uint8List.fromList(utf8.encode(password)));
  }

  /// PBKDF2-HMAC-SHA256 (NIST SP 800-132) — the FIPS-approved password KDF,
  /// offered alongside Argon2id for deployments that require it.
  ///
  /// [iterations] defaults to the OWASP-recommended 600 000 for HMAC-SHA256;
  /// lower it only in tests.
  static Uint8List pbkdf2Sha256({
    required String password,
    required Uint8List salt,
    int outputBytes = pqForgeDefaultSessionKeyBytes,
    int iterations = 600000,
  }) {
    RangeError.checkValueInInterval(iterations, 1, 1 << 31, 'iterations');
    final derivator = pc.PBKDF2KeyDerivator(pc.HMac(pc.SHA256Digest(), 64))
      ..init(pc.Pbkdf2Parameters(salt, iterations, outputBytes));
    return derivator.process(Uint8List.fromList(utf8.encode(password)));
  }
}
