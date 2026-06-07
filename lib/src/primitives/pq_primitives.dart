/// Thin adapters over pqcrypto and Pointy Castle.
library;

import 'dart:convert';
import 'dart:math';
import 'dart:typed_data';

import 'package:pointycastle/export.dart' as pc;
import 'package:pqcrypto/pqcrypto.dart';

import '../algorithms/pq_algorithms.dart';
import '../keys/pq_keys.dart';

final _secureRandom = Random.secure();

class PqBytes {
  const PqBytes._();

  static Uint8List randomBytes(int length) {
    if (length < 0) {
      throw ArgumentError.value(length, 'length', 'must be non-negative');
    }
    final bytes = Uint8List(length);
    for (var i = 0; i < length; i++) {
      bytes[i] = _secureRandom.nextInt(256);
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
    final (publicKey, secretKey) = _kem(algorithm).generateKeyPair(seed);
    return PqKeyPair(publicKey: publicKey, secretKey: secretKey);
  }

  static PqKemEncapsulation encapsulate(
    PqKemAlgorithm algorithm,
    Uint8List publicKey, {
    Uint8List? nonce,
  }) {
    requireLength('publicKey', publicKey, algorithm.publicKeyBytes);
    if (nonce != null) requireLength('nonce', nonce, 32);
    final (ciphertext, sharedSecret) = _kem(
      algorithm,
    ).encapsulate(publicKey, nonce);
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
    return _kem(algorithm).decapsulate(secretKey, ciphertext);
  }

  static KyberKem _kem(PqKemAlgorithm algorithm) => switch (algorithm) {
    PqKemAlgorithm.mlKem512 => PqcKem.kyber512,
    PqKemAlgorithm.mlKem768 => PqcKem.kyber768,
    PqKemAlgorithm.mlKem1024 => PqcKem.kyber1024,
  };
}

class PqSignaturePrimitives {
  const PqSignaturePrimitives._();

  static PqKeyPair generateKeyPair(PqSignatureAlgorithm algorithm) {
    final (publicKey, secretKey) = MlDsa.generateKeyPair(_params(algorithm));
    return PqKeyPair(publicKey: publicKey, secretKey: secretKey);
  }

  static PqKeyPair generateKeyPairSeeded(
    PqSignatureAlgorithm algorithm,
    Uint8List seed,
  ) {
    requireLength('seed', seed, 32);
    final (publicKey, secretKey) = MlDsa.generateKeyPairSeeded(
      _params(algorithm),
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
    final params = _params(algorithm);
    return preHash
        ? MlDsa.hashSign(secretKey, message, params, ctx: context)
        : MlDsa.sign(secretKey, message, params, ctx: context);
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
    final params = _params(algorithm);
    return preHash
        ? MlDsa.hashVerify(publicKey, message, signature, params, ctx: context)
        : MlDsa.verify(publicKey, message, signature, params, ctx: context);
  }

  static DilithiumParams _params(PqSignatureAlgorithm algorithm) {
    return switch (algorithm) {
      PqSignatureAlgorithm.mlDsa44 => DilithiumParams.mlDsa44,
      PqSignatureAlgorithm.mlDsa65 => DilithiumParams.mlDsa65,
      PqSignatureAlgorithm.mlDsa87 => DilithiumParams.mlDsa87,
    };
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
}
