/// Thin adapters over pqcrypto, PointyCastle, and `package:cryptography`.
library;

import 'dart:convert';
import 'dart:math';
import 'dart:typed_data';

import 'package:cryptography/cryptography.dart' as crypto;
import 'package:cryptography/dart.dart' as crypto_dart;
import 'package:pointycastle/export.dart' as pc;
import 'package:pqcrypto/pqcrypto.dart';
import 'package:pqforge/src/exceptions/pqforge_exception.dart';

import '../algorithms/pq_algorithms.dart';
import '../algorithms/pq_lattice_provider.dart';
import '../cipher/pq_cipher_suite.dart';
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
    // Written as two uint32 halves: ByteData.setUint64 throws on dart2js,
    // and `~/`//`%` stay exact there for every legitimate value (frame
    // counters, content lengths — all far below 2^53).
    return Uint8List(8)
      ..buffer.asByteData().setUint32(0, value ~/ 0x100000000, Endian.big)
      ..buffer.asByteData().setUint32(4, value % 0x100000000, Endian.big);
  }

  /// Reads a big-endian uint64 at [offset] — the inverse of [uint64].
  ///
  /// Decoded as two uint32 halves so it runs on dart2js (no
  /// `ByteData.getUint64`). Values at or above 2^53 are rejected: nothing in
  /// any pqforge format legitimately produces them, and they cannot be
  /// represented exactly on the web.
  static int readUint64(Uint8List bytes, [int offset = 0]) {
    final view = ByteData.sublistView(bytes, offset, offset + 8);
    final hi = view.getUint32(0, Endian.big);
    final lo = view.getUint32(4, Endian.big);
    if (hi > 0x1FFFFF) {
      throw const PqForgeException('uint64 field exceeds 2^53-1');
    }
    return hi * 0x100000000 + lo;
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

  /// SHA-384 one-shot digest (48 bytes).
  static Uint8List sha384(Uint8List data) => pc.SHA384Digest().process(data);

  /// SHA-512 one-shot digest (64 bytes).
  static Uint8List sha512(Uint8List data) => pc.SHA512Digest().process(data);

  /// SHA-256 over a byte stream in O(1) memory — one digest update per chunk,
  /// never the whole input. This is what lets the CLI pre-hash gigabyte-scale
  /// artifacts for digest-mode signing without buffering them.
  static Future<Uint8List> sha256OfStream(Stream<List<int>> chunks) async {
    final digest = pc.SHA256Digest();
    await for (final chunk in chunks) {
      final bytes = chunk is Uint8List ? chunk : Uint8List.fromList(chunk);
      digest.update(bytes, 0, bytes.length);
    }
    final out = Uint8List(digest.digestSize);
    digest.doFinal(out, 0);
    return out;
  }

  /// SHA-384 over a byte stream in O(1) memory.
  static Future<Uint8List> sha384OfStream(Stream<List<int>> chunks) async {
    final digest = pc.SHA384Digest();
    await for (final chunk in chunks) {
      final bytes = chunk is Uint8List ? chunk : Uint8List.fromList(chunk);
      digest.update(bytes, 0, bytes.length);
    }
    final out = Uint8List(digest.digestSize);
    digest.doFinal(out, 0);
    return out;
  }

  /// SHA-512 over a byte stream in O(1) memory.
  static Future<Uint8List> sha512OfStream(Stream<List<int>> chunks) async {
    final digest = pc.SHA512Digest();
    await for (final chunk in chunks) {
      final bytes = chunk is Uint8List ? chunk : Uint8List.fromList(chunk);
      digest.update(bytes, 0, bytes.length);
    }
    final out = Uint8List(digest.digestSize);
    digest.doFinal(out, 0);
    return out;
  }

  static Uint8List hmacSha256({
    required Uint8List key,
    required Uint8List data,
  }) {
    final hmac = pc.HMac(pc.SHA256Digest(), 64)..init(pc.KeyParameter(key));
    return hmac.process(data);
  }

  /// HMAC-SHA-384 (48-byte tag).
  static Uint8List hmacSha384({
    required Uint8List key,
    required Uint8List data,
  }) {
    final hmac = pc.HMac(pc.SHA384Digest(), 128)..init(pc.KeyParameter(key));
    return hmac.process(data);
  }

  /// HMAC-SHA-512 (64-byte tag).
  static Uint8List hmacSha512({
    required Uint8List key,
    required Uint8List data,
  }) {
    final hmac = pc.HMac(pc.SHA512Digest(), 128)..init(pc.KeyParameter(key));
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
  static Uint8List sha384(Uint8List data) => PqBytes.sha384(data);
  static Uint8List sha512(Uint8List data) => PqBytes.sha512(data);
  static Uint8List hmacSha256({
    required Uint8List key,
    required Uint8List data,
  }) => PqBytes.hmacSha256(key: key, data: data);
  static Uint8List hmacSha384({
    required Uint8List key,
    required Uint8List data,
  }) => PqBytes.hmacSha384(key: key, data: data);
  static Uint8List hmacSha512({
    required Uint8List key,
    required Uint8List data,
  }) => PqBytes.hmacSha512(key: key, data: data);
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

  /// FIPS 203 §7.2 encapsulation-key check **before** a live encapsulate.
  ///
  /// Returns `false` (never throws) for a wrong length or a key whose
  /// 12-bit coefficients are not in `[0, q)`. Valid keys return `true`.
  /// pqcrypto performs the modulus check; this wrapper does not reimplement
  /// ML-KEM.
  static bool checkEncapsulationKey(
    PqKemAlgorithm algorithm,
    Uint8List encapsulationKey,
  ) {
    if (encapsulationKey.length != algorithm.publicKeyBytes) {
      return false;
    }
    final nonce = Uint8List(32)..[0] = 0x01;
    try {
      final (ciphertext, sharedSecret) = PqLattice.provider.kemEncapsulate(
        algorithm,
        encapsulationKey,
        nonce: nonce,
      );
      sharedSecret.fillRange(0, sharedSecret.length, 0);
      ciphertext.fillRange(0, ciphertext.length, 0);
      return true;
    } on ArgumentError {
      return false;
    }
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

/// FIPS 205 SLH-DSA adapters over `pqcrypto`. Hash-based, not lattice — this
/// is a sibling of [PqSignaturePrimitives], not a [PqLatticeProvider] surface.
class PqSlhDsaPrimitives {
  const PqSlhDsaPrimitives._();

  static PqKeyPair generateKeyPair(PqSlhDsaAlgorithm algorithm) {
    final (publicKey, secretKey) = SlhDsa.generateKeyPair(_params(algorithm));
    requireLength('publicKey', publicKey, algorithm.publicKeyBytes);
    requireLength('secretKey', secretKey, algorithm.secretKeyBytes);
    return PqKeyPair(publicKey: publicKey, secretKey: secretKey);
  }

  /// Hedged FIPS 205 Algorithm 22, or HashSLH-DSA Algorithm 23 when [preHash]
  /// is set (default pre-hash: SHA-256, matching pqforge recipe digesting).
  ///
  /// Slow `s` parameter sets require [allowSlowSigning], matching `pqcrypto`.
  static Uint8List sign(
    PqSlhDsaAlgorithm algorithm,
    Uint8List secretKey,
    Uint8List message, {
    Uint8List? context,
    bool preHash = false,
    PqSlhDsaPreHash hash = PqSlhDsaPreHash.sha256,
    bool allowSlowSigning = false,
  }) {
    requireLength('secretKey', secretKey, algorithm.secretKeyBytes);
    requireDsaContext(context);
    final params = _params(algorithm);
    try {
      return preHash
          ? SlhDsa.hashSign(
              secretKey,
              message,
              _preHash(hash),
              params,
              context: context,
              allowSlowSigning: allowSlowSigning,
            )
          : SlhDsa.sign(
              secretKey,
              message,
              params,
              context: context,
              allowSlowSigning: allowSlowSigning,
            );
    } on UnsupportedError catch (error) {
      throw PqForgeException(error.message ?? '$error');
    }
  }

  static bool verify(
    PqSlhDsaAlgorithm algorithm,
    Uint8List publicKey,
    Uint8List message,
    Uint8List signature, {
    Uint8List? context,
    bool preHash = false,
    PqSlhDsaPreHash hash = PqSlhDsaPreHash.sha256,
  }) {
    if (publicKey.length != algorithm.publicKeyBytes ||
        signature.length != algorithm.signatureBytes ||
        (context?.length ?? 0) > 255) {
      return false;
    }
    final params = _params(algorithm);
    return preHash
        ? SlhDsa.hashVerify(
            publicKey,
            message,
            signature,
            _preHash(hash),
            params,
            context: context,
          )
        : SlhDsa.verify(
            publicKey,
            message,
            signature,
            params,
            context: context,
          );
  }

  static SlhDsaParams _params(PqSlhDsaAlgorithm algorithm) =>
      switch (algorithm) {
        PqSlhDsaAlgorithm.sha2128s => SlhDsaParams.sha2128s,
        PqSlhDsaAlgorithm.sha2128f => SlhDsaParams.sha2128f,
        PqSlhDsaAlgorithm.sha2192s => SlhDsaParams.sha2192s,
        PqSlhDsaAlgorithm.sha2192f => SlhDsaParams.sha2192f,
        PqSlhDsaAlgorithm.sha2256s => SlhDsaParams.sha2256s,
        PqSlhDsaAlgorithm.sha2256f => SlhDsaParams.sha2256f,
        PqSlhDsaAlgorithm.shake128s => SlhDsaParams.shake128s,
        PqSlhDsaAlgorithm.shake128f => SlhDsaParams.shake128f,
        PqSlhDsaAlgorithm.shake192s => SlhDsaParams.shake192s,
        PqSlhDsaAlgorithm.shake192f => SlhDsaParams.shake192f,
        PqSlhDsaAlgorithm.shake256s => SlhDsaParams.shake256s,
        PqSlhDsaAlgorithm.shake256f => SlhDsaParams.shake256f,
      };

  static SlhDsaPreHash _preHash(PqSlhDsaPreHash hash) => switch (hash) {
    PqSlhDsaPreHash.sha224 => SlhDsaPreHash.sha224,
    PqSlhDsaPreHash.sha256 => SlhDsaPreHash.sha256,
    PqSlhDsaPreHash.sha384 => SlhDsaPreHash.sha384,
    PqSlhDsaPreHash.sha512 => SlhDsaPreHash.sha512,
    PqSlhDsaPreHash.sha512224 => SlhDsaPreHash.sha512224,
    PqSlhDsaPreHash.sha512256 => SlhDsaPreHash.sha512256,
    PqSlhDsaPreHash.sha3224 => SlhDsaPreHash.sha3224,
    PqSlhDsaPreHash.sha3256 => SlhDsaPreHash.sha3256,
    PqSlhDsaPreHash.sha3384 => SlhDsaPreHash.sha3384,
    PqSlhDsaPreHash.sha3512 => SlhDsaPreHash.sha3512,
    PqSlhDsaPreHash.shake128 => SlhDsaPreHash.shake128,
    PqSlhDsaPreHash.shake256 => SlhDsaPreHash.shake256,
  };
}

class PqSymmetricPrimitives {
  const PqSymmetricPrimitives._();

  /// Sync ChaCha20-Poly1305 (RFC 8439) is available on this runtime.
  ///
  /// Always `true`. The helper uses `package:cryptography`'s Dart engine
  /// (32-bit Poly1305), not PointyCastle's 64-bit Poly1305. dart2js can
  /// run it. Callers must **not** copy PointyCastle's `2^53` mantissa check.
  static bool get supportsChaCha20Poly1305 => true;

  /// Dart ChaCha20-Poly1305. Pinned so dart2js does not go through
  /// `Cryptography.instance` (browser Web Crypto has no ChaCha).
  static const _syncChaCha = crypto_dart.DartChacha20.poly1305Aead();

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

  /// RFC 5869 HKDF-Extract with SHA-256. Empty/null [salt] is HashLen zeros.
  static Uint8List hkdfExtractSha256({
    required Uint8List ikm,
    Uint8List? salt,
  }) =>
      _hkdfExtract(hmac: PqBytes.hmacSha256, hashLen: 32, ikm: ikm, salt: salt);

  /// RFC 5869 HKDF-Expand with SHA-256.
  static Uint8List hkdfExpandSha256({
    required Uint8List prk,
    required Uint8List info,
    required int outputBytes,
  }) => _hkdfExpand(
    hmac: PqBytes.hmacSha256,
    hashLen: 32,
    prk: prk,
    info: info,
    outputBytes: outputBytes,
  );

  /// Combined HKDF-SHA-384 (Extract then Expand), matching [hkdfSha256].
  static Uint8List hkdfSha384({
    required Uint8List ikm,
    required Uint8List salt,
    required Uint8List info,
    int outputBytes = 48,
  }) {
    RangeError.checkValueInInterval(outputBytes, 1, 255 * 48, 'outputBytes');
    final derivator = pc.HKDFKeyDerivator(pc.SHA384Digest())
      ..init(pc.HkdfParameters(ikm, outputBytes, salt, info));
    final out = Uint8List(outputBytes);
    derivator.deriveKey(null, 0, out, 0);
    return out;
  }

  /// RFC 5869 HKDF-Extract with SHA-384.
  static Uint8List hkdfExtractSha384({
    required Uint8List ikm,
    Uint8List? salt,
  }) =>
      _hkdfExtract(hmac: PqBytes.hmacSha384, hashLen: 48, ikm: ikm, salt: salt);

  /// RFC 5869 HKDF-Expand with SHA-384.
  static Uint8List hkdfExpandSha384({
    required Uint8List prk,
    required Uint8List info,
    required int outputBytes,
  }) => _hkdfExpand(
    hmac: PqBytes.hmacSha384,
    hashLen: 48,
    prk: prk,
    info: info,
    outputBytes: outputBytes,
  );

  static Uint8List _hkdfExtract({
    required Uint8List Function({
      required Uint8List key,
      required Uint8List data,
    })
    hmac,
    required int hashLen,
    required Uint8List ikm,
    Uint8List? salt,
  }) {
    final actualSalt = (salt == null || salt.isEmpty)
        ? Uint8List(hashLen)
        : salt;
    return hmac(key: actualSalt, data: ikm);
  }

  static Uint8List _hkdfExpand({
    required Uint8List Function({
      required Uint8List key,
      required Uint8List data,
    })
    hmac,
    required int hashLen,
    required Uint8List prk,
    required Uint8List info,
    required int outputBytes,
  }) {
    RangeError.checkValueInInterval(
      outputBytes,
      1,
      255 * hashLen,
      'outputBytes',
    );
    final n = (outputBytes + hashLen - 1) ~/ hashLen;
    final okm = Uint8List(n * hashLen);
    var previous = Uint8List(0);
    var offset = 0;
    for (var i = 1; i <= n; i++) {
      final block = hmac(
        key: prk,
        data: PqBytes.concat([
          previous,
          info,
          Uint8List.fromList([i]),
        ]),
      );
      okm.setRange(offset, offset + hashLen, block);
      offset += hashLen;
      previous = block;
    }
    return Uint8List.sublistView(okm, 0, outputBytes);
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

  /// Sync ChaCha20-Poly1305 (RFC 8439). [key] is 32 bytes, [nonce] is 12 bytes
  /// and **caller-supplied**. Returns `ciphertext || tag` (16-byte tag).
  ///
  /// Uses the cryptography Dart engine (32-bit Poly1305), so this runs on
  /// dart2js. Distinct from [PqForgeSecureSession.encrypt], which is async,
  /// generates its own nonce, and prepends it. The PointyCastle session
  /// engine's ChaCha path still needs 64-bit integers; do not treat that
  /// engine as this helper.
  static Uint8List chacha20Poly1305Encrypt({
    required Uint8List key,
    required Uint8List nonce,
    required Uint8List plaintext,
    Uint8List? aad,
  }) {
    requireLength('key', key, 32);
    requireLength('nonce', nonce, pqForgeDefaultAeadNonceBytes);
    return _chacha20Poly1305(
      forEncryption: true,
      key: key,
      nonce: nonce,
      data: plaintext,
      aad: aad ?? Uint8List(0),
    );
  }

  /// Sync ChaCha20-Poly1305 open. [ciphertext] is `ciphertext || tag`.
  /// Throws [PqForgeAuthTagException] on a failed tag.
  static Uint8List chacha20Poly1305Decrypt({
    required Uint8List key,
    required Uint8List nonce,
    required Uint8List ciphertext,
    Uint8List? aad,
  }) {
    requireLength('key', key, 32);
    requireLength('nonce', nonce, pqForgeDefaultAeadNonceBytes);
    if (ciphertext.length < 16) {
      throw const PqForgeAuthTagException(
        'ciphertext is shorter than the authentication tag',
      );
    }
    try {
      return _chacha20Poly1305(
        forEncryption: false,
        key: key,
        nonce: nonce,
        data: ciphertext,
        aad: aad ?? Uint8List(0),
      );
    } on crypto.SecretBoxAuthenticationError {
      throw const PqForgeAuthTagException(
        'chacha20-poly1305 authentication tag verification failed',
      );
    }
  }

  static Uint8List _chacha20Poly1305({
    required bool forEncryption,
    required Uint8List key,
    required Uint8List nonce,
    required Uint8List data,
    required Uint8List aad,
  }) {
    final secretKey = crypto.SecretKeyData(key);
    if (forEncryption) {
      final box = _syncChaCha.encryptSync(
        data,
        secretKey: secretKey,
        nonce: nonce,
        aad: aad,
      );
      final cipherText = box.cipherText;
      final tag = box.mac.bytes;
      return Uint8List(cipherText.length + tag.length)
        ..setRange(0, cipherText.length, cipherText)
        ..setRange(cipherText.length, cipherText.length + tag.length, tag);
    }
    final tagLength = 16;
    final split = data.length - tagLength;
    final box = crypto.SecretBox(
      Uint8List.sublistView(data, 0, split),
      nonce: nonce,
      mac: crypto.Mac(Uint8List.sublistView(data, split)),
    );
    final clear = _syncChaCha.decryptSync(box, secretKey: secretKey, aad: aad);
    return Uint8List.fromList(clear);
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
