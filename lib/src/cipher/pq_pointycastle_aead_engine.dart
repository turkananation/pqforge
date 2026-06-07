/// Pure-Dart AEAD engine backed by PointyCastle (engine path 1).
library;

import 'dart:typed_data';

import 'package:pointycastle/export.dart' as pc;

import 'pq_cipher_suite.dart';

/// [PqForgeAeadEngine] implemented entirely in Dart via PointyCastle.
///
/// * AES-256-GCM uses `GCMBlockCipher(AESEngine())`.
/// * ChaCha20-Poly1305 uses `ChaCha20Poly1305(ChaCha7539Engine(), Poly1305())`.
///
/// Both produce the same `ciphertext || tag` layout as the `cryptography`
/// backend, so packets are byte-for-byte interoperable across engines.
final class PqForgePointyCastleAeadEngine implements PqForgeAeadEngine {
  const PqForgePointyCastleAeadEngine(this.cipherSuite);

  @override
  final PqForgeCipherSuite cipherSuite;

  @override
  PqForgeEngineProvider get provider => PqForgeEngineProvider.pureDart;

  @override
  Future<Uint8List> seal({
    required Uint8List key,
    required Uint8List nonce,
    required Uint8List plaintext,
    required Uint8List aad,
  }) async {
    cipherSuite.requireKey(key);
    cipherSuite.requireNonce(nonce);
    return _crypt(
      forEncryption: true,
      key: key,
      nonce: nonce,
      data: plaintext,
      aad: aad,
    );
  }

  @override
  Future<Uint8List> open({
    required Uint8List key,
    required Uint8List nonce,
    required Uint8List cipherTextWithTag,
    required Uint8List aad,
  }) async {
    cipherSuite.requireKey(key);
    cipherSuite.requireNonce(nonce);
    if (cipherTextWithTag.length < cipherSuite.tagLength) {
      throw const PqForgeAuthTagException(
        'ciphertext is shorter than the authentication tag',
      );
    }
    try {
      return _crypt(
        forEncryption: false,
        key: key,
        nonce: nonce,
        data: cipherTextWithTag,
        aad: aad,
      );
    } on pc.InvalidCipherTextException {
      // GCMBlockCipher reports a failed tag this way.
      throw _authFailure();
    } on ArgumentError catch (error) {
      // PointyCastle's ChaCha20Poly1305 reports a failed tag as an ArgumentError
      // ('mac check in ChaCha20Poly1305 failed'); anything else is a real bug.
      if (error.message?.toString().contains('mac check') == true) {
        throw _authFailure();
      }
      rethrow;
    }
  }

  // Builds and runs the selected AEAD cipher to completion. GCMBlockCipher and
  // ChaCha20Poly1305 share no AEAD supertype but expose the same drive surface
  // (getOutputSize / processBytes / doFinal), so each branch feeds a closure to
  // the shared zeroizing runner.
  Uint8List _crypt({
    required bool forEncryption,
    required Uint8List key,
    required Uint8List nonce,
    required Uint8List data,
    required Uint8List aad,
  }) {
    final params = _params(key, nonce, aad);
    switch (cipherSuite) {
      case PqForgeCipherSuite.aes256Gcm:
        final cipher = pc.GCMBlockCipher(pc.AESEngine())
          ..init(forEncryption, params);
        return _runZeroizing(cipher.getOutputSize(data.length), (out) {
          final n = cipher.processBytes(data, 0, data.length, out, 0);
          return n + cipher.doFinal(out, n);
        });
      case PqForgeCipherSuite.chaCha20Poly1305:
        final cipher = pc.ChaCha20Poly1305(pc.ChaCha7539Engine(), pc.Poly1305())
          ..init(forEncryption, params);
        return _runZeroizing(cipher.getOutputSize(data.length), (out) {
          final n = cipher.processBytes(data, 0, data.length, out, 0);
          return n + cipher.doFinal(out, n);
        });
    }
  }

  // Sizes the output buffer, runs [fill], and returns the written prefix. If the
  // run throws (most importantly a failed tag check on decryption, where `out`
  // already holds unauthenticated plaintext), the buffer is zeroized before the
  // error propagates so the fragments never linger in the heap.
  Uint8List _runZeroizing(int outputSize, int Function(Uint8List out) fill) {
    final out = Uint8List(outputSize);
    try {
      final written = fill(out);
      return written == out.length
          ? out
          : Uint8List.sublistView(out, 0, written);
    } catch (_) {
      out.fillRange(0, out.length, 0);
      rethrow;
    }
  }

  pc.AEADParameters<pc.KeyParameter> _params(
    Uint8List key,
    Uint8List nonce,
    Uint8List aad,
  ) => pc.AEADParameters(
    pc.KeyParameter(key),
    cipherSuite.tagLength * 8,
    nonce,
    aad,
  );

  PqForgeAuthTagException _authFailure() => PqForgeAuthTagException(
    '${cipherSuite.id} authentication tag verification failed',
  );
}
