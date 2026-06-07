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
    return switch (cipherSuite) {
      PqForgeCipherSuite.aes256Gcm => (pc.GCMBlockCipher(
        pc.AESEngine(),
      )..init(true, _params(key, nonce, aad))).process(plaintext),
      PqForgeCipherSuite.chaCha20Poly1305 => _drive(
        pc.ChaCha20Poly1305(pc.ChaCha7539Engine(), pc.Poly1305())
          ..init(true, _params(key, nonce, aad)),
        plaintext,
      ),
    };
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
      return switch (cipherSuite) {
        PqForgeCipherSuite.aes256Gcm => (pc.GCMBlockCipher(
          pc.AESEngine(),
        )..init(false, _params(key, nonce, aad))).process(cipherTextWithTag),
        PqForgeCipherSuite.chaCha20Poly1305 => _drive(
          pc.ChaCha20Poly1305(pc.ChaCha7539Engine(), pc.Poly1305())
            ..init(false, _params(key, nonce, aad)),
          cipherTextWithTag,
        ),
      };
    } on pc.InvalidCipherTextException {
      // GCMBlockCipher reports a failed tag this way.
      throw _authFailure();
    } on ArgumentError catch (error) {
      // PointyCastle's ChaCha20Poly1305 reports a failed tag as an ArgumentError
      // ('mac check in ChaCha20Poly1305 failed'); anything else is a real bug.
      if (error.message.toString().contains('mac check')) {
        throw _authFailure();
      }
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

  // GCMBlockCipher.process() finalises on its own, but ChaCha20Poly1305 (a
  // stream AEADCipher) does not — its process() neither calls doFinal nor sizes
  // the output for the tag. So we size against getOutputSize and finalise here.
  Uint8List _drive(pc.ChaCha20Poly1305 cipher, Uint8List input) {
    final out = Uint8List(cipher.getOutputSize(input.length));
    var written = cipher.processBytes(input, 0, input.length, out, 0);
    written += cipher.doFinal(out, written);
    return written == out.length ? out : Uint8List.sublistView(out, 0, written);
  }

  PqForgeAuthTagException _authFailure() => PqForgeAuthTagException(
    '${cipherSuite.id} authentication tag verification failed',
  );
}
