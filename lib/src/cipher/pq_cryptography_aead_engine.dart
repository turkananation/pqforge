/// High-performance AEAD engine backed by `package:cryptography` (engine path 2).
library;

import 'dart:typed_data';

import 'package:cryptography/cryptography.dart' as crypto;

import 'pq_cipher_suite.dart';

/// [PqForgeAeadEngine] implemented with `package:cryptography`.
///
/// On platforms with hardware-accelerated OS bindings (and on the web via
/// `package:cryptography`'s browser implementations) this can be substantially
/// faster than the pure-Dart engine. The `cryptography` package returns the MAC
/// separately in a [crypto.SecretBox]; this engine appends it to the ciphertext
/// to produce the same `ciphertext || tag` body the PointyCastle engine emits.
final class PqForgeCryptographyAeadEngine implements PqForgeAeadEngine {
  PqForgeCryptographyAeadEngine(this.cipherSuite)
    : _cipher = switch (cipherSuite) {
        PqForgeCipherSuite.aes256Gcm => crypto.AesGcm.with256bits(),
        PqForgeCipherSuite.chaCha20Poly1305 => crypto.Chacha20.poly1305Aead(),
      };

  @override
  final PqForgeCipherSuite cipherSuite;

  @override
  PqForgeEngineProvider get provider =>
      PqForgeEngineProvider.nativeCryptography;

  final crypto.Cipher _cipher;

  @override
  Future<Uint8List> seal({
    required Uint8List key,
    required Uint8List nonce,
    required Uint8List plaintext,
    required Uint8List aad,
  }) async {
    cipherSuite.requireKey(key);
    cipherSuite.requireNonce(nonce);
    final box = await _cipher.encrypt(
      plaintext,
      secretKey: crypto.SecretKey(key),
      nonce: nonce,
      aad: aad,
    );
    final cipherText = box.cipherText;
    final tag = box.mac.bytes;
    return Uint8List(cipherText.length + tag.length)
      ..setRange(0, cipherText.length, cipherText)
      ..setRange(cipherText.length, cipherText.length + tag.length, tag);
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
    final tagLength = cipherSuite.tagLength;
    if (cipherTextWithTag.length < tagLength) {
      throw const PqForgeAuthTagException(
        'ciphertext is shorter than the authentication tag',
      );
    }
    final split = cipherTextWithTag.length - tagLength;
    final box = crypto.SecretBox(
      cipherTextWithTag.sublist(0, split),
      nonce: nonce,
      mac: crypto.Mac(cipherTextWithTag.sublist(split)),
    );
    try {
      final clear = await _cipher.decrypt(
        box,
        secretKey: crypto.SecretKey(key),
        aad: aad,
      );
      return Uint8List.fromList(clear);
    } on crypto.SecretBoxAuthenticationError {
      throw PqForgeAuthTagException(
        '${cipherSuite.id} authentication tag verification failed',
      );
    }
  }
}
