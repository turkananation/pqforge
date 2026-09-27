import 'dart:typed_data';

import 'package:pqforge/pqforge.dart';
import 'package:test/test.dart';

void main() {
  group('AES-ECB block (QUIC header protection)', () {
    test('FIPS 197 C.1 AES-128', () {
      final key = _hex('000102030405060708090a0b0c0d0e0f');
      final block = _hex('00112233445566778899aabbccddeeff');
      expect(
        PqSymmetricPrimitives.aesEncryptBlock(key: key, block: block),
        orderedEquals(_hex('69c4e0d86a7b0430d8cdb78070b4c55a')),
      );
    });

    test('FIPS 197 C.3 AES-256', () {
      final key = _hex(
        '000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f',
      );
      final block = _hex('00112233445566778899aabbccddeeff');
      expect(
        PqSymmetricPrimitives.aesEncryptBlock(key: key, block: block),
        orderedEquals(_hex('8ea2b7ca516745bfeafc49904b496089')),
      );
    });

    test('wrong key or block length is refused', () {
      expect(
        () => PqSymmetricPrimitives.aesEncryptBlock(
          key: Uint8List(24),
          block: Uint8List(16),
        ),
        throwsArgumentError,
      );
      expect(
        () => PqSymmetricPrimitives.aesEncryptBlock(
          key: Uint8List(16),
          block: Uint8List(15),
        ),
        throwsArgumentError,
      );
    });
  });

  group('AES-128-GCM (QUIC Initial)', () {
    test('NIST empty plaintext tag', () {
      final key = Uint8List(16);
      final nonce = Uint8List(12);
      final sealed = PqSymmetricPrimitives.aes128GcmEncrypt(
        key: key,
        nonce: nonce,
        plaintext: Uint8List(0),
      );
      expect(sealed, orderedEquals(_hex('58e2fccefa7e3061367f1d57a4e7455a')));
      expect(
        PqSymmetricPrimitives.aes128GcmDecrypt(
          key: key,
          nonce: nonce,
          ciphertext: sealed,
        ),
        isEmpty,
      );
    });

    test('round-trip with AAD; bit-flip fails', () {
      final key = PqBytes.randomBytes(16);
      final nonce = PqBytes.randomBytes(12);
      final pt = Uint8List.fromList('quic initial'.codeUnits);
      final aad = Uint8List.fromList([0xc0, 0x00, 0x00, 0x00, 0x01]);
      final sealed = PqSymmetricPrimitives.aes128GcmEncrypt(
        key: key,
        nonce: nonce,
        plaintext: pt,
        aad: aad,
      );
      expect(
        PqSymmetricPrimitives.aes128GcmDecrypt(
          key: key,
          nonce: nonce,
          ciphertext: sealed,
          aad: aad,
        ),
        orderedEquals(pt),
      );
      sealed[0] ^= 1;
      expect(
        () => PqSymmetricPrimitives.aes128GcmDecrypt(
          key: key,
          nonce: nonce,
          ciphertext: sealed,
          aad: aad,
        ),
        throwsA(anything),
      );
    });
  });
}

Uint8List _hex(String hex) {
  final s = hex.replaceAll(RegExp(r'\s'), '');
  final out = Uint8List(s.length ~/ 2);
  for (var i = 0; i < out.length; i++) {
    out[i] = int.parse(s.substring(i * 2, i * 2 + 2), radix: 16);
  }
  return out;
}
