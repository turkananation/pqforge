import 'dart:typed_data';

import 'package:pqforge/pqforge.dart';
import 'package:test/test.dart';

void main() {
  group('ChaCha20 keystream (RFC 8439 / QUIC HP)', () {
    test('RFC 8439 §2.3.2 block count 1', () {
      final key = _hex(
        '000102030405060708090a0b0c0d0e0f'
        '101112131415161718191a1b1c1d1e1f',
      );
      final nonce = _hex('000000090000004a00000000');
      expect(
        PqSymmetricPrimitives.chacha20(key: key, nonce: nonce, counter: 1),
        orderedEquals(
          _hex(
            '10f1e7e4d13b5915500fdd1fa32071c4'
            'c7d1f4c733c068030422aa9ac3d46c4e'
            'd2826446079faa0914c2d705d98b02a2'
            'b5129cd1de164eb9cbd083e8a2503c4e',
          ),
        ),
      );
    });

    test('counter 0 is a different block from counter 1', () {
      final key = _hex(
        '000102030405060708090a0b0c0d0e0f'
        '101112131415161718191a1b1c1d1e1f',
      );
      final nonce = _hex('000000090000004a00000000');
      final block0 = PqSymmetricPrimitives.chacha20(
        key: key,
        nonce: nonce,
        counter: 0,
        length: 64,
      );
      final block1 = PqSymmetricPrimitives.chacha20(
        key: key,
        nonce: nonce,
        counter: 1,
        length: 64,
      );
      expect(block0, isNot(orderedEquals(block1)));
    });

    test('five bytes is the QUIC header-protection mask length', () {
      final key = Uint8List(32);
      final nonce = Uint8List(12);
      final mask = PqSymmetricPrimitives.chacha20(
        key: key,
        nonce: nonce,
        counter: 0,
        length: 5,
      );
      expect(mask, hasLength(5));
      final block = PqSymmetricPrimitives.chacha20(
        key: key,
        nonce: nonce,
        counter: 0,
        length: 64,
      );
      expect(mask, orderedEquals(block.sublist(0, 5)));
    });

    test('the Poly1305 AEAD is not the mask', () {
      final key = Uint8List(32);
      final nonce = Uint8List(12);
      final mask = PqSymmetricPrimitives.chacha20(
        key: key,
        nonce: nonce,
        counter: 0,
        length: 5,
      );
      final sealed = PqSymmetricPrimitives.chacha20Poly1305Encrypt(
        key: key,
        nonce: nonce,
        plaintext: Uint8List(5),
      );
      expect(sealed.length, 5 + 16);
      expect(sealed.sublist(0, 5), isNot(orderedEquals(mask)));
    });

    test('refuses a bad key, nonce, counter, or length', () {
      final key = Uint8List(32);
      final nonce = Uint8List(12);
      expect(
        () => PqSymmetricPrimitives.chacha20(
          key: Uint8List(31),
          nonce: nonce,
          counter: 0,
        ),
        throwsArgumentError,
      );
      expect(
        () => PqSymmetricPrimitives.chacha20(
          key: key,
          nonce: Uint8List(11),
          counter: 0,
        ),
        throwsArgumentError,
      );
      expect(
        () =>
            PqSymmetricPrimitives.chacha20(key: key, nonce: nonce, counter: -1),
        throwsArgumentError,
      );
      expect(
        () => PqSymmetricPrimitives.chacha20(
          key: key,
          nonce: nonce,
          counter: 0,
          length: 0,
        ),
        throwsArgumentError,
      );
    });
  });
}

Uint8List _hex(String hex) {
  final out = Uint8List(hex.length ~/ 2);
  for (var i = 0; i < out.length; i++) {
    out[i] = int.parse(hex.substring(i * 2, i * 2 + 2), radix: 16);
  }
  return out;
}
