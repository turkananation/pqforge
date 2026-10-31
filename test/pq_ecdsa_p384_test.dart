import 'dart:convert';
import 'dart:typed_data';

import 'package:pqforge/pqforge.dart';
import 'package:test/test.dart';

void main() {
  group('PqEcdsaP384', () {
    test('sign/verify round-trips and is deterministic', () {
      final kp = PqEcdsaP384.generateKeyPair();
      expect(kp.publicKey, hasLength(97));
      expect(kp.publicKey.first, 0x04);
      expect(kp.secretKey, hasLength(48));
      final message = Uint8List.fromList(utf8.encode('p384 signature'));
      final first = PqEcdsaP384.sign(
        privateKey: kp.secretKey,
        message: message,
      );
      final second = PqEcdsaP384.sign(
        privateKey: kp.secretKey,
        message: message,
      );
      expect(first, hasLength(96));
      expect(second, orderedEquals(first));
      expect(
        PqEcdsaP384.verify(
          publicKey: kp.publicKey,
          message: message,
          signature: first,
        ),
        isTrue,
      );
      final flipped = Uint8List.fromList(first)..[95] ^= 1;
      expect(
        PqEcdsaP384.verify(
          publicKey: kp.publicKey,
          message: message,
          signature: flipped,
        ),
        isFalse,
      );
    });

    test('verify returns false for a truncated signature', () {
      final kp = PqEcdsaP384.generateKeyPair();
      expect(
        PqEcdsaP384.verify(
          publicKey: kp.publicKey,
          message: Uint8List(1),
          signature: Uint8List(10),
        ),
        isFalse,
      );
    });

    test('publicKeyFromPrivate recovers the point', () {
      final kp = PqEcdsaP384.generateKeyPair();
      expect(
        PqEcdsaP384.publicKeyFromPrivate(kp.secretKey),
        orderedEquals(kp.publicKey),
      );
    });
  });
}
