import 'dart:convert';
import 'dart:typed_data';

import 'package:pqforge/pqforge.dart';
import 'package:test/test.dart';

void main() {
  group('PqEcdsaP521', () {
    test('sign/verify round-trips and is deterministic', () {
      final kp = PqEcdsaP521.generateKeyPair();
      expect(kp.publicKey, hasLength(133));
      expect(kp.publicKey.first, 0x04);
      expect(kp.secretKey, hasLength(66));
      expect(PqEcdsaP521.publicKeyFromPrivate(kp.secretKey), kp.publicKey);
      final message = Uint8List.fromList(utf8.encode('p521 signature'));
      final first = PqEcdsaP521.sign(
        privateKey: kp.secretKey,
        message: message,
      );
      final second = PqEcdsaP521.sign(
        privateKey: kp.secretKey,
        message: message,
      );
      expect(first, hasLength(132));
      expect(second, orderedEquals(first));
      expect(
        PqEcdsaP521.verify(
          publicKey: kp.publicKey,
          message: message,
          signature: first,
        ),
        isTrue,
      );
      final flipped = Uint8List.fromList(first)..[131] ^= 1;
      expect(
        PqEcdsaP521.verify(
          publicKey: kp.publicKey,
          message: message,
          signature: flipped,
        ),
        isFalse,
      );
    });
  });
}
