import 'dart:convert';
import 'dart:typed_data';

import 'package:pointycastle/export.dart' as pc;
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
    test('verify accepts the high-S form and a compressed point', () {
      final kp = PqEcdsaP384.generateKeyPair();
      final message = Uint8List.fromList([1, 2, 3]);
      final signature = PqEcdsaP384.sign(
        privateKey: kp.secretKey,
        message: message,
      );
      final n = pc.ECCurve_secp384r1().n;
      final s = _be(signature.sublist(48));
      final high = Uint8List.fromList(signature)
        ..setRange(48, 96, _fixed(n - s, 48));
      expect(
        PqEcdsaP384.verify(
          publicKey: kp.publicKey,
          message: message,
          signature: high,
        ),
        isTrue,
      );
      final point = pc.ECCurve_secp384r1().curve.decodePoint(kp.publicKey)!;
      final compressed = Uint8List.fromList(point.getEncoded(true));
      expect(compressed.length, 49);
      expect(
        PqEcdsaP384.verify(
          publicKey: compressed,
          message: message,
          signature: signature,
        ),
        isTrue,
      );
    });
  });
}

BigInt _be(List<int> bytes) {
  var value = BigInt.zero;
  for (final byte in bytes) {
    value = (value << 8) | BigInt.from(byte);
  }
  return value;
}

Uint8List _fixed(BigInt value, int length) {
  final out = Uint8List(length);
  final mask = BigInt.from(0xff);
  var rest = value;
  for (var i = length - 1; i >= 0; i--) {
    out[i] = (rest & mask).toInt();
    rest >>= 8;
  }
  return out;
}
