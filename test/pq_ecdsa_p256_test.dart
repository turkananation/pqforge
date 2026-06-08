import 'dart:convert';
import 'dart:typed_data';

import 'package:pqforge/pqforge.dart';
import 'package:test/test.dart';

void main() {
  group('PqEcdsaP256', () {
    test('generates well-formed P-256 key material', () {
      final kp = PqEcdsaP256.generateKeyPair();
      expect(kp.secretKey, hasLength(PqEcdsaP256.privateKeyBytes)); // 32
      expect(kp.publicKey, hasLength(PqEcdsaP256.publicKeyBytes)); // 65
      expect(
        kp.publicKey.first,
        0x04,
        reason: 'uncompressed SEC1 point prefix',
      );
    });

    test('sign/verify round-trips', () {
      final kp = PqEcdsaP256.generateKeyPair();
      final message = _bytes('hybrid classical signature payload');
      final sig = PqEcdsaP256.sign(privateKey: kp.secretKey, message: message);

      expect(sig, hasLength(PqEcdsaP256.signatureBytes)); // 64 = r||s
      expect(
        PqEcdsaP256.verify(
          publicKey: kp.publicKey,
          message: message,
          signature: sig,
        ),
        isTrue,
      );
    });

    test(
      'uses deterministic (RFC 6979) nonces — same input, same signature',
      () {
        final kp = PqEcdsaP256.generateKeyPair();
        final message = _bytes('deterministic ecdsa');
        final a = PqEcdsaP256.sign(privateKey: kp.secretKey, message: message);
        final b = PqEcdsaP256.sign(privateKey: kp.secretKey, message: message);
        expect(a, orderedEquals(b));
      },
    );

    test('rejects a tampered signature, message, or wrong key', () {
      final kp = PqEcdsaP256.generateKeyPair();
      final other = PqEcdsaP256.generateKeyPair();
      final message = _bytes('authentic');
      final sig = PqEcdsaP256.sign(privateKey: kp.secretKey, message: message);

      final tampered = Uint8List.fromList(sig)..[63] ^= 0xFF;
      expect(
        PqEcdsaP256.verify(
          publicKey: kp.publicKey,
          message: message,
          signature: tampered,
        ),
        isFalse,
      );
      expect(
        PqEcdsaP256.verify(
          publicKey: kp.publicKey,
          message: _bytes('forged'),
          signature: sig,
        ),
        isFalse,
      );
      expect(
        PqEcdsaP256.verify(
          publicKey: other.publicKey,
          message: message,
          signature: sig,
        ),
        isFalse,
      );
    });

    test('verify returns false (never throws) for malformed inputs', () {
      final kp = PqEcdsaP256.generateKeyPair();
      final message = _bytes('x');
      final sig = PqEcdsaP256.sign(privateKey: kp.secretKey, message: message);

      expect(
        PqEcdsaP256.verify(
          publicKey: Uint8List(10),
          message: message,
          signature: sig,
        ),
        isFalse,
      );
      expect(
        PqEcdsaP256.verify(
          publicKey: kp.publicKey,
          message: message,
          signature: Uint8List(10),
        ),
        isFalse,
      );
      // A 65-byte buffer that is not a valid curve point must not verify.
      expect(
        PqEcdsaP256.verify(
          publicKey: Uint8List(65)..[0] = 0x04,
          message: message,
          signature: sig,
        ),
        isFalse,
      );
    });

    test('sign rejects a wrong-length private key', () {
      expect(
        () => PqEcdsaP256.sign(privateKey: Uint8List(16), message: _bytes('x')),
        throwsArgumentError,
      );
    });
  });
}

Uint8List _bytes(String value) => Uint8List.fromList(utf8.encode(value));
