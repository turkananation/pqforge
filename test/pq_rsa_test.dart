import 'dart:typed_data';

import 'package:pqforge/pqforge.dart';
import 'package:test/test.dart';

void main() {
  group('PqRsa', () {
    late Uint8List modulus;
    late Uint8List exponent;
    late PqRsaPrivateKey privateKey;

    setUpAll(() {
      final kp = PqRsa.generateKeyPair();
      modulus = kp.modulus;
      exponent = kp.exponent;
      privateKey = kp.privateKey;
    });

    test('PKCS#1 SHA-256 round-trips and rejects a flipped signature', () {
      final message = Uint8List.fromList('rsa pkcs1'.codeUnits);
      final signature = PqRsa.signPkcs1(
        privateKey: privateKey,
        message: message,
        hash: PqRsaHash.sha256,
      );
      expect(signature, hasLength(256));
      expect(
        PqRsa.verifyPkcs1(
          modulus: modulus,
          exponent: exponent,
          message: message,
          signature: signature,
          hash: PqRsaHash.sha256,
        ),
        isTrue,
      );
      final flipped = Uint8List.fromList(signature)..[0] ^= 1;
      expect(
        PqRsa.verifyPkcs1(
          modulus: modulus,
          exponent: exponent,
          message: message,
          signature: flipped,
          hash: PqRsaHash.sha256,
        ),
        isFalse,
      );
    });

    test('PSS SHA-256 round-trips', () {
      final message = Uint8List.fromList('rsa pss'.codeUnits);
      final signature = PqRsa.signPss(
        privateKey: privateKey,
        message: message,
        hash: PqRsaHash.sha256,
      );
      expect(
        PqRsa.verifyPss(
          modulus: modulus,
          exponent: exponent,
          message: message,
          signature: signature,
          hash: PqRsaHash.sha256,
        ),
        isTrue,
      );
      expect(
        PqRsa.verifyPss(
          modulus: modulus,
          exponent: exponent,
          message: Uint8List.fromList('other'.codeUnits),
          signature: signature,
          hash: PqRsaHash.sha256,
        ),
        isFalse,
      );
    });

    test('a 1024-bit claim and exponent 1 do not verify', () {
      expect(
        PqRsa.verifyPkcs1(
          modulus: Uint8List(128),
          exponent: Uint8List.fromList([1, 0, 1]),
          message: Uint8List(1),
          signature: Uint8List(128),
          hash: PqRsaHash.sha256,
        ),
        isFalse,
      );
      expect(
        PqRsa.verifyPkcs1(
          modulus: modulus,
          exponent: Uint8List.fromList([1]),
          message: Uint8List(1),
          signature: Uint8List(256),
          hash: PqRsaHash.sha256,
        ),
        isFalse,
      );
    });

    test('PSS accepts a salt length other than the hash length', () {
      final message = Uint8List.fromList('salt 20'.codeUnits);
      final signature = PqRsa.signPss(
        privateKey: privateKey,
        message: message,
        hash: PqRsaHash.sha256,
        saltLength: 20,
      );
      expect(
        PqRsa.verifyPss(
          modulus: modulus,
          exponent: exponent,
          message: message,
          signature: signature,
          hash: PqRsaHash.sha256,
          saltLength: 20,
        ),
        isTrue,
      );
      expect(
        PqRsa.verifyPss(
          modulus: modulus,
          exponent: exponent,
          message: message,
          signature: signature,
          hash: PqRsaHash.sha256,
        ),
        isFalse,
      );
    });

    test('refuses a modulus size outside 2048, 3072, and 4096', () {
      expect(
        () => PqRsa.generateKeyPair(modulusBits: 1024),
        throwsArgumentError,
      );
    });
  });
}
