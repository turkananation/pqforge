import 'dart:math';
import 'dart:typed_data';

import 'package:pointycastle/export.dart' as pc;
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

    test('refuses a generated modulus outside 2048, 3072, and 4096', () {
      expect(
        () => PqRsa.generateKeyPair(modulusBits: 1024),
        throwsArgumentError,
      );
      expect(
        () => PqRsa.generateKeyPair(modulusBits: 512),
        throwsArgumentError,
      );
      expect(
        () => PqRsa.generateKeyPair(modulusBits: 8192),
        throwsArgumentError,
      );
    });

    test('refuses a 512-bit and an 8192-bit verify', () {
      expect(
        PqRsa.verifyPkcs1(
          modulus: Uint8List(64),
          exponent: Uint8List.fromList([1, 0, 1]),
          message: Uint8List(1),
          signature: Uint8List(64),
          hash: PqRsaHash.sha256,
        ),
        isFalse,
      );
      expect(
        PqRsa.verifyPkcs1(
          modulus: Uint8List(1024),
          exponent: Uint8List.fromList([1, 0, 1]),
          message: Uint8List(1),
          signature: Uint8List(1024),
          hash: PqRsaHash.sha256,
        ),
        isFalse,
      );
    });
  });

  for (final bits in const [1024, 2048, 3072, 4096]) {
    group('RSA $bits', () {
      late Uint8List modulus;
      late Uint8List exponent;
      late PqRsaPrivateKey privateKey;

      setUpAll(() {
        final kp = bits == 1024
            ? _rsa1024()
            : PqRsa.generateKeyPair(modulusBits: bits);
        modulus = kp.modulus;
        exponent = kp.exponent;
        privateKey = kp.privateKey;
      });

      for (final hash in PqRsaHash.values) {
        test('PKCS#1 ${hash.name} verifies and rejects a flipped byte', () {
          final message = Uint8List.fromList(
            'pkcs1 $bits ${hash.name}'.codeUnits,
          );
          final signature = PqRsa.signPkcs1(
            privateKey: privateKey,
            message: message,
            hash: hash,
          );
          expect(signature, hasLength(bits ~/ 8));
          expect(
            PqRsa.verifyPkcs1(
              modulus: modulus,
              exponent: exponent,
              message: message,
              signature: signature,
              hash: hash,
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
              hash: hash,
            ),
            isFalse,
          );
          expect(
            PqRsa.verifyPkcs1(
              modulus: modulus,
              exponent: exponent,
              message: Uint8List.fromList('other'.codeUnits),
              signature: signature,
              hash: hash,
            ),
            isFalse,
          );
        });

        test('PSS ${hash.name} verifies and rejects a flipped byte', () {
          final message = Uint8List.fromList(
            'pss $bits ${hash.name}'.codeUnits,
          );
          final tooSmall = bits ~/ 8 < hash.digestBytes * 2 + 2;
          if (tooSmall) {
            expect(
              () => PqRsa.signPss(
                privateKey: privateKey,
                message: message,
                hash: hash,
              ),
              throwsArgumentError,
            );
            expect(
              PqRsa.verifyPss(
                modulus: modulus,
                exponent: exponent,
                message: message,
                signature: Uint8List(bits ~/ 8),
                hash: hash,
              ),
              isFalse,
            );
            return;
          }
          final signature = PqRsa.signPss(
            privateKey: privateKey,
            message: message,
            hash: hash,
          );
          expect(
            PqRsa.verifyPss(
              modulus: modulus,
              exponent: exponent,
              message: message,
              signature: signature,
              hash: hash,
            ),
            isTrue,
          );
          final flipped = Uint8List.fromList(signature)..[0] ^= 1;
          expect(
            PqRsa.verifyPss(
              modulus: modulus,
              exponent: exponent,
              message: message,
              signature: flipped,
              hash: hash,
            ),
            isFalse,
          );
        });
      }
    });
  }
}

({PqRsaPrivateKey privateKey, Uint8List modulus, Uint8List exponent})
_rsa1024() {
  final fortuna = pc.FortunaRandom();
  final random = Random.secure();
  final seed = Uint8List(32);
  for (var i = 0; i < seed.length; i++) {
    seed[i] = random.nextInt(256);
  }
  fortuna.seed(pc.KeyParameter(seed));
  final generator = pc.RSAKeyGenerator()
    ..init(
      pc.ParametersWithRandom(
        pc.RSAKeyGeneratorParameters(BigInt.from(65537), 1024, 64),
        fortuna,
      ),
    );
  final pair = generator.generateKeyPair();
  final publicKey = pair.publicKey;
  final privateKey = pair.privateKey;
  final modulus = _fixed(publicKey.modulus!, 128);
  final exponent = _minimal(publicKey.exponent!);
  return (
    modulus: modulus,
    exponent: exponent,
    privateKey: PqRsaPrivateKey(
      modulus: modulus,
      privateExponent: _minimal(privateKey.privateExponent!),
      prime1: _minimal(privateKey.p!),
      prime2: _minimal(privateKey.q!),
      publicExponent: exponent,
    ),
  );
}

Uint8List _minimal(BigInt value) {
  if (value == BigInt.zero) return Uint8List(1);
  return _fixed(value, (value.bitLength + 7) >> 3);
}

Uint8List _fixed(BigInt value, int length) {
  final out = Uint8List(length);
  final mask = BigInt.from(0xff);
  var remaining = value;
  for (var i = length - 1; i >= 0; i--) {
    out[i] = (remaining & mask).toInt();
    remaining >>= 8;
  }
  return out;
}
