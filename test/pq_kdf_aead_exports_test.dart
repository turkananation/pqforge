import 'dart:convert';
import 'dart:typed_data';

import 'package:pqforge/pqforge.dart';
import 'package:test/test.dart';

void main() {
  group('RFC 5869 HKDF-SHA-256 Extract/Expand', () {
    test('Appendix A.1', () {
      final ikm = Uint8List.fromList(List<int>.filled(22, 0x0b));
      final salt = _hex('000102030405060708090a0b0c');
      final info = _hex('f0f1f2f3f4f5f6f7f8f9');
      final prk = PqSymmetricPrimitives.hkdfExtractSha256(ikm: ikm, salt: salt);
      expect(
        prk,
        orderedEquals(
          _hex(
            '077709362c2e32df0ddc3f0dc47bba63'
            '90b6c73bb50f9c3122ec844ad7c2b3e5',
          ),
        ),
      );
      final okm = PqSymmetricPrimitives.hkdfExpandSha256(
        prk: prk,
        info: info,
        outputBytes: 42,
      );
      expect(
        okm,
        orderedEquals(
          _hex(
            '3cb25f25faacd57a90434f64d0362f2a'
            '2d2d0a90cf1a5a4c5db02d56ecc4c5bf'
            '34007208d5b887185865',
          ),
        ),
      );
      expect(
        PqSymmetricPrimitives.hkdfSha256(
          ikm: ikm,
          salt: salt,
          info: info,
          outputBytes: 42,
        ),
        orderedEquals(okm),
        reason: 'Extract+Expand must match the combined HKDF helper',
      );
    });

    test('Appendix A.2 longer OKM', () {
      final ikm = _hex(
        '000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f'
        '202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f'
        '404142434445464748494a4b4c4d4e4f',
      );
      final salt = _hex(
        '606162636465666768696a6b6c6d6e6f707172737475767778797a7b7c7d7e7f'
        '808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f'
        'a0a1a2a3a4a5a6a7a8a9aaabacadaeaf',
      );
      final info = _hex(
        'b0b1b2b3b4b5b6b7b8b9babbbcbdbebfc0c1c2c3c4c5c6c7c8c9cacbcccdcecf'
        'd0d1d2d3d4d5d6d7d8d9dadbdcdddedfe0e1e2e3e4e5e6e7e8e9eaebecedeeef'
        'f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff',
      );
      final prk = PqSymmetricPrimitives.hkdfExtractSha256(ikm: ikm, salt: salt);
      expect(
        prk,
        orderedEquals(
          _hex(
            '06a6b88c5853361a06104c9ceb35b45c'
            'ef760014904671014a193f40c15fc244',
          ),
        ),
      );
      expect(
        PqSymmetricPrimitives.hkdfExpandSha256(
          prk: prk,
          info: info,
          outputBytes: 82,
        ),
        orderedEquals(
          _hex(
            'b11e398dc80327a1c8e7f78c596a4934'
            '4f012eda2d4efad8a050cc4c19afa97c'
            '59045a99cac7827271cb41c65e590e09'
            'da3275600c2f09b8367793a9aca3db71'
            'cc30c58179ec3e87c14c01d5c1f3434f'
            '1d87',
          ),
        ),
      );
    });

    test('Appendix A.3 empty salt and info', () {
      final ikm = Uint8List.fromList(List<int>.filled(22, 0x0b));
      final prk = PqSymmetricPrimitives.hkdfExtractSha256(
        ikm: ikm,
        salt: Uint8List(0),
      );
      expect(
        prk,
        orderedEquals(
          _hex(
            '19ef24a32c717b167f33a91d6f648bdf'
            '96596776afdb6377ac434c1c293ccb04',
          ),
        ),
      );
      expect(
        PqSymmetricPrimitives.hkdfExtractSha256(ikm: ikm),
        orderedEquals(prk),
        reason: 'null salt must equal empty salt (HashLen zeros)',
      );
      expect(
        PqSymmetricPrimitives.hkdfExpandSha256(
          prk: prk,
          info: Uint8List(0),
          outputBytes: 42,
        ),
        orderedEquals(
          _hex(
            '8da4e775a563c18f715f802a063c5a31'
            'b8a11f5c5ee1879ec3454e5f3c738d2d'
            '9d201395faa4b61a96c8',
          ),
        ),
      );
    });
  });

  group('SHA-384 / HMAC-SHA-384 / HKDF-SHA-384', () {
    test('hmacSha256 RFC 4231 test case 1', () {
      final tag = PqBytes.hmacSha256(
        key: Uint8List.fromList(List<int>.filled(20, 0x0b)),
        data: Uint8List.fromList(utf8.encode('Hi There')),
      );
      expect(
        tag,
        orderedEquals(
          _hex(
            'b0344c61d8db38535ca8afceaf0bf12b'
            '881dc200c9833da726e9376c2e32cff7',
          ),
        ),
      );
    });

    test('hmacSha384 RFC 4231 test case 1', () {
      final tag = PqBytes.hmacSha384(
        key: Uint8List.fromList(List<int>.filled(20, 0x0b)),
        data: Uint8List.fromList(utf8.encode('Hi There')),
      );
      expect(
        tag,
        orderedEquals(
          _hex(
            'afd03944d84895626b0825f4ab46907f'
            '15f9dadbe4101ec682aa034c7cebc59c'
            'faea9ea9076ede7f4af152e8b2fa9cb6',
          ),
        ),
      );
    });

    test('sha384 empty string and stream matches one-shot', () async {
      expect(
        PqBytes.sha384(Uint8List(0)),
        orderedEquals(
          _hex(
            '38b060a751ac96384cd9327eb1b1e36a'
            '21fdb71114be07434c0cc7bf63f6e1da'
            '274edebfe76f65fbd51ad2f14898b95b',
          ),
        ),
      );
      final data = Uint8List.fromList(List<int>.generate(200, (i) => i));
      final whole = PqBytes.sha384(data);
      expect(whole, hasLength(48));
      final streamed = await PqBytes.sha384OfStream(Stream.value(data));
      expect(streamed, orderedEquals(whole));
    });

    test('Extract+Expand matches combined hkdfSha384', () {
      final ikm = Uint8List.fromList(List<int>.filled(22, 0x0b));
      final salt = _hex('000102030405060708090a0b0c');
      final info = _hex('f0f1f2f3f4f5f6f7f8f9');
      final prk = PqSymmetricPrimitives.hkdfExtractSha384(ikm: ikm, salt: salt);
      expect(prk, hasLength(48));
      final okm = PqSymmetricPrimitives.hkdfExpandSha384(
        prk: prk,
        info: info,
        outputBytes: 42,
      );
      expect(
        PqSymmetricPrimitives.hkdfSha384(
          ikm: ikm,
          salt: salt,
          info: info,
          outputBytes: 42,
        ),
        orderedEquals(okm),
      );
    });
  });

  group('sync ChaCha20-Poly1305', () {
    test('RFC 8439 §2.8.2', () {
      final key = _hex(
        '808182838485868788898a8b8c8d8e8f'
        '909192939495969798999a9b9c9d9e9f',
      );
      final nonce = _hex('070000004041424344454647');
      final aad = _hex('50515253c0c1c2c3c4c5c6c7');
      final plaintext = _hex(
        '4c616469657320616e642047656e746c'
        '656d656e206f662074686520636c6173'
        '73206f66202739393a20496620492063'
        '6f756c64206f6666657220796f75206f'
        '6e6c79206f6e652074697020666f7220'
        '746865206675747572652c2073756e73'
        '637265656e20776f756c642062652069'
        '742e',
      );
      final expected = _hex(
        'd31a8d34648e60db7b86afbc53ef7ec2'
        'a4aded51296e08fea9e2b5a736ee62d6'
        '3dbea45e8ca9671282fafb69da92728b'
        '1a71de0a9e060b2905d6a5b67ecd3b36'
        '92ddbd7f2d778b8c9803aee328091b58'
        'fab324e4fad675945585808b4831d7bc'
        '3ff4def08e4b7a9de576d26586cec64b'
        '6116'
        '1ae10b594f09e26a7e902ecbd0600691',
      );
      final sealed = PqSymmetricPrimitives.chacha20Poly1305Encrypt(
        key: key,
        nonce: nonce,
        plaintext: plaintext,
        aad: aad,
      );
      expect(sealed, orderedEquals(expected));
      expect(
        PqSymmetricPrimitives.chacha20Poly1305Decrypt(
          key: key,
          nonce: nonce,
          ciphertext: sealed,
          aad: aad,
        ),
        orderedEquals(plaintext),
      );
    });

    test('round trip and bit-flip fails', () {
      final key = PqBytes.randomBytes(32);
      final nonce = PqBytes.randomBytes(12);
      final plain = Uint8List.fromList(utf8.encode('pqtransport record'));
      final aad = Uint8List.fromList(utf8.encode('tls13 header'));
      final sealed = PqSymmetricPrimitives.chacha20Poly1305Encrypt(
        key: key,
        nonce: nonce,
        plaintext: plain,
        aad: aad,
      );
      expect(sealed.length, plain.length + 16);
      final opened = PqSymmetricPrimitives.chacha20Poly1305Decrypt(
        key: key,
        nonce: nonce,
        ciphertext: sealed,
        aad: aad,
      );
      expect(opened, orderedEquals(plain));
      final flipped = Uint8List.fromList(sealed)..[0] ^= 0x01;
      expect(
        () => PqSymmetricPrimitives.chacha20Poly1305Decrypt(
          key: key,
          nonce: nonce,
          ciphertext: flipped,
          aad: aad,
        ),
        throwsA(isA<PqForgeAuthTagException>()),
      );
    });

    test('empty plaintext and mismatched nonce length', () {
      final key = PqBytes.randomBytes(32);
      final nonce = PqBytes.randomBytes(12);
      final sealed = PqSymmetricPrimitives.chacha20Poly1305Encrypt(
        key: key,
        nonce: nonce,
        plaintext: Uint8List(0),
      );
      expect(sealed, hasLength(16));
      expect(
        PqSymmetricPrimitives.chacha20Poly1305Decrypt(
          key: key,
          nonce: nonce,
          ciphertext: sealed,
        ),
        isEmpty,
      );
      expect(
        () => PqSymmetricPrimitives.chacha20Poly1305Encrypt(
          key: key,
          nonce: Uint8List(11),
          plaintext: Uint8List(1),
        ),
        throwsArgumentError,
      );
    });

    test('supportsChaCha20Poly1305 is true on this runtime', () {
      expect(PqSymmetricPrimitives.supportsChaCha20Poly1305, isTrue);
    });

    test(
      'matches the cryptography session engine for the same nonce',
      () async {
        final key = PqBytes.randomBytes(32);
        final nonce = PqBytes.randomBytes(12);
        final plain = Uint8List.fromList(List<int>.generate(40, (i) => i));
        final aad = Uint8List.fromList([1, 2, 3]);
        final sync = PqSymmetricPrimitives.chacha20Poly1305Encrypt(
          key: key,
          nonce: nonce,
          plaintext: plain,
          aad: aad,
        );
        final engine = PqForgeCryptographyAeadEngine(
          PqForgeCipherSuite.chaCha20Poly1305,
        );
        final asyncSeal = await engine.seal(
          key: key,
          nonce: nonce,
          plaintext: plain,
          aad: aad,
        );
        expect(sync, orderedEquals(asyncSeal));
      },
    );

    test(
      'matches the PointyCastle session engine when 64-bit integers exist',
      () async {
        final key = PqBytes.randomBytes(32);
        final nonce = PqBytes.randomBytes(12);
        final plain = Uint8List.fromList(List<int>.generate(40, (i) => i));
        final aad = Uint8List.fromList([1, 2, 3]);
        final sync = PqSymmetricPrimitives.chacha20Poly1305Encrypt(
          key: key,
          nonce: nonce,
          plaintext: plain,
          aad: aad,
        );
        const engine = PqForgePointyCastleAeadEngine(
          PqForgeCipherSuite.chaCha20Poly1305,
        );
        // PointyCastle Poly1305 needs integers wider than the IEEE-754
        // mantissa. dart2js does not; do not skip — assert the known throw.
        const two53 = 9007199254740992;
        final fullWidth = two53 + 1 != two53;
        if (fullWidth) {
          final asyncSeal = await engine.seal(
            key: key,
            nonce: nonce,
            plaintext: plain,
            aad: aad,
          );
          expect(sync, orderedEquals(asyncSeal));
        } else {
          await expectLater(
            engine.seal(key: key, nonce: nonce, plaintext: plain, aad: aad),
            throwsA(
              predicate(
                (error) => error.toString().contains('full width integer'),
                'PointyCastle Poly1305 platform check',
              ),
            ),
          );
        }
      },
    );
  });

  group('PqKemPrimitives.checkEncapsulationKey', () {
    test('accepts a live key and rejects truncated / oversized', () {
      for (final kem in PqKemAlgorithm.values) {
        final pair = PqKemPrimitives.generateKeyPair(kem);
        expect(
          PqKemPrimitives.checkEncapsulationKey(kem, pair.publicKey),
          isTrue,
          reason: kem.name,
        );
        expect(
          PqKemPrimitives.checkEncapsulationKey(
            kem,
            Uint8List.sublistView(pair.publicKey, 0, pair.publicKey.length - 1),
          ),
          isFalse,
        );
        expect(
          PqKemPrimitives.checkEncapsulationKey(
            kem,
            Uint8List.fromList([...pair.publicKey, 0]),
          ),
          isFalse,
        );
      }
    });

    test('rejects a modulus-corrupted ML-KEM-768 key', () {
      final pair = PqKemPrimitives.generateKeyPair(PqKemAlgorithm.mlKem768);
      final bad = Uint8List.fromList(pair.publicKey);
      // First 384 bytes are the first packed polynomial. All-0xFF 12-bit
      // coefficients are 4095, which is ≥ q=3329, so FIPS 203 §7.2 fails.
      for (var i = 0; i < 384; i++) {
        bad[i] = 0xff;
      }
      expect(
        PqKemPrimitives.checkEncapsulationKey(PqKemAlgorithm.mlKem768, bad),
        isFalse,
      );
    });
  });

  group('PqForgeCombiner.concatenateSharedSecrets', () {
    test('classicalThenPq matches combine input join without HKDF', () {
      final classical = Uint8List.fromList([1, 2, 3]);
      final pq = Uint8List.fromList([4, 5, 6, 7]);
      expect(
        PqForgeCombiner.concatenateSharedSecrets(
          classicalSharedSecret: classical,
          postQuantumSharedSecret: pq,
        ),
        orderedEquals([1, 2, 3, 4, 5, 6, 7]),
      );
      expect(
        PqForgeCombiner.concatenateSharedSecrets(
          classicalSharedSecret: classical,
          postQuantumSharedSecret: pq,
          order: PqHybridConcatOrder.pqThenClassical,
        ),
        orderedEquals([4, 5, 6, 7, 1, 2, 3]),
      );
    });

    test('rejects empty shares', () {
      expect(
        () => PqForgeCombiner.concatenateSharedSecrets(
          classicalSharedSecret: Uint8List(0),
          postQuantumSharedSecret: Uint8List.fromList([1]),
        ),
        throwsArgumentError,
      );
    });
  });
}

Uint8List _hex(String hex) {
  final compact = hex.replaceAll(RegExp(r'\s'), '');
  return Uint8List.fromList([
    for (var i = 0; i < compact.length; i += 2)
      int.parse(compact.substring(i, i + 2), radix: 16),
  ]);
}
