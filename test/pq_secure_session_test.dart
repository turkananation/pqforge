import 'dart:convert';
import 'dart:typed_data';

import 'package:pqforge/pqforge.dart';
import 'package:test/test.dart';

final List<PqForgeCipherSuite> _suites = PqForgeCipherSuite.values;
final List<PqForgeEngineProvider> _providers = PqForgeEngineProvider.values;

void main() {
  group('engine-level cross-backend byte compatibility', () {
    // The core interop guarantee: for identical key/nonce/plaintext/AAD, the
    // pure-Dart and native backends must produce byte-identical ciphertext+tag.
    for (final suite in _suites) {
      test(
        '${suite.id}: PointyCastle and cryptography seal identical bytes',
        () async {
          final key = _filled(32, 0x42);
          final nonce = _filled(12, 0x24);
          final plaintext = _bytes(
            'interoperability payload across two backends',
          );
          final aad = _bytes('routing:header:v1');

          final pure = PqForgePointyCastleAeadEngine(suite);
          final native = PqForgeCryptographyAeadEngine(suite);

          final sealedByPure = await pure.seal(
            key: key,
            nonce: nonce,
            plaintext: plaintext,
            aad: aad,
          );
          final sealedByNative = await native.seal(
            key: key,
            nonce: nonce,
            plaintext: plaintext,
            aad: aad,
          );

          expect(
            sealedByPure,
            orderedEquals(sealedByNative),
            reason: '${suite.id} ciphertext+tag diverged across backends',
          );
          // ciphertext length == plaintext length; tag length == 16.
          expect(sealedByPure, hasLength(plaintext.length + suite.tagLength));
        },
      );

      test(
        '${suite.id}: each backend opens the other backend\'s output',
        () async {
          final key = _filled(32, 7);
          final nonce = _filled(12, 9);
          final plaintext = _bytes('cross-open round trip');
          final aad = _bytes('aad-context');

          final pure = PqForgePointyCastleAeadEngine(suite);
          final native = PqForgeCryptographyAeadEngine(suite);

          final sealedByPure = await pure.seal(
            key: key,
            nonce: nonce,
            plaintext: plaintext,
            aad: aad,
          );
          final sealedByNative = await native.seal(
            key: key,
            nonce: nonce,
            plaintext: plaintext,
            aad: aad,
          );

          expect(
            await native.open(
              key: key,
              nonce: nonce,
              cipherTextWithTag: sealedByPure,
              aad: aad,
            ),
            orderedEquals(plaintext),
          );
          expect(
            await pure.open(
              key: key,
              nonce: nonce,
              cipherTextWithTag: sealedByNative,
              aad: aad,
            ),
            orderedEquals(plaintext),
          );
        },
      );
    }
  });

  group('PqForgeSecureSession wire packets', () {
    for (final suite in _suites) {
      for (final provider in _providers) {
        test(
          '${suite.id} / ${provider.name}: round-trips and frames the packet',
          () async {
            final session = PqForgeSecureSession(
              secretKey: _filled(32, 1),
              cipherSuite: suite,
              engineProvider: provider,
            );
            final payload = _bytes('hello secure session');
            final aad = _bytes('session:42');

            final packet = await session.encrypt(payload, associatedData: aad);
            // nonce(12) + ciphertext(payload.length) + tag(16)
            expect(
              packet,
              hasLength(suite.nonceLength + payload.length + suite.tagLength),
            );

            expect(
              await session.decrypt(packet, associatedData: aad),
              orderedEquals(payload),
            );
          },
        );
      }

      test(
        '${suite.id}: a pure-Dart packet decrypts under native (and vice versa)',
        () async {
          final key = _filled(32, 5);
          final pureSession = PqForgeSecureSession(
            secretKey: key,
            cipherSuite: suite,
            engineProvider: PqForgeEngineProvider.pureDart,
          );
          final nativeSession = PqForgeSecureSession(
            secretKey: key,
            cipherSuite: suite,
            engineProvider: PqForgeEngineProvider.nativeCryptography,
          );
          final payload = _bytes('backend interop over the wire');
          final aad = _bytes('hdr');

          final purePacket = await pureSession.encrypt(
            payload,
            associatedData: aad,
          );
          expect(
            await nativeSession.decrypt(purePacket, associatedData: aad),
            orderedEquals(payload),
          );

          final nativePacket = await nativeSession.encrypt(
            payload,
            associatedData: aad,
          );
          expect(
            await pureSession.decrypt(nativePacket, associatedData: aad),
            orderedEquals(payload),
          );
        },
      );

      test('${suite.id}: an empty payload round-trips', () async {
        final session = PqForgeSecureSession(
          secretKey: _filled(32, 2),
          cipherSuite: suite,
        );
        final packet = await session.encrypt(Uint8List(0));
        expect(packet, hasLength(suite.nonceLength + suite.tagLength));
        expect(await session.decrypt(packet), isEmpty);
      });

      test('${suite.id}: a fresh nonce is used for every encryption', () async {
        final session = PqForgeSecureSession(
          secretKey: _filled(32, 3),
          cipherSuite: suite,
        );
        final payload = _bytes('identical payload, distinct packets');
        final a = await session.encrypt(payload);
        final b = await session.encrypt(payload);
        expect(a, isNot(orderedEquals(b)));
        expect(
          a.sublist(0, suite.nonceLength),
          isNot(orderedEquals(b.sublist(0, suite.nonceLength))),
        );
      });
    }
  });

  group('authentication, AAD binding, and failure modes', () {
    for (final suite in _suites) {
      for (final provider in _providers) {
        PqForgeSecureSession session() => PqForgeSecureSession(
          secretKey: _filled(32, 8),
          cipherSuite: suite,
          engineProvider: provider,
        );

        test(
          '${suite.id} / ${provider.name}: a tampered tag throws PqForgeAuthTagException',
          () async {
            final s = session();
            final packet = await s.encrypt(
              _bytes('authentic'),
              associatedData: _bytes('ad'),
            );
            packet[packet.length - 1] ^= 0xFF;
            await expectLater(
              s.decrypt(packet, associatedData: _bytes('ad')),
              throwsA(isA<PqForgeAuthTagException>()),
            );
          },
        );

        test(
          '${suite.id} / ${provider.name}: a tampered nonce throws PqForgeAuthTagException',
          () async {
            final s = session();
            final packet = await s.encrypt(
              _bytes('data'),
              associatedData: _bytes('ad'),
            );
            packet[0] ^= 0xFF;
            await expectLater(
              s.decrypt(packet, associatedData: _bytes('ad')),
              throwsA(isA<PqForgeAuthTagException>()),
            );
          },
        );

        test(
          '${suite.id} / ${provider.name}: a mismatched AAD throws PqForgeAuthTagException',
          () async {
            final s = session();
            final packet = await s.encrypt(
              _bytes('data'),
              associatedData: _bytes('correct-aad'),
            );
            await expectLater(
              s.decrypt(packet, associatedData: _bytes('wrong-aad')),
              throwsA(isA<PqForgeAuthTagException>()),
            );
          },
        );

        test(
          '${suite.id} / ${provider.name}: a too-short packet throws ArgumentError',
          () async {
            final s = session();
            await expectLater(
              s.decrypt(Uint8List(suite.nonceLength + suite.tagLength - 1)),
              throwsArgumentError,
            );
          },
        );
      }
    }

    test(
      'a packet sealed under one suite does not open under another',
      () async {
        final key = _filled(32, 11);
        final gcm = PqForgeSecureSession(
          secretKey: key,
          cipherSuite: PqForgeCipherSuite.aes256Gcm,
        );
        final chacha = PqForgeSecureSession(
          secretKey: key,
          cipherSuite: PqForgeCipherSuite.chaCha20Poly1305,
        );
        final packet = await gcm.encrypt(
          _bytes('suite-bound payload'),
          associatedData: _bytes('x'),
        );
        await expectLater(
          chacha.decrypt(packet, associatedData: _bytes('x')),
          throwsA(isA<PqForgeAuthTagException>()),
        );
      },
    );
  });

  group('construction validation', () {
    for (final provider in _providers) {
      test('${provider.name}: rejects a key that is not 256-bit', () {
        expect(
          () => PqForgeSecureSession(
            secretKey: _filled(16, 0),
            cipherSuite: PqForgeCipherSuite.aes256Gcm,
            engineProvider: provider,
          ),
          throwsArgumentError,
        );
      });
    }
  });

  group('memory hygiene and lifecycle', () {
    for (final suite in _suites) {
      for (final provider in _providers) {
        test(
          '${suite.id} / ${provider.name}: decrypt does not mutate the packet',
          () async {
            final session = PqForgeSecureSession(
              secretKey: _filled(32, 4),
              cipherSuite: suite,
              engineProvider: provider,
            );
            final packet = await session.encrypt(
              _bytes('zero-copy views must not alter the source packet'),
              associatedData: _bytes('ad'),
            );
            final snapshot = Uint8List.fromList(packet);

            await session.decrypt(packet, associatedData: _bytes('ad'));

            expect(
              packet,
              orderedEquals(snapshot),
              reason: 'decrypt mutated its input packet',
            );
          },
        );
      }
    }

    test('dispose zeroizes the key and blocks further use', () async {
      final session = PqForgeSecureSession(
        secretKey: _filled(32, 9),
        cipherSuite: PqForgeCipherSuite.aes256Gcm,
      );
      final packet = await session.encrypt(_bytes('before disposal'));

      session.dispose();
      session.dispose(); // idempotent

      await expectLater(session.encrypt(_bytes('x')), throwsStateError);
      await expectLater(session.decrypt(packet), throwsStateError);
    });
  });
}

Uint8List _filled(int length, int value) =>
    Uint8List.fromList(List<int>.filled(length, value));

Uint8List _bytes(String value) => Uint8List.fromList(utf8.encode(value));
