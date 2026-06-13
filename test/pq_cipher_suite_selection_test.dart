import 'dart:io';
import 'dart:typed_data';

import 'package:pqforge/pqforge_io.dart';
import 'package:test/test.dart';

/// R3: ChaCha20-Poly1305 suite selection — non-default containers record an
/// `aeadSuite` marker, openers rebuild their engine (same provider) to match,
/// and AES-256-GCM output stays marker-free and byte-compatible with every
/// prior release.
void main() {
  const forge = PqForge(profile: PqForgeProfile.compact);
  late PqKeyBundle keys;

  setUp(() => keys = forge.generateKeys(keyId: 'suite-test'));

  Uint8List payload(int n) =>
      Uint8List.fromList(List<int>.generate(n, (i) => (i * 31 + 7) & 0xFF));

  group('one-shot envelopes', () {
    test(
      'chacha roundtrip: marker recorded, default engine opens it',
      () async {
        final plaintext = payload(4096);
        final envelope = await forge.encryptAsync(
          keys.kemKeyPair.publicKey,
          plaintext,
          engine: PqForgeCryptographyAeadEngine(
            PqForgeCipherSuite.chaCha20Poly1305,
          ),
        );
        expect(
          envelope.metadata[pqForgeAeadSuiteMetadataKey],
          'chacha20-poly1305',
        );
        expect(
          PqAeadSuite.of(envelope.metadata),
          PqForgeCipherSuite.chaCha20Poly1305,
        );
        // No engine passed: decryptAsync rebuilds from the marker.
        expect(
          await forge.decryptAsync(keys.kemKeyPair.secretKey, envelope),
          plaintext,
        );
      },
    );

    test(
      'AES-256-GCM output carries no marker and stays sync-compatible',
      () async {
        final plaintext = payload(512);
        final envelope = await forge.encryptAsync(
          keys.kemKeyPair.publicKey,
          plaintext,
        );
        expect(
          envelope.metadata.containsKey(pqForgeAeadSuiteMetadataKey),
          isFalse,
        );
        expect(PqAeadSuite.of(envelope.metadata), PqForgeCipherSuite.aes256Gcm);
        // Byte-compatible with the sync PointyCastle path.
        expect(forge.decrypt(keys.kemKeyPair.secretKey, envelope), plaintext);
      },
    );

    test(
      'cross-provider: pure-dart chacha seals, cryptography opens',
      () async {
        final plaintext = payload(2048);
        final envelope = await forge.encryptAsync(
          keys.kemKeyPair.publicKey,
          plaintext,
          engine: PqForgePointyCastleAeadEngine(
            PqForgeCipherSuite.chaCha20Poly1305,
          ),
        );
        final opened = await forge.decryptAsync(
          keys.kemKeyPair.secretKey,
          envelope,
          // AES engine on the other provider: the marker rebuilds it to the
          // recorded chacha suite on nativeCryptography.
          engine: PqForgeCryptographyAeadEngine(PqForgeCipherSuite.aes256Gcm),
        );
        expect(opened, plaintext);
      },
    );

    test('sync decrypt rejects a chacha envelope with guidance', () async {
      final envelope = await forge.encryptAsync(
        keys.kemKeyPair.publicKey,
        payload(64),
        engine: PqForgeCryptographyAeadEngine(
          PqForgeCipherSuite.chaCha20Poly1305,
        ),
      );
      expect(
        () => forge.decrypt(keys.kemKeyPair.secretKey, envelope),
        throwsA(
          isA<PqForgeException>().having(
            (e) => e.message,
            'message',
            contains('non-default AEAD suite'),
          ),
        ),
      );
    });

    test('a stripped suite marker fails authentication', () async {
      final envelope = await forge.encryptAsync(
        keys.kemKeyPair.publicKey,
        payload(64),
        engine: PqForgeCryptographyAeadEngine(
          PqForgeCipherSuite.chaCha20Poly1305,
        ),
      );
      final stripped = PqEnvelope(
        profile: envelope.profile,
        kemAlgorithm: envelope.kemAlgorithm,
        kemCiphertext: envelope.kemCiphertext,
        nonce: envelope.nonce,
        payload: envelope.payload,
        metadata: {...envelope.metadata}..remove(pqForgeAeadSuiteMetadataKey),
      );
      // Without the marker the opener runs AES-256-GCM over a ChaCha body —
      // guaranteed tag failure, even on this unsigned envelope.
      await expectLater(
        forge.decryptAsync(keys.kemKeyPair.secretKey, stripped),
        throwsA(isA<PqForgeAuthTagException>()),
      );
    });

    test('FIPS mode refuses the chacha suite end to end', () async {
      final envelope = await forge.encryptAsync(
        keys.kemKeyPair.publicKey,
        payload(64),
        engine: PqForgeCryptographyAeadEngine(
          PqForgeCipherSuite.chaCha20Poly1305,
        ),
      );
      PqFipsMode.enable();
      try {
        await expectLater(
          forge.encryptAsync(
            keys.kemKeyPair.publicKey,
            payload(16),
            engine: PqForgeCryptographyAeadEngine(
              PqForgeCipherSuite.chaCha20Poly1305,
            ),
          ),
          throwsA(
            isA<PqForgeException>().having(
              (e) => e.message,
              'message',
              contains('FIPS'),
            ),
          ),
        );
        await expectLater(
          forge.decryptAsync(keys.kemKeyPair.secretKey, envelope),
          throwsA(
            isA<PqForgeException>().having(
              (e) => e.message,
              'message',
              contains('FIPS'),
            ),
          ),
        );
      } finally {
        PqFipsMode.disable();
      }
    });
  });

  group('streaming containers', () {
    late Directory dir;

    setUp(() => dir = Directory.systemTemp.createTempSync('pqfs_suite_'));
    tearDown(() => dir.deleteSync(recursive: true));

    test(
      'chacha container: marker in header, default instance decrypts',
      () async {
        final original = payload(300 * 1024);
        final src = File('${dir.path}/in.bin')..writeAsBytesSync(original);
        final enc = File('${dir.path}/in.pqf');
        await PqForgeStreamCipher.forProvider(
          PqForgeEngineProvider.nativeCryptography,
          cipherSuite: PqForgeCipherSuite.chaCha20Poly1305,
        ).encryptFile(
          recipientPublicKey: keys.kemKeyPair.publicKey,
          input: src,
          output: enc,
          profile: PqForgeProfile.compact,
          frameSize: 64 * 1024,
        );

        final defaultCipher = PqForgeStreamCipher();
        final header = await defaultCipher.readHeader(enc);
        expect(
          PqAeadSuite.of(header.metadata),
          PqForgeCipherSuite.chaCha20Poly1305,
        );

        final out = File('${dir.path}/out.bin');
        await defaultCipher.decryptFile(
          recipientSecretKey: keys.kemKeyPair.secretKey,
          input: enc,
          output: out,
        );
        expect(out.readAsBytesSync(), original);
      },
    );

    test('pure-dart provider rebuilds to the recorded suite', () async {
      final original = payload(96 * 1024);
      final src = File('${dir.path}/in.bin')..writeAsBytesSync(original);
      final enc = File('${dir.path}/in.pqf');
      await PqForgeStreamCipher.forProvider(
        PqForgeEngineProvider.pureDart,
        cipherSuite: PqForgeCipherSuite.chaCha20Poly1305,
      ).encryptFile(
        recipientPublicKey: keys.kemKeyPair.publicKey,
        input: src,
        output: enc,
        profile: PqForgeProfile.compact,
        frameSize: 64 * 1024,
      );
      final out = File('${dir.path}/out.bin');
      await PqForgeStreamCipher.forProvider(
        PqForgeEngineProvider.pureDart,
      ).decryptFile(
        recipientSecretKey: keys.kemKeyPair.secretKey,
        input: enc,
        output: out,
      );
      expect(out.readAsBytesSync(), original);
    });
  });
}
