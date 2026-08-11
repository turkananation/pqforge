import 'dart:convert';
import 'dart:io';
import 'dart:typed_data';

import 'package:pqforge/pqforge_io.dart';
import 'package:test/test.dart';

/// Hybrid (ML-KEM + X25519) KEM-DEM: the one-shot async path and the streaming
/// container share one key schedule ([PqHybridKemDem]); confidentiality holds
/// while either assumption stands, the metadata marker is self-authenticating
/// via the KDF, and the sync paths reject hybrid inputs with clear errors.
void main() {
  const forge = PqForge(profile: PqForgeProfile.compact);
  late PqKeyBundle keys;
  late Uint8List kexPublic;
  late Uint8List kexSecret;

  setUp(() async {
    keys = forge.generateKeys();
    final pair = await const PqForgeHybridKeyAgreement()
        .generateClassicalKeyPairBytes();
    kexPublic = pair.publicKey;
    kexSecret = pair.secretKey;
  });

  Uint8List payload(int n) =>
      Uint8List.fromList(List<int>.generate(n, (i) => (i * 31 + 7) & 0xFF));

  group('one-shot hybrid envelopes', () {
    test('roundtrip, with the marker recorded in metadata', () async {
      final plaintext = payload(4096);
      final envelope = await forge.encryptAsync(
        keys.kemKeyPair.publicKey,
        plaintext,
        recipientKexPublicKey: kexPublic,
        aad: PqBytes.utf8Bytes('hybrid-test'),
      );
      expect(PqHybridKemDem.isHybrid(envelope.metadata), isTrue);
      final marker = PqHybridKemDem.parseMetadata(envelope.metadata)!;
      expect(marker.algorithm, PqClassicalKeyAgreementAlgorithm.x25519);
      expect(marker.ephemeralPublicKey, hasLength(32));

      final opened = await forge.decryptAsync(
        keys.kemKeyPair.secretKey,
        envelope,
        recipientKexSecretKey: kexSecret,
        aad: PqBytes.utf8Bytes('hybrid-test'),
      );
      expect(opened, plaintext);
    });

    test(
      'signed hybrid roundtrip binds the marker under the signature',
      () async {
        final plaintext = payload(512);
        final envelope = await forge.encryptAsync(
          keys.kemKeyPair.publicKey,
          plaintext,
          recipientKexPublicKey: kexPublic,
          signerSecretKey: keys.signatureKeyPair.secretKey,
        );
        expect(envelope.isSigned, isTrue);
        final opened = await forge.decryptAsync(
          keys.kemKeyPair.secretKey,
          envelope,
          recipientKexSecretKey: kexSecret,
          signerPublicKey: keys.signatureKeyPair.publicKey,
        );
        expect(opened, plaintext);
      },
    );

    test('missing X25519 secret fails before any AEAD work', () async {
      final envelope = await forge.encryptAsync(
        keys.kemKeyPair.publicKey,
        payload(64),
        recipientKexPublicKey: kexPublic,
      );
      await expectLater(
        forge.decryptAsync(keys.kemKeyPair.secretKey, envelope),
        throwsA(
          isA<PqForgeException>().having(
            (e) => e.message,
            'message',
            contains('X25519 secret key is required'),
          ),
        ),
      );
    });

    test('the wrong X25519 secret fails authentication', () async {
      final envelope = await forge.encryptAsync(
        keys.kemKeyPair.publicKey,
        payload(64),
        recipientKexPublicKey: kexPublic,
      );
      final wrong = await const PqForgeHybridKeyAgreement()
          .generateClassicalKeyPairBytes();
      await expectLater(
        forge.decryptAsync(
          keys.kemKeyPair.secretKey,
          envelope,
          recipientKexSecretKey: wrong.secretKey,
        ),
        throwsA(isA<PqForgeAuthTagException>()),
      );
    });

    test('a tampered ephemeral public key fails authentication', () async {
      final envelope = await forge.encryptAsync(
        keys.kemKeyPair.publicKey,
        payload(64),
        recipientKexPublicKey: kexPublic,
      );
      // Swap the recorded ephemeral key for a different valid one. The KDF
      // binds it (salt), so even this "plausible" forgery cannot produce the
      // right DEM key — no signature needed to catch it.
      final other = await const PqForgeHybridKeyAgreement()
          .generateClassicalKeyPairBytes();
      final tampered = PqEnvelope(
        profile: envelope.profile,
        kemAlgorithm: envelope.kemAlgorithm,
        kemCiphertext: envelope.kemCiphertext,
        nonce: envelope.nonce,
        payload: envelope.payload,
        metadata: {
          ...envelope.metadata,
          PqHybridKemDem.metadataKey: {
            'algorithm': 'x25519',
            'ephemeralPublicKey': base64Encode(other.publicKey),
          },
        },
      );
      await expectLater(
        forge.decryptAsync(
          keys.kemKeyPair.secretKey,
          tampered,
          recipientKexSecretKey: kexSecret,
        ),
        throwsA(isA<PqForgeAuthTagException>()),
      );
    });

    test('sync decrypt refuses hybrid envelopes with a clear error', () async {
      final envelope = await forge.encryptAsync(
        keys.kemKeyPair.publicKey,
        payload(64),
        recipientKexPublicKey: kexPublic,
      );
      expect(
        () => forge.decrypt(keys.kemKeyPair.secretKey, envelope),
        throwsA(
          isA<PqForgeException>().having(
            (e) => e.message,
            'message',
            contains('decryptAsync'),
          ),
        ),
      );
    });

    test('the hybridKex metadata key is reserved on both encrypt paths', () {
      final metadata = {
        PqHybridKemDem.metadataKey: {'algorithm': 'x25519'},
      };
      expect(
        () => forge.encrypt(
          keys.kemKeyPair.publicKey,
          payload(8),
          metadata: metadata,
        ),
        throwsA(isA<PqForgeException>()),
      );
      expect(
        forge.encryptAsync(
          keys.kemKeyPair.publicKey,
          payload(8),
          metadata: metadata,
        ),
        throwsA(isA<PqForgeException>()),
      );
    });
  });

  group('engine-aware one-shot path', () {
    test('non-hybrid encryptAsync output opens under sync decrypt (and the '
        'other engine)', () async {
      final plaintext = payload(2048);
      for (final provider in PqForgeEngineProvider.values) {
        final envelope = await forge.encryptAsync(
          keys.kemKeyPair.publicKey,
          plaintext,
          engine: aeadEngineForProvider(provider),
        );
        expect(PqHybridKemDem.isHybrid(envelope.metadata), isFalse);
        // Byte-compatible with the sync PointyCastle path.
        expect(forge.decrypt(keys.kemKeyPair.secretKey, envelope), plaintext);
        // And with the opposite async engine.
        final opposite = provider == PqForgeEngineProvider.pureDart
            ? PqForgeEngineProvider.nativeCryptography
            : PqForgeEngineProvider.pureDart;
        expect(
          await forge.decryptAsync(
            keys.kemKeyPair.secretKey,
            envelope,
            engine: aeadEngineForProvider(opposite),
          ),
          plaintext,
        );
      }
    });

    test('sync encrypt output opens under decryptAsync', () async {
      final plaintext = payload(1024);
      final envelope = forge.encrypt(keys.kemKeyPair.publicKey, plaintext);
      expect(
        await forge.decryptAsync(keys.kemKeyPair.secretKey, envelope),
        plaintext,
      );
    });
  });

  group('hybrid key schedule', () {
    test(
      'hybrid DEM key differs from the KEM-only key and is deterministic',
      () {
        final kemSecret = payload(32);
        final kemCiphertext = payload(PqKemAlgorithm.mlKem512.ciphertextBytes);
        final classical = payload(32);
        final ephemeral = payload(32);
        final hybrid = PqHybridKemDem.deriveDemKey(
          profile: PqForgeProfile.compact,
          kemSharedSecret: kemSecret,
          kemCiphertext: kemCiphertext,
          classicalSharedSecret: classical,
          classicalEphemeralPublicKey: ephemeral,
        );
        expect(hybrid, hasLength(32));
        expect(
          hybrid,
          PqHybridKemDem.deriveDemKey(
            profile: PqForgeProfile.compact,
            kemSharedSecret: kemSecret,
            kemCiphertext: kemCiphertext,
            classicalSharedSecret: classical,
            classicalEphemeralPublicKey: ephemeral,
          ),
          reason: 'derivation must be deterministic',
        );
        expect(
          hybrid,
          isNot(
            PqForge.deriveDemKey(
              PqForgeProfile.compact,
              kemSecret,
              kemCiphertext,
            ),
          ),
        );
      },
    );

    test('malformed hybridKex markers are rejected as PqForgeException', () {
      expect(
        () => PqHybridKemDem.parseMetadata({
          PqHybridKemDem.metadataKey: 'not-a-map',
        }),
        throwsA(isA<PqForgeException>()),
      );
      expect(
        () => PqHybridKemDem.parseMetadata({
          PqHybridKemDem.metadataKey: {'algorithm': 'x25519'},
        }),
        throwsA(isA<PqForgeException>()),
      );
      expect(
        () => PqHybridKemDem.parseMetadata({
          PqHybridKemDem.metadataKey: {
            'algorithm': 'p-384',
            'ephemeralPublicKey': base64Encode(Uint8List(32)),
          },
        }),
        throwsA(isA<PqForgeException>()),
      );
      expect(PqHybridKemDem.parseMetadata(const {}), isNull);
    });
  });

  group('streaming hybrid containers', () {
    late Directory dir;

    setUp(() => dir = Directory.systemTemp.createTempSync('pqfs_hybrid_'));
    tearDown(() => dir.deleteSync(recursive: true));

    test('roundtrip with the marker bound into the signed header', () async {
      final original = payload(300 * 1024);
      final src = File('${dir.path}/in.bin')..writeAsBytesSync(original);
      final enc = File('${dir.path}/in.pqf');
      final out = File('${dir.path}/out.bin');
      final cipher = PqForgeStreamCipher();

      final stats = await cipher.encryptFile(
        recipientPublicKey: keys.kemKeyPair.publicKey,
        recipientKexPublicKey: kexPublic,
        input: src,
        output: enc,
        profile: PqForgeProfile.compact,
        signerSecretKey: keys.signatureKeyPair.secretKey,
        frameSize: 64 * 1024,
      );
      expect(stats.signed, isTrue);

      final header = await cipher.readHeader(enc);
      expect(PqHybridKemDem.isHybrid(header.metadata), isTrue);

      await cipher.decryptFile(
        recipientSecretKey: keys.kemKeyPair.secretKey,
        recipientKexSecretKey: kexSecret,
        input: enc,
        output: out,
        signerPublicKey: keys.signatureKeyPair.publicKey,
      );
      expect(out.readAsBytesSync(), original);
    });

    test('missing X25519 secret fails before any frame is opened', () async {
      final src = File('${dir.path}/in.bin')..writeAsBytesSync(payload(1024));
      final enc = File('${dir.path}/in.pqf');
      final cipher = PqForgeStreamCipher();
      await cipher.encryptFile(
        recipientPublicKey: keys.kemKeyPair.publicKey,
        recipientKexPublicKey: kexPublic,
        input: src,
        output: enc,
        profile: PqForgeProfile.compact,
      );
      await expectLater(
        cipher.decryptFile(
          recipientSecretKey: keys.kemKeyPair.secretKey,
          input: enc,
          output: File('${dir.path}/out.bin'),
        ),
        throwsA(
          isA<PqForgeException>().having(
            (e) => e.message,
            'message',
            contains('X25519 secret key is required'),
          ),
        ),
      );
      expect(File('${dir.path}/out.bin').existsSync(), isFalse);
    });

    test('the wrong X25519 secret fails frame authentication', () async {
      final src = File('${dir.path}/in.bin')..writeAsBytesSync(payload(1024));
      final enc = File('${dir.path}/in.pqf');
      final cipher = PqForgeStreamCipher();
      await cipher.encryptFile(
        recipientPublicKey: keys.kemKeyPair.publicKey,
        recipientKexPublicKey: kexPublic,
        input: src,
        output: enc,
        profile: PqForgeProfile.compact,
      );
      final wrong = await const PqForgeHybridKeyAgreement()
          .generateClassicalKeyPairBytes();
      await expectLater(
        cipher.decryptFile(
          recipientSecretKey: keys.kemKeyPair.secretKey,
          recipientKexSecretKey: wrong.secretKey,
          input: enc,
          output: File('${dir.path}/out.bin'),
        ),
        throwsA(isA<PqForgeAuthTagException>()),
      );
    });
  });
}
