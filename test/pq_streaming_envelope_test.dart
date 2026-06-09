import 'dart:io';
import 'dart:typed_data';

import 'package:pqforge/pqforge_io.dart';
import 'package:test/test.dart';

/// Phase 3: the `.pqfs` streaming envelope. Round-trips across frame boundaries
/// in bounded memory, and rejects tampering, reordering, truncation, and
/// splicing via the per-frame `seq`/`isFinal` AAD binding.
void main() {
  // Compact profile keeps ML-KEM-512/ML-DSA-44 fast. A tiny frame size forces
  // many frames out of small payloads so the multi-frame paths are exercised.
  final forge = PqForge(profile: PqForgeProfile.compact);
  final cipher = PqForgeStreamCipher();
  const frameSize = 1024;

  late Directory dir;
  late PqKeyBundle keys;

  setUp(() {
    dir = Directory.systemTemp.createTempSync('pqfs_test_');
    keys = forge.generateKeys(profile: PqForgeProfile.compact);
  });
  tearDown(() => dir.deleteSync(recursive: true));

  Uint8List payload(int n) =>
      Uint8List.fromList(List<int>.generate(n, (i) => (i * 31 + 7) & 0xFF));

  File input(String name, Uint8List bytes) {
    final file = File('${dir.path}/$name');
    file.writeAsBytesSync(bytes);
    return file;
  }

  group('round-trip across frame boundaries', () {
    // 0, 1, just-under, exact, just-over a frame, and several frames.
    for (final size in const [0, 1, 1023, 1024, 1025, 4096, 10000]) {
      test('$size bytes', () async {
        final original = payload(size);
        final src = input('plain_$size.bin', original);
        final enc = File('${dir.path}/enc_$size.pqf');
        final dec = File('${dir.path}/dec_$size.bin');

        final stats = await cipher.encryptFile(
          recipientPublicKey: keys.kemKeyPair.publicKey,
          input: src,
          output: enc,
          profile: PqForgeProfile.compact,
          frameSize: frameSize,
        );
        expect(stats.plaintextBytes, size);
        expect(await PqForgeStreamCipher.isStreamingFile(enc), isTrue);

        await cipher.decryptFile(
          recipientSecretKey: keys.kemKeyPair.secretKey,
          input: enc,
          output: dec,
        );
        expect(dec.readAsBytesSync(), original);
      });
    }
  });

  group('signatures and associated data', () {
    test('signed streaming round-trips and rejects the wrong signer', () async {
      final original = payload(5000);
      final src = input('p.bin', original);
      final enc = File('${dir.path}/p.pqf');
      final dec = File('${dir.path}/p.out');

      await cipher.encryptFile(
        recipientPublicKey: keys.kemKeyPair.publicKey,
        input: src,
        output: enc,
        profile: PqForgeProfile.compact,
        frameSize: frameSize,
        signerSecretKey: keys.signatureKeyPair.secretKey,
        signerKeyId: 'streamer',
      );

      final header = await cipher.readHeader(enc);
      expect(header.isSigned, isTrue);
      expect(header.signerKeyId, 'streamer');

      await cipher.decryptFile(
        recipientSecretKey: keys.kemKeyPair.secretKey,
        input: enc,
        output: dec,
        signerPublicKey: keys.signatureKeyPair.publicKey,
      );
      expect(dec.readAsBytesSync(), original);

      final wrongSigner = forge.generateSignatureKeyPair();
      await expectLater(
        cipher.decryptFile(
          recipientSecretKey: keys.kemKeyPair.secretKey,
          input: enc,
          output: File('${dir.path}/p.bad'),
          signerPublicKey: wrongSigner.publicKey,
        ),
        throwsA(isA<PqForgeException>()),
      );
    });

    test('AAD is bound and a mismatch is rejected', () async {
      final original = payload(3000);
      final src = input('a.bin', original);
      final enc = File('${dir.path}/a.pqf');
      final aad = PqBytes.utf8Bytes('tenant:county-a');

      await cipher.encryptFile(
        recipientPublicKey: keys.kemKeyPair.publicKey,
        input: src,
        output: enc,
        profile: PqForgeProfile.compact,
        frameSize: frameSize,
        aad: aad,
      );

      await cipher.decryptFile(
        recipientSecretKey: keys.kemKeyPair.secretKey,
        input: enc,
        output: File('${dir.path}/a.out'),
        aadResolver: (_) => aad,
      );

      await expectLater(
        cipher.decryptFile(
          recipientSecretKey: keys.kemKeyPair.secretKey,
          input: enc,
          output: File('${dir.path}/a.bad'),
          aadResolver: (_) => PqBytes.utf8Bytes('tenant:county-b'),
        ),
        throwsA(isA<PqForgeException>()),
      );
      // Required AAD omitted entirely.
      await expectLater(
        cipher.decryptFile(
          recipientSecretKey: keys.kemKeyPair.secretKey,
          input: enc,
          output: File('${dir.path}/a.bad2'),
        ),
        throwsA(isA<PqForgeException>()),
      );
    });
  });

  group('integrity: tampering, truncation, splicing', () {
    late File enc;
    late Uint8List original;

    setUp(() async {
      original = payload(8000); // ~8 frames at frameSize 1024
      final src = input('t.bin', original);
      enc = File('${dir.path}/t.pqf');
      await cipher.encryptFile(
        recipientPublicKey: keys.kemKeyPair.publicKey,
        input: src,
        output: enc,
        profile: PqForgeProfile.compact,
        frameSize: frameSize,
      );
    });

    Future<void> expectDecryptFails() => expectLater(
      cipher.decryptFile(
        recipientSecretKey: keys.kemKeyPair.secretKey,
        input: enc,
        output: File('${dir.path}/t.out'),
      ),
      throwsA(anyOf(isA<PqForgeException>(), isA<PqForgeAuthTagException>())),
    );

    test('a flipped ciphertext byte fails authentication', () async {
      final bytes = enc.readAsBytesSync();
      bytes[bytes.length - 32] ^= 0x01; // inside the last frame's body
      enc.writeAsBytesSync(bytes);
      await expectDecryptFails();
    });

    test('dropping the final frame is detected', () async {
      final bytes = enc.readAsBytesSync();
      // Lop off the last frame entirely (more than one frame's worth of bytes).
      enc.writeAsBytesSync(
        Uint8List.sublistView(bytes, 0, bytes.length - (frameSize + 64)),
      );
      await expectDecryptFails();
    });

    test('trailing data after the final frame is rejected', () async {
      final bytes = enc.readAsBytesSync();
      enc.writeAsBytesSync(
        Uint8List.fromList([...bytes, ...List<int>.filled(32, 0xAB)]),
      );
      await expectDecryptFails();
    });

    test('a corrupted header is detected', () async {
      final bytes = enc.readAsBytesSync();
      bytes[20] ^= 0xFF; // inside headerCore (KEM ciphertext / metadata region)
      enc.writeAsBytesSync(bytes);
      await expectDecryptFails();
    });
  });

  test('a one-shot envelope is not detected as a streaming file', () async {
    final envelope = forge.encrypt(keys.kemKeyPair.publicKey, payload(64));
    final file = File('${dir.path}/legacy.pqf')
      ..writeAsBytesSync(envelope.toBinary());
    expect(await PqForgeStreamCipher.isStreamingFile(file), isFalse);
  });
}
