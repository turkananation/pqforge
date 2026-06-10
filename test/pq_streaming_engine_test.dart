import 'dart:async';
import 'dart:io';
import 'dart:typed_data';

import 'package:pqforge/pqforge_io.dart';
import 'package:test/test.dart';

/// Phase 4: the streaming bulk path runs through the swappable
/// [PqForgeAeadEngine], so the engine is the hardware-acceleration lever, and a
/// background-isolate offload (Axis A) keeps the calling isolate responsive.
void main() {
  final forge = PqForge(profile: PqForgeProfile.compact);
  late Directory dir;
  late PqKeyBundle keys;

  setUp(() {
    dir = Directory.systemTemp.createTempSync('pqfs_engine_');
    keys = forge.generateKeys(profile: PqForgeProfile.compact);
  });
  tearDown(() => dir.deleteSync(recursive: true));

  Uint8List payload(int n) =>
      Uint8List.fromList(List<int>.generate(n, (i) => (i * 17 + 5) & 0xFF));

  File write(String name, Uint8List bytes) =>
      File('${dir.path}/$name')..writeAsBytesSync(bytes);

  test(
    'a file sealed by one engine opens under the other (wire interop)',
    () async {
      final original = payload(6000);
      final src = write('x.bin', original);
      final enc = File('${dir.path}/x.pqf');
      final dec = File('${dir.path}/x.out');

      // Seal with pure-Dart PointyCastle, open with package:cryptography.
      await PqForgeStreamCipher.forProvider(
        PqForgeEngineProvider.pureDart,
      ).encryptFile(
        recipientPublicKey: keys.kemKeyPair.publicKey,
        input: src,
        output: enc,
        profile: PqForgeProfile.compact,
        frameSize: 1024,
      );
      await PqForgeStreamCipher.forProvider(
        PqForgeEngineProvider.nativeCryptography,
      ).decryptFile(
        recipientSecretKey: keys.kemKeyPair.secretKey,
        input: enc,
        output: dec,
      );
      expect(dec.readAsBytesSync(), original);

      // ...and the reverse direction.
      final enc2 = File('${dir.path}/y.pqf');
      final dec2 = File('${dir.path}/y.out');
      await PqForgeStreamCipher.forProvider(
        PqForgeEngineProvider.nativeCryptography,
      ).encryptFile(
        recipientPublicKey: keys.kemKeyPair.publicKey,
        input: src,
        output: enc2,
        profile: PqForgeProfile.compact,
        frameSize: 1024,
      );
      await PqForgeStreamCipher.forProvider(
        PqForgeEngineProvider.pureDart,
      ).decryptFile(
        recipientSecretKey: keys.kemKeyPair.secretKey,
        input: enc2,
        output: dec2,
      );
      expect(dec2.readAsBytesSync(), original);
    },
  );

  test('background encrypt/decrypt round-trips', () async {
    final original = payload(20000);
    final src = write('bg.bin', original);
    final enc = '${dir.path}/bg.pqf';
    final dec = '${dir.path}/bg.out';

    await PqForgeStreamCipher.encryptFileInBackground(
      recipientPublicKey: keys.kemKeyPair.publicKey,
      inputPath: src.path,
      outputPath: enc,
      profile: PqForgeProfile.compact,
    );
    await PqForgeStreamCipher.decryptFileInBackground(
      recipientSecretKey: keys.kemKeyPair.secretKey,
      inputPath: enc,
      outputPath: dec,
    );
    expect(File(dec).readAsBytesSync(), original);
  });

  test(
    'the calling isolate stays responsive during a background seal',
    () async {
      // Pin the slow pure-Dart engine (~1 MiB/s) so the worker stays busy for
      // a second-plus; a same-isolate synchronous cipher would freeze the
      // timer for that whole span. The assertion is on the *longest* gap
      // between ticks: the UI budget is 16 ms/frame, and the bound here is
      // 100 ms only to absorb CI scheduler/GC noise — orders of magnitude
      // below the multi-second stall this guards against (defect M4).
      final src = write('busy.bin', payload(1536 * 1024));
      final gapWatch = Stopwatch()..start();
      var maxGapMs = 0;
      var ticks = 0;
      final timer = Timer.periodic(const Duration(milliseconds: 10), (_) {
        final gap = gapWatch.elapsedMilliseconds;
        if (gap > maxGapMs) maxGapMs = gap;
        gapWatch.reset();
        ticks++;
      });
      try {
        await PqForgeStreamCipher.encryptFileInBackground(
          recipientPublicKey: keys.kemKeyPair.publicKey,
          inputPath: src.path,
          outputPath: '${dir.path}/busy.pqf',
          profile: PqForgeProfile.compact,
          engineProvider: PqForgeEngineProvider.pureDart,
        );
      } finally {
        timer.cancel();
      }
      expect(
        ticks,
        greaterThan(20),
        reason: 'sampler barely ran — not a valid measurement',
      );
      expect(
        maxGapMs,
        lessThan(100),
        reason:
            'the main isolate event loop stalled for ${maxGapMs}ms during '
            'the background seal',
      );
    },
    timeout: const Timeout(Duration(seconds: 90)),
  );
}
