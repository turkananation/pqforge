@Tags(['benchmark'])
/// Phase 0 of the pqforge optimization blueprint: synthetic, memory-tracked
/// baseline for the bulk encrypt/decrypt I/O path.
///
/// Two test groups live here:
///
///  * **memory budget gate (fast, always runs)** — pure unit tests of
///    [MemoryBudget]. This is the blueprint's exit gate: it verifies that the
///    safety check correctly *fails* a peak above 1.5× and *passes* a bounded
///    one, without allocating anything heavy. A plain `dart test` runs only
///    this group.
///  * **synthetic I/O baseline (heavy)** — generates a payload, runs the real
///    `PqForge.encrypt`/`decrypt` path inside worker isolates, and records peak
///    RSS + wall time + throughput. Skipped unless `PQFORGE_BENCH=1`.
///
/// ## Running
///
/// ```sh
/// # fast gate only (default)
/// dart test test/benchmark_io_test.dart
///
/// # full baseline (slow: pure-Dart AES-GCM runs at ~1 MiB/s)
/// PQFORGE_BENCH=1 dart test -t benchmark test/benchmark_io_test.dart
/// ```
///
/// ### Environment knobs
///
///  * `PQFORGE_BENCH=1`            — opt in to the heavy group.
///  * `PQFORGE_BENCH_MB=8`         — payload size in MiB (default 8). Amplification
///                                   is size-independent on the current whole-file
///                                   path, so a small payload still proves the
///                                   defect; scale up only on a big-RAM box.
///  * `PQFORGE_BENCH_PROFILES=maximum` — comma list of `compact,balanced,maximum`.
///  * `PQFORGE_BENCH_ENFORCE=1`    — turn budget breaches into test failures
///                                   (leave off for the Phase 0 baseline, which is
///                                   *expected* to exceed budget; flip on once the
///                                   streaming path lands).
///  * `PQFORGE_BENCH_REPORT=path`  — JSON report output (default: system temp).
library;

import 'dart:io';
import 'dart:isolate';
import 'dart:math';
import 'dart:typed_data';

import 'package:pqforge/pqforge_io.dart';
import 'package:test/test.dart';

import 'support/benchmark_harness.dart';

void main() {
  group('memory budget gate (fast, always runs)', () {
    const budget = MemoryBudget();

    test('flags amplification above the 1.5x limit as FAIL', () {
      // baseline 100, peak 360, payload 100 -> delta 260 -> 2.6x.
      final verdict = budget.evaluate(
        peakRssBytes: 360 * bytesPerMiB,
        baselineRssBytes: 100 * bytesPerMiB,
        payloadBytes: 100 * bytesPerMiB,
      );
      expect(verdict.amplificationFactor, closeTo(2.6, 1e-9));
      expect(verdict.ok, isFalse);
    });

    test('passes amplification at or below the 1.5x limit', () {
      // baseline 100, peak 245, payload 100 -> delta 145 -> 1.45x.
      final verdict = budget.evaluate(
        peakRssBytes: 245 * bytesPerMiB,
        baselineRssBytes: 100 * bytesPerMiB,
        payloadBytes: 100 * bytesPerMiB,
      );
      expect(verdict.amplificationFactor, closeTo(1.45, 1e-9));
      expect(verdict.ok, isTrue);
    });

    test(
      'a bounded streaming-style peak passes regardless of payload size',
      () {
        // 1 GiB payload, but only a 2 MiB resident frame buffer grows the heap.
        final verdict = budget.evaluate(
          peakRssBytes: 150 * bytesPerMiB + 2 * bytesPerMiB,
          baselineRssBytes: 150 * bytesPerMiB,
          payloadBytes: 1024 * bytesPerMiB,
        );
        expect(verdict.ok, isTrue);
        expect(verdict.amplificationFactor, lessThan(0.01));
      },
    );

    test(
      'absolute peak gate is informational below 256 MiB, active at GiB scale',
      () {
        final small = budget.evaluate(
          peakRssBytes: 200 * bytesPerMiB,
          baselineRssBytes: 150 * bytesPerMiB,
          payloadBytes: 8 * bytesPerMiB,
        );
        expect(small.absoluteGateApplicable, isFalse);

        final large = budget.evaluate(
          peakRssBytes: 1600 * bytesPerMiB,
          baselineRssBytes: 150 * bytesPerMiB,
          payloadBytes: 1024 * bytesPerMiB,
        );
        expect(large.absoluteGateApplicable, isTrue);
      },
    );

    test('rejects a non-positive payload', () {
      expect(
        () => budget.evaluate(
          peakRssBytes: 1,
          baselineRssBytes: 0,
          payloadBytes: 0,
        ),
        throwsArgumentError,
      );
    });
  });

  _heavyBaselineGroup();
}

void _heavyBaselineGroup() {
  final enabled = Platform.environment['PQFORGE_BENCH'] == '1';
  final payloadMiB =
      int.tryParse(Platform.environment['PQFORGE_BENCH_MB'] ?? '') ?? 8;
  final payloadBytes = payloadMiB * bytesPerMiB;
  final profileNames =
      (Platform.environment['PQFORGE_BENCH_PROFILES'] ?? 'maximum')
          .split(',')
          .map((name) => name.trim())
          .where((name) => name.isNotEmpty)
          .toList();
  final enforce = Platform.environment['PQFORGE_BENCH_ENFORCE'] == '1';
  // 'oneshot' (default) measures the legacy PqForge.encrypt path; 'streaming'
  // measures the bounded-memory .pqfs path (Phase 3) so amplification should
  // stay flat and small as payload size grows.
  final streaming = Platform.environment['PQFORGE_BENCH_MODE'] == 'streaming';
  final mode = streaming ? 'streaming' : 'oneshot';

  group(
    'synthetic I/O baseline (heavy)',
    () {
      const budget = MemoryBudget();
      final report = BenchmarkReport();
      final keyCache = <String, PqKeyBundle>{};
      late Directory tempDir;
      late String inputPath;
      late int payloadChecksum;

      PqKeyBundle keysFor(String profileName) {
        return keyCache.putIfAbsent(profileName, () {
          final profile = PqForgeProfile.byName(profileName);
          return PqForge(profile: profile).generateKeys(profile: profile);
        });
      }

      setUpAll(() {
        tempDir = Directory.systemTemp.createTempSync('pqforge_bench_');
        inputPath = '${tempDir.path}/payload.bin';
        stdout.writeln(
          '\n[pqforge bench] generating ${formatMiB(payloadBytes)} payload '
          'at $inputPath',
        );
        payloadChecksum = _generatePayloadFile(inputPath, payloadBytes);
        stdout.writeln(
          '[pqforge bench] mode=$mode profiles=$profileNames enforce=$enforce '
          'host=${Platform.numberOfProcessors} cores',
        );
      });

      tearDownAll(() {
        stdout
          ..writeln(
            '\n=== pqforge $mode benchmark (payload '
            '${formatMiB(payloadBytes)}) ===',
          )
          ..writeln(report.table());
        final reportPath =
            Platform.environment['PQFORGE_BENCH_REPORT'] ??
            '${Directory.systemTemp.path}/pqforge_benchmark_baseline.json';
        final file = report.writeJson(reportPath);
        stdout.writeln('JSON report written to ${file.path}\n');
        if (tempDir.existsSync()) tempDir.deleteSync(recursive: true);
      });

      for (final profileName in profileNames) {
        for (final signed in const [false, true]) {
          final cellName = '$profileName / ${signed ? 'signed' : 'unsigned'}';
          test(cellName, () async {
            final keys = keysFor(profileName);
            final envPath =
                '${tempDir.path}/$profileName-${signed ? 'signed' : 'unsigned'}.pqf';

            // ---- encrypt ----
            late Map<String, Object?> encInfo;
            final encRun = await measure(() async {
              encInfo = streaming
                  ? await _encryptStreamingInIsolate(
                      profileName: profileName,
                      inputPath: inputPath,
                      envPath: envPath,
                      recipientPublicKey: keys.kemKeyPair.publicKey,
                      signerSecretKey: keys.signatureKeyPair.secretKey,
                      signed: signed,
                    )
                  : await _encryptInIsolate(
                      profileName: profileName,
                      inputPath: inputPath,
                      envPath: envPath,
                      recipientPublicKey: keys.kemKeyPair.publicKey,
                      signerSecretKey: keys.signatureKeyPair.secretKey,
                      signed: signed,
                    );
            });
            final encResult = BenchmarkResult(
              operation: 'encrypt',
              profileName: profileName,
              signed: signed,
              payloadBytes: payloadBytes,
              run: encRun,
              verdict: budget.evaluate(
                peakRssBytes: encRun.peakBytes,
                baselineRssBytes: encRun.baselineBytes,
                payloadBytes: payloadBytes,
              ),
              detail: encInfo,
            );
            report.add(encResult);
            _printCell(encResult);

            // ---- decrypt ----
            final outputPath = '$envPath.out';
            late Map<String, Object?> decInfo;
            final decRun = await measure(() async {
              decInfo = streaming
                  ? await _decryptStreamingInIsolate(
                      envPath: envPath,
                      outputPath: outputPath,
                      recipientSecretKey: keys.kemKeyPair.secretKey,
                      signerPublicKey: keys.signatureKeyPair.publicKey,
                      signed: signed,
                    )
                  : await _decryptInIsolate(
                      profileName: profileName,
                      envPath: envPath,
                      recipientSecretKey: keys.kemKeyPair.secretKey,
                      signerPublicKey: keys.signatureKeyPair.publicKey,
                      signed: signed,
                    );
            });
            final decResult = BenchmarkResult(
              operation: 'decrypt',
              profileName: profileName,
              signed: signed,
              payloadBytes: payloadBytes,
              run: decRun,
              verdict: budget.evaluate(
                peakRssBytes: decRun.peakBytes,
                baselineRssBytes: decRun.baselineBytes,
                payloadBytes: payloadBytes,
              ),
              detail: decInfo,
            );
            report.add(decResult);
            _printCell(decResult);

            // ---- correctness: full round-trip ----
            expect(
              decInfo['plaintextBytes'],
              payloadBytes,
              reason: 'decrypted length must equal the original payload',
            );
            expect(
              decInfo['checksum'],
              payloadChecksum,
              reason: 'decrypted bytes must match the original (round-trip)',
            );

            // Bound disk use across cells on large runs.
            for (final path in [envPath, outputPath]) {
              final file = File(path);
              if (file.existsSync()) file.deleteSync();
            }

            if (enforce) {
              expect(
                encResult.verdict.ok && decResult.verdict.ok,
                isTrue,
                reason:
                    'PQFORGE_BENCH_ENFORCE=1 and a memory budget was '
                    'exceeded:\n  encrypt: ${encResult.verdict.describe()}'
                    '\n  decrypt: ${decResult.verdict.describe()}',
              );
            }
          }, timeout: Timeout(Duration(seconds: 120 + payloadMiB * 20)));
        }
      }
    },
    skip: enabled
        ? false
        : 'Set PQFORGE_BENCH=1 to run the heavy I/O baseline (slow; see file doc).',
  );
}

void _printCell(BenchmarkResult result) {
  stdout.writeln(
    '  ${result.label}: ${result.verdict.describe()} '
    '| ${result.throughputMiBs.toStringAsFixed(2)} MiB/s '
    '| ${(result.run.wall.inMilliseconds / 1000).toStringAsFixed(1)}s wall '
    '| ${result.run.sampleCount} samples',
  );
}

/// FNV-1a (32-bit). Deterministic and isolate-safe (no shared state), used to
/// verify the round-trip without transferring the payload across isolates.
int fnv1a32(Uint8List data) {
  var hash = 0x811C9DC5;
  for (final byte in data) {
    hash = ((hash ^ byte) * 0x01000193) & 0xFFFFFFFF;
  }
  return hash;
}

/// Writes [sizeBytes] of deterministic pseudo-random data to [path] in 4 MiB
/// chunks (bounded setup memory) and returns its [fnv1a32] checksum.
int _generatePayloadFile(String path, int sizeBytes) {
  final random = Random(0xC0FFEE);
  const chunkBytes = 4 * bytesPerMiB;
  final buffer = Uint8List(chunkBytes);
  final handle = File(path).openSync(mode: FileMode.write);
  var hash = 0x811C9DC5;
  var written = 0;
  try {
    while (written < sizeBytes) {
      final remaining = sizeBytes - written;
      final n = remaining < chunkBytes ? remaining : chunkBytes;
      for (var i = 0; i < n; i++) {
        final byte = random.nextInt(256);
        buffer[i] = byte;
        hash = ((hash ^ byte) * 0x01000193) & 0xFFFFFFFF;
      }
      handle.writeFromSync(buffer, 0, n);
      written += n;
    }
  } finally {
    handle.closeSync();
  }
  return hash;
}

/// Encrypts the file at [inputPath] in a worker isolate (so the parent's RSS
/// sampler stays live), writes the envelope to [envPath], and returns timing +
/// size detail. Mirrors the CLI ingestion — including the defect-M2
/// `Uint8List.fromList` copy — so the baseline reflects true current peak RSS.
Future<Map<String, Object?>> _encryptInIsolate({
  required String profileName,
  required String inputPath,
  required String envPath,
  required Uint8List recipientPublicKey,
  required Uint8List signerSecretKey,
  required bool signed,
}) {
  return Isolate.run(() {
    final profile = PqForgeProfile.byName(profileName);
    final forge = PqForge(profile: profile);
    // Phase 1 (M2): readAsBytesSync already returns a Uint8List — no fromList.
    final fileBytes = File(inputPath).readAsBytesSync();
    final stopwatch = Stopwatch()..start();
    final envelope = forge.encrypt(
      recipientPublicKey,
      fileBytes,
      profile: profile,
      signerSecretKey: signed ? signerSecretKey : null,
      signatureAlgorithm: signed ? profile.signature : null,
    );
    final encryptMs = stopwatch.elapsedMilliseconds;
    final binary = envelope.toBinary();
    final serializeMs = stopwatch.elapsedMilliseconds - encryptMs;
    File(envPath).writeAsBytesSync(binary);
    return <String, Object?>{
      'encryptMs': encryptMs,
      'serializeMs': serializeMs,
      'envelopeBytes': binary.length,
    };
  });
}

/// Reads + decrypts the envelope at [envPath] in a worker isolate and returns
/// timing plus the recovered-plaintext length and [fnv1a32] checksum (for the
/// parent's round-trip assertion). Mirrors `readEnvelope`'s defect-M2 copy.
Future<Map<String, Object?>> _decryptInIsolate({
  required String profileName,
  required String envPath,
  required Uint8List recipientSecretKey,
  required Uint8List signerPublicKey,
  required bool signed,
}) {
  return Isolate.run(() {
    final profile = PqForgeProfile.byName(profileName);
    final forge = PqForge(profile: profile);
    // Phase 1 (M2): no redundant fromList; fromBinary takes zero-copy views.
    final envelope = PqEnvelope.fromBinary(File(envPath).readAsBytesSync());
    final stopwatch = Stopwatch()..start();
    final plaintext = forge.decrypt(
      recipientSecretKey,
      envelope,
      signerPublicKey: signed ? signerPublicKey : null,
    );
    final decryptMs = stopwatch.elapsedMilliseconds;
    return <String, Object?>{
      'decryptMs': decryptMs,
      'plaintextBytes': plaintext.length,
      'checksum': fnv1a32(plaintext),
    };
  });
}

/// Streaming (`.pqfs`) encrypt in a worker isolate (Phase 3). Peak heap is a
/// small multiple of the frame size regardless of payload length, so the
/// measured amplification should stay flat as the payload grows.
Future<Map<String, Object?>> _encryptStreamingInIsolate({
  required String profileName,
  required String inputPath,
  required String envPath,
  required Uint8List recipientPublicKey,
  required Uint8List signerSecretKey,
  required bool signed,
}) {
  return Isolate.run(() async {
    final profile = PqForgeProfile.byName(profileName);
    final stopwatch = Stopwatch()..start();
    final stats = await PqForgeStreamCipher().encryptFile(
      recipientPublicKey: recipientPublicKey,
      input: File(inputPath),
      output: File(envPath),
      profile: profile,
      signerSecretKey: signed ? signerSecretKey : null,
    );
    return <String, Object?>{
      'encryptMs': stopwatch.elapsedMilliseconds,
      'frames': stats.frameCount,
      'envelopeBytes': stats.containerBytes,
    };
  });
}

/// Streaming decrypt in a worker isolate. The recovered plaintext is written to
/// [outputPath] and checksummed with a bounded, chunked read (never the whole
/// file in memory), so the decrypt measurement itself stays bounded.
Future<Map<String, Object?>> _decryptStreamingInIsolate({
  required String envPath,
  required String outputPath,
  required Uint8List recipientSecretKey,
  required Uint8List signerPublicKey,
  required bool signed,
}) {
  return Isolate.run(() async {
    final stopwatch = Stopwatch()..start();
    await PqForgeStreamCipher().decryptFile(
      recipientSecretKey: recipientSecretKey,
      input: File(envPath),
      output: File(outputPath),
      signerPublicKey: signed ? signerPublicKey : null,
    );
    final decryptMs = stopwatch.elapsedMilliseconds;
    return <String, Object?>{
      'decryptMs': decryptMs,
      'plaintextBytes': File(outputPath).lengthSync(),
      'checksum': _fnv1aFile(outputPath),
    };
  });
}

/// FNV-1a over a file read in 4 MiB chunks — bounded memory, so it can run
/// inside the measured streaming-decrypt region without inflating peak RSS.
int _fnv1aFile(String path) {
  final handle = File(path).openSync();
  const chunkBytes = 4 * bytesPerMiB;
  final buffer = Uint8List(chunkBytes);
  var hash = 0x811C9DC5;
  try {
    while (true) {
      final n = handle.readIntoSync(buffer);
      if (n <= 0) break;
      for (var i = 0; i < n; i++) {
        hash = ((hash ^ buffer[i]) * 0x01000193) & 0xFFFFFFFF;
      }
    }
  } finally {
    handle.closeSync();
  }
  return hash;
}
