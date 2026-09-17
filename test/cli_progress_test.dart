import 'dart:io';
import 'dart:isolate';

import 'package:test/test.dart';

import '../bin/src/console.dart';
import '../bin/src/progress_reporter.dart';
import '../bin/src/support.dart';

void main() {
  late Directory dir;
  late File log;
  late IOSink sink;
  late Console previous;

  setUp(() {
    dir = Directory.systemTemp.createTempSync('pqforge-progress-');
    log = File('${dir.path}/log.txt');
    sink = log.openWrite();
    previous = Console.instance;
    Console.instance = Console(const Ansi(false), out: sink, err: sink);
  });

  tearDown(() async {
    await sink.flush();
    await sink.close();
    Console.instance = previous;
    if (dir.existsSync()) dir.deleteSync(recursive: true);
  });

  Future<String> output() async {
    await sink.flush();
    return log.readAsStringSync();
  }

  test('completeFile reports finished count, not started count', () async {
    final progress = ProgressReporter(total: 3, operation: 'encrypting');
    progress.startFile('a.txt', fileSizeBytes: 10);
    progress.startFile('b.txt', fileSizeBytes: 10);
    progress.startFile('c.txt', fileSizeBytes: 10);
    progress.completeFile('b.txt');
    progress.completeFile('a.txt');
    progress.failFile('c.txt', 'boom');
    progress.done();

    expect(progress.successCount, 2);
    expect(progress.failCount, 1);
    expect(progress.hasFailures, isTrue);

    final text = await output();
    expect(text, contains('[1/3] SUCCESS: b.txt'));
    expect(text, contains('[2/3] SUCCESS: a.txt'));
    expect(text, contains('[3/3] FAILED: c.txt'));
    expect(text, contains('Failures: 1'));
  });

  test('quiet mutes per-file lines but still prints the summary', () async {
    final progress = ProgressReporter(
      total: 1,
      operation: 'decrypting',
      quiet: true,
    );
    progress.startFile('secret.bin', fileSizeBytes: 32);
    progress.completeFile('secret.bin');
    progress.done();

    final text = await output();
    expect(text, isNot(contains('SUCCESS: secret.bin')));
    expect(text, contains('decrypting complete: 1 file(s) processed'));
    expect(text, contains('Failures: 0'));
  });

  test('updateBytes writes a throttled byte progress line', () async {
    final progress = ProgressReporter(total: 1, operation: 'encrypting');
    progress.startFile('big.bin', fileSizeBytes: 2048);
    progress.updateBytes(processed: 2048, totalBytes: 2048);
    progress.completeFile('big.bin');
    progress.done();

    final text = await output();
    expect(text, contains('encrypting'));
    expect(text, contains('2.0 KB/2.0 KB'));
    expect(text, contains('SUCCESS: big.bin'));
  });

  test(
    'completeFile throughput uses finished bytes, not started bytes',
    () async {
      const twoMeg = 2 * 1024 * 1024;
      final progress = ProgressReporter(total: 3, operation: 'encrypting');
      progress.startFile('a.bin', fileSizeBytes: twoMeg);
      progress.startFile('b.bin', fileSizeBytes: twoMeg);
      progress.startFile('c.bin', fileSizeBytes: twoMeg);
      progress.completeFile('a.bin');

      final text = await output();
      expect(text, contains('2.0 MB/s'));
      expect(text, isNot(contains('6.0 MB/s')));
    },
  );

  test(
    'failJob marks the job failed without a per-file SUCCESS line',
    () async {
      final progress = ProgressReporter(total: 4, operation: 'packing');
      progress.failJob('kem encapsulate failed');
      progress.done();

      expect(progress.hasFailures, isTrue);
      expect(progress.failCount, 1);
      expect(progress.successCount, 0);

      final text = await output();
      expect(text, isNot(contains('SUCCESS:')));
      expect(text, contains('Failures: 1'));
      expect(text, contains('kem encapsulate failed'));
    },
  );

  test('concurrent updateBytes aggregates in-flight files', () async {
    const meg = 1024 * 1024;
    final progress = ProgressReporter(total: 2, operation: 'encrypting');
    progress.startFile('a.bin', fileSizeBytes: 2 * meg);
    progress.startFile('b.bin', fileSizeBytes: 2 * meg);
    await Future<void>.delayed(const Duration(milliseconds: 110));
    progress.updateBytes(path: 'a.bin', processed: meg, totalBytes: 2 * meg);
    await Future<void>.delayed(const Duration(milliseconds: 110));
    progress.updateBytes(path: 'b.bin', processed: meg, totalBytes: 2 * meg);

    final text = await output();
    expect(text, contains('2048.0 KB/4096.0 KB'));
    expect(progress.inFlightCount, 2);
  });

  test('updateBytes after completeFile is ignored', () async {
    final progress = ProgressReporter(total: 1, operation: 'encrypting');
    progress.startFile('a.bin', fileSizeBytes: 2048);
    progress.completeFile('a.bin');
    progress.updateBytes(path: 'a.bin', processed: 2048, totalBytes: 2048);
    expect(progress.successCount, 1);
  });

  test('isolateRunWithProgress forwards byte updates', () async {
    final received = <(int, int?)>[];
    await isolateRunWithProgress<void>((port) {
      return Isolate.run(() async {
        port.send(<Object?>[10, 30]);
        port.send(<Object?>[30, 30]);
      });
    }, onProgress: (processed, total) => received.add((processed, total)));
    expect(received, [(10, 30), (30, 30)]);
  });
}
