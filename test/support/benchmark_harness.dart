/// Reusable memory + wall-time measurement harness for pqforge's I/O
/// benchmarks (Phase 0 of the optimization blueprint).
///
/// The harness is deliberately framework-free (no `package:test` import) so the
/// pure pieces — [MemoryBudget], [BudgetVerdict], [BenchmarkResult],
/// [BenchmarkReport] — can be unit-tested directly and reused by any future
/// bench or CLI tool.
///
/// ## Why the workload must run in a worker isolate
///
/// The production bulk pipeline is fully synchronous on the caller isolate
/// (defect M4). A same-isolate `Timer.periodic` sampler would therefore be
/// starved for the entire encryption and miss the peak. [measure] samples
/// [ProcessInfo.currentRss] on the *current* isolate while the caller runs the
/// actual work inside `Isolate.run`; because RSS is a process-wide OS metric,
/// the worker's allocations are visible to the parent's sampler. (Verified
/// empirically: a 300 MiB worker allocation shows up as a ~289 MiB parent-side
/// delta.)
library;

import 'dart:async';
import 'dart:convert';
import 'dart:io';

/// One mebibyte in bytes.
const int bytesPerMiB = 1024 * 1024;

/// Process-wide resident set size in bytes, sampled now.
int currentRssBytes() => ProcessInfo.currentRss;

/// Process-lifetime peak resident set size in bytes (getrusage `ru_maxrss` on
/// POSIX). Monotonic — useful only as an absolute cross-check of the sampled
/// per-run peak, never as a per-run delta.
int maxRssBytes() => ProcessInfo.maxRss;

/// Bytes rendered as a fixed-precision MiB value.
double bytesToMiB(int bytes) => bytes / bytesPerMiB;

/// Bytes rendered as a `"123.4 MiB"` string.
String formatMiB(int bytes) => '${bytesToMiB(bytes).toStringAsFixed(1)} MiB';

/// Polls [currentRssBytes] on a fixed interval and remembers the high-water
/// mark seen between [start] and [stop].
class RssSampler {
  RssSampler({
    required this.baselineBytes,
    this.interval = const Duration(milliseconds: 50),
  }) : _peakBytes = baselineBytes;

  /// RSS captured immediately before sampling began; the peak is floored to it.
  final int baselineBytes;

  /// Sampling cadence (the blueprint specifies 50 ms).
  final Duration interval;

  Timer? _timer;
  int _peakBytes;
  int _sampleCount = 0;

  /// Highest RSS observed so far (never below [baselineBytes]).
  int get peakBytes => _peakBytes;

  /// Number of samples taken — a sanity check that the event loop was free to
  /// fire the timer (a value near zero means the sampler was starved).
  int get sampleCount => _sampleCount;

  void start() {
    _timer ??= Timer.periodic(interval, (_) {
      final rss = currentRssBytes();
      _sampleCount++;
      if (rss > _peakBytes) _peakBytes = rss;
    });
  }

  void stop() {
    _timer?.cancel();
    _timer = null;
  }
}

/// The outcome of a single [measure] call.
class MeasuredRun {
  MeasuredRun({
    required this.baselineBytes,
    required this.peakBytes,
    required this.wall,
    required this.sampleCount,
    required this.maxRssEndBytes,
  });

  /// RSS just before the workload started.
  final int baselineBytes;

  /// Highest sampled RSS during the workload.
  final int peakBytes;

  /// End-to-end wall time of the workload (includes isolate spawn + file I/O).
  final Duration wall;

  /// Samples the 50 ms timer managed to take while the workload ran.
  final int sampleCount;

  /// Process `maxRss` read after the workload, as an absolute cross-check.
  final int maxRssEndBytes;

  /// Peak minus baseline, floored at zero — the resident growth attributable to
  /// the workload.
  int get deltaBytes =>
      peakBytes - baselineBytes < 0 ? 0 : peakBytes - baselineBytes;
}

/// Lets pending I/O flush and the heap quiesce before a baseline RSS reading.
/// Dart cannot force a GC, so this is a best-effort settle, not a guarantee.
Future<void> settleMemory([
  Duration delay = const Duration(milliseconds: 200),
]) async {
  await Future<void>.delayed(delay);
}

/// Records a baseline RSS, samples the peak while [body] runs, and returns the
/// timing + memory result.
///
/// [body] should perform the work under test inside `Isolate.run` so that this
/// isolate's event loop stays free to fire the sampler (see the library doc).
Future<MeasuredRun> measure(
  Future<void> Function() body, {
  Duration settle = const Duration(milliseconds: 200),
}) async {
  await settleMemory(settle);
  final baseline = currentRssBytes();
  final sampler = RssSampler(baselineBytes: baseline)..start();
  final stopwatch = Stopwatch()..start();
  try {
    await body();
  } finally {
    stopwatch.stop();
    sampler.stop();
  }
  return MeasuredRun(
    baselineBytes: baseline,
    peakBytes: sampler.peakBytes,
    wall: stopwatch.elapsed,
    sampleCount: sampler.sampleCount,
    maxRssEndBytes: maxRssBytes(),
  );
}

/// The pass/fail policy for a benchmarked operation.
///
/// Two distinct checks are tracked because they answer different questions:
///
///  * **Payload amplification** `(peak - baseline) / payload` is the size-robust
///    regression signal. The whole-file path amplifies ~3× (unsigned) to ~5×
///    (signed); a bounded streaming path drives this toward zero regardless of
///    payload size. This is the gate that [ok] reflects.
///  * **Absolute peak factor** `peak / payload` is the blueprint's literal
///    "peak RSS > 1.5 × file size" rule. It is only meaningful once the payload
///    dwarfs the ~150 MiB Dart VM floor, so it is reported but only flagged
///    [BudgetVerdict.absoluteGateApplicable] at/above [absoluteGateMinBytes].
class MemoryBudget {
  const MemoryBudget({
    this.amplificationLimit = 1.5,
    this.absoluteGateMinBytes = 256 * bytesPerMiB,
  });

  /// Maximum allowed `(peak - baseline) / payload`.
  final double amplificationLimit;

  /// Payload size at or above which the absolute `peak / payload` gate is
  /// considered meaningful rather than VM-floor noise.
  final int absoluteGateMinBytes;

  BudgetVerdict evaluate({
    required int peakRssBytes,
    required int baselineRssBytes,
    required int payloadBytes,
  }) {
    if (payloadBytes <= 0) {
      throw ArgumentError.value(payloadBytes, 'payloadBytes', 'must be > 0');
    }
    final delta = peakRssBytes - baselineRssBytes;
    final amplification = delta / payloadBytes;
    return BudgetVerdict(
      ok: amplification <= amplificationLimit,
      amplificationFactor: amplification,
      amplificationLimit: amplificationLimit,
      absolutePeakFactor: peakRssBytes / payloadBytes,
      absoluteGateApplicable: payloadBytes >= absoluteGateMinBytes,
      payloadBytes: payloadBytes,
      peakRssBytes: peakRssBytes,
      baselineRssBytes: baselineRssBytes,
      deltaBytes: delta,
    );
  }
}

/// Immutable result of applying a [MemoryBudget] to a measurement.
class BudgetVerdict {
  const BudgetVerdict({
    required this.ok,
    required this.amplificationFactor,
    required this.amplificationLimit,
    required this.absolutePeakFactor,
    required this.absoluteGateApplicable,
    required this.payloadBytes,
    required this.peakRssBytes,
    required this.baselineRssBytes,
    required this.deltaBytes,
  });

  /// Whether [amplificationFactor] is within [amplificationLimit].
  final bool ok;
  final double amplificationFactor;
  final double amplificationLimit;
  final double absolutePeakFactor;
  final bool absoluteGateApplicable;
  final int payloadBytes;
  final int peakRssBytes;
  final int baselineRssBytes;
  final int deltaBytes;

  String describe() {
    final status = ok ? 'PASS' : 'FAIL';
    final amp = amplificationFactor.toStringAsFixed(2);
    final limit = amplificationLimit.toStringAsFixed(2);
    final absolute = absoluteGateApplicable
        ? ', absolute ${absolutePeakFactor.toStringAsFixed(2)}x (gate active)'
        : ', absolute ${absolutePeakFactor.toStringAsFixed(2)}x (informational)';
    return '$status amplification ${amp}x / ${limit}x'
        ' (Δ ${formatMiB(deltaBytes)} over ${formatMiB(payloadBytes)})$absolute';
  }

  Map<String, Object?> toJson() => {
    'ok': ok,
    'amplificationFactor': amplificationFactor,
    'amplificationLimit': amplificationLimit,
    'absolutePeakFactor': absolutePeakFactor,
    'absoluteGateApplicable': absoluteGateApplicable,
    'payloadBytes': payloadBytes,
    'peakRssBytes': peakRssBytes,
    'baselineRssBytes': baselineRssBytes,
    'deltaBytes': deltaBytes,
  };
}

/// A single benchmarked operation (one encrypt or one decrypt), pairing the raw
/// [MeasuredRun] with its [BudgetVerdict] and operation metadata.
class BenchmarkResult {
  BenchmarkResult({
    required this.operation,
    required this.profileName,
    required this.signed,
    required this.payloadBytes,
    required this.run,
    required this.verdict,
    this.detail = const {},
  });

  /// `'encrypt'` or `'decrypt'`.
  final String operation;
  final String profileName;
  final bool signed;
  final int payloadBytes;
  final MeasuredRun run;
  final BudgetVerdict verdict;

  /// Operation-specific extras (inner crypto ms, envelope bytes, checksum, …).
  final Map<String, Object?> detail;

  /// Throughput over the end-to-end wall time, MiB/s.
  double get throughputMiBs {
    final seconds = run.wall.inMicroseconds / Duration.microsecondsPerSecond;
    if (seconds <= 0) return double.infinity;
    return bytesToMiB(payloadBytes) / seconds;
  }

  String get label =>
      '$profileName/${signed ? 'signed' : 'unsigned'}/$operation';

  Map<String, Object?> toJson() => {
    'operation': operation,
    'profile': profileName,
    'signed': signed,
    'payloadBytes': payloadBytes,
    'baselineRssBytes': run.baselineBytes,
    'peakRssBytes': run.peakBytes,
    'deltaBytes': run.deltaBytes,
    'maxRssEndBytes': run.maxRssEndBytes,
    'wallMillis': run.wall.inMilliseconds,
    'sampleCount': run.sampleCount,
    'throughputMiBs': throughputMiBs,
    'verdict': verdict.toJson(),
    'detail': detail,
  };
}

/// Collects [BenchmarkResult]s, renders a console table, and serializes a JSON
/// report that later phases diff against.
class BenchmarkReport {
  BenchmarkReport({Map<String, Object?>? environment})
    : environment = environment ?? captureEnvironment();

  final List<BenchmarkResult> results = [];
  final Map<String, Object?> environment;

  void add(BenchmarkResult result) => results.add(result);

  /// Snapshot of the host the numbers were recorded on (for honest comparison).
  static Map<String, Object?> captureEnvironment() => {
    'dartVersion': Platform.version,
    'os': Platform.operatingSystem,
    'osVersion': Platform.operatingSystemVersion,
    'numberOfProcessors': Platform.numberOfProcessors,
    'recordedAtUtc': DateTime.now().toUtc().toIso8601String(),
  };

  String table() {
    if (results.isEmpty) return '(no benchmark results recorded)';
    final rows = <List<String>>[
      [
        'profile',
        'signed',
        'op',
        'payload',
        'baseline',
        'peak',
        'Δ',
        'amp',
        'MiB/s',
        'wall',
        'gate',
      ],
    ];
    for (final r in results) {
      rows.add([
        r.profileName,
        r.signed ? 'yes' : 'no',
        r.operation,
        formatMiB(r.payloadBytes),
        formatMiB(r.run.baselineBytes),
        formatMiB(r.run.peakBytes),
        formatMiB(r.run.deltaBytes),
        '${r.verdict.amplificationFactor.toStringAsFixed(2)}x',
        r.throughputMiBs.toStringAsFixed(2),
        '${(r.run.wall.inMilliseconds / 1000).toStringAsFixed(1)}s',
        r.verdict.ok ? 'PASS' : 'FAIL',
      ]);
    }
    final widths = List<int>.generate(
      rows.first.length,
      (col) =>
          rows.map((row) => row[col].length).reduce((a, b) => a > b ? a : b),
    );
    final buffer = StringBuffer();
    for (var i = 0; i < rows.length; i++) {
      final row = rows[i];
      buffer.writeln(
        [
          for (var col = 0; col < row.length; col++)
            row[col].padRight(widths[col]),
        ].join('  '),
      );
      if (i == 0) {
        buffer.writeln(widths.map((w) => '-' * w).join('  '));
      }
    }
    return buffer.toString();
  }

  Map<String, Object?> toJson() => {
    'environment': environment,
    'results': [for (final r in results) r.toJson()],
  };

  File writeJson(String path) {
    final file = File(path);
    file.parent.createSync(recursive: true);
    file.writeAsStringSync(
      '${const JsonEncoder.withIndent('  ').convert(toJson())}\n',
    );
    return file;
  }
}
