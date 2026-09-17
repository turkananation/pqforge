/// Live progress reporting for CLI file operations.
library;

import 'console.dart';

/// Throttled progress line plus per-item SUCCESS/FAILED summaries.
///
/// Safe to call from the main isolate while work runs on background isolates:
/// every method is synchronous, so concurrent folder tasks cannot tear counters.
/// [completeFile] / [failFile] report *finished* items, not started ones, so
/// overlapping jobs never print `[8/10]` for the first file that happened to
/// finish after eight others had already started.
///
/// Throughput uses *finished* bytes plus in-flight [updateBytes] counts,
/// never the sum of files that have only started. Concurrent folder jobs
/// therefore cannot report 80 MB/s after the first of eight 10 MB files
/// completes. Byte updates are keyed by path so parallel isolates cannot
/// overwrite each other's live totals.
class ProgressReporter {
  ProgressReporter({
    required this.total,
    required this.operation,
    this.showPath = true,
    this.quiet = false,
  }) : _started = DateTime.now(),
       _lastUiUpdate = DateTime.now();

  /// Known item count. `0` means unknown (display `[n]` without a denominator).
  final int total;
  final String operation;
  final bool showPath;
  final bool quiet;
  final DateTime _started;

  int _startedCount = 0;
  int _successCount = 0;
  int _failCount = 0;
  int _finishedBytes = 0;
  String? _lastPath;
  final Map<String, int> _fileBytes = {};
  final Map<String, int> _liveByPath = {};

  DateTime _lastUiUpdate;
  static const Duration _uiThrottleWindow = Duration(milliseconds: 100);

  final List<String> _failedPaths = [];

  int get successCount => _successCount;
  int get failCount => _failCount;
  int get finishedCount => _successCount + _failCount;
  bool get hasFailures => _failCount > 0;
  int get inFlightCount => _startedCount - finishedCount;

  int get _liveBytes {
    var sum = 0;
    for (final n in _liveByPath.values) {
      sum += n;
    }
    return sum;
  }

  int get _knownRemainingBytes {
    var sum = 0;
    for (final n in _fileBytes.values) {
      sum += n;
    }
    return sum;
  }

  int get _throughputBytes => _finishedBytes + _liveBytes;

  /// Called when an item begins. Throttled on the live CR line.
  void startFile(String path, {int? fileSizeBytes}) {
    _startedCount++;
    _lastPath = path;
    _liveByPath[path] = 0;
    if (fileSizeBytes != null && fileSizeBytes > 0) {
      _fileBytes[path] = fileSizeBytes;
    }
    if (quiet) return;

    final now = DateTime.now();
    if (now.difference(_lastUiUpdate) >= _uiThrottleWindow || _isLastStart) {
      _lastUiUpdate = now;
      final throughputStr = _calculateThroughput(
        now.difference(_started).inSeconds,
      );
      final label = showPath ? path : '';
      console.progress(
        '$operation [${_ratio(_startedCount)}] $throughputStr$label...',
      );
    }
  }

  /// Byte-level update for a streaming single-file (or current-entry) job.
  /// Throttled. Does not change item counts. [path] keys the update so
  /// concurrent folder isolates cannot clobber each other; omitted [path]
  /// uses the most recently started item.
  void updateBytes({String? path, required int processed, int? totalBytes}) {
    final key = path ?? _lastPath;
    if (key == null || !_liveByPath.containsKey(key)) {
      return;
    }
    _liveByPath[key] = processed < 0 ? 0 : processed;
    if (totalBytes != null && totalBytes > 0) {
      _fileBytes.putIfAbsent(key, () => totalBytes);
    }
    if (quiet) return;
    final now = DateTime.now();
    final isLast =
        totalBytes != null && totalBytes > 0 && processed >= totalBytes;
    if (!isLast && now.difference(_lastUiUpdate) < _uiThrottleWindow) {
      return;
    }
    _lastUiUpdate = now;
    final elapsed = now.difference(_started).inSeconds;
    final throughput = _calculateThroughput(elapsed);
    final throughputBody = throughput.isEmpty
        ? ''
        : ' (${throughput.replaceAll(', ', '').trim()})';
    if (inFlightCount > 1) {
      final processedAll = _throughputBytes;
      final totalAll = _finishedBytes + _knownRemainingBytes;
      final totalStr = totalAll <= 0 ? '' : '/${_formatMegabytes(totalAll)}';
      console.progress(
        '$operation [${_ratio(_startedCount)}] '
        '${_formatMegabytes(processedAll)}$totalStr$throughputBody...',
      );
      return;
    }
    final processedStr = _formatMegabytes(processed);
    final totalStr = totalBytes == null || totalBytes <= 0
        ? ''
        : '/${_formatMegabytes(totalBytes)}';
    console.progress('$operation $processedStr$totalStr$throughputBody...');
  }

  /// Called when an item completes successfully. Permanent stdout line.
  void completeFile(String path) {
    _successCount++;
    _accountBytes(path);
    if (!quiet) {
      _printFileSummary('SUCCESS', path, isError: false);
    }
  }

  /// Called when an item fails. Permanent stdout line; [done] restates the set.
  void failFile(String path, String reason) {
    _failCount++;
    _accountBytes(path);
    _failedPaths.add('$path -> $reason');
    if (!quiet) {
      _printFileSummary('FAILED', path, isError: true);
    }
  }

  /// Job-level failure when no item is in flight (e.g. KEM failed before the
  /// first pack entry). No per-file line; [done] still reports a failure.
  void failJob(String reason) {
    _failCount++;
    _failedPaths.add(reason);
  }

  void _accountBytes(String path) {
    _finishedBytes += _fileBytes.remove(path) ?? _liveByPath[path] ?? 0;
    _liveByPath.remove(path);
    if (_lastPath == path) _lastPath = null;
  }

  void _printFileSummary(String status, String path, {required bool isError}) {
    final elapsed = DateTime.now().difference(_started).inSeconds;
    final finished = finishedCount;
    final rate = finished / (elapsed == 0 ? 1 : elapsed);
    final throughputStr = _calculateThroughput(elapsed);
    final successRate = finished > 0 ? (_successCount / finished) * 100 : 0.0;

    console.progressDone();

    final styledStatus = isError
        ? console.ansi.bold(console.ansi.brightRed(status))
        : console.ansi.green(status);

    console.info(
      '[${_ratio(finished)}] $styledStatus: ${showPath ? path : ''} '
      '($throughputStr${rate.toStringAsFixed(1)}/s, '
      'Success: ${successRate.toStringAsFixed(1)}%)',
    );
  }

  /// Clears the live line and prints the completion summary. Always prints,
  /// even under [quiet], so CI logs still show the outcome.
  void done() {
    final elapsed = DateTime.now().difference(_started).inSeconds;
    final counted = total > 0 ? total : finishedCount;
    final rate = counted / (elapsed == 0 ? 1 : elapsed);
    final finalSuccessRate = counted > 0
        ? (_successCount / counted) * 100
        : 0.0;
    final totalThroughputStr = _calculateThroughput(elapsed);

    console.progressDone();

    final summary =
        '$operation complete: $counted file(s) processed in '
        '${_formatDuration(elapsed)} '
        '($totalThroughputStr${rate.toStringAsFixed(1)}/s) | '
        'Successes: $_successCount | Failures: $_failCount | '
        'Success Rate: ${finalSuccessRate.toStringAsFixed(1)}%';
    if (_failCount > 0) {
      console.failure(summary);
    } else {
      console.success(summary);
    }

    if (_failCount > 0) {
      console.section('Failed operations');
      for (final fault in _failedPaths) {
        console.info('  ${console.ansi.brightRed('✗')} $fault');
      }
    }
  }

  bool get _isLastStart => total > 0 && _startedCount >= total;

  String _ratio(int n) => total > 0 ? '$n/$total' : '$n';

  String _calculateThroughput(int elapsedSeconds) {
    if (_throughputBytes == 0) return '';
    final seconds = elapsedSeconds == 0 ? 1 : elapsedSeconds;
    final mbPerSecond = (_throughputBytes / (1024 * 1024)) / seconds;
    return '${mbPerSecond.toStringAsFixed(1)} MB/s, ';
  }

  String _formatMegabytes(int bytes) {
    final mb = bytes / (1024 * 1024);
    if (mb >= 10) return '${mb.toStringAsFixed(1)} MB';
    if (bytes >= 1024) return '${(bytes / 1024).toStringAsFixed(1)} KB';
    return '$bytes B';
  }

  String _formatDuration(int seconds) {
    if (seconds < 60) return '${seconds}s';
    final m = seconds ~/ 60;
    final s = seconds % 60;
    return '${m}m ${s}s';
  }
}

/// Single-item progress wrapper used by encrypt/decrypt/sign and peers.
Future<T> withFileProgress<T>({
  required bool quiet,
  required String operation,
  required String path,
  required int bytes,
  required Future<T> Function(ProgressReporter progress) action,
}) async {
  final progress = ProgressReporter(
    total: 1,
    operation: operation,
    quiet: quiet,
  );
  try {
    progress.startFile(path, fileSizeBytes: bytes);
    final result = await action(progress);
    progress.completeFile(path);
    return result;
  } catch (error) {
    progress.failFile(path, error.toString());
    rethrow;
  } finally {
    progress.done();
  }
}
