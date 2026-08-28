/// Live progress reporting for folder operations.
library;

import 'console.dart';

/// A meticulous, high-performance progress reporter for folder operations
/// that features adaptive UI throttling, data throughput tracking, and verbosity states.
class ProgressReporter {
  ProgressReporter({
    required this.total,
    required this.operation, // e.g. 'encrypting', 'decrypting', 'packing'
    this.showPath = true,
    this.quiet = false,
  }) : _started = DateTime.now(),
       _lastUiUpdate = DateTime.now();

  final int total;
  final String operation;
  final bool showPath;
  final bool quiet;
  final DateTime _started;

  int _current = 0;
  int _successCount = 0;
  int _failCount = 0;
  int _totalBytesProcessed = 0;

  // High-precision frame throttling variables
  DateTime _lastUiUpdate;
  static const Duration _uiThrottleWindow = Duration(milliseconds: 100);

  // Critical failure tracking
  final List<String> _failedPaths = [];

  /// Called precisely when an isolate begins processing this specific file.
  /// Throttled to prevent UI frame-drops.
  void startFile(String path, {int? fileSizeBytes}) {
    _current++;
    if (fileSizeBytes != null) {
      _totalBytesProcessed += fileSizeBytes;
    }

    if (quiet) return;

    final now = DateTime.now();
    if (now.difference(_lastUiUpdate) >= _uiThrottleWindow ||
        _current == total) {
      _lastUiUpdate = now;
      final elapsed = now.difference(_started).inSeconds;
      final throughputStr = _calculateThroughput(elapsed);

      // Shows temporary live status while the file is actively processing
      final msg =
          '$operation [$_current/$total] $throughputStr ${showPath ? path : ''}...';
      console.progress(msg);
    }
  }

  /// Called when a file completes successfully. Commits a permanent newline to stdout.
  void completeFile(String path) {
    _successCount++;
    if (!quiet) {
      _printFileSummary('SUCCESS', path, isError: false);
    }
  }

  /// Called when a file fails to process. Commits a permanent newline to stdout.
  void failFile(String path, String reason) {
    _failCount++;
    _failedPaths.add('$path -> $reason');
    if (!quiet) {
      _printFileSummary('FAILED', path, isError: true);
    }
  }

  /// Helper to calculate stats and print line-by-line using your real console.info API
  void _printFileSummary(String status, String path, {required bool isError}) {
    final elapsed = DateTime.now().difference(_started).inSeconds;
    final rate = _current / (elapsed == 0 ? 1 : elapsed);
    final throughputStr = _calculateThroughput(elapsed);

    // Calculate real-time success percentage based on processed files
    final successRate = _current > 0 ? (_successCount / _current) * 100 : 0.0;

    // First clear the temporary carriage-return progress line
    console.progressDone();

    // Style the status tag using your custom Ansi utility layer
    final styledStatus = isError
        ? console.ansi.bold(console.ansi.brightRed(status))
        : console.ansi.green(status);

    // Use your console.info method to print a permanent newline
    console.info(
      '[$_current/$total] $styledStatus: ${showPath ? path : ''} '
      '($throughputStr${rate.toStringAsFixed(1)}/s, Success: ${successRate.toStringAsFixed(1)}%)',
    );
  }

  /// Called when all files are done. Clears the progress line and prints summary.
  void done() {
    final elapsed = DateTime.now().difference(_started).inSeconds;
    final rate = total / (elapsed == 0 ? 1 : elapsed);
    final finalSuccessRate = total > 0 ? (_successCount / total) * 100 : 0.0;
    final totalThroughputStr = _calculateThroughput(elapsed);

    console.progressDone(); //

    // Print core task completion block using your native styling configuration
    console.success(
      '$operation complete: $total file(s) processed in ${_formatDuration(elapsed)} '
      '($totalThroughputStr${rate.toStringAsFixed(1)}/s) | Successes: $_successCount | Failures: $_failCount | Success Rate: ${finalSuccessRate.toStringAsFixed(1)}%',
    );

    // If any files failed, render a separate error summary pane at the very bottom
    if (_failCount > 0) {
      console.section('Failed Operations Review Block');
      for (final fault in _failedPaths) {
        console.info('  ${console.ansi.brightRed('✗')} $fault');
      }
    }
  }

  String _calculateThroughput(int elapsedSeconds) {
    if (_totalBytesProcessed == 0) return '';
    final seconds = elapsedSeconds == 0 ? 1 : elapsedSeconds;
    final mbPerSecond = (_totalBytesProcessed / (1024 * 1024)) / seconds;
    return '${mbPerSecond.toStringAsFixed(1)} MB/s, ';
  }

  String _formatDuration(int seconds) {
    if (seconds < 60) return '${seconds}s';
    final m = seconds ~/ 60;
    final s = seconds % 60;
    return '${m}m ${s}s';
  }
}
