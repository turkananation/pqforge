/// XEdDSA batch on isolates. One signature stays on the caller. A longer
/// batch uses at most four [Isolate.run] calls at a time.
///
/// `Z` is drawn by the caller, so a custom random generator is the one
/// that runs. The worker receives only sendable byte lists.
library;

import 'dart:isolate';

/// Runs [jobs]. Closures may capture [Uint8List] values and nothing else.
Future<List<T>> runJobs<T>(List<T Function()> jobs) async {
  if (jobs.length <= 1) {
    return [for (final job in jobs) job()];
  }
  const width = 4;
  final out = List<T?>.filled(jobs.length, null);
  var next = 0;
  Future<void> worker() async {
    while (true) {
      final index = next;
      if (index >= jobs.length) return;
      next = index + 1;
      out[index] = await Isolate.run(jobs[index]);
    }
  }

  final workers = jobs.length < width ? jobs.length : width;
  await Future.wait<void>([for (var i = 0; i < workers; i++) worker()]);
  return [for (final value in out) value as T];
}
