/// Inline XEdDSA batch. Used when `dart:isolate` is absent (dart2wasm).
library;

/// Runs [jobs] on this isolate, in order.
Future<List<T>> runJobs<T>(List<T Function()> jobs) async {
  return [for (final job in jobs) job()];
}
