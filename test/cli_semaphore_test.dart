import 'dart:async';

import 'package:test/test.dart';

import '../bin/src/support.dart';

/// Phase 5: the bounded concurrency primitive behind the per-file folder isolate
/// pool. It must never let more than its permit count run at once, and must let
/// every queued task through.
void main() {
  test('never exceeds the permit count and drains every task', () async {
    const permits = 3;
    const tasks = 30;
    final pool = Semaphore(permits);
    var running = 0;
    var peak = 0;
    var completed = 0;

    await Future.wait(
      List.generate(tasks, (_) async {
        await pool.acquire();
        try {
          running++;
          if (running > peak) peak = running;
          // Yield across the event loop so overlaps are real, not illusory.
          await Future<void>.delayed(const Duration(milliseconds: 1));
          running--;
          completed++;
        } finally {
          pool.release();
        }
      }),
    );

    expect(peak, lessThanOrEqualTo(permits));
    expect(peak, greaterThan(1), reason: 'tasks should actually overlap');
    expect(completed, tasks);
  });

  test('a single permit serializes tasks', () async {
    final pool = Semaphore(1);
    var running = 0;
    var peak = 0;
    await Future.wait(
      List.generate(8, (_) async {
        await pool.acquire();
        try {
          running++;
          if (running > peak) peak = running;
          await Future<void>.delayed(const Duration(milliseconds: 1));
          running--;
        } finally {
          pool.release();
        }
      }),
    );
    expect(peak, 1);
  });
}
