/// Lifecycle commands: `version` (print the version) and `uninstall` (remove a
/// global install). Both are presentation-light wrappers; the version value is
/// single-sourced from pubspec.yaml via the generated `version.g.dart`.
library;

import 'dart:io';

import 'package:args/command_runner.dart';

import 'console.dart';

/// `pqforge version` — the subcommand form of the top-level `--version` flag,
/// for users who reach for `pqforge version` out of habit.
class VersionCommand extends Command<void> {
  @override
  String get name => 'version';

  @override
  String get description => 'Print the pqforge version and exit.';

  @override
  Future<void> run() async => console.info('pqforge $pqforgeCliVersion');
}

/// `pqforge uninstall` — one command to remove pqforge however it was installed.
///
/// A global pub install (`dart pub global activate pqforge`, or
/// `--source path`) is removed with `dart pub global deactivate pqforge`, which
/// this command runs for you. A downloaded standalone binary is removed by
/// deleting the executable, whose path is printed.
class UninstallCommand extends Command<void> {
  UninstallCommand() {
    argParser
      ..addFlag(
        'dry-run',
        negatable: false,
        help: 'Show what would happen without changing anything.',
      )
      ..addFlag(
        'yes',
        abbr: 'y',
        negatable: false,
        help: 'Skip the confirmation prompt.',
      );
  }

  @override
  String get name => 'uninstall';

  @override
  String get description => 'Remove pqforge (global pub install or binary).';

  @override
  String get usageFooter => usageExamples([
    '# Show how to uninstall, change nothing',
    'pqforge uninstall --dry-run',
    '# Remove a global pub install without prompting',
    'pqforge uninstall --yes',
  ]);

  @override
  Future<void> run() async {
    final dryRun = argResults!['dry-run'] as bool;
    final assumeYes = argResults!['yes'] as bool;

    console.section('Uninstall pqforge');

    if (!_runningUnderDartVm) {
      // A compiled standalone binary: pub deactivate does not apply.
      console.info('This is a standalone binary. Delete it to uninstall:');
      console.detail('remove', Platform.resolvedExecutable, pad: 8);
      console.hint(
        'If you also installed it with pub, run: '
        'dart pub global deactivate pqforge',
      );
      return;
    }

    console.detail('command', 'dart pub global deactivate pqforge', pad: 8);

    if (dryRun) {
      console.hint('Dry run — nothing was changed.');
      return;
    }

    if (!assumeYes &&
        !_confirm('Run "dart pub global deactivate pqforge" now?')) {
      console.info('Aborted. Nothing was changed.');
      return;
    }

    final result = await Process.run(Platform.resolvedExecutable, const [
      'pub',
      'global',
      'deactivate',
      'pqforge',
    ]);
    final out = (result.stdout as String).trimRight();
    if (out.isNotEmpty) console.info(out);

    if (result.exitCode == 0) {
      console.success('pqforge has been uninstalled.');
    } else {
      console.warn(
        'pub could not deactivate pqforge (exit ${result.exitCode}); it may '
        'not be installed as a global pub package.',
      );
      final err = (result.stderr as String).trim();
      if (err.isNotEmpty) console.info(err);
      console.hint(
        'If you installed a downloaded binary, delete it from your PATH '
        'instead.',
      );
    }
  }

  /// True when the process runs under the Dart VM (`dart run` or a pub global
  /// snapshot), where `dart pub global deactivate` is meaningful. False for an
  /// AOT-compiled standalone binary.
  bool get _runningUnderDartVm {
    final exe = Platform.resolvedExecutable;
    final sep = Platform.pathSeparator;
    final base = exe.contains(sep)
        ? exe.substring(exe.lastIndexOf(sep) + 1)
        : exe;
    final name = base.toLowerCase();
    return name == 'dart' || name == 'dart.exe';
  }

  bool _confirm(String prompt) {
    // No terminal (CI, pipes, scripts): never block on input — abort safely.
    // Callers that want to proceed unattended pass --yes.
    if (!stdin.hasTerminal) return false;
    stdout.write('$prompt [y/N] ');
    final answer = stdin.readLineSync()?.trim().toLowerCase();
    return answer == 'y' || answer == 'yes';
  }
}
