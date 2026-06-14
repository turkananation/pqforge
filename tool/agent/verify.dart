/// Runs pqforge's repeatable local verification profiles.
library;

import 'dart:io';

const _usage = '''
Usage: dart run tool/agent/verify.dart <quick|docs|full|release>

  quick    generated files, package boundaries, formatting, and analysis
  docs     generated files and local Markdown links
  full     quick + links + tests + runnable examples
  release  full + strict pub.dev archive validation
''';

Future<void> main(List<String> args) async {
  final mode = args.isEmpty ? 'quick' : args.single;
  if (!const {'quick', 'docs', 'full', 'release'}.contains(mode)) {
    stderr.write(_usage);
    exitCode = 64;
    return;
  }

  await _run('CLI version', [
    'dart',
    'run',
    'tool/version/generate_version.dart',
    '--check',
  ]);
  await _run('visibility outputs', [
    'dart',
    'run',
    'tool/visibility/generate_visibility.dart',
    '--check',
  ]);
  await _run('package boundaries', [
    'dart',
    'run',
    'tool/agent/check_package_boundaries.dart',
  ]);

  if (mode == 'docs') {
    await _run('Markdown links', [
      'dart',
      'run',
      'tool/agent/check_links.dart',
    ]);
    return;
  }

  await _run('formatting', [
    'dart',
    'format',
    '--output=none',
    '--set-exit-if-changed',
    '.',
  ]);
  await _run('static analysis', ['dart', 'analyze']);

  if (mode == 'quick') return;

  await _run('Markdown links', ['dart', 'run', 'tool/agent/check_links.dart']);
  await _run('test suite', ['dart', 'test']);
  await _runExamples();

  if (mode == 'release') {
    await _run('pub.dev archive', [
      'dart',
      'run',
      'tool/agent/check_publish_surface.dart',
      '--strict',
    ]);
  }
}

Future<void> _runExamples() async {
  final temp = Directory.systemTemp.createTempSync('pqforge-verify-');
  try {
    final input = File(_join(temp.path, 'input.txt'))
      ..writeAsStringSync('pqforge file example\n');
    await _run('example: pqforge', [
      'dart',
      'run',
      'example/pqforge_example.dart',
    ]);
    await _run('example: file encryption', [
      'dart',
      'run',
      'example/file_encryption_example.dart',
      input.path,
      _join(temp.path, 'output.pqf'),
      _join(temp.path, 'wrapped-key.json'),
    ]);
    for (final name in const [
      'hybrid_combiner_example.dart',
      'secure_session_example.dart',
      'hybrid_key_agreement_example.dart',
      'catalog_recipes_example.dart',
    ]) {
      await _run('example: $name', ['dart', 'run', 'example/$name']);
    }
  } finally {
    if (temp.existsSync()) temp.deleteSync(recursive: true);
  }
}

Future<void> _run(String label, List<String> command) async {
  stdout.writeln('\n==> $label');
  final process = await Process.start(
    command.first,
    command.sublist(1),
    mode: ProcessStartMode.inheritStdio,
  );
  final code = await process.exitCode;
  if (code != 0) {
    throw ProcessException(command.first, command.sublist(1), label, code);
  }
}

String _join(String left, String right) =>
    '$left${Platform.pathSeparator}$right';
