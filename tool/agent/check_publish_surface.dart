/// Validates that the pub.dev archive contains only the consumable package.
library;

import 'dart:convert';
import 'dart:io';

const _allowedTopLevel = <String>[
  'CHANGELOG.md',
  'LICENSE',
  'README.md',
  'bin',
  'example',
  'lib',
  'pubspec.yaml',
];

Future<void> main(List<String> args) async {
  final strict = args.contains('--strict');
  final command = <String>[
    'pub',
    'publish',
    '--dry-run',
    if (!strict) '--ignore-warnings',
  ];
  final process = await Process.start('dart', command);
  final stdoutText = await utf8.decodeStream(process.stdout);
  final stderrText = await utf8.decodeStream(process.stderr);
  final code = await process.exitCode;
  final output = '$stdoutText$stderrText';

  if (code != 0) {
    stderr.write(output);
    exitCode = code;
    return;
  }

  final archive = _archiveSection(output);
  final present = _topLevelEntries(archive);
  final unexpected = present
      .where((path) => !_allowedTopLevel.contains(path))
      .toList();
  final missing = _allowedTopLevel
      .where((path) => !present.contains(path))
      .toList();

  if (unexpected.isNotEmpty || missing.isNotEmpty) {
    if (unexpected.isNotEmpty) {
      stderr.writeln(
        'Unexpected pub.dev archive entries: ${unexpected.join(', ')}',
      );
    }
    if (missing.isNotEmpty) {
      stderr.writeln('Missing required archive entries: ${missing.join(', ')}');
    }
    stderr.writeln();
    stderr.write(archive);
    exitCode = 1;
    return;
  }

  final size = RegExp(
    r'Total compressed archive size:\s*([^\r\n]+)',
  ).firstMatch(output)?.group(1)?.trim().replaceFirst(RegExp(r'\.$'), '');
  stdout.writeln(
    'Pub archive surface is valid'
    '${size == null ? '' : ' (compressed: $size)'}.',
  );
}

String _archiveSection(String output) {
  final start = output.indexOf('Publishing ');
  final end = output.indexOf('Total compressed archive size:');
  if (start < 0 || end < 0 || end <= start) {
    throw StateError('Could not locate the package file list in pub output.');
  }
  return output.substring(start, end);
}

Set<String> _topLevelEntries(String archive) {
  final entries = <String>{};
  final linePattern = RegExp(r'^[├└]── ([^ \r\n]+)', multiLine: true);
  for (final match in linePattern.allMatches(archive)) {
    entries.add(match.group(1)!);
  }
  return entries;
}
