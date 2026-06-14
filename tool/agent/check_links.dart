/// Checks repository-maintained Markdown links without external network access.
library;

import 'dart:io';

final _markdownLink = RegExp(r'!?\[[^\]]*\]\(([^)]+)\)');

void main() {
  final files = <File>[
    for (final path in const [
      'README.md',
      'CHANGELOG.md',
      'CLAUDE.md',
      'AGENTS.md',
    ])
      if (File(path).existsSync()) File(path),
    ..._markdownFiles(Directory('doc')),
    ..._markdownFiles(Directory('wiki')),
  ];

  var broken = 0;
  for (final file in files) {
    final base = file.parent;
    final content = file.readAsStringSync();
    for (final match in _markdownLink.allMatches(content)) {
      final raw = match.group(1)!.trim();
      final target = _linkTarget(raw);
      if (target == null) continue;

      final decoded = Uri.decodeComponent(target);
      final candidate = File(_join(base.path, decoded));
      if (candidate.existsSync() || Directory(candidate.path).existsSync()) {
        continue;
      }

      // GitHub Wiki links commonly omit the .md suffix.
      if (_isInside(file, 'wiki') &&
          File('${candidate.path}.md').existsSync()) {
        continue;
      }

      stderr.writeln('BROKEN ${file.path} -> $raw');
      broken++;
    }
  }

  if (broken != 0) {
    stderr.writeln('Found $broken broken local Markdown link(s).');
    exitCode = 1;
    return;
  }
  stdout.writeln('Markdown links are valid (${files.length} files).');
}

Iterable<File> _markdownFiles(Directory root) sync* {
  if (!root.existsSync()) return;
  for (final entity in root.listSync(recursive: true, followLinks: false)) {
    if (entity is! File || !entity.path.endsWith('.md')) continue;
    if (entity.path.startsWith(_join('doc', 'api'))) continue;
    yield entity;
  }
}

String? _linkTarget(String raw) {
  var value = raw;
  if (value.startsWith('<') && value.endsWith('>')) {
    value = value.substring(1, value.length - 1);
  }
  final titleStart = value.indexOf(RegExp(r'''\s+["']'''));
  if (titleStart >= 0) value = value.substring(0, titleStart);
  if (value.isEmpty ||
      value.startsWith('#') ||
      value.startsWith('/') ||
      value.startsWith('http://') ||
      value.startsWith('https://') ||
      value.startsWith('mailto:') ||
      value.startsWith('data:')) {
    return null;
  }
  return value.split('#').first.split('?').first;
}

bool _isInside(File file, String directory) {
  final prefix = '$directory${Platform.pathSeparator}';
  return file.path == directory || file.path.startsWith(prefix);
}

String _join(String left, String right) {
  if (left == '.') return right;
  return '$left${Platform.pathSeparator}$right';
}
