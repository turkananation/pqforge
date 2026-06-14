/// Enforces the published package's web-safe core and FFI boundaries.
library;

import 'dart:io';

final _directive = RegExp(
  r'''^\s*(?:import|export)\s+['"]([^'"]+)['"]''',
  multiLine: true,
);

void main() {
  final violations = <String>[];
  final visited = <String>{};
  final pending = <String>['lib/pqforge.dart'];

  while (pending.isNotEmpty) {
    final path = _normalize(pending.removeLast());
    if (!visited.add(path)) continue;

    final file = File(path);
    if (!file.existsSync()) {
      violations.add('Missing local import/export target: $path');
      continue;
    }

    for (final match in _directive.allMatches(file.readAsStringSync())) {
      final uri = match.group(1)!;
      if (uri == 'dart:io' || uri == 'dart:ffi') {
        violations.add('$path imports $uri through the web-safe core graph.');
      } else if (uri.startsWith('package:pqforge/')) {
        // A self-import (`package:pqforge/src/...`) still lives in lib/; resolve
        // it so the traversal follows it instead of skipping it as external.
        pending.add(_join('lib', uri.substring('package:pqforge/'.length)));
      } else if (!uri.contains(':')) {
        pending.add(_join(file.parent.path, uri));
      }
    }
  }

  for (final file in _dartFiles(Directory('.'))) {
    final path = _normalize(file.path);
    if (path.startsWith('tool/openssl_interop/')) continue;
    if (RegExp(
      r'''^\s*import\s+['"]dart:ffi['"]''',
      multiLine: true,
    ).hasMatch(file.readAsStringSync())) {
      violations.add('$path imports dart:ffi outside tool/openssl_interop/.');
    }
  }

  if (violations.isNotEmpty) {
    for (final violation in violations) {
      stderr.writeln('BOUNDARY $violation');
    }
    exitCode = 1;
    return;
  }

  stdout.writeln(
    'Package boundaries are valid '
    '(${visited.length} web-safe core files checked).',
  );
}

Iterable<File> _dartFiles(Directory root) sync* {
  for (final entity in root.listSync(recursive: true, followLinks: false)) {
    if (entity is! File || !entity.path.endsWith('.dart')) continue;
    final path = _normalize(entity.path);
    if (path.startsWith('.dart_tool/') || path.startsWith('doc/api/')) continue;
    yield entity;
  }
}

String _join(String left, String right) =>
    '$left${Platform.pathSeparator}$right';

String _normalize(String path) {
  final parts = <String>[];
  for (final part in path.replaceAll('\\', '/').split('/')) {
    if (part.isEmpty || part == '.') continue;
    if (part == '..') {
      if (parts.isNotEmpty) parts.removeLast();
    } else {
      parts.add(part);
    }
  }
  return parts.join('/');
}
