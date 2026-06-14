import 'dart:io';

import 'package:test/test.dart';

// The generated CLI version constant. Single-sourced from pubspec.yaml by
// tool/version/generate_version.dart.
import '../bin/src/version.g.dart';

void main() {
  test(
    'CLI version tracks pubspec.yaml (run generate_version if this fails)',
    () {
      final pubspecVersion = File('pubspec.yaml')
          .readAsLinesSync()
          .map(
            (line) => RegExp(r'^version:\s*(\S+)').firstMatch(line)?.group(1),
          )
          .firstWhere((value) => value != null, orElse: () => null);

      expect(pubspecVersion, isNotNull, reason: 'pubspec.yaml has no version.');
      expect(
        pqforgeCliVersion,
        pubspecVersion,
        reason:
            'pqforgeCliVersion must equal the pubspec version. '
            'Run `dart run tool/version/generate_version.dart`.',
      );
    },
  );
}
