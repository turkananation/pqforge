import 'dart:io';

import 'package:test/test.dart';

// The generated CLI version constant. Single-sourced from pubspec.yaml by
// tool/version/generate_version.dart.
import '../bin/src/version.g.dart';

void main() {
  test(
    'CLI version tracks pubspec.yaml (run generate_version if this fails)',
    () {
      final pubspecVersion = RegExp(
        r'^version:\s*(\S+)',
        multiLine: true,
      ).firstMatch(File('pubspec.yaml').readAsStringSync())?.group(1);

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
