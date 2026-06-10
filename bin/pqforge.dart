/// pqforge — a post-quantum encryption and signing CLI.
///
/// Entry point and command wiring. Presentation lives in `src/console.dart`,
/// shared helpers in `src/support.dart`, and the commands in
/// `src/pqc_commands.dart` and `src/hybrid_commands.dart`.
library;

import 'dart:io';

import 'package:args/args.dart';
import 'package:args/command_runner.dart';
import 'package:pqforge/pqforge.dart';

import 'src/console.dart';
import 'src/hybrid_commands.dart';
import 'src/pqc_commands.dart';

const _description =
    'Post-quantum encryption and signatures for files, folders, text, media, '
    'documents, and hybrid PQC + classical workflows.';

/// Display order and grouping for the styled top-level help.
const Map<String, List<String>> _groups = {
  'Keys': ['keygen'],
  'Encrypt / decrypt': [
    'encrypt',
    'decrypt',
    'encrypt-folder',
    'decrypt-folder',
    'encrypt-text',
    'decrypt-text',
    'encrypt-media',
    'decrypt-media',
  ],
  'Folder archive (pack)': ['pack', 'unpack'],
  'Sign / verify · post-quantum': ['sign', 'verify'],
  'Hybrid & classical': [
    'hybrid-sign',
    'hybrid-verify',
    'ecdsa-sign',
    'ecdsa-verify',
  ],
};

Future<void> main(List<String> args) async {
  // Resolve color before anything is rendered so the banner, usage, and errors
  // are styled consistently (and stay plain when piped or NO_COLOR is set).
  Console.configure(color: resolveColor(args));
  final runner = PqForgeRunner();

  // Bare invocation is a friendly help screen, not an error.
  if (args.isEmpty) {
    runner.printUsage();
    return;
  }

  try {
    await runner.run(args);
  } on UsageException catch (error) {
    console.failure(error.message);
    stderr.writeln();
    stderr.writeln(error.usage);
    exitCode = 64; // EX_USAGE
  } on PqForgeException catch (error) {
    console.failure(error.message);
    exitCode = 70; // EX_SOFTWARE
  } on FormatException catch (error) {
    console.failure('Malformed input: ${error.message}');
    exitCode = 65; // EX_DATAERR
  } on FileSystemException catch (error) {
    final path = error.path == null ? '' : ' (${error.path})';
    console.failure('${error.message}$path');
    exitCode = 66; // EX_NOINPUT
  } on ArgumentError catch (error) {
    // package:args surfaces missing mandatory options as ArgumentError, and the
    // library raises them for malformed key/byte lengths. Both are user input.
    final name = error.name;
    console.failure(
      name == null ? '${error.message}' : '$name: ${error.message}',
    );
    exitCode = 64; // EX_USAGE
  } on Object catch (error) {
    console.failure('$error');
    exitCode = 70;
  }
}

/// A [CommandRunner] with a styled, grouped help screen, a `--version` flag,
/// and a `--no-color` toggle.
final class PqForgeRunner extends CommandRunner<void> {
  PqForgeRunner() : super('pqforge', _description) {
    argParser
      ..addFlag(
        'version',
        negatable: false,
        help: 'Print the pqforge version and exit.',
      )
      ..addFlag(
        'color',
        defaultsTo: true,
        help:
            'Use ANSI colors (use --no-color to disable; auto-off when piped).',
      );
    addCommand(KeygenCommand());
    addCommand(EncryptCommand());
    addCommand(DecryptCommand());
    addCommand(EncryptFolderCommand());
    addCommand(DecryptFolderCommand());
    addCommand(EncryptTextCommand());
    addCommand(DecryptTextCommand());
    addCommand(EncryptMediaCommand());
    addCommand(DecryptMediaCommand());
    addCommand(PackCommand());
    addCommand(UnpackCommand());
    addCommand(SignCommand());
    addCommand(VerifyCommand());
    addCommand(HybridSignCommand());
    addCommand(HybridVerifyCommand());
    addCommand(EcdsaSignCommand());
    addCommand(EcdsaVerifyCommand());
  }

  @override
  Future<void> runCommand(ArgResults topLevelResults) async {
    if (topLevelResults['version'] as bool) {
      console.info('pqforge $pqforgeCliVersion');
      return;
    }
    return super.runCommand(topLevelResults);
  }

  @override
  String get usage {
    final ansi = console.ansi;
    final buffer = StringBuffer()
      ..writeln(console.banner())
      ..writeln();
    for (final line in _wrap(_description, 76)) {
      buffer.writeln('  $line');
    }
    buffer
      ..writeln()
      ..writeln(
        '  ${ansi.bold('Usage:')} ${ansi.cyan('pqforge')} '
        '<command> [options]',
      )
      ..writeln(
        '         ${ansi.cyan('pqforge')} help <command>'
        '   ${ansi.dim('full help for a command')}',
      );

    final column = _nameColumn();
    final shown = <String>{};
    for (final group in _groups.entries) {
      final names = group.value.where(_isVisible).toList();
      if (names.isEmpty) continue;
      buffer
        ..writeln()
        ..writeln('  ${ansi.bold(group.key)}');
      for (final name in names) {
        shown.add(name);
        _writeCommandRow(buffer, ansi, name, column);
      }
    }
    final rest = commands.keys
        .where((name) => !shown.contains(name) && _isVisible(name))
        .toList();
    if (rest.isNotEmpty) {
      buffer
        ..writeln()
        ..writeln('  ${ansi.bold('More')}');
      for (final name in rest) {
        _writeCommandRow(buffer, ansi, name, column);
      }
    }

    buffer
      ..writeln()
      ..writeln('  ${ansi.bold('Global options')}')
      ..writeln(_indent(argParser.usage, 4))
      ..write(usageFooter);
    return buffer.toString();
  }

  @override
  String get usageFooter {
    final ansi = console.ansi;
    return [
      '',
      '  ${ansi.bold('Examples')}',
      '  ${ansi.gray('# Generate a wrapped key bundle, then encrypt a file')}',
      '  pqforge keygen --key-id vault --out-dir keys '
          '--passphrase-env PQFORGE_PASSPHRASE',
      '  pqforge encrypt --recipient-public keys/vault.kem.public.json '
          '--in f --out f.pqf',
      '',
      '  ${ansi.dim('Legend')}  🛡️  ML-KEM/ML-DSA · PQC   '
          '🤝 X25519/Ed25519   🔒 AES-GCM/ECDSA-P256',
      '  ${ansi.dim('Docs')}    https://github.com/turkananation/pqforge'
          '  ·  doc/CLI.md',
      '',
    ].join('\n');
  }

  bool _isVisible(String name) {
    final command = commands[name];
    return command != null && !command.hidden;
  }

  int _nameColumn() => commands.keys
      .where(_isVisible)
      .map((name) => name.length)
      .fold(0, (max, length) => length > max ? length : max);

  void _writeCommandRow(
    StringBuffer buffer,
    Ansi ansi,
    String name,
    int column,
  ) {
    final label = ansi.cyan(name.padRight(column));
    buffer.writeln('    $label  ${commands[name]!.summary}');
  }
}

/// Greedy word wrap to [width] columns.
List<String> _wrap(String text, int width) {
  final words = text.split(' ');
  final lines = <String>[];
  var current = StringBuffer();
  for (final word in words) {
    if (current.isEmpty) {
      current.write(word);
    } else if (current.length + 1 + word.length <= width) {
      current.write(' $word');
    } else {
      lines.add(current.toString());
      current = StringBuffer(word);
    }
  }
  if (current.isNotEmpty) lines.add(current.toString());
  return lines;
}

String _indent(String text, int spaces) {
  final pad = ' ' * spaces;
  return text
      .split('\n')
      .map((line) => line.isEmpty ? line : '$pad$line')
      .join('\n');
}
