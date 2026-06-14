/// Presentation layer for the pqforge CLI: ANSI styling, terminal detection,
/// the ASCII wordmark banner, and styled status writers.
///
/// Dependency-free on purpose — a cryptography package should not pull in a
/// terminal-styling dependency for ~200 lines of escape codes. Color is opt-out
/// (`--no-color` / `NO_COLOR`) and auto-disables when stdout is not a terminal,
/// so piped output stays clean and machine-readable.
library;

import 'dart:io';

import 'version.g.dart';

// Re-exported so any file importing console.dart sees the generated
// `pqforgeCliVersion`, which is single-sourced from pubspec.yaml by
// `tool/version/generate_version.dart`.
export 'version.g.dart';

/// Shorthand for the shared, color-configured console used across commands.
Console get console => Console.instance;

/// SGR escape-code wrapper. When [enabled] is false every styling method is the
/// identity function, so call sites never branch on color support.
class Ansi {
  const Ansi(this.enabled);

  final bool enabled;

  String _sgr(String code, String text) =>
      enabled ? '\x1B[${code}m$text\x1B[0m' : text;

  String bold(String text) => _sgr('1', text);
  String dim(String text) => _sgr('2', text);
  String italic(String text) => _sgr('3', text);
  String underline(String text) => _sgr('4', text);

  String red(String text) => _sgr('31', text);
  String green(String text) => _sgr('32', text);
  String yellow(String text) => _sgr('33', text);
  String blue(String text) => _sgr('34', text);
  String magenta(String text) => _sgr('35', text);
  String cyan(String text) => _sgr('36', text);
  String gray(String text) => _sgr('90', text);

  String brightCyan(String text) => _sgr('96', text);
  String brightGreen(String text) => _sgr('92', text);
  String brightRed(String text) => _sgr('91', text);

  /// Wraps [text] in an arbitrary raw SGR [code] (e.g. `'38;5;45'`).
  String raw(String code, String text) => _sgr(code, text);
}

/// Styled writer over a pair of [IOSink]s. Diagnostics go to stderr; status and
/// data go to stdout so the two streams can be redirected independently.
class Console {
  Console(this.ansi, {IOSink? out, IOSink? err})
    : _out = out ?? stdout,
      _err = err ?? stderr;

  final Ansi ansi;
  final IOSink _out;
  final IOSink _err;

  // --- configuration -------------------------------------------------------

  static Console instance = Console(Ansi(_autoColor()));

  /// Reconfigures the shared [instance] with an explicit color decision.
  static void configure({required bool color}) =>
      instance = Console(Ansi(color));

  bool get color => ansi.enabled;

  /// Usable terminal width, defaulting to 80 columns when stdout is not a tty.
  int get width {
    if (!stdout.hasTerminal) return 80;
    final columns = stdout.terminalColumns;
    return columns > 0 ? columns : 80;
  }

  // --- status lines (stdout) ----------------------------------------------

  /// A green check followed by [message]. Use for top-level command success.
  void success(String message) =>
      _out.writeln('${ansi.brightGreen('✓')} $message');

  /// A `created  <path>` line for files an operation just wrote.
  void created(String path) =>
      _out.writeln('  ${ansi.green('created')}  ${ansi.bold(path)}');

  /// A neutral, aligned `label  value` line under a section.
  void detail(String label, String value, {int pad = 9}) =>
      _out.writeln('  ${ansi.dim(label.padRight(pad))}  $value');

  /// A bold/underlined section header preceded by a blank line.
  void section(String title) =>
      _out.writeln('\n${ansi.bold(ansi.underline(title))}');

  /// Plain informational text on stdout.
  void info(String message) => _out.writeln(message);

  /// A dim hint line, typically a "next step" suggestion.
  void hint(String message) => _out.writeln(ansi.gray(message));

  /// Raw, undecorated stdout — for pipeable data (e.g. decrypted text).
  void raw(String text) => _out.writeln(text);

  // --- diagnostics (stderr) ------------------------------------------------

  /// A yellow warning on stderr.
  void warn(String message) =>
      _err.writeln('${ansi.yellow('⚠')} ${ansi.yellow('warning:')} $message');

  /// A red failure marker on stderr. Does not exit; callers set the exit code.
  void failure(String message) =>
      _err.writeln('${ansi.brightRed('✗')} $message');

  // --- banner --------------------------------------------------------------

  /// Renders the wordmark banner, picking the full block art or a one-line
  /// fallback based on color support and terminal width.
  String banner() {
    if (ansi.enabled && width >= 66) return _blockBanner();
    return _compactBanner();
  }

  String _compactBanner() {
    final mark = ansi.bold(ansi.brightCyan('pqforge'));
    final tag = ansi.dim('· post-quantum crypto CLI · v$pqforgeCliVersion');
    return '$mark $tag';
  }

  String _blockBanner() {
    // Vertical cyan→blue gradient applied row by row to the assembled glyphs.
    const palette = ['96', '96', '36', '36', '34', '34'];
    final rows = _assembleWordmark('PQFORGE');
    final painted = <String>[];
    for (var i = 0; i < rows.length; i++) {
      painted.add('  ${ansi.raw(palette[i], rows[i])}');
    }
    final subtitle = ansi.dim(
      '  Post-quantum recipes · ML-KEM · ML-DSA · X25519 · Ed25519 · ECDSA-P256',
    );
    return '${painted.join('\n')}\n$subtitle';
  }
}

/// Renders a styled "Examples" block for a command's `usageFooter`. Lines that
/// start with `#` are dimmed as comments; everything else is shown verbatim.
String usageExamples(Iterable<String> lines) {
  final ansi = Console.instance.ansi;
  final body = lines
      .map((line) => line.startsWith('#') ? '  ${ansi.gray(line)}' : '  $line')
      .join('\n');
  return '\n${ansi.bold('Examples')}\n$body';
}

/// Auto color decision honoring the `NO_COLOR` and `CLICOLOR_FORCE`
/// conventions, plus `TERM=dumb` and tty detection.
bool _autoColor() {
  final env = Platform.environment;
  if (env.containsKey('NO_COLOR')) return false;
  final force = env['CLICOLOR_FORCE'];
  if (force != null && force.isNotEmpty && force != '0') return true;
  if (env['TERM'] == 'dumb') return false;
  return stdout.hasTerminal;
}

/// Resolves the effective color setting from raw args (pre-parse) and the
/// environment, so the banner and usage are styled consistently before the
/// argument parser runs.
bool resolveColor(List<String> rawArgs) {
  if (rawArgs.contains('--no-color')) return false;
  return _autoColor();
}

/// Joins per-letter glyphs column-wise into the printable banner rows.
List<String> _assembleWordmark(String word) {
  const height = 6;
  final rows = List.filled(height, '');
  for (var i = 0; i < word.length; i++) {
    final glyph = _glyphs[word[i]];
    if (glyph == null) continue;
    final separator = i == 0 ? '' : ' ';
    for (var r = 0; r < height; r++) {
      rows[r] = '${rows[r]}$separator${glyph[r]}';
    }
  }
  return rows;
}

/// ANSI Shadow block glyphs for the wordmark, each a fixed 6-row grid with
/// every row padded to the glyph's own width so column assembly stays aligned.
const Map<String, List<String>> _glyphs = {
  'P': ['██████╗ ', '██╔══██╗', '██████╔╝', '██╔═══╝ ', '██║     ', '╚═╝     '],
  'Q': [
    ' ██████╗ ',
    '██╔═══██╗',
    '██║   ██║',
    '██║▄▄ ██║',
    '╚██████╔╝',
    ' ╚══▀▀═╝ ',
  ],
  'F': ['███████╗', '██╔════╝', '█████╗  ', '██╔══╝  ', '██║     ', '╚═╝     '],
  'O': [
    ' ██████╗ ',
    '██╔═══██╗',
    '██║   ██║',
    '██║   ██║',
    '╚██████╔╝',
    ' ╚═════╝ ',
  ],
  'R': ['██████╗ ', '██╔══██╗', '██████╔╝', '██╔══██╗', '██║  ██║', '╚═╝  ╚═╝'],
  'G': [
    ' ██████╗ ',
    '██╔════╝ ',
    '██║  ███╗',
    '██║   ██║',
    '╚██████╔╝',
    ' ╚═════╝ ',
  ],
  'E': ['███████╗', '██╔════╝', '█████╗  ', '██╔══╝  ', '███████╗', '╚══════╝'],
};
