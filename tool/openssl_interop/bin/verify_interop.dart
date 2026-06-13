/// Cross-checks pqforge's pure-Dart AEAD engines against the system OpenSSL.
///
/// For every suite (AES-256-GCM, ChaCha20-Poly1305) × every pqforge engine
/// (`package:cryptography`, PointyCastle) it verifies, over a range of sizes:
///
///  1. **byte-identical seals** — same key/nonce/aad/plaintext must produce
///     the same `ciphertext ‖ tag` as OpenSSL EVP;
///  2. **cross opens** — OpenSSL opens pqforge's body and vice versa;
///  3. **tamper detection on both sides** — a flipped byte fails OpenSSL
///     (`OpenSslAuthFailure`) and pqforge (`PqForgeAuthTagException`).
///
/// Exits non-zero on any mismatch. When libcrypto is absent the run is
/// skipped (exit 0) unless `REQUIRE_OPENSSL=1`, so dev boxes without OpenSSL
/// stay green while CI enforces the check. `--bench` additionally measures
/// OpenSSL vs pure-Dart throughput — the R6 hardware-ceiling number quoted in
/// doc/technical/PERFORMANCE_AUDIT_AND_HYBRID_CLI.md.
library;

import 'dart:io';
import 'dart:typed_data';

import 'package:openssl_pqforge_interop/openssl_aead.dart';
import 'package:pqforge/pqforge.dart';

Future<void> main(List<String> args) async {
  final openSsl = OpenSslAead.tryLoad();
  if (openSsl == null) {
    final required = Platform.environment['REQUIRE_OPENSSL'] == '1';
    stdout.writeln(
      required
          ? 'FAIL: libcrypto not found and REQUIRE_OPENSSL=1 '
                '(set LIBCRYPTO_PATH to point at it)'
          : 'SKIP: libcrypto not found — interop verification not run',
    );
    exitCode = required ? 1 : 0;
    return;
  }
  stdout.writeln('OpenSSL : ${openSsl.version()} (${openSsl.libraryPath})');

  var failures = 0;
  for (final suite in PqForgeCipherSuite.values) {
    for (final engine in <PqForgeAeadEngine>[
      PqForgeCryptographyAeadEngine(suite),
      PqForgePointyCastleAeadEngine(suite),
    ]) {
      failures += await _verify(openSsl, suite, engine);
    }
  }

  if (args.contains('--bench')) await _bench(openSsl);

  stdout.writeln(
    failures == 0
        ? 'OK: all suites and engines byte-compatible with OpenSSL'
        : 'FAIL: $failures check(s) failed',
  );
  exitCode = failures == 0 ? 0 : 1;
}

Future<int> _verify(
  OpenSslAead openSsl,
  PqForgeCipherSuite suite,
  PqForgeAeadEngine engine,
) async {
  final label = '${suite.id} × ${engine.provider.name}';
  var failures = 0;
  void fail(String what) {
    failures++;
    stdout.writeln('  FAIL [$label] $what');
  }

  for (final size in const [0, 1, 17, 4096, 1 << 20]) {
    final key = PqBytes.randomBytes(suite.keyLength);
    final nonce = PqBytes.randomBytes(suite.nonceLength);
    final aad = PqBytes.randomBytes(size == 0 ? 0 : 32);
    final plaintext = PqBytes.randomBytes(size);

    final ours = await engine.seal(
      key: key,
      nonce: nonce,
      plaintext: plaintext,
      aad: aad,
    );
    final theirs = openSsl.seal(
      suiteId: suite.id,
      key: key,
      nonce: nonce,
      plaintext: plaintext,
      aad: aad,
    );
    if (!_equal(ours, theirs)) fail('seal mismatch at $size bytes');

    final openedByOpenSsl = openSsl.open(
      suiteId: suite.id,
      key: key,
      nonce: nonce,
      cipherTextWithTag: ours,
      aad: aad,
    );
    if (!_equal(openedByOpenSsl, plaintext)) {
      fail('OpenSSL could not open our body at $size bytes');
    }
    final openedByUs = await engine.open(
      key: key,
      nonce: nonce,
      cipherTextWithTag: theirs,
      aad: aad,
    );
    if (!_equal(openedByUs, plaintext)) {
      fail('we could not open the OpenSSL body at $size bytes');
    }

    if (size > 0) {
      final tampered = Uint8List.fromList(ours)..[size ~/ 2] ^= 0x01;
      try {
        openSsl.open(
          suiteId: suite.id,
          key: key,
          nonce: nonce,
          cipherTextWithTag: tampered,
          aad: aad,
        );
        fail('OpenSSL accepted a tampered body at $size bytes');
      } on OpenSslAuthFailure {
        // expected
      }
      try {
        await engine.open(
          key: key,
          nonce: nonce,
          cipherTextWithTag: tampered,
          aad: aad,
        );
        fail('pqforge accepted a tampered body at $size bytes');
      } on PqForgeAuthTagException {
        // expected
      }
    }
  }
  stdout.writeln(
    '  ${failures == 0 ? 'ok  ' : 'FAIL'} $label '
    '(sizes 0/1/17/4096/1MiB, cross-open + tamper)',
  );
  return failures;
}

Future<void> _bench(OpenSslAead openSsl) async {
  const totalMiB = 64;
  const frame = 1 << 20;
  final key = PqBytes.randomBytes(32);
  final plaintext = PqBytes.randomBytes(frame);
  final aad = Uint8List(0);

  for (final suite in PqForgeCipherSuite.values) {
    final watchOpenSsl = Stopwatch()..start();
    for (var i = 0; i < totalMiB; i++) {
      openSsl.seal(
        suiteId: suite.id,
        key: key,
        nonce: PqBytes.randomBytes(12),
        plaintext: plaintext,
        aad: aad,
      );
    }
    watchOpenSsl.stop();

    final engine = PqForgeCryptographyAeadEngine(suite);
    final watchDart = Stopwatch()..start();
    for (var i = 0; i < totalMiB; i++) {
      await engine.seal(
        key: key,
        nonce: PqBytes.randomBytes(12),
        plaintext: plaintext,
        aad: aad,
      );
    }
    watchDart.stop();

    String rate(Stopwatch w) =>
        (totalMiB * 1000 / w.elapsedMilliseconds).toStringAsFixed(1);
    stdout.writeln(
      '  bench ${suite.id}: OpenSSL ${rate(watchOpenSsl)} MiB/s vs '
      'pure Dart (cryptography) ${rate(watchDart)} MiB/s',
    );
  }
}

bool _equal(Uint8List a, Uint8List b) {
  if (a.length != b.length) return false;
  for (var i = 0; i < a.length; i++) {
    if (a[i] != b[i]) return false;
  }
  return true;
}
