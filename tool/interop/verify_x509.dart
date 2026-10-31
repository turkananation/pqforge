/// Mint a P-256 chain and check it with the pinned OpenSSL and BoringSSL.
///
/// Skips unless [PINNED_TLS_PREFIX] points at a build from `build_pinned.sh`,
/// or `REQUIRE_PINNED_TLS=1`, in which case a missing build is a failure.
/// `dart test` does not run this. CI does.
library;

import 'dart:convert';
import 'dart:io';
import 'dart:typed_data';

import 'package:pqforge/pqforge.dart';

void main() {
  final prefix =
      Platform.environment['PINNED_TLS_PREFIX'] ??
      '${Directory.current.path}/tool/interop/.build';
  final openssl = '$prefix/openssl/bin/openssl';
  final boring = '$prefix/boringssl/bin/boringssl_verify';
  final required = Platform.environment['REQUIRE_PINNED_TLS'] == '1';
  if (!File(openssl).existsSync() || !File(boring).existsSync()) {
    stdout.writeln(
      required
          ? 'FAIL: pinned OpenSSL or BoringSSL is missing under $prefix'
          : 'SKIP: pinned TLS build not present',
    );
    exitCode = required ? 1 : 0;
    return;
  }

  final pins = _pins(File('tool/interop/pins.env').readAsStringSync());
  final version = _run(openssl, const ['version']);
  if (!version.startsWith(
    'OpenSSL ${pins['OPENSSL_TAG']!.replaceFirst('openssl-', '')}',
  )) {
    _fail('OpenSSL version is "$version", pin is ${pins['OPENSSL_TAG']}');
  }
  final commit = File('$prefix/boringssl/COMMIT').readAsStringSync().trim();
  if (commit != pins['BORINGSSL_COMMIT']) {
    _fail('BoringSSL commit is $commit, pin is ${pins['BORINGSSL_COMMIT']}');
  }
  stdout.writeln(version.trim());
  stdout.writeln('BoringSSL ${pins['BORINGSSL_TAG']} $commit');

  final dir = Directory.systemTemp.createTempSync('pqforge-pinned-');
  try {
    final minted = _mint();
    File(
      '${dir.path}/ca.pem',
    ).writeAsStringSync(_pem('CERTIFICATE', minted.$1));
    File(
      '${dir.path}/leaf.pem',
    ).writeAsStringSync(_pem('CERTIFICATE', minted.$2));
    _run(openssl, [
      'verify',
      '-CAfile',
      '${dir.path}/ca.pem',
      '${dir.path}/leaf.pem',
    ]);
    _run(boring, ['${dir.path}/leaf.pem', '${dir.path}/ca.pem']);

    _run(openssl, [
      'req',
      '-x509',
      '-newkey',
      'ec',
      '-pkeyopt',
      'ec_paramgen_curve:prime256v1',
      '-keyout',
      '${dir.path}/openssl.key',
      '-out',
      '${dir.path}/openssl.pem',
      '-days',
      '30',
      '-nodes',
      '-subj',
      '/CN=openssl-leaf',
    ]);
    final der = File('${dir.path}/openssl.der');
    _run(openssl, [
      'x509',
      '-in',
      '${dir.path}/openssl.pem',
      '-outform',
      'DER',
      '-out',
      der.path,
    ]);
    final parsed = PqX509.parse(der.readAsBytesSync());
    final certificate = parsed.certificate;
    if (certificate == null) {
      _fail('OpenSSL certificate did not parse: ${parsed.failure}');
    }
    if (!PqX509.checkSignature(certificate, certificate.publicKey)) {
      _fail('OpenSSL certificate signature did not check');
    }
  } finally {
    dir.deleteSync(recursive: true);
  }
  stdout.writeln('OK: P-256 chain matches pinned OpenSSL and BoringSSL');
}

(Uint8List, Uint8List) _mint() {
  final caKeys = PqEcdsaP256.generateKeyPair();
  final leafKeys = PqEcdsaP256.generateKeyPair();
  final caName = PqX509Name.commonName('pqforge-ca');
  Uint8List sign(Uint8List secret, Uint8List tbs) =>
      PqX509.encodeEcdsaSignature(
        PqEcdsaP256.sign(privateKey: secret, message: tbs),
      );
  final ca = PqX509.mint(
    issuer: caName,
    subject: caName,
    publicKey: PqX509EcdsaP256Key(caKeys.publicKey),
    algorithm: PqX509Algorithm.ecdsaP256Sha256,
    sign: (tbs) => sign(caKeys.secretKey, tbs),
    notBefore: DateTime.utc(2026, 1, 1),
    notAfter: DateTime.utc(2027, 1, 1),
    serial: Uint8List.fromList([1]),
    ca: true,
    digitalSignature: false,
    keyCertSign: true,
    includeEku: false,
  );
  final leaf = PqX509.mint(
    issuer: caName,
    subject: PqX509Name.commonName('localhost'),
    publicKey: PqX509EcdsaP256Key(leafKeys.publicKey),
    algorithm: PqX509Algorithm.ecdsaP256Sha256,
    sign: (tbs) => sign(caKeys.secretKey, tbs),
    notBefore: DateTime.utc(2026, 1, 1),
    notAfter: DateTime.utc(2027, 1, 1),
    serial: Uint8List.fromList([2]),
    subjectAltNames: [const PqX509DnsName('localhost')],
  );
  return (ca, leaf);
}

String _pem(String label, Uint8List der) {
  final encoded = base64.encode(der);
  final lines = <String>[];
  for (var i = 0; i < encoded.length; i += 64) {
    final end = i + 64 > encoded.length ? encoded.length : i + 64;
    lines.add(encoded.substring(i, end));
  }
  return '-----BEGIN $label-----\n${lines.join('\n')}\n-----END $label-----\n';
}

Map<String, String> _pins(String text) {
  final out = <String, String>{};
  for (final line in text.split('\n')) {
    final trimmed = line.trim();
    if (trimmed.isEmpty || trimmed.startsWith('#')) continue;
    final split = trimmed.split('=');
    if (split.length != 2) _fail('bad pin line: $trimmed');
    out[split[0]] = split[1];
  }
  return out;
}

String _run(String program, List<String> args) {
  final result = Process.runSync(
    program,
    args,
    environment: {
      ...Platform.environment,
      'LD_LIBRARY_PATH':
          '${File(program).parent.parent.path}/lib:${Platform.environment['LD_LIBRARY_PATH'] ?? ''}',
    },
  );
  if (result.exitCode != 0) {
    _fail('$program ${args.join(' ')}\n${result.stdout}${result.stderr}');
  }
  return '${result.stdout}';
}

Never _fail(String message) {
  stderr.writeln(message);
  exit(1);
}
