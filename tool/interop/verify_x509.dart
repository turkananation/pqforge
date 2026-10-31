/// Check every certificate signature pqforge mints against pinned OpenSSL
/// and BoringSSL, and parse a certificate OpenSSL minted for each one.
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
    for (final minted in _ourChains()) {
      _verifyOurs(openssl, boring, dir, minted.$1, minted.$2, minted.$3);
    }
    for (final minted in _opensslCertificates(dir, openssl)) {
      _verifyTheirs(openssl, dir, minted.$1, minted.$2, minted.$3);
    }
  } finally {
    dir.deleteSync(recursive: true);
  }
  stdout.writeln(
    'OK: every signature algorithm matches pinned OpenSSL and BoringSSL',
  );
}

void _verifyOurs(
  String openssl,
  String boring,
  Directory dir,
  String name,
  Uint8List caDer,
  Uint8List leafDer,
) {
  final ca = '${dir.path}/$name-ca.pem';
  final leaf = '${dir.path}/$name-leaf.pem';
  File(ca).writeAsStringSync(_pem('CERTIFICATE', caDer));
  File(leaf).writeAsStringSync(_pem('CERTIFICATE', leafDer));
  stdout.writeln('ours $name');
  _run(openssl, ['verify', '-CAfile', ca, leaf]);
  _run(boring, [leaf, ca]);
}

void _verifyTheirs(
  String openssl,
  Directory dir,
  String name,
  PqX509Algorithm algorithm,
  List<String> reqArgs,
) {
  final pem = '${dir.path}/$name.pem';
  final derPath = '${dir.path}/$name.der';
  stdout.writeln('openssl $name');
  _run(openssl, [...reqArgs, '-out', pem]);
  _run(openssl, ['x509', '-in', pem, '-outform', 'DER', '-out', derPath]);
  final parsed = PqX509.parse(File(derPath).readAsBytesSync());
  final certificate = parsed.certificate;
  if (certificate == null) {
    _fail('$name did not parse: ${parsed.failure}');
  }
  if (certificate.algorithm != algorithm) {
    _fail('$name algorithm is ${certificate.algorithm}, expected $algorithm');
  }
  if (!PqX509.checkSignature(certificate, certificate.publicKey)) {
    _fail('$name signature did not check');
  }
}

typedef _Sign = Uint8List Function(Uint8List tbs);

(Uint8List, Uint8List) _chain({
  required PqX509PublicKey caKey,
  required PqX509PublicKey leafKey,
  required PqX509Algorithm algorithm,
  required _Sign sign,
  bool pssPublicKey = false,
  int? pssSaltLength,
}) {
  final caName = PqX509Name.commonName('pqforge-ca');
  final notBefore = DateTime.utc(2026, 1, 1);
  final notAfter = DateTime.utc(2027, 1, 1);
  final ca = PqX509.mint(
    issuer: caName,
    subject: caName,
    publicKey: caKey,
    algorithm: algorithm,
    sign: sign,
    notBefore: notBefore,
    notAfter: notAfter,
    serial: Uint8List.fromList([1]),
    ca: true,
    digitalSignature: false,
    keyCertSign: true,
    includeEku: false,
    pssPublicKey: pssPublicKey,
    pssSaltLength: pssSaltLength,
  );
  final leaf = PqX509.mint(
    issuer: caName,
    subject: PqX509Name.commonName('localhost'),
    publicKey: leafKey,
    algorithm: algorithm,
    sign: sign,
    notBefore: notBefore,
    notAfter: notAfter,
    serial: Uint8List.fromList([2]),
    subjectAltNames: [const PqX509DnsName('localhost')],
    pssPublicKey: pssPublicKey,
    pssSaltLength: pssSaltLength,
  );
  return (ca, leaf);
}

List<(String, Uint8List, Uint8List)> _ourChains() {
  final out = <(String, Uint8List, Uint8List)>[];

  final p256Ca = PqEcdsaP256.generateKeyPair();
  final p256Leaf = PqEcdsaP256.generateKeyPair();
  final p256 = _chain(
    caKey: PqX509EcdsaP256Key(p256Ca.publicKey),
    leafKey: PqX509EcdsaP256Key(p256Leaf.publicKey),
    algorithm: PqX509Algorithm.ecdsaP256Sha256,
    sign: (tbs) => PqX509.encodeEcdsaSignature(
      PqEcdsaP256.sign(privateKey: p256Ca.secretKey, message: tbs),
    ),
  );
  out.add(('ecdsa-p256', p256.$1, p256.$2));

  final p384Ca = PqEcdsaP384.generateKeyPair();
  final p384Leaf = PqEcdsaP384.generateKeyPair();
  final p384 = _chain(
    caKey: PqX509EcdsaP384Key(p384Ca.publicKey),
    leafKey: PqX509EcdsaP384Key(p384Leaf.publicKey),
    algorithm: PqX509Algorithm.ecdsaP384Sha384,
    sign: (tbs) => PqX509.encodeEcdsaSignature(
      PqEcdsaP384.sign(privateKey: p384Ca.secretKey, message: tbs),
    ),
  );
  out.add(('ecdsa-p384', p384.$1, p384.$2));

  final edCa = PqEd25519.generateKeyPair();
  final edLeaf = PqEd25519.generateKeyPair();
  final ed = _chain(
    caKey: PqX509Ed25519Key(edCa.publicKey),
    leafKey: PqX509Ed25519Key(edLeaf.publicKey),
    algorithm: PqX509Algorithm.ed25519,
    sign: (tbs) => PqEd25519.sign(secretKey: edCa.secretKey, message: tbs),
  );
  out.add(('ed25519', ed.$1, ed.$2));

  for (final level in PqSignatureAlgorithm.values) {
    final which = switch (level) {
      PqSignatureAlgorithm.mlDsa44 => PqX509Algorithm.mlDsa44,
      PqSignatureAlgorithm.mlDsa65 => PqX509Algorithm.mlDsa65,
      PqSignatureAlgorithm.mlDsa87 => PqX509Algorithm.mlDsa87,
    };
    final ca = PqSignaturePrimitives.generateKeyPair(level);
    final leaf = PqSignaturePrimitives.generateKeyPair(level);
    final chain = _chain(
      caKey: PqX509MlDsaKey(which, ca.publicKey),
      leafKey: PqX509MlDsaKey(which, leaf.publicKey),
      algorithm: which,
      sign: (tbs) => PqSignaturePrimitives.sign(level, ca.secretKey, tbs),
    );
    out.add((level.id, chain.$1, chain.$2));
  }

  final rsa = PqRsa.generateKeyPair();
  final rsaKey = PqX509RsaKey(rsa.modulus, rsa.exponent);
  final leafRsa = PqRsa.generateKeyPair();
  final leafKey = PqX509RsaKey(leafRsa.modulus, leafRsa.exponent);
  const hashes = [
    (PqX509Algorithm.rsaPkcs1Sha256, PqRsaHash.sha256, 'pkcs1-sha256'),
    (PqX509Algorithm.rsaPkcs1Sha384, PqRsaHash.sha384, 'pkcs1-sha384'),
    (PqX509Algorithm.rsaPkcs1Sha512, PqRsaHash.sha512, 'pkcs1-sha512'),
    (PqX509Algorithm.rsaPssSha256, PqRsaHash.sha256, 'pss-sha256'),
    (PqX509Algorithm.rsaPssSha384, PqRsaHash.sha384, 'pss-sha384'),
    (PqX509Algorithm.rsaPssSha512, PqRsaHash.sha512, 'pss-sha512'),
  ];
  for (final hash in hashes) {
    final pss =
        hash.$1 == PqX509Algorithm.rsaPssSha256 ||
        hash.$1 == PqX509Algorithm.rsaPssSha384 ||
        hash.$1 == PqX509Algorithm.rsaPssSha512;
    final chain = _chain(
      caKey: rsaKey,
      leafKey: leafKey,
      algorithm: hash.$1,
      sign: (tbs) => pss
          ? PqRsa.signPss(
              privateKey: rsa.privateKey,
              message: tbs,
              hash: hash.$2,
            )
          : PqRsa.signPkcs1(
              privateKey: rsa.privateKey,
              message: tbs,
              hash: hash.$2,
            ),
    );
    out.add((hash.$3, chain.$1, chain.$2));
  }

  final salt20 = _chain(
    caKey: rsaKey,
    leafKey: leafKey,
    algorithm: PqX509Algorithm.rsaPssSha256,
    pssSaltLength: 20,
    sign: (tbs) => PqRsa.signPss(
      privateKey: rsa.privateKey,
      message: tbs,
      hash: PqRsaHash.sha256,
      saltLength: 20,
    ),
  );
  out.add(('pss-sha256-salt20', salt20.$1, salt20.$2));

  final pssKey = _chain(
    caKey: rsaKey,
    leafKey: leafKey,
    algorithm: PqX509Algorithm.rsaPssSha256,
    pssPublicKey: true,
    sign: (tbs) => PqRsa.signPss(
      privateKey: rsa.privateKey,
      message: tbs,
      hash: PqRsaHash.sha256,
    ),
  );
  out.add(('pss-sha256-spki', pssKey.$1, pssKey.$2));
  return out;
}

List<(String, PqX509Algorithm, List<String>)> _opensslCertificates(
  Directory dir,
  String openssl,
) {
  List<String> req(String name, List<String> head) => [
    'req',
    '-x509',
    ...head,
    '-keyout',
    '${dir.path}/$name.key',
    '-days',
    '30',
    '-nodes',
    '-subj',
    '/CN=openssl-$name',
  ];

  final out = <(String, PqX509Algorithm, List<String>)>[
    (
      'ecdsa-p256',
      PqX509Algorithm.ecdsaP256Sha256,
      req('ecdsa-p256', const [
        '-newkey',
        'ec',
        '-pkeyopt',
        'ec_paramgen_curve:prime256v1',
        '-sha256',
      ]),
    ),
    (
      'ecdsa-p384',
      PqX509Algorithm.ecdsaP384Sha384,
      req('ecdsa-p384', const [
        '-newkey',
        'ec',
        '-pkeyopt',
        'ec_paramgen_curve:secp384r1',
        '-sha384',
      ]),
    ),
    (
      'ed25519',
      PqX509Algorithm.ed25519,
      req('ed25519', const ['-newkey', 'ed25519']),
    ),
    (
      'ml-dsa-44',
      PqX509Algorithm.mlDsa44,
      req('ml-dsa-44', const ['-newkey', 'ML-DSA-44']),
    ),
    (
      'ml-dsa-65',
      PqX509Algorithm.mlDsa65,
      req('ml-dsa-65', const ['-newkey', 'ML-DSA-65']),
    ),
    (
      'ml-dsa-87',
      PqX509Algorithm.mlDsa87,
      req('ml-dsa-87', const ['-newkey', 'ML-DSA-87']),
    ),
    (
      'pkcs1-sha256',
      PqX509Algorithm.rsaPkcs1Sha256,
      req('pkcs1-sha256', const ['-newkey', 'rsa:2048', '-sha256']),
    ),
    (
      'pkcs1-sha384',
      PqX509Algorithm.rsaPkcs1Sha384,
      req('pkcs1-sha384', const ['-newkey', 'rsa:2048', '-sha384']),
    ),
    (
      'pkcs1-sha512',
      PqX509Algorithm.rsaPkcs1Sha512,
      req('pkcs1-sha512', const ['-newkey', 'rsa:2048', '-sha512']),
    ),
    (
      'pss-padding-sha256',
      PqX509Algorithm.rsaPssSha256,
      req('pss-padding-sha256', const [
        '-newkey',
        'rsa:2048',
        '-sha256',
        '-sigopt',
        'rsa_padding_mode:pss',
        '-sigopt',
        'rsa_pss_saltlen:32',
      ]),
    ),
  ];

  const pss = [
    (PqX509Algorithm.rsaPssSha256, 'sha256', 32),
    (PqX509Algorithm.rsaPssSha384, 'sha384', 48),
    (PqX509Algorithm.rsaPssSha512, 'sha512', 64),
  ];
  for (final item in pss) {
    final name = 'pss-${item.$2}';
    final key = '${dir.path}/$name.key';
    _run(openssl, [
      'genpkey',
      '-algorithm',
      'RSA-PSS',
      '-pkeyopt',
      'rsa_keygen_bits:2048',
      '-pkeyopt',
      'rsa_pss_keygen_md:${item.$2}',
      '-pkeyopt',
      'rsa_pss_keygen_mgf1_md:${item.$2}',
      '-pkeyopt',
      'rsa_pss_keygen_saltlen:${item.$3}',
      '-out',
      key,
    ]);
    out.add((
      name,
      item.$1,
      [
        'req',
        '-x509',
        '-key',
        key,
        '-${item.$2}',
        '-days',
        '30',
        '-subj',
        '/CN=openssl-$name',
      ],
    ));
  }
  return out;
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
