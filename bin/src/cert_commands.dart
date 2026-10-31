/// `cert issue`, `cert inspect`, and `cert verify`.
///
/// Issue writes the PEM OpenSSL reads by default. `--der` writes the raw
/// certificate instead. The secret is a keygen file: ECDSA-P256, Ed25519, or
/// ML-DSA. The certificate is self-signed.
library;

import 'dart:convert';
import 'dart:io';
import 'dart:math';
import 'dart:typed_data';

import 'package:args/args.dart';
import 'package:args/command_runner.dart';
import 'package:pqforge/pqforge.dart';

import 'console.dart';
import 'support.dart';

final class CertCommand extends Command<void> {
  CertCommand() {
    addSubcommand(CertIssueCommand());
    addSubcommand(CertRequestCommand());
    addSubcommand(CertSignCommand());
    addSubcommand(CertInspectCommand());
    addSubcommand(CertVerifyCommand());
  }

  @override
  String get name => 'cert';

  @override
  String get description =>
      'Issue, inspect, or verify an X.509 certificate (PEM by default).';

  @override
  String get invocation =>
      'pqforge cert <issue|req|sign|inspect|verify> [arguments]';
}

final class CertIssueCommand extends Command<void> {
  CertIssueCommand() {
    argParser
      ..addOption(
        'secret',
        valueHelp: 'file',
        help:
            'keygen secret: ecdsa-p256, ed25519, or ML-DSA. Wrapped keys need '
            'a passphrase. Mutually exclusive with --key.',
      )
      ..addOption(
        'key',
        valueHelp: 'file',
        help:
            'OpenSSL PEM private key (PRIVATE KEY, EC PRIVATE KEY, or '
            'RSA PRIVATE KEY), the file openssl req -keyout writes.',
      )
      ..addOption(
        'public',
        valueHelp: 'file',
        help:
            'Matching public key. Required for an ML-DSA --secret. Derived '
            'for ecdsa-p256, ed25519, and --key.',
      )
      ..addOption(
        'cn',
        valueHelp: 'name',
        help: 'Subject common name. Shorthand for --subj /CN=name.',
      )
      ..addOption(
        'subj',
        valueHelp: '/CN=...',
        help:
            'OpenSSL -subj. Example: /C=KE/ST=Nairobi/O=pqforge/CN=localhost.',
      )
      ..addMultiOption(
        'dns',
        valueHelp: 'name',
        help: 'DNS subject alternative name. Repeat for more than one.',
      )
      ..addMultiOption(
        'addext',
        valueHelp: 'name=value',
        help:
            'OpenSSL -addext. Repeatable. subjectAltName, keyUsage, '
            'extendedKeyUsage, basicConstraints.',
      )
      ..addOption(
        'days',
        defaultsTo: '365',
        valueHelp: 'n',
        help: 'Validity, in days, starting now (UTC).',
      )
      ..addOption(
        'out',
        mandatory: true,
        valueHelp: 'file',
        help: 'PEM certificate, or DER when --der is set.',
      )
      ..addFlag(
        'ca',
        negatable: false,
        help: 'Mark the certificate as a CA (keyCertSign, no serverAuth).',
      )
      ..addFlag('der', negatable: false, help: 'Write DER instead of PEM.');
    addPassphraseOptions(argParser);
    addQuietOption(argParser);
  }

  @override
  String get name => 'issue';

  @override
  String get description => 'Write a self-signed certificate. PEM by default.';

  @override
  String get usageFooter => usageExamples([
    'pqforge cert issue --key key.pem --subj /C=KE/O=pqforge/CN=localhost \\',
    '  --addext subjectAltName=DNS:localhost --out localhost.pem',
  ]);

  @override
  Future<void> run() async {
    final results = argResults!;
    final cn = results['cn'] as String?;
    final subj = results['subj'] as String?;
    final dns = results['dns'] as List<String>;
    final addext = PqX509Addext.parse(results['addext'] as List<String>);
    if ((cn == null) == (subj == null)) {
      throw const PqForgeException('Provide one of --cn or --subj.');
    }
    if (dns.isNotEmpty && addext.hasSan) {
      throw const PqForgeException('Use --dns or --addext subjectAltName.');
    }
    final days = int.tryParse(results['days'] as String);
    if (days == null || days < 1 || days > 8250) {
      throw const PqForgeException('--days must be from 1 to 8250.');
    }
    final ca = addext.hasBasic ? addext.ca : results['ca'] as bool;
    final built = await _signer(results);
    final subject = subj == null
        ? PqX509Name.commonName(cn!)
        : PqX509Name.subject(subj);
    final names = addext.hasSan
        ? addext.names
        : [
            for (final name in (dns.isEmpty ? [?cn, ?_cnOf(subj)] : dns))
              if (name.isNotEmpty) PqX509DnsName(name),
          ];
    final notBefore = DateTime.now().toUtc();
    final der = PqX509.mint(
      issuer: subject,
      subject: subject,
      publicKey: built.publicKey,
      algorithm: built.algorithm,
      sign: built.sign,
      notBefore: notBefore,
      notAfter: notBefore.add(Duration(days: days)),
      serial: _serial(),
      subjectAltNames: ca ? const [] : names,
      ca: ca,
      pathLen: addext.pathLen,
      digitalSignature: !ca && !addext.hasKeyUsage,
      keyCertSign: ca && !addext.hasKeyUsage,
      includeEku:
          !ca &&
          (addext.hasEku ? addext.serverAuth || addext.clientAuth : true),
      serverAuth: addext.hasEku ? addext.serverAuth : true,
      clientAuth: addext.clientAuth,
      keyUsageMask: addext.hasKeyUsage ? addext.keyUsage : null,
      basicCritical: addext.hasBasic ? addext.basicCritical : true,
      keyUsageCritical: addext.hasKeyUsage ? addext.keyUsageCritical : true,
      ekuCritical: addext.ekuCritical,
      sanCritical: addext.sanCritical,
    );
    await _write(results, der, 'CERTIFICATE');
    if (!quietFrom(results)) {
      console.detail('algorithm', _algorithmName(built.algorithm), pad: 12);
      console.detail('subject', subj ?? 'CN=$cn', pad: 12);
      console.created(results['out'] as String);
    }
  }
}

final class CertRequestCommand extends Command<void> {
  CertRequestCommand() {
    argParser
      ..addOption('secret', valueHelp: 'file', help: 'keygen secret.')
      ..addOption('key', valueHelp: 'file', help: 'OpenSSL PEM private key.')
      ..addOption('public', valueHelp: 'file', help: 'ML-DSA public key.')
      ..addOption('cn', valueHelp: 'name', help: 'Shorthand for --subj /CN=.')
      ..addOption('subj', valueHelp: '/CN=...', help: 'OpenSSL -subj.')
      ..addMultiOption('dns', valueHelp: 'name', help: 'DNS SAN.')
      ..addMultiOption(
        'addext',
        valueHelp: 'name=value',
        help: 'OpenSSL -addext. Repeatable.',
      )
      ..addOption('out', mandatory: true, valueHelp: 'file', help: 'CSR PEM.')
      ..addFlag('der', negatable: false, help: 'Write DER.');
    addPassphraseOptions(argParser);
    addQuietOption(argParser);
  }

  @override
  String get name => 'req';

  @override
  String get description =>
      'Write a PKCS#10 request. openssl req -verify reads it.';

  @override
  String get usageFooter => usageExamples([
    'pqforge cert req --key key.pem --subj /CN=localhost \\',
    '  --addext subjectAltName=DNS:localhost --out localhost.csr',
  ]);

  @override
  Future<void> run() async {
    final results = argResults!;
    final cn = results['cn'] as String?;
    final subj = results['subj'] as String?;
    final dns = results['dns'] as List<String>;
    final addext = PqX509Addext.parse(results['addext'] as List<String>);
    if ((cn == null) == (subj == null)) {
      throw const PqForgeException('Provide one of --cn or --subj.');
    }
    final built = await _signer(results);
    final subject = subj == null
        ? PqX509Name.commonName(cn!)
        : PqX509Name.subject(subj);
    final names = addext.hasSan
        ? addext.names
        : [for (final name in dns) PqX509DnsName(name)];
    final der = PqX509.mintRequest(
      subject: subject,
      publicKey: built.publicKey,
      algorithm: built.algorithm,
      sign: built.sign,
      subjectAltNames: names,
      ca: addext.ca,
      pathLen: addext.pathLen,
      includeBasic: addext.hasBasic,
      keyUsageMask: addext.keyUsage,
      includeEku: addext.hasEku,
      clientAuth: addext.clientAuth,
    );
    await _write(results, der, 'CERTIFICATE REQUEST');
    if (!quietFrom(results)) console.created(results['out'] as String);
  }
}

final class CertSignCommand extends Command<void> {
  CertSignCommand() {
    argParser
      ..addOption('in', mandatory: true, valueHelp: 'file', help: 'CSR PEM.')
      ..addOption(
        'ca',
        mandatory: true,
        valueHelp: 'file',
        help: 'CA certificate PEM or DER.',
      )
      ..addOption('ca-secret', valueHelp: 'file', help: 'CA keygen secret.')
      ..addOption(
        'ca-key',
        valueHelp: 'file',
        help: 'CA OpenSSL PEM private key.',
      )
      ..addOption('ca-public', valueHelp: 'file', help: 'CA ML-DSA public key.')
      ..addOption('days', defaultsTo: '365', valueHelp: 'n')
      ..addOption('out', mandatory: true, valueHelp: 'file')
      ..addFlag('der', negatable: false, help: 'Write DER.');
    addPassphraseOptions(argParser);
    addQuietOption(argParser);
  }

  @override
  String get name => 'sign';

  @override
  String get description =>
      'Sign a request with a CA. openssl x509 -req -copy_extensions copy.';

  @override
  String get usageFooter => usageExamples([
    'pqforge cert sign --in localhost.csr --ca ca.pem \\',
    '  --ca-key ca.key --days 365 --out localhost.pem',
  ]);

  @override
  Future<void> run() async {
    final results = argResults!;
    final days = int.tryParse(results['days'] as String);
    if (days == null || days < 1 || days > 8250) {
      throw const PqForgeException('--days must be from 1 to 8250.');
    }
    final caDer = _readCertificates(
      await File(results['ca'] as String).readAsBytes(),
    );
    if (caDer.length != 1) {
      throw const PqForgeException('The CA file must hold one certificate.');
    }
    final ca = PqX509.parse(caDer.single).certificate;
    if (ca == null || ca.ca != true) {
      throw const PqForgeException('The CA certificate is not a CA.');
    }
    final built = await _signer(
      results,
      secretName: 'ca-secret',
      keyName: 'ca-key',
      publicName: 'ca-public',
    );
    final request = await File(results['in'] as String).readAsBytes();
    final csr = String.fromCharCodes(request).contains('-----BEGIN ')
        ? PqX509.pemBlocks(String.fromCharCodes(request)).single.der
        : request;
    final notBefore = DateTime.now().toUtc();
    final der = PqX509.signRequest(
      request: csr,
      issuer: PqX509Name(ca.subjectDer),
      algorithm: ca.algorithm,
      sign: built.sign,
      notBefore: notBefore,
      notAfter: notBefore.add(Duration(days: days)),
      serial: _serial(),
      pssSaltLength: ca.pssSaltLength,
    );
    await _write(results, der, 'CERTIFICATE');
    if (!quietFrom(results)) console.created(results['out'] as String);
  }
}

final class CertInspectCommand extends Command<void> {
  CertInspectCommand() {
    argParser.addOption(
      'in',
      mandatory: true,
      valueHelp: 'file',
      help:
          'PEM or DER. A PEM file may hold certificates, requests, and private keys.',
    );
  }

  @override
  String get name => 'inspect';

  @override
  String get description =>
      'Print a certificate, request, or private key. The secret is not printed.';

  @override
  String get usageFooter =>
      usageExamples(['pqforge cert inspect --in localhost.pem']);

  @override
  Future<void> run() async {
    final input = argResults!['in'] as String;
    final bytes = await File(input).readAsBytes();
    if (bytes.isEmpty) {
      throw const PqForgeException('The file is empty.');
    }
    final text = String.fromCharCodes(bytes);
    if (!text.contains('-----BEGIN ')) {
      _printCertificate(bytes);
      return;
    }
    final blocks = PqX509.pemBlocks(text);
    for (var i = 0; i < blocks.length; i++) {
      if (blocks.length > 1) console.section('block ${i + 1}');
      final block = blocks[i];
      switch (block.label) {
        case 'CERTIFICATE':
        case 'X509 CERTIFICATE':
          _printCertificate(block.der);
        case 'CERTIFICATE REQUEST':
        case 'NEW CERTIFICATE REQUEST':
          _printRequest(block.der);
        case 'PRIVATE KEY':
        case 'EC PRIVATE KEY':
        case 'RSA PRIVATE KEY':
          _printPrivateKey(block.label, block.der);
        default:
          console.detail('kind', block.label, pad: _pad);
          console.detail('bytes', '${block.der.length}', pad: _pad);
      }
    }
  }
}

final class CertVerifyCommand extends Command<void> {
  CertVerifyCommand() {
    argParser
      ..addOption(
        'in',
        mandatory: true,
        valueHelp: 'file',
        help:
            'Leaf PEM or DER. Further PEM blocks are intermediates, leaf first.',
      )
      ..addOption(
        'anchor',
        mandatory: true,
        valueHelp: 'file',
        help:
            'Trust anchor PEM or DER. Several PEM blocks are several anchors.',
      );
    addQuietOption(argParser);
  }

  @override
  String get name => 'verify';

  @override
  String get description => 'Check a chain against a trust anchor.';

  @override
  String get usageFooter =>
      usageExamples(['pqforge cert verify --in leaf.pem --anchor ca.pem']);

  @override
  Future<void> run() async {
    final results = argResults!;
    final chain = _readCertificates(
      await File(results['in'] as String).readAsBytes(),
    );
    final anchors = _readCertificates(
      await File(results['anchor'] as String).readAsBytes(),
    );
    final path = PqX509.validate(
      chain: chain,
      anchors: anchors,
      now: DateTime.now().toUtc(),
    );
    if (!path.trusted) {
      console.failure(path.failure!.name);
      exitCode = 1;
      return;
    }
    if (!quietFrom(results)) console.info('OK');
  }
}

Future<_Built> _signer(
  ArgResults results, {
  String secretName = 'secret',
  String keyName = 'key',
  String publicName = 'public',
}) async {
  final secretPath = results[secretName] as String?;
  final keyPath = results[keyName] as String?;
  if ((secretPath == null) == (keyPath == null)) {
    throw PqForgeException('Provide one of --$secretName or --$keyName.');
  }
  if (keyPath != null) {
    final pem = PqX509.readPrivateKey(await File(keyPath).readAsString());
    return _Built(pem.algorithm, pem.publicKey, pem.sign);
  }
  final passphrase = await passphraseFrom(results);
  final secret = await readKey(secretPath!, passphrase: passphrase);
  final publicPath = results[publicName] as String?;
  final public = publicPath == null ? null : await readKey(publicPath);
  return _identity(secret, public);
}

Future<void> _write(ArgResults results, Uint8List der, String label) async {
  final out = File(results['out'] as String);
  await out.parent.create(recursive: true);
  if (results['der'] as bool) {
    await out.writeAsBytes(der);
  } else {
    await out.writeAsString(PqX509.toPem(der, label: label));
  }
}

String? _cnOf(String? subj) {
  if (subj == null) return null;
  final match = RegExp(r'(?:^|/)CN=([^/+]+)').firstMatch(subj);
  return match?.group(1);
}

final class _Built {
  _Built(this.algorithm, this.publicKey, this.sign);

  final PqX509Algorithm algorithm;
  final PqX509PublicKey publicKey;
  final Uint8List Function(Uint8List tbs) sign;
}

_Built _identity(PqExportedKey secret, PqExportedKey? public) {
  if (secret.algorithmId == PqClassicalSignatureAlgorithm.ecdsaP256.id) {
    requireKind(secret, classicalSignatureSecretKind);
    final derived = PqEcdsaP256.publicKeyFromPrivate(secret.bytes);
    return _Built(
      PqX509Algorithm.ecdsaP256Sha256,
      PqX509EcdsaP256Key(
        _matchPublic(public, derived, classicalSignaturePublicKind),
      ),
      (tbs) => PqX509.encodeEcdsaSignature(
        PqEcdsaP256.sign(privateKey: secret.bytes, message: tbs),
      ),
    );
  }
  if (secret.algorithmId == PqClassicalSignatureAlgorithm.ed25519.id) {
    requireKind(secret, classicalSignatureSecretKind);
    final derived = PqEd25519.publicKeyFromSeed(secret.bytes);
    return _Built(
      PqX509Algorithm.ed25519,
      PqX509Ed25519Key(
        _matchPublic(public, derived, classicalSignaturePublicKind),
      ),
      (tbs) => PqEd25519.sign(secretKey: secret.bytes, message: tbs),
    );
  }
  final ml = PqSignatureAlgorithm.tryById(secret.algorithmId);
  if (ml != null) {
    if (public == null) {
      throw PqForgeException(
        '${ml.id} needs --public. The secret does not carry the public key.',
      );
    }
    requireKind(secret, PqKeyKind.signatureSecret);
    requireKind(public, PqKeyKind.signaturePublic);
    if (public.bytes.length != ml.publicKeyBytes) {
      throw PqForgeException(
        'Public key length ${public.bytes.length} is not ${ml.id}.',
      );
    }
    final algorithm = switch (ml) {
      PqSignatureAlgorithm.mlDsa44 => PqX509Algorithm.mlDsa44,
      PqSignatureAlgorithm.mlDsa65 => PqX509Algorithm.mlDsa65,
      PqSignatureAlgorithm.mlDsa87 => PqX509Algorithm.mlDsa87,
    };
    return _Built(
      algorithm,
      PqX509MlDsaKey(algorithm, public.bytes),
      (tbs) => PqSignaturePrimitives.sign(ml, secret.bytes, tbs),
    );
  }
  throw PqForgeException(
    'Cannot issue a certificate with ${secret.algorithmId}.',
  );
}

Uint8List _matchPublic(PqExportedKey? public, Uint8List derived, String kind) {
  if (public == null) return derived;
  requireKind(public, kind);
  if (public.bytes.length != derived.length) {
    throw const PqForgeException('Public key does not match the secret.');
  }
  for (var i = 0; i < derived.length; i++) {
    if (public.bytes[i] != derived[i]) {
      throw const PqForgeException('Public key does not match the secret.');
    }
  }
  return derived;
}

Uint8List _serial() {
  final serial = Uint8List(16);
  final random = Random.secure();
  for (var i = 0; i < serial.length; i++) {
    serial[i] = random.nextInt(256);
  }
  if (serial.every((byte) => byte == 0)) serial[15] = 1;
  return serial;
}

List<Uint8List> _readCertificates(Uint8List bytes) {
  if (bytes.isEmpty) {
    throw const PqForgeException('Certificate file is empty.');
  }
  if (String.fromCharCodes(bytes).contains('-----BEGIN ')) {
    return PqX509.fromPem(String.fromCharCodes(bytes));
  }
  return [bytes];
}

String _algorithmName(PqX509Algorithm algorithm) => switch (algorithm) {
  PqX509Algorithm.ecdsaP256Sha256 => 'ecdsa-with-SHA256',
  PqX509Algorithm.ecdsaP384Sha384 => 'ecdsa-with-SHA384',
  PqX509Algorithm.ed25519 => 'Ed25519',
  PqX509Algorithm.mlDsa44 => 'ML-DSA-44',
  PqX509Algorithm.mlDsa65 => 'ML-DSA-65',
  PqX509Algorithm.mlDsa87 => 'ML-DSA-87',
  PqX509Algorithm.rsaPkcs1Sha256 => 'sha256WithRSAEncryption',
  PqX509Algorithm.rsaPkcs1Sha384 => 'sha384WithRSAEncryption',
  PqX509Algorithm.rsaPkcs1Sha512 => 'sha512WithRSAEncryption',
  PqX509Algorithm.rsaPssSha256 => 'RSASSA-PSS-SHA256',
  PqX509Algorithm.rsaPssSha384 => 'RSASSA-PSS-SHA384',
  PqX509Algorithm.rsaPssSha512 => 'RSASSA-PSS-SHA512',
};

const _pad = 12;

void _printCertificate(Uint8List der) {
  final parsed = PqX509.parse(der);
  final certificate = parsed.certificate;
  if (certificate == null) {
    throw PqForgeException(
      'Certificate did not parse (${parsed.failure!.name}).',
    );
  }
  console.detail('kind', 'certificate', pad: _pad);
  console.detail('version', '${certificate.version}', pad: _pad);
  console.detail('serial', _hex(certificate.serial), pad: _pad);
  console.detail('algorithm', _algorithmName(certificate.algorithm), pad: _pad);
  if (certificate.pssSaltLength != null) {
    console.detail('pss salt', '${certificate.pssSaltLength}', pad: _pad);
  }
  console.detail('issuer', _name(certificate.issuerDer), pad: _pad);
  console.detail('subject', _name(certificate.subjectDer), pad: _pad);
  console.detail(
    'not before',
    certificate.notBefore.toIso8601String(),
    pad: _pad,
  );
  console.detail(
    'not after',
    certificate.notAfter.toIso8601String(),
    pad: _pad,
  );
  console.detail('public key', _keyText(certificate.publicKey), pad: _pad);
  if (certificate.ca != null) {
    final path = certificate.pathLen == null
        ? ''
        : ', pathlen ${certificate.pathLen}';
    console.detail('ca', '${certificate.ca}$path', pad: _pad);
  }
  if (certificate.keyUsageBits != null) {
    console.detail(
      'key usage',
      _keyUsage(certificate.keyUsageBits!),
      pad: _pad,
    );
  }
  if (certificate.extKeyUsage.isNotEmpty) {
    console.detail(
      'eku',
      certificate.extKeyUsage.map(_dotted).join(', '),
      pad: _pad,
    );
  }
  if (certificate.subjectAltNames.isNotEmpty) {
    console.detail(
      'san',
      certificate.subjectAltNames.map(_generalName).join(', '),
      pad: _pad,
    );
  }
  if (certificate.mustStaple) console.detail('must staple', 'yes', pad: _pad);
  for (final extension in certificate.extensions) {
    final flag = extension.critical ? ' critical' : '';
    console.detail('extension', '${extension.oid.join('.')}$flag', pad: _pad);
  }
  console.detail(
    'signature',
    PqX509.checkSignature(certificate, certificate.publicKey)
        ? 'valid under this public key'
        : 'not signed by this public key',
    pad: _pad,
  );
  console.detail('bytes', '${der.length}', pad: _pad);
}

void _printRequest(Uint8List der) {
  final parsed = PqX509.parseRequest(der);
  final request = parsed.request;
  if (request == null) {
    throw PqForgeException('Request did not parse (${parsed.failure!.name}).');
  }
  console.detail('kind', 'request', pad: _pad);
  console.detail('algorithm', _algorithmName(request.algorithm), pad: _pad);
  if (request.pssSaltLength != null) {
    console.detail('pss salt', '${request.pssSaltLength}', pad: _pad);
  }
  console.detail('subject', _name(request.subject.der), pad: _pad);
  console.detail('public key', _keyText(request.publicKey), pad: _pad);
  if (request.hasBasic) {
    final path = request.pathLen == null ? '' : ', pathlen ${request.pathLen}';
    console.detail('ca', '${request.ca == true}$path', pad: _pad);
  }
  if (request.keyUsageBits != null) {
    console.detail('key usage', _keyUsage(request.keyUsageBits!), pad: _pad);
  }
  final eku = [
    if (request.serverAuth) 'serverAuth',
    if (request.clientAuth) 'clientAuth',
  ];
  if (eku.isNotEmpty) console.detail('eku', eku.join(', '), pad: _pad);
  if (request.names.isNotEmpty) {
    console.detail(
      'san',
      request.names.map(_generalName).join(', '),
      pad: _pad,
    );
  }
  console.detail(
    'signature',
    PqX509.checkRequest(request) ? 'valid' : 'invalid',
    pad: _pad,
  );
  console.detail('bytes', '${der.length}', pad: _pad);
}

void _printPrivateKey(String label, Uint8List der) {
  final PqX509PrivateKey key;
  try {
    key = PqX509.readPrivateKey(PqX509.toPem(der, label: label));
  } on FormatException catch (error) {
    throw PqForgeException('Private key did not parse (${error.message}).');
  }
  console.detail('kind', label, pad: _pad);
  console.detail('algorithm', _algorithmName(key.algorithm), pad: _pad);
  console.detail('public key', _keyText(key.publicKey), pad: _pad);
  console.detail('secret', 'not printed', pad: _pad);
}

String _keyText(PqX509PublicKey key) => switch (key) {
  PqX509EcdsaP256Key() => 'ECDSA P-256 ${_preview(key.uncompressed)}',
  PqX509EcdsaP384Key() => 'ECDSA P-384 ${_preview(key.uncompressed)}',
  PqX509Ed25519Key() => 'Ed25519 ${_preview(key.raw)}',
  PqX509MlDsaKey() => '${_algorithmName(key.algorithm)} ${_preview(key.raw)}',
  PqX509RsaKey() =>
    'RSA ${_bits(key.modulus)} e=${_unsigned(key.exponent)} ${_preview(key.modulus)}',
};

String _keyUsage(int bits) {
  const names = [
    'digitalSignature',
    'nonRepudiation',
    'keyEncipherment',
    'dataEncipherment',
    'keyAgreement',
    'keyCertSign',
    'cRLSign',
    'encipherOnly',
    'decipherOnly',
  ];
  final used = <String>[];
  for (var i = 0; i < names.length; i++) {
    if ((bits & (1 << i)) != 0) used.add(names[i]);
  }
  return used.isEmpty ? 'none' : used.join(', ');
}

String _generalName(PqX509GeneralName name) => switch (name) {
  PqX509DnsName() => 'DNS:${name.ascii}',
  PqX509Ip4Name() => 'IP:${name.octets.join('.')}',
  PqX509Ip6Name() => 'IP:${_hex(name.octets)}',
  PqX509EmailName() => 'email:${name.mailbox}',
  PqX509UriName() => 'URI:${name.uri}',
  PqX509DirectoryName() => 'dir:${_name(name.name)}',
  PqX509OtherName() => 'otherName',
};

String _name(Uint8List der) {
  final outer = _tlv(der, 0);
  if (outer == null || outer.tag != 0x30 || outer.total != der.length) {
    return _commonName(der);
  }
  final parts = <String>[];
  var offset = 0;
  while (offset < outer.value.length) {
    final set = _tlv(outer.value, offset);
    if (set == null || set.tag != 0x31) return _commonName(der);
    final rdn = <String>[];
    var inner = 0;
    while (inner < set.value.length) {
      final atv = _tlv(set.value, inner);
      if (atv == null || atv.tag != 0x30) return _commonName(der);
      final oid = _tlv(atv.value, 0);
      if (oid == null || oid.tag != 0x06) return _commonName(der);
      final value = _tlv(atv.value, oid.total);
      if (value == null) return _commonName(der);
      rdn.add('${_attr(oid.value)}=${_chars(value.value)}');
      inner += atv.total;
    }
    parts.add(rdn.join('+'));
    offset += set.total;
  }
  return parts.isEmpty ? _commonName(der) : parts.join(', ');
}

String _attr(Uint8List oid) {
  if (_rawIs(oid, const [0x55, 0x04, 0x03])) return 'CN';
  if (_rawIs(oid, const [0x55, 0x04, 0x06])) return 'C';
  if (_rawIs(oid, const [0x55, 0x04, 0x07])) return 'L';
  if (_rawIs(oid, const [0x55, 0x04, 0x08])) return 'ST';
  if (_rawIs(oid, const [0x55, 0x04, 0x0a])) return 'O';
  if (_rawIs(oid, const [0x55, 0x04, 0x0b])) return 'OU';
  if (_rawIs(oid, const [
    0x2a,
    0x86,
    0x48,
    0x86,
    0xf7,
    0x0d,
    0x01,
    0x09,
    0x01,
  ])) {
    return 'emailAddress';
  }
  return _dotted(_decodeOid(oid) ?? const [0]);
}

String _dotted(List<int> arcs) {
  const server = [1, 3, 6, 1, 5, 5, 7, 3, 1];
  const client = [1, 3, 6, 1, 5, 5, 7, 3, 2];
  if (_arcsEqual(arcs, server)) return 'serverAuth';
  if (_arcsEqual(arcs, client)) return 'clientAuth';
  return arcs.join('.');
}

bool _arcsEqual(List<int> a, List<int> b) {
  if (a.length != b.length) return false;
  for (var i = 0; i < a.length; i++) {
    if (a[i] != b[i]) return false;
  }
  return true;
}

String _chars(Uint8List bytes) {
  try {
    return utf8.decode(bytes);
  } on FormatException {
    return _hex(bytes);
  }
}

String _hex(Uint8List bytes) =>
    bytes.map((byte) => byte.toRadixString(16).padLeft(2, '0')).join();

String _preview(Uint8List bytes) {
  if (bytes.length <= 20) return _hex(bytes);
  return '${_hex(Uint8List.sublistView(bytes, 0, 8))}… ${bytes.length} bytes';
}

int _bits(Uint8List modulus) {
  var bits = (modulus.length - 1) * 8;
  var top = modulus[0];
  while (top > 0) {
    bits++;
    top >>= 1;
  }
  return bits;
}

int _unsigned(Uint8List bytes) {
  var value = 0;
  for (final byte in bytes) {
    value = (value << 8) | byte;
  }
  return value;
}

List<int>? _decodeOid(Uint8List contents) {
  if (contents.isEmpty) return null;
  final arcs = <int>[contents[0] ~/ 40, contents[0] % 40];
  var value = 0;
  var pending = false;
  for (var i = 1; i < contents.length; i++) {
    value = (value << 7) | (contents[i] & 0x7f);
    pending = true;
    if ((contents[i] & 0x80) == 0) {
      arcs.add(value);
      value = 0;
      pending = false;
    }
  }
  return pending ? null : arcs;
}

bool _rawIs(Uint8List oid, List<int> expected) {
  if (oid.length != expected.length) return false;
  for (var i = 0; i < oid.length; i++) {
    if (oid[i] != expected[i]) return false;
  }
  return true;
}

final class _Tlv {
  _Tlv(this.tag, this.value, this.total);

  final int tag;
  final Uint8List value;
  final int total;
}

_Tlv? _tlv(Uint8List bytes, int offset) {
  if (offset + 1 >= bytes.length) return null;
  final tag = bytes[offset];
  var length = bytes[offset + 1];
  var header = 2;
  if (length & 0x80 != 0) {
    final count = length & 0x7f;
    if (count == 0 || count > 3 || offset + 2 + count > bytes.length) {
      return null;
    }
    length = 0;
    for (var i = 0; i < count; i++) {
      length = (length << 8) | bytes[offset + 2 + i];
    }
    header = 2 + count;
  }
  if (offset + header + length > bytes.length) return null;
  return _Tlv(
    tag,
    Uint8List.sublistView(bytes, offset + header, offset + header + length),
    header + length,
  );
}

String _commonName(Uint8List name) {
  const oid = [0x06, 0x03, 0x55, 0x04, 0x03];
  for (var i = 0; i + oid.length + 2 < name.length; i++) {
    var match = true;
    for (var j = 0; j < oid.length; j++) {
      if (name[i + j] != oid[j]) match = false;
    }
    if (!match) continue;
    final tagAt = i + oid.length;
    final tag = name[tagAt];
    if (tag != 0x13 && tag != 0x0c) continue;
    final length = name[tagAt + 1];
    if (length >= 0x80 || tagAt + 2 + length > name.length) continue;
    return 'CN=${String.fromCharCodes(name.sublist(tagAt + 2, tagAt + 2 + length))}';
  }
  return '${name.length} bytes';
}
