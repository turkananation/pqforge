/// `cert issue`, `cert inspect`, and `cert verify`.
///
/// Issue writes the PEM OpenSSL reads by default. `--der` writes the raw
/// certificate instead. The secret is a keygen file: ECDSA-P256, Ed25519, or
/// ML-DSA. The certificate is self-signed.
library;

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
      help: 'PEM or DER certificate. A PEM file may hold several.',
    );
  }

  @override
  String get name => 'inspect';

  @override
  String get description => 'Print the subject, issuer, dates, and algorithm.';

  @override
  String get usageFooter =>
      usageExamples(['pqforge cert inspect --in localhost.pem']);

  @override
  Future<void> run() async {
    final input = argResults!['in'] as String;
    final bytes = await File(input).readAsBytes();
    final text = String.fromCharCodes(bytes);
    if (text.contains('CERTIFICATE REQUEST')) {
      for (final block in PqX509.pemBlocks(text)) {
        if (block.label != 'CERTIFICATE REQUEST' &&
            block.label != 'NEW CERTIFICATE REQUEST') {
          continue;
        }
        final parsed = PqX509.parseRequest(block.der);
        final request = parsed.request;
        if (request == null) {
          throw PqForgeException(
            'Request did not parse (${parsed.failure!.name}).',
          );
        }
        console.detail('kind', 'request', pad: 12);
        console.detail('algorithm', _algorithmName(request.algorithm), pad: 12);
        console.detail('subject', _commonName(request.subject.der), pad: 12);
        final dns = [
          for (final name in request.names)
            if (name is PqX509DnsName) name.ascii,
        ];
        if (dns.isNotEmpty) console.detail('san', dns.join(', '), pad: 12);
      }
      return;
    }
    final certs = _readCertificates(bytes);
    for (var i = 0; i < certs.length; i++) {
      final parsed = PqX509.parse(certs[i]);
      final certificate = parsed.certificate;
      if (certificate == null) {
        throw PqForgeException(
          'Certificate ${i + 1} did not parse (${parsed.failure!.name}).',
        );
      }
      if (certs.length > 1) console.info('certificate ${i + 1}');
      console.detail(
        'algorithm',
        _algorithmName(certificate.algorithm),
        pad: 12,
      );
      console.detail('subject', _commonName(certificate.subjectDer), pad: 12);
      console.detail('issuer', _commonName(certificate.issuerDer), pad: 12);
      console.detail(
        'not before',
        certificate.notBefore.toIso8601String(),
        pad: 12,
      );
      console.detail(
        'not after',
        certificate.notAfter.toIso8601String(),
        pad: 12,
      );
      console.detail('ca', '${certificate.ca == true}', pad: 12);
      final dns = [
        for (final name in certificate.subjectAltNames)
          if (name is PqX509DnsName) name.ascii,
      ];
      if (dns.isNotEmpty) console.detail('san', dns.join(', '), pad: 12);
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
