/// `cert issue`, `cert inspect`, and `cert verify`.
///
/// Issue writes the PEM OpenSSL reads by default. `--der` writes the raw
/// certificate instead. The secret is a keygen file: ECDSA-P256, Ed25519, or
/// ML-DSA. The certificate is self-signed.
library;

import 'dart:io';
import 'dart:math';
import 'dart:typed_data';

import 'package:args/command_runner.dart';
import 'package:pqforge/pqforge.dart';

import 'console.dart';
import 'support.dart';

final class CertCommand extends Command<void> {
  CertCommand() {
    addSubcommand(CertIssueCommand());
    addSubcommand(CertInspectCommand());
    addSubcommand(CertVerifyCommand());
  }

  @override
  String get name => 'cert';

  @override
  String get description =>
      'Issue, inspect, or verify an X.509 certificate (PEM by default).';

  @override
  String get invocation => 'pqforge cert <issue|inspect|verify> [arguments]';
}

final class CertIssueCommand extends Command<void> {
  CertIssueCommand() {
    argParser
      ..addOption(
        'secret',
        mandatory: true,
        valueHelp: 'file',
        help:
            'Signing secret from keygen: ecdsa-p256, ed25519, or an ML-DSA '
            'sign secret. Wrapped keys need a passphrase.',
      )
      ..addOption(
        'public',
        valueHelp: 'file',
        help:
            'Matching public key. Required for ML-DSA. Derived for '
            'ecdsa-p256 and ed25519 when omitted.',
      )
      ..addOption(
        'cn',
        mandatory: true,
        valueHelp: 'name',
        help: 'Subject common name. Also the DNS SAN when --dns is omitted.',
      )
      ..addMultiOption(
        'dns',
        valueHelp: 'name',
        help: 'DNS subject alternative name. Repeat for more than one.',
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
    'pqforge cert issue --secret keys/ci.ecdsa-p256.secret.wrapped.json \\',
    '  --passphrase-env PQFORGE_PASSPHRASE --cn localhost --out localhost.pem',
  ]);

  @override
  Future<void> run() async {
    final results = argResults!;
    final passphrase = await passphraseFrom(results);
    final secret = await readKey(
      results['secret'] as String,
      passphrase: passphrase,
    );
    final publicPath = results['public'] as String?;
    final public = publicPath == null ? null : await readKey(publicPath);
    final cn = results['cn'] as String;
    final dns = results['dns'] as List<String>;
    final days = int.tryParse(results['days'] as String);
    if (days == null || days < 1 || days > 8250) {
      throw const PqForgeException('--days must be from 1 to 8250.');
    }
    final ca = results['ca'] as bool;
    final built = _identity(secret, public);
    final notBefore = DateTime.now().toUtc();
    final der = PqX509.mint(
      issuer: PqX509Name.commonName(cn),
      subject: PqX509Name.commonName(cn),
      publicKey: built.publicKey,
      algorithm: built.algorithm,
      sign: built.sign,
      notBefore: notBefore,
      notAfter: notBefore.add(Duration(days: days)),
      serial: _serial(),
      subjectAltNames: ca
          ? const []
          : [
              for (final name in (dns.isEmpty ? [cn] : dns))
                PqX509DnsName(name),
            ],
      ca: ca,
      digitalSignature: !ca,
      keyCertSign: ca,
      includeEku: !ca,
    );
    final out = File(results['out'] as String);
    await out.parent.create(recursive: true);
    if (results['der'] as bool) {
      await out.writeAsBytes(der);
    } else {
      await out.writeAsString(PqX509.toPem(der));
    }
    if (!quietFrom(results)) {
      console.detail('algorithm', _algorithmName(built.algorithm), pad: 12);
      console.detail('subject', 'CN=$cn', pad: 12);
      console.created(out.path);
    }
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
    final certs = _readCertificates(await File(input).readAsBytes());
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
