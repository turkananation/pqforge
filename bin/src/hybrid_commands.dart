/// Hybrid and classical CLI commands: ML-DSA + Ed25519/ECDSA-P256 dual
/// signatures, and standalone ECDSA-P256 signing and verification.
library;

import 'dart:convert';
import 'dart:io';
import 'dart:typed_data';

import 'package:args/command_runner.dart';
import 'package:pqforge/pqforge.dart';

import 'console.dart';
import 'support.dart';

/// `hybrid-sign` — one ML-DSA signature plus one classical signature
/// (Ed25519 or ECDSA-P256), bound together over the same message.
final class HybridSignCommand extends Command<void> {
  HybridSignCommand() {
    argParser
      ..addOption(
        'signer-secret',
        mandatory: true,
        valueHelp: 'file',
        help:
            'Raw or wrapped ML-DSA secret key JSON (the post-quantum signer).',
      )
      ..addOption(
        'classical-secret',
        mandatory: true,
        valueHelp: 'file',
        help:
            'Raw or wrapped Ed25519/ECDSA-P256 secret key JSON from '
            'keygen --classical.',
      )
      ..addOption(
        'in',
        mandatory: true,
        valueHelp: 'file',
        help: 'Input file to sign.',
      )
      ..addOption(
        'out',
        mandatory: true,
        valueHelp: 'file',
        help: 'Hybrid signature JSON output file.',
      )
      ..addOption(
        'context',
        valueHelp: 'string',
        help: 'Optional domain-separation context bound into the signature.',
      )
      ..addOption(
        'policy',
        allowed: ['require-both', 'accept-either'],
        defaultsTo: 'require-both',
        valueHelp: 'policy',
        help: 'Combination policy recorded for verification.',
      );
    addPassphraseOptions(argParser);
  }

  @override
  String get name => 'hybrid-sign';

  @override
  String get description =>
      'Create an ML-DSA + Ed25519/ECDSA-P256 hybrid (dual) signature.';

  @override
  String get usageFooter => usageExamples([
    '# Pair a maximum-profile ML-DSA key with an ECDSA-P256 key',
    'pqforge hybrid-sign \\',
    '  --signer-secret keys/vault.sign.secret.wrapped.json \\',
    '  --classical-secret keys/vault.ecdsa-p256.secret.wrapped.json \\',
    '  --passphrase-env PQFORGE_PASSPHRASE \\',
    '  --in release.tar.gz --out release.hybrid.json',
  ]);

  @override
  Future<void> run() async {
    final results = argResults!;
    final passphrase = await passphraseFrom(results);

    final pqcSecret = await readKey(
      results['signer-secret'] as String,
      passphrase: passphrase,
    );
    requireKind(pqcSecret, PqKeyKind.signatureSecret);
    final classicalSecret = await readKey(
      results['classical-secret'] as String,
      passphrase: passphrase,
    );
    requireKind(classicalSecret, classicalSignatureSecretKind);

    final pqcAlgorithm = PqSignatureAlgorithm.byId(pqcSecret.algorithmId);
    final classicalAlgorithm = PqClassicalSignatureAlgorithm.byId(
      classicalSecret.algorithmId,
    );
    final signer = PqForgeHybridSigner(
      profile: profileForSignature(pqcAlgorithm),
      classicalAlgorithm: classicalAlgorithm,
    );
    final classicalKeyPair = await signer.classicalKeyPairFromSecret(
      classicalSecret.bytes,
    );

    final message = Uint8List.fromList(
      await File(results['in'] as String).readAsBytes(),
    );
    final context = optionalContext(results);
    final policy = _policyFrom(results['policy'] as String);

    final signature = await signer.sign(
      pqcSecretKey: pqcSecret.bytes,
      classicalKeyPair: classicalKeyPair,
      message: message,
      context: context,
      pqcAlgorithm: pqcAlgorithm,
      policy: policy,
    );

    final json = {
      ...signature.toJson(),
      if (context != null) 'context': base64Encode(context),
    };
    final output = File(results['out'] as String);
    await writeJson(output, json);
    console.success(
      'Hybrid signed (${pqcAlgorithm.name} + ${classicalAlgorithm.id}, '
      '${policy.name})',
    );
    console.created(output.path);
  }
}

/// `hybrid-verify` — verify an ML-DSA + classical hybrid signature.
final class HybridVerifyCommand extends Command<void> {
  HybridVerifyCommand() {
    argParser
      ..addOption(
        'signer-public',
        mandatory: true,
        valueHelp: 'file',
        help: 'ML-DSA public key JSON (the post-quantum signer).',
      )
      ..addOption(
        'classical-public',
        mandatory: true,
        valueHelp: 'file',
        help: 'Ed25519/ECDSA-P256 public key JSON from keygen --classical.',
      )
      ..addOption(
        'in',
        mandatory: true,
        valueHelp: 'file',
        help: 'Signed input file.',
      )
      ..addOption(
        'signature',
        mandatory: true,
        valueHelp: 'file',
        help: 'Hybrid signature JSON file.',
      )
      ..addOption(
        'context',
        valueHelp: 'string',
        help: 'Override the context stored in the signature JSON.',
      );
  }

  @override
  String get name => 'hybrid-verify';

  @override
  String get description =>
      'Verify an ML-DSA + Ed25519/ECDSA-P256 hybrid (dual) signature.';

  @override
  String get usageFooter => usageExamples([
    'pqforge hybrid-verify \\',
    '  --signer-public keys/vault.sign.public.json \\',
    '  --classical-public keys/vault.ecdsa-p256.public.json \\',
    '  --in release.tar.gz --signature release.hybrid.json',
  ]);

  @override
  Future<void> run() async {
    final results = argResults!;
    final pqcPublic = await readKey(results['signer-public'] as String);
    requireKind(pqcPublic, PqKeyKind.signaturePublic);
    final classicalPublic = await readKey(
      results['classical-public'] as String,
    );
    requireKind(classicalPublic, classicalSignaturePublicKind);

    final sigJson = await readJsonMap(File(results['signature'] as String));
    final signature = PqHybridSignature.fromJson(sigJson);

    final classicalKeyAlgorithm = PqClassicalSignatureAlgorithm.byId(
      classicalPublic.algorithmId,
    );
    if (classicalKeyAlgorithm != signature.classicalAlgorithm) {
      throw PqForgeException(
        'Classical key is ${classicalKeyAlgorithm.id} but the signature uses '
        '${signature.classicalAlgorithm.id}.',
      );
    }

    final signer = PqForgeHybridSigner(
      profile: profileForSignature(signature.pqcAlgorithm),
      classicalAlgorithm: signature.classicalAlgorithm,
    );
    final message = Uint8List.fromList(
      await File(results['in'] as String).readAsBytes(),
    );
    final context = optionalContext(results) ?? _storedContext(sigJson);

    final ok = await signer.verify(
      pqcPublicKey: pqcPublic.bytes,
      classicalPublicKey: classicalPublic.bytes,
      message: message,
      signature: signature,
      context: context,
    );
    final label =
        '${signature.pqcAlgorithm.name} + ${signature.classicalAlgorithm.id}, '
        '${signature.policy.name}';
    if (ok) {
      console.success('Hybrid signature verified ($label)');
    } else {
      console.failure('Hybrid signature verification FAILED ($label)');
      exitCode = 1;
    }
  }

  Uint8List? _storedContext(Map<String, Object?> json) {
    final stored = json['context'];
    return stored is String ? base64Decode(stored) : null;
  }
}

/// `ecdsa-sign` — standalone ECDSA over NIST P-256 (RFC 6979, low-S).
final class EcdsaSignCommand extends Command<void> {
  EcdsaSignCommand() {
    argParser
      ..addOption(
        'secret',
        mandatory: true,
        valueHelp: 'file',
        help:
            'Raw or wrapped ECDSA-P256 secret key JSON from '
            'keygen --classical ecdsa-p256.',
      )
      ..addOption(
        'in',
        mandatory: true,
        valueHelp: 'file',
        help: 'Input file to sign.',
      )
      ..addOption(
        'out',
        mandatory: true,
        valueHelp: 'file',
        help: 'Signature JSON output file.',
      );
    addPassphraseOptions(argParser);
  }

  @override
  String get name => 'ecdsa-sign';

  @override
  String get description =>
      'Sign a file with standalone ECDSA-P256 (deterministic, low-S).';

  @override
  String get usageFooter => usageExamples([
    'pqforge ecdsa-sign --secret keys/vault.ecdsa-p256.secret.wrapped.json \\',
    '  --passphrase-env PQFORGE_PASSPHRASE --in firmware.bin --out firmware.ecdsa.json',
  ]);

  @override
  Future<void> run() async {
    final results = argResults!;
    final passphrase = await passphraseFrom(results);
    final secret = await readKey(
      results['secret'] as String,
      passphrase: passphrase,
    );
    requireKind(secret, classicalSignatureSecretKind);
    requireEcdsaKey(secret);

    final message = Uint8List.fromList(
      await File(results['in'] as String).readAsBytes(),
    );
    final signature = PqEcdsaP256.sign(
      privateKey: secret.bytes,
      message: message,
    );
    final output = File(results['out'] as String);
    await writeJson(output, {
      'version': 1,
      'scheme': 'ecdsa-p256',
      'signature': base64Encode(signature),
    });
    console.success('ECDSA-P256 signed');
    console.created(output.path);
  }
}

/// `ecdsa-verify` — verify a standalone ECDSA-P256 signature.
final class EcdsaVerifyCommand extends Command<void> {
  EcdsaVerifyCommand() {
    argParser
      ..addOption(
        'public',
        mandatory: true,
        valueHelp: 'file',
        help: 'ECDSA-P256 public key JSON from keygen --classical ecdsa-p256.',
      )
      ..addOption(
        'in',
        mandatory: true,
        valueHelp: 'file',
        help: 'Signed input file.',
      )
      ..addOption(
        'signature',
        mandatory: true,
        valueHelp: 'file',
        help: 'ECDSA signature JSON file.',
      );
  }

  @override
  String get name => 'ecdsa-verify';

  @override
  String get description => 'Verify a standalone ECDSA-P256 signature.';

  @override
  String get usageFooter => usageExamples([
    'pqforge ecdsa-verify --public keys/vault.ecdsa-p256.public.json \\',
    '  --in firmware.bin --signature firmware.ecdsa.json',
  ]);

  @override
  Future<void> run() async {
    final results = argResults!;
    final public = await readKey(results['public'] as String);
    requireKind(public, classicalSignaturePublicKind);
    requireEcdsaKey(public);

    final message = Uint8List.fromList(
      await File(results['in'] as String).readAsBytes(),
    );
    final sigJson = await readJsonMap(File(results['signature'] as String));
    final signature = base64Decode(sigJson['signature'] as String);

    final ok = PqEcdsaP256.verify(
      publicKey: public.bytes,
      message: message,
      signature: signature,
    );
    if (ok) {
      console.success('ECDSA-P256 signature verified');
    } else {
      console.failure('ECDSA-P256 signature verification FAILED');
      exitCode = 1;
    }
  }
}

PqDualSignaturePolicy _policyFrom(String value) => switch (value) {
  'accept-either' => PqDualSignaturePolicy.acceptEither,
  _ => PqDualSignaturePolicy.requireBoth,
};
