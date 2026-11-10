/// `compose-sign` / `compose-verify`: two or three explicit signature legs.
library;

import 'dart:io';
import 'dart:typed_data';

import 'package:args/command_runner.dart';
import 'package:pqforge/pqforge.dart';

import 'console.dart';
import 'progress_reporter.dart';
import 'support.dart';

/// Opt-in dual or triple signature. Each flag is one leg. Nothing is implied.
final class ComposeSignCommand extends Command<void> {
  ComposeSignCommand() {
    argParser
      ..addOption(
        'ml-dsa-secret',
        valueHelp: 'file',
        help: 'Optional ML-DSA secret. One leg. Omit it to leave ML-DSA out.',
      )
      ..addOption(
        'slh-secret',
        valueHelp: 'file',
        help: 'Optional SLH-DSA secret. One leg. Omit it to leave SLH-DSA out.',
      )
      ..addMultiOption(
        'classical-secret',
        valueHelp: 'file',
        help:
            'Optional classical secret. Repeat for a second classical leg. '
            'Ed25519, ECDSA-P256, ECDSA-P384, or ECDSA-P521.',
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
        help: 'Composite signature JSON output file.',
      )
      ..addOption(
        'context',
        valueHelp: 'string',
        help: 'Optional domain-separation context bound into every leg.',
      )
      ..addOption(
        'policy',
        allowed: ['require-all', 'accept-any'],
        defaultsTo: 'require-all',
        valueHelp: 'policy',
        help:
            'require-all fails unless every leg verifies. accept-any '
            'succeeds when one leg verifies.',
      )
      ..addFlag(
        'digest',
        negatable: false,
        help:
            'Sign the streamed SHA-256 of the input. Recorded in the JSON. '
            'compose-verify re-hashes.',
      );
    addPassphraseOptions(argParser);
    addQuietOption(argParser);
  }

  @override
  String get name => 'compose-sign';

  @override
  String get description =>
      'Sign with 2 or 3 opted-in algorithms (ML-DSA, SLH-DSA, Ed25519, '
      'ECDSA P-256/P-384/P-521).';

  @override
  String get usageFooter => usageExamples([
    '# Dual: ML-DSA + SLH-DSA',
    'pqforge compose-sign \\',
    '  --ml-dsa-secret keys/vault.sign.secret.wrapped.json \\',
    '  --slh-secret keys/vault.slh-dsa-shake-128f.secret.wrapped.json \\',
    '  --passphrase-env PQFORGE_PASSPHRASE \\',
    '  --in release.bin --out release.dual.json',
    '# Triple: ML-DSA + SLH-DSA + ECDSA-P384',
    'pqforge compose-sign \\',
    '  --ml-dsa-secret keys/vault.sign.secret.wrapped.json \\',
    '  --slh-secret keys/vault.slh-dsa-shake-128f.secret.wrapped.json \\',
    '  --classical-secret keys/vault.ecdsa-p384.secret.wrapped.json \\',
    '  --passphrase-env PQFORGE_PASSPHRASE \\',
    '  --in release.bin --out release.triple.json',
  ]);

  @override
  Future<void> run() async {
    final results = argResults!;
    final passphrase = await passphraseFrom(results);
    final quiet = quietFrom(results);
    final mlPath = results['ml-dsa-secret'] as String?;
    final slhPath = results['slh-secret'] as String?;
    final classicalPaths = results['classical-secret'] as List<String>;
    final legCount =
        (mlPath == null ? 0 : 1) +
        (slhPath == null ? 0 : 1) +
        classicalPaths.length;
    if (legCount < 2 || legCount > 3) {
      usageException(
        'compose-sign needs 2 or 3 legs (dual or triple), got $legCount. '
        'Pass --ml-dsa-secret, --slh-secret, and/or repeatable '
        '--classical-secret.',
      );
    }

    Uint8List? mlSecret;
    PqSignatureAlgorithm? mlAlgorithm;
    if (mlPath != null) {
      final key = await readKey(mlPath, passphrase: passphrase);
      requireKind(key, PqKeyKind.signatureSecret);
      requireMlDsaSignatureKey(key);
      mlSecret = key.bytes;
      mlAlgorithm = PqSignatureAlgorithm.byId(key.algorithmId);
    }
    Uint8List? slhSecret;
    PqSlhDsaAlgorithm? slhAlgorithm;
    if (slhPath != null) {
      final key = await readKey(slhPath, passphrase: passphrase);
      requireKind(key, PqKeyKind.signatureSecret);
      slhAlgorithm = PqSlhDsaAlgorithm.tryById(key.algorithmId);
      if (slhAlgorithm == null) {
        throw PqForgeException(
          'Expected an SLH-DSA secret, got ${key.algorithmId}.',
        );
      }
      slhSecret = key.bytes;
    }
    final classical = <PqClassicalSignatureKeyPair>[];
    for (final path in classicalPaths) {
      final key = await readKey(path, passphrase: passphrase);
      requireKind(key, classicalSignatureSecretKind);
      final algorithm = PqClassicalSignatureAlgorithm.byId(key.algorithmId);
      final signer = PqForgeHybridSigner(classicalAlgorithm: algorithm);
      classical.add(await signer.classicalKeyPairFromSecret(key.bytes));
    }

    final digestMode = results['digest'] as bool;
    final input = File(results['in'] as String);
    final fileName = input.uri.pathSegments.last;
    final output = File(results['out'] as String);
    final policy = PqCompositePolicy.byId(results['policy'] as String);
    final composer = PqForgeSignatureComposer(
      profile: mlAlgorithm == null
          ? PqForgeProfile.compact
          : profileForSignature(mlAlgorithm),
    );
    await withFileProgress(
      quiet: quiet,
      operation: digestMode ? 'digest-signing' : 'signing',
      path: fileName,
      bytes: await input.length(),
      action: (progress) async {
        final message = digestMode
            ? await digestMessageOfFile(
                input,
                onProgress: (processed, total) => progress.updateBytes(
                  processed: processed,
                  totalBytes: total,
                ),
              )
            : await input.readAsBytes();
        final signature = await composer.sign(
          message: message,
          mlDsaSecret: mlSecret,
          mlDsa: mlAlgorithm,
          slhSecret: slhSecret,
          slhDsa: slhAlgorithm,
          classical: classical,
          policy: policy,
          context: optionalContext(results),
          digest: digestMode,
        );
        await writeJson(output, signature.toJson());
      },
    );
    if (!quiet) {
      console.detail(
        'legs',
        [
          if (mlAlgorithm != null) mlAlgorithm.id,
          if (slhAlgorithm != null) slhAlgorithm.id,
          for (final key in classical) key.algorithm.id,
        ].join(' + '),
      );
      console.detail('policy', policy.id);
      console.created(output.path);
    }
  }
}

/// Verifies a composite signature. Pass the public key for each leg you want
/// checked. A missing key makes that leg fail.
final class ComposeVerifyCommand extends Command<void> {
  ComposeVerifyCommand() {
    argParser
      ..addOption(
        'ml-dsa-public',
        valueHelp: 'file',
        help: 'ML-DSA public key, when the signature has an ML-DSA leg.',
      )
      ..addOption(
        'slh-public',
        valueHelp: 'file',
        help: 'SLH-DSA public key, when the signature has an SLH-DSA leg.',
      )
      ..addMultiOption(
        'classical-public',
        valueHelp: 'file',
        help: 'Classical public key. Repeat once per classical leg.',
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
        help: 'Composite signature JSON from compose-sign.',
      )
      ..addOption(
        'policy',
        allowed: ['require-all', 'accept-any'],
        defaultsTo: 'require-all',
        valueHelp: 'policy',
        help:
            'Caller policy. Must equal the policy in the signature file. '
            'The file cannot widen require-all into accept-any.',
      );
    addQuietOption(argParser);
  }

  @override
  String get name => 'compose-verify';

  @override
  String get description =>
      'Verify a 2-leg or 3-leg composite signature from compose-sign.';

  @override
  String get usageFooter => usageExamples([
    'pqforge compose-verify \\',
    '  --ml-dsa-public keys/vault.sign.public.json \\',
    '  --slh-public keys/vault.slh-dsa-shake-128f.public.json \\',
    '  --classical-public keys/vault.ecdsa-p384.public.json \\',
    '  --in release.bin --signature release.triple.json',
  ]);

  @override
  Future<void> run() async {
    final results = argResults!;
    final quiet = quietFrom(results);
    final signature = PqCompositeSignature.fromJson(
      await readJsonMap(File(results['signature'] as String)),
    );
    final policy = PqCompositePolicy.byId(results['policy'] as String);
    if (signature.policy != policy) {
      throw PqForgeException(
        'Composite signature policy is ${signature.policy.id}, not '
        '${policy.id}. Pass the same --policy that compose-sign recorded. '
        'The file cannot change the verification policy.',
      );
    }
    final mlPath = results['ml-dsa-public'] as String?;
    Uint8List? mlPublic;
    if (mlPath != null) {
      final key = await readKey(mlPath);
      requireKind(key, PqKeyKind.signaturePublic);
      requireMlDsaSignatureKey(key);
      mlPublic = key.bytes;
    }
    final slhPath = results['slh-public'] as String?;
    Uint8List? slhPublic;
    if (slhPath != null) {
      final key = await readKey(slhPath);
      requireKind(key, PqKeyKind.signaturePublic);
      if (PqSlhDsaAlgorithm.tryById(key.algorithmId) == null) {
        throw PqForgeException(
          'Expected an SLH-DSA public key, got ${key.algorithmId}.',
        );
      }
      slhPublic = key.bytes;
    }
    final classical = <({String algorithmId, Uint8List publicKey})>[];
    for (final path in results['classical-public'] as List<String>) {
      final key = await readKey(path);
      requireKind(key, classicalSignaturePublicKind);
      PqClassicalSignatureAlgorithm.byId(key.algorithmId);
      classical.add((algorithmId: key.algorithmId, publicKey: key.bytes));
    }

    final input = File(results['in'] as String);
    final fileName = input.uri.pathSegments.last;
    final progress = ProgressReporter(
      total: 1,
      operation: signature.digest ? 'digest-verifying' : 'verifying',
      quiet: quiet,
    );
    progress.startFile(fileName, fileSizeBytes: await input.length());
    late final bool ok;
    try {
      final message = signature.digest
          ? await digestMessageOfFile(
              input,
              onProgress: (processed, total) =>
                  progress.updateBytes(processed: processed, totalBytes: total),
            )
          : await input.readAsBytes();
      ok = await const PqForgeSignatureComposer().verify(
        message: message,
        signature: signature,
        mlDsaPublic: mlPublic,
        slhPublic: slhPublic,
        classicalPublic: classical,
        policy: policy,
      );
      if (ok) {
        progress.completeFile(fileName);
      } else {
        progress.failFile(
          fileName,
          'signature mismatch (${signature.policy.id})',
        );
        exitCode = 1;
      }
    } catch (error) {
      progress.failFile(fileName, error.toString());
      rethrow;
    } finally {
      progress.done();
    }
    if (ok && !quiet) {
      console.detail(
        'legs',
        signature.legs.map((leg) => leg.algorithmId).join(' + '),
      );
      console.detail('policy', signature.policy.id);
    }
  }
}
