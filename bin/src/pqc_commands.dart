/// Pure post-quantum CLI commands: key generation, file/folder/text/media
/// encryption, and ML-DSA / SLH-DSA recipe signing and verification.
library;

import 'dart:convert';
import 'dart:io';
import 'dart:isolate';
import 'dart:typed_data';

import 'package:args/args.dart';
import 'package:args/command_runner.dart';
import 'package:pqforge/pqforge_io.dart';

import 'console.dart';
import 'progress_reporter.dart';
import 'support.dart';

const _profiles = ['compact', 'balanced', 'maximum'];
const _classicalAlgorithms = ['x25519', 'ed25519', 'ecdsa-p256'];

/// `keygen` — ML-KEM + ML-DSA bundles, profile-matched SLH-DSA keys, plus the
/// classical keypairs that make every hybrid workflow work out of the box.
final class KeygenCommand extends Command<void> {
  KeygenCommand() {
    argParser
      ..addOption(
        'profile',
        allowed: _profiles,
        defaultsTo: 'maximum',
        valueHelp: 'name',
        help:
            'Composition profile for the ML-KEM/ML-DSA bundle and the '
            'default SLH-DSA parameter set.',
      )
      ..addOption(
        'key-id',
        defaultsTo: 'pqforge-key',
        valueHelp: 'id',
        help: 'Key identifier embedded in exported key JSON and filenames.',
      )
      ..addOption(
        'out-dir',
        abbr: 'o',
        defaultsTo: '.',
        valueHelp: 'dir',
        help: 'Directory to receive exported key JSON files.',
      )
      ..addMultiOption(
        'classical',
        allowed: _classicalAlgorithms,
        valueHelp: 'algo',
        help:
            'Limit the classical keypairs to specific algorithms (default: '
            'all of x25519, ed25519, ecdsa-p256). x25519 is the hybrid '
            'encryption key; ed25519/ecdsa-p256 are hybrid signer keys.',
      )
      ..addFlag(
        'no-classical',
        negatable: false,
        help: 'Generate only the post-quantum keys (skip classical keys).',
      )
      ..addFlag(
        'classical-only',
        negatable: false,
        help: 'Skip ML-KEM/ML-DSA/SLH-DSA and emit only classical keys.',
      )
      ..addMultiOption(
        'slh-dsa',
        allowed: PqSlhDsaAlgorithm.ids,
        valueHelp: 'algo',
        help:
            'Limit SLH-DSA keypairs to specific FIPS 205 parameter sets '
            '(default: the profile-matched SHAKE-f set — compact 128f, '
            'balanced 192f, maximum 256f). Repeat to emit several sets.',
      )
      ..addFlag(
        'no-slh-dsa',
        negatable: false,
        help: 'Skip SLH-DSA key generation.',
      )
      ..addFlag(
        'slh-dsa-only',
        negatable: false,
        help: 'Skip ML-KEM/ML-DSA and classical; emit only SLH-DSA keys.',
      )
      ..addFlag(
        'quiet',
        abbr: 'q',
        negatable: false,
        help: 'Mute verbose line-by-line file completion summaries.',
      )
      ..addOption(
        'argon-iterations',
        defaultsTo: '2',
        valueHelp: 'n',
        help: 'Argon2id iterations used when wrapping secret keys.',
      )
      ..addOption(
        'argon-memory-power-of-2',
        defaultsTo: '16',
        valueHelp: 'n',
        help: 'Argon2id memory exponent used when wrapping secret keys.',
      )
      ..addOption(
        'argon-lanes',
        defaultsTo: '4',
        valueHelp: 'n',
        help: 'Argon2id lanes used when wrapping secret keys.',
      )
      ..addOption(
        'wrap-concurrency',
        defaultsTo: '2',
        valueHelp: 'n',
        help:
            'Secret keys wrapped in parallel (1-4). Each Argon2id instance '
            'holds 2^argon-memory-power-of-2 KiB (default 64 MiB), so raise '
            'this only on machines with RAM to spare.',
      );
    addPassphraseOptions(argParser);
    addQuietOption(argParser);
  }

  @override
  String get name => 'keygen';

  @override
  String get description =>
      'Generate ML-KEM/ML-DSA, SLH-DSA, and classical (hybrid) key material.';

  @override
  String get usageFooter => usageExamples([
    '# Wrapped maximum-profile bundle + SLH-DSA-SHAKE-256f + hybrid keys',
    'pqforge keygen --profile maximum --key-id vault --out-dir keys \\',
    '  --passphrase-env PQFORGE_PASSPHRASE',
    '# Post-quantum bundle only (ML-KEM + ML-DSA + profile SLH-DSA)',
    'pqforge keygen --key-id vault --out-dir keys --no-classical \\',
    '  --passphrase-env PQFORGE_PASSPHRASE',
    '# Specific SLH-DSA sets (and skip the profile default extras)',
    'pqforge keygen --slh-dsa slh-dsa-shake-128f --slh-dsa slh-dsa-sha2-128s \\',
    '  --no-classical --key-id archive --out-dir keys',
  ]);

  @override
  Future<void> run() async {
    final results = argResults!;
    final profile = PqForgeProfile.byName(results['profile'] as String);
    final keyId = results['key-id'] as String;
    final outDir = Directory(results['out-dir'] as String);
    final classicalOnly = results['classical-only'] as bool;
    final noClassical = results['no-classical'] as bool;
    final selectedClassical = results['classical'] as List<String>;
    final slhDsaOnly = results['slh-dsa-only'] as bool;
    final noSlhDsa = results['no-slh-dsa'] as bool;
    final selectedSlh = results['slh-dsa'] as List<String>;
    if (noClassical && (classicalOnly || selectedClassical.isNotEmpty)) {
      throw const PqForgeException(
        '--no-classical cannot be combined with --classical/--classical-only.',
      );
    }
    if (noSlhDsa && (slhDsaOnly || selectedSlh.isNotEmpty)) {
      throw const PqForgeException(
        '--no-slh-dsa cannot be combined with --slh-dsa/--slh-dsa-only.',
      );
    }
    if (slhDsaOnly && classicalOnly) {
      throw const PqForgeException(
        '--slh-dsa-only cannot be combined with --classical-only.',
      );
    }
    if (slhDsaOnly && selectedClassical.isNotEmpty) {
      throw const PqForgeException(
        '--slh-dsa-only cannot be combined with --classical.',
      );
    }
    // All classical keys by default: hybrid encryption and hybrid signing then
    // work out of the box. --classical narrows, --no-classical / --slh-dsa-only
    // opts out.
    final classical = noClassical || slhDsaOnly
        ? const <String>[]
        : (selectedClassical.isEmpty
              ? _classicalAlgorithms
              : selectedClassical);
    final emitPqc = !classicalOnly && !slhDsaOnly;
    final slhAlgorithms = _slhDsaAlgorithms(
      profile: profile,
      noSlhDsa: noSlhDsa,
      slhDsaOnly: slhDsaOnly,
      classicalOnly: classicalOnly,
      selected: selectedSlh,
    );
    final passphrase = await passphraseFrom(results);
    await outDir.create(recursive: true);

    final publicFiles = <String, PqExportedKey>{};
    final secretFiles = <String, PqExportedKey>{};
    final forge = PqForge(profile: profile);

    if (emitPqc) {
      final bundle = forge.generateKeys(keyId: keyId);
      publicFiles['$keyId.kem.public.json'] = bundle.exportKemPublicKey();
      publicFiles['$keyId.sign.public.json'] = bundle
          .exportSignaturePublicKey();
      secretFiles['$keyId.kem.secret.json'] = bundle.exportKemSecretKey();
      secretFiles['$keyId.sign.secret.json'] = bundle
          .exportSignatureSecretKey();
    }

    for (final algorithm in slhAlgorithms) {
      final pair = forge.generateSlhDsaKeyPair(algorithm: algorithm);
      publicFiles['$keyId.${algorithm.fileStem}.public.json'] = forge
          .exportSlhDsaPublicKey(pair, algorithm: algorithm, keyId: keyId);
      secretFiles['$keyId.${algorithm.fileStem}.secret.json'] = forge
          .exportSlhDsaSecretKey(pair, algorithm: algorithm, keyId: keyId);
    }

    // The classical generators are independent async work — run them
    // concurrently instead of awaiting one keypair at a time.
    final classicalPairs = await Future.wait(
      classical.map((algo) => _generateClassical(algo, keyId)),
    );
    for (var i = 0; i < classical.length; i++) {
      publicFiles['$keyId.${classical[i]}.public.json'] =
          classicalPairs[i].public;
      secretFiles['$keyId.${classical[i]}.secret.json'] =
          classicalPairs[i].secret;
    }

    if (publicFiles.isEmpty && secretFiles.isEmpty) {
      throw const PqForgeException(
        '--classical-only cannot be combined with an empty classical set.',
      );
    }

    for (final entry in publicFiles.entries) {
      await writeJson(outDir.child(entry.key), entry.value.toJson());
    }
    final quiet = quietFrom(results);
    final wrapProgress = passphrase != null && secretFiles.isNotEmpty
        ? ProgressReporter(
            total: secretFiles.length,
            operation: 'wrapping keys',
            quiet: quiet,
          )
        : null;
    try {
      await _writeSecrets(
        secretFiles,
        outDir,
        passphrase,
        results,
        progress: wrapProgress,
      );
    } finally {
      wrapProgress?.done();
    }

    if (!quiet) {
      console.section(
        _keygenSectionTitle(
          emitPqc: emitPqc,
          slhAlgorithms: slhAlgorithms,
          classicalOnly: classicalOnly,
          slhDsaOnly: slhDsaOnly,
          profile: profile,
        ),
      );
      if (emitPqc) {
        console.detail('profile', profile.name);
        console.detail(
          'pqc',
          '${profile.kem.name} (encryption) · ${profile.signature.name} '
              '(signatures)',
        );
      }
      if (slhAlgorithms.isNotEmpty) {
        console.detail(
          'slh-dsa',
          slhAlgorithms.map((algorithm) => algorithm.name).join(' · '),
        );
      }
      if (classical.isNotEmpty) {
        console.detail(
          'classical',
          [
            if (classical.contains('x25519')) 'X25519 (hybrid encryption)',
            if (classical.contains('ed25519')) 'Ed25519 (hybrid signing)',
            if (classical.contains('ecdsa-p256')) 'ECDSA-P256 (hybrid signing)',
          ].join(' · '),
        );
      }
      if (emitPqc && classical.contains('x25519')) {
        console.detail(
          'hybrid',
          'encrypt --hybrid → ${suiteLabel(profile, hybrid: true)}',
        );
      }
      for (final name in publicFiles.keys) {
        console.created(outDir.child(name).path);
      }
      for (final name in secretFiles.keys) {
        final path = passphrase == null
            ? outDir.child(name).path
            : outDir.child(name.replaceFirst('.json', '.wrapped.json')).path;
        console.created(path);
      }
    }
    if (passphrase == null && secretFiles.isNotEmpty) {
      console.warn(
        'wrote raw secret-key JSON. Pass --passphrase-env, --passphrase-file, '
        'or --passphrase to wrap secrets with Argon2id + AES-256-GCM.',
      );
    }
  }

  List<PqSlhDsaAlgorithm> _slhDsaAlgorithms({
    required PqForgeProfile profile,
    required bool noSlhDsa,
    required bool slhDsaOnly,
    required bool classicalOnly,
    required List<String> selected,
  }) {
    if (noSlhDsa) return const [];
    if (selected.isNotEmpty) {
      return [for (final id in selected) PqSlhDsaAlgorithm.byId(id)];
    }
    if (slhDsaOnly || !classicalOnly) return [profile.slhDsa];
    return const [];
  }

  String _keygenSectionTitle({
    required bool emitPqc,
    required List<PqSlhDsaAlgorithm> slhAlgorithms,
    required bool classicalOnly,
    required bool slhDsaOnly,
    required PqForgeProfile profile,
  }) {
    if (slhDsaOnly) return 'Generated SLH-DSA key material';
    if (classicalOnly) return 'Generated classical key material';
    if (emitPqc) return 'Generated ${profile.name} key bundle';
    return 'Generated key material';
  }

  Future<({PqExportedKey public, PqExportedKey secret})> _generateClassical(
    String algo,
    String keyId,
  ) async {
    if (algo == 'x25519') {
      final pair = await const PqForgeHybridKeyAgreement()
          .generateClassicalKeyPairBytes();
      return (
        public: PqExportedKey(
          kind: classicalKexPublicKind,
          algorithmId: 'x25519',
          keyId: keyId,
          bytes: pair.publicKey,
        ),
        secret: PqExportedKey(
          kind: classicalKexSecretKind,
          algorithmId: 'x25519',
          keyId: keyId,
          bytes: pair.secretKey,
        ),
      );
    }
    final algorithm = PqClassicalSignatureAlgorithm.byId(algo);
    final pair = await PqForgeHybridSigner(
      classicalAlgorithm: algorithm,
    ).generateClassicalKeyPair();
    return (
      public: PqExportedKey(
        kind: classicalSignaturePublicKind,
        algorithmId: algorithm.id,
        keyId: keyId,
        bytes: pair.publicKey,
      ),
      secret: PqExportedKey(
        kind: classicalSignatureSecretKind,
        algorithmId: algorithm.id,
        keyId: keyId,
        bytes: pair.secretKey,
      ),
    );
  }

  Future<void> _writeSecrets(
    Map<String, PqExportedKey> secretFiles,
    Directory outDir,
    String? passphrase,
    ArgResults argResults, {
    ProgressReporter? progress,
  }) async {
    if (passphrase == null) {
      for (final entry in secretFiles.entries) {
        await writeJson(outDir.child(entry.key), entry.value.toJson());
      }
      return;
    }
    final iterations = int.parse(argResults['argon-iterations'] as String);
    final memoryPowerOf2 = int.parse(
      argResults['argon-memory-power-of-2'] as String,
    );
    final lanes = int.parse(argResults['argon-lanes'] as String);
    // Argon2id wrapping is a deliberate ~0.5 s CPU+RAM burn per key; with the
    // full default key set that is the dominant keygen cost. Wrap on a small
    // pool of background isolates — bounded because every concurrent wrap
    // pins its own Argon2id arena (default 64 MiB).
    final wrapConcurrency =
        (int.tryParse(argResults['wrap-concurrency'] as String) ?? 2).clamp(
          1,
          4,
        );
    final pool = Semaphore(wrapConcurrency);
    await Future.wait([
      for (final entry in secretFiles.entries)
        () async {
          await pool.acquire();
          progress?.startFile(entry.key);
          try {
            final wrapped = await _wrapKeyInIsolate(
              entry.value,
              passphrase,
              iterations: iterations,
              memoryPowerOf2: memoryPowerOf2,
              lanes: lanes,
            );
            await writeJson(
              outDir.child(entry.key.replaceFirst('.json', '.wrapped.json')),
              wrapped.toJson(),
            );
            progress?.completeFile(entry.key);
          } catch (error) {
            progress?.failFile(entry.key, error.toString());
            rethrow;
          } finally {
            pool.release();
          }
        }(),
    ]);
  }
}

/// Wraps one secret key on a background isolate. Top-level so the
/// `Isolate.run` closure's context chain holds only these sendable parameters
/// — written inline in the pooled task it would capture the enclosing scope
/// (the semaphore and its completers) and fail to send.
Future<PqWrappedKey> _wrapKeyInIsolate(
  PqExportedKey key,
  String passphrase, {
  required int iterations,
  required int memoryPowerOf2,
  required int lanes,
}) {
  return Isolate.run(
    () => const PqForge().wrapKeyWithPassphrase(
      key,
      passphrase,
      iterations: iterations,
      memoryPowerOf2: memoryPowerOf2,
      lanes: lanes,
    ),
  );
}

/// Prints the suite/engine/signature detail lines every encrypt/decrypt
/// command emits, so the algorithm combination in effect is always visible.
void _printSuite({
  required PqForgeProfile profile,
  required bool hybrid,
  PqForgeCipherSuite suite = PqForgeCipherSuite.aes256Gcm,
  PqForgeEngineProvider? engine,
  PqSignatureAlgorithm? signature,
  int additionalRecipients = 0,
}) {
  console.detail('suite', suiteLabel(profile, hybrid: hybrid, suite: suite));
  if (engine != null) console.detail('engine', engineLabel(engine));
  if (signature != null) console.detail('signature', signature.name);
  if (additionalRecipients > 0) {
    console.detail(
      'recipients',
      '1 primary + $additionalRecipients key-wrapped',
    );
  }
}

/// `encrypt` — encrypt a single file to an ML-KEM public key, optionally
/// hybridized with the recipient's X25519 key.
final class EncryptCommand extends Command<void> {
  EncryptCommand() {
    addEnvelopeOptions(argParser, includeProfile: true);
    argParser
      ..addMultiOption(
        'recipient-public',
        valueHelp: 'file',
        help:
            'Recipient ML-KEM public key JSON from pqforge keygen. Repeat to '
            'add recipients: the payload is sealed once and the key is '
            'wrapped to each extra recipient (~1.6 KB each).',
      )
      ..addOption(
        'in',
        mandatory: true,
        valueHelp: 'file',
        help: 'Plaintext input file.',
      )
      ..addOption(
        'out',
        mandatory: true,
        valueHelp: 'file',
        help: 'Encrypted .pqf output file.',
      )
      ..addOption(
        'aad',
        valueHelp: 'string',
        help: 'Optional associated data. Defaults to file:<basename>.',
      );
    addHybridEncryptOptions(argParser);
    addEngineOption(argParser);
    addCipherOption(argParser);
    addPassphraseOptions(argParser);
    addQuietOption(argParser);
  }

  @override
  String get name => 'encrypt';

  @override
  String get description =>
      'Encrypt a file to one or more ML-KEM public keys (add --hybrid for '
      'ML-KEM + X25519).';

  @override
  String get usageFooter => usageExamples([
    'pqforge encrypt --recipient-public keys/vault.kem.public.json \\',
    '  --in report.pdf --out report.pdf.pqf --profile maximum',
    '# Hybrid: ML-KEM + X25519 (uses keys/vault.x25519.public.json)',
    'pqforge encrypt --hybrid --recipient-public keys/vault.kem.public.json \\',
    '  --in report.pdf --out report.pdf.pqf',
    '# Two recipients, one ciphertext',
    'pqforge encrypt --recipient-public keys/vault.kem.public.json \\',
    '  --recipient-public keys/audit.kem.public.json \\',
    '  --in report.pdf --out report.pdf.pqf',
  ]);

  @override
  Future<void> run() async {
    final results = argResults!;
    final passphrase = await passphraseFrom(results);
    final recipients = await recipientsFrom(results);
    final input = File(results['in'] as String);
    final output = File(results['out'] as String);
    final profile = resolveProfile(results);
    final signer = await optionalSignerSecret(results, passphrase);
    final engineProvider = engineFrom(results);
    final cipher = cipherFrom(results);

    final fileName = input.uri.pathSegments.last;
    final aad = PqRecipeMessages.fileAad(
      fileName: fileName,
      aad: optionalAad(results),
    );
    final length = await input.length();
    final metadata = <String, Object?>{
      'recipe': 'file-encryption',
      'fileName': fileName,
      'contentLength': length,
    };
    final quiet = quietFrom(results);

    if (length >= PqForgeStreamCipher.streamingThresholdBytes) {
      // Large file: stream it frame-by-frame so peak memory stays a few MB
      // regardless of size (Phase 3). The container is self-describing, so the
      // matching decrypt auto-detects it.
      final stats = await withFileProgress(
        quiet: quiet,
        operation: 'encrypting',
        path: fileName,
        bytes: length,
        action: (progress) {
          return PqForgeStreamCipher.forProvider(
            engineProvider,
            cipherSuite: cipher,
          ).encryptFile(
            recipientPublicKey: recipients.primary.bytes,
            recipientKexPublicKey: recipients.primaryKex?.bytes,
            additionalRecipients: recipients.additional,
            recipientKeyId: recipients.primary.keyId,
            input: input,
            output: output,
            profile: profile,
            aad: aad,
            metadata: metadata,
            signerSecretKey: signer?.bytes,
            signerKeyId: signerKeyId(results, signer),
            onProgress: (processed, total) =>
                progress.updateBytes(processed: processed, totalBytes: total),
          );
        },
      );
      if (!quiet) {
        console.detail(
          'envelope',
          'streaming ${profile.name}'
              '${signer == null ? '' : ' (signed)'} — ${stats.frameCount} frames',
        );
        _printSuite(
          profile: profile,
          hybrid: recipients.hybrid,
          suite: cipher,
          engine: engineProvider,
          signature: signer == null ? null : profile.signature,
          additionalRecipients: recipients.additional.length,
        );
        console.created(output.path);
      }
      return;
    }

    // readAsBytes already returns a fresh Uint8List; the prior fromList was a
    // redundant full-file copy (defect M2). encryptAsync runs the DEM stage on
    // the selected engine, so small files get the same ~10x AEAD speedup as
    // the streaming path instead of being pinned to PointyCastle.
    await withFileProgress(
      quiet: quiet,
      operation: 'encrypting',
      path: fileName,
      bytes: length,
      action: (_) async {
        final plaintext = await input.readAsBytes();
        final envelope = await PqForge(profile: profile).encryptAsync(
          recipients.primary.bytes,
          plaintext,
          recipientKexPublicKey: recipients.primaryKex?.bytes,
          additionalRecipients: recipients.additional,
          recipientKeyId: recipients.primary.keyId,
          engine: aeadEngineForProvider(engineProvider, cipherSuite: cipher),
          aad: aad,
          metadata: metadata,
          profile: profile,
          signerSecretKey: signer?.bytes,
          signerKeyId: signerKeyId(results, signer),
        );
        await writeEnvelope(output, envelope);
      },
    );
    if (!quiet) {
      _printSuite(
        profile: profile,
        hybrid: recipients.hybrid,
        suite: cipher,
        engine: engineProvider,
        signature: signer == null ? null : profile.signature,
        additionalRecipients: recipients.additional.length,
      );
      console.created(output.path);
    }
  }
}

/// `decrypt` — decrypt a `.pqf` file with an ML-KEM secret key.
final class DecryptCommand extends Command<void> {
  DecryptCommand() {
    argParser
      ..addOption(
        'recipient-secret',
        mandatory: true,
        valueHelp: 'file',
        help: 'Recipient raw or wrapped ML-KEM secret key JSON.',
      )
      ..addOption(
        'in',
        mandatory: true,
        valueHelp: 'file',
        help: 'Encrypted .pqf input file.',
      )
      ..addOption(
        'out',
        mandatory: true,
        valueHelp: 'file',
        help: 'Plaintext output file.',
      )
      ..addOption(
        'aad',
        valueHelp: 'string',
        help: 'Optional associated data. Defaults to fileName metadata.',
      )
      ..addOption(
        'signer-public',
        valueHelp: 'file',
        help: 'ML-DSA public key JSON, required for signed envelopes.',
      );
    addHybridDecryptOptions(argParser);
    addEngineOption(argParser);
    addPassphraseOptions(argParser);
    addQuietOption(argParser);
  }

  @override
  String get name => 'decrypt';

  @override
  String get description =>
      'Decrypt a .pqf file with an ML-KEM secret key (hybrid auto-detected).';

  @override
  String get usageFooter => usageExamples([
    'pqforge decrypt --recipient-secret keys/vault.kem.secret.wrapped.json \\',
    '  --passphrase-env PQFORGE_PASSPHRASE --in report.pdf.pqf --out report.pdf',
  ]);

  @override
  Future<void> run() async {
    final results = argResults!;
    final passphrase = await passphraseFrom(results);
    final recipient = await readKey(
      results['recipient-secret'] as String,
      passphrase: passphrase,
    );
    requireKind(recipient, PqKeyKind.kemSecret);
    final input = File(results['in'] as String);
    final output = File(results['out'] as String);
    final signer = await optionalPublicKey(
      results['signer-public'] as String?,
      PqKeyKind.signaturePublic,
    );
    final engineProvider = engineFrom(results);
    final quiet = quietFrom(results);
    final fileName = input.uri.pathSegments.last;
    final length = await input.length();

    if (await PqForgeStreamCipher.isStreamingFile(input)) {
      final cipher = PqForgeStreamCipher.forProvider(engineProvider);
      final peek = await cipher.readHeader(input);
      final hybrid = PqHybridKemDem.isHybrid(peek.metadata);
      final kexSecret = await hybridKexSecretFrom(
        results,
        passphrase,
        hybridInput: hybrid,
        // Multi-recipient containers may hold a hybrid wrap entry for us even
        // when the primary isn't hybrid — resolve the key opportunistically.
        discover: PqMultiRecipient.hasEntries(peek.metadata),
      );
      await withFileProgress(
        quiet: quiet,
        operation: 'decrypting',
        path: fileName,
        bytes: length,
        action: (progress) {
          return cipher.decryptFile(
            recipientSecretKey: recipient.bytes,
            recipientKexSecretKey: kexSecret?.bytes,
            recipientKeyId: recipient.keyId,
            input: input,
            output: output,
            signerPublicKey: signer?.bytes,
            aadResolver: (header) => PqRecipeMessages.fileAad(
              fileName: _requiredMeta(header.metadata, 'fileName', 'File'),
              aad: optionalAad(results),
            ),
            onProgress: (processed, total) =>
                progress.updateBytes(processed: processed, totalBytes: total),
          );
        },
      );
      if (!quiet) {
        _printSuite(
          profile: peek.profile,
          hybrid: hybrid,
          suite: PqAeadSuite.of(peek.metadata),
          engine: engineProvider,
          signature: peek.isSigned ? peek.signatureAlgorithm : null,
        );
        console.created(output.path);
      }
      return;
    }

    final envelope = await withFileProgress(
      quiet: quiet,
      operation: 'decrypting',
      path: fileName,
      bytes: length,
      action: (_) async {
        final opened = await readEnvelope(input);
        final kexSecret = await hybridKexSecretFrom(
          results,
          passphrase,
          hybridInput: PqHybridKemDem.isHybrid(opened.metadata),
          discover: PqMultiRecipient.hasEntries(opened.metadata),
        );
        final aad = PqRecipeMessages.fileAad(
          fileName: _requiredMeta(opened.metadata, 'fileName', 'File'),
          aad: optionalAad(results),
        );
        final plaintext = await PqForge(profile: opened.profile).decryptAsync(
          recipient.bytes,
          opened,
          recipientKexSecretKey: kexSecret?.bytes,
          recipientKeyId: recipient.keyId,
          engine: aeadEngineForProvider(engineProvider),
          aad: aad,
          signerPublicKey: signer?.bytes,
        );
        await output.parent.create(recursive: true);
        await output.writeAsBytes(plaintext);
        return opened;
      },
    );
    if (!quiet) {
      _printSuite(
        profile: envelope.profile,
        hybrid: PqHybridKemDem.isHybrid(envelope.metadata),
        suite: PqAeadSuite.of(envelope.metadata),
        engine: engineProvider,
        signature: envelope.isSigned ? envelope.signatureAlgorithm : null,
      );
      console.created(output.path);
    }
  }
}

String _requiredMeta(Map<String, Object?> metadata, String key, String label) {
  final value = metadata[key];
  if (value is! String || value.isEmpty) {
    throw PqForgeException('$label envelope metadata must include $key.');
  }
  return value;
}

/// `encrypt-folder` — encrypt every regular file under a folder tree.
final class EncryptFolderCommand extends Command<void> {
  EncryptFolderCommand() {
    addEnvelopeOptions(argParser, includeProfile: true);
    argParser
      ..addMultiOption(
        'recipient-public',
        valueHelp: 'file',
        help:
            'Recipient ML-KEM public key JSON from pqforge keygen. Repeat to '
            'add recipients (every envelope gets key-wrap entries for them).',
      )
      ..addOption(
        'in-dir',
        mandatory: true,
        valueHelp: 'dir',
        help: 'Plaintext folder.',
      )
      ..addOption(
        'out-dir',
        mandatory: true,
        valueHelp: 'dir',
        help: 'Folder that receives encrypted .pqf files.',
      )
      ..addOption(
        'aad',
        valueHelp: 'string',
        help: 'Optional global associated data bound to every folder entry.',
      )
      ..addOption(
        'concurrency',
        valueHelp: 'n',
        help: 'Max files encrypted in parallel (default: CPU count, max 8).',
      );
    addHybridEncryptOptions(argParser);
    addEngineOption(argParser);
    addCipherOption(argParser);
    addPassphraseOptions(argParser);
    addQuietOption(argParser);
  }

  @override
  String get name => 'encrypt-folder';

  @override
  String get description => 'Encrypt a folder tree, preserving relative paths.';

  @override
  String get usageFooter => usageExamples([
    'pqforge encrypt-folder --recipient-public keys/vault.kem.public.json \\',
    '  --in-dir ./records --out-dir ./records.pqf --aad tenant:county-a',
  ]);

  @override
  Future<void> run() async {
    final results = argResults!;
    final passphrase = await passphraseFrom(results);
    final recipients = await recipientsFrom(results);
    final inputDir = Directory(results['in-dir'] as String);
    final outputDir = Directory(results['out-dir'] as String);
    final profile = resolveProfile(results);
    final signer = await optionalSignerSecret(results, passphrase);
    final aad = optionalAad(results);
    final keyId = signerKeyId(results, signer);
    final concurrency = concurrencyFrom(results);
    final engineProvider = engineFrom(results);
    final cipher = cipherFrom(results);
    final quiet = quietFrom(results);

    final files = await listFiles(
      inputDir,
      onSkipped: (path, error) {
        if (!quiet) console.warn('skipping $path: $error');
      },
    );

    final progress = ProgressReporter(
      total: files.length,
      operation: 'encrypting',
      showPath: true,
      quiet: quiet,
    );

    final pool = Semaphore(concurrency);
    final tasks = <Future<void>>[];
    for (final entity in files) {
      final relativePath = safeRelativePath(inputDir, entity);

      var fileSizeBytes = 0;
      try {
        fileSizeBytes = entity.lengthSync();
      } on FileSystemException {
        // Stat failed; throughput stays without this file's size.
      }

      tasks.add(() async {
        await pool.acquire();
        try {
          progress.startFile(relativePath, fileSizeBytes: fileSizeBytes);
          await isolateRunWithProgress(
            (port) => _encryptFolderEntryInIsolate(
              recipientPublicKey: recipients.primary.bytes,
              recipientKexPublicKey: recipients.primaryKex?.bytes,
              additionalRecipients: recipients.additional,
              recipientKeyId: recipients.primary.keyId,
              profile: profile,
              inputPath: entity.path,
              outputPath: joinPath(outputDir.path, '$relativePath.pqf'),
              relativePath: relativePath,
              aad: aad,
              signerSecretKey: signer?.bytes,
              signerKeyId: keyId,
              engineProvider: engineProvider,
              cipherSuite: cipher,
              progressPort: port,
            ),
            onProgress: (processed, total) {
              progress.updateBytes(
                path: relativePath,
                processed: processed,
                totalBytes: total,
              );
            },
          );
          progress.completeFile(relativePath);
        } catch (e) {
          progress.failFile(relativePath, e.toString());
        } finally {
          pool.release();
        }
      }());
    }
    await Future.wait(tasks);
    progress.done();
    if (progress.hasFailures) exitCode = 1;

    if (!quiet) {
      _printSuite(
        profile: profile,
        hybrid: recipients.hybrid,
        suite: cipher,
        engine: engineProvider,
        signature: signer == null ? null : profile.signature,
        additionalRecipients: recipients.additional.length,
      );
      console.detail('output', outputDir.path);
    }
  }
}

/// Encrypts one folder entry on a background isolate (Axis B). Large entries are
/// streamed (`.pqfs`), small ones use a one-shot envelope; both carry the same
/// folder-entry AAD and metadata so [_decryptFolderEntryInIsolate] auto-routes,
/// and both run their DEM stage on the selected engine.
Future<void> _encryptFolderEntryInIsolate({
  required Uint8List recipientPublicKey,
  required Uint8List? recipientKexPublicKey,
  required List<PqRecipientSpec> additionalRecipients,
  required String? recipientKeyId,
  required PqForgeProfile profile,
  required String inputPath,
  required String outputPath,
  required String relativePath,
  required Uint8List? aad,
  required Uint8List? signerSecretKey,
  required String? signerKeyId,
  required PqForgeEngineProvider engineProvider,
  required PqForgeCipherSuite cipherSuite,
  SendPort? progressPort,
}) {
  return Isolate.run(() async {
    final input = File(inputPath);
    final output = File(outputPath);
    final length = await input.length();
    final entryAad = PqRecipeMessages.folderEntryAad(
      relativePath: relativePath,
      aad: aad,
    );
    final metadata = <String, Object?>{
      'recipe': 'folder-entry-encryption',
      'fileName': relativePath.split('/').last,
      'relativePath': relativePath,
      'contentLength': length,
    };
    void report(int processed, int? total) {
      progressPort?.send(<Object?>[processed, total]);
    }

    if (length >= PqForgeStreamCipher.streamingThresholdBytes) {
      await PqForgeStreamCipher.forProvider(
        engineProvider,
        cipherSuite: cipherSuite,
      ).encryptFile(
        recipientPublicKey: recipientPublicKey,
        recipientKexPublicKey: recipientKexPublicKey,
        additionalRecipients: additionalRecipients,
        recipientKeyId: recipientKeyId,
        input: input,
        output: output,
        profile: profile,
        aad: entryAad,
        metadata: metadata,
        signerSecretKey: signerSecretKey,
        signerKeyId: signerKeyId,
        onProgress: report,
      );
      return;
    }

    final envelope = await PqForge(profile: profile).encryptAsync(
      recipientPublicKey,
      await input.readAsBytes(),
      recipientKexPublicKey: recipientKexPublicKey,
      additionalRecipients: additionalRecipients,
      recipientKeyId: recipientKeyId,
      engine: aeadEngineForProvider(engineProvider, cipherSuite: cipherSuite),
      aad: entryAad,
      metadata: metadata,
      profile: profile,
      signerSecretKey: signerSecretKey,
      signerKeyId: signerKeyId,
    );
    await output.parent.create(recursive: true);
    await output.writeAsBytes(envelope.toBinary());
    report(length, length);
  });
}

/// `decrypt-folder` — decrypt a tree produced by encrypt-folder.
final class DecryptFolderCommand extends Command<void> {
  DecryptFolderCommand() {
    argParser
      ..addOption(
        'recipient-secret',
        mandatory: true,
        valueHelp: 'file',
        help: 'Recipient raw or wrapped ML-KEM secret key JSON.',
      )
      ..addOption(
        'in-dir',
        mandatory: true,
        valueHelp: 'dir',
        help: 'Folder of .pqf files.',
      )
      ..addOption(
        'out-dir',
        mandatory: true,
        valueHelp: 'dir',
        help: 'Folder that receives plaintext files.',
      )
      ..addOption(
        'aad',
        valueHelp: 'string',
        help: 'Optional global associated data bound to every folder entry.',
      )
      ..addOption(
        'signer-public',
        valueHelp: 'file',
        help: 'ML-DSA public key JSON, required for signed envelopes.',
      )
      ..addOption(
        'concurrency',
        valueHelp: 'n',
        help: 'Max files decrypted in parallel (default: CPU count, max 8).',
      );
    addHybridDecryptOptions(argParser);
    addEngineOption(argParser);
    addPassphraseOptions(argParser);
    addQuietOption(argParser);
  }

  @override
  String get name => 'decrypt-folder';

  @override
  String get description => 'Decrypt a folder tree produced by encrypt-folder.';

  @override
  String get usageFooter => usageExamples([
    'pqforge decrypt-folder \\',
    '  --recipient-secret keys/vault.kem.secret.wrapped.json \\',
    '  --passphrase-env PQFORGE_PASSPHRASE --in-dir ./records.pqf \\',
    '  --out-dir ./records.open --aad tenant:county-a',
  ]);

  @override
  Future<void> run() async {
    final results = argResults!;
    final passphrase = await passphraseFrom(results);
    final recipient = await readKey(
      results['recipient-secret'] as String,
      passphrase: passphrase,
    );
    requireKind(recipient, PqKeyKind.kemSecret);

    final kexSecret = await hybridKexSecretFrom(
      results,
      passphrase,
      hybridInput: false,
      discover: true,
    );
    final inputDir = Directory(results['in-dir'] as String);
    final outputDir = Directory(results['out-dir'] as String);
    final signer = await optionalPublicKey(
      results['signer-public'] as String?,
      PqKeyKind.signaturePublic,
    );
    final aad = optionalAad(results);
    final concurrency = concurrencyFrom(results);
    final engineProvider = engineFrom(results);
    final quiet = quietFrom(results);

    final files = await listFiles(
      inputDir,
      onSkipped: (path, error) {
        if (!quiet) console.warn('skipping $path: $error');
      },
    );

    final pqfFiles = files.where((f) => f.path.endsWith('.pqf')).toList();

    final progress = ProgressReporter(
      total: pqfFiles.length,
      operation: 'decrypting',
      showPath: true,
      quiet: quiet,
    );

    final pool = Semaphore(concurrency);
    final tasks = <Future<void>>[];
    for (final entity in pqfFiles) {
      final relativePath = safeRelativePath(inputDir, entity);
      var fileSizeBytes = 0;
      try {
        fileSizeBytes = entity.lengthSync();
      } on FileSystemException {
        // Stat failed; throughput stays without this file's size.
      }

      tasks.add(() async {
        await pool.acquire();
        try {
          progress.startFile(relativePath, fileSizeBytes: fileSizeBytes);
          await isolateRunWithProgress(
            (port) => _decryptFolderEntryInIsolate(
              recipientSecretKey: recipient.bytes,
              recipientKexSecretKey: kexSecret?.bytes,
              recipientKeyId: recipient.keyId,
              inputPath: entity.path,
              outputDirPath: outputDir.path,
              aad: aad,
              signerPublicKey: signer?.bytes,
              engineProvider: engineProvider,
              progressPort: port,
            ),
            onProgress: (processed, total) {
              progress.updateBytes(
                path: relativePath,
                processed: processed,
                totalBytes: total,
              );
            },
          );
          progress.completeFile(relativePath);
        } catch (e) {
          progress.failFile(relativePath, e.toString());
        } finally {
          pool.release();
        }
      }());
    }
    await Future.wait(tasks);
    progress.done();
    if (progress.hasFailures) exitCode = 1;

    if (!quiet) {
      console.detail('engine', engineLabel(engineProvider));
      console.detail('output', outputDir.path);
    }
  }
}

/// Decrypts one folder entry on a background isolate, auto-routing between the
/// streaming (`.pqfs`) and one-shot envelope formats. The relative path comes
/// from the (header-bound) metadata and is re-validated against path traversal.
Future<void> _decryptFolderEntryInIsolate({
  required Uint8List recipientSecretKey,
  required Uint8List? recipientKexSecretKey,
  required String? recipientKeyId,
  required String inputPath,
  required String outputDirPath,
  required Uint8List? aad,
  required Uint8List? signerPublicKey,
  required PqForgeEngineProvider engineProvider,
  SendPort? progressPort,
}) {
  return Isolate.run(() async {
    void report(int processed, int? total) {
      progressPort?.send(<Object?>[processed, total]);
    }

    final input = File(inputPath);
    if (await PqForgeStreamCipher.isStreamingFile(input)) {
      final header = await PqForgeStreamCipher.forProvider(
        engineProvider,
      ).readHeader(input);
      final relativePath = _folderRelativePath(header.metadata, input.path);
      await PqForgeStreamCipher.forProvider(engineProvider).decryptFile(
        recipientSecretKey: recipientSecretKey,
        recipientKexSecretKey: recipientKexSecretKey,
        recipientKeyId: recipientKeyId,
        input: input,
        output: File(joinPath(outputDirPath, relativePath)),
        signerPublicKey: signerPublicKey,
        aadResolver: (_) => PqRecipeMessages.folderEntryAad(
          relativePath: relativePath,
          aad: aad,
        ),
        onProgress: report,
      );
      return;
    }

    final envelope = await readEnvelope(input);
    final relativePath = _folderRelativePath(envelope.metadata, input.path);
    final plaintext = await PqForge(profile: envelope.profile).decryptAsync(
      recipientSecretKey,
      envelope,
      recipientKexSecretKey: recipientKexSecretKey,
      recipientKeyId: recipientKeyId,
      engine: aeadEngineForProvider(engineProvider),
      aad: PqRecipeMessages.folderEntryAad(
        relativePath: relativePath,
        aad: aad,
      ),
      signerPublicKey: signerPublicKey,
    );
    final output = File(joinPath(outputDirPath, relativePath));
    await output.parent.create(recursive: true);
    await output.writeAsBytes(plaintext);
    report(plaintext.length, plaintext.length);
  });
}

String _folderRelativePath(Map<String, Object?> metadata, String sourcePath) {
  final relativePath = metadata['relativePath'];
  if (relativePath is! String || relativePath.isEmpty) {
    throw PqForgeException('$sourcePath has no relativePath metadata.');
  }
  requireSafeRelativePath(relativePath);
  return relativePath;
}

/// `encrypt-text` — encrypt UTF-8 text, binding a text id into AAD.
final class EncryptTextCommand extends Command<void> {
  EncryptTextCommand() {
    addEnvelopeOptions(argParser, includeProfile: true);
    argParser
      ..addMultiOption(
        'recipient-public',
        valueHelp: 'file',
        help:
            'Recipient ML-KEM public key JSON from pqforge keygen. Repeat to '
            'add recipients (one ciphertext, key wrapped to each).',
      )
      ..addOption(
        'text',
        valueHelp: 'string',
        help: 'Plaintext string to encrypt.',
      )
      ..addOption('in', valueHelp: 'file', help: 'UTF-8 plaintext input file.')
      ..addOption(
        'out',
        mandatory: true,
        valueHelp: 'file',
        help: 'Encrypted .pqf output file.',
      )
      ..addOption(
        'text-id',
        valueHelp: 'id',
        help: 'Stable text id. Defaults to input basename or inline-text.',
      )
      ..addOption(
        'aad',
        valueHelp: 'string',
        help: 'Optional associated data string.',
      );
    addHybridEncryptOptions(argParser);
    addPassphraseOptions(argParser);
    addQuietOption(argParser);
  }

  @override
  String get name => 'encrypt-text';

  @override
  String get description => 'Encrypt UTF-8 text and bind a text id into AAD.';

  @override
  String get usageFooter => usageExamples([
    'pqforge encrypt-text --recipient-public keys/vault.kem.public.json \\',
    "  --text 'private memo' --text-id memo-2026-001 --out memo.pqf",
  ]);

  @override
  Future<void> run() async {
    final results = argResults!;
    final passphrase = await passphraseFrom(results);
    final recipients = await recipientsFrom(results);
    final (text, defaultTextId) = await readTextInput(results);
    final textId = results['text-id'] as String? ?? defaultTextId;
    final profile = resolveProfile(results);
    final signer = await optionalSignerSecret(results, passphrase);
    final quiet = quietFrom(results);
    final plaintext = PqBytes.utf8Bytes(text);
    // Same AAD and metadata as PqForge.sealText, routed through encryptAsync
    // so the hybrid/multi-recipient markers can ride along.
    final output = File(results['out'] as String);
    await withFileProgress(
      quiet: quiet,
      operation: 'encrypting',
      path: textId,
      bytes: plaintext.length,
      action: (_) async {
        final envelope = await PqForge(profile: profile).encryptAsync(
          recipients.primary.bytes,
          plaintext,
          recipientKexPublicKey: recipients.primaryKex?.bytes,
          additionalRecipients: recipients.additional,
          recipientKeyId: recipients.primary.keyId,
          aad: PqRecipeMessages.textAad(
            textId: textId,
            aad: optionalAad(results),
          ),
          metadata: {
            'recipe': 'text-seal',
            'textId': textId,
            'encoding': 'utf-8',
          },
          profile: profile,
          signerSecretKey: signer?.bytes,
          signerKeyId: signerKeyId(results, signer),
        );
        await writeEnvelope(output, envelope);
      },
    );
    if (!quiet) {
      _printSuite(
        profile: profile,
        hybrid: recipients.hybrid,
        signature: signer == null ? null : profile.signature,
        additionalRecipients: recipients.additional.length,
      );
      console.created(output.path);
    }
  }
}

/// `decrypt-text` — decrypt an encrypted UTF-8 text envelope.
final class DecryptTextCommand extends Command<void> {
  DecryptTextCommand() {
    argParser
      ..addOption(
        'recipient-secret',
        mandatory: true,
        valueHelp: 'file',
        help: 'Recipient raw or wrapped ML-KEM secret key JSON.',
      )
      ..addOption(
        'in',
        mandatory: true,
        valueHelp: 'file',
        help: 'Encrypted .pqf input file.',
      )
      ..addOption(
        'out',
        valueHelp: 'file',
        help: 'UTF-8 plaintext output file. Defaults to stdout.',
      )
      ..addOption(
        'aad',
        valueHelp: 'string',
        help: 'Optional associated data string.',
      )
      ..addOption(
        'signer-public',
        valueHelp: 'file',
        help: 'ML-DSA public key JSON, required for signed envelopes.',
      );
    addHybridDecryptOptions(argParser);
    addPassphraseOptions(argParser);
    addQuietOption(argParser);
  }

  @override
  String get name => 'decrypt-text';

  @override
  String get description => 'Decrypt an encrypted UTF-8 text envelope.';

  @override
  String get usageFooter => usageExamples([
    'pqforge decrypt-text \\',
    '  --recipient-secret keys/vault.kem.secret.wrapped.json \\',
    '  --passphrase-env PQFORGE_PASSPHRASE --in memo.pqf',
  ]);

  @override
  Future<void> run() async {
    final results = argResults!;
    final passphrase = await passphraseFrom(results);
    final recipient = await readKey(
      results['recipient-secret'] as String,
      passphrase: passphrase,
    );
    requireKind(recipient, PqKeyKind.kemSecret);
    final quiet = quietFrom(results);
    final inputFile = File(results['in'] as String);
    final envelope = await readEnvelope(inputFile);
    final signer = await optionalPublicKey(
      results['signer-public'] as String?,
      PqKeyKind.signaturePublic,
    );
    final kexSecret = await hybridKexSecretFrom(
      results,
      passphrase,
      hybridInput: PqHybridKemDem.isHybrid(envelope.metadata),
      discover: PqMultiRecipient.hasEntries(envelope.metadata),
    );
    // Mirrors PqForge.openText (textId/encoding checks + text AAD) on the
    // hybrid-capable async path.
    final textId = _requiredMeta(envelope.metadata, 'textId', 'text');
    final encoding = envelope.metadata['encoding'] as String? ?? 'utf-8';
    if (encoding != 'utf-8') {
      throw PqForgeException('Unsupported text envelope encoding: $encoding');
    }
    final outputPath = results['out'] as String?;
    if (outputPath == null) {
      // No --out: emit the decrypted text raw so it stays pipeable. Never
      // attach a progress line here — it would mix with the payload.
      final plaintext = await PqForge(profile: envelope.profile).decryptAsync(
        recipient.bytes,
        envelope,
        recipientKexSecretKey: kexSecret?.bytes,
        recipientKeyId: recipient.keyId,
        aad: PqRecipeMessages.textAad(
          textId: textId,
          aad: optionalAad(results),
        ),
        signerPublicKey: signer?.bytes,
      );
      console.raw(utf8.decode(plaintext));
      return;
    }

    await withFileProgress(
      quiet: quiet,
      operation: 'decrypting',
      path: textId,
      bytes: await inputFile.length(),
      action: (_) async {
        final plaintext = await PqForge(profile: envelope.profile).decryptAsync(
          recipient.bytes,
          envelope,
          recipientKexSecretKey: kexSecret?.bytes,
          recipientKeyId: recipient.keyId,
          aad: PqRecipeMessages.textAad(
            textId: textId,
            aad: optionalAad(results),
          ),
          signerPublicKey: signer?.bytes,
        );
        final text = utf8.decode(plaintext);
        await File(outputPath).writeAsString(text);
      },
    );
    if (!quiet) {
      console.created(outputPath);
    }
  }
}

/// `encrypt-media` — encrypt media bytes with media id and MIME binding.
final class EncryptMediaCommand extends Command<void> {
  EncryptMediaCommand() {
    addEnvelopeOptions(argParser, includeProfile: true);
    argParser
      ..addMultiOption(
        'recipient-public',
        valueHelp: 'file',
        help:
            'Recipient ML-KEM public key JSON from pqforge keygen. Repeat to '
            'add recipients (one ciphertext, key wrapped to each).',
      )
      ..addOption(
        'in',
        mandatory: true,
        valueHelp: 'file',
        help: 'Media input file.',
      )
      ..addOption(
        'out',
        mandatory: true,
        valueHelp: 'file',
        help: 'Encrypted .pqf output file.',
      )
      ..addOption(
        'media-id',
        valueHelp: 'id',
        help: 'Stable media id. Defaults to input basename.',
      )
      ..addOption(
        'mime-type',
        valueHelp: 'type',
        help: 'Media MIME type. Inferred from extension when omitted.',
      )
      ..addOption(
        'aad',
        valueHelp: 'string',
        help: 'Optional associated data string.',
      );
    addHybridEncryptOptions(argParser);
    addEngineOption(argParser);
    addCipherOption(argParser);
    addPassphraseOptions(argParser);
    addQuietOption(argParser);
  }

  @override
  String get name => 'encrypt-media';

  @override
  String get description =>
      'Encrypt media bytes with media id and MIME binding.';

  @override
  String get usageFooter => usageExamples([
    'pqforge encrypt-media --recipient-public keys/vault.kem.public.json \\',
    '  --in cover.png --media-id cover-2026-001 --out cover.png.pqf',
  ]);

  @override
  Future<void> run() async {
    final results = argResults!;
    final passphrase = await passphraseFrom(results);
    final recipients = await recipientsFrom(results);
    final input = File(results['in'] as String);
    final mediaId =
        results['media-id'] as String? ?? input.uri.pathSegments.last;
    final mimeType =
        results['mime-type'] as String? ?? guessMimeType(input.path);
    final profile = resolveProfile(results);
    final signer = await optionalSignerSecret(results, passphrase);
    final engineProvider = engineFrom(results);
    final cipher = cipherFrom(results);
    final output = File(results['out'] as String);
    final aad = PqRecipeMessages.mediaAad(
      mediaId: mediaId,
      mimeType: mimeType,
      aad: optionalAad(results),
    );
    final length = await input.length();
    final metadata = <String, Object?>{
      'recipe': 'media-seal',
      'mediaId': mediaId,
      'mimeType': mimeType,
      'contentLength': length,
    };
    final quiet = quietFrom(results);

    if (length >= PqForgeStreamCipher.streamingThresholdBytes) {
      final stats = await withFileProgress(
        quiet: quiet,
        operation: 'encrypting',
        path: mediaId,
        bytes: length,
        action: (progress) {
          return PqForgeStreamCipher.forProvider(
            engineProvider,
            cipherSuite: cipher,
          ).encryptFile(
            recipientPublicKey: recipients.primary.bytes,
            recipientKexPublicKey: recipients.primaryKex?.bytes,
            additionalRecipients: recipients.additional,
            recipientKeyId: recipients.primary.keyId,
            input: input,
            output: output,
            profile: profile,
            aad: aad,
            metadata: metadata,
            signerSecretKey: signer?.bytes,
            signerKeyId: signerKeyId(results, signer),
            onProgress: (processed, total) =>
                progress.updateBytes(processed: processed, totalBytes: total),
          );
        },
      );
      if (!quiet) {
        console.detail(
          'media',
          '$mediaId, $mimeType — ${stats.frameCount} frames',
        );
        _printSuite(
          profile: profile,
          hybrid: recipients.hybrid,
          suite: cipher,
          engine: engineProvider,
          signature: signer == null ? null : profile.signature,
          additionalRecipients: recipients.additional.length,
        );
        console.created(output.path);
      }
      return;
    }

    await withFileProgress(
      quiet: quiet,
      operation: 'encrypting',
      path: mediaId,
      bytes: length,
      action: (_) async {
        final bytes = await input.readAsBytes();
        final envelope = await PqForge(profile: profile).encryptAsync(
          recipients.primary.bytes,
          bytes,
          recipientKexPublicKey: recipients.primaryKex?.bytes,
          additionalRecipients: recipients.additional,
          recipientKeyId: recipients.primary.keyId,
          engine: aeadEngineForProvider(engineProvider, cipherSuite: cipher),
          aad: aad,
          metadata: metadata,
          profile: profile,
          signerSecretKey: signer?.bytes,
          signerKeyId: signerKeyId(results, signer),
        );
        await writeEnvelope(output, envelope);
      },
    );
    if (!quiet) {
      _printSuite(
        profile: profile,
        hybrid: recipients.hybrid,
        suite: cipher,
        engine: engineProvider,
        signature: signer == null ? null : profile.signature,
        additionalRecipients: recipients.additional.length,
      );
      console.created(output.path);
    }
  }
}

/// `decrypt-media` — decrypt an encrypted media envelope.
final class DecryptMediaCommand extends Command<void> {
  DecryptMediaCommand() {
    argParser
      ..addOption(
        'recipient-secret',
        mandatory: true,
        valueHelp: 'file',
        help: 'Recipient raw or wrapped ML-KEM secret key JSON.',
      )
      ..addOption(
        'in',
        mandatory: true,
        valueHelp: 'file',
        help: 'Encrypted .pqf input file.',
      )
      ..addOption(
        'out',
        mandatory: true,
        valueHelp: 'file',
        help: 'Plain media output file.',
      )
      ..addOption(
        'aad',
        valueHelp: 'string',
        help: 'Optional associated data string.',
      )
      ..addOption(
        'signer-public',
        valueHelp: 'file',
        help: 'ML-DSA public key JSON, required for signed envelopes.',
      );
    addHybridDecryptOptions(argParser);
    addEngineOption(argParser);
    addPassphraseOptions(argParser);
    addQuietOption(argParser);
  }

  @override
  String get name => 'decrypt-media';

  @override
  String get description => 'Decrypt an encrypted media envelope.';

  @override
  String get usageFooter => usageExamples([
    'pqforge decrypt-media \\',
    '  --recipient-secret keys/vault.kem.secret.wrapped.json \\',
    '  --passphrase-env PQFORGE_PASSPHRASE --in cover.png.pqf --out cover.png',
  ]);

  @override
  Future<void> run() async {
    final results = argResults!;
    final passphrase = await passphraseFrom(results);
    final recipient = await readKey(
      results['recipient-secret'] as String,
      passphrase: passphrase,
    );
    requireKind(recipient, PqKeyKind.kemSecret);
    final input = File(results['in'] as String);
    final output = File(results['out'] as String);
    final signer = await optionalPublicKey(
      results['signer-public'] as String?,
      PqKeyKind.signaturePublic,
    );
    final engineProvider = engineFrom(results);
    final quiet = quietFrom(results);
    final fileName = input.uri.pathSegments.last;
    final length = await input.length();

    if (await PqForgeStreamCipher.isStreamingFile(input)) {
      final cipher = PqForgeStreamCipher.forProvider(engineProvider);
      final peek = await cipher.readHeader(input);
      final hybrid = PqHybridKemDem.isHybrid(peek.metadata);
      final kexSecret = await hybridKexSecretFrom(
        results,
        passphrase,
        hybridInput: hybrid,
        discover: PqMultiRecipient.hasEntries(peek.metadata),
      );
      await withFileProgress(
        quiet: quiet,
        operation: 'decrypting',
        path: fileName,
        bytes: length,
        action: (progress) {
          return cipher.decryptFile(
            recipientSecretKey: recipient.bytes,
            recipientKexSecretKey: kexSecret?.bytes,
            recipientKeyId: recipient.keyId,
            input: input,
            output: output,
            signerPublicKey: signer?.bytes,
            aadResolver: (header) => PqRecipeMessages.mediaAad(
              mediaId: _requiredMeta(header.metadata, 'mediaId', 'media'),
              mimeType: _requiredMeta(header.metadata, 'mimeType', 'media'),
              aad: optionalAad(results),
            ),
            onProgress: (processed, total) =>
                progress.updateBytes(processed: processed, totalBytes: total),
          );
        },
      );
      if (!quiet) {
        _printSuite(
          profile: peek.profile,
          hybrid: hybrid,
          suite: PqAeadSuite.of(peek.metadata),
          engine: engineProvider,
          signature: peek.isSigned ? peek.signatureAlgorithm : null,
        );
        console.created(output.path);
      }
      return;
    }

    final envelope = await withFileProgress(
      quiet: quiet,
      operation: 'decrypting',
      path: fileName,
      bytes: length,
      action: (_) async {
        final opened = await readEnvelope(input);
        final kexSecret = await hybridKexSecretFrom(
          results,
          passphrase,
          hybridInput: PqHybridKemDem.isHybrid(opened.metadata),
          discover: PqMultiRecipient.hasEntries(opened.metadata),
        );
        final mediaId = _requiredMeta(opened.metadata, 'mediaId', 'media');
        final mimeType = _requiredMeta(opened.metadata, 'mimeType', 'media');
        final media = await PqForge(profile: opened.profile).decryptAsync(
          recipient.bytes,
          opened,
          recipientKexSecretKey: kexSecret?.bytes,
          recipientKeyId: recipient.keyId,
          engine: aeadEngineForProvider(engineProvider),
          aad: PqRecipeMessages.mediaAad(
            mediaId: mediaId,
            mimeType: mimeType,
            aad: optionalAad(results),
          ),
          signerPublicKey: signer?.bytes,
        );
        await output.parent.create(recursive: true);
        await output.writeAsBytes(media);
        return opened;
      },
    );
    if (!quiet) {
      _printSuite(
        profile: envelope.profile,
        hybrid: PqHybridKemDem.isHybrid(envelope.metadata),
        suite: PqAeadSuite.of(envelope.metadata),
        engine: engineProvider,
        signature: envelope.isSigned ? envelope.signatureAlgorithm : null,
      );
      console.created(output.path);
    }
  }
}

/// `pack` — pack a folder into ONE encrypted streaming archive.
///
/// Unlike `encrypt-folder` (one envelope per file), this collapses the whole
/// tree into a single sequential stream sealed by one streaming envelope — one
/// KEM encapsulation and one optional signature for the entire folder. Ideal for
/// many tiny files: it slashes per-file PQC overhead and write amplification.
final class PackCommand extends Command<void> {
  PackCommand() {
    addEnvelopeOptions(argParser, includeProfile: true);
    argParser
      ..addMultiOption(
        'recipient-public',
        valueHelp: 'file',
        help:
            'Recipient ML-KEM public key JSON from pqforge keygen. Repeat to '
            'add recipients: ONE archive, sealed once, openable by each.',
      )
      ..addOption(
        'in-dir',
        mandatory: true,
        valueHelp: 'dir',
        help: 'Plaintext folder to pack.',
      )
      ..addOption(
        'out',
        mandatory: true,
        valueHelp: 'file',
        help: 'Single encrypted archive output file.',
      )
      ..addOption(
        'aad',
        valueHelp: 'string',
        help: 'Optional associated data bound to the archive.',
      );
    addHybridEncryptOptions(argParser);
    addEngineOption(argParser);
    addCipherOption(argParser);
    addPassphraseOptions(argParser);
    addQuietOption(argParser);
  }

  @override
  String get name => 'pack';

  @override
  String get description =>
      'Pack a folder into one encrypted streaming archive (one KEM/signature '
      'for the whole tree).';

  @override
  String get usageFooter => usageExamples([
    'pqforge pack --recipient-public keys/vault.kem.public.json \\',
    '  --in-dir ./records --out records.pqf --profile maximum',
  ]);

  @override
  Future<void> run() async {
    final results = argResults!;
    final passphrase = await passphraseFrom(results);
    final recipients = await recipientsFrom(results);
    final inputDir = Directory(results['in-dir'] as String);
    final output = File(results['out'] as String);
    final profile = resolveProfile(results);
    final signer = await optionalSignerSecret(results, passphrase);
    final aad = optionalAad(results);
    final engineProvider = engineFrom(results);
    final cipher = cipherFrom(results);
    final quiet = quietFrom(results);

    final entries = [
      for (final file in await listFiles(
        inputDir,
        onSkipped: (path, error) {
          if (!quiet) console.warn('skipping $path: $error');
        },
      ))
        PqPackEntry(
          relativePath: safeRelativePath(inputDir, file),
          sourcePath: file.path,
        ),
    ];

    final progress = ProgressReporter(
      total: entries.length,
      operation: 'packing',
      quiet: quiet,
    );
    PqPackEntry? current;
    try {
      final stats =
          await PqForgeStreamCipher.forProvider(
            engineProvider,
            cipherSuite: cipher,
          ).encryptStream(
            recipientPublicKey: recipients.primary.bytes,
            recipientKexPublicKey: recipients.primaryKex?.bytes,
            additionalRecipients: recipients.additional,
            recipientKeyId: recipients.primary.keyId,
            source: PqFolderPack.packStream(
              entries,
              onEntryStart: (entry, length) {
                final previous = current;
                if (previous != null) {
                  progress.completeFile(previous.relativePath);
                }
                current = entry;
                progress.startFile(entry.relativePath, fileSizeBytes: length);
              },
              onEntryProgress: (entry, processed, length) {
                progress.updateBytes(processed: processed, totalBytes: length);
              },
            ),
            output: output,
            profile: profile,
            aad: PqRecipeMessages.folderPackAad(aad: aad),
            metadata: {'recipe': 'folder-pack', 'entryCount': entries.length},
            signerSecretKey: signer?.bytes,
            signerKeyId: signerKeyId(results, signer),
          );
      if (current != null) {
        progress.completeFile(current!.relativePath);
      }
      progress.done();
      if (!quiet) {
        console.detail(
          'archive',
          '${entries.length} file(s), ${stats.frameCount} frames',
        );
        _printSuite(
          profile: profile,
          hybrid: recipients.hybrid,
          suite: cipher,
          engine: engineProvider,
          signature: signer == null ? null : profile.signature,
          additionalRecipients: recipients.additional.length,
        );
        console.created(output.path);
      }
    } catch (error) {
      if (current != null) {
        progress.failFile(current!.relativePath, error.toString());
      } else {
        progress.failJob(error.toString());
      }
      progress.done();
      rethrow;
    }
  }
}

/// `unpack` — restore a folder tree from a `pack` archive.
final class UnpackCommand extends Command<void> {
  UnpackCommand() {
    argParser
      ..addOption(
        'recipient-secret',
        mandatory: true,
        valueHelp: 'file',
        help: 'Recipient raw or wrapped ML-KEM secret key JSON.',
      )
      ..addOption(
        'in',
        mandatory: true,
        valueHelp: 'file',
        help: 'Encrypted archive produced by pqforge pack.',
      )
      ..addOption(
        'out-dir',
        mandatory: true,
        valueHelp: 'dir',
        help: 'Folder that receives the restored tree.',
      )
      ..addOption(
        'aad',
        valueHelp: 'string',
        help: 'Optional associated data bound to the archive.',
      )
      ..addOption(
        'signer-public',
        valueHelp: 'file',
        help: 'ML-DSA public key JSON, required for signed archives.',
      );
    addHybridDecryptOptions(argParser);
    addEngineOption(argParser);
    addPassphraseOptions(argParser);
    addQuietOption(argParser);
  }

  @override
  String get name => 'unpack';

  @override
  String get description =>
      'Restore a folder tree from a pqforge pack archive.';

  @override
  String get usageFooter => usageExamples([
    'pqforge unpack --recipient-secret keys/vault.kem.secret.wrapped.json \\',
    '  --passphrase-env PQFORGE_PASSPHRASE --in records.pqf --out-dir ./records',
  ]);

  @override
  Future<void> run() async {
    final results = argResults!;
    final passphrase = await passphraseFrom(results);
    final recipient = await readKey(
      results['recipient-secret'] as String,
      passphrase: passphrase,
    );
    requireKind(recipient, PqKeyKind.kemSecret);
    final input = File(results['in'] as String);
    final outputDir = Directory(results['out-dir'] as String);
    final signer = await optionalPublicKey(
      results['signer-public'] as String?,
      PqKeyKind.signaturePublic,
    );
    final aad = optionalAad(results);
    final engineProvider = engineFrom(results);
    final quiet = quietFrom(results);

    if (!await PqForgeStreamCipher.isStreamingFile(input)) {
      throw PqForgeException(
        '${input.path} is not a pqforge streaming archive.',
      );
    }

    final cipher = PqForgeStreamCipher.forProvider(engineProvider);
    final peek = await cipher.readHeader(input);
    final hybrid = PqHybridKemDem.isHybrid(peek.metadata);
    final kexSecret = await hybridKexSecretFrom(
      results,
      passphrase,
      hybridInput: hybrid,
      discover: PqMultiRecipient.hasEntries(peek.metadata),
    );

    final entryCount = switch (peek.metadata['entryCount']) {
      final int n => n,
      final num n => n.toInt(),
      _ => 0,
    };
    final progress = ProgressReporter(
      total: entryCount,
      operation: 'unpacking',
      quiet: quiet,
    );
    String? active;
    try {
      final frames = cipher.decryptStream(
        recipientSecretKey: recipient.bytes,
        recipientKexSecretKey: kexSecret?.bytes,
        recipientKeyId: recipient.keyId,
        input: input,
        signerPublicKey: signer?.bytes,
        aadResolver: (_) => PqRecipeMessages.folderPackAad(aad: aad),
      );
      final count = await PqFolderPack.unpackFromStream(
        frames,
        outputDirPath: outputDir.path,
        onEntryStart: (path, length) {
          active = path;
          progress.startFile(path, fileSizeBytes: length);
        },
        onEntryProgress: (path, processed, length) {
          progress.updateBytes(processed: processed, totalBytes: length);
        },
        onEntryDone: (path) {
          progress.completeFile(path);
          active = null;
        },
      );
      progress.done();
      if (progress.hasFailures) exitCode = 1;
      if (!quiet) {
        console.detail('files', '$count');
        _printSuite(
          profile: peek.profile,
          hybrid: hybrid,
          suite: PqAeadSuite.of(peek.metadata),
          engine: engineProvider,
          signature: peek.isSigned ? peek.signatureAlgorithm : null,
        );
        console.detail('output', outputDir.path);
      }
    } catch (error) {
      if (active != null) {
        progress.failFile(active!, error.toString());
      } else {
        progress.failJob(error.toString());
      }
      progress.done();
      rethrow;
    }
  }
}

/// `inspect` — describe a pqforge artifact without decrypting it.
final class InspectCommand extends Command<void> {
  InspectCommand() {
    argParser.addOption(
      'in',
      mandatory: true,
      valueHelp: 'file',
      help: 'A .pqf/.pqfs envelope, key JSON, or signature JSON file.',
    );
  }

  @override
  String get name => 'inspect';

  @override
  String get description =>
      'Show the format, profile, and algorithm combination of a pqforge file.';

  @override
  String get usageFooter => usageExamples([
    'pqforge inspect --in report.pdf.pqf',
    'pqforge inspect --in keys/vault.kem.public.json',
  ]);

  @override
  Future<void> run() async {
    final input = File(argResults!['in'] as String);

    if (await PqForgeStreamCipher.isStreamingFile(input)) {
      final header = await PqForgeStreamCipher().readHeader(input);
      final hybrid = PqHybridKemDem.isHybrid(header.metadata);
      console.section('Streaming envelope (.pqfs)');
      console.detail('profile', header.profile.name);
      _printSuite(
        profile: header.profile,
        hybrid: hybrid,
        suite: PqAeadSuite.of(header.metadata),
        signature: header.isSigned ? header.signatureAlgorithm : null,
        additionalRecipients: PqMultiRecipient.parseEntries(
          header.metadata,
        ).length,
      );
      if (header.signerKeyId != null) {
        console.detail('signer key id', header.signerKeyId!);
      }
      console.detail('frame size', '${header.frameSize} bytes');
      console.detail('aad bound', header.aadHash == null ? 'no' : 'yes');
      _printMetadata(header.metadata);
      return;
    }

    final bytes = await input.readAsBytes();
    final envelope = _tryParseEnvelope(bytes);
    if (envelope != null) {
      final hybrid = PqHybridKemDem.isHybrid(envelope.metadata);
      console.section('One-shot envelope (.pqf)');
      console.detail('profile', envelope.profile.name);
      _printSuite(
        profile: envelope.profile,
        hybrid: hybrid,
        suite: PqAeadSuite.of(envelope.metadata),
        signature: envelope.isSigned ? envelope.signatureAlgorithm : null,
        additionalRecipients: PqMultiRecipient.parseEntries(
          envelope.metadata,
        ).length,
      );
      if (envelope.signerKeyId != null) {
        console.detail('signer key id', envelope.signerKeyId!);
      }
      console.detail('payload', '${envelope.payload.length} bytes');
      console.detail('aad bound', envelope.aadHash == null ? 'no' : 'yes');
      _printMetadata(envelope.metadata);
      return;
    }

    final json = await readJsonMap(input);
    if (json.containsKey('ciphertext') && json.containsKey('kdf')) {
      console.section('Wrapped (passphrase-protected) key');
      console.detail('kind', json['keyKind'] as String? ?? 'unknown');
      console.detail('algorithm', json['algorithmId'] as String? ?? 'unknown');
      if (json['keyId'] is String) console.detail('key id', '${json['keyId']}');
      console.detail('kdf', json['kdf'] as String? ?? 'unknown');
      return;
    }
    if (json.containsKey('kind') && json.containsKey('bytes')) {
      console.section('Exported key');
      console.detail('kind', json['kind'] as String? ?? 'unknown');
      console.detail('algorithm', json['algorithmId'] as String? ?? 'unknown');
      if (json['keyId'] is String) console.detail('key id', '${json['keyId']}');
      console.warn(
        (json['kind'] as String? ?? '').contains('secret')
            ? 'this is a RAW secret key — wrap it with a passphrase for storage'
            : 'public key — safe to distribute',
      );
      return;
    }
    if (json.containsKey('pqcSignature') &&
        json.containsKey('classicalSignature')) {
      console.section('Hybrid (dual) signature');
      console.detail('pqc', json['pqcAlgorithm'] as String? ?? 'unknown');
      console.detail(
        'classical',
        json['classicalAlgorithm'] as String? ?? 'unknown',
      );
      console.detail('policy', json['policy'] as String? ?? 'unknown');
      return;
    }
    if (json.containsKey('signature')) {
      console.section('Detached signature');
      console.detail('kind', json['kind'] as String? ?? 'document');
      console.detail(
        'algorithm',
        json['signatureAlgorithm'] as String? ??
            json['scheme'] as String? ??
            'unknown',
      );
      return;
    }
    throw PqForgeException('${input.path} is not a recognized pqforge file.');
  }

  PqEnvelope? _tryParseEnvelope(Uint8List bytes) {
    try {
      return PqEnvelope.fromBinary(bytes);
    } on Object {
      return null;
    }
  }

  void _printMetadata(Map<String, Object?> metadata) {
    for (final entry in metadata.entries) {
      // Container markers are already rendered as suite/recipients lines.
      if (pqForgeReservedMetadataKeys.contains(entry.key)) continue;
      console.detail(entry.key, '${entry.value}');
    }
  }
}

/// `sign` — detached ML-DSA or SLH-DSA recipe signatures
/// (document/text/media/artifact).
final class SignCommand extends Command<void> {
  SignCommand() {
    argParser
      ..addOption(
        'signer-secret',
        mandatory: true,
        valueHelp: 'file',
        help:
            'Raw or wrapped ML-DSA or SLH-DSA secret key JSON from pqforge keygen.',
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
      )
      ..addOption(
        'kind',
        allowed: ['document', 'text', 'media', 'artifact'],
        defaultsTo: 'document',
        valueHelp: 'kind',
        help: 'Recipe-specific signature kind.',
      )
      ..addOption(
        'document-id',
        valueHelp: 'id',
        help: 'Stable document id. Defaults to input basename.',
      )
      ..addOption(
        'text-id',
        valueHelp: 'id',
        help: 'Stable text id. Defaults to input basename.',
      )
      ..addOption(
        'media-id',
        valueHelp: 'id',
        help: 'Stable media id. Defaults to input basename.',
      )
      ..addOption(
        'mime-type',
        valueHelp: 'type',
        help: 'Media MIME type. Inferred from extension when omitted.',
      )
      ..addOption(
        'artifact-id',
        valueHelp: 'id',
        help: 'Stable artifact id. Defaults to input basename.',
      )
      ..addOption(
        'version',
        defaultsTo: '1',
        valueHelp: 'n',
        help: 'Artifact version for kind=artifact.',
      );
    addPassphraseOptions(argParser);
    addQuietOption(argParser);
  }

  @override
  String get name => 'sign';

  @override
  String get description =>
      'Create detached ML-DSA or SLH-DSA recipe signatures.';

  @override
  String get usageFooter => usageExamples([
    'pqforge sign --signer-secret keys/vault.sign.secret.wrapped.json \\',
    '  --passphrase-env PQFORGE_PASSPHRASE --kind document \\',
    '  --in contract.pdf --document-id contract-2026-001 --out contract.sig.json',
    'pqforge sign --signer-secret keys/vault.slh-dsa-shake-128f.secret.wrapped.json \\',
    '  --passphrase-env PQFORGE_PASSPHRASE --kind document \\',
    '  --in archive.pdf --out archive.slh.sig.json',
  ]);

  @override
  Future<void> run() async {
    final results = argResults!;
    final passphrase = await passphraseFrom(results);
    final signer = await readKey(
      results['signer-secret'] as String,
      passphrase: passphrase,
    );
    requireKind(signer, PqKeyKind.signatureSecret);
    final input = File(results['in'] as String);
    final quiet = quietFrom(results);
    final slhDsa = PqSlhDsaAlgorithm.tryById(signer.algorithmId);
    final mlDsa = slhDsa == null
        ? PqSignatureAlgorithm.byId(signer.algorithmId)
        : null;
    final algorithmId = slhDsa?.id ?? mlDsa!.id;
    final algorithmName = slhDsa?.name ?? mlDsa!.name;
    final forge = PqForge(profile: profileForPqcSignatureId(algorithmId));
    final kind = results['kind'] as String;
    final fileName = input.uri.pathSegments.last;
    final output = File(results['out'] as String);

    await withFileProgress(
      quiet: quiet,
      operation: 'signing',
      path: fileName,
      bytes: await input.length(),
      action: (_) async {
        final bytes = await input.readAsBytes();
        late final Map<String, Object?> json;
        switch (kind) {
          case 'text':
            final textId = results['text-id'] as String? ?? fileName;
            final signature = forge.signText(
              signerSecretKey: signer.bytes,
              text: utf8.decode(bytes),
              textId: textId,
              algorithm: mlDsa,
              slhDsa: slhDsa,
            );
            json = signatureJson(
              kind: kind,
              algorithmId: algorithmId,
              signature: signature,
              extra: {'textId': textId, 'encoding': 'utf-8'},
            );
          case 'media':
            final mediaId = results['media-id'] as String? ?? fileName;
            final mimeType =
                results['mime-type'] as String? ?? guessMimeType(input.path);
            final signature = forge.signMedia(
              signerSecretKey: signer.bytes,
              mediaId: mediaId,
              mimeType: mimeType,
              mediaBytes: bytes,
              algorithm: mlDsa,
              slhDsa: slhDsa,
            );
            json = signatureJson(
              kind: kind,
              algorithmId: algorithmId,
              signature: signature,
              extra: {'mediaId': mediaId, 'mimeType': mimeType},
            );
          case 'artifact':
            final artifactId = results['artifact-id'] as String? ?? fileName;
            final version = int.parse(results['version'] as String);
            final artifact = forge.signArtifact(
              signerSecretKey: signer.bytes,
              artifactId: artifactId,
              version: version,
              artifactBytes: bytes,
              algorithm: mlDsa,
              slhDsa: slhDsa,
            );
            json = signatureJson(
              kind: kind,
              algorithmId: algorithmId,
              signature: artifact.signature,
              extra: {
                'artifactId': artifactId,
                'version': version,
                'artifactHash': base64Encode(artifact.artifactHash),
              },
            );
          default:
            final documentId = results['document-id'] as String? ?? fileName;
            final signature = forge.signDocument(
              signer.bytes,
              bytes,
              documentId: documentId,
              algorithm: mlDsa,
              slhDsa: slhDsa,
            );
            json = signatureJson(
              kind: 'document',
              algorithmId: algorithmId,
              signature: signature,
              extra: {'documentId': documentId},
            );
        }
        await writeJson(output, json);
      },
    );
    if (!quiet) {
      console.detail('algorithm', '$kind, $algorithmName');
      console.created(output.path);
    }
  }
}

/// `verify` — verify detached ML-DSA or SLH-DSA recipe signatures.
final class VerifyCommand extends Command<void> {
  VerifyCommand() {
    argParser
      ..addOption(
        'signer-public',
        mandatory: true,
        valueHelp: 'file',
        help: 'ML-DSA or SLH-DSA public key JSON from pqforge keygen.',
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
        help: 'Signature JSON file.',
      )
      ..addOption(
        'document-id',
        valueHelp: 'id',
        help: 'Override the signature JSON document id.',
      )
      ..addOption(
        'text-id',
        valueHelp: 'id',
        help: 'Override the signature JSON text id.',
      )
      ..addOption(
        'media-id',
        valueHelp: 'id',
        help: 'Override the signature JSON media id.',
      )
      ..addOption(
        'mime-type',
        valueHelp: 'type',
        help: 'Override the signature JSON MIME type.',
      )
      ..addOption(
        'artifact-id',
        valueHelp: 'id',
        help: 'Override the signature JSON artifact id.',
      )
      ..addOption(
        'version',
        valueHelp: 'n',
        help: 'Override the signature JSON artifact version.',
      );
    addQuietOption(argParser);
  }

  @override
  String get name => 'verify';

  @override
  String get description =>
      'Verify detached ML-DSA or SLH-DSA recipe signatures.';

  @override
  String get usageFooter => usageExamples([
    'pqforge verify --signer-public keys/vault.sign.public.json \\',
    '  --in contract.pdf --signature contract.sig.json',
  ]);

  @override
  Future<void> run() async {
    final results = argResults!;
    final signer = await readKey(results['signer-public'] as String);
    requireKind(signer, PqKeyKind.signaturePublic);
    final input = File(results['in'] as String);
    final quiet = quietFrom(results);
    final fileName = input.uri.pathSegments.last;
    final progress = ProgressReporter(
      total: 1,
      operation: 'verifying',
      quiet: quiet,
    );
    progress.startFile(fileName, fileSizeBytes: await input.length());
    late final bool ok;
    late final String kind;
    late final String algorithmName;
    try {
      final bytes = await input.readAsBytes();
      final sigJson = await readJsonMap(File(results['signature'] as String));
      final algorithmId = sigJson['signatureAlgorithm'] as String;
      final slhDsa = PqSlhDsaAlgorithm.tryById(algorithmId);
      final mlDsa = slhDsa == null
          ? PqSignatureAlgorithm.byId(algorithmId)
          : null;
      algorithmName = slhDsa?.name ?? mlDsa!.name;
      final signature = base64Decode(sigJson['signature'] as String);
      kind = sigJson['kind'] as String? ?? 'document';
      final forge = PqForge(profile: profileForPqcSignatureId(algorithmId));

      ok = switch (kind) {
        'text' => forge.verifyText(
          signerPublicKey: signer.bytes,
          text: utf8.decode(bytes),
          textId: results['text-id'] as String? ?? sigJson['textId'] as String,
          signature: signature,
          algorithm: mlDsa,
          slhDsa: slhDsa,
        ),
        'media' => forge.verifyMedia(
          signerPublicKey: signer.bytes,
          mediaId:
              results['media-id'] as String? ?? sigJson['mediaId'] as String,
          mimeType:
              results['mime-type'] as String? ?? sigJson['mimeType'] as String,
          mediaBytes: bytes,
          signature: signature,
          algorithm: mlDsa,
          slhDsa: slhDsa,
        ),
        'artifact' => forge.verifyArtifact(
          signer.bytes,
          bytes,
          PqArtifactSignature(
            artifactId:
                results['artifact-id'] as String? ??
                sigJson['artifactId'] as String,
            version:
                int.tryParse(results['version'] as String? ?? '') ??
                sigJson['version'] as int,
            artifactHash: base64Decode(sigJson['artifactHash'] as String),
            signatureAlgorithm: mlDsa,
            slhDsa: slhDsa,
            signature: signature,
          ),
        ),
        _ => forge.verifyDocument(
          signer.bytes,
          bytes,
          signature,
          documentId:
              results['document-id'] as String? ??
              sigJson['documentId'] as String,
          algorithm: mlDsa,
          slhDsa: slhDsa,
        ),
      };
      if (ok) {
        progress.completeFile(fileName);
      } else {
        progress.failFile(fileName, 'signature mismatch ($kind)');
        exitCode = 1;
      }
    } catch (error) {
      progress.failFile(fileName, error.toString());
      rethrow;
    } finally {
      progress.done();
    }
    if (ok && !quiet) {
      console.detail('algorithm', '$kind, $algorithmName');
    }
  }
}
