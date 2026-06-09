/// Pure post-quantum CLI commands: key generation, file/folder/text/media
/// encryption, and ML-DSA recipe signing and verification.
library;

import 'dart:convert';
import 'dart:io';
import 'dart:isolate';
import 'dart:typed_data';

import 'package:args/args.dart';
import 'package:args/command_runner.dart';
import 'package:pqforge/pqforge_io.dart';

import 'console.dart';
import 'support.dart';

const _profiles = ['compact', 'balanced', 'maximum'];

/// `keygen` — ML-KEM + ML-DSA bundles, plus optional classical keypairs.
final class KeygenCommand extends Command<void> {
  KeygenCommand() {
    argParser
      ..addOption(
        'profile',
        allowed: _profiles,
        defaultsTo: 'balanced',
        valueHelp: 'name',
        help: 'Composition profile for the ML-KEM/ML-DSA bundle.',
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
        allowed: ['x25519', 'ed25519', 'ecdsa-p256'],
        valueHelp: 'algo',
        help:
            'Also generate classical keypairs. Repeatable. x25519 is a '
            'hybrid key-agreement key; ed25519/ecdsa-p256 are hybrid signer '
            'keys for hybrid-sign.',
      )
      ..addFlag(
        'classical-only',
        negatable: false,
        help: 'Skip the ML-KEM/ML-DSA bundle and emit only --classical keys.',
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
      );
    addPassphraseOptions(argParser);
  }

  @override
  String get name => 'keygen';

  @override
  String get description =>
      'Generate ML-KEM/ML-DSA (and optional classical) key material.';

  @override
  String get usageFooter => usageExamples([
    '# Wrapped maximum-profile bundle for a vault',
    'pqforge keygen --profile maximum --key-id vault --out-dir keys \\',
    '  --passphrase-env PQFORGE_PASSPHRASE',
    '# Add an ECDSA-P256 signer key for hybrid-sign',
    'pqforge keygen --key-id vault --out-dir keys --classical ecdsa-p256 \\',
    '  --passphrase-env PQFORGE_PASSPHRASE',
  ]);

  @override
  Future<void> run() async {
    final results = argResults!;
    final profile = PqForgeProfile.byName(results['profile'] as String);
    final keyId = results['key-id'] as String;
    final outDir = Directory(results['out-dir'] as String);
    final classical = results['classical'] as List<String>;
    final classicalOnly = results['classical-only'] as bool;
    final passphrase = await passphraseFrom(results);
    await outDir.create(recursive: true);

    final publicFiles = <String, PqExportedKey>{};
    final secretFiles = <String, PqExportedKey>{};

    if (!classicalOnly) {
      final bundle = PqForge(profile: profile).generateKeys(keyId: keyId);
      publicFiles['$keyId.kem.public.json'] = bundle.exportKemPublicKey();
      publicFiles['$keyId.sign.public.json'] = bundle
          .exportSignaturePublicKey();
      secretFiles['$keyId.kem.secret.json'] = bundle.exportKemSecretKey();
      secretFiles['$keyId.sign.secret.json'] = bundle
          .exportSignatureSecretKey();
    }

    for (final algo in classical) {
      final pair = await _generateClassical(algo, keyId);
      publicFiles['$keyId.$algo.public.json'] = pair.public;
      secretFiles['$keyId.$algo.secret.json'] = pair.secret;
    }

    if (publicFiles.isEmpty && secretFiles.isEmpty) {
      throw const PqForgeException(
        '--classical-only requires at least one --classical algorithm.',
      );
    }

    for (final entry in publicFiles.entries) {
      await writeJson(outDir.child(entry.key), entry.value.toJson());
    }
    await _writeSecrets(secretFiles, outDir, passphrase, results);

    console.section(
      classicalOnly
          ? 'Generated classical key material'
          : 'Generated ${profile.name} key bundle',
    );
    if (!classicalOnly) console.detail('profile', profile.name);
    for (final name in publicFiles.keys) {
      console.created(outDir.child(name).path);
    }
    for (final name in secretFiles.keys) {
      final path = passphrase == null
          ? outDir.child(name).path
          : outDir.child(name.replaceFirst('.json', '.wrapped.json')).path;
      console.created(path);
    }
    if (passphrase == null && secretFiles.isNotEmpty) {
      console.warn(
        'wrote raw secret-key JSON. Pass --passphrase-env, --passphrase-file, '
        'or --passphrase to wrap secrets with Argon2id + AES-256-GCM.',
      );
    }
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
    ArgResults argResults,
  ) async {
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
    const forge = PqForge();
    for (final entry in secretFiles.entries) {
      final wrapped = forge.wrapKeyWithPassphrase(
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
    }
  }
}

/// `encrypt` — encrypt a single file to an ML-KEM public key.
final class EncryptCommand extends Command<void> {
  EncryptCommand() {
    addEnvelopeOptions(argParser, includeProfile: true);
    argParser
      ..addOption(
        'recipient-public',
        mandatory: true,
        valueHelp: 'file',
        help: 'Recipient ML-KEM public key JSON from pqforge keygen.',
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
    addPassphraseOptions(argParser);
  }

  @override
  String get name => 'encrypt';

  @override
  String get description => 'Encrypt a file to an ML-KEM public key.';

  @override
  String get usageFooter => usageExamples([
    'pqforge encrypt --recipient-public keys/vault.kem.public.json \\',
    '  --in report.pdf --out report.pdf.pqf --profile maximum',
  ]);

  @override
  Future<void> run() async {
    final results = argResults!;
    final passphrase = await passphraseFrom(results);
    final recipient = await readKey(results['recipient-public'] as String);
    requireKind(recipient, PqKeyKind.kemPublic);
    final input = File(results['in'] as String);
    final output = File(results['out'] as String);
    final profile = profileFrom(results);
    final signer = await optionalSignerSecret(results, passphrase);

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

    if (length >= PqForgeStreamCipher.streamingThresholdBytes) {
      // Large file: stream it frame-by-frame so peak memory stays a few MB
      // regardless of size (Phase 3). The container is self-describing, so the
      // matching decrypt auto-detects it.
      final stats = await PqForgeStreamCipher().encryptFile(
        recipientPublicKey: recipient.bytes,
        input: input,
        output: output,
        profile: profile,
        aad: aad,
        metadata: metadata,
        signerSecretKey: signer?.bytes,
        signerKeyId: signerKeyId(results, signer),
      );
      console.success(
        'Encrypted to streaming ${profile.name} envelope'
        '${signer == null ? '' : ' (signed)'} — ${stats.frameCount} frames',
      );
      console.created(output.path);
      return;
    }

    // readAsBytes already returns a fresh Uint8List; the prior fromList was a
    // redundant full-file copy (defect M2). PqForge.encrypt copies defensively.
    final plaintext = await input.readAsBytes();
    final envelope = PqForge(profile: profile).encrypt(
      recipient.bytes,
      plaintext,
      aad: aad,
      metadata: metadata,
      profile: profile,
      signerSecretKey: signer?.bytes,
      signerKeyId: signerKeyId(results, signer),
    );
    await writeEnvelope(output, envelope);
    console.success(
      'Encrypted to ${profile.name} envelope${signer == null ? '' : ' (signed)'}',
    );
    console.created(output.path);
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
    addPassphraseOptions(argParser);
  }

  @override
  String get name => 'decrypt';

  @override
  String get description => 'Decrypt a .pqf file with an ML-KEM secret key.';

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

    if (await PqForgeStreamCipher.isStreamingFile(input)) {
      await PqForgeStreamCipher().decryptFile(
        recipientSecretKey: recipient.bytes,
        input: input,
        output: output,
        signerPublicKey: signer?.bytes,
        aadResolver: (header) => PqRecipeMessages.fileAad(
          fileName: _requiredMeta(header.metadata, 'fileName', 'File'),
          aad: optionalAad(results),
        ),
      );
      console.success('Decrypted (streaming)');
      console.created(output.path);
      return;
    }

    final envelope = await readEnvelope(input);
    final aad = PqRecipeMessages.fileAad(
      fileName: _requiredMeta(envelope.metadata, 'fileName', 'File'),
      aad: optionalAad(results),
    );
    final plaintext = PqForge(profile: envelope.profile).decrypt(
      recipient.bytes,
      envelope,
      aad: aad,
      signerPublicKey: signer?.bytes,
    );
    await output.parent.create(recursive: true);
    await output.writeAsBytes(plaintext);
    console.success('Decrypted');
    console.created(output.path);
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
      ..addOption(
        'recipient-public',
        mandatory: true,
        valueHelp: 'file',
        help: 'Recipient ML-KEM public key JSON from pqforge keygen.',
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
    addPassphraseOptions(argParser);
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
    final recipient = await readKey(results['recipient-public'] as String);
    requireKind(recipient, PqKeyKind.kemPublic);
    final inputDir = Directory(results['in-dir'] as String);
    final outputDir = Directory(results['out-dir'] as String);
    final profile = profileFrom(results);
    final signer = await optionalSignerSecret(results, passphrase);
    final aad = optionalAad(results);
    final keyId = signerKeyId(results, signer);
    final concurrency = concurrencyFrom(results);

    // Axis B: one file per background isolate, gated by a semaphore. Each file
    // gets its own DEM key by construction, so there is no shared-nonce hazard.
    final files = await listFiles(inputDir);
    final pool = Semaphore(concurrency);
    await Future.wait(
      files.map((file) async {
        final relativePath = safeRelativePath(inputDir, file);
        await pool.acquire();
        try {
          await _encryptFolderEntryInIsolate(
            recipientPublicKey: recipient.bytes,
            profileName: profile.name,
            inputPath: file.path,
            outputPath: joinPath(outputDir.path, '$relativePath.pqf'),
            relativePath: relativePath,
            aad: aad,
            signerSecretKey: signer?.bytes,
            signerKeyId: keyId,
          );
        } finally {
          pool.release();
        }
      }),
    );
    console.success(
      'Encrypted ${files.length} file(s) to ${profile.name} envelopes '
      '(concurrency $concurrency)',
    );
    console.detail('output', outputDir.path);
  }
}

/// Encrypts one folder entry on a background isolate (Axis B). Large entries are
/// streamed (`.pqfs`), small ones use a one-shot envelope; both carry the same
/// folder-entry AAD and metadata so [_decryptFolderEntryInIsolate] auto-routes.
Future<void> _encryptFolderEntryInIsolate({
  required Uint8List recipientPublicKey,
  required String profileName,
  required String inputPath,
  required String outputPath,
  required String relativePath,
  required Uint8List? aad,
  required Uint8List? signerSecretKey,
  required String? signerKeyId,
}) {
  return Isolate.run(() async {
    final profile = PqForgeProfile.byName(profileName);
    final input = File(inputPath);
    final output = File(outputPath);
    final length = await input.length();

    if (length >= PqForgeStreamCipher.streamingThresholdBytes) {
      await PqForgeStreamCipher().encryptFile(
        recipientPublicKey: recipientPublicKey,
        input: input,
        output: output,
        profile: profile,
        aad: PqRecipeMessages.folderEntryAad(
          relativePath: relativePath,
          aad: aad,
        ),
        metadata: {
          'recipe': 'folder-entry-encryption',
          'fileName': relativePath.split('/').last,
          'relativePath': relativePath,
          'contentLength': length,
        },
        signerSecretKey: signerSecretKey,
        signerKeyId: signerKeyId,
      );
      return;
    }

    final envelope = PqForge(profile: profile).encryptFolderEntry(
      recipientPublicKey,
      await input.readAsBytes(),
      relativePath: relativePath,
      aad: aad,
      profile: profile,
      signerSecretKey: signerSecretKey,
      signerKeyId: signerKeyId,
    );
    await output.parent.create(recursive: true);
    await output.writeAsBytes(envelope.toBinary());
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
    addPassphraseOptions(argParser);
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
    final inputDir = Directory(results['in-dir'] as String);
    final outputDir = Directory(results['out-dir'] as String);
    final signer = await optionalPublicKey(
      results['signer-public'] as String?,
      PqKeyKind.signaturePublic,
    );
    final aad = optionalAad(results);
    final concurrency = concurrencyFrom(results);

    final files = (await listFiles(inputDir))
        .where((file) => file.path.endsWith('.pqf'))
        .toList();
    final pool = Semaphore(concurrency);
    await Future.wait(
      files.map((file) async {
        await pool.acquire();
        try {
          await _decryptFolderEntryInIsolate(
            recipientSecretKey: recipient.bytes,
            inputPath: file.path,
            outputDirPath: outputDir.path,
            aad: aad,
            signerPublicKey: signer?.bytes,
          );
        } finally {
          pool.release();
        }
      }),
    );
    console.success(
      'Decrypted ${files.length} file(s) (concurrency $concurrency)',
    );
    console.detail('output', outputDir.path);
  }
}

/// Decrypts one folder entry on a background isolate, auto-routing between the
/// streaming (`.pqfs`) and one-shot envelope formats. The relative path comes
/// from the (header-bound) metadata and is re-validated against path traversal.
Future<void> _decryptFolderEntryInIsolate({
  required Uint8List recipientSecretKey,
  required String inputPath,
  required String outputDirPath,
  required Uint8List? aad,
  required Uint8List? signerPublicKey,
}) {
  return Isolate.run(() async {
    final input = File(inputPath);
    if (await PqForgeStreamCipher.isStreamingFile(input)) {
      final header = await PqForgeStreamCipher().readHeader(input);
      final relativePath = _folderRelativePath(header.metadata, input.path);
      await PqForgeStreamCipher().decryptFile(
        recipientSecretKey: recipientSecretKey,
        input: input,
        output: File(joinPath(outputDirPath, relativePath)),
        signerPublicKey: signerPublicKey,
        aadResolver: (_) => PqRecipeMessages.folderEntryAad(
          relativePath: relativePath,
          aad: aad,
        ),
      );
      return;
    }

    final envelope = await readEnvelope(input);
    final relativePath = _folderRelativePath(envelope.metadata, input.path);
    final plaintext = PqForge(profile: envelope.profile).decryptFolderEntry(
      recipientSecretKey,
      envelope,
      aad: aad,
      signerPublicKey: signerPublicKey,
    );
    final output = File(joinPath(outputDirPath, relativePath));
    await output.parent.create(recursive: true);
    await output.writeAsBytes(plaintext);
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
      ..addOption(
        'recipient-public',
        mandatory: true,
        valueHelp: 'file',
        help: 'Recipient ML-KEM public key JSON from pqforge keygen.',
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
    addPassphraseOptions(argParser);
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
    final recipient = await readKey(results['recipient-public'] as String);
    requireKind(recipient, PqKeyKind.kemPublic);
    final (text, defaultTextId) = await readTextInput(results);
    final textId = results['text-id'] as String? ?? defaultTextId;
    final profile = profileFrom(results);
    final signer = await optionalSignerSecret(results, passphrase);
    final envelope = PqForge(profile: profile).sealText(
      recipient.bytes,
      text,
      textId: textId,
      aad: optionalAad(results),
      profile: profile,
      signerSecretKey: signer?.bytes,
      signerKeyId: signerKeyId(results, signer),
    );
    final output = File(results['out'] as String);
    await writeEnvelope(output, envelope);
    console.success('Encrypted text (id: $textId)');
    console.created(output.path);
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
    addPassphraseOptions(argParser);
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
    final envelope = await readEnvelope(File(results['in'] as String));
    final signer = await optionalPublicKey(
      results['signer-public'] as String?,
      PqKeyKind.signaturePublic,
    );
    final text = PqForge(profile: envelope.profile).openText(
      recipient.bytes,
      envelope,
      aad: optionalAad(results),
      signerPublicKey: signer?.bytes,
    );
    final output = results['out'] as String?;
    if (output == null) {
      // No --out: emit the decrypted text raw so it stays pipeable.
      console.raw(text);
    } else {
      await File(output).writeAsString(text);
      console.success('Decrypted text');
      console.created(output);
    }
  }
}

/// `encrypt-media` — encrypt media bytes with media id and MIME binding.
final class EncryptMediaCommand extends Command<void> {
  EncryptMediaCommand() {
    addEnvelopeOptions(argParser, includeProfile: true);
    argParser
      ..addOption(
        'recipient-public',
        mandatory: true,
        valueHelp: 'file',
        help: 'Recipient ML-KEM public key JSON from pqforge keygen.',
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
    addPassphraseOptions(argParser);
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
    final recipient = await readKey(results['recipient-public'] as String);
    requireKind(recipient, PqKeyKind.kemPublic);
    final input = File(results['in'] as String);
    final mediaId =
        results['media-id'] as String? ?? input.uri.pathSegments.last;
    final mimeType =
        results['mime-type'] as String? ?? guessMimeType(input.path);
    final profile = profileFrom(results);
    final signer = await optionalSignerSecret(results, passphrase);
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

    if (length >= PqForgeStreamCipher.streamingThresholdBytes) {
      final stats = await PqForgeStreamCipher().encryptFile(
        recipientPublicKey: recipient.bytes,
        input: input,
        output: output,
        profile: profile,
        aad: aad,
        metadata: metadata,
        signerSecretKey: signer?.bytes,
        signerKeyId: signerKeyId(results, signer),
      );
      console.success(
        'Encrypted media (id: $mediaId, $mimeType) to streaming envelope'
        '${signer == null ? '' : ' (signed)'} — ${stats.frameCount} frames',
      );
      console.created(output.path);
      return;
    }

    final bytes = await input.readAsBytes(); // M2: no redundant full-file copy
    final envelope = PqForge(profile: profile).sealMedia(
      recipient.bytes,
      bytes,
      mediaId: mediaId,
      mimeType: mimeType,
      aad: optionalAad(results),
      profile: profile,
      signerSecretKey: signer?.bytes,
      signerKeyId: signerKeyId(results, signer),
    );
    await writeEnvelope(output, envelope);
    console.success('Encrypted media (id: $mediaId, $mimeType)');
    console.created(output.path);
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
    addPassphraseOptions(argParser);
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

    if (await PqForgeStreamCipher.isStreamingFile(input)) {
      await PqForgeStreamCipher().decryptFile(
        recipientSecretKey: recipient.bytes,
        input: input,
        output: output,
        signerPublicKey: signer?.bytes,
        aadResolver: (header) => PqRecipeMessages.mediaAad(
          mediaId: _requiredMeta(header.metadata, 'mediaId', 'media'),
          mimeType: _requiredMeta(header.metadata, 'mimeType', 'media'),
          aad: optionalAad(results),
        ),
      );
      console.success('Decrypted media (streaming)');
      console.created(output.path);
      return;
    }

    final envelope = await readEnvelope(input);
    final media = PqForge(profile: envelope.profile).openMedia(
      recipient.bytes,
      envelope,
      aad: optionalAad(results),
      signerPublicKey: signer?.bytes,
    );
    await output.parent.create(recursive: true);
    await output.writeAsBytes(media);
    console.success('Decrypted media');
    console.created(output.path);
  }
}

/// `sign` — detached ML-DSA recipe signatures (document/text/media/artifact).
final class SignCommand extends Command<void> {
  SignCommand() {
    argParser
      ..addOption(
        'signer-secret',
        mandatory: true,
        valueHelp: 'file',
        help: 'Raw or wrapped ML-DSA secret key JSON from pqforge keygen.',
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
  }

  @override
  String get name => 'sign';

  @override
  String get description => 'Create detached ML-DSA recipe signatures.';

  @override
  String get usageFooter => usageExamples([
    'pqforge sign --signer-secret keys/vault.sign.secret.wrapped.json \\',
    '  --passphrase-env PQFORGE_PASSPHRASE --kind document \\',
    '  --in contract.pdf --document-id contract-2026-001 --out contract.sig.json',
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
    final bytes = await input.readAsBytes(); // M2: no redundant full-file copy
    final algorithm = PqSignatureAlgorithm.byId(signer.algorithmId);
    final forge = PqForge(profile: profileForSignature(algorithm));
    final kind = results['kind'] as String;
    final fileName = input.uri.pathSegments.last;

    late final Map<String, Object?> json;
    switch (kind) {
      case 'text':
        final textId = results['text-id'] as String? ?? fileName;
        final signature = forge.signText(
          signerSecretKey: signer.bytes,
          text: utf8.decode(bytes),
          textId: textId,
          algorithm: algorithm,
        );
        json = signatureJson(
          kind: kind,
          algorithm: algorithm,
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
          algorithm: algorithm,
        );
        json = signatureJson(
          kind: kind,
          algorithm: algorithm,
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
          algorithm: algorithm,
        );
        json = signatureJson(
          kind: kind,
          algorithm: algorithm,
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
          algorithm: algorithm,
        );
        json = signatureJson(
          kind: 'document',
          algorithm: algorithm,
          signature: signature,
          extra: {'documentId': documentId},
        );
    }
    final output = File(results['out'] as String);
    await writeJson(output, json);
    console.success('Signed ($kind, ${algorithm.name})');
    console.created(output.path);
  }
}

/// `verify` — verify detached ML-DSA recipe signatures.
final class VerifyCommand extends Command<void> {
  VerifyCommand() {
    argParser
      ..addOption(
        'signer-public',
        mandatory: true,
        valueHelp: 'file',
        help: 'ML-DSA public key JSON from pqforge keygen.',
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
  }

  @override
  String get name => 'verify';

  @override
  String get description => 'Verify detached ML-DSA recipe signatures.';

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
    final bytes = await input.readAsBytes(); // M2: no redundant full-file copy
    final sigJson = await readJsonMap(File(results['signature'] as String));
    final algorithm = PqSignatureAlgorithm.byId(
      sigJson['signatureAlgorithm'] as String,
    );
    final signature = base64Decode(sigJson['signature'] as String);
    final kind = sigJson['kind'] as String? ?? 'document';
    final forge = PqForge(profile: profileForSignature(algorithm));

    final ok = switch (kind) {
      'text' => forge.verifyText(
        signerPublicKey: signer.bytes,
        text: utf8.decode(bytes),
        textId: results['text-id'] as String? ?? sigJson['textId'] as String,
        signature: signature,
        algorithm: algorithm,
      ),
      'media' => forge.verifyMedia(
        signerPublicKey: signer.bytes,
        mediaId: results['media-id'] as String? ?? sigJson['mediaId'] as String,
        mimeType:
            results['mime-type'] as String? ?? sigJson['mimeType'] as String,
        mediaBytes: bytes,
        signature: signature,
        algorithm: algorithm,
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
          signatureAlgorithm: algorithm,
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
        algorithm: algorithm,
      ),
    };
    if (ok) {
      console.success('Signature verified ($kind, ${algorithm.name})');
    } else {
      console.failure('Signature verification FAILED ($kind)');
      exitCode = 1;
    }
  }
}
