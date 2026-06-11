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
const _classicalAlgorithms = ['x25519', 'ed25519', 'ecdsa-p256'];

/// `keygen` — ML-KEM + ML-DSA bundles plus the classical keypairs that make
/// every hybrid workflow (hybrid encrypt, hybrid-sign) work out of the box.
final class KeygenCommand extends Command<void> {
  KeygenCommand() {
    argParser
      ..addOption(
        'profile',
        allowed: _profiles,
        defaultsTo: 'maximum',
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
        help: 'Generate only the ML-KEM/ML-DSA bundle (skip classical keys).',
      )
      ..addFlag(
        'classical-only',
        negatable: false,
        help: 'Skip the ML-KEM/ML-DSA bundle and emit only classical keys.',
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
      'Generate ML-KEM/ML-DSA and classical (hybrid) key material.';

  @override
  String get usageFooter => usageExamples([
    '# Wrapped maximum-profile bundle + X25519/Ed25519/ECDSA-P256 hybrid keys',
    'pqforge keygen --profile maximum --key-id vault --out-dir keys \\',
    '  --passphrase-env PQFORGE_PASSPHRASE',
    '# Post-quantum bundle only',
    'pqforge keygen --key-id vault --out-dir keys --no-classical \\',
    '  --passphrase-env PQFORGE_PASSPHRASE',
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
    if (noClassical && (classicalOnly || selectedClassical.isNotEmpty)) {
      throw const PqForgeException(
        '--no-classical cannot be combined with --classical/--classical-only.',
      );
    }
    // All classical keys by default: hybrid encryption and hybrid signing then
    // work out of the box. --classical narrows, --no-classical opts out.
    final classical = noClassical
        ? const <String>[]
        : (selectedClassical.isEmpty
              ? _classicalAlgorithms
              : selectedClassical);
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
    await _writeSecrets(secretFiles, outDir, passphrase, results);

    console.section(
      classicalOnly
          ? 'Generated classical key material'
          : 'Generated ${profile.name} key bundle',
    );
    if (!classicalOnly) {
      console.detail('profile', profile.name);
      console.detail(
        'pqc',
        '${profile.kem.name} (encryption) · ${profile.signature.name} '
            '(signatures)',
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
    if (!classicalOnly && classical.contains('x25519')) {
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

/// Prints the suite/engine/signature detail lines every encrypt/decrypt
/// command emits, so the algorithm combination in effect is always visible.
void _printSuite({
  required PqForgeProfile profile,
  required bool hybrid,
  PqForgeEngineProvider? engine,
  PqSignatureAlgorithm? signature,
}) {
  console.detail('suite', suiteLabel(profile, hybrid: hybrid));
  if (engine != null) console.detail('engine', engineLabel(engine));
  if (signature != null) console.detail('signature', signature.name);
}

/// `encrypt` — encrypt a single file to an ML-KEM public key, optionally
/// hybridized with the recipient's X25519 key.
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
    addHybridEncryptOptions(argParser);
    addEngineOption(argParser);
    addPassphraseOptions(argParser);
  }

  @override
  String get name => 'encrypt';

  @override
  String get description =>
      'Encrypt a file to an ML-KEM public key (add --hybrid for '
      'ML-KEM + X25519).';

  @override
  String get usageFooter => usageExamples([
    'pqforge encrypt --recipient-public keys/vault.kem.public.json \\',
    '  --in report.pdf --out report.pdf.pqf --profile maximum',
    '# Hybrid: ML-KEM + X25519 (uses keys/vault.x25519.public.json)',
    'pqforge encrypt --hybrid --recipient-public keys/vault.kem.public.json \\',
    '  --in report.pdf --out report.pdf.pqf',
  ]);

  @override
  Future<void> run() async {
    final results = argResults!;
    final passphrase = await passphraseFrom(results);
    final recipient = await readKey(results['recipient-public'] as String);
    requireKind(recipient, PqKeyKind.kemPublic);
    final kexPublic = await hybridKexPublicFrom(results);
    final input = File(results['in'] as String);
    final output = File(results['out'] as String);
    final profile = resolveProfile(results);
    final signer = await optionalSignerSecret(results, passphrase);
    final engineProvider = engineFrom(results);

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
      final stats = await PqForgeStreamCipher.forProvider(engineProvider)
          .encryptFile(
            recipientPublicKey: recipient.bytes,
            recipientKexPublicKey: kexPublic?.bytes,
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
      _printSuite(
        profile: profile,
        hybrid: kexPublic != null,
        engine: engineProvider,
        signature: signer == null ? null : profile.signature,
      );
      console.created(output.path);
      return;
    }

    // readAsBytes already returns a fresh Uint8List; the prior fromList was a
    // redundant full-file copy (defect M2). encryptAsync runs the DEM stage on
    // the selected engine, so small files get the same ~10x AEAD speedup as
    // the streaming path instead of being pinned to PointyCastle.
    final plaintext = await input.readAsBytes();
    final envelope = await PqForge(profile: profile).encryptAsync(
      recipient.bytes,
      plaintext,
      recipientKexPublicKey: kexPublic?.bytes,
      engine: aeadEngineForProvider(engineProvider),
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
    _printSuite(
      profile: profile,
      hybrid: kexPublic != null,
      engine: engineProvider,
      signature: signer == null ? null : profile.signature,
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
    addHybridDecryptOptions(argParser);
    addEngineOption(argParser);
    addPassphraseOptions(argParser);
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

    if (await PqForgeStreamCipher.isStreamingFile(input)) {
      final cipher = PqForgeStreamCipher.forProvider(engineProvider);
      final peek = await cipher.readHeader(input);
      final hybrid = PqHybridKemDem.isHybrid(peek.metadata);
      final kexSecret = await hybridKexSecretFrom(
        results,
        passphrase,
        hybridInput: hybrid,
      );
      final header = await cipher.decryptFile(
        recipientSecretKey: recipient.bytes,
        recipientKexSecretKey: kexSecret?.bytes,
        input: input,
        output: output,
        signerPublicKey: signer?.bytes,
        aadResolver: (header) => PqRecipeMessages.fileAad(
          fileName: _requiredMeta(header.metadata, 'fileName', 'File'),
          aad: optionalAad(results),
        ),
      );
      console.success('Decrypted (streaming)');
      _printSuite(
        profile: header.profile,
        hybrid: hybrid,
        engine: engineProvider,
        signature: header.isSigned ? header.signatureAlgorithm : null,
      );
      console.created(output.path);
      return;
    }

    final envelope = await readEnvelope(input);
    final hybrid = PqHybridKemDem.isHybrid(envelope.metadata);
    final kexSecret = await hybridKexSecretFrom(
      results,
      passphrase,
      hybridInput: hybrid,
    );
    final aad = PqRecipeMessages.fileAad(
      fileName: _requiredMeta(envelope.metadata, 'fileName', 'File'),
      aad: optionalAad(results),
    );
    final plaintext = await PqForge(profile: envelope.profile).decryptAsync(
      recipient.bytes,
      envelope,
      recipientKexSecretKey: kexSecret?.bytes,
      engine: aeadEngineForProvider(engineProvider),
      aad: aad,
      signerPublicKey: signer?.bytes,
    );
    await output.parent.create(recursive: true);
    await output.writeAsBytes(plaintext);
    console.success('Decrypted');
    _printSuite(
      profile: envelope.profile,
      hybrid: hybrid,
      engine: engineProvider,
      signature: envelope.isSigned ? envelope.signatureAlgorithm : null,
    );
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
    addHybridEncryptOptions(argParser);
    addEngineOption(argParser);
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
    final kexPublic = await hybridKexPublicFrom(results);
    final inputDir = Directory(results['in-dir'] as String);
    final outputDir = Directory(results['out-dir'] as String);
    final profile = resolveProfile(results);
    final signer = await optionalSignerSecret(results, passphrase);
    final aad = optionalAad(results);
    final keyId = signerKeyId(results, signer);
    final concurrency = concurrencyFrom(results);
    final engineProvider = engineFrom(results);

    // Axis B: one file per background isolate, gated by a semaphore. Each file
    // gets its own DEM key by construction, so there is no shared-nonce hazard.
    // The walk is streamed straight into the pool — work starts on the first
    // file found, and no sorted whole-tree list is ever materialized.
    final pool = Semaphore(concurrency);
    final tasks = <Future<void>>[];
    await for (final entity in inputDir.list(
      recursive: true,
      followLinks: false,
    )) {
      if (entity is! File) continue;
      final relativePath = safeRelativePath(inputDir, entity);
      tasks.add(() async {
        await pool.acquire();
        try {
          await _encryptFolderEntryInIsolate(
            recipientPublicKey: recipient.bytes,
            recipientKexPublicKey: kexPublic?.bytes,
            profile: profile,
            inputPath: entity.path,
            outputPath: joinPath(outputDir.path, '$relativePath.pqf'),
            relativePath: relativePath,
            aad: aad,
            signerSecretKey: signer?.bytes,
            signerKeyId: keyId,
            engineProvider: engineProvider,
          );
        } finally {
          pool.release();
        }
      }());
    }
    await Future.wait(tasks);
    console.success(
      'Encrypted ${tasks.length} file(s) to ${profile.name} envelopes '
      '(concurrency $concurrency)',
    );
    _printSuite(
      profile: profile,
      hybrid: kexPublic != null,
      engine: engineProvider,
      signature: signer == null ? null : profile.signature,
    );
    console.detail('output', outputDir.path);
  }
}

/// Encrypts one folder entry on a background isolate (Axis B). Large entries are
/// streamed (`.pqfs`), small ones use a one-shot envelope; both carry the same
/// folder-entry AAD and metadata so [_decryptFolderEntryInIsolate] auto-routes,
/// and both run their DEM stage on the selected engine.
Future<void> _encryptFolderEntryInIsolate({
  required Uint8List recipientPublicKey,
  required Uint8List? recipientKexPublicKey,
  required PqForgeProfile profile,
  required String inputPath,
  required String outputPath,
  required String relativePath,
  required Uint8List? aad,
  required Uint8List? signerSecretKey,
  required String? signerKeyId,
  required PqForgeEngineProvider engineProvider,
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

    if (length >= PqForgeStreamCipher.streamingThresholdBytes) {
      await PqForgeStreamCipher.forProvider(engineProvider).encryptFile(
        recipientPublicKey: recipientPublicKey,
        recipientKexPublicKey: recipientKexPublicKey,
        input: input,
        output: output,
        profile: profile,
        aad: entryAad,
        metadata: metadata,
        signerSecretKey: signerSecretKey,
        signerKeyId: signerKeyId,
      );
      return;
    }

    final envelope = await PqForge(profile: profile).encryptAsync(
      recipientPublicKey,
      await input.readAsBytes(),
      recipientKexPublicKey: recipientKexPublicKey,
      engine: aeadEngineForProvider(engineProvider),
      aad: entryAad,
      metadata: metadata,
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
    addHybridDecryptOptions(argParser);
    addEngineOption(argParser);
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
    // Trees can mix hybrid and pure-PQC entries, so the X25519 key is resolved
    // opportunistically up front; a hybrid entry with no key fails per-file
    // with the library's descriptive error.
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

    // Streamed walk into the bounded pool (mirrors encrypt-folder).
    final pool = Semaphore(concurrency);
    final tasks = <Future<void>>[];
    await for (final entity in inputDir.list(
      recursive: true,
      followLinks: false,
    )) {
      if (entity is! File || !entity.path.endsWith('.pqf')) continue;
      tasks.add(() async {
        await pool.acquire();
        try {
          await _decryptFolderEntryInIsolate(
            recipientSecretKey: recipient.bytes,
            recipientKexSecretKey: kexSecret?.bytes,
            inputPath: entity.path,
            outputDirPath: outputDir.path,
            aad: aad,
            signerPublicKey: signer?.bytes,
            engineProvider: engineProvider,
          );
        } finally {
          pool.release();
        }
      }());
    }
    await Future.wait(tasks);
    console.success(
      'Decrypted ${tasks.length} file(s) (concurrency $concurrency)',
    );
    console.detail('engine', engineLabel(engineProvider));
    console.detail('output', outputDir.path);
  }
}

/// Decrypts one folder entry on a background isolate, auto-routing between the
/// streaming (`.pqfs`) and one-shot envelope formats. The relative path comes
/// from the (header-bound) metadata and is re-validated against path traversal.
Future<void> _decryptFolderEntryInIsolate({
  required Uint8List recipientSecretKey,
  required Uint8List? recipientKexSecretKey,
  required String inputPath,
  required String outputDirPath,
  required Uint8List? aad,
  required Uint8List? signerPublicKey,
  required PqForgeEngineProvider engineProvider,
}) {
  return Isolate.run(() async {
    final input = File(inputPath);
    if (await PqForgeStreamCipher.isStreamingFile(input)) {
      final header = await PqForgeStreamCipher.forProvider(
        engineProvider,
      ).readHeader(input);
      final relativePath = _folderRelativePath(header.metadata, input.path);
      await PqForgeStreamCipher.forProvider(engineProvider).decryptFile(
        recipientSecretKey: recipientSecretKey,
        recipientKexSecretKey: recipientKexSecretKey,
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
    final plaintext = await PqForge(profile: envelope.profile).decryptAsync(
      recipientSecretKey,
      envelope,
      recipientKexSecretKey: recipientKexSecretKey,
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
    addHybridEncryptOptions(argParser);
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
    final kexPublic = await hybridKexPublicFrom(results);
    final (text, defaultTextId) = await readTextInput(results);
    final textId = results['text-id'] as String? ?? defaultTextId;
    final profile = resolveProfile(results);
    final signer = await optionalSignerSecret(results, passphrase);
    // Same AAD and metadata as PqForge.sealText, routed through encryptAsync
    // so the hybrid marker can ride along.
    final envelope = await PqForge(profile: profile).encryptAsync(
      recipient.bytes,
      PqBytes.utf8Bytes(text),
      recipientKexPublicKey: kexPublic?.bytes,
      aad: PqRecipeMessages.textAad(textId: textId, aad: optionalAad(results)),
      metadata: {'recipe': 'text-seal', 'textId': textId, 'encoding': 'utf-8'},
      profile: profile,
      signerSecretKey: signer?.bytes,
      signerKeyId: signerKeyId(results, signer),
    );
    final output = File(results['out'] as String);
    await writeEnvelope(output, envelope);
    console.success('Encrypted text (id: $textId)');
    _printSuite(
      profile: profile,
      hybrid: kexPublic != null,
      signature: signer == null ? null : profile.signature,
    );
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
    addHybridDecryptOptions(argParser);
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
    final kexSecret = await hybridKexSecretFrom(
      results,
      passphrase,
      hybridInput: PqHybridKemDem.isHybrid(envelope.metadata),
    );
    // Mirrors PqForge.openText (textId/encoding checks + text AAD) on the
    // hybrid-capable async path.
    final textId = _requiredMeta(envelope.metadata, 'textId', 'text');
    final encoding = envelope.metadata['encoding'] as String? ?? 'utf-8';
    if (encoding != 'utf-8') {
      throw PqForgeException('Unsupported text envelope encoding: $encoding');
    }
    final plaintext = await PqForge(profile: envelope.profile).decryptAsync(
      recipient.bytes,
      envelope,
      recipientKexSecretKey: kexSecret?.bytes,
      aad: PqRecipeMessages.textAad(textId: textId, aad: optionalAad(results)),
      signerPublicKey: signer?.bytes,
    );
    final text = utf8.decode(plaintext);
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
    addHybridEncryptOptions(argParser);
    addEngineOption(argParser);
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
    final kexPublic = await hybridKexPublicFrom(results);
    final input = File(results['in'] as String);
    final mediaId =
        results['media-id'] as String? ?? input.uri.pathSegments.last;
    final mimeType =
        results['mime-type'] as String? ?? guessMimeType(input.path);
    final profile = resolveProfile(results);
    final signer = await optionalSignerSecret(results, passphrase);
    final engineProvider = engineFrom(results);
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
      final stats = await PqForgeStreamCipher.forProvider(engineProvider)
          .encryptFile(
            recipientPublicKey: recipient.bytes,
            recipientKexPublicKey: kexPublic?.bytes,
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
      _printSuite(
        profile: profile,
        hybrid: kexPublic != null,
        engine: engineProvider,
        signature: signer == null ? null : profile.signature,
      );
      console.created(output.path);
      return;
    }

    final bytes = await input.readAsBytes(); // M2: no redundant full-file copy
    final envelope = await PqForge(profile: profile).encryptAsync(
      recipient.bytes,
      bytes,
      recipientKexPublicKey: kexPublic?.bytes,
      engine: aeadEngineForProvider(engineProvider),
      aad: aad,
      metadata: metadata,
      profile: profile,
      signerSecretKey: signer?.bytes,
      signerKeyId: signerKeyId(results, signer),
    );
    await writeEnvelope(output, envelope);
    console.success('Encrypted media (id: $mediaId, $mimeType)');
    _printSuite(
      profile: profile,
      hybrid: kexPublic != null,
      engine: engineProvider,
      signature: signer == null ? null : profile.signature,
    );
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
    addHybridDecryptOptions(argParser);
    addEngineOption(argParser);
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
    final engineProvider = engineFrom(results);

    if (await PqForgeStreamCipher.isStreamingFile(input)) {
      final cipher = PqForgeStreamCipher.forProvider(engineProvider);
      final peek = await cipher.readHeader(input);
      final hybrid = PqHybridKemDem.isHybrid(peek.metadata);
      final kexSecret = await hybridKexSecretFrom(
        results,
        passphrase,
        hybridInput: hybrid,
      );
      await cipher.decryptFile(
        recipientSecretKey: recipient.bytes,
        recipientKexSecretKey: kexSecret?.bytes,
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
      _printSuite(
        profile: peek.profile,
        hybrid: hybrid,
        engine: engineProvider,
        signature: peek.isSigned ? peek.signatureAlgorithm : null,
      );
      console.created(output.path);
      return;
    }

    final envelope = await readEnvelope(input);
    final hybrid = PqHybridKemDem.isHybrid(envelope.metadata);
    final kexSecret = await hybridKexSecretFrom(
      results,
      passphrase,
      hybridInput: hybrid,
    );
    final mediaId = _requiredMeta(envelope.metadata, 'mediaId', 'media');
    final mimeType = _requiredMeta(envelope.metadata, 'mimeType', 'media');
    final media = await PqForge(profile: envelope.profile).decryptAsync(
      recipient.bytes,
      envelope,
      recipientKexSecretKey: kexSecret?.bytes,
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
    console.success('Decrypted media');
    _printSuite(
      profile: envelope.profile,
      hybrid: hybrid,
      engine: engineProvider,
      signature: envelope.isSigned ? envelope.signatureAlgorithm : null,
    );
    console.created(output.path);
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
    addPassphraseOptions(argParser);
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
    final recipient = await readKey(results['recipient-public'] as String);
    requireKind(recipient, PqKeyKind.kemPublic);
    final kexPublic = await hybridKexPublicFrom(results);
    final inputDir = Directory(results['in-dir'] as String);
    final output = File(results['out'] as String);
    final profile = resolveProfile(results);
    final signer = await optionalSignerSecret(results, passphrase);
    final aad = optionalAad(results);
    final engineProvider = engineFrom(results);

    final entries = [
      for (final file in await listFiles(inputDir))
        PqPackEntry(
          relativePath: safeRelativePath(inputDir, file),
          sourcePath: file.path,
        ),
    ];

    // The pack stream is piped straight into the AEAD writer: the plaintext
    // archive never exists on disk (no temp spool, no extra free-space need).
    final stats = await PqForgeStreamCipher.forProvider(engineProvider)
        .encryptStream(
          recipientPublicKey: recipient.bytes,
          recipientKexPublicKey: kexPublic?.bytes,
          source: PqFolderPack.packStream(entries),
          output: output,
          profile: profile,
          aad: PqRecipeMessages.folderPackAad(aad: aad),
          metadata: {'recipe': 'folder-pack', 'entryCount': entries.length},
          signerSecretKey: signer?.bytes,
          signerKeyId: signerKeyId(results, signer),
        );
    console.success(
      'Packed ${entries.length} file(s) into a streaming ${profile.name} '
      'archive${signer == null ? '' : ' (signed)'} — ${stats.frameCount} frames',
    );
    _printSuite(
      profile: profile,
      hybrid: kexPublic != null,
      engine: engineProvider,
      signature: signer == null ? null : profile.signature,
    );
    console.created(output.path);
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
    );

    // Authenticated plaintext frames stream straight into the unpacker — no
    // decrypted temp file. On any failure the unpacker removes the files it
    // created, so no partial tree is left behind.
    final frames = cipher.decryptStream(
      recipientSecretKey: recipient.bytes,
      recipientKexSecretKey: kexSecret?.bytes,
      input: input,
      signerPublicKey: signer?.bytes,
      aadResolver: (_) => PqRecipeMessages.folderPackAad(aad: aad),
    );
    final count = await PqFolderPack.unpackFromStream(
      frames,
      outputDirPath: outputDir.path,
    );
    console.success('Unpacked $count file(s)');
    _printSuite(
      profile: peek.profile,
      hybrid: hybrid,
      engine: engineProvider,
      signature: peek.isSigned ? peek.signatureAlgorithm : null,
    );
    console.detail('output', outputDir.path);
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
        signature: header.isSigned ? header.signatureAlgorithm : null,
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
        signature: envelope.isSigned ? envelope.signatureAlgorithm : null,
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
      if (entry.key == PqHybridKemDem.metadataKey) continue; // shown as suite
      console.detail(entry.key, '${entry.value}');
    }
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
