import 'dart:convert';
import 'dart:io';
import 'dart:typed_data';

import 'package:args/args.dart';
import 'package:args/command_runner.dart';
import 'package:pqforge/pqforge.dart';

Future<void> main(List<String> args) async {
  final runner =
      CommandRunner<void>(
          'pqforge',
          'Post-quantum file, folder, text, media, signing, and verification workflows.',
        )
        ..addCommand(_KeygenCommand())
        ..addCommand(_EncryptCommand())
        ..addCommand(_DecryptCommand())
        ..addCommand(_EncryptFolderCommand())
        ..addCommand(_DecryptFolderCommand())
        ..addCommand(_EncryptTextCommand())
        ..addCommand(_DecryptTextCommand())
        ..addCommand(_EncryptMediaCommand())
        ..addCommand(_DecryptMediaCommand())
        ..addCommand(_SignCommand())
        ..addCommand(_VerifyCommand());

  try {
    await runner.run(args);
  } on UsageException catch (error) {
    stderr.writeln(error);
    exitCode = 64;
  } on Object catch (error) {
    stderr.writeln('pqforge: $error');
    exitCode = 70;
  }
}

final class _KeygenCommand extends Command<void> {
  _KeygenCommand() {
    argParser
      ..addOption(
        'profile',
        allowed: ['compact', 'balanced', 'maximum'],
        defaultsTo: 'balanced',
        help: 'Composition profile.',
      )
      ..addOption(
        'key-id',
        defaultsTo: 'pqforge-key',
        help: 'Key identifier embedded in exported key JSON.',
      )
      ..addOption(
        'out-dir',
        abbr: 'o',
        defaultsTo: '.',
        help: 'Directory to receive exported key JSON files.',
      )
      ..addOption(
        'argon-iterations',
        defaultsTo: '2',
        help: 'Argon2id iterations used when wrapping secret keys.',
      )
      ..addOption(
        'argon-memory-power-of-2',
        defaultsTo: '16',
        help: 'Argon2id memory exponent used when wrapping secret keys.',
      )
      ..addOption(
        'argon-lanes',
        defaultsTo: '4',
        help: 'Argon2id lanes used when wrapping secret keys.',
      );
    _addPassphraseOptions(argParser);
  }

  @override
  String get name => 'keygen';

  @override
  String get description =>
      'Generate ML-KEM and ML-DSA key material, optionally wrapping secrets.';

  @override
  Future<void> run() async {
    final profile = PqForgeProfile.byName(argResults!['profile'] as String);
    final keyId = argResults!['key-id'] as String;
    final outDir = Directory(argResults!['out-dir'] as String);
    final passphrase = await _passphraseFrom(argResults!);
    final forge = PqForge(profile: profile);
    await outDir.create(recursive: true);

    final bundle = forge.generateKeys(keyId: keyId);
    final publicFiles = <String, PqExportedKey>{
      '$keyId.kem.public.json': bundle.exportKemPublicKey(),
      '$keyId.sign.public.json': bundle.exportSignaturePublicKey(),
    };
    for (final entry in publicFiles.entries) {
      await _writeJson(outDir.child(entry.key), entry.value.toJson());
    }

    final secretFiles = <String, PqExportedKey>{
      '$keyId.kem.secret.json': bundle.exportKemSecretKey(),
      '$keyId.sign.secret.json': bundle.exportSignatureSecretKey(),
    };
    if (passphrase == null) {
      stderr.writeln(
        'warning: writing raw secret key JSON; pass --passphrase-env, '
        '--passphrase-file, or --passphrase to write wrapped secrets.',
      );
      for (final entry in secretFiles.entries) {
        await _writeJson(outDir.child(entry.key), entry.value.toJson());
      }
    } else {
      final iterations = int.parse(argResults!['argon-iterations'] as String);
      final memoryPowerOf2 = int.parse(
        argResults!['argon-memory-power-of-2'] as String,
      );
      final lanes = int.parse(argResults!['argon-lanes'] as String);
      for (final entry in secretFiles.entries) {
        final wrapped = forge.wrapKeyWithPassphrase(
          entry.value,
          passphrase,
          iterations: iterations,
          memoryPowerOf2: memoryPowerOf2,
          lanes: lanes,
        );
        await _writeJson(
          outDir.child(entry.key.replaceFirst('.json', '.wrapped.json')),
          wrapped.toJson(),
        );
      }
    }

    stdout.writeln('profile: ${profile.name}');
    for (final name in publicFiles.keys) {
      stdout.writeln('wrote: ${outDir.child(name).path}');
    }
    for (final name in secretFiles.keys) {
      final path = passphrase == null
          ? outDir.child(name).path
          : outDir.child(name.replaceFirst('.json', '.wrapped.json')).path;
      stdout.writeln('wrote: $path');
    }
  }
}

final class _EncryptCommand extends Command<void> {
  _EncryptCommand() {
    _addEnvelopeOptions(argParser, includeProfile: true);
    argParser
      ..addOption(
        'recipient-public',
        mandatory: true,
        help: 'Recipient ML-KEM public key JSON from pqforge keygen.',
      )
      ..addOption('in', mandatory: true, help: 'Plaintext input file.')
      ..addOption('out', mandatory: true, help: 'Encrypted .pqf output file.')
      ..addOption(
        'aad',
        help: 'Optional associated data string. Defaults to file:<basename>.',
      );
    _addPassphraseOptions(argParser);
  }

  @override
  String get name => 'encrypt';

  @override
  String get description => 'Encrypt a file to an ML-KEM public key.';

  @override
  Future<void> run() async {
    final passphrase = await _passphraseFrom(argResults!);
    final recipient = await _readKey(argResults!['recipient-public'] as String);
    _requireKind(recipient, PqKeyKind.kemPublic);
    final input = File(argResults!['in'] as String);
    final output = File(argResults!['out'] as String);
    final profile = _profileFrom(argResults!);
    final signer = await _optionalSignerSecret(argResults!, passphrase);

    final plaintext = Uint8List.fromList(await input.readAsBytes());
    final fileName = input.uri.pathSegments.last;
    final aad = PqRecipeMessages.fileAad(
      fileName: fileName,
      aad: _optionalAad(argResults!),
    );
    final envelope = PqForge(profile: profile).encrypt(
      recipient.bytes,
      plaintext,
      aad: aad,
      metadata: {
        'recipe': 'file-encryption',
        'fileName': fileName,
        'contentLength': plaintext.length,
      },
      profile: profile,
      signerSecretKey: signer?.bytes,
      signerKeyId: _signerKeyId(argResults!, signer),
    );
    await _writeEnvelope(output, envelope);
    stdout.writeln('encrypted: ${output.path}');
  }
}

final class _DecryptCommand extends Command<void> {
  _DecryptCommand() {
    argParser
      ..addOption(
        'recipient-secret',
        mandatory: true,
        help: 'Recipient raw or wrapped ML-KEM secret key JSON.',
      )
      ..addOption('in', mandatory: true, help: 'Encrypted .pqf input file.')
      ..addOption('out', mandatory: true, help: 'Plaintext output file.')
      ..addOption(
        'aad',
        help: 'Optional associated data string. Defaults to fileName metadata.',
      )
      ..addOption(
        'signer-public',
        help: 'Optional ML-DSA public key JSON required for signed envelopes.',
      );
    _addPassphraseOptions(argParser);
  }

  @override
  String get name => 'decrypt';

  @override
  String get description => 'Decrypt a .pqf file with an ML-KEM secret key.';

  @override
  Future<void> run() async {
    final passphrase = await _passphraseFrom(argResults!);
    final recipient = await _readKey(
      argResults!['recipient-secret'] as String,
      passphrase: passphrase,
    );
    _requireKind(recipient, PqKeyKind.kemSecret);
    final envelope = await _readEnvelope(File(argResults!['in'] as String));
    final signer = await _optionalPublicKey(
      argResults!['signer-public'] as String?,
      PqKeyKind.signaturePublic,
    );

    final fileName = envelope.metadata['fileName'];
    if (fileName is! String || fileName.isEmpty) {
      throw const PqForgeException(
        'file envelope metadata must include fileName',
      );
    }
    final aad = PqRecipeMessages.fileAad(
      fileName: fileName,
      aad: _optionalAad(argResults!),
    );
    final plaintext = PqForge(profile: envelope.profile).decrypt(
      recipient.bytes,
      envelope,
      aad: aad,
      signerPublicKey: signer?.bytes,
    );
    final output = File(argResults!['out'] as String);
    await output.parent.create(recursive: true);
    await output.writeAsBytes(plaintext);
    stdout.writeln('decrypted: ${output.path}');
  }
}

final class _EncryptFolderCommand extends Command<void> {
  _EncryptFolderCommand() {
    _addEnvelopeOptions(argParser, includeProfile: true);
    argParser
      ..addOption(
        'recipient-public',
        mandatory: true,
        help: 'Recipient ML-KEM public key JSON from pqforge keygen.',
      )
      ..addOption('in-dir', mandatory: true, help: 'Plaintext folder.')
      ..addOption(
        'out-dir',
        mandatory: true,
        help: 'Folder that receives encrypted .pqf files.',
      )
      ..addOption(
        'aad',
        help: 'Optional global associated data bound to every folder entry.',
      );
    _addPassphraseOptions(argParser);
  }

  @override
  String get name => 'encrypt-folder';

  @override
  String get description =>
      'Encrypt every regular file in a folder, preserving relative paths.';

  @override
  Future<void> run() async {
    final passphrase = await _passphraseFrom(argResults!);
    final recipient = await _readKey(argResults!['recipient-public'] as String);
    _requireKind(recipient, PqKeyKind.kemPublic);
    final inputDir = Directory(argResults!['in-dir'] as String);
    final outputDir = Directory(argResults!['out-dir'] as String);
    final profile = _profileFrom(argResults!);
    final signer = await _optionalSignerSecret(argResults!, passphrase);
    final aad = _optionalAad(argResults!);
    final forge = PqForge(profile: profile);
    var count = 0;

    final files = await _listFiles(inputDir);
    for (final file in files) {
      final relativePath = _safeRelativePath(inputDir, file);
      final plaintext = Uint8List.fromList(await file.readAsBytes());
      final envelope = forge.encryptFolderEntry(
        recipient.bytes,
        plaintext,
        relativePath: relativePath,
        aad: aad,
        profile: profile,
        signerSecretKey: signer?.bytes,
        signerKeyId: _signerKeyId(argResults!, signer),
      );
      await _writeEnvelope(
        File(_joinPath(outputDir.path, '$relativePath.pqf')),
        envelope,
      );
      count += 1;
    }
    stdout.writeln('encrypted files: $count');
  }
}

final class _DecryptFolderCommand extends Command<void> {
  _DecryptFolderCommand() {
    argParser
      ..addOption(
        'recipient-secret',
        mandatory: true,
        help: 'Recipient raw or wrapped ML-KEM secret key JSON.',
      )
      ..addOption('in-dir', mandatory: true, help: 'Folder of .pqf files.')
      ..addOption(
        'out-dir',
        mandatory: true,
        help: 'Folder that receives plaintext files.',
      )
      ..addOption(
        'aad',
        help: 'Optional global associated data bound to every folder entry.',
      )
      ..addOption(
        'signer-public',
        help: 'Optional ML-DSA public key JSON required for signed envelopes.',
      );
    _addPassphraseOptions(argParser);
  }

  @override
  String get name => 'decrypt-folder';

  @override
  String get description =>
      'Decrypt a folder produced by encrypt-folder, preserving relative paths.';

  @override
  Future<void> run() async {
    final passphrase = await _passphraseFrom(argResults!);
    final recipient = await _readKey(
      argResults!['recipient-secret'] as String,
      passphrase: passphrase,
    );
    _requireKind(recipient, PqKeyKind.kemSecret);
    final inputDir = Directory(argResults!['in-dir'] as String);
    final outputDir = Directory(argResults!['out-dir'] as String);
    final signer = await _optionalPublicKey(
      argResults!['signer-public'] as String?,
      PqKeyKind.signaturePublic,
    );
    final aad = _optionalAad(argResults!);
    var count = 0;

    final files = (await _listFiles(
      inputDir,
    )).where((file) => file.path.endsWith('.pqf'));
    for (final file in files) {
      final envelope = await _readEnvelope(file);
      final relativePath = envelope.metadata['relativePath'];
      if (relativePath is! String) {
        throw PqForgeException('${file.path} has no relativePath metadata');
      }
      _requireSafeRelativePath(relativePath);
      final plaintext = PqForge(profile: envelope.profile).decryptFolderEntry(
        recipient.bytes,
        envelope,
        aad: aad,
        signerPublicKey: signer?.bytes,
      );
      final output = File(_joinPath(outputDir.path, relativePath));
      await output.parent.create(recursive: true);
      await output.writeAsBytes(plaintext);
      count += 1;
    }
    stdout.writeln('decrypted files: $count');
  }
}

final class _EncryptTextCommand extends Command<void> {
  _EncryptTextCommand() {
    _addEnvelopeOptions(argParser, includeProfile: true);
    argParser
      ..addOption(
        'recipient-public',
        mandatory: true,
        help: 'Recipient ML-KEM public key JSON from pqforge keygen.',
      )
      ..addOption('text', help: 'Plaintext string to encrypt.')
      ..addOption('in', help: 'UTF-8 plaintext input file.')
      ..addOption('out', mandatory: true, help: 'Encrypted .pqf output file.')
      ..addOption(
        'text-id',
        help: 'Stable text id. Defaults to input basename or inline-text.',
      )
      ..addOption('aad', help: 'Optional associated data string.');
    _addPassphraseOptions(argParser);
  }

  @override
  String get name => 'encrypt-text';

  @override
  String get description => 'Encrypt UTF-8 text and bind a text id into AAD.';

  @override
  Future<void> run() async {
    final passphrase = await _passphraseFrom(argResults!);
    final recipient = await _readKey(argResults!['recipient-public'] as String);
    _requireKind(recipient, PqKeyKind.kemPublic);
    final (text, defaultTextId) = await _readTextInput(argResults!);
    final textId = argResults!['text-id'] as String? ?? defaultTextId;
    final profile = _profileFrom(argResults!);
    final signer = await _optionalSignerSecret(argResults!, passphrase);
    final envelope = PqForge(profile: profile).sealText(
      recipient.bytes,
      text,
      textId: textId,
      aad: _optionalAad(argResults!),
      profile: profile,
      signerSecretKey: signer?.bytes,
      signerKeyId: _signerKeyId(argResults!, signer),
    );
    await _writeEnvelope(File(argResults!['out'] as String), envelope);
    stdout.writeln('encrypted text: ${argResults!['out']}');
  }
}

final class _DecryptTextCommand extends Command<void> {
  _DecryptTextCommand() {
    argParser
      ..addOption(
        'recipient-secret',
        mandatory: true,
        help: 'Recipient raw or wrapped ML-KEM secret key JSON.',
      )
      ..addOption('in', mandatory: true, help: 'Encrypted .pqf input file.')
      ..addOption(
        'out',
        help: 'UTF-8 plaintext output file. Defaults to stdout.',
      )
      ..addOption('aad', help: 'Optional associated data string.')
      ..addOption(
        'signer-public',
        help: 'Optional ML-DSA public key JSON required for signed envelopes.',
      );
    _addPassphraseOptions(argParser);
  }

  @override
  String get name => 'decrypt-text';

  @override
  String get description => 'Decrypt an encrypted UTF-8 text envelope.';

  @override
  Future<void> run() async {
    final passphrase = await _passphraseFrom(argResults!);
    final recipient = await _readKey(
      argResults!['recipient-secret'] as String,
      passphrase: passphrase,
    );
    _requireKind(recipient, PqKeyKind.kemSecret);
    final envelope = await _readEnvelope(File(argResults!['in'] as String));
    final signer = await _optionalPublicKey(
      argResults!['signer-public'] as String?,
      PqKeyKind.signaturePublic,
    );
    final text = PqForge(profile: envelope.profile).openText(
      recipient.bytes,
      envelope,
      aad: _optionalAad(argResults!),
      signerPublicKey: signer?.bytes,
    );
    final output = argResults!['out'] as String?;
    if (output == null) {
      stdout.writeln(text);
    } else {
      await File(output).writeAsString(text);
      stdout.writeln('decrypted text: $output');
    }
  }
}

final class _EncryptMediaCommand extends Command<void> {
  _EncryptMediaCommand() {
    _addEnvelopeOptions(argParser, includeProfile: true);
    argParser
      ..addOption(
        'recipient-public',
        mandatory: true,
        help: 'Recipient ML-KEM public key JSON from pqforge keygen.',
      )
      ..addOption('in', mandatory: true, help: 'Media input file.')
      ..addOption('out', mandatory: true, help: 'Encrypted .pqf output file.')
      ..addOption(
        'media-id',
        help: 'Stable media id. Defaults to input basename.',
      )
      ..addOption(
        'mime-type',
        help:
            'Media MIME type. Defaults from extension or application/octet-stream.',
      )
      ..addOption('aad', help: 'Optional associated data string.');
    _addPassphraseOptions(argParser);
  }

  @override
  String get name => 'encrypt-media';

  @override
  String get description =>
      'Encrypt media bytes with media id and MIME binding.';

  @override
  Future<void> run() async {
    final passphrase = await _passphraseFrom(argResults!);
    final recipient = await _readKey(argResults!['recipient-public'] as String);
    _requireKind(recipient, PqKeyKind.kemPublic);
    final input = File(argResults!['in'] as String);
    final mediaId =
        argResults!['media-id'] as String? ?? input.uri.pathSegments.last;
    final mimeType =
        argResults!['mime-type'] as String? ?? _guessMimeType(input.path);
    final profile = _profileFrom(argResults!);
    final signer = await _optionalSignerSecret(argResults!, passphrase);
    final bytes = Uint8List.fromList(await input.readAsBytes());
    final envelope = PqForge(profile: profile).sealMedia(
      recipient.bytes,
      bytes,
      mediaId: mediaId,
      mimeType: mimeType,
      aad: _optionalAad(argResults!),
      profile: profile,
      signerSecretKey: signer?.bytes,
      signerKeyId: _signerKeyId(argResults!, signer),
    );
    await _writeEnvelope(File(argResults!['out'] as String), envelope);
    stdout.writeln('encrypted media: ${argResults!['out']}');
  }
}

final class _DecryptMediaCommand extends Command<void> {
  _DecryptMediaCommand() {
    argParser
      ..addOption(
        'recipient-secret',
        mandatory: true,
        help: 'Recipient raw or wrapped ML-KEM secret key JSON.',
      )
      ..addOption('in', mandatory: true, help: 'Encrypted .pqf input file.')
      ..addOption('out', mandatory: true, help: 'Plain media output file.')
      ..addOption('aad', help: 'Optional associated data string.')
      ..addOption(
        'signer-public',
        help: 'Optional ML-DSA public key JSON required for signed envelopes.',
      );
    _addPassphraseOptions(argParser);
  }

  @override
  String get name => 'decrypt-media';

  @override
  String get description => 'Decrypt an encrypted media envelope.';

  @override
  Future<void> run() async {
    final passphrase = await _passphraseFrom(argResults!);
    final recipient = await _readKey(
      argResults!['recipient-secret'] as String,
      passphrase: passphrase,
    );
    _requireKind(recipient, PqKeyKind.kemSecret);
    final envelope = await _readEnvelope(File(argResults!['in'] as String));
    final signer = await _optionalPublicKey(
      argResults!['signer-public'] as String?,
      PqKeyKind.signaturePublic,
    );
    final media = PqForge(profile: envelope.profile).openMedia(
      recipient.bytes,
      envelope,
      aad: _optionalAad(argResults!),
      signerPublicKey: signer?.bytes,
    );
    final output = File(argResults!['out'] as String);
    await output.parent.create(recursive: true);
    await output.writeAsBytes(media);
    stdout.writeln('decrypted media: ${output.path}');
  }
}

final class _SignCommand extends Command<void> {
  _SignCommand() {
    argParser
      ..addOption(
        'signer-secret',
        mandatory: true,
        help: 'Raw or wrapped ML-DSA secret key JSON from pqforge keygen.',
      )
      ..addOption('in', mandatory: true, help: 'Input file to sign.')
      ..addOption('out', mandatory: true, help: 'Signature JSON output file.')
      ..addOption(
        'kind',
        allowed: ['document', 'text', 'media', 'artifact'],
        defaultsTo: 'document',
        help: 'Recipe-specific signature kind.',
      )
      ..addOption(
        'document-id',
        help: 'Stable document id. Defaults to input basename.',
      )
      ..addOption(
        'text-id',
        help: 'Stable text id. Defaults to input basename.',
      )
      ..addOption(
        'media-id',
        help: 'Stable media id. Defaults to input basename.',
      )
      ..addOption(
        'mime-type',
        help:
            'Media MIME type. Defaults from extension or application/octet-stream.',
      )
      ..addOption(
        'artifact-id',
        help: 'Stable artifact id. Defaults to input basename.',
      )
      ..addOption(
        'version',
        defaultsTo: '1',
        help: 'Artifact version for kind=artifact.',
      );
    _addPassphraseOptions(argParser);
  }

  @override
  String get name => 'sign';

  @override
  String get description => 'Create detached ML-DSA recipe signatures.';

  @override
  Future<void> run() async {
    final passphrase = await _passphraseFrom(argResults!);
    final signer = await _readKey(
      argResults!['signer-secret'] as String,
      passphrase: passphrase,
    );
    _requireKind(signer, PqKeyKind.signatureSecret);
    final input = File(argResults!['in'] as String);
    final bytes = Uint8List.fromList(await input.readAsBytes());
    final algorithm = PqSignatureAlgorithm.byId(signer.algorithmId);
    final forge = PqForge(profile: _profileForSignature(algorithm));
    final kind = argResults!['kind'] as String;
    final fileName = input.uri.pathSegments.last;

    late final Map<String, Object?> json;
    switch (kind) {
      case 'text':
        final textId = argResults!['text-id'] as String? ?? fileName;
        final signature = forge.signText(
          signerSecretKey: signer.bytes,
          text: utf8.decode(bytes),
          textId: textId,
          algorithm: algorithm,
        );
        json = _signatureJson(
          kind: kind,
          algorithm: algorithm,
          signature: signature,
          extra: {'textId': textId, 'encoding': 'utf-8'},
        );
      case 'media':
        final mediaId = argResults!['media-id'] as String? ?? fileName;
        final mimeType =
            argResults!['mime-type'] as String? ?? _guessMimeType(input.path);
        final signature = forge.signMedia(
          signerSecretKey: signer.bytes,
          mediaId: mediaId,
          mimeType: mimeType,
          mediaBytes: bytes,
          algorithm: algorithm,
        );
        json = _signatureJson(
          kind: kind,
          algorithm: algorithm,
          signature: signature,
          extra: {'mediaId': mediaId, 'mimeType': mimeType},
        );
      case 'artifact':
        final artifactId = argResults!['artifact-id'] as String? ?? fileName;
        final version = int.parse(argResults!['version'] as String);
        final artifact = forge.signArtifact(
          signerSecretKey: signer.bytes,
          artifactId: artifactId,
          version: version,
          artifactBytes: bytes,
          algorithm: algorithm,
        );
        json = _signatureJson(
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
        final documentId = argResults!['document-id'] as String? ?? fileName;
        final signature = forge.signDocument(
          signer.bytes,
          bytes,
          documentId: documentId,
          algorithm: algorithm,
        );
        json = _signatureJson(
          kind: 'document',
          algorithm: algorithm,
          signature: signature,
          extra: {'documentId': documentId},
        );
    }
    await _writeJson(File(argResults!['out'] as String), json);
    stdout.writeln('signed: ${argResults!['out']}');
  }
}

final class _VerifyCommand extends Command<void> {
  _VerifyCommand() {
    argParser
      ..addOption(
        'signer-public',
        mandatory: true,
        help: 'ML-DSA public key JSON from pqforge keygen.',
      )
      ..addOption('in', mandatory: true, help: 'Signed input file.')
      ..addOption('signature', mandatory: true, help: 'Signature JSON file.')
      ..addOption(
        'document-id',
        help: 'Override the signature JSON document id.',
      )
      ..addOption('text-id', help: 'Override the signature JSON text id.')
      ..addOption('media-id', help: 'Override the signature JSON media id.')
      ..addOption('mime-type', help: 'Override the signature JSON MIME type.')
      ..addOption(
        'artifact-id',
        help: 'Override the signature JSON artifact id.',
      )
      ..addOption(
        'version',
        help: 'Override the signature JSON artifact version.',
      );
  }

  @override
  String get name => 'verify';

  @override
  String get description => 'Verify detached ML-DSA recipe signatures.';

  @override
  Future<void> run() async {
    final signer = await _readKey(argResults!['signer-public'] as String);
    _requireKind(signer, PqKeyKind.signaturePublic);
    final input = File(argResults!['in'] as String);
    final bytes = Uint8List.fromList(await input.readAsBytes());
    final sigJson = await _readJsonMap(
      File(argResults!['signature'] as String),
    );
    final algorithm = PqSignatureAlgorithm.byId(
      sigJson['signatureAlgorithm'] as String,
    );
    final signature = base64Decode(sigJson['signature'] as String);
    final kind = sigJson['kind'] as String? ?? 'document';
    final forge = PqForge(profile: _profileForSignature(algorithm));

    final ok = switch (kind) {
      'text' => forge.verifyText(
        signerPublicKey: signer.bytes,
        text: utf8.decode(bytes),
        textId:
            argResults!['text-id'] as String? ?? sigJson['textId'] as String,
        signature: signature,
        algorithm: algorithm,
      ),
      'media' => forge.verifyMedia(
        signerPublicKey: signer.bytes,
        mediaId:
            argResults!['media-id'] as String? ?? sigJson['mediaId'] as String,
        mimeType:
            argResults!['mime-type'] as String? ??
            sigJson['mimeType'] as String,
        mediaBytes: bytes,
        signature: signature,
        algorithm: algorithm,
      ),
      'artifact' => forge.verifyArtifact(
        signer.bytes,
        bytes,
        PqArtifactSignature(
          artifactId:
              argResults!['artifact-id'] as String? ??
              sigJson['artifactId'] as String,
          version:
              int.tryParse(argResults!['version'] as String? ?? '') ??
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
            argResults!['document-id'] as String? ??
            sigJson['documentId'] as String,
        algorithm: algorithm,
      ),
    };
    stdout.writeln(ok ? 'verified: true' : 'verified: false');
    if (!ok) exitCode = 1;
  }
}

void _addEnvelopeOptions(ArgParser parser, {required bool includeProfile}) {
  if (includeProfile) {
    parser.addOption(
      'profile',
      allowed: ['compact', 'balanced', 'maximum'],
      defaultsTo: 'maximum',
      help: 'Envelope profile.',
    );
  }
  parser
    ..addOption(
      'signer-secret',
      help: 'Optional raw or wrapped ML-DSA secret key JSON to sign envelopes.',
    )
    ..addOption('signer-key-id', help: 'Optional signer key id metadata.');
}

void _addPassphraseOptions(ArgParser parser) {
  parser
    ..addOption(
      'passphrase-env',
      help: 'Environment variable containing the wrapping passphrase.',
    )
    ..addOption(
      'passphrase-file',
      help: 'File containing the wrapping passphrase.',
    )
    ..addOption(
      'passphrase',
      help: 'Wrapping passphrase. Prefer --passphrase-env for scripts.',
    );
}

Future<PqExportedKey> _readKey(String path, {String? passphrase}) async {
  final json = await _readJsonMap(File(path));
  if (json.containsKey('ciphertext') && json.containsKey('kdf')) {
    if (passphrase == null) {
      throw PqForgeException(
        'Passphrase required to unwrap $path; use --passphrase-env, '
        '--passphrase-file, or --passphrase.',
      );
    }
    return const PqForge().unwrapKeyWithPassphrase(
      PqWrappedKey.fromJson(json),
      passphrase,
    );
  }
  return PqExportedKey.fromJson(json);
}

Future<PqExportedKey?> _optionalSignerSecret(
  ArgResults results,
  String? passphrase,
) async {
  final signerPath = results['signer-secret'] as String?;
  if (signerPath == null) return null;
  final signer = await _readKey(signerPath, passphrase: passphrase);
  _requireKind(signer, PqKeyKind.signatureSecret);
  return signer;
}

Future<PqExportedKey?> _optionalPublicKey(String? path, String kind) async {
  if (path == null) return null;
  final key = await _readKey(path);
  _requireKind(key, kind);
  return key;
}

String? _signerKeyId(ArgResults results, PqExportedKey? signer) {
  return results['signer-key-id'] as String? ?? signer?.keyId;
}

Future<String?> _passphraseFrom(ArgResults results) async {
  final direct = results['passphrase'] as String?;
  final envName = results['passphrase-env'] as String?;
  final filePath = results['passphrase-file'] as String?;
  final count = [direct, envName, filePath].whereType<String>().length;
  if (count > 1) {
    throw const PqForgeException(
      'Use only one of --passphrase, --passphrase-env, or --passphrase-file',
    );
  }
  if (direct != null) return direct;
  if (envName != null) {
    final value = Platform.environment[envName];
    if (value == null || value.isEmpty) {
      throw PqForgeException('Environment variable $envName is empty or unset');
    }
    return value;
  }
  if (filePath != null) {
    final value = await File(filePath).readAsString();
    return value.replaceFirst(RegExp(r'\r?\n$'), '');
  }
  return null;
}

Future<Map<String, Object?>> _readJsonMap(File file) async {
  return Map<String, Object?>.from(
    jsonDecode(await file.readAsString()) as Map,
  );
}

Future<void> _writeJson(File file, Map<String, Object?> json) async {
  await file.parent.create(recursive: true);
  await file.writeAsString(
    '${const JsonEncoder.withIndent('  ').convert(json)}\n',
  );
}

Future<PqEnvelope> _readEnvelope(File file) async {
  return PqEnvelope.fromBinary(Uint8List.fromList(await file.readAsBytes()));
}

Future<void> _writeEnvelope(File file, PqEnvelope envelope) async {
  await file.parent.create(recursive: true);
  await file.writeAsBytes(envelope.toBinary());
}

void _requireKind(PqExportedKey key, String kind) {
  if (key.kind != kind) {
    throw PqForgeException('Expected $kind key, got ${key.kind}');
  }
}

PqForgeProfile _profileFrom(ArgResults results) {
  return PqForgeProfile.byName(results['profile'] as String);
}

Uint8List? _optionalAad(ArgResults results) {
  final aad = results['aad'] as String?;
  return aad == null ? null : PqBytes.utf8Bytes(aad);
}

Future<List<File>> _listFiles(Directory directory) async {
  final files = <File>[];
  await for (final entity in directory.list(
    recursive: true,
    followLinks: false,
  )) {
    if (entity is File) files.add(entity);
  }
  files.sort((a, b) => a.path.compareTo(b.path));
  return files;
}

String _safeRelativePath(Directory root, File file) {
  final rootPath = _directoryPrefix(root.absolute.path);
  final filePath = file.absolute.path;
  if (!filePath.startsWith(rootPath)) {
    throw PqForgeException('${file.path} is not inside ${root.path}');
  }
  final relative = filePath
      .substring(rootPath.length)
      .split(Platform.pathSeparator)
      .join('/');
  _requireSafeRelativePath(relative);
  return relative;
}

String _directoryPrefix(String path) {
  return path.endsWith(Platform.pathSeparator)
      ? path
      : '$path${Platform.pathSeparator}';
}

void _requireSafeRelativePath(String relativePath) {
  final segments = relativePath.split('/');
  if (relativePath.isEmpty ||
      relativePath.startsWith('/') ||
      relativePath.contains(r'\') ||
      segments.any(
        (segment) => segment.isEmpty || segment == '.' || segment == '..',
      )) {
    throw PqForgeException('Unsafe relative path: $relativePath');
  }
}

String _joinPath(String root, String relativePath) {
  return '${root.endsWith('/') ? root.substring(0, root.length - 1) : root}/$relativePath';
}

Future<(String, String)> _readTextInput(ArgResults results) async {
  final text = results['text'] as String?;
  final input = results['in'] as String?;
  if (text == null && input == null) {
    throw const PqForgeException('Provide --text or --in');
  }
  if (text != null && input != null) {
    throw const PqForgeException('Use only one of --text or --in');
  }
  if (text != null) return (text, 'inline-text');
  final file = File(input!);
  return (await file.readAsString(), file.uri.pathSegments.last);
}

Map<String, Object?> _signatureJson({
  required String kind,
  required PqSignatureAlgorithm algorithm,
  required Uint8List signature,
  required Map<String, Object?> extra,
}) {
  return {
    'version': 1,
    'kind': kind,
    ...extra,
    'signatureAlgorithm': algorithm.id,
    'signature': base64Encode(signature),
  };
}

String _guessMimeType(String path) {
  final lower = path.toLowerCase();
  if (lower.endsWith('.jpg') || lower.endsWith('.jpeg')) return 'image/jpeg';
  if (lower.endsWith('.png')) return 'image/png';
  if (lower.endsWith('.gif')) return 'image/gif';
  if (lower.endsWith('.webp')) return 'image/webp';
  if (lower.endsWith('.mp4')) return 'video/mp4';
  if (lower.endsWith('.mov')) return 'video/quicktime';
  if (lower.endsWith('.mp3')) return 'audio/mpeg';
  if (lower.endsWith('.wav')) return 'audio/wav';
  if (lower.endsWith('.pdf')) return 'application/pdf';
  if (lower.endsWith('.txt')) return 'text/plain';
  return 'application/octet-stream';
}

PqForgeProfile _profileForSignature(PqSignatureAlgorithm algorithm) {
  return switch (algorithm) {
    PqSignatureAlgorithm.mlDsa44 => PqForgeProfile.compact,
    PqSignatureAlgorithm.mlDsa65 => PqForgeProfile.balanced,
    PqSignatureAlgorithm.mlDsa87 => PqForgeProfile.maximum,
  };
}

extension on Directory {
  File child(String name) =>
      File('${path.endsWith('/') ? path : '$path/'}$name');
}
