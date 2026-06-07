import 'dart:convert';
import 'dart:io';

import 'package:pqforge/pqforge.dart';

Future<void> main(List<String> args) async {
  if (args.isEmpty || args.length > 3) {
    stderr.writeln(
      'Usage: dart run example/file_encryption_example.dart '
      '<input-file> [output.pqf] [wrapped-key.json]',
    );
    exitCode = 64;
    return;
  }

  final input = File(args[0]);
  if (!input.existsSync()) {
    stderr.writeln('Input file not found: ${input.path}');
    exitCode = 66;
    return;
  }

  final output = File(args.length >= 2 ? args[1] : '${input.path}.pqf');
  final keyStoreFile = File(
    args.length == 3 ? args[2] : '${output.path}.wrapped-key.json',
  );
  final passphrase =
      Platform.environment['PQFORGE_DEMO_PASSPHRASE'] ??
      'change-me-demo-passphrase';
  final forge = PqForge();
  final recipient = forge.generateKeys(
    profile: PqForgeProfile.maximum,
    keyId: 'file-demo-recipient',
  );
  final custody = PqPassphraseKeyCustody(
    forge: forge,
    store: JsonFileKeyCustodyStore(keyStoreFile),
  );
  final aad = PqBytes.utf8Bytes('file:${input.uri.pathSegments.last}');
  final plaintext = input.readAsBytesSync();

  await custody.wrapAndPut(
    recipient.exportKemSecretKey(),
    passphrase,
    storageId: recipient.keyId,
  );

  final envelope = forge.encryptFileBytes(
    recipient.kemKeyPair.publicKey,
    plaintext,
    aad: aad,
    metadata: {
      'fileName': input.uri.pathSegments.last,
      'contentLength': plaintext.length,
    },
  );
  output.writeAsBytesSync(envelope.toBinary());

  final decoded = PqEnvelope.fromBinary(output.readAsBytesSync());
  final restoredSecret = await custody.getAndUnwrap(
    recipient.keyId!,
    passphrase,
  );
  final opened = forge.decryptFileBytes(
    restoredSecret.bytes,
    decoded,
    aad: aad,
  );
  final verified = PqBytes.constantTimeEquals(plaintext, opened);

  stdout.writeln('input: ${input.path}');
  stdout.writeln('encrypted: ${output.path}');
  stdout.writeln('wrapped key: ${keyStoreFile.path}');
  stdout.writeln('profile: ${envelope.profile.name}');
  stdout.writeln('input bytes: ${plaintext.length}');
  stdout.writeln('encrypted bytes: ${output.lengthSync()}');
  stdout.writeln('round-trip verified: $verified');
  stdout.writeln(
    'set PQFORGE_DEMO_PASSPHRASE to control the demo key-wrapping passphrase.',
  );
}

final class JsonFileKeyCustodyStore implements PqKeyCustodyStore {
  const JsonFileKeyCustodyStore(this.file);

  final File file;

  @override
  Future<void> put(String storageId, Map<String, Object?> document) async {
    final all = await _readAll();
    all[storageId] = document;
    await file.parent.create(recursive: true);
    await file.writeAsString(const JsonEncoder.withIndent('  ').convert(all));
  }

  @override
  Future<Map<String, Object?>?> get(String storageId) async {
    final all = await _readAll();
    final document = all[storageId];
    return document == null ? null : Map<String, Object?>.from(document as Map);
  }

  @override
  Future<void> delete(String storageId) async {
    final all = await _readAll();
    all.remove(storageId);
    await file.parent.create(recursive: true);
    await file.writeAsString(const JsonEncoder.withIndent('  ').convert(all));
  }

  Future<Map<String, Object?>> _readAll() async {
    if (!await file.exists()) return <String, Object?>{};
    final raw = await file.readAsString();
    if (raw.trim().isEmpty) return <String, Object?>{};
    return Map<String, Object?>.from(jsonDecode(raw) as Map);
  }
}
