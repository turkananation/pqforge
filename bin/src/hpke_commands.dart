/// `hpke` — X-Wing HPKE. Does not read or write `.pqf` or `.pqfs`.
library;

import 'dart:io';

import 'package:args/command_runner.dart';
import 'package:pqforge/pqforge.dart';
import 'package:zeroize/zeroize.dart';

import 'support.dart';

const _xwingPublicKind = 'xwing-public';
const _xwingSecretKind = 'xwing-secret';
const _xwingAlgorithm = 'xwing';

/// Parent for `keygen`, `seal`, and `open`.
final class HpkeCommand extends Command<void> {
  HpkeCommand() {
    addSubcommand(HpkeKeygenCommand());
    addSubcommand(HpkeSealCommand());
    addSubcommand(HpkeOpenCommand());
  }

  @override
  String get name => 'hpke';

  @override
  String get description =>
      'X-Wing HPKE keygen, seal, and open. Not a .pqf or .pqfs command. '
      'PQXDH, the Double Ratchet, and the Sparse Post-Quantum Ratchet '
      'are not flags on this command.';
}

final class HpkeKeygenCommand extends Command<void> {
  HpkeKeygenCommand() {
    argParser
      ..addOption(
        'kem',
        allowed: const ['xwing'],
        defaultsTo: 'xwing',
        help: 'KEM. Only xwing is accepted.',
      )
      ..addOption('key-id', defaultsTo: 'xwing', valueHelp: 'id')
      ..addOption('out-dir', abbr: 'o', defaultsTo: '.', valueHelp: 'dir');
  }

  @override
  String get name => 'keygen';

  @override
  String get description =>
      'Write a 32-byte X-Wing seed and a 1216-byte public key as JSON.';

  @override
  Future<void> run() async {
    PqFipsMode.requireXWingAllowed();
    final results = argResults!;
    final keyId = results['key-id'] as String;
    final outDir = Directory(results['out-dir'] as String);
    await outDir.create(recursive: true);
    final pair = await PqXWing.generateKeyPair();
    try {
      await writeJson(
        File('${outDir.path}/$keyId.xwing.public.json'),
        PqExportedKey(
          kind: _xwingPublicKind,
          algorithmId: _xwingAlgorithm,
          keyId: keyId,
          bytes: pair.publicKey,
        ).toJson(),
      );
      await writeJson(
        File('${outDir.path}/$keyId.xwing.secret.json'),
        PqExportedKey(
          kind: _xwingSecretKind,
          algorithmId: _xwingAlgorithm,
          keyId: keyId,
          bytes: pair.secretKey,
        ).toJson(),
      );
    } finally {
      secureZero(pair.secretKey);
    }
  }
}

final class HpkeSealCommand extends Command<void> {
  HpkeSealCommand() {
    argParser
      ..addOption(
        'kem',
        allowed: const ['xwing'],
        defaultsTo: 'xwing',
        help: 'KEM. Only xwing is accepted.',
      )
      ..addOption(
        'recipient-public',
        mandatory: true,
        valueHelp: 'file',
        help: 'X-Wing public key JSON from hpke keygen.',
      )
      ..addOption('in', abbr: 'i', mandatory: true, valueHelp: 'file')
      ..addOption('out', abbr: 'o', mandatory: true, valueHelp: 'file')
      ..addOption(
        'cipher',
        allowed: const ['aes-128-gcm', 'aes-256-gcm', 'chacha20-poly1305'],
        defaultsTo: 'aes-256-gcm',
        help: 'HPKE AEAD. The KEM is still X-Wing.',
      );
  }

  @override
  String get name => 'seal';

  @override
  String get description =>
      'Encapsulate with X-Wing and seal the plaintext. The output magic '
      'is XW01, not PQF1.';

  @override
  Future<void> run() async {
    PqFipsMode.requireXWingAllowed();
    final results = argResults!;
    final public = await readKey(results['recipient-public'] as String);
    if (public.kind != _xwingPublicKind ||
        public.algorithmId != _xwingAlgorithm) {
      throw const PqForgeException(
        'hpke seal requires an xwing-public key, not an ML-KEM or hybrid key',
      );
    }
    final plaintext = await File(results['in'] as String).readAsBytes();
    final suite = HpkeSuite(
      kem: HpkeKem.xWing,
      aead: _aead(results['cipher'] as String),
    );
    final sealed = await PqHpke.seal(
      suite: suite,
      mode: HpkeMode.base,
      recipientPublicKey: public.bytes,
      plaintext: plaintext,
    );
    final message = PqXWingMessage.encode(
      suite: suite,
      enc: sealed.enc,
      ciphertext: sealed.ciphertext,
    );
    sealed.context.dispose();
    await File(results['out'] as String).writeAsBytes(message);
  }
}

final class HpkeOpenCommand extends Command<void> {
  HpkeOpenCommand() {
    argParser
      ..addOption(
        'kem',
        allowed: const ['xwing'],
        defaultsTo: 'xwing',
        help: 'KEM. Only xwing is accepted.',
      )
      ..addOption(
        'recipient-secret',
        mandatory: true,
        valueHelp: 'file',
        help: 'X-Wing seed JSON from hpke keygen.',
      )
      ..addOption('in', abbr: 'i', mandatory: true, valueHelp: 'file')
      ..addOption('out', abbr: 'o', mandatory: true, valueHelp: 'file');
  }

  @override
  String get name => 'open';

  @override
  String get description => 'Open an XW01 message. Refuses a PQF1 envelope.';

  @override
  Future<void> run() async {
    PqFipsMode.requireXWingAllowed();
    final results = argResults!;
    final secret = await readKey(results['recipient-secret'] as String);
    if (secret.kind != _xwingSecretKind ||
        secret.algorithmId != _xwingAlgorithm) {
      throw const PqForgeException(
        'hpke open requires an xwing-secret key, not an ML-KEM or hybrid key',
      );
    }
    final bytes = await File(results['in'] as String).readAsBytes();
    final message = PqXWingMessage.decode(bytes);
    final pair = await PqXWing.generateKeyPairDerand(secret.bytes);
    try {
      final opened = await PqHpke.open(
        suite: message.suite,
        mode: HpkeMode.base,
        enc: message.enc,
        ciphertext: message.ciphertext,
        recipientKey: HpkeKeyPair(
          kem: HpkeKem.xWing,
          secretKey: pair.secretKey,
          publicKey: pair.publicKey,
        ),
      );
      opened.context.dispose();
      await File(results['out'] as String).writeAsBytes(opened.plaintext);
    } finally {
      secureZero(pair.secretKey);
    }
  }
}

HpkeAead _aead(String name) => switch (name) {
  'aes-128-gcm' => HpkeAead.aes128Gcm,
  'aes-256-gcm' => HpkeAead.aes256Gcm,
  'chacha20-poly1305' => HpkeAead.chacha20Poly1305,
  _ => throw PqForgeException('Unsupported HPKE cipher: $name'),
};
