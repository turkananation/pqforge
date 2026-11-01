import 'dart:convert';
import 'dart:io';
import 'dart:typed_data';

import 'package:pqforge/pqforge.dart';
import 'package:test/test.dart';

void main() {
  final vectors = jsonDecode(File('test/hpke_rfc9180.json').readAsStringSync());

  test('RFC 9180 known answers for X25519 and P-256', () async {
    expect(vectors, isA<List<dynamic>>());
    for (final raw in vectors as List<dynamic>) {
      final vector = raw as Map<String, dynamic>;
      await _expectVector(vector);
    }
  });

  test('P-384 round trips in every mode and AEAD', () async {
    const suite = HpkeSuite(
      kem: HpkeKem.p384HkdfSha384,
      kdf: HpkeKdf.hkdfSha384,
      aead: HpkeAead.aes256Gcm,
    );
    final recipient = await PqHpke.generateKeyPair(HpkeKem.p384HkdfSha384);
    final sender = await PqHpke.generateKeyPair(HpkeKem.p384HkdfSha384);
    final psk = Uint8List.fromList(List<int>.generate(32, (i) => i + 1));
    final pskId = Uint8List.fromList(utf8.encode('p384-psk'));
    final info = Uint8List.fromList(utf8.encode('p384-info'));
    final aad = Uint8List.fromList(utf8.encode('p384-aad'));
    final plaintext = Uint8List.fromList(utf8.encode('p384 record'));
    for (final aead in HpkeAead.values) {
      for (final mode in HpkeMode.values) {
        final chosen = HpkeSuite(kem: suite.kem, kdf: suite.kdf, aead: aead);
        if (!aead.canSeal) {
          final setup = await PqHpke.setupSender(
            suite: chosen,
            mode: mode,
            recipientPublicKey: recipient.publicKey,
            info: info,
            psk: mode.usesPsk ? psk : null,
            pskId: mode.usesPsk ? pskId : null,
            senderKey: mode.usesAuth ? sender : null,
          );
          expect(
            () => setup.context.seal(plaintext),
            throwsA(isA<PqForgeException>()),
          );
          final opened = await PqHpke.setupRecipient(
            suite: chosen,
            mode: mode,
            enc: setup.enc,
            recipientKey: recipient,
            info: info,
            psk: mode.usesPsk ? psk : null,
            pskId: mode.usesPsk ? pskId : null,
            senderPublicKey: mode.usesAuth ? sender.publicKey : null,
          );
          final context = Uint8List.fromList(utf8.encode('export'));
          expect(setup.context.export(context, 32), opened.export(context, 32));
          setup.context.dispose();
          opened.dispose();
          continue;
        }
        final sealed = await PqHpke.seal(
          suite: chosen,
          mode: mode,
          recipientPublicKey: recipient.publicKey,
          plaintext: plaintext,
          info: info,
          aad: aad,
          psk: mode.usesPsk ? psk : null,
          pskId: mode.usesPsk ? pskId : null,
          senderKey: mode.usesAuth ? sender : null,
        );
        final opened = await PqHpke.open(
          suite: chosen,
          mode: mode,
          enc: sealed.enc,
          ciphertext: sealed.ciphertext,
          recipientKey: recipient,
          info: info,
          aad: aad,
          psk: mode.usesPsk ? psk : null,
          pskId: mode.usesPsk ? pskId : null,
          senderPublicKey: mode.usesAuth ? sender.publicKey : null,
        );
        expect(opened.plaintext, plaintext);
        final context = Uint8List.fromList(utf8.encode('export'));
        expect(
          sealed.context.export(context, 32),
          opened.context.export(context, 32),
        );
        sealed.context.dispose();
        opened.context.dispose();
        expect(
          () => sealed.context.export(context, 32),
          throwsA(isA<PqForgeException>()),
        );
      }
    }
  });

  test('a failed open does not consume the sequence', () async {
    final recipient = await PqHpke.generateKeyPair(HpkeKem.x25519HkdfSha256);
    final first = Uint8List.fromList(utf8.encode('one'));
    final second = Uint8List.fromList(utf8.encode('two'));
    final setup = await PqHpke.setupSender(
      suite: HpkeSuite.x25519ChaCha20Poly1305,
      mode: HpkeMode.base,
      recipientPublicKey: recipient.publicKey,
    );
    final ct0 = setup.context.seal(first);
    final ct1 = setup.context.seal(second);
    final recipientCtx = await PqHpke.setupRecipient(
      suite: HpkeSuite.x25519ChaCha20Poly1305,
      mode: HpkeMode.base,
      enc: setup.enc,
      recipientKey: recipient,
    );
    final tampered = Uint8List.fromList(ct0)..[0] ^= 0x01;
    expect(
      () => recipientCtx.open(tampered),
      throwsA(isA<PqForgeAuthTagException>()),
    );
    expect(recipientCtx.open(ct0), first);
    expect(recipientCtx.open(ct1), second);
    expect(() => recipientCtx.seal(first), throwsA(isA<PqForgeException>()));
    expect(() => setup.context.open(ct0), throwsA(isA<PqForgeException>()));
  });

  test('auth and PSK mismatches fail closed', () async {
    final recipient = await PqHpke.generateKeyPair(HpkeKem.x25519HkdfSha256);
    final sender = await PqHpke.generateKeyPair(HpkeKem.x25519HkdfSha256);
    final other = await PqHpke.generateKeyPair(HpkeKem.x25519HkdfSha256);
    final psk = Uint8List.fromList(List<int>.filled(32, 7));
    final pskId = Uint8List.fromList(utf8.encode('id'));
    final plaintext = Uint8List.fromList(utf8.encode('sealed'));
    final sealed = await PqHpke.seal(
      suite: HpkeSuite.x25519Aes128Gcm,
      mode: HpkeMode.authPsk,
      recipientPublicKey: recipient.publicKey,
      plaintext: plaintext,
      psk: psk,
      pskId: pskId,
      senderKey: sender,
    );
    expect(
      () => PqHpke.open(
        suite: HpkeSuite.x25519Aes128Gcm,
        mode: HpkeMode.authPsk,
        enc: sealed.enc,
        ciphertext: sealed.ciphertext,
        recipientKey: recipient,
        psk: psk,
        pskId: pskId,
        senderPublicKey: other.publicKey,
      ),
      throwsA(isA<PqForgeAuthTagException>()),
    );
    final wrongPsk = Uint8List.fromList(psk)..[0] ^= 0xff;
    expect(
      () => PqHpke.open(
        suite: HpkeSuite.x25519Aes128Gcm,
        mode: HpkeMode.authPsk,
        enc: sealed.enc,
        ciphertext: sealed.ciphertext,
        recipientKey: recipient,
        psk: wrongPsk,
        pskId: pskId,
        senderPublicKey: sender.publicKey,
      ),
      throwsA(isA<PqForgeAuthTagException>()),
    );
    expect(
      () => PqHpke.setupSender(
        suite: HpkeSuite.x25519Aes128Gcm,
        mode: HpkeMode.base,
        recipientPublicKey: recipient.publicKey,
        psk: psk,
        pskId: pskId,
      ),
      throwsArgumentError,
    );
    expect(
      () => PqHpke.setupSender(
        suite: HpkeSuite.x25519Aes128Gcm,
        mode: HpkeMode.psk,
        recipientPublicKey: recipient.publicKey,
      ),
      throwsArgumentError,
    );
  });

  test('HKDF-SHA512 schedules with an X25519 KEM', () async {
    const suite = HpkeSuite(
      kem: HpkeKem.x25519HkdfSha256,
      kdf: HpkeKdf.hkdfSha512,
      aead: HpkeAead.aes128Gcm,
    );
    final recipient = await PqHpke.generateKeyPair(suite.kem);
    final plaintext = Uint8List.fromList(utf8.encode('sha-512 schedule'));
    final sealed = await PqHpke.seal(
      suite: suite,
      mode: HpkeMode.base,
      recipientPublicKey: recipient.publicKey,
      plaintext: plaintext,
    );
    final opened = await PqHpke.open(
      suite: suite,
      mode: HpkeMode.base,
      enc: sealed.enc,
      ciphertext: sealed.ciphertext,
      recipientKey: recipient,
    );
    expect(opened.plaintext, plaintext);
  });
}

Future<void> _expectVector(Map<String, dynamic> vector) async {
  final mode = HpkeMode.fromId(vector['mode'] as int);
  final kem = HpkeKem.fromId(vector['kem_id'] as int);
  final suite = HpkeSuite(
    kem: kem,
    kdf: HpkeKdf.fromId(vector['kdf_id'] as int),
    aead: HpkeAead.fromId(vector['aead_id'] as int),
  );
  final label =
      'mode ${mode.name} kem ${kem.id} kdf ${suite.kdf.id} '
      'aead ${suite.aead.id}';
  final recipient = await PqHpke.deriveKeyPair(
    kem: kem,
    ikm: _hex(vector['ikmR'] as String),
  );
  expect(recipient.secretKey, _hex(vector['skRm'] as String), reason: label);
  expect(recipient.publicKey, _hex(vector['pkRm'] as String), reason: label);
  HpkeKeyPair? sender;
  if (vector['ikmS'] != null) {
    sender = await PqHpke.deriveKeyPair(
      kem: kem,
      ikm: _hex(vector['ikmS'] as String),
    );
    expect(sender.secretKey, _hex(vector['skSm'] as String), reason: label);
    expect(sender.publicKey, _hex(vector['pkSm'] as String), reason: label);
  }
  final setup = await PqHpke.setupSender(
    suite: suite,
    mode: mode,
    recipientPublicKey: recipient.publicKey,
    info: _hex(vector['info'] as String),
    psk: vector['psk'] == null ? null : _hex(vector['psk'] as String),
    pskId: vector['psk_id'] == null ? null : _hex(vector['psk_id'] as String),
    senderKey: sender,
    ephemeralIkm: _hex(vector['ikmE'] as String),
  );
  expect(setup.enc, _hex(vector['enc'] as String), reason: label);
  expect(setup.enc, _hex(vector['pkEm'] as String), reason: label);
  final opened = await PqHpke.setupRecipient(
    suite: suite,
    mode: mode,
    enc: setup.enc,
    recipientKey: recipient,
    info: _hex(vector['info'] as String),
    psk: vector['psk'] == null ? null : _hex(vector['psk'] as String),
    pskId: vector['psk_id'] == null ? null : _hex(vector['psk_id'] as String),
    senderPublicKey: sender?.publicKey,
  );
  final encryptions = vector['encryptions'] as List<dynamic>;
  var produced = 0;
  for (final raw in encryptions) {
    final encryption = raw as Map<String, dynamic>;
    final seq = encryption['seq'] as int;
    while (produced < seq) {
      final skipped = setup.context.seal(
        _hex(encryption['pt'] as String),
        aad: _hex(encryption['aad'] as String),
      );
      expect(
        opened.open(skipped, aad: _hex(encryption['aad'] as String)),
        _hex(encryption['pt'] as String),
        reason: '$label seq $produced',
      );
      produced++;
    }
    final ciphertext = setup.context.seal(
      _hex(encryption['pt'] as String),
      aad: _hex(encryption['aad'] as String),
    );
    expect(
      ciphertext,
      _hex(encryption['ct'] as String),
      reason: '$label seq $seq',
    );
    expect(
      opened.open(ciphertext, aad: _hex(encryption['aad'] as String)),
      _hex(encryption['pt'] as String),
      reason: '$label open $seq',
    );
    produced++;
  }
  for (final raw in vector['exports'] as List<dynamic>) {
    final exported = raw as Map<String, dynamic>;
    final context = _hex(exported['exporter_context'] as String);
    final length = exported['L'] as int;
    final expected = _hex(exported['exported_value'] as String);
    expect(setup.context.export(context, length), expected, reason: label);
    expect(opened.export(context, length), expected, reason: label);
  }
  setup.context.dispose();
  opened.dispose();
}

Uint8List _hex(String hex) {
  if (hex.isEmpty) return Uint8List(0);
  final out = Uint8List(hex.length ~/ 2);
  for (var i = 0; i < out.length; i++) {
    out[i] = int.parse(hex.substring(i * 2, i * 2 + 2), radix: 16);
  }
  return out;
}
