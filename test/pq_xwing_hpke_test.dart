import 'dart:io';
import 'dart:typed_data';

import 'package:cryptography/cryptography.dart' as crypto;
import 'package:pqforge/pqforge.dart';
import 'package:test/test.dart';

import 'xwing_vectors.dart';

void main() {
  const suite = HpkeSuite(kem: HpkeKem.xWing, aead: HpkeAead.aes256Gcm);

  test(
    'HPKE base seal opens and the exporter is HKDF of the X-Wing secret',
    () async {
      final recipient = await PqXWing.generateKeyPairDerand(xwingSeed1);
      final direct = await PqXWing.encapsulateDerand(
        recipient.publicKey,
        xwingEseed1,
      );
      final info = Uint8List.fromList('app'.codeUnits);
      final sealed = await PqHpke.seal(
        suite: suite,
        mode: HpkeMode.base,
        recipientPublicKey: recipient.publicKey,
        plaintext: Uint8List.fromList('record'.codeUnits),
        info: info,
        aad: Uint8List.fromList('aad'.codeUnits),
        ephemeralIkm: xwingEseed1,
      );
      expect(sealed.enc, direct.ciphertext);
      final opened = await PqHpke.open(
        suite: suite,
        mode: HpkeMode.base,
        enc: sealed.enc,
        ciphertext: sealed.ciphertext,
        recipientKey: HpkeKeyPair(
          kem: HpkeKem.xWing,
          secretKey: recipient.secretKey,
          publicKey: recipient.publicKey,
        ),
        info: info,
        aad: Uint8List.fromList('aad'.codeUnits),
      );
      expect(opened.plaintext, Uint8List.fromList('record'.codeUnits));
      final context = Uint8List.fromList('export'.codeUnits);
      expect(
        sealed.context.export(context, 32),
        _expectedExport(direct.sharedSecret, info, context),
      );
      expect(
        () => PqHpke.open(
          suite: suite,
          mode: HpkeMode.base,
          enc: sealed.enc,
          ciphertext: sealed.ciphertext,
          recipientKey: HpkeKeyPair(
            kem: HpkeKem.xWing,
            secretKey: recipient.secretKey,
            publicKey: recipient.publicKey,
          ),
          info: Uint8List.fromList('other'.codeUnits),
        ),
        throwsA(isA<Exception>()),
      );
      sealed.context.dispose();
      opened.context.dispose();
    },
  );

  test(
    'a 32-byte ephemeral seed is rejected and auth returns no enc',
    () async {
      final recipient = await PqXWing.generateKeyPairDerand(xwingSeed1);
      expect(
        () => PqHpke.seal(
          suite: suite,
          mode: HpkeMode.base,
          recipientPublicKey: recipient.publicKey,
          plaintext: Uint8List(1),
          ephemeralIkm: Uint8List(32),
        ),
        throwsArgumentError,
      );
      expect(
        () => PqHpke.seal(
          suite: suite,
          mode: HpkeMode.auth,
          recipientPublicKey: recipient.publicKey,
          plaintext: Uint8List(1),
          senderKey: HpkeKeyPair(
            kem: HpkeKem.xWing,
            secretKey: recipient.secretKey,
            publicKey: recipient.publicKey,
          ),
        ),
        throwsArgumentError,
      );
      expect(
        () => PqHpke.seal(
          suite: suite,
          mode: HpkeMode.authPsk,
          recipientPublicKey: recipient.publicKey,
          plaintext: Uint8List(1),
          psk: Uint8List(32),
          pskId: Uint8List.fromList('id'.codeUnits),
          senderKey: HpkeKeyPair(
            kem: HpkeKem.xWing,
            secretKey: recipient.secretKey,
            publicKey: recipient.publicKey,
          ),
        ),
        throwsArgumentError,
      );
    },
  );

  test('PSK mode seals and a base open of that ciphertext fails', () async {
    final recipient = await PqXWing.generateKeyPairDerand(xwingSeed1);
    final key = HpkeKeyPair(
      kem: HpkeKem.xWing,
      secretKey: recipient.secretKey,
      publicKey: recipient.publicKey,
    );
    final psk = Uint8List(32)..[0] = 1;
    final pskId = Uint8List.fromList('id'.codeUnits);
    final sealed = await PqHpke.seal(
      suite: suite,
      mode: HpkeMode.psk,
      recipientPublicKey: recipient.publicKey,
      plaintext: Uint8List.fromList('psk'.codeUnits),
      psk: psk,
      pskId: pskId,
      ephemeralIkm: xwingEseed1,
    );
    final opened = await PqHpke.open(
      suite: suite,
      mode: HpkeMode.psk,
      enc: sealed.enc,
      ciphertext: sealed.ciphertext,
      recipientKey: key,
      psk: psk,
      pskId: pskId,
    );
    expect(opened.plaintext, Uint8List.fromList('psk'.codeUnits));
    expect(sealed.enc, xwingCt1);
    expect(
      () => PqHpke.open(
        suite: suite,
        mode: HpkeMode.base,
        enc: sealed.enc,
        ciphertext: sealed.ciphertext,
        recipientKey: key,
      ),
      throwsA(isA<Exception>()),
    );
    sealed.context.dispose();
    opened.context.dispose();
  });

  test(
    'DeriveKeyPair is not the raw seed, and FIPS rejects the facade',
    () async {
      final ikm = Uint8List.fromList(xwingSeed1);
      final derived = await PqHpke.deriveKeyPair(kem: HpkeKem.xWing, ikm: ikm);
      final raw = await PqXWing.generateKeyPairDerand(ikm);
      expect(derived.publicKey, isNot(raw.publicKey));
      final known = await PqXWing.encapsulateDerand(
        derived.publicKey,
        xwingEseed1,
      );
      expect(
        await PqXWing.decapsulate(known.ciphertext, derived.secretKey),
        known.sharedSecret,
      );
      final fresh = await PqHpke.generateKeyPair(HpkeKem.xWing);
      final sealed = await PqHpke.seal(
        suite: suite,
        mode: HpkeMode.base,
        recipientPublicKey: fresh.publicKey,
        plaintext: Uint8List.fromList([7]),
      );
      final opened = await PqHpke.open(
        suite: suite,
        mode: HpkeMode.base,
        enc: sealed.enc,
        ciphertext: sealed.ciphertext,
        recipientKey: fresh,
      );
      expect(opened.plaintext, Uint8List.fromList([7]));
      sealed.context.dispose();
      opened.context.dispose();
      final empty = await PqHpke.deriveKeyPair(
        kem: HpkeKem.xWing,
        ikm: Uint8List(0),
      );
      expect(empty.publicKey, hasLength(1216));

      PqFipsMode.enable();
      try {
        expect(
          () => PqHpke.generateKeyPair(HpkeKem.xWing),
          throwsA(isA<PqForgeException>()),
        );
        final math = await PqXWing.generateKeyPairDerand(xwingSeed1);
        expect(math.publicKey, xwingPk1);
      } finally {
        PqFipsMode.disable();
      }
    },
  );

  test(
    'the default agreement mode is unchanged and X-Wing is opt-in',
    () async {
      const custom = PqForgeHybridKeyAgreement();
      expect(custom.mode, PqHybridAgreementMode.pqforge);
      expect(
        () => custom.encapsulateXWing(xwingPk1),
        throwsA(isA<PqForgeException>()),
      );
      const xwing = PqForgeHybridKeyAgreement(
        mode: PqHybridAgreementMode.xWing,
      );
      expect(
        () => xwing.initiate(
          serverClassicalPublicKey: crypto.SimplePublicKey(
            Uint8List(32),
            type: crypto.KeyPairType.x25519,
          ),
          serverKemPublicKey: Uint8List(0),
          deploymentSalt: Uint8List(1),
        ),
        throwsA(
          isA<PqForgeException>().having(
            (error) => error.message,
            'message',
            contains('does not use the pqforge handshake'),
          ),
        ),
      );
      final enc = await xwing.encapsulateXWing(xwingPk1, eseed: xwingEseed1);
      expect(enc.sharedSecret, xwingSs1);
      expect(enc.ciphertext, xwingCt1);
      expect(
        await xwing.decapsulateXWing(enc.ciphertext, xwingSeed1),
        xwingSs1,
      );
      expect(
        () => custom.decapsulateXWing(xwingCt1, xwingSeed1),
        throwsA(isA<PqForgeException>()),
      );
      final request = PqHybridKeyAgreementRequest(
        profile: PqForgeProfile.balanced,
        serverClassicalPublicKey: Uint8List(32),
        serverKemPublicKey: Uint8List(
          PqForgeProfile.balanced.kem.publicKeyBytes,
        ),
        clientClassicalPublicKey: Uint8List(32),
        kemCiphertext: Uint8List(PqForgeProfile.balanced.kem.ciphertextBytes),
      );
      final server = await xwing.generateClassicalKeyPair();
      expect(
        () => xwing.accept(
          serverClassicalKeyPair: server,
          serverKemSecretKey: Uint8List(0),
          request: request,
          deploymentSalt: Uint8List(1),
        ),
        throwsA(
          isA<PqForgeException>().having(
            (error) => error.message,
            'message',
            contains('does not use the pqforge handshake'),
          ),
        ),
      );
      PqFipsMode.enable();
      try {
        expect(
          () => xwing.encapsulateXWing(xwingPk1, eseed: xwingEseed1),
          throwsA(isA<PqForgeException>()),
        );
      } finally {
        PqFipsMode.disable();
      }
    },
  );

  test('XW01 is not PQF1', () {
    final message = PqXWingMessage.encode(
      suite: suite,
      enc: xwingCt1,
      ciphertext: Uint8List.fromList([1, 2, 3, 4]),
    );
    expect(String.fromCharCodes(message.sublist(0, 4)), 'XW01');
    expect(String.fromCharCodes(message.sublist(0, 4)), isNot('PQF1'));
    final decoded = PqXWingMessage.decode(message);
    expect(decoded.enc, xwingCt1);
    expect(decoded.ciphertext, Uint8List.fromList([1, 2, 3, 4]));
    expect(
      () => PqXWingMessage.decode(Uint8List.fromList('PQF1'.codeUnits)),
      throwsA(isA<PqForgeException>()),
    );
  });

  test('a 32-byte X-Wing seed wraps and unwraps', () {
    final forge = PqForge();
    final key = PqExportedKey(
      kind: 'xwing-secret',
      algorithmId: 'xwing',
      bytes: xwingSeed1,
    );
    final wrapped = forge.wrapKeyWithPassphrase(
      key,
      'correct horse',
      iterations: 1,
      memoryPowerOf2: 10,
      lanes: 1,
    );
    final opened = forge.unwrapKeyWithPassphrase(wrapped, 'correct horse');
    expect(opened.bytes, xwingSeed1);
    expect(xwingSeed1, hasLength(32));
  });

  test('hpke seal round-trips and does not write PQF1', () async {
    final dir = await Directory.systemTemp.createTemp('pqforge-xwing');
    try {
      final dart = Platform.resolvedExecutable;
      final keygen = await Process.run(dart, [
        'run',
        'bin/pqforge.dart',
        'hpke',
        'keygen',
        '--key-id',
        'demo',
        '--out-dir',
        dir.path,
      ]);
      expect(keygen.exitCode, 0, reason: '${keygen.stdout}\n${keygen.stderr}');
      final plain = File('${dir.path}/plain.txt')
        ..writeAsStringSync('hello xwing');
      final sealed = File('${dir.path}/out.xwing');
      final seal = await Process.run(dart, [
        'run',
        'bin/pqforge.dart',
        'hpke',
        'seal',
        '--recipient-public',
        '${dir.path}/demo.xwing.public.json',
        '--in',
        plain.path,
        '--out',
        sealed.path,
      ]);
      expect(seal.exitCode, 0, reason: '${seal.stdout}\n${seal.stderr}');
      final bytes = sealed.readAsBytesSync();
      expect(String.fromCharCodes(bytes.sublist(0, 4)), 'XW01');
      final opened = File('${dir.path}/opened.txt');
      final open = await Process.run(dart, [
        'run',
        'bin/pqforge.dart',
        'hpke',
        'open',
        '--recipient-secret',
        '${dir.path}/demo.xwing.secret.json',
        '--in',
        sealed.path,
        '--out',
        opened.path,
      ]);
      expect(open.exitCode, 0, reason: '${open.stdout}\n${open.stderr}');
      expect(opened.readAsStringSync(), 'hello xwing');
    } finally {
      dir.deleteSync(recursive: true);
    }
  });
}

Uint8List _expectedExport(Uint8List ss, Uint8List info, Uint8List context) {
  final suiteId = Uint8List(10)
    ..setRange(0, 4, 'HPKE'.codeUnits)
    ..[4] = 0x64
    ..[5] = 0x7a
    ..[6] = 0x00
    ..[7] = 0x01
    ..[8] = 0x00
    ..[9] = 0x02;
  Uint8List labeledExtract(Uint8List salt, String label, Uint8List ikm) {
    final labeled = Uint8List.fromList([
      ...'HPKE-v1'.codeUnits,
      ...suiteId,
      ...label.codeUnits,
      ...ikm,
    ]);
    final used = salt.isEmpty ? Uint8List(32) : salt;
    return PqBytes.hmacSha256(key: used, data: labeled);
  }

  Uint8List labeledExpand(
    Uint8List prk,
    String label,
    Uint8List info,
    int length,
  ) {
    final labeled = Uint8List.fromList([
      (length >> 8) & 0xff,
      length & 0xff,
      ...'HPKE-v1'.codeUnits,
      ...suiteId,
      ...label.codeUnits,
      ...info,
    ]);
    return PqBytes.hmacSha256(
      key: prk,
      data: Uint8List.fromList([...labeled, 0x01]),
    ).sublist(0, length);
  }

  final pskIdHash = labeledExtract(Uint8List(0), 'psk_id_hash', Uint8List(0));
  final infoHash = labeledExtract(Uint8List(0), 'info_hash', info);
  final schedule = Uint8List.fromList([
    HpkeMode.base.wire,
    ...pskIdHash,
    ...infoHash,
  ]);
  final secret = labeledExtract(ss, 'secret', Uint8List(0));
  final exporter = labeledExpand(secret, 'exp', schedule, 32);
  return labeledExpand(exporter, 'sec', context, 32);
}
