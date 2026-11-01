import 'dart:convert';
import 'dart:typed_data';

import 'package:pqforge/pqforge.dart';

Future<void> main() async {
  final recipient = await PqHpke.generateKeyPair(HpkeKem.x25519HkdfSha256);
  final sender = await PqHpke.generateKeyPair(HpkeKem.x25519HkdfSha256);
  final info = Uint8List.fromList(utf8.encode('county ledger v1'));
  final aad = Uint8List.fromList(utf8.encode('desk=records'));
  final plaintext = Uint8List.fromList(
    utf8.encode('budget line stays inside the seal'),
  );

  final sealed = await PqHpke.seal(
    suite: HpkeSuite.x25519Aes128Gcm,
    mode: HpkeMode.base,
    recipientPublicKey: recipient.publicKey,
    info: info,
    aad: aad,
    plaintext: plaintext,
  );
  final opened = await PqHpke.open(
    suite: HpkeSuite.x25519Aes128Gcm,
    mode: HpkeMode.base,
    enc: sealed.enc,
    ciphertext: sealed.ciphertext,
    recipientKey: recipient,
    info: info,
    aad: aad,
  );
  print('base open: ${utf8.decode(opened.plaintext)}');

  final authed = await PqHpke.seal(
    suite: HpkeSuite.x25519ChaCha20Poly1305,
    mode: HpkeMode.auth,
    recipientPublicKey: recipient.publicKey,
    senderKey: sender,
    info: info,
    plaintext: plaintext,
  );
  final authedOpen = await PqHpke.open(
    suite: HpkeSuite.x25519ChaCha20Poly1305,
    mode: HpkeMode.auth,
    enc: authed.enc,
    ciphertext: authed.ciphertext,
    recipientKey: recipient,
    senderPublicKey: sender.publicKey,
    info: info,
  );
  print('auth open: ${utf8.decode(authedOpen.plaintext)}');

  final setup = await PqHpke.setupSender(
    suite: const HpkeSuite(aead: HpkeAead.exportOnly),
    mode: HpkeMode.base,
    recipientPublicKey: recipient.publicKey,
    info: info,
  );
  final peer = await PqHpke.setupRecipient(
    suite: const HpkeSuite(aead: HpkeAead.exportOnly),
    mode: HpkeMode.base,
    enc: setup.enc,
    recipientKey: recipient,
    info: info,
  );
  final label = Uint8List.fromList(utf8.encode('channel secret'));
  final left = setup.context.export(label, 32);
  final right = peer.export(label, 32);
  print('export matches: ${_same(left, right)} (${left.length} bytes)');

  final wide = await PqHpke.generateKeyPair(HpkeKem.x448HkdfSha512);
  final wideSealed = await PqHpke.seal(
    suite: const HpkeSuite(
      kem: HpkeKem.x448HkdfSha512,
      kdf: HpkeKdf.hkdfSha512,
      aead: HpkeAead.aes256Gcm,
    ),
    mode: HpkeMode.base,
    recipientPublicKey: wide.publicKey,
    info: info,
    plaintext: plaintext,
  );
  final wideOpen = await PqHpke.open(
    suite: const HpkeSuite(
      kem: HpkeKem.x448HkdfSha512,
      kdf: HpkeKdf.hkdfSha512,
      aead: HpkeAead.aes256Gcm,
    ),
    mode: HpkeMode.base,
    enc: wideSealed.enc,
    ciphertext: wideSealed.ciphertext,
    recipientKey: wide,
    info: info,
  );
  print('x448 open: ${utf8.decode(wideOpen.plaintext)}');
  setup.context.dispose();
  peer.dispose();
  sealed.context.dispose();
  opened.context.dispose();
}

bool _same(Uint8List left, Uint8List right) {
  if (left.length != right.length) return false;
  for (var i = 0; i < left.length; i++) {
    if (left[i] != right[i]) return false;
  }
  return true;
}
