import 'dart:convert';
import 'dart:typed_data';

import 'package:pqforge/pqforge.dart';

void main() {
  final forge = PqForge(profile: PqForgeProfile.compact);
  final signer = forge.generateSignatureKeyPair();
  final recipient = forge.generateKemKeyPair();

  final webhookPayload = Uint8List.fromList(utf8.encode('{"invoice":"paid"}'));
  final timestampMs = DateTime.now().millisecondsSinceEpoch;
  final webhookSignature = forge.signWebhook(
    signerSecretKey: signer.secretKey,
    eventType: 'invoice.paid',
    timestampMs: timestampMs,
    payload: webhookPayload,
  );
  final webhookOk = forge.verifyWebhook(
    signerPublicKey: signer.publicKey,
    eventType: 'invoice.paid',
    timestampMs: timestampMs,
    payload: webhookPayload,
    signature: webhookSignature,
    nowMs: timestampMs,
  );

  final email = Uint8List.fromList(
    utf8.encode('From: ops@example.test\nSubject: PQC\n\nPrivate body.'),
  );
  final sealedEmail = forge.sealEmail(
    recipient.publicKey,
    email,
    messageId: 'message-123',
    aad: PqBytes.utf8Bytes('tenant:demo'),
    profile: PqForgeProfile.compact,
  );
  final openedEmail = forge.openEmail(
    recipient.secretKey,
    sealedEmail,
    aad: PqBytes.utf8Bytes('tenant:demo'),
  );

  final sealedText = forge.sealText(
    recipient.publicKey,
    'Confidential field memo',
    textId: 'memo-123',
    aad: PqBytes.utf8Bytes('tenant:demo'),
    profile: PqForgeProfile.compact,
  );
  final openedText = forge.openText(
    recipient.secretKey,
    sealedText,
    aad: PqBytes.utf8Bytes('tenant:demo'),
  );
  final textSignature = forge.signText(
    signerSecretKey: signer.secretKey,
    text: openedText,
    textId: 'memo-123',
  );
  final textOk = forge.verifyText(
    signerPublicKey: signer.publicKey,
    text: openedText,
    textId: 'memo-123',
    signature: textSignature,
  );

  final mediaBytes = Uint8List.fromList([137, 80, 78, 71, 13, 10, 26, 10]);
  final sealedMedia = forge.sealMedia(
    recipient.publicKey,
    mediaBytes,
    mediaId: 'cover.png',
    mimeType: 'image/png',
    profile: PqForgeProfile.compact,
  );
  final mediaSignature = forge.signMedia(
    signerSecretKey: signer.secretKey,
    mediaId: 'cover.png',
    mimeType: 'image/png',
    mediaBytes: mediaBytes,
  );
  final mediaOk = forge.verifyMedia(
    signerPublicKey: signer.publicKey,
    mediaId: 'cover.png',
    mimeType: 'image/png',
    mediaBytes: forge.openMedia(recipient.secretKey, sealedMedia),
    signature: mediaSignature,
  );

  final token = forge.issueToken(
    signerSecretKey: signer.secretKey,
    issuer: 'pqforge-demo',
    subject: 'user-1',
    issuedAtMs: timestampMs,
    expiresAtMs: timestampMs + 60000,
    claims: {
      'roles': ['operator'],
      'tenant': 'demo',
    },
  );
  final tokenOk = forge.verifyToken(
    signer.publicKey,
    PqSignedToken.fromJson(token.toJson()),
    nowMs: timestampMs + 1000,
  );

  print('webhook verified: $webhookOk');
  print('sealed email profile: ${sealedEmail.profile.name}');
  print('opened email bytes: ${openedEmail.length}');
  print('text verified: $textOk');
  print('media verified: $mediaOk');
  print('token verified: $tokenOk');
}
