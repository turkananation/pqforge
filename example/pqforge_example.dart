import 'dart:convert';
import 'dart:typed_data';

import 'package:pqforge/pqforge.dart';

void main() {
  final forge = PqForge(profile: PqForgeProfile.compact);
  final message = Uint8List.fromList(utf8.encode('pqforge example payload'));

  print('== 1. Generate keys ==');
  final bundle = forge.generateKeys(keyId: 'example-bundle');
  print(
    '${bundle.profile.name}: '
    '${bundle.profile.kem.name} + ${bundle.profile.signature.name}',
  );

  print('\n== 2. Sign and verify a document ==');
  final documentSignature = forge.signDocument(
    bundle.signatureKeyPair.secretKey,
    message,
    documentId: 'example-document',
  );
  final documentOk = forge.verifyDocument(
    bundle.signatureKeyPair.publicKey,
    message,
    documentSignature,
    documentId: 'example-document',
  );
  print('document verified: $documentOk');

  print('\n== 3. Encrypt and decrypt a record ==');
  final envelope = forge.encrypt(
    bundle.kemKeyPair.publicKey,
    message,
    aad: PqBytes.utf8Bytes('record:example'),
    metadata: {'recordType': 'demo'},
  );
  final opened = forge.decrypt(
    bundle.kemKeyPair.secretKey,
    envelope,
    aad: PqBytes.utf8Bytes('record:example'),
  );
  print('opened: ${utf8.decode(opened)}');

  print('\n== 4. Binary and JSON envelopes ==');
  final binary = envelope.toBinary();
  final jsonEnvelope = envelope.toJson();
  print('binary bytes: ${binary.length}');
  print('json keys: ${jsonEnvelope.keys.join(', ')}');

  print('\n== 5. Signed encrypted envelope ==');
  final signed = forge.encrypt(
    bundle.kemKeyPair.publicKey,
    message,
    signerSecretKey: bundle.signatureKeyPair.secretKey,
    signerKeyId: 'example-signer',
  );
  final signedOpened = forge.decrypt(
    bundle.kemKeyPair.secretKey,
    signed,
    signerPublicKey: bundle.signatureKeyPair.publicKey,
  );
  print('signed opened: ${utf8.decode(signedOpened)}');

  print('\n== 6. Hybrid session derivation ==');
  final kem = forge.encapsulate(bundle.kemKeyPair.publicKey);
  final classicalSharedSecret = PqBytes.randomBytes(32);
  final transcript = PqBytes.lengthPrefixed([
    PqBytes.utf8Bytes('example/handshake/v1'),
    bundle.kemKeyPair.publicKey,
    kem.ciphertext,
  ]);
  final sessionKey = forge.deriveHybridSessionKey(
    classicalSharedSecret: classicalSharedSecret,
    latticeSharedSecret: kem.sharedSecret,
    deploymentSalt: PqBytes.randomBytes(32),
    transcriptHash: PqBytes.sha256(transcript),
    roleContext: PqBytes.utf8Bytes('client->server'),
  );
  print('hybrid session key: ${sessionKey.length} bytes');
}
