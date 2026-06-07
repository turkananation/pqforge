import 'dart:convert';
import 'dart:typed_data';

import 'package:pqforge/pqforge.dart';
import 'package:pqforge/pqforge_cryptography.dart';

Future<void> main() async {
  const profile = PqForgeProfile.compact;
  final forge = PqForge(profile: profile);
  final serverKem = forge.generateKemKeyPair();
  const agreement = PqForgeHybridKeyAgreement(profile: profile);
  final serverX25519 = await agreement.generateClassicalKeyPair();
  final serverX25519Public = await serverX25519.extractPublicKey();
  final deploymentSalt = PqBytes.randomBytes(32);
  final transcriptContext = PqBytes.utf8Bytes('demo/server-api/v1');

  final client = await agreement.initiate(
    serverClassicalPublicKey: serverX25519Public,
    serverKemPublicKey: serverKem.publicKey,
    deploymentSalt: deploymentSalt,
    transcriptContext: transcriptContext,
    roleContext: PqBytes.utf8Bytes('client->server'),
  );
  final server = await agreement.accept(
    serverClassicalKeyPair: serverX25519,
    serverKemSecretKey: serverKem.secretKey,
    request: PqHybridKeyAgreementRequest.fromJson(client.request.toJson()),
    deploymentSalt: deploymentSalt,
    roleContext: PqBytes.utf8Bytes('client->server'),
  );

  print('hybrid key agreement');
  print('profile: ${profile.name}');
  print('request json keys: ${client.request.toJson().keys.join(', ')}');
  print(
    'session keys match: ${PqBytes.constantTimeEquals(client.sessionKey, server)}',
  );

  final pqcSigner = forge.generateSignatureKeyPair();
  const signer = PqForgeHybridSigner(profile: profile);
  final ed25519 = await signer.generateClassicalKeyPair();
  final ed25519Public = await ed25519.extractPublicKey();
  final message = Uint8List.fromList(utf8.encode('release manifest'));
  final signature = await signer.sign(
    pqcSecretKey: pqcSigner.secretKey,
    classicalKeyPair: ed25519,
    message: message,
    context: PqBytes.utf8Bytes('release/v1'),
  );
  final ok = await signer.verify(
    pqcPublicKey: pqcSigner.publicKey,
    classicalPublicKey: ed25519Public,
    message: message,
    signature: PqHybridSignature.fromJson(signature.toJson()),
    context: PqBytes.utf8Bytes('release/v1'),
  );

  print('\nhybrid signature');
  print('classical algorithm: ${signature.classicalAlgorithm.id}');
  print('pqc algorithm: ${signature.pqcAlgorithm.id}');
  print('verified: $ok');
}
