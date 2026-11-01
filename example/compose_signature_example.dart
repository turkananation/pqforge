import 'dart:typed_data';

import 'package:pqforge/pqforge.dart';

Future<void> main() async {
  const forge = PqForge(profile: PqForgeProfile.compact);
  final ml = forge.generateSignatureKeyPair();
  final p256 = PqEcdsaP256.generateKeyPair();
  final p521 = PqEcdsaP521.generateKeyPair();
  const composer = PqForgeSignatureComposer(profile: PqForgeProfile.compact);
  final message = Uint8List.fromList([1, 2, 3, 4]);
  final signature = await composer.sign(
    message: message,
    mlDsaSecret: ml.secretKey,
    mlDsa: PqSignatureAlgorithm.mlDsa44,
    classical: [
      PqClassicalSignatureKeyPair(
        algorithm: PqClassicalSignatureAlgorithm.ecdsaP256,
        publicKey: p256.publicKey,
        secretKey: p256.secretKey,
      ),
      PqClassicalSignatureKeyPair(
        algorithm: PqClassicalSignatureAlgorithm.ecdsaP521,
        publicKey: p521.publicKey,
        secretKey: p521.secretKey,
      ),
    ],
  );
  final ok = await composer.verify(
    message: message,
    signature: PqCompositeSignature.fromJson(signature.toJson()),
    mlDsaPublic: ml.publicKey,
    classicalPublic: [
      (algorithmId: 'ecdsa-p256', publicKey: p256.publicKey),
      (algorithmId: 'ecdsa-p521', publicKey: p521.publicKey),
    ],
  );
  print(
    'triple verified: $ok '
    '(${signature.legs.map((leg) => leg.algorithmId).join(' + ')})',
  );
}
