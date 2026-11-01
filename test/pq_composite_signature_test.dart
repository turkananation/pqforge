import 'dart:convert';
import 'dart:typed_data';

import 'package:pqforge/pqforge.dart';
import 'package:test/test.dart';

void main() {
  const forge = PqForge(profile: PqForgeProfile.compact);
  final message = Uint8List.fromList(utf8.encode('compose me'));

  test('dual ML-DSA + SLH-DSA require-all, and a tampered leg fails', () async {
    const slh = PqSlhDsaAlgorithm.shake128f;
    final ml = forge.generateSignatureKeyPair();
    final hash = forge.generateSlhDsaKeyPair(algorithm: slh);
    const composer = PqForgeSignatureComposer(profile: PqForgeProfile.compact);
    final signature = await composer.sign(
      message: message,
      mlDsaSecret: ml.secretKey,
      mlDsa: PqSignatureAlgorithm.mlDsa44,
      slhSecret: hash.secretKey,
      slhDsa: slh,
    );
    expect(signature.legs.map((leg) => leg.algorithmId), [
      'ml-dsa-44',
      'slh-dsa-shake-128f',
    ]);
    final restored = PqCompositeSignature.fromJson(signature.toJson());
    expect(
      await composer.verify(
        message: message,
        signature: restored,
        mlDsaPublic: ml.publicKey,
        slhPublic: hash.publicKey,
      ),
      isTrue,
    );
    final tampered = PqCompositeSignature(
      policy: signature.policy,
      legs: [
        signature.legs.first,
        PqCompositeLeg(
          algorithmId: slh.id,
          signature: Uint8List.fromList(signature.legs.last.signature)
            ..[0] ^= 1,
        ),
      ],
    );
    expect(
      await composer.verify(
        message: message,
        signature: tampered,
        mlDsaPublic: ml.publicKey,
        slhPublic: hash.publicKey,
      ),
      isFalse,
    );
  });

  test('triple ML-DSA + P-256 + P-521 and accept-any', () async {
    final ml = forge.generateSignatureKeyPair();
    final p256 = PqEcdsaP256.generateKeyPair();
    final p521 = PqEcdsaP521.generateKeyPair();
    const composer = PqForgeSignatureComposer(profile: PqForgeProfile.compact);
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
      policy: PqCompositePolicy.acceptAny,
      context: Uint8List.fromList(utf8.encode('release')),
    );
    expect(signature.legs, hasLength(3));
    expect(
      await composer.verify(
        message: message,
        signature: signature,
        classicalPublic: [
          (algorithmId: 'ecdsa-p256', publicKey: p256.publicKey),
          (algorithmId: 'ecdsa-p521', publicKey: p521.publicKey),
        ],
      ),
      isTrue,
    );
    final strict = PqCompositeSignature(
      policy: PqCompositePolicy.requireAll,
      context: signature.context,
      legs: signature.legs,
    );
    expect(
      await composer.verify(
        message: message,
        signature: strict,
        mlDsaPublic: ml.publicKey,
        classicalPublic: [
          (algorithmId: 'ecdsa-p521', publicKey: p521.publicKey),
        ],
      ),
      isFalse,
    );
  });

  test('rejects a single leg and a fourth leg', () {
    PqCompositeLeg leg(String id, int length) =>
        PqCompositeLeg(algorithmId: id, signature: Uint8List(length));
    expect(
      () => PqCompositeSignature(
        legs: [leg('ml-dsa-44', PqSignatureAlgorithm.mlDsa44.signatureBytes)],
      ),
      throwsA(isA<PqForgeException>()),
    );
    expect(
      () => PqCompositeSignature(
        legs: [
          leg('ml-dsa-44', PqSignatureAlgorithm.mlDsa44.signatureBytes),
          leg('ed25519', 64),
          leg('ecdsa-p256', 64),
          leg('ecdsa-p521', 132),
        ],
      ),
      throwsA(isA<PqForgeException>()),
    );
  });
}
