import 'dart:convert';
import 'dart:typed_data';

import 'package:pqforge/pqforge.dart';
import 'package:test/test.dart';

void main() {
  group('PqForgeHybridKeyAgreement', () {
    test('derives identical X25519 + ML-KEM session keys', () async {
      const profile = PqForgeProfile.compact;
      final forge = PqForge(profile: profile);
      final serverKem = forge.generateKemKeyPair();
      const agreement = PqForgeHybridKeyAgreement(profile: profile);
      final serverX25519 = await agreement.generateClassicalKeyPair();
      final serverX25519Public = await serverX25519.extractPublicKey();
      final deploymentSalt = Uint8List.fromList(List<int>.filled(32, 7));
      final transcriptContext = _bytes('api-session:alpha');
      final roleContext = _bytes('client->server');

      final client = await agreement.initiate(
        serverClassicalPublicKey: serverX25519Public,
        serverKemPublicKey: serverKem.publicKey,
        deploymentSalt: deploymentSalt,
        transcriptContext: transcriptContext,
        roleContext: roleContext,
      );
      final restoredRequest = PqHybridKeyAgreementRequest.fromJson(
        client.request.toJson(),
      );
      final server = await agreement.accept(
        serverClassicalKeyPair: serverX25519,
        serverKemSecretKey: serverKem.secretKey,
        request: restoredRequest,
        deploymentSalt: deploymentSalt,
        roleContext: roleContext,
      );

      expect(PqBytes.constantTimeEquals(client.sessionKey, server), isTrue);
      expect(restoredRequest.transcriptHash, hasLength(32));
      expect(
        restoredRequest.kemCiphertext,
        hasLength(profile.kem.ciphertextBytes),
      );
    });

    test('rejects transcript tampering', () async {
      const profile = PqForgeProfile.compact;
      final forge = PqForge(profile: profile);
      final serverKem = forge.generateKemKeyPair();
      const agreement = PqForgeHybridKeyAgreement(profile: profile);
      final serverX25519 = await agreement.generateClassicalKeyPair();
      final serverX25519Public = await serverX25519.extractPublicKey();
      final client = await agreement.initiate(
        serverClassicalPublicKey: serverX25519Public,
        serverKemPublicKey: serverKem.publicKey,
        deploymentSalt: Uint8List.fromList(List<int>.filled(32, 9)),
        transcriptContext: _bytes('original'),
      );
      final tampered = PqHybridKeyAgreementRequest(
        profile: profile,
        serverClassicalPublicKey: client.request.serverClassicalPublicKey,
        serverKemPublicKey: client.request.serverKemPublicKey,
        clientClassicalPublicKey: client.request.clientClassicalPublicKey,
        kemCiphertext: client.request.kemCiphertext,
        transcriptContext: _bytes('tampered'),
        transcriptHash: client.request.transcriptHash,
      );

      expect(
        () => agreement.accept(
          serverClassicalKeyPair: serverX25519,
          serverKemSecretKey: serverKem.secretKey,
          request: tampered,
          deploymentSalt: Uint8List.fromList(List<int>.filled(32, 9)),
        ),
        throwsA(isA<PqForgeException>()),
      );
    });
  });

  group('PqForgeHybridSigner', () {
    test('signs and verifies with ML-DSA + Ed25519', () async {
      const profile = PqForgeProfile.compact;
      final forge = PqForge(profile: profile);
      final pqc = forge.generateSignatureKeyPair();
      const signer = PqForgeHybridSigner(profile: profile);
      final classical = await signer.generateClassicalKeyPair();
      final classicalPublic = classical.publicKey;
      final message = _bytes('release manifest');
      final context = _bytes('release:v1');

      final signature = await signer.sign(
        pqcSecretKey: pqc.secretKey,
        classicalKeyPair: classical,
        message: message,
        context: context,
      );
      final restored = PqHybridSignature.fromJson(signature.toJson());

      expect(
        await signer.verify(
          pqcPublicKey: pqc.publicKey,
          classicalPublicKey: classicalPublic,
          message: message,
          signature: restored,
          context: context,
        ),
        isTrue,
      );
      expect(
        await signer.verify(
          pqcPublicKey: pqc.publicKey,
          classicalPublicKey: classicalPublic,
          message: _bytes('changed manifest'),
          signature: restored,
          context: context,
        ),
        isFalse,
      );
    });

    test('signs and verifies with ML-DSA + ECDSA-P256', () async {
      const profile = PqForgeProfile.compact;
      final forge = PqForge(profile: profile);
      final pqc = forge.generateSignatureKeyPair();
      const signer = PqForgeHybridSigner(
        profile: profile,
        classicalAlgorithm: PqClassicalSignatureAlgorithm.ecdsaP256,
      );
      final classical = await signer.generateClassicalKeyPair();
      expect(classical.algorithm, PqClassicalSignatureAlgorithm.ecdsaP256);
      expect(classical.publicKey, hasLength(65));
      final message = _bytes('firmware image v4');
      final context = _bytes('firmware:v1');

      final signature = await signer.sign(
        pqcSecretKey: pqc.secretKey,
        classicalKeyPair: classical,
        message: message,
        context: context,
      );
      expect(
        signature.classicalAlgorithm,
        PqClassicalSignatureAlgorithm.ecdsaP256,
      );
      final restored = PqHybridSignature.fromJson(signature.toJson());

      expect(
        await signer.verify(
          pqcPublicKey: pqc.publicKey,
          classicalPublicKey: classical.publicKey,
          message: message,
          signature: restored,
          context: context,
        ),
        isTrue,
      );
      expect(
        await signer.verify(
          pqcPublicKey: pqc.publicKey,
          classicalPublicKey: classical.publicKey,
          message: _bytes('tampered image'),
          signature: restored,
          context: context,
        ),
        isFalse,
      );
    });

    test(
      'rejects a key pair whose algorithm differs from the signer',
      () async {
        const profile = PqForgeProfile.compact;
        final forge = PqForge(profile: profile);
        final pqc = forge.generateSignatureKeyPair();
        const ed25519Signer = PqForgeHybridSigner(profile: profile);
        const ecdsaSigner = PqForgeHybridSigner(
          profile: profile,
          classicalAlgorithm: PqClassicalSignatureAlgorithm.ecdsaP256,
        );
        final ecdsaKeyPair = await ecdsaSigner.generateClassicalKeyPair();

        await expectLater(
          ed25519Signer.sign(
            pqcSecretKey: pqc.secretKey,
            classicalKeyPair: ecdsaKeyPair,
            message: _bytes('x'),
          ),
          throwsA(isA<PqForgeException>()),
        );
      },
    );
  });

  group('classical key persistence helpers', () {
    test('classicalKeyPairFromSecret recovers an Ed25519 signer', () async {
      const profile = PqForgeProfile.compact;
      final pqc = PqForge(profile: profile).generateSignatureKeyPair();
      const signer = PqForgeHybridSigner(profile: profile);
      final original = await signer.generateClassicalKeyPair();

      final recovered = await signer.classicalKeyPairFromSecret(
        original.secretKey,
      );
      expect(recovered.algorithm, PqClassicalSignatureAlgorithm.ed25519);
      expect(recovered.publicKey, orderedEquals(original.publicKey));

      final message = _bytes('signed from a stored secret');
      final signature = await signer.sign(
        pqcSecretKey: pqc.secretKey,
        classicalKeyPair: recovered,
        message: message,
      );
      expect(
        await signer.verify(
          pqcPublicKey: pqc.publicKey,
          classicalPublicKey: original.publicKey,
          message: message,
          signature: signature,
        ),
        isTrue,
      );
    });

    test('classicalKeyPairFromSecret recovers an ECDSA-P256 signer', () async {
      const profile = PqForgeProfile.compact;
      final pqc = PqForge(profile: profile).generateSignatureKeyPair();
      const signer = PqForgeHybridSigner(
        profile: profile,
        classicalAlgorithm: PqClassicalSignatureAlgorithm.ecdsaP256,
      );
      final original = await signer.generateClassicalKeyPair();

      final recovered = await signer.classicalKeyPairFromSecret(
        original.secretKey,
      );
      expect(recovered.algorithm, PqClassicalSignatureAlgorithm.ecdsaP256);
      expect(recovered.publicKey, orderedEquals(original.publicKey));

      final message = _bytes('ecdsa from a stored secret');
      final signature = await signer.sign(
        pqcSecretKey: pqc.secretKey,
        classicalKeyPair: recovered,
        message: message,
      );
      expect(
        await signer.verify(
          pqcPublicKey: pqc.publicKey,
          classicalPublicKey: original.publicKey,
          message: message,
          signature: signature,
        ),
        isTrue,
      );
    });

    test('generateClassicalKeyPairBytes yields 32-byte X25519 keys', () async {
      const agreement = PqForgeHybridKeyAgreement();
      final seed = Uint8List.fromList(List<int>.filled(32, 3));
      final a = await agreement.generateClassicalKeyPairBytes(seed: seed);
      final b = await agreement.generateClassicalKeyPairBytes(seed: seed);

      expect(a.publicKey, hasLength(32));
      expect(a.secretKey, hasLength(32));
      // Seeded generation is deterministic.
      expect(a.publicKey, orderedEquals(b.publicKey));
      expect(a.secretKey, orderedEquals(b.secretKey));
    });
  });
}

Uint8List _bytes(String value) => Uint8List.fromList(utf8.encode(value));
