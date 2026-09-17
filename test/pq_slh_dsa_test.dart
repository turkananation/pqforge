import 'dart:convert';
import 'dart:typed_data';

import 'package:pqcrypto/pqcrypto.dart';
import 'package:pqforge/pqforge.dart';
import 'package:test/test.dart';

void main() {
  group('PqSlhDsaAlgorithm', () {
    test('covers all 12 FIPS 205 sets with pqcrypto sizes', () {
      expect(PqSlhDsaAlgorithm.values, hasLength(12));
      expect(PqSlhDsaAlgorithm.ids, hasLength(12));
      for (final algorithm in PqSlhDsaAlgorithm.values) {
        expect(PqSlhDsaAlgorithm.ids, contains(algorithm.id));
        final params = _params(algorithm);
        expect(algorithm.name, params.name);
        expect(algorithm.publicKeyBytes, params.publicKeyBytes);
        expect(algorithm.secretKeyBytes, params.secretKeyBytes);
        expect(algorithm.signatureBytes, params.signatureBytes);
        expect(algorithm.securityCategory, params.securityCategory);
        expect(algorithm.isFast, params.isFast);
        expect(PqSlhDsaAlgorithm.byId(algorithm.id), algorithm);
        expect(PqSlhDsaAlgorithm.byId(algorithm.name), algorithm);
        expect(PqSlhDsaAlgorithm.tryById(algorithm.id), algorithm);
      }
    });

    test('lookup rejects unknown identifiers', () {
      expect(PqSlhDsaAlgorithm.tryById('ml-dsa-65'), isNull);
      expect(
        () => PqSlhDsaAlgorithm.byId('sphincs+'),
        throwsA(isA<PqForgeException>()),
      );
    });
  });

  group('profiles', () {
    test('named profiles pick the matching SHAKE-f SLH-DSA set', () {
      expect(PqForgeProfile.compact.slhDsa, PqSlhDsaAlgorithm.shake128f);
      expect(PqForgeProfile.balanced.slhDsa, PqSlhDsaAlgorithm.shake192f);
      expect(PqForgeProfile.maximum.slhDsa, PqSlhDsaAlgorithm.shake256f);
    });
  });

  group('key generation', () {
    const forge = PqForge(profile: PqForgeProfile.compact);

    test('generateSlhDsaKeyPair emits every FIPS 205 set at spec length', () {
      for (final algorithm in PqSlhDsaAlgorithm.values) {
        final pair = forge.generateSlhDsaKeyPair(algorithm: algorithm);
        expect(pair.publicKey, hasLength(algorithm.publicKeyBytes));
        expect(pair.secretKey, hasLength(algorithm.secretKeyBytes));
        final exported = forge.exportSlhDsaPublicKey(
          pair,
          algorithm: algorithm,
          keyId: 'kat',
        );
        expect(exported.kind, PqKeyKind.signaturePublic);
        expect(exported.algorithmId, algorithm.id);
        expect(exported.keyId, 'kat');
        expect(exported.bytes, pair.publicKey);
      }
    });

    test(
      'generateKeys stays ML-KEM + ML-DSA (SLH-DSA is a sibling family)',
      () {
        final bundle = forge.generateKeys(keyId: 'bundle');
        expect(
          bundle.signatureKeyPair.publicKey,
          hasLength(PqSignatureAlgorithm.mlDsa44.publicKeyBytes),
        );
      },
    );
  });

  group('sign / verify', () {
    const forge = PqForge(profile: PqForgeProfile.compact);
    final message = Uint8List.fromList(utf8.encode('slh-dsa/payload'));
    final context = Uint8List.fromList(utf8.encode('pqforge/slh-dsa/v1'));

    test('SHAKE-128f round-trips raw and pre-hash signatures', () {
      const algorithm = PqSlhDsaAlgorithm.shake128f;
      final keys = forge.generateSlhDsaKeyPair(algorithm: algorithm);

      final raw = forge.signSlhDsa(
        keys.secretKey,
        message,
        algorithm: algorithm,
        context: context,
      );
      expect(raw, hasLength(algorithm.signatureBytes));
      expect(
        forge.verifySlhDsa(
          keys.publicKey,
          message,
          raw,
          algorithm: algorithm,
          context: context,
        ),
        isTrue,
      );
      expect(
        forge.verifySlhDsa(
          keys.publicKey,
          Uint8List.fromList(utf8.encode('tampered')),
          raw,
          algorithm: algorithm,
          context: context,
        ),
        isFalse,
      );

      final hashed = forge.signSlhDsa(
        keys.secretKey,
        message,
        algorithm: algorithm,
        context: context,
        preHash: true,
      );
      expect(
        forge.verifySlhDsa(
          keys.publicKey,
          message,
          hashed,
          algorithm: algorithm,
          context: context,
          preHash: true,
        ),
        isTrue,
      );
      expect(
        forge.verifySlhDsa(
          keys.publicKey,
          message,
          hashed,
          algorithm: algorithm,
          context: context,
        ),
        isFalse,
        reason: 'pure SLH-DSA must not verify a HashSLH-DSA signature',
      );
    });

    test('SHA2-128f round-trips (covers the SHA-2 hash family)', () {
      const algorithm = PqSlhDsaAlgorithm.sha2128f;
      final keys = forge.generateSlhDsaKeyPair(algorithm: algorithm);
      final signature = forge.signSlhDsa(
        keys.secretKey,
        message,
        algorithm: algorithm,
      );
      expect(
        forge.verifySlhDsa(
          keys.publicKey,
          message,
          signature,
          algorithm: algorithm,
        ),
        isTrue,
      );
    });

    test('s-set signing requires allowSlowSigning', () {
      const algorithm = PqSlhDsaAlgorithm.shake128s;
      final keys = forge.generateSlhDsaKeyPair(algorithm: algorithm);
      expect(
        () => forge.signSlhDsa(keys.secretKey, message, algorithm: algorithm),
        throwsA(isA<PqForgeException>()),
      );
    });

    test('document recipe signs and verifies with SLH-DSA', () {
      const algorithm = PqSlhDsaAlgorithm.shake128f;
      final keys = forge.generateSlhDsaKeyPair(algorithm: algorithm);
      final document = Uint8List.fromList(utf8.encode('contract body'));
      final signature = forge.signDocument(
        keys.secretKey,
        document,
        documentId: 'contract-1',
        slhDsa: algorithm,
      );
      expect(signature, hasLength(algorithm.signatureBytes));
      expect(
        forge.verifyDocument(
          keys.publicKey,
          document,
          signature,
          documentId: 'contract-1',
          slhDsa: algorithm,
        ),
        isTrue,
      );
      expect(
        forge.verifyDocument(
          keys.publicKey,
          document,
          signature,
          documentId: 'other',
          slhDsa: algorithm,
        ),
        isFalse,
      );
    });

    test('webhook recipe signs and verifies with SLH-DSA', () {
      const algorithm = PqSlhDsaAlgorithm.shake128f;
      final keys = forge.generateSlhDsaKeyPair(algorithm: algorithm);
      final payload = Uint8List.fromList(utf8.encode('{"event":"paid"}'));
      const timestampMs = 1700000000000;
      final signature = forge.signWebhook(
        signerSecretKey: keys.secretKey,
        eventType: 'invoice.paid',
        timestampMs: timestampMs,
        payload: payload,
        slhDsa: algorithm,
      );
      expect(signature, hasLength(algorithm.signatureBytes));
      expect(
        forge.verifyWebhook(
          signerPublicKey: keys.publicKey,
          eventType: 'invoice.paid',
          timestampMs: timestampMs,
          payload: payload,
          signature: signature,
          slhDsa: algorithm,
          nowMs: timestampMs + 1000,
        ),
        isTrue,
      );
      expect(
        forge.verifyWebhook(
          signerPublicKey: keys.publicKey,
          eventType: 'invoice.refunded',
          timestampMs: timestampMs,
          payload: payload,
          signature: signature,
          slhDsa: algorithm,
          nowMs: timestampMs + 1000,
        ),
        isFalse,
      );
    });

    test('artifact recipe signs and verifies with SLH-DSA', () {
      const algorithm = PqSlhDsaAlgorithm.shake128f;
      final keys = forge.generateSlhDsaKeyPair(algorithm: algorithm);
      final bytes = Uint8List.fromList(utf8.encode('release tarball'));
      final artifact = forge.signArtifact(
        signerSecretKey: keys.secretKey,
        artifactId: 'release.tar.gz',
        version: 3,
        artifactBytes: bytes,
        slhDsa: algorithm,
      );
      expect(artifact.slhDsa, algorithm);
      expect(artifact.signatureAlgorithm, isNull);
      expect(artifact.algorithmId, algorithm.id);
      expect(artifact.signature, hasLength(algorithm.signatureBytes));
      expect(forge.verifyArtifact(keys.publicKey, bytes, artifact), isTrue);
      expect(
        forge.verifyArtifact(
          keys.publicKey,
          Uint8List.fromList(utf8.encode('tampered')),
          artifact,
        ),
        isFalse,
      );
    });

    test('refuses mixing ML-DSA and SLH-DSA on one recipe call', () {
      expect(
        () => forge.signDocument(
          Uint8List(64),
          Uint8List(4),
          documentId: 'x',
          algorithm: PqSignatureAlgorithm.mlDsa44,
          slhDsa: PqSlhDsaAlgorithm.shake128f,
        ),
        throwsA(isA<PqForgeException>()),
      );
    });
  });

  group('custody', () {
    const forge = PqForge(profile: PqForgeProfile.compact);

    test('wraps and unwraps an SLH-DSA secret with Argon2id', () {
      const algorithm = PqSlhDsaAlgorithm.shake128f;
      final keys = forge.generateSlhDsaKeyPair(algorithm: algorithm);
      final exported = forge.exportSlhDsaSecretKey(
        keys,
        algorithm: algorithm,
        keyId: 'vault',
      );
      final wrapped = forge.wrapKeyWithPassphrase(
        exported,
        'test-passphrase',
        iterations: 1,
        memoryPowerOf2: 10,
        lanes: 1,
      );
      expect(wrapped.algorithmId, algorithm.id);
      expect(wrapped.keyKind, PqKeyKind.signatureSecret);
      final opened = forge.unwrapKeyWithPassphrase(wrapped, 'test-passphrase');
      expect(opened.bytes, keys.secretKey);
      expect(opened.algorithmId, algorithm.id);
    });
  });
}

SlhDsaParams _params(PqSlhDsaAlgorithm algorithm) => switch (algorithm) {
  PqSlhDsaAlgorithm.sha2128s => SlhDsaParams.sha2128s,
  PqSlhDsaAlgorithm.sha2128f => SlhDsaParams.sha2128f,
  PqSlhDsaAlgorithm.sha2192s => SlhDsaParams.sha2192s,
  PqSlhDsaAlgorithm.sha2192f => SlhDsaParams.sha2192f,
  PqSlhDsaAlgorithm.sha2256s => SlhDsaParams.sha2256s,
  PqSlhDsaAlgorithm.sha2256f => SlhDsaParams.sha2256f,
  PqSlhDsaAlgorithm.shake128s => SlhDsaParams.shake128s,
  PqSlhDsaAlgorithm.shake128f => SlhDsaParams.shake128f,
  PqSlhDsaAlgorithm.shake192s => SlhDsaParams.shake192s,
  PqSlhDsaAlgorithm.shake192f => SlhDsaParams.shake192f,
  PqSlhDsaAlgorithm.shake256s => SlhDsaParams.shake256s,
  PqSlhDsaAlgorithm.shake256f => SlhDsaParams.shake256f,
};
