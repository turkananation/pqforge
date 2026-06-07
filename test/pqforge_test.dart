import 'dart:convert';
import 'dart:typed_data';

import 'package:pqforge/pqforge.dart';
import 'package:test/test.dart';

void main() {
  group('algorithms and profiles', () {
    test('balanced profile carries the framework defaults', () {
      const profile = PqForgeProfile.balanced;

      expect(profile.kem, PqKemAlgorithm.mlKem768);
      expect(profile.signature, PqSignatureAlgorithm.mlDsa65);
      expect(profile.sessionKeyBytes, 32);
      expect(profile.kem.publicKeyBytes, 1184);
      expect(profile.signature.signatureBytes, 3309);
    });

    test('lookup rejects unsupported identifiers', () {
      expect(
        () => PqKemAlgorithm.byId('kyber768'),
        throwsA(isA<PqForgeException>()),
      );
      expect(
        () => PqForgeProfile.byName('unknown'),
        throwsA(isA<PqForgeException>()),
      );
    });
  });

  group('facade signatures and key generation', () {
    final forge = PqForge(profile: PqForgeProfile.compact);
    final message = _bytes('signed payload');
    final context = _bytes('test/signature/v1');

    test('generateKeys returns a combined bundle', () {
      final bundle = forge.generateKeys(keyId: 'bundle-a');

      expect(bundle.keyId, 'bundle-a');
      expect(
        bundle.kemKeyPair.publicKey,
        hasLength(PqKemAlgorithm.mlKem512.publicKeyBytes),
      );
      expect(
        bundle.signatureKeyPair.publicKey,
        hasLength(PqSignatureAlgorithm.mlDsa44.publicKeyBytes),
      );
    });

    test('signs and verifies detached payloads', () {
      final keys = forge.generateSignatureKeyPair();
      final signature = forge.sign(keys.secretKey, message, context: context);

      expect(
        forge.verify(keys.publicKey, message, signature, context: context),
        isTrue,
      );
      expect(
        forge.verify(
          keys.publicKey,
          _bytes('changed'),
          signature,
          context: context,
        ),
        isFalse,
      );
      expect(
        forge.verify(
          keys.publicKey,
          message,
          signature,
          context: _bytes('test/other/v1'),
        ),
        isFalse,
      );
    });

    test('supports deterministic signature key generation from seed', () {
      final seed = Uint8List.fromList(List<int>.filled(32, 9));
      final a = forge.generateSignatureKeyPairFromSeed(seed);
      final b = forge.generateSignatureKeyPairFromSeed(seed);

      expect(PqBytes.constantTimeEquals(a.publicKey, b.publicKey), isTrue);
      expect(PqBytes.constantTimeEquals(a.secretKey, b.secretKey), isTrue);
    });
  });

  group('envelope codecs', () {
    final forge = PqForge(profile: PqForgeProfile.compact);

    test('binary and JSON envelopes round trip and decrypt', () {
      final recipient = forge.generateKemKeyPair();
      final aad = _bytes('record:alpha');
      final envelope = forge.encrypt(
        recipient.publicKey,
        _bytes('private record'),
        aad: aad,
        metadata: {'purpose': 'unit-test'},
      );

      final binaryDecoded = PqEnvelope.fromBinary(envelope.toBinary());
      final jsonDecoded = PqEnvelope.fromJson(envelope.toJson());

      expect(
        forge.decrypt(recipient.secretKey, binaryDecoded, aad: aad),
        _bytes('private record'),
      );
      expect(
        forge.decrypt(recipient.secretKey, jsonDecoded, aad: aad),
        _bytes('private record'),
      );
      expect(binaryDecoded.metadata['purpose'], 'unit-test');
    });

    test('tamper checks reject wrong AAD and malformed lengths', () {
      final recipient = forge.generateKemKeyPair();
      final envelope = forge.encrypt(
        recipient.publicKey,
        _bytes('medical note'),
        aad: _bytes('patient:123'),
      );

      expect(
        () => forge.decrypt(
          recipient.secretKey,
          envelope,
          aad: _bytes('patient:456'),
        ),
        throwsA(isA<PqForgeException>()),
      );
      expect(
        () => PqEnvelope(
          profile: PqForgeProfile.compact,
          kemAlgorithm: PqKemAlgorithm.mlKem512,
          kemCiphertext: Uint8List(1),
          nonce: Uint8List(12),
          payload: Uint8List(16),
        ),
        throwsArgumentError,
      );
    });
  });

  group('KEM-DEM and signed envelopes', () {
    final forge = PqForge(profile: PqForgeProfile.compact);

    test('encrypt/decrypt is easy for records', () {
      final recipient = forge.generateKemKeyPair();
      final envelope = forge.encrypt(
        recipient.publicKey,
        _bytes('private payload'),
      );

      final opened = forge.decrypt(recipient.secretKey, envelope);

      expect(opened, _bytes('private payload'));
      expect(
        envelope.kemCiphertext,
        hasLength(PqKemAlgorithm.mlKem512.ciphertextBytes),
      );
      expect(envelope.payload.length, greaterThan('private payload'.length));
    });

    test('signed envelopes authenticate the sender', () {
      final recipient = forge.generateKemKeyPair();
      final signer = forge.generateSignatureKeyPair();
      final wrongSigner = forge.generateSignatureKeyPair();

      final envelope = forge.encrypt(
        recipient.publicKey,
        _bytes('signed private record'),
        signerSecretKey: signer.secretKey,
        signerKeyId: 'signer-a',
      );

      expect(
        forge.decrypt(
          recipient.secretKey,
          envelope,
          signerPublicKey: signer.publicKey,
        ),
        _bytes('signed private record'),
      );
      expect(
        () => forge.decrypt(
          recipient.secretKey,
          envelope,
          signerPublicKey: wrongSigner.publicKey,
        ),
        throwsA(isA<PqForgeException>()),
      );
    });

    test('compatibility helpers bind info and signature context hashes', () {
      final recipient = forge.generateKemKeyPair();
      final signer = forge.generateSignatureKeyPair();
      final info = _bytes('api:v1/recipient:alpha');
      final signatureContext = _bytes('workflow:records:v1');

      final envelope = forge.sealToKemPublicKey(
        recipient.publicKey,
        _bytes('info-bound payload'),
        info: info,
      );
      expect(
        forge.openFromKemSecretKey(recipient.secretKey, envelope, info: info),
        _bytes('info-bound payload'),
      );
      expect(
        () => forge.openFromKemSecretKey(
          recipient.secretKey,
          envelope,
          info: _bytes('wrong-info'),
        ),
        throwsA(isA<PqForgeException>()),
      );

      final signed = forge.sealAndSign(
        recipient.publicKey,
        signer.secretKey,
        _bytes('context-bound payload'),
        signatureContext: signatureContext,
      );
      expect(
        forge.openSignedFromKemSecretKey(
          recipient.secretKey,
          signer.publicKey,
          signed,
          signatureContext: signatureContext,
        ),
        _bytes('context-bound payload'),
      );
      expect(
        () => forge.openSignedFromKemSecretKey(
          recipient.secretKey,
          signer.publicKey,
          signed,
          signatureContext: _bytes('wrong-context'),
        ),
        throwsA(isA<PqForgeException>()),
      );
    });
  });

  group('key custody hooks and wrapping', () {
    final forge = PqForge(profile: PqForgeProfile.compact);

    test(
      'wraps and unwraps an exported key without plaintext metadata leakage',
      () {
        final keys = forge.generateKemKeyPair();
        final exported = PqExportedKey(
          kind: 'kem-secret',
          algorithmId: PqKemAlgorithm.mlKem512.id,
          keyId: 'kem-a',
          bytes: keys.secretKey,
        );

        final wrapped = forge.wrapKeyWithPassphrase(exported, 'correct horse');
        final unwrapped = forge.unwrapKeyWithPassphrase(
          wrapped,
          'correct horse',
        );

        expect(
          wrapped.toJson().containsValue(base64Encode(keys.secretKey)),
          isFalse,
        );
        expect(unwrapped.kind, exported.kind);
        expect(unwrapped.algorithmId, exported.algorithmId);
        expect(
          PqBytes.constantTimeEquals(unwrapped.bytes, keys.secretKey),
          isTrue,
        );
        expect(
          () => forge.unwrapKeyWithPassphrase(wrapped, 'wrong horse'),
          throwsA(isA<Exception>()),
        );
      },
    );

    test(
      'passphrase custody stores wrapped keys in pluggable memory storage',
      () async {
        final keys = forge.generateKeys(keyId: 'file-key-a');
        final store = PqMemoryKeyCustodyStore();
        final custody = PqPassphraseKeyCustody(forge: forge, store: store);
        final exported = keys.exportKemSecretKey();

        await custody.wrapAndPut(exported, 'strong passphrase');
        final restored = await custody.getAndUnwrap(
          'file-key-a',
          'strong passphrase',
        );

        expect(store.snapshot, contains('file-key-a'));
        expect(
          store.snapshot['file-key-a']!.containsValue(
            base64Encode(keys.kemKeyPair.secretKey),
          ),
          isFalse,
        );
        expect(restored.kind, PqKeyKind.kemSecret);
        expect(restored.algorithmId, PqKemAlgorithm.mlKem512.id);
        expect(
          PqBytes.constantTimeEquals(restored.bytes, keys.kemKeyPair.secretKey),
          isTrue,
        );
      },
    );

    test('callback custody store adapts app databases or vaults', () async {
      final backing = <String, Map<String, Object?>>{};
      final store = PqCallbackKeyCustodyStore(
        putDocument: (id, document) =>
            backing[id] = Map<String, Object?>.from(document),
        getDocument: (id) => backing[id],
        deleteDocument: backing.remove,
      );
      final custody = PqPassphraseKeyCustody(forge: forge, store: store);
      final key = PqExportedKey(
        kind: PqKeyKind.signatureSecret,
        algorithmId: PqSignatureAlgorithm.mlDsa44.id,
        keyId: 'signer-a',
        bytes: forge.generateSignatureKeyPair().secretKey,
      );

      await custody.wrapAndPut(key, 'db passphrase', storageId: 'db/signer-a');
      final restored = await custody.getAndUnwrap(
        'db/signer-a',
        'db passphrase',
      );

      expect(restored.kind, PqKeyKind.signatureSecret);
      expect(restored.algorithmId, key.algorithmId);
      expect(PqBytes.constantTimeEquals(restored.bytes, key.bytes), isTrue);

      await custody.delete('db/signer-a');
      expect(await custody.getWrappedKey('db/signer-a'), isNull);
    });
  });

  group('cookbook recipes', () {
    final forge = PqForge(profile: PqForgeProfile.compact);

    test('document signing verifies and rejects changed bytes', () {
      final signer = forge.generateSignatureKeyPair();
      final document = _bytes('contract bytes');
      final signature = forge.signDocument(
        signer.secretKey,
        document,
        documentId: 'contract-1',
      );

      expect(
        forge.verifyDocument(
          signer.publicKey,
          document,
          signature,
          documentId: 'contract-1',
        ),
        isTrue,
      );
      expect(
        forge.verifyDocument(
          signer.publicKey,
          _bytes('changed bytes'),
          signature,
          documentId: 'contract-1',
        ),
        isFalse,
      );
    });

    test('government and medical records use file/data-at-rest helpers', () {
      final vault = forge.generateKemKeyPair(
        algorithm: PqKemAlgorithm.mlKem1024,
      );
      final envelope = forge.encryptRecord(
        vault.publicKey,
        _bytes('diagnosis: confidential'),
        recordType: 'medical-record',
        recordId: 'patient-123',
        aad: _bytes('tenant:hospital-a'),
      );

      expect(envelope.profile, PqForgeProfile.maximum);
      expect(envelope.metadata['recordType'], 'medical-record');
      expect(
        forge.decryptFileBytes(
          vault.secretKey,
          envelope,
          aad: _bytes('tenant:hospital-a'),
        ),
        _bytes('diagnosis: confidential'),
      );
    });

    test('file helper round trips with maximum profile key bundles', () {
      final recipient = forge.generateKeys(profile: PqForgeProfile.maximum);
      final fileBytes = _bytes('%PDF-1.7 confidential county app');
      final aad = _bytes('file:KajiadoCountyApp.pdf');

      final envelope = forge.encryptFileBytes(
        recipient.kemKeyPair.publicKey,
        fileBytes,
        aad: aad,
      );

      expect(envelope.profile, PqForgeProfile.maximum);
      expect(
        forge.decryptFileBytes(
          recipient.kemKeyPair.secretKey,
          envelope,
          aad: aad,
        ),
        fileBytes,
      );
    });

    test('identity binding is signed by an authority', () {
      final authority = forge.generateSignatureKeyPair();
      final identity = forge.generateSignatureKeyPair();

      final binding = forge.createIdentityBinding(
        authoritySecretKey: authority.secretKey,
        subjectId: 'user-1',
        identityPublicKey: identity.publicKey,
        notBeforeMs: 1,
        expiresAtMs: 999,
      );

      expect(forge.verifyIdentityBinding(authority.publicKey, binding), isTrue);
      expect(forge.verifyIdentityBinding(identity.publicKey, binding), isFalse);
    });

    test('signed logs detect tampering and produce next hash', () {
      final signer = forge.generateSignatureKeyPair(
        algorithm: PqSignatureAlgorithm.mlDsa44,
      );
      final entry = forge.appendSignedLogEntry(
        signerSecretKey: signer.secretKey,
        previousHash: Uint8List(32),
        payload: _bytes('audit event'),
        timestampMs: 123,
      );

      expect(forge.verifySignedLogEntry(signer.publicKey, entry), isTrue);
      expect(entry.entryHash(), hasLength(32));
      final tampered = PqSignedLogEntry(
        previousHash: Uint8List(32),
        payload: _bytes('changed event'),
        timestampMs: 123,
        signatureAlgorithm: entry.signatureAlgorithm,
        signature: entry.signature,
      );
      expect(forge.verifySignedLogEntry(signer.publicKey, tampered), isFalse);
    });

    test('software artifact signatures bind version and bytes', () {
      final signer = forge.generateSignatureKeyPair();
      final artifact = forge.signArtifact(
        signerSecretKey: signer.secretKey,
        artifactId: 'release.tar.gz',
        version: 7,
        artifactBytes: _bytes('artifact bytes'),
      );

      expect(
        forge.verifyArtifact(
          signer.publicKey,
          _bytes('artifact bytes'),
          artifact,
        ),
        isTrue,
      );
      expect(
        forge.verifyArtifact(
          signer.publicKey,
          _bytes('changed bytes'),
          artifact,
        ),
        isFalse,
      );
    });

    test('dual signatures combine app-supplied classical verification', () {
      final signer = forge.generateSignatureKeyPair();
      final message = _bytes('release manifest');
      final dual = forge.dualSign(
        secretKey: signer.secretKey,
        message: message,
        classicalSignature: _bytes('classical-signature'),
      );

      expect(
        forge.dualVerify(
          publicKey: signer.publicKey,
          message: message,
          signature: dual,
          classicalVerifier: (m, s) => utf8.decode(s) == 'classical-signature',
        ),
        isTrue,
      );
      expect(
        forge.dualVerify(
          publicKey: signer.publicKey,
          message: message,
          signature: dual,
          classicalVerifier: (m, s) => false,
        ),
        isFalse,
      );
    });
  });

  group('hybrid session derivation and isolate DTOs', () {
    final forge = PqForge(profile: PqForgeProfile.compact);

    test('combines classical and lattice secrets with transcript binding', () {
      final recipient = forge.generateKemKeyPair();
      final kem = forge.encapsulate(recipient.publicKey);
      final recovered = forge.decapsulate(recipient.secretKey, kem.ciphertext);
      final classical = Uint8List.fromList(List<int>.filled(32, 7));
      final deploymentSalt = Uint8List.fromList(List<int>.filled(32, 11));
      final transcriptHash = PqBytes.sha256(_bytes('transcript-a'));

      final senderKey = forge.deriveHybridSessionKey(
        classicalSharedSecret: classical,
        latticeSharedSecret: kem.sharedSecret,
        deploymentSalt: deploymentSalt,
        transcriptHash: transcriptHash,
      );
      final recipientKey = forge.deriveHybridSessionKey(
        classicalSharedSecret: classical,
        latticeSharedSecret: recovered,
        deploymentSalt: deploymentSalt,
        transcriptHash: transcriptHash,
      );
      final otherTranscriptKey = forge.deriveHybridSessionKey(
        classicalSharedSecret: classical,
        latticeSharedSecret: recovered,
        deploymentSalt: deploymentSalt,
        transcriptHash: PqBytes.sha256(_bytes('transcript-b')),
      );

      expect(PqBytes.constantTimeEquals(senderKey, recipientKey), isTrue);
      expect(
        PqBytes.constantTimeEquals(senderKey, otherTranscriptKey),
        isFalse,
      );
      expect(
        () => forge.deriveHybridSessionKey(
          classicalSharedSecret: Uint8List(0),
          latticeSharedSecret: Uint8List(32),
          deploymentSalt: Uint8List(32),
          transcriptHash: Uint8List(32),
        ),
        throwsArgumentError,
      );
    });

    test('offload DTOs are isolate-sendable plain data', () {
      const request = PqOffloadRequest(
        operation: 'sign-document',
        profileName: 'compact',
        payload: [1, 2, 3],
        metadata: {'documentId': 'doc-1'},
      );
      const response = PqOffloadResponse(
        operation: 'sign-document',
        payload: [4, 5, 6],
      );

      expect(request.profileName, 'compact');
      expect(response.payload, [4, 5, 6]);
    });
  });
}

Uint8List _bytes(String value) => Uint8List.fromList(utf8.encode(value));
