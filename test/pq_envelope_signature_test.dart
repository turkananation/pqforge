import 'dart:typed_data';

import 'package:pqforge/pqforge.dart';
import 'package:test/test.dart';

/// Phase 2 (defect M1): envelope signatures are computed over a 32-byte digest
/// of the header plus SHA-256(payload), signed with `preHash:true`, instead of
/// over the whole payload concatenated into a fresh buffer. Signing cost and
/// memory no longer scale with payload size.
void main() {
  // Compact profile keeps ML-DSA-44 keygen/sign fast for the test suite.
  final forge = PqForge(profile: PqForgeProfile.compact);
  final message = Uint8List.fromList(List<int>.generate(4096, (i) => i & 0xFF));

  group('envelope pre-hashed signatures', () {
    test('signed envelopes round-trip through binary', () {
      final recipient = forge.generateKemKeyPair();
      final signer = forge.generateSignatureKeyPair();

      final envelope = forge.encrypt(
        recipient.publicKey,
        message,
        signerSecretKey: signer.secretKey,
        signerKeyId: 'signer-a',
      );
      expect(envelope.version, pqForgeEnvelopeVersion);
      expect(envelope.isSigned, isTrue);
      // ML-DSA-44 signatures are fixed-size regardless of payload length.
      expect(
        envelope.signature,
        hasLength(PqSignatureAlgorithm.mlDsa44.signatureBytes),
      );

      // On-disk envelopes must still verify + decrypt after serialization.
      final restored = PqEnvelope.fromBinary(envelope.toBinary());
      expect(
        forge.decrypt(
          recipient.secretKey,
          restored,
          signerPublicKey: signer.publicKey,
        ),
        message,
      );
    });

    test('unsigned envelopes carry no signature', () {
      final recipient = forge.generateKemKeyPair();
      final envelope = forge.encrypt(recipient.publicKey, message);
      expect(envelope.isSigned, isFalse);
      expect(forge.decrypt(recipient.secretKey, envelope), message);
    });

    test('a wrong signer key fails verification', () {
      final recipient = forge.generateKemKeyPair();
      final signer = forge.generateSignatureKeyPair();
      final wrongSigner = forge.generateSignatureKeyPair();

      final envelope = forge.encrypt(
        recipient.publicKey,
        message,
        signerSecretKey: signer.secretKey,
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

    test('a tampered payload fails verification before any AEAD work', () {
      final recipient = forge.generateKemKeyPair();
      final signer = forge.generateSignatureKeyPair();
      final envelope = forge.encrypt(
        recipient.publicKey,
        message,
        signerSecretKey: signer.secretKey,
      );

      final mutatedPayload = Uint8List.fromList(envelope.payload);
      mutatedPayload[0] ^= 0x01;
      // Keep the original signature so the digest (which covers the payload) no
      // longer matches — the signature check must reject it.
      final tampered = _rebuild(
        envelope,
        payload: mutatedPayload,
        signature: envelope.signature,
      );

      expect(
        () => forge.decrypt(
          recipient.secretKey,
          tampered,
          signerPublicKey: signer.publicKey,
        ),
        throwsA(isA<PqForgeException>()),
      );
    });
  });
}

/// Rebuilds [source] with selected fields overridden.
PqEnvelope _rebuild(
  PqEnvelope source, {
  Uint8List? payload,
  Uint8List? signature,
}) {
  return PqEnvelope(
    version: source.version,
    profile: source.profile,
    kemAlgorithm: source.kemAlgorithm,
    signatureAlgorithm: source.signatureAlgorithm,
    kemCiphertext: source.kemCiphertext,
    nonce: source.nonce,
    payload: payload ?? source.payload,
    aadHash: source.aadHash,
    signerKeyId: source.signerKeyId,
    signature: signature,
    metadata: source.metadata,
  );
}
